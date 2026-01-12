/*
 * ProFTPD MongoDB Authentication Module
 * Copyright (c) 2025
 *
 * OVERVIEW:
 * This module provides MongoDB-based authentication for ProFTPD FTP server.
 * Users are authenticated against documents stored in a MongoDB collection,
 * supporting multiple password hashing methods (plain, bcrypt, crypt, sha256, sha512).
 *
 * CONFIGURATION DIRECTIVES:
 * - AuthMongoConnectionString: MongoDB connection URI
 * - AuthMongoDatabaseName: Database name containing user collection
 * - AuthMongoAuthCollectionName: Collection name with user documents
 * - AuthMongoDocumentFieldUsername: Field name for username in documents
 * - AuthMongoDocumentFieldPassword: Field name for password hash in documents
 * - AuthMongoDocumentFieldUid: Field name for user ID (numeric string)
 * - AuthMongoDocumentFieldGid: Field name for group ID (numeric string)
 * - AuthMongoDocumentFieldPath: Field name for user's home directory path
 * - AuthMongoPasswordHashMethod: Hash method (plain, bcrypt, crypt, sha256, sha512)
 * - AuthMongoConnectionPoolSize: Max pool size 1-100 (default: 10, optional)
 * - AuthMongoDebugLogging: Enable verbose debug logging (on/off)
 * - AuthMongoNoAuthString: Custom error message for failed authentication
 * - AuthMongoNoConnectionString: Custom error message for connection failures
 *
 * DOCUMENT STRUCTURE EXAMPLE:
 * {
 *   "username": "john",
 *   "password": "$6$salt$hash...",  // SHA-512 hash
 *   "uid": "1001",
 *   "gid": "1001",
 *   "path": "/home/john"
 * }
 */

#include "conf.h"
#include "privs.h"
#include <mongoc/mongoc.h>
#include <bson/bson.h>
#include <crypt.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#define MOD_AUTH_MONGODB_VERSION "mod_auth_mongodb/1.2.0"

/* Password hash methods - determines how stored passwords are verified
 * PLAIN:   Direct string comparison (insecure, for testing only)
 * BCRYPT:  Uses bcrypt algorithm ($2a$, $2b$, $2y$ prefixes)
 * CRYPT:   Traditional Unix crypt() function
 * SHA256:  SHA-256 based crypt ($5$ prefix)
 * SHA512:  SHA-512 based crypt ($6$ prefix)
 */
#define HASH_METHOD_PLAIN   0
#define HASH_METHOD_BCRYPT  1
#define HASH_METHOD_CRYPT   2
#define HASH_METHOD_SHA256  3
#define HASH_METHOD_SHA512  4

/* Security constants */
#define MAX_USERNAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 1024
#define DEFAULT_POOL_SIZE 10

/* Module configuration structure - runtime configuration values loaded from
 * ProFTPD config file during session initialization. These values determine
 * how to connect to MongoDB and which fields to query for user data.
 */
static char *mongodb_connection_string = NULL;
static char *mongodb_database_name = NULL;
static char *mongodb_collection_name = NULL;
static char *mongodb_field_username = NULL;
static char *mongodb_field_password = NULL;
static char *mongodb_field_uid = NULL;
static char *mongodb_field_gid = NULL;
static char *mongodb_field_path = NULL;
static char *mongodb_error_noauth = NULL;
static char *mongodb_error_noconnection = NULL;
static int mongodb_debug_logging = FALSE;
static int mongodb_password_hash_method = HASH_METHOD_PLAIN;
static int mongodb_pool_size = DEFAULT_POOL_SIZE;

/* MongoDB connection pool for reusing connections across authentication requests.
 * This significantly improves performance by avoiding connection overhead.
 */
static mongoc_client_pool_t *mongodb_client_pool = NULL;

/* Query result cache - prevents duplicate MongoDB queries for same user
 * during authentication flow (getpwnam + auth both query for same user)
 */
#define USER_CACHE_TTL_SECONDS 5
#define USER_CACHE_USERNAME_MAX 256
#define USER_CACHE_PASSWORD_MAX 512
#define USER_CACHE_PATH_MAX 1024

typedef struct {
    char username[USER_CACHE_USERNAME_MAX];
    char password_hash[USER_CACHE_PASSWORD_MAX];
    uid_t uid;
    gid_t gid;
    char home_dir[USER_CACHE_PATH_MAX];
    struct timeval cached_at;
    int valid;
} user_cache_entry_t;

static user_cache_entry_t user_cache = {0};

module auth_mongodb_module;

/* Forward declarations */
static int auth_mongodb_sess_init(void);
static void auth_mongodb_module_cleanup(const void *event_data, void *user_data);
static void auth_mongodb_sess_cleanup(const void *event_data, void *user_data);
static int parse_uid_gid(const char *str, unsigned long *out, const char *field_name);
static int validate_mongodb_configuration(void);
static int is_cache_valid(const char *username);
static void cache_user_data(const char *username, const char *password_hash,
                           uid_t uid, gid_t gid, const char *home_dir);
static void invalidate_cache(void);
static int constant_time_compare(const char *a, const char *b, size_t len);
static char *expand_environment_variables(pool *p, const char *str);

/* ==============================================================================
 * CONFIGURATION DIRECTIVE HANDLERS
 * 
 * These functions process configuration directives from proftpd.conf.
 * Each handler validates the directive arguments and stores values in the
 * ProFTPD configuration tree for later retrieval during session initialization.
 * 
 * CHECK_ARGS: Validates correct number of arguments
 * CHECK_CONF: Ensures directive is used in correct context (root/virtual/global)
 * add_config_param_str/add_config_param: Stores the configuration value
 * ============================================================================== */

/**
 * Handler: AuthMongoConnectionString
 * Sets the MongoDB connection URI (e.g., mongodb://localhost:27017)
 * 
 * Supports environment variable expansion using ${VAR_NAME} syntax.
 * This allows sensitive credentials to be stored in environment variables
 * instead of hardcoded in configuration files.
 * 
 * Example: "mongodb://user:${MONGO_PASSWORD}@host:27017"
 */
MODRET set_mongodb_connection_string(cmd_rec *cmd) {
    char *expanded_string;
    
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    /* Expand environment variables in the connection string */
    expanded_string = expand_environment_variables(cmd->tmp_pool, cmd->argv[1]);
    if (!expanded_string) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Failed to expand environment variables in connection string");
        return PR_ERROR(cmd);
    }
    
    add_config_param_str(cmd->argv[0], 1, expanded_string);
    return PR_HANDLED(cmd);
}

/**
 * Handler: AuthMongoDatabaseName
 * Sets the database name containing the user authentication collection
 */
MODRET set_mongodb_database_name(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

/**
 * Handler: AuthMongoAuthCollectionName
 * Sets the collection name where user documents are stored
 */
MODRET set_mongodb_collection_name(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_mongodb_field_username(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_mongodb_field_password(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_mongodb_field_uid(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_mongodb_field_gid(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_mongodb_field_path(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_mongodb_error_noauth(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_mongodb_error_noconnection(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

/**
 * Handler: AuthMongoDebugLogging
 * Enables/disables verbose debug logging for troubleshooting
 * Accepts: on, off, true, false, yes, no
 */
MODRET set_mongodb_debug_logging(cmd_rec *cmd) {
    int debug_flag = FALSE;
    
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    debug_flag = get_boolean(cmd, 1);
    if (debug_flag == -1) {
        CONF_ERROR(cmd, "expected boolean parameter");
    }
    
    add_config_param(cmd->argv[0], 1, (void *)(long)debug_flag);
    return PR_HANDLED(cmd);
}

/**
 * Handler: AuthMongoPasswordHashMethod
 * Configures the password hashing algorithm used for verification
 * Valid methods: plain, bcrypt, crypt, sha256, sha512
 * The method must match how passwords are stored in MongoDB
 */
MODRET set_mongodb_password_hash_method(cmd_rec *cmd) {
    char *method = NULL;
    int hash_method = HASH_METHOD_PLAIN;
    
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    method = cmd->argv[1];
    
    if (strcasecmp(method, "plain") == 0) {
        hash_method = HASH_METHOD_PLAIN;
    } else if (strcasecmp(method, "bcrypt") == 0) {
        hash_method = HASH_METHOD_BCRYPT;
    } else if (strcasecmp(method, "crypt") == 0) {
        hash_method = HASH_METHOD_CRYPT;
    } else if (strcasecmp(method, "sha256") == 0 || strcasecmp(method, "sha256-crypt") == 0) {
        hash_method = HASH_METHOD_SHA256;
    } else if (strcasecmp(method, "sha512") == 0 || strcasecmp(method, "sha512-crypt") == 0) {
        hash_method = HASH_METHOD_SHA512;
    } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unsupported hash method: ", method, 
                   ". Valid methods: plain, bcrypt, crypt, sha256, sha512", NULL));
    }
    
    add_config_param(cmd->argv[0], 1, (void *)(long)hash_method);
    return PR_HANDLED(cmd);
}

/**
 * Handler: AuthMongoConnectionPoolSize
 * Sets the maximum size of the MongoDB connection pool (1-100)
 * Default: 10 connections
 */
MODRET set_mongodb_pool_size(cmd_rec *cmd) {
    int pool_size = 0;
    char *endptr = NULL;
    
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    pool_size = (int)strtol(cmd->argv[1], &endptr, 10);
    
    if (*endptr != '\0' || pool_size < 1 || pool_size > 100) {
        CONF_ERROR(cmd, "pool size must be between 1 and 100");
    }
    
    add_config_param(cmd->argv[0], 1, (void *)(long)pool_size);
    return PR_HANDLED(cmd);
}

/* Configuration table */
static conftable auth_mongodb_conftab[] = {
    { "AuthMongoConnectionString",      set_mongodb_connection_string,  NULL },
    { "AuthMongoDatabaseName",          set_mongodb_database_name,      NULL },
    { "AuthMongoAuthCollectionName",    set_mongodb_collection_name,    NULL },
    { "AuthMongoDocumentFieldUsername", set_mongodb_field_username,     NULL },
    { "AuthMongoDocumentFieldPassword", set_mongodb_field_password,     NULL },
    { "AuthMongoDocumentFieldUid",      set_mongodb_field_uid,          NULL },
    { "AuthMongoDocumentFieldGid",      set_mongodb_field_gid,          NULL },
    { "AuthMongoDocumentFieldPath",     set_mongodb_field_path,         NULL },
    { "AuthMongoNoAuthString",          set_mongodb_error_noauth,       NULL },
    { "AuthMongoNoConnectionString",    set_mongodb_error_noconnection, NULL },
    { "AuthMongoDebugLogging",          set_mongodb_debug_logging,      NULL },
    { "AuthMongoPasswordHashMethod",    set_mongodb_password_hash_method, NULL },
    { "AuthMongoConnectionPoolSize",    set_mongodb_pool_size,          NULL },
    { NULL, NULL, NULL }
};

/* ==============================================================================
 * QUERY CACHE FUNCTIONS
 * 
 * These functions manage a simple cache to avoid duplicate MongoDB queries
 * during authentication. ProFTPD calls getpwnam() followed by auth() for the
 * same user, which would normally result in 2 identical queries.
 * ============================================================================== */

/**
 * is_cache_valid - Check if cached user data is valid and fresh
 * @username: Username to check in cache
 * 
 * Returns: 1 if cache hit and fresh, 0 if cache miss or expired
 * 
 * Cache entries are valid for USER_CACHE_TTL_SECONDS to balance performance
 * and security (ensures recent password changes are detected).
 */
static int is_cache_valid(const char *username) {
    struct timeval now;
    long elapsed_usec;
    
    if (!user_cache.valid || !username) {
        return 0;
    }
    
    if (strcmp(user_cache.username, username) != 0) {
        return 0;  /* Different user */
    }
    
    gettimeofday(&now, NULL);
    elapsed_usec = (now.tv_sec - user_cache.cached_at.tv_sec) * 1000000L +
                   (now.tv_usec - user_cache.cached_at.tv_usec);
    
    if (elapsed_usec > (USER_CACHE_TTL_SECONDS * 1000000L)) {
        if (mongodb_debug_logging) {
            pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                       ": Cache expired for user '%s' (age: %.1fs)", 
                       username, elapsed_usec / 1000000.0);
        }
        return 0;  /* Expired */
    }
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Cache hit for user '%s' (age: %.1fs)", 
                   username, elapsed_usec / 1000000.0);
    }
    
    return 1;
}

/**
 * cache_user_data - Store user data in cache
 * @username: Username to cache
 * @password_hash: Password hash to cache
 * @uid: User ID
 * @gid: Group ID
 * @home_dir: Home directory path
 * 
 * Stores user data with current timestamp. Cache is automatically invalidated
 * after USER_CACHE_TTL_SECONDS.
 */
static void cache_user_data(const char *username, const char *password_hash,
                           uid_t uid, gid_t gid, const char *home_dir) {
    if (!username || !password_hash || !home_dir) {
        return;
    }
    
    /* Copy data safely with bounds checking */
    strncpy(user_cache.username, username, USER_CACHE_USERNAME_MAX - 1);
    user_cache.username[USER_CACHE_USERNAME_MAX - 1] = '\0';
    
    strncpy(user_cache.password_hash, password_hash, USER_CACHE_PASSWORD_MAX - 1);
    user_cache.password_hash[USER_CACHE_PASSWORD_MAX - 1] = '\0';
    
    strncpy(user_cache.home_dir, home_dir, USER_CACHE_PATH_MAX - 1);
    user_cache.home_dir[USER_CACHE_PATH_MAX - 1] = '\0';
    
    user_cache.uid = uid;
    user_cache.gid = gid;
    gettimeofday(&user_cache.cached_at, NULL);
    user_cache.valid = 1;
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Cached user data for '%s' (ttl: %ds)", 
                   username, USER_CACHE_TTL_SECONDS);
    }
}

/**
 * invalidate_cache - Clear the user cache (secure memory wipe)
 * 
 * Called when authentication fails or on session cleanup to prevent
 * information leakage across sessions. Uses explicit_bzero if available
 * to prevent compiler optimization from removing the zeroing.
 */
static void invalidate_cache(void) {
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    explicit_bzero(&user_cache, sizeof(user_cache));
#else
    volatile unsigned char *p = (volatile unsigned char *)&user_cache;
    size_t i;
    for (i = 0; i < sizeof(user_cache); i++) {
        p[i] = 0;
    }
#endif
    user_cache.valid = 0;
}

/**
 * expand_environment_variables - Expand ${VAR} references in a string
 * @p: Memory pool to allocate from
 * @str: String potentially containing ${VAR_NAME} references
 * 
 * Returns: Newly allocated string with variables expanded, or original if no expansion needed
 * 
 * This function replaces ${VAR_NAME} patterns with their environment variable values.
 * Used to avoid hardcoding sensitive credentials (passwords) in configuration files.
 * 
 * Example: "mongodb://user:${MONGO_PASSWORD}@host" becomes "mongodb://user:secret123@host"
 * 
 * Security: Environment variables are only expanded at module initialization,
 * not during runtime authentication to prevent injection attacks.
 */
static char *expand_environment_variables(pool *p, const char *str) {
    const char *src = str;
    char *result = NULL;
    char *dest = NULL;
    size_t result_len = 0;
    size_t result_capacity = 0;
    
    if (!str || !p) {
        return NULL;
    }
    
    /* Initial capacity estimate: original string length * 2 for expansion */
    result_capacity = strlen(str) * 2 + 1;
    result = palloc(p, result_capacity);
    if (!result) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Failed to allocate memory for environment variable expansion");
        return (char *)str;  /* Return original on allocation failure */
    }
    dest = result;
    
    while (*src) {
        if (*src == '$' && *(src + 1) == '{') {
            /* Found ${VAR} pattern - extract variable name */
            const char *var_start = src + 2;
            const char *var_end = strchr(var_start, '}');
            
            if (var_end) {
                /* Extract variable name */
                size_t var_name_len = var_end - var_start;
                char *var_name = palloc(p, var_name_len + 1);
                const char *var_value;
                
                if (!var_name) {
                    pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                               ": Failed to allocate memory for variable name");
                    return (char *)str;
                }
                
                memcpy(var_name, var_start, var_name_len);
                var_name[var_name_len] = '\0';
                
                /* Get environment variable value */
                var_value = getenv(var_name);
                
                if (var_value) {
                    size_t value_len = strlen(var_value);
                    
                    /* Ensure we have enough space */
                    if (result_len + value_len + 1 > result_capacity) {
                        result_capacity = (result_len + value_len) * 2 + 1;
                        /* Note: We can't use realloc with ProFTPD pools, so we use a large initial capacity */
                        pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                                   ": Environment variable expansion may be truncated for very long values");
                    }
                    
                    /* Copy environment variable value */
                    if (result_len + value_len < result_capacity) {
                        memcpy(dest, var_value, value_len);
                        dest += value_len;
                        result_len += value_len;
                    }
                    
                    if (mongodb_debug_logging) {
                        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                                   ": Expanded environment variable ${%s}", var_name);
                    }
                } else {
                    /* Variable not found - log warning and leave empty */
                    pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                               ": Environment variable ${%s} not found - substituting empty string", 
                               var_name);
                }
                
                /* Move past the ${VAR} pattern */
                src = var_end + 1;
                continue;
            }
        }
        
        /* Regular character - copy as-is */
        if (result_len + 1 < result_capacity) {
            *dest++ = *src;
            result_len++;
        }
        src++;
    }
    
    /* Null-terminate the result */
    if (result_len < result_capacity) {
        *dest = '\0';
    } else {
        result[result_capacity - 1] = '\0';
    }
    
    return result;
}

/**
 * constant_time_compare - Compare two strings in constant time
 * @a: First string
 * @b: Second string  
 * @len: Maximum length to compare
 * 
 * Returns: 0 if strings match, non-zero if they differ
 * 
 * This function compares strings in constant time to prevent timing attacks.
 * Always compares all bytes up to len, regardless of where differences occur.
 * CRITICAL for password verification security.
 */
static int constant_time_compare(const char *a, const char *b, size_t len) {
    volatile unsigned char result = 0;
    size_t i;
    
    if (!a || !b) {
        return -1;
    }
    
    /* Compare all bytes, accumulate differences */
    for (i = 0; i < len; i++) {
        result |= ((unsigned char)a[i]) ^ ((unsigned char)b[i]);
    }
    
    return result;
}

/* ==============================================================================
 * PASSWORD VERIFICATION FUNCTIONS
 * ============================================================================== */

/**
 * parse_uid_gid - Safely parse string to unsigned integer with validation
 * @str: String to parse
 * @out: Output parameter for parsed value
 * @field_name: Field name for error messages
 * 
 * Returns: 0 on success, -1 on error
 * 
 * This function safely converts string representations of uid/gid to integers,
 * with proper error checking to prevent invalid values (especially uid 0/root).
 */
static int parse_uid_gid(const char *str, unsigned long *out, const char *field_name) {
    char *endptr = NULL;
    long val;
    
    if (!str || !out || !field_name) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Invalid parameters to parse_uid_gid");
        return -1;
    }
    
    errno = 0;
    val = strtol(str, &endptr, 10);
    
    /* Check for conversion errors */
    if (errno != 0 || *endptr != '\0' || endptr == str) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Invalid %s value '%s': not a valid number", field_name, str);
        return -1;
    }
    
    /* Check range - must be positive and within system limits */
    if (val < 1 || val > UINT_MAX) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Invalid %s value '%s': out of range (must be 1-%u)", 
                   field_name, str, UINT_MAX);
        return -1;
    }
    
    *out = (unsigned long)val;
    return 0;
}

/**
 * find_bson_field - Find a BSON field supporting both flat and nested paths
 * @iter: Output iterator positioned at the found field
 * @doc: BSON document to search
 * @field_path: Field path (e.g., "uid" or "server.uid")
 * 
 * Returns: 1 if field found, 0 if not found
 * 
 * This function handles both simple field names and dot-notation paths for
 * nested document fields. For example:
 * - "uid" searches for a top-level field named "uid"
 * - "server.uid" searches for doc["server"]["uid"]
 * 
 * Uses bson_iter_find_descendant() which properly handles nested paths,
 * unlike bson_iter_init_find() which only searches top-level fields.
 */
static int find_bson_field(bson_iter_t *iter, const bson_t *doc, const char *field_path) {
    bson_iter_t parent_iter;
    
    if (!iter || !doc || !field_path) {
        return 0;
    }
    
    /* Initialize parent iterator at document root */
    if (!bson_iter_init(&parent_iter, doc)) {
        return 0;
    }
    
    /* Use bson_iter_find_descendant for proper nested field support
     * This handles both "field" and "parent.child.field" paths correctly */
    if (bson_iter_find_descendant(&parent_iter, field_path, iter)) {
        return 1;
    }
    
    return 0;
}

/**
 * verify_password - Verify user password against stored hash (thread-safe)
 * @plain_password: Password provided by user attempting to authenticate
 * @stored_hash: Password hash retrieved from MongoDB document
 * 
 * Returns: 1 if password matches, 0 if password doesn't match
 * 
 * This function uses the configured hash method (mongodb_password_hash_method)
 * to verify the password. For cryptographic methods (bcrypt, crypt, sha256, sha512),
 * the crypt_r() function (thread-safe) automatically detects the hash format from
 * the stored_hash prefix ($2b$ for bcrypt, $5$ for SHA-256, $6$ for SHA-512, etc.).
 * 
 * SECURITY: Uses thread-safe crypt_r() to prevent race conditions during concurrent
 * authentication attempts.
 */
static int verify_password(const char *plain_password, const char *stored_hash) {
    char *hashed = NULL;
    int result = 0;
    
    switch (mongodb_password_hash_method) {
        case HASH_METHOD_PLAIN:
            /* Plain text comparison - WARNING: NOT SECURE, for testing only */
            /* Use constant-time comparison even for plain text to prevent timing attacks */
            {
                size_t plain_len = strlen(plain_password);
                size_t stored_len = strlen(stored_hash);
                size_t max_len = (plain_len > stored_len) ? plain_len : stored_len;
                
                if (max_len > MAX_PASSWORD_LENGTH) {
                    pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                               ": Password length exceeds maximum (%zu > %d)", 
                               max_len, MAX_PASSWORD_LENGTH);
                    result = 0;
                } else if (plain_len != stored_len) {
                    /* Lengths differ - still do constant-time comparison to avoid timing leak */
                    char dummy[MAX_PASSWORD_LENGTH];
                    memset(dummy, 0, sizeof(dummy));
                    constant_time_compare(plain_password, dummy, plain_len);
                    result = 0;
                } else {
                    result = (constant_time_compare(plain_password, stored_hash, plain_len) == 0);
                }
                
                if (mongodb_debug_logging) {
                    pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                               " (plain): Password comparison %s", 
                               result ? "matched" : "failed");
                }
            }
            break;
            
        case HASH_METHOD_BCRYPT:
        case HASH_METHOD_CRYPT:
        case HASH_METHOD_SHA256:
        case HASH_METHOD_SHA512:
            /* Use crypt_r() for thread-safe password hashing */
            /* The hash format is detected automatically from the stored hash */
            /* bcrypt: $2b$10$... or $2y$10$... */
            /* SHA-256: $5$... */
            /* SHA-512: $6$... */
            /* DES/MD5 crypt: other formats */
#if defined(_GNU_SOURCE) || defined(__linux__)
            /* Thread-safe version available on Linux/GNU systems */
            struct crypt_data data;
            data.initialized = 0;
            hashed = crypt_r(plain_password, stored_hash, &data);
#else
            /* Fallback to non-thread-safe version on other platforms */
            /* WARNING: This may cause race conditions with concurrent logins */
            pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                       ": Using non-thread-safe crypt() - consider upgrading to Linux");
            hashed = crypt(plain_password, stored_hash);
#endif
            if (hashed == NULL) {
                pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                           ": crypt() failed for password verification");
                result = 0;
            } else {
                result = (strcmp(hashed, stored_hash) == 0);
                if (mongodb_debug_logging) {
                    const char *method_name = "unknown";
                    if (strncmp(stored_hash, "$2a$", 4) == 0 || 
                        strncmp(stored_hash, "$2b$", 4) == 0 || 
                        strncmp(stored_hash, "$2y$", 4) == 0) {
                        method_name = "bcrypt";
                    } else if (strncmp(stored_hash, "$6$", 3) == 0) {
                        method_name = "sha512-crypt";
                    } else if (strncmp(stored_hash, "$5$", 3) == 0) {
                        method_name = "sha256-crypt";
                    } else {
                        method_name = "crypt";
                    }
                    pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                               " (%s): Password comparison %s", 
                               method_name, result ? "matched" : "failed");
                }
            }
            break;
            
        default:
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       " : Unknown hash method: %d", mongodb_password_hash_method);
            result = 0;
            break;
    }
    
    return result;
}

/* ==============================================================================
 * MONGODB QUERY FUNCTIONS
 * ============================================================================== */

/**
 * query_mongodb_user - Query MongoDB for user document by username
 * @username: Username to search for
 * @client_out: Output parameter - MongoDB client handle (caller must destroy)
 * @collection_out: Output parameter - Collection handle (caller must destroy)
 * @cursor_out: Output parameter - Query cursor handle (caller must destroy)
 * 
 * Returns: Pointer to BSON document if user found, NULL if not found or error
 * 
 * This function establishes a MongoDB connection, queries for a user document
 * matching the username field, and returns the document. The caller is responsible
 * for cleaning up the returned MongoDB resources (client, collection, cursor).
 * 
 * IMPORTANT: The returned document pointer is only valid while the cursor exists.
 * Copy any needed data before destroying the cursor.
 */
static const bson_t* query_mongodb_user(const char *username, mongoc_client_t **client_out,
                                        mongoc_collection_t **collection_out,
                                        mongoc_cursor_t **cursor_out) {
    mongoc_client_t *client = NULL;
    mongoc_database_t *database = NULL;
    mongoc_collection_t *collection = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL;
    const bson_t *doc = NULL;
    bson_error_t error;
    
    /* Validate configuration */
    if (!mongodb_connection_string || !mongodb_database_name || 
        !mongodb_collection_name || !mongodb_field_username) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Missing required configuration directives");
        return NULL;
    }
    
    /* Check if connection pool is initialized */
    if (!mongodb_client_pool) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MongoDB connection pool not initialized");
        if (mongodb_error_noconnection) {
            pr_response_add_err(R_530, "%s", mongodb_error_noconnection);
        }
        return NULL;
    }
    
    /* Get client from connection pool (reuses existing connections) */
    client = mongoc_client_pool_pop(mongodb_client_pool);
    if (!client) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Failed to get MongoDB client from pool");
        if (mongodb_error_noconnection) {
            pr_response_add_err(R_530, "%s", mongodb_error_noconnection);
        }
        return NULL;
    }
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Connected to MongoDB, querying user '%s'", username);
    }
    
    /* Get database and collection */
    database = mongoc_client_get_database(client, mongodb_database_name);
    collection = mongoc_client_get_collection(client, mongodb_database_name, 
                                               mongodb_collection_name);
    
    /* Build query: { "username_field": "username" } */
    query = bson_new();
    BSON_APPEND_UTF8(query, mongodb_field_username, username);
    
    if (mongodb_debug_logging) {
        char *query_str = bson_as_canonical_extended_json(query, NULL);
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Query: %s", query_str);
        bson_free(query_str);
    }
    
    /* Execute query */
    cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);
    bson_destroy(query);
    mongoc_database_destroy(database);
    
    if (!cursor) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Failed to execute query");
        mongoc_collection_destroy(collection);
        /* CRITICAL FIX: Return client to pool instead of destroying it
         * Destroying would leak the connection and eventually exhaust the pool */
        mongoc_client_pool_push(mongodb_client_pool, client);
        if (mongodb_error_noconnection) {
            pr_response_add_err(R_530, "%s", mongodb_error_noconnection);
        }
        return NULL;
    }
    
    /* Check for errors */
    if (mongoc_cursor_error(cursor, &error)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MongoDB query error: %s", error.message);
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        /* SECURITY FIX: Return client to pool instead of destroying it */
        mongoc_client_pool_push(mongodb_client_pool, client);
        if (mongodb_error_noconnection) {
            pr_response_add_err(R_530, "%s", mongodb_error_noconnection);
        }
        return NULL;
    }
    
    /* Get first result */
    if (mongoc_cursor_next(cursor, &doc)) {
        if (mongodb_debug_logging) {
            char *doc_str = bson_as_canonical_extended_json(doc, NULL);
            pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                       ": Found user document: %s", doc_str);
            bson_free(doc_str);
        }
        
        /* Return resources to caller for cleanup */
        *client_out = client;
        *collection_out = collection;
        *cursor_out = cursor;
        return doc;
    }
    
    /* User not found */
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": User '%s' not found in MongoDB", username);
    }
    
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    /* Return client to pool instead of destroying it */
    mongoc_client_pool_push(mongodb_client_pool, client);
    return NULL;
}

/* ==============================================================================
 * PROFTPD AUTHENTICATION HANDLERS
 * ============================================================================== */

/**
 * auth_mongodb_getpwnam - ProFTPD getpwnam authentication handler
 * @cmd: Command record containing username in argv[0]
 * 
 * Returns: PR_DECLINED if user not found, or data structure with passwd info
 * 
 * This handler is called by ProFTPD to retrieve user account information.
 * It queries MongoDB for the user document and constructs a passwd structure
 * containing uid, gid, home directory, and other account details.
 * 
 * The passwd structure is allocated from session.pool and persists for the
 * duration of the FTP session.
 */
MODRET auth_mongodb_getpwnam(cmd_rec *cmd) {
    const char *username = NULL;
    const bson_t *doc = NULL;
    mongoc_client_t *client = NULL;
    mongoc_collection_t *collection = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;
    struct passwd *pw = NULL;
    const char *uid_str = NULL;
    const char *gid_str = NULL;
    const char *path_str = NULL;
    const char *password_str = NULL;
    uid_t uid = 0;
    gid_t gid = 0;
    size_t username_len = 0;
    
    username = cmd->argv[0];
    
    /* SECURITY: Validate username length to prevent potential overflow issues */
    if (!username) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION ": NULL username provided");
        return PR_DECLINED(cmd);
    }
    
    username_len = strlen(username);
    if (username_len == 0 || username_len >= MAX_USERNAME_LENGTH) {
        pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                   ": Invalid username length: %zu (max: %d)", 
                   username_len, MAX_USERNAME_LENGTH - 1);
        return PR_DECLINED(cmd);
    }
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": getpwnam called for user '%s'", username);
    }
    
    /* Check cache first - avoid duplicate MongoDB query */
    if (is_cache_valid(username)) {
        /* Use cached data */
        pw = pcalloc(session.pool, sizeof(struct passwd));
        pw->pw_name = pstrdup(session.pool, user_cache.username);
        pw->pw_uid = user_cache.uid;
        pw->pw_gid = user_cache.gid;
        pw->pw_dir = pstrdup(session.pool, user_cache.home_dir);
        pw->pw_shell = pstrdup(session.pool, "/bin/false");
        pw->pw_passwd = pstrdup(session.pool, "x");
        pw->pw_gecos = pstrdup(session.pool, "");
        
        if (mongodb_debug_logging) {
            pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                       ": Using cached data for user '%s'", username);
        }
        
        return mod_create_data(cmd, pw);
    }
    
    /* Cache miss - query MongoDB */
    doc = query_mongodb_user(username, &client, &collection, &cursor);
    if (!doc) {
        return PR_DECLINED(cmd);
    }
    
    /* Extract uid field with type checking and safe parsing */
    if (!find_bson_field(&iter, doc, mongodb_field_uid)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Missing uid field '%s' in user document", mongodb_field_uid);
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return PR_DECLINED(cmd);
    }
    
    /* Handle both string and numeric BSON types for uid */
    if (BSON_ITER_HOLDS_UTF8(&iter)) {
        unsigned long uid_val;
        uid_str = bson_iter_utf8(&iter, NULL);
        if (parse_uid_gid(uid_str, &uid_val, "uid") != 0) {
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
            return PR_DECLINED(cmd);
        }
        uid = (uid_t)uid_val;
    } else if (BSON_ITER_HOLDS_INT32(&iter)) {
        int32_t uid_val = bson_iter_int32(&iter);
        if (uid_val < 1) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Invalid uid value %d: must be >= 1", uid_val);
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
            return PR_DECLINED(cmd);
        }
        uid = (uid_t)uid_val;
    } else if (BSON_ITER_HOLDS_INT64(&iter)) {
        int64_t uid_val = bson_iter_int64(&iter);
        if (uid_val < 1 || uid_val > UINT_MAX) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Invalid uid value %lld: out of range", (long long)uid_val);
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
            return PR_DECLINED(cmd);
        }
        uid = (uid_t)uid_val;
    } else {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Invalid uid field type (expected string or integer)");
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return PR_DECLINED(cmd);
    }
    
    /* Extract gid field with type checking and safe parsing */
    if (!find_bson_field(&iter, doc, mongodb_field_gid)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Missing gid field '%s' in user document", mongodb_field_gid);
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return PR_DECLINED(cmd);
    }
    
    /* Handle both string and numeric BSON types for gid */
    if (BSON_ITER_HOLDS_UTF8(&iter)) {
        unsigned long gid_val;
        gid_str = bson_iter_utf8(&iter, NULL);
        if (parse_uid_gid(gid_str, &gid_val, "gid") != 0) {
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
            return PR_DECLINED(cmd);
        }
        gid = (gid_t)gid_val;
    } else if (BSON_ITER_HOLDS_INT32(&iter)) {
        int32_t gid_val = bson_iter_int32(&iter);
        if (gid_val < 1) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Invalid gid value %d: must be >= 1", gid_val);
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
            return PR_DECLINED(cmd);
        }
        gid = (gid_t)gid_val;
    } else if (BSON_ITER_HOLDS_INT64(&iter)) {
        int64_t gid_val = bson_iter_int64(&iter);
        if (gid_val < 1 || gid_val > UINT_MAX) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Invalid gid value %lld: out of range", (long long)gid_val);
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
            return PR_DECLINED(cmd);
        }
        gid = (gid_t)gid_val;
    } else {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Invalid gid field type (expected string or integer)");
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return PR_DECLINED(cmd);
    }
    
    /* Extract path field with type checking */
    if (!find_bson_field(&iter, doc, mongodb_field_path)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Missing path field '%s' in user document", mongodb_field_path);
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return PR_DECLINED(cmd);
    }
    
    if (!BSON_ITER_HOLDS_UTF8(&iter)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Invalid path field type (expected string)");
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return PR_DECLINED(cmd);
    }
    path_str = bson_iter_utf8(&iter, NULL);
    
    /* Extract password field for caching (but don't log it) */
    password_str = NULL;
    if (find_bson_field(&iter, doc, mongodb_field_password)) {
        if (BSON_ITER_HOLDS_UTF8(&iter)) {
            password_str = bson_iter_utf8(&iter, NULL);
        }
    }
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": User '%s' - uid=%d, gid=%d, path=%s", 
                   username, (int)uid, (int)gid, path_str);
    }
    
    /* Cache user data to avoid duplicate query in auth() */
    if (password_str) {
        cache_user_data(username, password_str, uid, gid, path_str);
    }
    
    /* Create passwd structure */
    pw = pcalloc(session.pool, sizeof(struct passwd));
    pw->pw_name = pstrdup(session.pool, username);
    pw->pw_uid = uid;
    pw->pw_gid = gid;
    pw->pw_dir = pstrdup(session.pool, path_str);
    pw->pw_shell = pstrdup(session.pool, "/bin/false");
    pw->pw_passwd = pstrdup(session.pool, "x");
    pw->pw_gecos = pstrdup(session.pool, "");
    
    /* Cleanup MongoDB resources and return client to pool */
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_pool_push(mongodb_client_pool, client);
    
    return mod_create_data(cmd, pw);
}

/**
 * auth_mongodb_auth - ProFTPD password authentication handler
 * @cmd: Command record with username in argv[0] and password in argv[1]
 * 
 * Returns: PR_HANDLED on successful auth, PR_ERROR_INT with PR_AUTH_BADPWD on failure
 * 
 * This handler verifies the user's password against the stored hash in MongoDB.
 * It queries for the user document, extracts the password field, and calls
 * verify_password() to check if the provided password matches.
 * 
 * On success, sets session.auth_mech to identify this module as the authenticator.
 * On failure, returns appropriate error response to the FTP client.
 */
MODRET auth_mongodb_auth(cmd_rec *cmd) {
    const char *username = NULL;
    const char *password = NULL;
    const bson_t *doc = NULL;
    mongoc_client_t *client = NULL;
    mongoc_collection_t *collection = NULL;
    mongoc_cursor_t *cursor = NULL;
    bson_iter_t iter;
    const char *stored_password = NULL;
    int using_cache = 0;
    size_t username_len = 0;
    
    username = cmd->argv[0];
    password = cmd->argv[1];
    
    /* SECURITY: Validate inputs */
    if (!username || !password) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": NULL username or password provided");
        if (mongodb_error_noauth) {
            pr_response_add_err(R_530, "%s", mongodb_error_noauth);
        }
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    
    username_len = strlen(username);
    if (username_len == 0 || username_len >= MAX_USERNAME_LENGTH) {
        pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                   ": Invalid username length: %zu (max: %d)", 
                   username_len, MAX_USERNAME_LENGTH - 1);
        if (mongodb_error_noauth) {
            pr_response_add_err(R_530, "%s", mongodb_error_noauth);
        }
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": auth called for user '%s'", username);
    }
    
    /* Check cache first - avoid duplicate MongoDB query */
    if (is_cache_valid(username)) {
        stored_password = user_cache.password_hash;
        using_cache = 1;
        
        if (mongodb_debug_logging) {
            pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                       ": Using cached password hash for user '%s'", username);
        }
    } else {
        /* Cache miss - query MongoDB */
        doc = query_mongodb_user(username, &client, &collection, &cursor);
        if (!doc) {
            invalidate_cache();  /* Ensure stale cache doesn't persist */
            if (mongodb_error_noauth) {
                pr_response_add_err(R_530, "%s", mongodb_error_noauth);
            }
            return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
        }
        
        /* Extract password field with type checking */
        if (!find_bson_field(&iter, doc, mongodb_field_password)) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Missing password field '%s' in user document", 
                       mongodb_field_password);
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
            invalidate_cache();
            if (mongodb_error_noauth) {
                pr_response_add_err(R_530, "%s", mongodb_error_noauth);
            }
            return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
        }
        
        if (!BSON_ITER_HOLDS_UTF8(&iter)) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Invalid password field type (expected string)");
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
            invalidate_cache();
            if (mongodb_error_noauth) {
                pr_response_add_err(R_530, "%s", mongodb_error_noauth);
            }
            return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
        }
        stored_password = bson_iter_utf8(&iter, NULL);
    }
    
    /* Verify password using configured hash method */
    if (!verify_password(password, stored_password)) {
        if (mongodb_debug_logging) {
            pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                       ": Password verification failed for user '%s'", username);
        }
        
        /* Clean up MongoDB resources if we queried */
        if (!using_cache) {
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_client_pool_push(mongodb_client_pool, client);
        }
        
        /* Invalidate cache on auth failure for security */
        invalidate_cache();
        
        if (mongodb_error_noauth) {
            pr_response_add_err(R_530, "%s", mongodb_error_noauth);
        }
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Authentication successful for user '%s'", username);
    }
    
    /* Cleanup MongoDB resources and return client to pool (if we queried) */
    if (!using_cache) {
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_pool_push(mongodb_client_pool, client);
    }
    
    session.auth_mech = MOD_AUTH_MONGODB_VERSION;
    return PR_HANDLED(cmd);
}

/* Authentication table */
static authtable auth_mongodb_authtab[] = {
    { 0, "getpwnam", auth_mongodb_getpwnam, NULL },
    { 0, "auth",     auth_mongodb_auth, NULL },
    { 0, NULL, NULL, NULL }
};

/* ==============================================================================
 * MODULE LIFECYCLE FUNCTIONS
 * ============================================================================== */

/**
 * auth_mongodb_sess_init - Session initialization callback
 * 
 * Returns: 0 on success
 * 
 * Called once per FTP session (when a client connects). This function retrieves
 * all configuration directive values from the ProFTPD config tree and stores them
 * in module-level static variables for use during authentication.
 * 
 * Configuration values are set by directives in proftpd.conf and stored in
 * main_server->conf during ProFTPD startup.
 */
static int auth_mongodb_sess_init(void) {
    config_rec *c = NULL;
    
    /* Retrieve configuration values */
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoConnectionString", FALSE);
    if (c) {
        mongodb_connection_string = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoDatabaseName", FALSE);
    if (c) {
        mongodb_database_name = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoAuthCollectionName", FALSE);
    if (c) {
        mongodb_collection_name = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoDocumentFieldUsername", FALSE);
    if (c) {
        mongodb_field_username = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoDocumentFieldPassword", FALSE);
    if (c) {
        mongodb_field_password = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoDocumentFieldUid", FALSE);
    if (c) {
        mongodb_field_uid = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoDocumentFieldGid", FALSE);
    if (c) {
        mongodb_field_gid = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoDocumentFieldPath", FALSE);
    if (c) {
        mongodb_field_path = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoNoAuthString", FALSE);
    if (c) {
        mongodb_error_noauth = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoNoConnectionString", FALSE);
    if (c) {
        mongodb_error_noconnection = (char *)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoDebugLogging", FALSE);
    if (c) {
        mongodb_debug_logging = (int)(long)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoPasswordHashMethod", FALSE);
    if (c) {
        mongodb_password_hash_method = (int)(long)c->argv[0];
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoConnectionPoolSize", FALSE);
    if (c) {
        mongodb_pool_size = (int)(long)c->argv[0];
    }
    
    /* Create connection pool if not already created (first session) */
    if (!mongodb_client_pool && mongodb_connection_string) {
        mongoc_uri_t *uri = NULL;
        bson_error_t error;
        
        pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
                   ": ===== INITIALIZING MONGODB CONNECTION =====");
        pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
                   ": Creating MongoDB connection pool...");
        
        /* Parse and validate connection URI */
        uri = mongoc_uri_new_with_error(mongodb_connection_string, &error);
        if (!uri) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Invalid MongoDB connection string: %s", error.message);
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Please check your AuthMongoConnectionString directive");
            return -1;
        }
        
        /* Create connection pool with reasonable limits */
        mongodb_client_pool = mongoc_client_pool_new(uri);
        mongoc_uri_destroy(uri);
        
        if (!mongodb_client_pool) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Failed to create MongoDB connection pool");
            return -1;
        }
        
        /* Set pool options for better performance and reliability */
        mongoc_client_pool_set_error_api(mongodb_client_pool, MONGOC_ERROR_API_VERSION_2);
        mongoc_client_pool_max_size(mongodb_client_pool, (uint32_t)mongodb_pool_size);
        
        pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
                   ": Connection pool created (max size: %d)", mongodb_pool_size);
        
        /* Validate configuration with comprehensive readiness checks */
        if (validate_mongodb_configuration() != 0) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": ===== READINESS CHECK FAILED =====");
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Module will NOT work until issues are resolved");
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": Please check error messages above and fix configuration");
            /* Don't fail startup completely - allow ProFTPD to start
             * but log prominent errors so admins know auth won't work */
            pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                       ": All authentication attempts will FAIL until MongoDB is accessible");
        }
    }
    
    if (mongodb_debug_logging) {
        const char *method_name = "unknown";
        switch (mongodb_password_hash_method) {
            case HASH_METHOD_PLAIN: method_name = "plain"; break;
            case HASH_METHOD_BCRYPT: method_name = "bcrypt"; break;
            case HASH_METHOD_CRYPT: method_name = "crypt"; break;
            case HASH_METHOD_SHA256: method_name = "sha256"; break;
            case HASH_METHOD_SHA512: method_name = "sha512"; break;
        }
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Session initialized with MongoDB configuration (hash method: %s)", 
                   method_name);
    }
    
    return 0;
}

/**
 * auth_mongodb_sess_cleanup - Session cleanup callback
 * @event_data: Event-specific data (unused)
 * @user_data: User-provided data (unused)
 * 
 * Called when an FTP session ends (client disconnects). This function
 * invalidates the user cache to prevent sensitive data from persisting
 * in memory after the session ends.
 * 
 * SECURITY: Critical for preventing information leakage between sessions.
 */
static void auth_mongodb_sess_cleanup(const void *event_data, void *user_data) {
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Session cleanup - invalidating cache");
    }
    
    /* Clear sensitive cached data */
    invalidate_cache();
}

/**
 * validate_mongodb_configuration - Test MongoDB connection and validate config
 * 
 * Returns: 0 on success, -1 on failure
 * 
 * This function performs comprehensive readiness checks at startup:
 * 1. Validates configuration completeness (all required directives set)
 * 2. Tests MongoDB server connectivity (ping)
 * 3. Verifies database exists and is accessible
 * 4. Verifies authentication collection exists
 * 5. Tests a sample query on the collection
 * 
 * Called during first session initialization (when connection pool is created)
 * to fail fast if configuration is invalid. All failures are logged to ProFTPD's
 * SystemLog for easy troubleshooting.
 */
static int validate_mongodb_configuration(void) {
    mongoc_client_t *client = NULL;
    mongoc_database_t *database = NULL;
    mongoc_collection_t *collection = NULL;
    bson_t *ping_cmd = NULL;
    bson_t *list_collections_cmd = NULL;
    bson_t reply;
    bson_error_t error;
    int success = 0;
    int validation_failed = 0;
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": Starting configuration readiness checks...");
    
    /* ===== STEP 1: Validate configuration completeness ===== */
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [1/5] Checking configuration directives...");
    
    if (!mongodb_connection_string) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MISSING REQUIRED DIRECTIVE: AuthMongoConnectionString");
        validation_failed = 1;
    }
    if (!mongodb_database_name) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MISSING REQUIRED DIRECTIVE: AuthMongoDatabaseName");
        validation_failed = 1;
    }
    if (!mongodb_collection_name) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MISSING REQUIRED DIRECTIVE: AuthMongoAuthCollectionName");
        validation_failed = 1;
    }
    if (!mongodb_field_username) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MISSING REQUIRED DIRECTIVE: AuthMongoDocumentFieldUsername");
        validation_failed = 1;
    }
    if (!mongodb_field_password) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MISSING REQUIRED DIRECTIVE: AuthMongoDocumentFieldPassword");
        validation_failed = 1;
    }
    if (!mongodb_field_uid) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MISSING REQUIRED DIRECTIVE: AuthMongoDocumentFieldUid");
        validation_failed = 1;
    }
    if (!mongodb_field_gid) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MISSING REQUIRED DIRECTIVE: AuthMongoDocumentFieldGid");
        validation_failed = 1;
    }
    if (!mongodb_field_path) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": MISSING REQUIRED DIRECTIVE: AuthMongoDocumentFieldPath");
        validation_failed = 1;
    }
    
    if (validation_failed) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Configuration validation FAILED - see errors above");
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Please add all required directives to proftpd.conf");
        return -1;
    }
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [1/5] Configuration directives OK");
    
    /* ===== STEP 2: Validate connection pool ===== */
    if (!mongodb_client_pool) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Connection pool not initialized");
        return -1;
    }
    
    /* Get a client from the pool for readiness tests */
    client = mongoc_client_pool_pop(mongodb_client_pool);
    if (!client) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Failed to get client from pool for validation");
        return -1;
    }
    
    /* ===== STEP 3: Test MongoDB server connectivity ===== */
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [2/5] Testing MongoDB server connectivity...");
    
    ping_cmd = BCON_NEW("ping", BCON_INT32(1));
    success = mongoc_client_command_simple(client, "admin", ping_cmd, NULL, &reply, &error);
    
    bson_destroy(ping_cmd);
    bson_destroy(&reply);
    
    if (!success) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": [2/5] MongoDB server connectivity FAILED: %s", error.message);
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Please verify MongoDB server is running and accessible");
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Connection string: %s", mongodb_connection_string);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return -1;
    }
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [2/5] MongoDB server connectivity OK");
    
    /* ===== STEP 4: Verify database exists ===== */
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [3/5] Verifying database '%s' exists...", mongodb_database_name);
    
    database = mongoc_client_get_database(client, mongodb_database_name);
    if (!database) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": [3/5] Failed to access database '%s'", mongodb_database_name);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return -1;
    }
    
    /* Test database accessibility with a listCollections command */
    list_collections_cmd = BCON_NEW("listCollections", BCON_INT32(1), 
                                    "nameOnly", BCON_BOOL(true));
    success = mongoc_database_command_simple(database, list_collections_cmd, 
                                            NULL, &reply, &error);
    bson_destroy(list_collections_cmd);
    
    if (!success) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": [3/5] Database '%s' not accessible: %s", 
                   mongodb_database_name, error.message);
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Please verify database exists and credentials are correct");
        bson_destroy(&reply);
        mongoc_database_destroy(database);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return -1;
    }
    
    bson_destroy(&reply);
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [3/5] Database '%s' OK", mongodb_database_name);
    
    /* ===== STEP 5: Verify collection exists ===== */
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [4/5] Verifying collection '%s' exists...", mongodb_collection_name);
    
    collection = mongoc_database_get_collection(database, mongodb_collection_name);
    if (!collection) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": [4/5] Failed to access collection '%s'", mongodb_collection_name);
        mongoc_database_destroy(database);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return -1;
    }
    
    /* Verify collection actually exists by attempting a count */
    bson_t *count_query = bson_new();
    int64_t doc_count = mongoc_collection_count_documents(collection, count_query, 
                                                          NULL, NULL, NULL, &error);
    bson_destroy(count_query);
    
    if (doc_count < 0) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": [4/5] Collection '%s' not accessible: %s", 
                   mongodb_collection_name, error.message);
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Please verify collection exists in database '%s'", 
                   mongodb_database_name);
        mongoc_collection_destroy(collection);
        mongoc_database_destroy(database);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return -1;
    }
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [4/5] Collection '%s' OK (contains %lld documents)", 
               mongodb_collection_name, (long long)doc_count);
    
    if (doc_count == 0) {
        pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                   ": WARNING: Collection '%s' is EMPTY - no users can authenticate", 
                   mongodb_collection_name);
    }
    
    /* ===== STEP 6: Test sample query ===== */
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": [5/5] Testing sample query on collection...");
    
    /* Attempt to query for a document with the configured username field
     * This validates that the field mapping is correct and queries work */
    bson_t *test_query = BCON_NEW(mongodb_field_username, "{", "$exists", BCON_BOOL(true), "}");
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(collection, test_query, 
                                                                NULL, NULL);
    
    if (!cursor) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": [5/5] Failed to execute test query on collection");
        bson_destroy(test_query);
        mongoc_collection_destroy(collection);
        mongoc_database_destroy(database);
        mongoc_client_pool_push(mongodb_client_pool, client);
        return -1;
    }
    
    /* Try to fetch one document to validate query works */
    const bson_t *doc;
    if (mongoc_cursor_next(cursor, &doc)) {
        /* Successfully retrieved a document - validation passed */
        pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
                   ": [5/5] Sample query OK - collection is queryable");
    } else {
        /* Check if there was an error or just no documents matched */
        if (mongoc_cursor_error(cursor, &error)) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                       ": [5/5] Test query failed: %s", error.message);
            bson_destroy(test_query);
            mongoc_cursor_destroy(cursor);
            mongoc_collection_destroy(collection);
            mongoc_database_destroy(database);
            mongoc_client_pool_push(mongodb_client_pool, client);
            return -1;
        } else {
            /* No error, just no documents with username field */
            pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                       ": WARNING: No documents found with field '%s'", 
                       mongodb_field_username);
            pr_log_pri(PR_LOG_WARNING, MOD_AUTH_MONGODB_VERSION 
                       ": Please verify your AuthMongoDocumentFieldUsername setting");
        }
    }
    
    /* Cleanup test query resources */
    bson_destroy(test_query);
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_database_destroy(database);
    mongoc_client_pool_push(mongodb_client_pool, client);
    
    /* ===== All validation checks passed ===== */
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": ===== READINESS CHECK PASSED - Module is ready =====");
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": Server: %s", mongodb_connection_string);
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": Database: %s", mongodb_database_name);
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": Collection: %s", mongodb_collection_name);
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION 
               ": Username field: %s", mongodb_field_username);
    
    return 0;
}

/**
 * auth_mongodb_init - Module initialization callback
 * 
 * Returns: 0 on success, -1 on failure
 * 
 * Called once when ProFTPD starts up (before any sessions). Initializes the
 * MongoDB C driver and creates a connection pool for efficient connection reuse.
 * This is a process-wide initialization that validates configuration early.
 */
static int auth_mongodb_init(void) {
    /* Initialize MongoDB driver */
    mongoc_init();
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION ": Module initialized");
    
    /* Register event handlers for cleanup */
    pr_event_register(&auth_mongodb_module, "core.exit", auth_mongodb_sess_cleanup, NULL);
    pr_event_register(&auth_mongodb_module, "core.shutdown", auth_mongodb_module_cleanup, NULL);
    
    /* Note: Connection pool will be created in sess_init after config is loaded */
    
    return 0;
}

/**
 * auth_mongodb_module_cleanup - Module cleanup callback
 * @event_data: Event-specific data (unused)
 * @user_data: User-provided data (unused)
 * 
 * Called when ProFTPD is shutting down. This function destroys the MongoDB
 * connection pool and performs cleanup of the MongoDB C driver.
 * 
 * IMPORTANT: Prevents memory leaks on server restart/shutdown.
 */
static void auth_mongodb_module_cleanup(const void *event_data, void *user_data) {
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION ": Module cleanup starting");
    
    /* Destroy connection pool if it exists */
    if (mongodb_client_pool) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Destroying MongoDB connection pool");
        mongoc_client_pool_destroy(mongodb_client_pool);
        mongodb_client_pool = NULL;
    }
    
    /* Cleanup MongoDB driver */
    mongoc_cleanup();
    
    /* Securely wipe cache */
    invalidate_cache();
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION ": Module cleanup complete");
}

/* ==============================================================================
 * MODULE DEFINITION STRUCTURE
 * 
 * This structure registers the module with ProFTPD and defines all hooks,
 * handlers, and metadata. ProFTPD uses this structure to integrate the
 * module into its authentication chain.
 * ============================================================================== */
module auth_mongodb_module = {
    NULL, NULL,                     /* Always NULL (reserved for internal use) */
    0x20,                           /* API version 2.0 (ProFTPD module API) */
    "auth_mongodb",                 /* Module name (used in logs and directives) */
    auth_mongodb_conftab,           /* Configuration directive handlers */
    NULL,                           /* Command handlers (FTP commands - not used) */
    auth_mongodb_authtab,           /* Authentication handlers (getpwnam, auth) */
    auth_mongodb_init,              /* Module initialization (called at startup) */
    auth_mongodb_sess_init,         /* Session initialization (called per connection) */
    MOD_AUTH_MONGODB_VERSION        /* Module version string */
};
