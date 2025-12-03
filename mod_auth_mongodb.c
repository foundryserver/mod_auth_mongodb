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

#define MOD_AUTH_MONGODB_VERSION "mod_auth_mongodb/1.0"

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

module auth_mongodb_module;

/* Forward declarations */
static int auth_mongodb_sess_init(void);
static void auth_mongodb_cleanup(void);

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
 */
MODRET set_mongodb_connection_string(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
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
    { NULL, NULL, NULL }
};

/* ==============================================================================
 * PASSWORD VERIFICATION FUNCTIONS
 * ============================================================================== */

/**
 * verify_password - Verify user password against stored hash
 * @plain_password: Password provided by user attempting to authenticate
 * @stored_hash: Password hash retrieved from MongoDB document
 * 
 * Returns: 1 if password matches, 0 if password doesn't match
 * 
 * This function uses the configured hash method (mongodb_password_hash_method)
 * to verify the password. For cryptographic methods (bcrypt, crypt, sha256, sha512),
 * the crypt() function automatically detects the hash format from the stored_hash
 * prefix ($2b$ for bcrypt, $5$ for SHA-256, $6$ for SHA-512, etc.).
 */
static int verify_password(const char *plain_password, const char *stored_hash) {
    char *hashed = NULL;
    int result = 0;
    
    switch (mongodb_password_hash_method) {
        case HASH_METHOD_PLAIN:
            /* Plain text comparison */
            result = (strcmp(plain_password, stored_hash) == 0);
            if (mongodb_debug_logging) {
                pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                           " (plain): Password comparison %s", 
                           result ? "matched" : "failed");
            }
            break;
            
        case HASH_METHOD_BCRYPT:
        case HASH_METHOD_CRYPT:
        case HASH_METHOD_SHA256:
        case HASH_METHOD_SHA512:
            /* Use crypt() for bcrypt, traditional crypt, and SHA variants */
            /* The hash format is detected automatically from the stored hash */
            /* bcrypt: $2b$10$... or $2y$10$... */
            /* SHA-256: $5$... */
            /* SHA-512: $6$... */
            /* DES/MD5 crypt: other formats */
            hashed = crypt(plain_password, stored_hash);
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
    mongoc_uri_t *uri = NULL;
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
    
    /* Parse MongoDB URI */
    uri = mongoc_uri_new_with_error(mongodb_connection_string, &error);
    if (!uri) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Failed to parse MongoDB URI: %s", error.message);
        if (mongodb_error_noconnection) {
            pr_response_add_err(R_530, "%s", mongodb_error_noconnection);
        }
        return NULL;
    }
    
    /* Create MongoDB client */
    client = mongoc_client_new_from_uri(uri);
    if (!client) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Failed to create MongoDB client");
        mongoc_uri_destroy(uri);
        if (mongodb_error_noconnection) {
            pr_response_add_err(R_530, "%s", mongodb_error_noconnection);
        }
        return NULL;
    }
    mongoc_uri_destroy(uri);
    
    mongoc_client_set_error_api(client, 2);
    
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
        mongoc_client_destroy(client);
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
        mongoc_client_destroy(client);
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
    mongoc_client_destroy(client);
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
    uid_t uid = 0;
    gid_t gid = 0;
    
    username = cmd->argv[0];
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": getpwnam called for user '%s'", username);
    }
    
    /* Query MongoDB */
    doc = query_mongodb_user(username, &client, &collection, &cursor);
    if (!doc) {
        return PR_DECLINED(cmd);
    }
    
    /* Extract uid field */
    if (!bson_iter_init_find(&iter, doc, mongodb_field_uid)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Missing uid field '%s' in user document", mongodb_field_uid);
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        return PR_DECLINED(cmd);
    }
    uid_str = bson_iter_utf8(&iter, NULL);
    uid = (uid_t)atoi(uid_str);
    
    /* Extract gid field */
    if (!bson_iter_init_find(&iter, doc, mongodb_field_gid)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Missing gid field '%s' in user document", mongodb_field_gid);
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        return PR_DECLINED(cmd);
    }
    gid_str = bson_iter_utf8(&iter, NULL);
    gid = (gid_t)atoi(gid_str);
    
    /* Extract path field */
    if (!bson_iter_init_find(&iter, doc, mongodb_field_path)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Missing path field '%s' in user document", mongodb_field_path);
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        return PR_DECLINED(cmd);
    }
    path_str = bson_iter_utf8(&iter, NULL);
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": User '%s' - uid=%s, gid=%s, path=%s", 
                   username, uid_str, gid_str, path_str);
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
    
    /* Cleanup MongoDB resources */
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_destroy(client);
    
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
    
    username = cmd->argv[0];
    password = cmd->argv[1];
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": auth called for user '%s'", username);
    }
    
    /* Query MongoDB */
    doc = query_mongodb_user(username, &client, &collection, &cursor);
    if (!doc) {
        if (mongodb_error_noauth) {
            pr_response_add_err(R_530, "%s", mongodb_error_noauth);
        }
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    
    /* Extract password field */
    if (!bson_iter_init_find(&iter, doc, mongodb_field_password)) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_MONGODB_VERSION 
                   ": Missing password field '%s' in user document", 
                   mongodb_field_password);
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        if (mongodb_error_noauth) {
            pr_response_add_err(R_530, "%s", mongodb_error_noauth);
        }
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    stored_password = bson_iter_utf8(&iter, NULL);
    
    /* Verify password using configured hash method */
    if (!verify_password(password, stored_password)) {
        if (mongodb_debug_logging) {
            pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                       ": Password verification failed for user '%s'", username);
        }
        mongoc_cursor_destroy(cursor);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        if (mongodb_error_noauth) {
            pr_response_add_err(R_530, "%s", mongodb_error_noauth);
        }
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    
    if (mongodb_debug_logging) {
        pr_log_pri(PR_LOG_DEBUG, MOD_AUTH_MONGODB_VERSION 
                   ": Authentication successful for user '%s'", username);
    }
    
    /* Cleanup MongoDB resources */
    mongoc_cursor_destroy(cursor);
    mongoc_collection_destroy(collection);
    mongoc_client_destroy(client);
    
    session.auth_mech = MOD_AUTH_MONGODB_VERSION;
    return PR_HANDLED(cmd);
}

/* Authentication table */
static authtable auth_mongodb_authtab[] = {
    { 0, "getpwnam", auth_mongodb_getpwnam },
    { 0, "auth",     auth_mongodb_auth },
    { 0, NULL, NULL }
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
        mongodb_debug_logging = *((int *)c->argv[0]);
    }
    
    c = find_config(main_server->conf, CONF_PARAM, "AuthMongoPasswordHashMethod", FALSE);
    if (c) {
        mongodb_password_hash_method = *((int *)c->argv[0]);
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
 * auth_mongodb_init - Module initialization callback
 * 
 * Returns: 0 on success
 * 
 * Called once when ProFTPD starts up (before any sessions). Initializes the
 * MongoDB C driver which must be done before any MongoDB operations can occur.
 * This is a process-wide initialization.
 */
static int auth_mongodb_init(void) {
    /* Initialize MongoDB driver */
    mongoc_init();
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION ": Module initialized");
    
    return 0;
}

/**
 * auth_mongodb_cleanup - Module cleanup callback
 * 
 * Called when ProFTPD shuts down. Cleans up the MongoDB C driver and releases
 * any global resources. This is a process-wide cleanup.
 */
static void auth_mongodb_cleanup(void) {
    /* Cleanup MongoDB driver */
    mongoc_cleanup();
    
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
