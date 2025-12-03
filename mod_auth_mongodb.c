/*
 * ProFTPD MongoDB Authentication Module
 * Copyright (c) 2025
 *
 * This module provides authentication against a MongoDB database.
 */

#include "conf.h"
#include "privs.h"
#include <mongoc/mongoc.h>
#include <bson/bson.h>
#include <crypt.h>
#include <string.h>

#define MOD_AUTH_MONGODB_VERSION "mod_auth_mongodb/1.0"

/* Password hash methods */
#define HASH_METHOD_PLAIN   0
#define HASH_METHOD_BCRYPT  1
#define HASH_METHOD_CRYPT   2
#define HASH_METHOD_SHA256  3
#define HASH_METHOD_SHA512  4

/* Module configuration structure */
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

/* Configuration directive handlers */
MODRET set_mongodb_connection_string(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_mongodb_database_name(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);
    
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

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

/* Helper function to verify password based on configured hash method */
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

/* Helper function to query MongoDB and return user document */
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

/* Authentication handler: getpwnam */
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

/* Authentication handler: auth */
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

/* Session initialization */
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

/* Module initialization */
static int auth_mongodb_init(void) {
    /* Initialize MongoDB driver */
    mongoc_init();
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION ": Module initialized");
    
    return 0;
}

/* Module cleanup */
static void auth_mongodb_cleanup(void) {
    /* Cleanup MongoDB driver */
    mongoc_cleanup();
    
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_MONGODB_VERSION ": Module cleanup complete");
}

/* Module definition */
module auth_mongodb_module = {
    NULL, NULL,                     /* Always NULL */
    0x20,                           /* API version 2.0 */
    "auth_mongodb",                 /* Module name */
    auth_mongodb_conftab,           /* Configuration handlers */
    NULL,                           /* Command handlers */
    auth_mongodb_authtab,           /* Authentication handlers */
    auth_mongodb_init,              /* Module initialization */
    auth_mongodb_sess_init,         /* Session initialization */
    MOD_AUTH_MONGODB_VERSION        /* Module version */
};
