# ProFTPD MongoDB Authentication Module

A ProFTPD authentication module that authenticates users against a MongoDB database, supporting multiple password hashing methods (bcrypt, SHA-256/512, crypt) with user chroot jailing to their home directories.

## Features

- ✅ MongoDB-based authentication (supports replica sets)
- ✅ Multiple password hashing methods (bcrypt, SHA-256, SHA-512, crypt, plain)
- ✅ **Connection pooling** for high-performance concurrent authentication
- ✅ **Thread-safe password verification** using `crypt_r()` on Linux
- ✅ **Strict input validation** prevents uid/gid exploits (no uid 0 attacks)
- ✅ **BSON type safety** - handles string and numeric uid/gid formats
- ✅ **Startup configuration validation** - fails fast with clear error messages
- ✅ Automatic user chroot jailing to home directory
- ✅ Per-user uid/gid from MongoDB
- ✅ Configurable field names (flexible MongoDB schema)
- ✅ Custom error messages for clients
- ✅ Debug logging for troubleshooting
- ✅ Dynamic loading as DSO module (no ProFTPD recompilation needed)
- ✅ FTP and SFTP support

## Security Notice

This module has been hardened for production use with the following security measures:

- **Thread-safe authentication** prevents race conditions during concurrent logins
- **Connection pooling** (max 10 connections) prevents resource exhaustion
- **Input validation** on all uid/gid values prevents privilege escalation attacks
- **BSON type checking** prevents type confusion vulnerabilities
- **Compiled with security flags**: stack protection, buffer overflow detection, RELRO, immediate binding
- **Startup validation** ensures configuration is correct before accepting connections

**Recommended deployment practices:**

- Use **bcrypt** for password hashing (not plain text)
- Store uid/gid values >= 1 (never 0 for root)
- Use MongoDB authentication and SSL/TLS for connections
- Enable debug logging initially to verify correct operation
- Monitor logs for authentication failures

## Documentation

- **[CHANGELOG.md](CHANGELOG.md)** - Version history and release notes
- **[SECURITY_IMPROVEMENTS.md](SECURITY_IMPROVEMENTS.md)** - Detailed technical security improvements
- **[MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)** - Upgrading from v1.0 to v1.1
- **[AI_DISCLOSURE.md](AI_DISCLOSURE.md)** - Full transparency about AI assistance in development
- **[proftpd.conf.sample](proftpd.conf.sample)** - Complete configuration example

## Quick Start

### 1. Install Prerequisites

**Debian/Ubuntu:**

```bash
sudo apt-get install libmongoc-dev libbson-dev proftpd-dev pkg-config build-essential
```

**RHEL/CentOS:**

```bash
sudo yum install mongo-c-driver-devel proftpd-devel pkgconfig gcc
```

### 2. Build ProFTPD with DSO Support

```bash
./configure \
    --sysconfdir=/etc/proftpd \
    --disable-ident \
    --enable-dso \
    --with-modules=mod_tls:mod_sftp
make
sudo make install
```

### 3. Build the MongoDB Module

**Option A: Using prxs (recommended):**

```bash
prxs -c -i -d \
  $(pkg-config --cflags libmongoc-1.0) \
  $(pkg-config --libs libmongoc-1.0) \
  mod_auth_mongodb.c
```

**Option B: Using Makefile:**

```bash
make
sudo cp mod_auth_mongodb.so /usr/local/libexec/
```

## Configuration Directives

All directives are configured in `proftpd.conf`. See `proftpd.conf.sample` for a fully documented example.

| Directive                        | Required | Description                                                 | Example                                              |
| -------------------------------- | -------- | ----------------------------------------------------------- | ---------------------------------------------------- |
| `AuthMongoConnectionString`      | ✅       | MongoDB connection URI (supports replica sets)              | `"mongodb://user:pass@host:27017/?authSource=admin"` |
| `AuthMongoDatabaseName`          | ✅       | Database name containing user collection                    | `"authentication"`                                   |
| `AuthMongoAuthCollectionName`    | ✅       | Collection name with user documents                         | `"users"`                                            |
| `AuthMongoDocumentFieldUsername` | ✅       | Field name for username                                     | `"username"`                                         |
| `AuthMongoDocumentFieldPassword` | ✅       | Field name for password/hash                                | `"password"`                                         |
| `AuthMongoDocumentFieldUid`      | ✅       | Field name for user ID (string)                             | `"uid"`                                              |
| `AuthMongoDocumentFieldGid`      | ✅       | Field name for group ID (string)                            | `"gid"`                                              |
| `AuthMongoDocumentFieldPath`     | ✅       | Field name for home directory path                          | `"home_directory"`                                   |
| `AuthMongoPasswordHashMethod`    | ❌       | Hash method: `plain`, `bcrypt`, `crypt`, `sha256`, `sha512` | `bcrypt` (default: `plain`)                          |
| `AuthMongoNoAuthString`          | ❌       | Error message for failed authentication                     | `"Your username/password is incorrect"`              |
| `AuthMongoNoConnectionString`    | ❌       | Error message for connection failures                       | `"Failed to connect to Authentication Server"`       |
| `AuthMongoDebugLogging`          | ❌       | Enable debug logging (`yes`/`no`)                           | `yes` (default: `no`)                                |

### MongoDB Connection URI Examples

**Single server:**

```
mongodb://user:pass@localhost:27017/?authSource=admin
```

**Replica set with authentication:**

```
mongodb://user:pass@mongo1.vm.lan:27017,mongo2.vm.lan:27017,mongo3.vm.lan:27017/?replicaSet=rs0&authSource=admin&authMechanism=SCRAM-SHA-256&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000
```

**No authentication:**

```
mongodb://localhost:27017/
```

These values would be configured in proftpd.conf.

### Proftpd Related Settings.

AuthMongoConnectionString: (connection string url to mondo db)
AuthMongoNoAuthString: "Your username/password is incorrect"
AuthMongoNoConnectionString: "Failed to connect to Authentication Server"

### Specific Mongo Collection/Document Settings

AuthMongoAuthCollectionName: ( name of the collection to authenticate against )
AuthMongoDocumentFieldUsername: (name of the document field to authenticate against)
AuthMongoDocumentFieldPassword: (name of the document field to authenticate against)
AuthMongoDocumentFieldUid: ( name of the document field to get the uid)
AuthMongoDocumentFieldGid: ( name of the document field to get the gid)
AuthMongoDocumentFieldPath: ( name of the document field to get the path to the user data)
AuthMongoPasswordHashMethod: ( password hash method: plain, bcrypt, crypt, sha256, sha512 )

### Sample Connection Uri:

```
mongodb://username:password@mongo1.vm.lan:27017,mongo2.vm.lan:27017,mongo3.vm.lan:27017/?retryWrites=true&loadBalanced=false&replicaSet=rs0&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256
```

## Configuration

See `proftpd.conf.sample` for a complete example. Key directives:

```apache
LoadModule mod_auth_mongodb.so

# Connection settings
AuthMongoConnectionString "mongodb://user:pass@host:27017/..."
AuthMongoDatabaseName "authentication"
AuthMongoAuthCollectionName "users"

# Field mappings
AuthMongoDocumentFieldUsername "username"
AuthMongoDocumentFieldPassword "password"
AuthMongoDocumentFieldUid "uid"
AuthMongoDocumentFieldGid "gid"
AuthMongoDocumentFieldPath "home_directory"

# Error messages
AuthMongoNoAuthString "Your username/password is incorrect"
AuthMongoNoConnectionString "Failed to connect to Authentication Server"

# Password hashing method
AuthMongoPasswordHashMethod bcrypt

# Debug logging
AuthMongoDebugLogging yes

# Use only MongoDB authentication
AuthOrder mod_auth_mongodb.c
```

## MongoDB Document Schema

Your MongoDB collection should contain documents with the following structure:

**With bcrypt (Recommended):**

```json
{
  "_id": ObjectId("..."),
  "username": "testuser",
  "password": "$2b$10$N9qo8uLOickgx2ZMRZoMye.Ik3JSk5U5p7L6Km1hp7RmWfXfGOIJy",
  "uid": "1001",
  "gid": "1001",
  "home_directory": "/home/testuser"
}
```

**With plain text (Not recommended):**

```json
{
  "_id": ObjectId("..."),
  "username": "testuser",
  "password": "testpassword",
  "uid": "1001",
  "gid": "1001",
  "home_directory": "/home/testuser"
}
```

**Important Notes:**

- `password` format depends on `AuthMongoPasswordHashMethod`:
  - **bcrypt**: Hash from Node.js bcrypt (e.g., `$2b$10$...`) - **RECOMMENDED**
  - **sha512**: SHA-512 crypt hash (e.g., `$6$...`)
  - **sha256**: SHA-256 crypt hash (e.g., `$5$...`)
  - **crypt**: Traditional Unix crypt hash
  - **plain**: Plain text password (not secure)
- `uid` and `gid` can be stored as **strings** (e.g., `"1001"`) or **integers** (e.g., `1001`)
  - Must be >= 1 (values < 1 are rejected to prevent root access)
  - Validated at runtime with range checking
- `home_directory` should be an absolute path (string)
- All fields must be present for authentication to succeed

### Generating Password Hashes

**Using Node.js (bcrypt):**

```javascript
const bcrypt = require("bcrypt");
const salt = await bcrypt.genSalt(10);
const hash = await bcrypt.hash("yourpassword", salt);
console.log(hash);
// Output: $2b$10$N9qo8uLOickgx2ZMRZoMye.Ik3JSk5U5p7L6Km1hp7RmWfXfGOIJy
```

## How It Works

### Authentication Flow

1. **Client connects** to ProFTPD (FTP port 21 or SFTP port 2222)
2. **Client provides** username and password
3. **Module queries MongoDB** using connection from pool (reused for efficiency)
4. **Field validation** - checks BSON types and validates uid/gid ranges (>= 1)
5. **Password verification** using thread-safe `crypt_r()` with configured hash method
6. **On success:**
   - ProFTPD retrieves validated uid, gid, and home_directory from MongoDB
   - Switches process to user's uid/gid
   - Chroots user to their home directory (user sees it as `/`)
   - User is jailed - cannot navigate above home directory
   - Connection is returned to pool for reuse
7. **On failure:**
   - Custom error message sent to client
   - Connection rejected
   - Connection returned to pool

### Performance Optimizations

- **Connection pooling**: Maintains up to 10 reusable MongoDB connections
- **Query result caching**: Caches user data for 5 seconds to avoid duplicate queries
  - ProFTPD calls `getpwnam()` then `auth()` for the same user
  - Cache hit eliminates second MongoDB query (50% reduction)
  - Automatic cache invalidation on authentication failure
- **Thread-safe**: Supports concurrent authentication requests without race conditions
- **Fail-fast validation**: Tests MongoDB connectivity at server startup
- **Efficient resource management**: All connections returned to pool after use

**Expected performance:**

- First auth: ~5-10ms (MongoDB query + cache population)
- Second auth (cached): ~0.1ms (cache lookup only)
- Cache TTL: 5 seconds (balances performance vs. security)

### Security Features

- **User isolation**: Each user runs with their own uid/gid and is chrooted
- **Password hashing**: Supports bcrypt and other strong hashing methods
- **Thread-safe authentication**: Uses `crypt_r()` to prevent race conditions (Linux)
- **UID/GID validation**: Strict range checking prevents uid 0 (root) attacks
- **BSON type safety**: Validates field types before conversion to prevent type confusion
- **Input sanitization**: Safe parsing of all numeric values with error checking
- **Connection pooling**: Reuses connections efficiently (max 10 concurrent)
- **Startup validation**: Tests MongoDB connectivity at server start
- **No system users needed**: All user data comes from MongoDB
- **Replica set support**: High availability with MongoDB clusters
- **Configurable timeouts**: Prevents hanging on MongoDB connection issues
  **Using command line (SHA-256):**

## Contributing

Issues and pull requests welcome! This module is production-ready with security hardening.

Please note: Future contributions may also use AI assistance tools. All contributions undergo human review regardless of development method.

## License

Copyright (c) 2025. This module is provided as-is for use with ProFTPD.

## License

Copyright (c) 2025. This module is provided as-is for use with ProFTPD.

## Support

For issues:

1. Enable `AuthMongoDebugLogging yes` and check `/var/log/proftpd/system.log`
2. Verify MongoDB connection with `mongosh`
3. Test configuration syntax with `proftpd -t`
4. Check the fully documented `proftpd.conf.sample` for examples
5. Open a github Issue only after completing steps 1-4.

## Usage

1. Configure ProFTPD using the directives above
2. Restart ProFTPD: `sudo systemctl restart proftpd`
3. Check logs: `/var/log/proftpd/system.log`
4. Connect via FTP/SFTP client using credentials from MongoDB

## Troubleshooting

### Enable Debug Logging

Set `AuthMongoDebugLogging yes` to see detailed authentication flow in logs.

### Check MongoDB Connection

Verify your connection string works:

```bash
mongosh "mongodb://user:pass@host:27017/database"
```

### Verify Module Loading

```bash
proftpd -V | grep auth_mongodb
```

### Common Issues

- **Module not loading**: Check module path in LoadModule directive
- **Connection failures**: Verify MongoDB URI, firewall, and authentication
- **Authentication fails**:
  - Check field names match your MongoDB schema
  - Verify `AuthMongoPasswordHashMethod` matches your password format
  - Enable debug logging to see password verification details
  - Ensure bcrypt hashes start with `$2a$`, `$2b$`, or `$2y$`
- **Permission errors**: Ensure home directories exist and are accessible
- **Wrong hash method**: If passwords always fail, check that stored hash format matches configured method
