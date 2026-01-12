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
- **Connection pooling** (configurable, default 10) prevents resource exhaustion
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

> **⚠️ CRITICAL:** ProFTPD DSO modules **must** be compiled using the `prxs` tool (ProFTPD Extension Tool) with libtool. Direct gcc compilation will create a shared library that ProFTPD cannot load, resulting in "Invalid argument" errors. Additionally, the `LoadModule` directive must reference the module as `mod_auth_mongodb.c` (not `.so`) - this is a ProFTPD convention where the configuration references the source filename.

### 1. Install Prerequisites

**Debian/Ubuntu:**

```bash
sudo apt-get install libmongoc-dev libbson-dev proftpd-dev pkg-config build-essential
```

**RHEL/CentOS:**

```bash
sudo yum install mongo-c-driver-devel proftpd-devel pkgconfig gcc
```

**Verify Prerequisites:**

```bash
# Check ProFTPD has DSO support
proftpd -V | grep "DSO support"

# Verify prxs tool is available
which prxs

# Check MongoDB C driver
pkg-config --modversion libmongoc-1.0
```

If `prxs` is not found, ProFTPD must be rebuilt with `--enable-dso`.

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

**Why prxs is Required:**

ProFTPD DSO modules have a specific internal structure that `prxs` creates using libtool. Direct gcc compilation (even with `-shared -fPIC`) creates a standard shared library that lacks this structure. When ProFTPD attempts to load a module compiled without prxs, it fails with "Invalid argument" because the module doesn't conform to ProFTPD's DSO requirements.

**Option A: Using Makefile (recommended):**

```bash
# Build the module (uses prxs internally)
make

# Verify build succeeded
ls -l .libs/mod_auth_mongodb.so

# Install to /usr/local/libexec/
sudo make install

# Verify installation
ls -l /usr/local/libexec/mod_auth_mongodb.*
```

**Option B: Using prxs directly:**

```bash
# Compile with prxs
prxs -c \
  -I /usr/include/libmongoc-1.0 \
  -I /usr/include/libbson-1.0 \
  -l mongoc-1.0 \
  -l bson-1.0 \
  -l rt \
  mod_auth_mongodb.c

# Install
sudo prxs -i mod_auth_mongodb.la

# Verify
ls -l /usr/local/libexec/mod_auth_mongodb.so
```

**Build Output:**

A successful `prxs` build creates:

- `.libs/mod_auth_mongodb.so` - The actual shared library
- `mod_auth_mongodb.la` - Libtool metadata file (required for installation)
- `mod_auth_mongodb.lo` - Libtool object file
- `mod_auth_mongodb.a` - Static library

**Clean Build:**

```bash
make clean
# Or manually: prxs -d mod_auth_mongodb.c
```

Edit your `proftpd.conf` (see `proftpd.conf.sample` for complete example):

```apache
# CRITICAL: Use .c extension (ProFTPD convention), NOT .so
LoadModule mod_auth_mongodb.c

# MongoDB connection
AuthMongoConnectionString "mongodb://user:pass@host:27017/?authSource=admin"
AuthMongoDatabaseName "authentication"
AuthMongoAuthCollectionName "users"

# Field mappings (adjust to match your MongoDB schema)
AuthMongoDocumentFieldUsername "username"
AuthMongoDocumentFieldPassword "password"
AuthMongoDocumentFieldUid "uid"
AuthMongoDocumentFieldGid "gid"
AuthMongoDocumentFieldPath "home_directory"

# Password hashing (bcrypt recommended)
AuthMongoPasswordHashMethod bcrypt

# Optional: Enable debug logging for initial setup
AuthMongoDebugLogging yes

# Use only MongoDB authentication
AuthOrder mod_auth_mongodb.c
```

### 5. Test Configuration

```bash
# Test syntax
sudo proftpd -t

# Look for successful module initialization:
# "mod_auth_mongodb/1.1.1: Module initialized"

# If you see "Invalid argument" error:
# 1. Verify LoadModule uses .c extension (not .so)
# 2. Confirm module was compiled with prxs
# 3. Check module exists: ls -l /usr/local/libexec/mod_auth_mongodb.so
```

### 6. Start ProFTPD

```bash
# Restart ProFTPD
sudo systemctl restart proftpd

# Check logs for successful startup
sudo tail -f /var/log/proftpd/system.log

# Test connection
ftp localhost
# Or with SFTP:
sftp -P 2222 username@localhost
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
| `AuthMongoConnectionPoolSize`    | ❌       | Max connection pool size (1-100)                            | `20` (default: `10`)                                 |
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
AuthMongoConnectionPoolSize: (max connection pool size 1-100, default: 10, optional)
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

- **Connection pooling**: Maintains configurable pool of reusable MongoDB connections (default: 10, max: 100)
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

## Troubleshooting

### Module Loading Issues

#### "LoadModule: error loading module: Invalid argument"

This is the most common issue and has specific causes:

**Cause 1: Wrong file extension in LoadModule directive**

```bash
# Check your proftpd.conf
grep LoadModule /etc/proftpd/proftpd.conf | grep mongodb

# WRONG - will fail
LoadModule mod_auth_mongodb.so

# CORRECT - will work
LoadModule mod_auth_mongodb.c

# Fix it
sudo sed -i 's/mod_auth_mongodb.so/mod_auth_mongodb.c/' /etc/proftpd/proftpd.conf
sudo proftpd -t
```

**Cause 2: Module compiled with direct gcc instead of prxs**

```bash
# Rebuild with prxs
make clean
make
sudo make install

# Verify .la file exists (created only by prxs)
ls -l /usr/local/libexec/mod_auth_mongodb.la
```

**Cause 3: ProFTPD built without DSO support**

```bash
# Check for DSO support
proftpd -V | grep "DSO support"

# If not present, rebuild ProFTPD:
./configure --enable-dso --sysconfdir=/etc/proftpd --with-modules=mod_tls:mod_sftp
make
sudo make install
```

**Cause 4: Module file missing or in wrong location**

```bash
# Check module exists
ls -l /usr/local/libexec/mod_auth_mongodb.so

# Check ProFTPD's module directory
proftpd -V | grep "Shared Module Directory"

# If module is in wrong location, reinstall
sudo prxs -i mod_auth_mongodb.la
```

### Enable Debug Logging

Set `AuthMongoDebugLogging yes` to see detailed authentication flow in logs.

```bash
# Watch logs in real-time
sudo tail -f /var/log/proftpd/system.log
```

### Check MongoDB Connection

Verify your connection string works:

```bash
mongosh "mongodb://user:pass@host:27017/database?authSource=admin"
```

### Verify Module Loading

```bash
# Test configuration syntax
sudo proftpd -t

# Should see: "mod_auth_mongodb/1.1.1: Module initialized"

# List loaded modules
proftpd -l | grep auth
```

### Common Authentication Issuestication Issues

**MongoDB connection failures:**

```bash
# Test MongoDB connectivity
mongosh "mongodb://user:pass@host:27017/dbname?authSource=admin"

# Check firewall
telnet mongo-host 27017

# Verify credentials and authSource
# Common mistake: wrong authSource (should match where user is defined)
```

**Authentication always fails:**

```bash
# Enable debug logging
AuthMongoDebugLogging yes

# Check field names match your MongoDB schema
mongosh
use authentication
db.users.findOne({username: "testuser"})

# Verify AuthMongoPasswordHashMethod matches password format:
# - bcrypt hashes start with $2a$, $2b$, or $2y$
# - sha512 hashes start with $6$
# - sha256 hashes start with $5$
```

**Permission errors (can't access home directory):**

```bash
# Create home directory
sudo mkdir -p /home/testuser

# Set ownership (uid:gid from MongoDB)
sudo chown 1001:1001 /home/testuser

# Set permissions
sudo chmod 755 /home/testuser

# Verify
ls -ld /home/testuser
```

**UID/GID validation errors in logs:**

```bash
# UIDs and GIDs must be >= 1 (never 0 for security)
# Check MongoDB documents:
mongosh
db.users.find({}, {username: 1, uid: 1, gid: 1})

# Values can be strings ("1001") or numbers (1001)
# Both are accepted, but must be >= 1
```

### Build Issues

**prxs not found:**

```bash
# Install ProFTPD development package
sudo apt-get install proftpd-dev  # Debian/Ubuntu
sudo yum install proftpd-devel    # RHEL/CentOS

# Or build ProFTPD with DSO support
./configure --enable-dso
make && sudo make install
```

**MongoDB C driver not found:**

```bash
# Install MongoDB C driver
sudo apt-get install libmongoc-dev libbson-dev  # Debian/Ubuntu
sudo yum install mongo-c-driver-devel           # RHEL/CentOS

# Verify.
pkg-config --modversion libmongoc-1.0
```

## Support

For issues:

1. **Enable debug logging**: `AuthMongoDebugLogging yes`
2. **Check logs**: `sudo tail -f /var/log/proftpd/system.log`
3. **Verify MongoDB connection**: `mongosh "mongodb://..."`
4. **Test configuration**: `sudo proftpd -t`
5. **Review documentation**: `proftpd.conf.sample` has complete examples
6. **Check build method**: Module must be compiled with `prxs`
7. **Verify LoadModule**: Must use `.c` extension, not `.so`
8. **Open GitHub issue** only after completing steps 1-7

## Additional Resources

- **[BUILD.md](BUILD.md)** - Detailed build troubleshooting guide
- **[proftpd.conf.sample](proftpd.conf.sample)** - Complete configuration with all directives
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes
- **ProFTPD DSO Guide**: http://www.proftpd.org/docs/howto/DSO.html
- **prxs manual**: `man prxs`
