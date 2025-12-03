# ProFTPD MongoDB Authentication Module

A ProFTPD authentication module that authenticates users against a MongoDB database, supporting multiple password hashing methods (bcrypt, SHA-256/512, crypt) with user chroot jailing to their home directories.

## Features

- ✅ MongoDB-based authentication (supports replica sets)
- ✅ Multiple password hashing methods (bcrypt, SHA-256, SHA-512, crypt, plain)
- ✅ Automatic user chroot jailing to home directory
- ✅ Per-user uid/gid from MongoDB
- ✅ Configurable field names (flexible MongoDB schema)
- ✅ Custom error messages for clients
- ✅ Debug logging for troubleshooting
- ✅ Dynamic loading as DSO module (no ProFTPD recompilation needed)
- ✅ FTP and SFTP support

## Resources

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
LoadModule mod_auth_mongodb.c

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
- `uid` and `gid` are stored as strings
- `home_directory` should be an absolute path
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
3. **Module queries MongoDB** using the configured connection string and field names
4. **Password verification** using the configured hash method (bcrypt, SHA-512, etc.)
5. **On success:**
   - ProFTPD retrieves uid, gid, and home_directory from MongoDB
   - Switches process to user's uid/gid
   - Chroots user to their home directory (user sees it as `/`)
   - User is jailed - cannot navigate above home directory
6. **On failure:**
   - Custom error message sent to client
   - Connection rejected

### Security Features

- **User isolation**: Each user runs with their own uid/gid and is chrooted
- **Password hashing**: Supports bcrypt and other strong hashing methods
- **No system users needed**: All user data comes from MongoDB
- **Replica set support**: High availability with MongoDB clusters
- **Configurable timeouts**: Prevents hanging on MongoDB connection issues
  **Using command line (SHA-256):**

````bash
### Common Issues

| Issue | Solution |
|-------|----------|
| **Module not loading** | • Check module path: `proftpd -V \| grep PROFTPD_DIR_MODULE`<br>• Verify DSO support: `proftpd -V \| grep DSO`<br>• Check module exists: `ls -la /usr/local/libexec/mod_auth_mongodb.*` |
| **Connection failures** | • Test MongoDB: `mongosh "mongodb://..."`<br>• Check firewall rules<br>• Verify authSource in connection string<br>• Enable debug logging to see connection details |
| **Authentication always fails** | • Verify `AuthMongoPasswordHashMethod` matches password format<br>• Check bcrypt hashes start with `$2a$`, `$2b$`, or `$2y$`<br>• Enable debug logging: `AuthMongoDebugLogging yes`<br>• Test query manually in MongoDB<br>• Check all required fields exist in documents |
| **User can access wrong directory** | • Verify `DefaultRoot ~` is set<br>• Check home_directory field has correct path<br>• Ensure directory exists and has correct ownership |
| **Permission denied errors** | • Create home directory: `mkdir -p /home/user`<br>• Set ownership: `chown uid:gid /home/user`<br>• Set permissions: `chmod 755 /home/user` |
| **Syntax error in config** | • Test config: `proftpd -t -c /etc/proftpd/proftpd.conf`<br>• Check for typos in directive names<br>• Ensure LoadModule comes before other directives |

### Testing Commands

```bash
# Test configuration syntax
proftpd -t -c /etc/proftpd/proftpd.conf

# Check if module is loaded
proftpd -l | grep mongodb

# Test FTP connection
ftp localhost
# Enter username and password

# Test SFTP connection
sftp -P 2222 testuser@localhost

# Monitor authentication in real-time
tail -f /var/log/proftpd/system.log

# Test MongoDB connection
mongosh "mongodb://user:pass@host:27017/authentication"
````

## Contributing

Issues and pull requests welcome! This is a simple authentication module designed for basic use cases.

## License

Copyright (c) 2025. This module is provided as-is for use with ProFTPD.

## Support

For issues:

1. Enable `AuthMongoDebugLogging yes` and check `/var/log/proftpd/system.log`
2. Verify MongoDB connection with `mongosh`
3. Test configuration syntax with `proftpd -t`
4. Check the fully documented `proftpd.conf.sample` for examples

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
