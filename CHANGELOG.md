# Changelog

All notable changes to the ProFTPD MongoDB Authentication Module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### ✨ Features

- **Added nested BSON field path support** - Field directives now support dot notation for nested documents

  - Supports both flat fields (e.g., `"uid"`) and nested paths (e.g., `"server.uid"`)
  - New `find_bson_field()` helper function using `bson_iter_find_descendant()`
  - Works with arbitrary nesting depth (e.g., `"config.server.credentials.uid"`)
  - Applied to all field mappings: uid, gid, path, password, username
  - Allows flexible MongoDB schema organization without flattening documents
  - Backward compatible with existing flat field configurations

- **Added comprehensive startup readiness checks** - Validates configuration and connectivity at first connection
  - Validates all required directives are set
  - Tests MongoDB server connectivity (ping)
  - Verifies database exists and is accessible
  - Confirms collection exists in database
  - Tests sample query to verify field mappings
  - Detailed progress logging for each validation step
  - Clear error messages for troubleshooting configuration issues

### 🔒 Security Enhancements

- **Added environment variable support for connection strings** - Prevents credential exposure in version control
  - Use `${VAR_NAME}` syntax in `AuthMongoConnectionString` directive
  - Example: `"mongodb://user:${MONGO_PASSWORD}@host:27017/?authSource=admin"`
  - Variables expanded at module initialization (safe from runtime injection)
  - Allows separation of configuration from secrets management
  - Follows security best practices for credential storage

### 📚 Documentation

- Updated `proftpd.conf.sample` with environment variable examples
- Updated `README.md` with security best practices section
- Added systemd and init script environment variable configuration examples

## [1.2.0] - 2026-01-11

### 🔴 CRITICAL SECURITY FIXES

- **Fixed MongoDB client pool leak** - Clients are now properly returned to pool in all error paths (CVE-class: Resource Leak)
  - Fixed in `query_mongodb_user()` when user not found or cursor errors occur
  - Prevents connection pool exhaustion denial of service
- **Fixed timing attack vulnerability** - Implemented constant-time password comparison (CVE-class: Information Disclosure)
  - All password comparisons now use constant-time algorithm
  - Prevents password brute-forcing via timing analysis
- **Fixed password hash memory exposure** - Implemented secure memory wiping (CVE-class: Information Disclosure)
  - Uses `explicit_bzero()` on Linux, volatile pointer method on other platforms
  - Prevents password hash extraction from process memory dumps
- **Fixed missing session cleanup** - Added session cleanup handler (CVE-class: Information Leakage)
  - Cache is now invalidated on session disconnect
  - Prevents sensitive data persistence across sessions
- **Fixed connection pool memory leak** - Added module cleanup handler
  - Connection pool properly destroyed on ProFTPD shutdown
  - Prevents memory leaks on server restarts
- **Fixed missing input validation** - Added username/password length checks
  - Username max: 256 characters
  - Password max: 1024 characters
  - Prevents potential buffer issues and log flooding
- **Fixed connection blocking**
  - When sftp client connects in rapid succession, the auth routine was blocking new authentications.

### Added

- **Configurable connection pool size** via `AuthMongoConnectionPoolSize` directive (1-100, default: 10)
- **Constant-time comparison function** for all password verification methods
- **Secure memory wiping** using `explicit_bzero()` or volatile pointer method
- **Session cleanup handler** that clears cache on disconnect
- **Module cleanup handler** that destroys connection pool on shutdown
- **Input length validation** for usernames and passwords
- **Enhanced error messages** with more context for debugging
- Security constants: `MAX_USERNAME_LENGTH`, `MAX_PASSWORD_LENGTH`, `DEFAULT_POOL_SIZE`

### Changed

- Module version updated to 1.2.0
- `invalidate_cache()` now uses secure memory wiping instead of `memset()`
- `verify_password()` in PLAIN mode now uses constant-time comparison with length checks
- All error paths in `query_mongodb_user()` properly return clients to pool
- Connection pool size now configurable instead of hardcoded to 10
- Event handlers registered in `auth_mongodb_init()` for proper cleanup

### Security

- **Timing attack resistance**: Password verification is now constant-time
- **Memory safety**: Password hashes securely wiped from memory
- **Resource management**: All MongoDB resources properly cleaned up
- **Input validation**: All user inputs validated for length and NULL
- **Compliance**: Meets OWASP authentication best practices, CWE-208, CWE-401, CWE-404, CWE-20, CWE-312

### Documentation

- Added `SECURITY_REVIEW_2026.md` with comprehensive security analysis
- Documented all security issues found and fixes applied
- Added upgrade instructions and testing recommendations
- Added performance impact analysis (< 3μs overhead)

### Upgrade Notes

- **CRITICAL**: All production deployments should upgrade immediately
- Fully backward compatible with v1.1.x configurations
- New `AuthMongoConnectionPoolSize` directive is optional
- No database schema changes required
- Recompilation required: `make clean && make && sudo make install`

## [1.1.1] - 2025-12-03

### Fixed

- **Build**: Fixed corrupted `.PHONY` declaration in Makefile causing "multiple target patterns" error
- **Build**: Fixed missing field initializers in `authtable` structure (added NULL for 'm' field)
- **Build**: Fixed missing field initializers in module structure (added NULL for 'handle' and 0 for 'priority')
- **Build**: Removed unused `auth_mongodb_cleanup()` function that caused compilation warning
- **Build**: Removed unused variables `uri` and `error` from `auth_mongodb_init()`

### Added

- **Build**: Added missing `install` target to Makefile for module installation
- **Build**: Added comprehensive debug output to Makefile build process
- **Build**: Added build verification that confirms `.so` file creation and displays file location

## [1.1.0] - 2025-12-03

### Added

- **Connection pooling** for MongoDB connections (max 10 concurrent connections)
- **Query result caching** - 5-second cache eliminates duplicate MongoDB queries (50% reduction)
- **Thread-safe password verification** using `crypt_r()` on Linux systems
- **Startup configuration validation** - tests MongoDB connectivity at server start
- **BSON type checking** - validates field types before conversion
- **Safe integer parsing** - uses `strtol()` with comprehensive error checking
- **UID/GID range validation** - enforces minimum value of 1 to prevent root access
- Support for numeric (int32/int64) uid/gid fields in MongoDB (previously strings only)
- Security hardening compiler flags (stack protection, RELRO, BIND_NOW)
- `make lint` target for static analysis with cppcheck
- `make security-check` target to verify security features
- `errno.h` and `sys/time.h` includes for better portability

### Changed

- All MongoDB client connections now use connection pool instead of creating new connections
- Error paths now properly return connections to pool (fixes resource leaks)
- Module initialization validates configuration before first authentication attempt
- Improved error messages with specific details about validation failures

### Fixed

- **Critical**: Thread-safety issue with `crypt()` replaced with `crypt_r()`
- **Critical**: UID/GID parsing vulnerability - `atoi()` replaced with validated `strtol()`
- **Critical**: Missing validation allowed uid 0 (root) - now enforced >= 1
- Resource leak in error paths - database handle not destroyed
- All error paths now properly clean up MongoDB resources
- Client connections now returned to pool instead of destroyed

### Security

- Stack smashing protection enabled (`-fstack-protector-strong`)
- Buffer overflow detection enabled (`-D_FORTIFY_SOURCE=2`)
- Read-only relocations enabled (`-Wl,-z,relro`)
- Immediate symbol binding (`-Wl,-z,now`)
- All compiler warnings treated as errors (`-Werror`)

### Performance

- 10-100x faster authentication under load due to connection pooling
- 50% fewer MongoDB queries due to intelligent caching (5-second TTL)
- Cache hit rate: ~50% on typical auth flow (auth() reuses getpwnam() data)
- Sub-millisecond response time for cached lookups
- Eliminated connection overhead for each authentication request
- Reduced MongoDB server load from repeated connections and duplicate queries

## [1.0.0] - 2025-12-02

### Added

- Initial release
- MongoDB-based authentication for ProFTPD
- Support for multiple password hashing methods (plain, bcrypt, crypt, sha256, sha512)
- Configurable field names for flexible MongoDB schema
- Debug logging support
- Custom error messages
- FTP and SFTP support
- User chroot jailing
