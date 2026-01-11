# Dependencies

This document lists all dependencies required to build and run `mod_auth_mongodb`.

## Build-Time Dependencies

These are required to compile the module:

### Required

- **ProFTPD** (>= 1.3.6)

  - ProFTPD source code or development headers
  - Used for: Module API and integration

- **MongoDB C Driver (libmongoc)** (>= 1.17.0)

  - Includes libbson
  - Used for: MongoDB database connectivity and operations
  - Homepage: http://mongoc.org/

- **libbson** (>= 1.17.0)

  - Usually bundled with libmongoc
  - Used for: BSON document creation and parsing

- **C Compiler**

  - GCC (>= 4.8) or Clang (>= 3.5)
  - C99 standard support required

- **GNU Make**
  - For building the module

### Optional

- **pkg-config**
  - Helps locate MongoDB C driver libraries
  - Recommended for easier builds

## Runtime Dependencies

These are required when running ProFTPD with this module:

- **ProFTPD** (>= 1.3.6)

  - The FTP server itself

- **MongoDB C Driver shared libraries**

  - libmongoc-1.0.so (Linux) or equivalent
  - libbson-1.0.so (Linux) or equivalent

- **MongoDB Server** (>= 3.6)
  - A running MongoDB instance (can be local or remote)
  - Used for: User authentication data storage

## Installation Instructions

### Debian/Ubuntu

```bash
# Build dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    proftpd-dev \
    libmongoc-dev \
    libbson-dev \
    pkg-config

# Runtime (if not already installed)
sudo apt-get install -y \
    proftpd-basic \
    libmongoc-1.0-0 \
    libbson-1.0-0
```

### RHEL/CentOS/Fedora

```bash
# Build dependencies
sudo yum install -y \
    gcc \
    make \
    proftpd-devel \
    mongo-c-driver-devel \
    pkg-config

# Runtime (if not already installed)
sudo yum install -y \
    proftpd \
    mongo-c-driver-libs
```

### macOS (Homebrew)

```bash
# Build dependencies
brew install \
    proftpd \
    mongo-c-driver \
    pkg-config

# ProFTPD headers may need to be linked
brew link proftpd
```

### Building MongoDB C Driver from Source

If your distribution doesn't have libmongoc packages:

```bash
# Install cmake
sudo apt-get install cmake  # Debian/Ubuntu
# or
sudo yum install cmake      # RHEL/CentOS

# Build mongo-c-driver
wget https://github.com/mongodb/mongo-c-driver/releases/download/1.24.0/mongo-c-driver-1.24.0.tar.gz
tar xzf mongo-c-driver-1.24.0.tar.gz
cd mongo-c-driver-1.24.0
mkdir cmake-build && cd cmake-build
cmake -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF ..
make
sudo make install
```

## Verification

Verify dependencies are installed:

```bash
# Check pkg-config can find libmongoc
pkg-config --modversion libmongoc-1.0

# Check for ProFTPD
proftpd -v

# Check compiler
gcc --version
```

## Minimum Version Requirements Summary

| Dependency                    | Minimum Version | Recommended |
| ----------------------------- | --------------- | ----------- |
| ProFTPD                       | 1.3.6           | 1.3.8+      |
| libmongoc                     | 1.17.0          | 1.24.0+     |
| libbson                       | 1.17.0          | 1.24.0+     |
| GCC                           | 4.8             | 9.0+        |
| MongoDB Server                | 3.6             | 5.0+        |
| CMake (if building libmongoc) | 3.5             | 3.20+       |

## Notes

- **ProFTPD Development Files**: On some systems, you need the `-dev` or `-devel` package to get header files required for module compilation.

- **MongoDB C Driver**: The driver consists of two libraries: `libmongoc` (high-level) and `libbson` (low-level). Both are required.

- **Package Names**: Package names vary by distribution. Check your distribution's package repository for exact names.

- **Static vs Shared Linking**: This module uses dynamic linking by default. Ensure the MongoDB C driver shared libraries are in your library path (`LD_LIBRARY_PATH` on Linux).

- **MongoDB Server**: While required for operation, the MongoDB server can run on a different machine. Network connectivity to MongoDB is all that's needed at runtime.
