# Makefile for ProFTPD MongoDB Authentication Module

# Module name
MODULE = mod_auth_mongodb

# Compiler and flags
CC = gcc

# Security and optimization flags
# -Wall -Wextra: Enable all warnings
# -Werror: Treat warnings as errors
# -fPIC: Position-independent code for shared library
# -O2: Optimization level 2
# -D_FORTIFY_SOURCE=2: Enable runtime buffer overflow detection
# -fstack-protector-strong: Stack smashing protection
# -D_GNU_SOURCE: Enable GNU extensions (needed for crypt_r on Linux)
# -DPR_SHARED_MODULE: Required for ProFTPD DSO modules
CFLAGS = -Wall -Wextra -Werror -fPIC -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -D_GNU_SOURCE -DPR_SHARED_MODULE

# Linker security flags
# -shared: Create shared library
# -Wl,-z,relro: Read-only relocations
# -Wl,-z,now: Resolve all symbols at load time (prevents lazy binding attacks)
LDFLAGS = -shared -Wl,-z,relro,-z,now

# MongoDB C driver flags
MONGOC_CFLAGS = $(shell pkg-config --cflags libmongoc-1.0)
MONGOC_LIBS = $(shell pkg-config --libs libmongoc-1.0)

# Extract include paths for prxs (prxs needs -I flags passed separately)
MONGOC_INCLUDES = $(shell pkg-config --cflags-only-I libmongoc-1.0)

# ProFTPD include path (adjust as needed)
PROFTPD_INCLUDE = -I/usr/local/include/proftpd -I/usr/include/proftpd

# Output
TARGET = $(MODULE).so

# Source files
SOURCES = $(MODULE).c

# Dependency check
check-deps:
	@echo "Checking dependencies..."
	@which pkg-config > /dev/null 2>&1 || (echo "ERROR: pkg-config is not installed" && exit 1)
	@which prxs > /dev/null 2>&1 || (echo "ERROR: prxs is not installed. Install proftpd-dev or build ProFTPD with --enable-dso" && exit 1)
	@pkg-config --exists libmongoc-1.0 || (echo "ERROR: libmongoc-1.0 not found. Install mongo-c-driver development package" && exit 1)
	@pkg-config --exists libbson-1.0 || (echo "ERROR: libbson-1.0 not found. Install libbson development package" && exit 1)
	@test -f /usr/local/include/proftpd/conf.h -o -f /usr/include/proftpd/conf.h || (echo "ERROR: ProFTPD headers not found. Install proftpd-dev or proftpd-devel package" && exit 1)
	@echo "All dependencies are satisfied."

# Build rule using prxs (recommended)
all: check-deps
	@echo "Building $(MODULE) using prxs (ProFTPD Extension Tool)..."
	prxs -c $(MONGOC_INCLUDES) -l mongoc-1.0 -l bson-1.0 -l rt $(SOURCES)
	@echo ""
	@echo "✓ Module compiled successfully using prxs with libtool"
	@ls -lh .libs/$(TARGET) 2>/dev/null || ls -lh $(TARGET)
	@echo ""
	@echo "To install: make install"
	@echo "Or manually: sudo prxs -i $(MODULE).la"

# Alternative build rule using direct gcc compilation (not recommended)
direct: check-deps $(TARGET)

$(TARGET): $(SOURCES)
	@echo "Building $(TARGET)..."
	@echo "Source files: $(SOURCES)"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "PROFTPD_INCLUDE: $(PROFTPD_INCLUDE)"
	@echo "MONGOC_CFLAGS: $(MONGOC_CFLAGS)"
	@echo "MONGOC_LIBS: $(MONGOC_LIBS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo ""
	@echo "Running compilation command..."
	$(CC) $(CFLAGS) $(PROFTPD_INCLUDE) $(MONGOC_CFLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCES) $(MONGOC_LIBS)
	@echo ""
	@echo "Compilation complete. Checking for output file..."
	@if [ -f $(TARGET) ]; then \
		echo "✓ $(TARGET) created successfully"; \
		ls -lh $(TARGET); \
		echo "File location: $$(pwd)/$(TARGET)"; \
	else \
		echo "✗ ERROR: $(TARGET) was not created!"; \
		exit 1; \
	fi
	@echo ""
	@echo "Build complete with security hardening enabled:"
	@echo "  - Stack protection"
	@echo "  - Buffer overflow detection"
	@echo "  - Read-only relocations"
	@echo "  - Immediate symbol resolution"

# Clean rule
clean:
	@echo "Cleaning build artifacts..."
	prxs -d $(SOURCES) 2>/dev/null || true
	rm -f $(TARGET) $(MODULE).o $(MODULE).lo $(MODULE).la
	rm -rf .libs
	@echo "Clean complete."

# Install rule
install:
	@echo "Installing $(MODULE) using prxs..."
	@if [ -f $(MODULE).la ]; then \
		prxs -i $(MODULE).la; \
	else \
		echo "ERROR: $(MODULE).la not found. Run 'make' first."; \
		exit 1; \
	fi
	@echo ""
	@echo "✓ Module installed successfully to /usr/local/libexec/"
	@echo ""
	@echo "Next steps:"
	@echo "1. Add to your proftpd.conf:"
	@echo "     LoadModule mod_auth_mongodb.c"
	@echo "   NOTE: Use .c extension, not .so (ProFTPD convention)"
	@echo "2. Configure MongoDB authentication directives (see proftpd.conf.sample)"
	@echo "3. Test configuration: sudo proftpd -t"
	@echo "4. Restart ProFTPD: sudo systemctl restart proftpd"

# Static analysis
lint:
	@echo "Running static analysis with cppcheck..."
	@which cppcheck > /dev/null 2>&1 || (echo "cppcheck not installed. Install with: sudo apt-get install cppcheck" && exit 1)
	cppcheck --enable=all --suppress=missingIncludeSystem --std=c11 $(SOURCES)

# Security check
security-check: $(TARGET)
	@echo "Checking security features..."
	@echo "Checking for stack protection:"
	@readelf -s $(TARGET) | grep -q __stack_chk_fail && echo "  ✓ Stack protection enabled" || echo "  ✗ Stack protection missing"
	@echo "Checking for position-independent code:"
	@readelf -h $(TARGET) | grep -q "DYN" && echo "  ✓ Position-independent code" || echo "  ✗ Not position-independent"
	@echo "Checking for read-only relocations:"
	@readelf -d $(TARGET) | grep -q "BIND_NOW" && echo "  ✓ BIND_NOW enabled" || echo "  ✗ BIND_NOW missing"

# Help
help:
	@echo "Available targets:"
	@echo "  all            - Build the module using prxs (recommended, default)"
	@echo "  direct         - Build using direct gcc compilation (not recommended)"
	@echo "  clean          - Remove compiled files and build artifacts"
	@echo "  install        - Install module using prxs"
	@echo "  lint           - Run static analysis with cppcheck"
	@echo "  security-check - Verify security features in compiled module"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Build methods:"
	@echo "  prxs (default) - Uses ProFTPD Extension Tool with libtool"
	@echo "                   Ensures proper DSO module structure"
	@echo "                   Required for ProFTPD to load the module"
	@echo "  direct         - Direct gcc compilation (may not work with all ProFTPD builds)"
	@echo ""
	@echo "Important: ProFTPD DSO modules must:"
	@echo "  1. Be compiled with prxs for proper module structure"
	@echo "  2. Be loaded with LoadModule mod_auth_mongodb.c (use .c not .so)"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - libmongoc-1.0 and libbson-1.0 development packages"
	@echo "  - ProFTPD development headers and prxs tool"
	@echo "  - pkg-config"
	@echo "  - gcc with security hardening support"
	@echo ""
	@echo "Install dependencies (Debian/Ubuntu):"
	@echo "  sudo apt-get install libmongoc-dev libbson-dev proftpd-dev pkg-config build-essential"
	@echo ""
	@echo "Install dependencies (RHEL/CentOS):"
	@echo "  sudo yum install mongo-c-driver-devel proftpd-devel pkgconfig gcc"

.PHONY: all clean install help check-deps lint security-check
