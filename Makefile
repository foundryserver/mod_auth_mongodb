# Makefile for ProFTPD MongoDB Authentication Module

# Module name
MODULE = mod_auth_mongodb

# Compiler and flags
CC = gcc
CFLAGS = -Wall -fPIC -shared
MONGOC_CFLAGS = $(shell pkg-config --cflags libmongoc-1.0)
MONGOC_LIBS = $(shell pkg-config --libs libmongoc-1.0)

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
	@pkg-config --exists libmongoc-1.0 || (echo "ERROR: libmongoc-1.0 not found. Install mongo-c-driver development package" && exit 1)
	@pkg-config --exists libbson-1.0 || (echo "ERROR: libbson-1.0 not found. Install libbson development package" && exit 1)
	@test -f /usr/local/include/proftpd/conf.h -o -f /usr/include/proftpd/conf.h || (echo "ERROR: ProFTPD headers not found. Install proftpd-dev or proftpd-devel package" && exit 1)
	@echo "All dependencies are satisfied."

# Build rule
all: check-deps $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(PROFTPD_INCLUDE) $(MONGOC_CFLAGS) -o $(TARGET) $(SOURCES) $(MONGOC_LIBS)

# Clean rule
clean:
	rm -f $(TARGET)

# Install rule (adjust PROFTPD_MODULES_DIR as needed)
install: $(TARGET)
	@echo "Installing $(TARGET) to ProFTPD modules directory..."
	@echo "You may need to run: sudo cp $(TARGET) /usr/local/libexec/ or /usr/lib/proftpd/"
	@echo "Adjust the path based on your ProFTPD installation."

# Help
help:
	@echo "Available targets:"
	@echo "  all     - Build the module (default)"
	@echo "  clean   - Remove compiled files"
	@echo "  install - Show installation instructions"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - libmongoc-1.0 and libbson-1.0 development packages"
	@echo "  - ProFTPD development headers"
	@echo "  - pkg-config"
	@echo ""
	@echo "Install dependencies (Debian/Ubuntu):"
	@echo "  sudo apt-get install libmongoc-dev libbson-dev proftpd-dev pkg-config"
	@echo ""
	@echo "Install dependencies (RHEL/CentOS):"
	@echo "  sudo yum install mongo-c-driver-devel proftpd-devel pkgconfig"

.PHONY: all clean install help check-deps
