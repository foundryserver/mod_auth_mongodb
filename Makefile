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

# Build rule
all: $(TARGET)

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

.PHONY: all clean install help
