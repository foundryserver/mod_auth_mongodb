#!/bin/bash
# ProFTPD MongoDB Auth - Connection Diagnostics Script
# This script helps diagnose parallel connection and pool exhaustion issues

echo "=================================================="
echo "ProFTPD MongoDB Auth - Connection Diagnostics"
echo "=================================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

echo "1. Checking ProFTPD Configuration..."
echo "-----------------------------------"

# Find ProFTPD config
PROFTPD_CONF="/etc/proftpd/proftpd.conf"
if [ ! -f "$PROFTPD_CONF" ]; then
    PROFTPD_CONF="/usr/local/etc/proftpd.conf"
fi

if [ ! -f "$PROFTPD_CONF" ]; then
    echo -e "${YELLOW}WARNING: Could not find proftpd.conf${NC}"
    echo "Please specify path manually"
else
    echo "Config file: $PROFTPD_CONF"
    
    # Check MaxInstances
    MAX_INSTANCES=$(grep "^[[:space:]]*MaxInstances" "$PROFTPD_CONF" | awk '{print $2}')
    if [ -z "$MAX_INSTANCES" ]; then
        echo -e "${YELLOW}WARNING: MaxInstances not set (default: 30)${NC}"
        MAX_INSTANCES=30
    else
        echo "MaxInstances: $MAX_INSTANCES"
        if [ "$MAX_INSTANCES" -lt 50 ]; then
            echo -e "${YELLOW}  ⚠ RECOMMENDATION: Increase to 100 for parallel SFTP${NC}"
        else
            echo -e "${GREEN}  ✓ Good for parallel connections${NC}"
        fi
    fi
    
    # Check MongoDB Pool Size
    POOL_SIZE=$(grep "^[[:space:]]*AuthMongoConnectionPoolSize" "$PROFTPD_CONF" | awk '{print $2}')
    if [ -z "$POOL_SIZE" ]; then
        echo -e "${YELLOW}WARNING: AuthMongoConnectionPoolSize not set (default: 50)${NC}"
        POOL_SIZE=50
    else
        echo "AuthMongoConnectionPoolSize: $POOL_SIZE"
        if [ "$POOL_SIZE" -lt 20 ]; then
            echo -e "${RED}  ✗ TOO SMALL: Increase to at least 50${NC}"
        elif [ "$POOL_SIZE" -lt 40 ]; then
            echo -e "${YELLOW}  ⚠ May be too small for heavy parallel usage${NC}"
        else
            echo -e "${GREEN}  ✓ Good for parallel connections${NC}"
        fi
    fi
    
    # Check debug logging
    DEBUG=$(grep "^[[:space:]]*AuthMongoDebugLogging" "$PROFTPD_CONF" | awk '{print $2}')
    if [ -z "$DEBUG" ]; then
        echo "AuthMongoDebugLogging: not set (default: off)"
        echo -e "${YELLOW}  ⚠ Enable for troubleshooting: AuthMongoDebugLogging yes${NC}"
    else
        echo "AuthMongoDebugLogging: $DEBUG"
    fi
fi

echo ""
echo "2. Checking ProFTPD Process..."
echo "----------------------------"

if pgrep proftpd > /dev/null; then
    echo -e "${GREEN}✓ ProFTPD is running${NC}"
    PROFTPD_PID=$(pgrep proftpd | head -1)
    echo "  PID: $PROFTPD_PID"
    
    # Check how long it's been running
    UPTIME=$(ps -p $PROFTPD_PID -o etime= | tr -d ' ')
    echo "  Uptime: $UPTIME"
else
    echo -e "${RED}✗ ProFTPD is NOT running${NC}"
    echo "  Start with: systemctl start proftpd"
fi

echo ""
echo "3. Checking Current Connections..."
echo "--------------------------------"

# Find ProFTPD port
PROFTPD_PORT=$(grep "^[[:space:]]*Port" "$PROFTPD_CONF" 2>/dev/null | awk '{print $2}')
if [ -z "$PROFTPD_PORT" ]; then
    PROFTPD_PORT=21  # Default FTP port
fi

ACTIVE_CONNECTIONS=$(netstat -tn 2>/dev/null | grep ":$PROFTPD_PORT " | grep ESTABLISHED | wc -l)
echo "Active connections on port $PROFTPD_PORT: $ACTIVE_CONNECTIONS"

if [ "$ACTIVE_CONNECTIONS" -gt 0 ]; then
    if [ ! -z "$MAX_INSTANCES" ] && [ "$ACTIVE_CONNECTIONS" -gt "$((MAX_INSTANCES - 10))" ]; then
        echo -e "${YELLOW}  ⚠ Approaching MaxInstances limit${NC}"
    fi
    
    if [ ! -z "$POOL_SIZE" ] && [ "$ACTIVE_CONNECTIONS" -gt "$((POOL_SIZE / 2))" ]; then
        echo -e "${YELLOW}  ⚠ High load on MongoDB connection pool${NC}"
    fi
fi

echo ""
echo "4. Checking Logs for Errors..."
echo "-----------------------------"

LOG_FILE="/var/log/proftpd/system.log"
if [ ! -f "$LOG_FILE" ]; then
    LOG_FILE="/var/log/proftpd.log"
fi

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${YELLOW}WARNING: Could not find log file${NC}"
else
    echo "Log file: $LOG_FILE"
    echo ""
    
    # Check for pool exhaustion errors (last 100 lines)
    POOL_ERRORS=$(tail -100 "$LOG_FILE" | grep -c "Failed to get MongoDB client from pool")
    if [ "$POOL_ERRORS" -gt 0 ]; then
        echo -e "${RED}✗ POOL EXHAUSTION DETECTED: $POOL_ERRORS errors in last 100 lines${NC}"
        echo "  Last error:"
        tail -100 "$LOG_FILE" | grep "Failed to get MongoDB client from pool" | tail -1 | sed 's/^/  /'
        echo -e "${YELLOW}  ACTION REQUIRED: Increase AuthMongoConnectionPoolSize${NC}"
    else
        echo -e "${GREEN}✓ No pool exhaustion errors (last 100 lines)${NC}"
    fi
    
    # Check for connection errors
    CONN_ERRORS=$(tail -100 "$LOG_FILE" | grep -c "Could not connect")
    if [ "$CONN_ERRORS" -gt 0 ]; then
        echo -e "${RED}✗ CONNECTION ERRORS: $CONN_ERRORS errors in last 100 lines${NC}"
    else
        echo -e "${GREEN}✓ No connection errors (last 100 lines)${NC}"
    fi
    
    # Check successful authentications
    SUCCESS_COUNT=$(tail -100 "$LOG_FILE" | grep -c "Authentication successful")
    echo "Recent successful authentications: $SUCCESS_COUNT"
    
    # Check pool initialization
    POOL_INIT=$(grep "Connection pool created" "$LOG_FILE" | tail -1)
    if [ ! -z "$POOL_INIT" ]; then
        echo ""
        echo "Pool initialization:"
        echo "$POOL_INIT" | sed 's/^/  /'
    fi
fi

echo ""
echo "5. MongoDB Connection Test..."
echo "----------------------------"

# Extract MongoDB connection string from config
MONGO_URI=$(grep "^[[:space:]]*AuthMongoConnectionString" "$PROFTPD_CONF" 2>/dev/null | sed 's/AuthMongoConnectionString[[:space:]]*//' | tr -d '"')
if [ -z "$MONGO_URI" ]; then
    echo -e "${YELLOW}WARNING: Could not extract MongoDB URI from config${NC}"
else
    echo "Testing MongoDB connectivity..."
    # Try to ping MongoDB using mongosh or mongo
    if command -v mongosh &> /dev/null; then
        if timeout 5 mongosh "$MONGO_URI" --quiet --eval "db.adminCommand('ping')" &> /dev/null; then
            echo -e "${GREEN}✓ MongoDB is accessible${NC}"
        else
            echo -e "${RED}✗ MongoDB connection FAILED${NC}"
            echo "  Check connection string and MongoDB server status"
        fi
    elif command -v mongo &> /dev/null; then
        if timeout 5 mongo "$MONGO_URI" --quiet --eval "db.adminCommand('ping')" &> /dev/null; then
            echo -e "${GREEN}✓ MongoDB is accessible${NC}"
        else
            echo -e "${RED}✗ MongoDB connection FAILED${NC}"
            echo "  Check connection string and MongoDB server status"
        fi
    else
        echo -e "${YELLOW}  ⚠ mongosh/mongo client not found, skipping MongoDB test${NC}"
    fi
fi

echo ""
echo "6. Recommendations..."
echo "-------------------"

ISSUES_FOUND=0

if [ ! -z "$POOL_SIZE" ] && [ "$POOL_SIZE" -lt 40 ]; then
    echo -e "${YELLOW}• Increase AuthMongoConnectionPoolSize to at least 50${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

if [ ! -z "$MAX_INSTANCES" ] && [ "$MAX_INSTANCES" -lt 50 ]; then
    echo -e "${YELLOW}• Increase MaxInstances to at least 100${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

if [ "$POOL_ERRORS" -gt 0 ]; then
    echo -e "${RED}• CRITICAL: MongoDB pool exhaustion detected - increase pool size NOW${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

if [ "$ISSUES_FOUND" -eq 0 ]; then
    echo -e "${GREEN}✓ No issues detected - configuration looks good!${NC}"
fi

echo ""
echo "=================================================="
echo "Diagnostic complete!"
echo ""
echo "For more information, see:"
echo "  - PARALLEL_CONNECTIONS_FIX.md"
echo "  - proftpd.conf.sample"
echo "=================================================="
