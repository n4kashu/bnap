#!/bin/bash

# Stop Bitcoin Core daemon 
# Bitcoin Native Asset Protocol

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$PROJECT_ROOT/config/bitcoin.conf"
DATADIR="$PROJECT_ROOT/.bitcoin-regtest"

echo "Stopping Bitcoin Core daemon..."

# Check if daemon is running
if ! pgrep -f "bitcoind.*regtest" > /dev/null; then
    echo "Bitcoin daemon doesn't appear to be running"
    exit 0
fi

# Stop the daemon gracefully
bitcoin-cli -conf="$CONFIG_FILE" -datadir="$DATADIR" stop

echo "Bitcoin daemon stop command sent"
echo "Waiting for daemon to shut down..."

# Wait for daemon to stop
timeout=30
while pgrep -f "bitcoind.*regtest" > /dev/null && [ $timeout -gt 0 ]; do
    sleep 1
    timeout=$((timeout - 1))
done

if pgrep -f "bitcoind.*regtest" > /dev/null; then
    echo "Warning: Daemon did not stop gracefully, you may need to kill it manually"
    echo "Use: pkill -f 'bitcoind.*regtest'"
    exit 1
else
    echo "Bitcoin daemon stopped successfully!"
fi