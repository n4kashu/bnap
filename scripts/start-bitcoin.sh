#!/bin/bash

# Start Bitcoin Core daemon for regtest development
# Bitcoin Native Asset Protocol

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$PROJECT_ROOT/config/bitcoin.conf"

echo "Starting Bitcoin Core daemon in regtest mode..."

# Check if bitcoind is available
if ! command -v bitcoind &> /dev/null; then
    echo "Error: bitcoind not found. Please install Bitcoin Core."
    exit 1
fi

# Check if daemon is already running
if pgrep -f "bitcoind.*regtest" > /dev/null; then
    echo "Bitcoin daemon appears to be already running"
    exit 1
fi

# Create data directory if it doesn't exist
DATADIR="$PROJECT_ROOT/.bitcoin-regtest"
mkdir -p "$DATADIR"

# Start the daemon
bitcoind \
    -conf="$CONFIG_FILE" \
    -datadir="$DATADIR" \
    -daemon

echo "Bitcoin daemon started successfully!"
echo "RPC available at: http://127.0.0.1:18443"
echo "Data directory: $DATADIR"

# Wait a moment for daemon to start
sleep 2

# Generate initial blocks if this is a fresh start
if [ ! -f "$DATADIR/regtest/blocks/blk00000.dat" ]; then
    echo "Generating initial blocks for regtest..."
    sleep 3  # Give daemon more time to start
    
    # Generate an address and mine some blocks
    ADDRESS=$(bitcoin-cli -conf="$CONFIG_FILE" -datadir="$DATADIR" getnewaddress)
    bitcoin-cli -conf="$CONFIG_FILE" -datadir="$DATADIR" generatetoaddress 101 "$ADDRESS"
    
    echo "Generated 101 blocks to address: $ADDRESS"
fi

echo "Bitcoin regtest environment ready!"
echo "Use 'bitcoin-cli -conf=$CONFIG_FILE -datadir=$DATADIR <command>' to interact"