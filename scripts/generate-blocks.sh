#!/bin/bash

# Generate test blocks in regtest
# Bitcoin Native Asset Protocol

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$PROJECT_ROOT/config/bitcoin.conf"
DATADIR="$PROJECT_ROOT/.bitcoin-regtest"

# Default values
BLOCKS=${1:-1}
ADDRESS=${2:-}

echo "Generating $BLOCKS blocks..."

# Check if daemon is running
if ! pgrep -f "bitcoind.*regtest" > /dev/null; then
    echo "Error: Bitcoin daemon is not running"
    echo "Start it with: ./scripts/start-bitcoin.sh"
    exit 1
fi

# Get or create address
if [ -z "$ADDRESS" ]; then
    ADDRESS=$(bitcoin-cli -conf="$CONFIG_FILE" -datadir="$DATADIR" getnewaddress)
    echo "Using new address: $ADDRESS"
else
    echo "Using provided address: $ADDRESS"
fi

# Generate blocks
bitcoin-cli -conf="$CONFIG_FILE" -datadir="$DATADIR" generatetoaddress "$BLOCKS" "$ADDRESS"

# Show current block height
HEIGHT=$(bitcoin-cli -conf="$CONFIG_FILE" -datadir="$DATADIR" getblockcount)
echo "Current block height: $HEIGHT"

# Show balance for the address
BALANCE=$(bitcoin-cli -conf="$CONFIG_FILE" -datadir="$DATADIR" getreceivedbyaddress "$ADDRESS")
echo "Balance for $ADDRESS: $BALANCE BTC"