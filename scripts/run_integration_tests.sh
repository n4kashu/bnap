#!/bin/bash

# Bitcoin Native Asset Protocol - Network Integration Test Runner
# This script sets up the environment and runs comprehensive integration tests

set -e

echo "🧪 BNAP Network Integration Test Runner"
echo "======================================="

# Check if Bitcoin Core is installed
if ! command -v bitcoind &> /dev/null; then
    echo "❌ Bitcoin Core not found!"
    echo "Please install Bitcoin Core to run integration tests:"
    echo "  - Ubuntu/Debian: sudo apt-get install bitcoind"
    echo "  - macOS: brew install bitcoin"
    echo "  - Build from source: https://github.com/bitcoin/bitcoin"
    exit 1
fi

if ! command -v bitcoin-cli &> /dev/null; then
    echo "❌ bitcoin-cli not found!"
    echo "Please install Bitcoin Core CLI tools"
    exit 1
fi

echo "✅ Bitcoin Core found: $(bitcoind --version | head -n1)"

# Check Python dependencies
echo "📦 Checking Python dependencies..."

# Check if we're in the project directory
if [ ! -f "network/rpc.py" ]; then
    echo "❌ Please run this script from the project root directory"
    exit 1
fi

# Set PYTHONPATH
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Check required Python packages
REQUIRED_PACKAGES=("psutil")
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! python3 -c "import $pkg" 2>/dev/null; then
        echo "❌ Missing Python package: $pkg"
        echo "Install with: pip install $pkg"
        exit 1
    fi
done

echo "✅ Python dependencies satisfied"

# Set environment variables for testing
export BITCOIN_RPC_HOST=localhost
export BITCOIN_RPC_USER=test
export BITCOIN_RPC_PASSWORD=test

# Create tests directory if it doesn't exist
mkdir -p tests

echo "🚀 Starting integration tests..."
echo ""

# Run the integration tests
if python3 tests/test_network_integration.py; then
    echo ""
    echo "✅ All network integration tests passed!"
    echo ""
    echo "📊 Test Summary:"
    echo "  - RPC Client Integration: ✅"
    echo "  - Transaction Broadcasting: ✅"
    echo "  - Confirmation Monitoring: ✅"
    echo "  - Mempool Monitoring: ✅"
    echo "  - Registry Synchronization: ✅"
    echo "  - Multi-Node Failover: ✅"
    echo "  - Performance Benchmarks: ✅"
    echo "  - Stress Testing: ✅"
    echo ""
    echo "🎉 Network integration test suite completed successfully!"
    exit 0
else
    echo ""
    echo "❌ Some integration tests failed!"
    echo ""
    echo "💡 Troubleshooting tips:"
    echo "  1. Ensure Bitcoin Core is properly installed and in PATH"
    echo "  2. Check that no other Bitcoin processes are running"
    echo "  3. Verify sufficient disk space for regtest data"
    echo "  4. Check firewall/port availability"
    echo "  5. Review test output for specific error messages"
    echo ""
    exit 1
fi