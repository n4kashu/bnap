# Bitcoin Node Setup Guide

This guide provides comprehensive instructions for setting up and configuring Bitcoin Core nodes for BNAP deployment across different environments.

## Bitcoin Core Installation

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 2 GB (4 GB recommended)
- **Storage**: 500 GB for mainnet, 50 GB for testnet
- **Network**: 50 GB/month bandwidth

#### Recommended Requirements
- **CPU**: 4+ cores, 2.5 GHz
- **RAM**: 8 GB (16 GB for high-traffic)
- **Storage**: 1 TB SSD (NVMe preferred)
- **Network**: 100 Mbps unlimited bandwidth

### Installation Methods

#### Method 1: Official Bitcoin PPA (Ubuntu/Debian)

```bash
# Add Bitcoin Core PPA
sudo add-apt-repository ppa:bitcoin/bitcoin
sudo apt update

# Install Bitcoin Core
sudo apt install -y bitcoind bitcoin-cli bitcoin-qt

# Verify installation
bitcoind --version
```

#### Method 2: Binary Download and Installation

```bash
# Download Bitcoin Core (replace version as needed)
cd /tmp
wget https://bitcoincore.org/bin/bitcoin-core-25.0/bitcoin-25.0-x86_64-linux-gnu.tar.gz

# Download and verify checksums
wget https://bitcoincore.org/bin/bitcoin-core-25.0/SHA256SUMS
wget https://bitcoincore.org/bin/bitcoin-core-25.0/SHA256SUMS.asc

# Import Bitcoin Core signing keys
gpg --keyserver hkp://keyserver.ubuntu.com --recv-keys 01EA5486DE18A882D4C2684590C8019E36C2E964

# Verify signatures
gpg --verify SHA256SUMS.asc SHA256SUMS

# Verify checksums
sha256sum --ignore-missing --check SHA256SUMS

# Extract and install
tar -xzf bitcoin-25.0-x86_64-linux-gnu.tar.gz
sudo install -m 0755 -o root -g root -t /usr/local/bin bitcoin-25.0/bin/*

# Create Bitcoin data directory
mkdir -p ~/.bitcoin
```

#### Method 3: Compilation from Source

```bash
# Install build dependencies
sudo apt install -y build-essential libtool autotools-dev automake pkg-config \
    libssl-dev libevent-dev bsdmainutils python3 libboost-system-dev \
    libboost-filesystem-dev libboost-chrono-dev libboost-test-dev \
    libboost-thread-dev libdb-dev libdb++-dev libminiupnpc-dev \
    libzmq3-dev libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev \
    qttools5-dev-tools libprotobuf-dev protobuf-compiler

# Clone Bitcoin repository
git clone https://github.com/bitcoin/bitcoin.git
cd bitcoin

# Checkout stable version
git checkout v25.0

# Build Bitcoin Core
./autogen.sh
./configure --enable-wallet --with-gui=qt5
make -j$(nproc)
sudo make install

# Verify installation
bitcoin-cli --version
```

## Network-Specific Configuration

### Mainnet Configuration

Create `~/.bitcoin/bitcoin.conf`:

```ini
# Network configuration
mainnet=1
testnet=0
regtest=0

# RPC configuration
server=1
rpcuser=bnap_mainnet_user
rpcpassword=REPLACE_WITH_SECURE_PASSWORD
rpcallowip=127.0.0.1
rpcport=8332
rpcbind=127.0.0.1

# Connection settings
maxconnections=50
timeout=30000

# Performance optimizations
dbcache=2000
maxmempool=500
mempoolexpiry=72

# Security settings
disablewallet=0
walletnotify=echo "Wallet transaction: %s" >> /var/log/bitcoin/wallet.log

# Logging
debug=rpc
debug=net
printtoconsole=0
logips=1

# Fee estimation
blocksonly=0
fallbackfee=0.00001000

# Pruning (optional, saves disk space)
# prune=2000  # Keep only 2GB of block data

# ZMQ notifications (for real-time updates)
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
zmqpubhashtx=tcp://127.0.0.1:28334
zmqpubhashblock=tcp://127.0.0.1:28335
```

### Testnet Configuration

Create `~/.bitcoin/bitcoin.conf`:

```ini
# Network configuration
mainnet=0
testnet=1
regtest=0

# RPC configuration
server=1
rpcuser=bnap_testnet_user
rpcpassword=testnet_secure_password_123
rpcallowip=127.0.0.1
rpcport=18332
rpcbind=127.0.0.1

# Connection settings
maxconnections=20
timeout=15000

# Performance settings (lighter for testing)
dbcache=1000
maxmempool=300
mempoolexpiry=24

# Fast sync settings for testnet
assumevalid=00000000000000000000000000000000000000000000000000000000000000000
checkpoints=0

# Logging
debug=rpc
printtoconsole=0
logips=0

# Fee settings
fallbackfee=0.00010000
mintxfee=0.00001000

# ZMQ for development
zmqpubrawblock=tcp://127.0.0.1:28432
zmqpubrawtx=tcp://127.0.0.1:28433
```

### Regtest Configuration (Development)

Create `~/.bitcoin/bitcoin.conf`:

```ini
# Network configuration
mainnet=0
testnet=0
regtest=1

# RPC configuration
server=1
rpcuser=bnap_regtest
rpcpassword=regtest123
rpcallowip=127.0.0.1
rpcallowip=0.0.0.0/0
rpcport=18443
rpcbind=0.0.0.0

# Fast development settings
dbcache=100
maxmempool=50
connect=0
listen=0

# No fees in regtest
fallbackfee=0.00000000
paytxfee=0.00000000

# Logging
debug=1
printtoconsole=1
logips=0

# ZMQ for development
zmqpubrawblock=tcp://127.0.0.1:28543
zmqpubrawtx=tcp://127.0.0.1:28544
```

## Production Deployment

### System Service Configuration

#### Create Bitcoin User

```bash
# Create dedicated user for Bitcoin
sudo useradd -r -s /bin/false bitcoin
sudo mkdir -p /home/bitcoin/.bitcoin
sudo chown -R bitcoin:bitcoin /home/bitcoin
```

#### Systemd Service File

Create `/etc/systemd/system/bitcoind.service`:

```ini
[Unit]
Description=Bitcoin Core Daemon
Documentation=https://github.com/bitcoin/bitcoin/blob/master/doc/init.md
After=network.target

[Service]
Type=notify
NotifyAccess=all
ExecStart=/usr/local/bin/bitcoind -daemon \
                                 -pid=/run/bitcoind/bitcoind.pid \
                                 -conf=/home/bitcoin/.bitcoin/bitcoin.conf \
                                 -datadir=/home/bitcoin/.bitcoin \
                                 -startupnotify='systemd-notify --ready'

# Process management
PIDFile=/run/bitcoind/bitcoind.pid
Restart=always
RestartSec=30
TimeoutStartSec=infinity
TimeoutStopSec=600

# User and group
User=bitcoin
Group=bitcoin

# Directory permissions
RuntimeDirectory=bitcoind
RuntimeDirectoryMode=0710

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

# Resource limits
LimitNOFILE=128000

[Install]
WantedBy=multi-user.target
```

#### Enable and Start Service

```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable Bitcoin service
sudo systemctl enable bitcoind

# Start Bitcoin service
sudo systemctl start bitcoind

# Check service status
sudo systemctl status bitcoind

# View logs
sudo journalctl -u bitcoind -f
```

### Security Hardening

#### File Permissions

```bash
# Set secure permissions
sudo chmod 700 /home/bitcoin/.bitcoin
sudo chmod 600 /home/bitcoin/.bitcoin/bitcoin.conf
sudo chown -R bitcoin:bitcoin /home/bitcoin/.bitcoin

# Create log directory
sudo mkdir -p /var/log/bitcoin
sudo chown bitcoin:bitcoin /var/log/bitcoin
sudo chmod 755 /var/log/bitcoin
```

#### Network Security

```bash
# Configure firewall
sudo ufw allow from 10.0.0.0/8 to any port 8332    # RPC access (internal only)
sudo ufw allow from 172.16.0.0/12 to any port 8332
sudo ufw allow from 192.168.0.0/16 to any port 8332
sudo ufw allow 8333/tcp                             # P2P network
sudo ufw allow 18333/tcp                            # Testnet P2P

# For production, consider IP whitelisting
sudo ufw allow from YOUR_BNAP_SERVER_IP to any port 8332
```

#### RPC Security

```bash
# Generate secure RPC password
RPC_PASSWORD=$(openssl rand -base64 32)

# Update bitcoin.conf with secure credentials
sudo sed -i "s/rpcpassword=.*/rpcpassword=$RPC_PASSWORD/" /home/bitcoin/.bitcoin/bitcoin.conf

# Store credentials securely for BNAP
echo "RPC_PASSWORD=$RPC_PASSWORD" | sudo tee /etc/bnap/bitcoin-rpc.env
sudo chmod 600 /etc/bnap/bitcoin-rpc.env
sudo chown bnap:bnap /etc/bnap/bitcoin-rpc.env
```

## Docker Deployment

### Bitcoin Core Dockerfile

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create bitcoin user
RUN groupadd -r bitcoin && useradd -r -g bitcoin bitcoin

# Install Bitcoin Core
RUN cd /tmp && \
    wget https://bitcoincore.org/bin/bitcoin-core-25.0/bitcoin-25.0-x86_64-linux-gnu.tar.gz && \
    wget https://bitcoincore.org/bin/bitcoin-core-25.0/SHA256SUMS && \
    sha256sum --ignore-missing --check SHA256SUMS && \
    tar -xzf bitcoin-25.0-x86_64-linux-gnu.tar.gz && \
    install -m 0755 -o root -g root -t /usr/local/bin bitcoin-25.0/bin/* && \
    rm -rf /tmp/*

# Create data directory
RUN mkdir -p /home/bitcoin/.bitcoin && \
    chown -R bitcoin:bitcoin /home/bitcoin

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports
EXPOSE 8332 8333 18332 18333 18443 18444

# Set volume
VOLUME ["/home/bitcoin/.bitcoin"]

# Set entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["bitcoind"]
```

### Docker Entrypoint Script

Create `docker-entrypoint.sh`:

```bash
#!/bin/bash
set -e

# Set default UID/GID if not provided
BITCOIN_UID=${BITCOIN_UID:-1000}
BITCOIN_GID=${BITCOIN_GID:-1000}

# Create bitcoin user with specified UID/GID
groupmod -g "$BITCOIN_GID" bitcoin
usermod -u "$BITCOIN_UID" -g "$BITCOIN_GID" bitcoin

# Fix permissions
chown -R bitcoin:bitcoin /home/bitcoin/.bitcoin

# Execute command as bitcoin user
exec gosu bitcoin "$@"
```

### Docker Compose Configuration

```yaml
version: '3.8'

services:
  bitcoin-mainnet:
    build: .
    container_name: bitcoin-mainnet
    restart: unless-stopped
    ports:
      - "8332:8332"   # RPC
      - "8333:8333"   # P2P
    volumes:
      - bitcoin_mainnet_data:/home/bitcoin/.bitcoin
      - ./config/bitcoin-mainnet.conf:/home/bitcoin/.bitcoin/bitcoin.conf:ro
    environment:
      - BITCOIN_UID=1000
      - BITCOIN_GID=1000
    command: >
      bitcoind
      -conf=/home/bitcoin/.bitcoin/bitcoin.conf
      -datadir=/home/bitcoin/.bitcoin
      -printtoconsole
    healthcheck:
      test: ["CMD", "bitcoin-cli", "getblockchaininfo"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5m

  bitcoin-testnet:
    build: .
    container_name: bitcoin-testnet
    restart: unless-stopped
    ports:
      - "18332:18332" # RPC
      - "18333:18333" # P2P
    volumes:
      - bitcoin_testnet_data:/home/bitcoin/.bitcoin
      - ./config/bitcoin-testnet.conf:/home/bitcoin/.bitcoin/bitcoin.conf:ro
    environment:
      - BITCOIN_UID=1000
      - BITCOIN_GID=1000
    command: >
      bitcoind
      -conf=/home/bitcoin/.bitcoin/bitcoin.conf
      -datadir=/home/bitcoin/.bitcoin
      -printtoconsole

volumes:
  bitcoin_mainnet_data:
  bitcoin_testnet_data:
```

## High Availability Setup

### Multiple Node Configuration

#### Primary Node Configuration

```ini
# Primary node (bitcoin-primary.conf)
mainnet=1
server=1

# RPC settings
rpcuser=bnap_primary
rpcpassword=primary_secure_password
rpcallowip=10.0.1.0/24
rpcport=8332

# Networking
maxconnections=100
addnode=bitcoin-backup.local:8333

# ZMQ for replication
zmqpubrawblock=tcp://0.0.0.0:28332
zmqpubrawtx=tcp://0.0.0.0:28333
```

#### Backup Node Configuration

```ini
# Backup node (bitcoin-backup.conf)
mainnet=1
server=1

# RPC settings
rpcuser=bnap_backup
rpcpassword=backup_secure_password
rpcallowip=10.0.1.0/24
rpcport=8332

# Networking
maxconnections=100
connect=bitcoin-primary.local:8333

# Read-only mode
disablewallet=1
```

### Load Balancer Configuration (HAProxy)

```
global
    daemon
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

listen bitcoin_rpc
    bind *:8332
    balance roundrobin
    option tcp-check
    tcp-check send-binary 504f5354202f20485454502f312e310d0a0d0a
    tcp-check expect string HTTP/1.1
    
    server bitcoin-primary bitcoin-primary.local:8332 check
    server bitcoin-backup bitcoin-backup.local:8332 check backup

listen bitcoin_p2p
    bind *:8333
    balance source
    server bitcoin-primary bitcoin-primary.local:8333 check
    server bitcoin-backup bitcoin-backup.local:8333 check backup
```

## Performance Optimization

### Memory Optimization

```ini
# Memory-optimized configuration
dbcache=4000           # Use 4GB for database cache
maxmempool=1000        # 1GB mempool
mempoolexpiry=72       # 3-day expiry

# Reduce memory usage
blocksonly=1           # Download blocks only, no loose transactions
maxconnections=20      # Limit connections
```

### I/O Optimization

```ini
# I/O optimized settings
assumevalid=LATEST_BLOCK_HASH  # Skip signature validation for old blocks
checkpoints=1                   # Use checkpoints
par=4                          # Parallel script verification threads

# Database settings
dblogsize=1000
flushwallet=1
```

### Network Optimization

```ini
# Network optimization
maxconnections=100
maxreceivebuffer=5000
maxsendbuffer=1000
timeout=30000

# Connection management
addnode=seed.bitcoin.sipa.be
addnode=dnsseed.bluematt.me
addnode=dnsseed.bitcoin.dashjr.org
```

## Monitoring and Maintenance

### Health Check Scripts

Create `/usr/local/bin/bitcoin-health-check.sh`:

```bash
#!/bin/bash

# Bitcoin health check script
BITCOIN_CLI="/usr/local/bin/bitcoin-cli"
RPC_USER="bnap_user"
RPC_PASSWORD="$(grep rpcpassword ~/.bitcoin/bitcoin.conf | cut -d'=' -f2)"

# Check if Bitcoin daemon is running
if ! pgrep -f bitcoind > /dev/null; then
    echo "ERROR: Bitcoin daemon is not running"
    exit 1
fi

# Check RPC connectivity
if ! $BITCOIN_CLI -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASSWORD" getblockchaininfo > /dev/null 2>&1; then
    echo "ERROR: Cannot connect to Bitcoin RPC"
    exit 1
fi

# Check sync status
BLOCK_COUNT=$($BITCOIN_CLI -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASSWORD" getblockcount)
CHAIN_INFO=$($BITCOIN_CLI -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASSWORD" getblockchaininfo)
VERIFICATION_PROGRESS=$(echo "$CHAIN_INFO" | jq -r '.verificationprogress')

if (( $(echo "$VERIFICATION_PROGRESS < 0.99" | bc -l) )); then
    echo "WARNING: Node is still syncing ($VERIFICATION_PROGRESS%)"
fi

echo "OK: Bitcoin node healthy (block $BLOCK_COUNT)"
```

### Log Rotation Configuration

Create `/etc/logrotate.d/bitcoin`:

```
/var/log/bitcoin/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 bitcoin bitcoin
    postrotate
        systemctl reload bitcoind
    endscript
}
```

### Backup Scripts

Create `/usr/local/bin/bitcoin-backup.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/var/backups/bitcoin"
BITCOIN_DIR="/home/bitcoin/.bitcoin"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop Bitcoin (optional, for consistent backup)
# systemctl stop bitcoind

# Backup wallet and configuration
tar -czf "$BACKUP_DIR/bitcoin_backup_$DATE.tar.gz" \
    "$BITCOIN_DIR/bitcoin.conf" \
    "$BITCOIN_DIR/wallet.dat" \
    "$BITCOIN_DIR/peers.dat"

# Restart Bitcoin
# systemctl start bitcoind

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "bitcoin_backup_*.tar.gz" -mtime +30 -delete

echo "Bitcoin backup completed: bitcoin_backup_$DATE.tar.gz"
```

## Troubleshooting

### Common Issues

#### Slow Initial Sync

```bash
# Check sync progress
bitcoin-cli getblockchaininfo | jq '.verificationprogress'

# Optimize for faster sync
echo "assumevalid=$(bitcoin-cli getbestblockhash)" >> ~/.bitcoin/bitcoin.conf
echo "par=$(nproc)" >> ~/.bitcoin/bitcoin.conf
```

#### RPC Connection Issues

```bash
# Test RPC connection
bitcoin-cli -rpcuser=your_user -rpcpassword=your_password getblockchaininfo

# Check if RPC server is enabled
grep "server=1" ~/.bitcoin/bitcoin.conf

# Verify RPC credentials
grep -E "rpc(user|password)" ~/.bitcoin/bitcoin.conf
```

#### High Memory Usage

```bash
# Monitor Bitcoin memory usage
ps aux | grep bitcoind

# Reduce memory usage
bitcoin-cli setmempoolsize 100  # Reduce mempool to 100MB
```

#### Network Connectivity Issues

```bash
# Check peer connections
bitcoin-cli getpeerinfo | jq length

# Add specific peers
bitcoin-cli addnode "seed.bitcoin.sipa.be" "add"

# Check network info
bitcoin-cli getnetworkinfo
```

### Debugging Tools

```bash
# Enable debug logging
echo "debug=net" >> ~/.bitcoin/bitcoin.conf
echo "debug=rpc" >> ~/.bitcoin/bitcoin.conf

# View debug log
tail -f ~/.bitcoin/debug.log

# RPC debugging
bitcoin-cli -rpcwait getblockchaininfo
bitcoin-cli help  # List all RPC commands
```

This comprehensive Bitcoin node setup guide ensures optimal configuration for BNAP integration across all deployment environments.