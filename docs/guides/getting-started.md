# Getting Started with BNAP

This tutorial walks you through your first BNAP asset creation and minting operations, from installation to your first successful transaction.

## Prerequisites

Before starting, ensure you have:

- **Python 3.8 or later**
- **Bitcoin Core 24.0+** installed and running
- **At least 0.01 BTC** for transaction fees (testnet is fine for learning)
- **Basic command line familiarity**

## Step 1: Install BNAP

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/bnap/bnap.git
cd bnap

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install BNAP
pip install -e .

# Verify installation
bnap --version
# Expected output: BNAP v1.0.0
```

### Verify Dependencies

```bash
# Check Bitcoin Core version
bitcoin-cli --version

# Test Bitcoin RPC connection
bitcoin-cli getblockchaininfo
```

## Step 2: Initial Setup

### Configure Bitcoin Node (Testnet)

Create or edit `~/.bitcoin/bitcoin.conf`:

```ini
# Use testnet for learning
testnet=1
server=1

# RPC configuration
rpcuser=bnap_tutorial
rpcpassword=secure_password_123
rpcallowip=127.0.0.1
rpcport=18332
```

### Start Bitcoin Node

```bash
# Start Bitcoin daemon (if not running)
bitcoind -daemon

# Wait for startup and check connection
sleep 10
bitcoin-cli getblockchaininfo
```

### Initialize BNAP

```bash
# Create BNAP configuration directory
mkdir -p ~/.bnap

# Generate validator keys
bnap config generate-keys \
    --validator-id "tutorial_validator" \
    --key-type schnorr \
    --output-file ~/.bnap/validator_keys.json

# Initialize registry
bnap registry init \
    --validator-id "tutorial_validator" \
    --network testnet

# Verify setup
bnap validator health-check
```

Expected output:
```
✅ Bitcoin RPC connection: OK
✅ Validator keys: OK  
✅ Registry access: OK
✅ Network: testnet
🎉 BNAP is ready!
```

## Step 3: Create Your First Fungible Token

### Design Your Token

Let's create a simple reward token:

- **Name**: Tutorial Rewards
- **Symbol**: REWARD
- **Maximum Supply**: 1,000,000 tokens
- **Per-mint Limit**: 10,000 tokens per transaction

### Create the Asset

```bash
# Create fungible token
bnap asset create-fungible \
    --name "Tutorial Rewards" \
    --symbol "REWARD" \
    --max-supply 1000000 \
    --per-mint-limit 10000 \
    --decimal-places 2 \
    --issuer-description "Learning token for BNAP tutorial"
```

Example output:
```
🎯 Creating fungible asset...
✅ Asset created successfully!

Asset Details:
  Asset ID: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
  Name: Tutorial Rewards
  Symbol: REWARD
  Maximum Supply: 1,000,000.00 REWARD
  Current Supply: 0.00 REWARD
  Status: Active
```

**💡 Pro Tip**: Save your Asset ID! You'll need it for all future operations.

### Verify Asset Creation

```bash
# Query the asset
bnap registry query --asset-type fungible --format table

# Get asset details
export TUTORIAL_ASSET_ID="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
bnap asset info --asset-id "$TUTORIAL_ASSET_ID"
```

## Step 4: Mint Your First Tokens

### Get a Bitcoin Address

```bash
# Create a new Bitcoin address for receiving tokens
RECIPIENT_ADDRESS=$(bitcoin-cli getnewaddress "tutorial_recipient" "bech32")
echo "Recipient address: $RECIPIENT_ADDRESS"
```

### Mint Tokens

```bash
# Mint 1,000 REWARD tokens
bnap mint fungible \
    --asset-id "$TUTORIAL_ASSET_ID" \
    --amount 1000 \
    --recipient "$RECIPIENT_ADDRESS" \
    --fee-rate 10
```

Example output:
```
🏭 Creating mint transaction...
📝 Transaction Details:
  Asset: Tutorial Rewards (REWARD)
  Amount: 10.00 REWARD  
  Recipient: tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
  Fee: 2,500 sats

🔍 Validating transaction...
✅ Supply check: OK (10.00 / 1,000,000.00)
✅ Mint limit: OK (10.00 / 100.00 per tx)  
✅ Recipient validation: OK
✅ Fee estimation: OK

📡 Broadcasting transaction...
✅ Transaction broadcast successfully!

Transaction ID: def456789abcdef123456789abcdef0123456789abcdef123456789abcdef01234
```

### Wait for Confirmation

```bash
# Check transaction status
bnap transaction status --txid "def456789abcdef123456789abcdef0123456789abcdef123456789abcdef01234"

# Monitor confirmations
watch "bnap transaction status --txid def456..."
```

**⏱️ Note**: Testnet confirmation typically takes 5-10 minutes.

### Verify the Mint

```bash
# Check asset supply
bnap asset info --asset-id "$TUTORIAL_ASSET_ID"

# View transaction history
bnap registry transactions --asset-id "$TUTORIAL_ASSET_ID"
```

Expected output:
```
Asset: Tutorial Rewards (REWARD)
Total Supply: 10.00 / 1,000,000.00 REWARD
Transactions: 1
Status: Active

Recent Transactions:
  def4567... | 2024-01-15 14:30 | MINT | 10.00 REWARD | ✅ Confirmed
```

## Step 5: Create Your First NFT

### Design Your NFT Collection

Let's create a simple art collection:

- **Collection Name**: Tutorial Art
- **Symbol**: ART
- **Collection Size**: 100 NFTs
- **Content**: IPFS-hosted images

### Prepare NFT Content

```bash
# Create content directory
mkdir -p ~/tutorial_nft_content

# Create sample metadata
cat > ~/tutorial_nft_content/metadata.json << EOF
{
  "name": "Tutorial Art #1",
  "description": "First NFT created with BNAP tutorial",
  "image": "https://example.com/tutorial_art_1.jpg",
  "attributes": [
    {
      "trait_type": "Color",
      "value": "Blue"
    },
    {
      "trait_type": "Rarity",
      "value": "Common"
    }
  ]
}
EOF

# Calculate content hash
CONTENT_HASH=$(sha256sum ~/tutorial_nft_content/metadata.json | cut -d' ' -f1)
echo "Content hash: $CONTENT_HASH"
```

### Create NFT Collection

```bash
# Create NFT asset
bnap asset create-nft \
    --name "Tutorial Art" \
    --symbol "ART" \
    --collection-size 100 \
    --content-hash "$CONTENT_HASH" \
    --content-uri "file://~/tutorial_nft_content/metadata.json" \
    --issuer-description "Tutorial NFT collection"
```

Example output:
```
🎨 Creating NFT collection...
✅ NFT collection created successfully!

Collection Details:
  Asset ID: 987fcdeb65432109876543210fedcba0987654321fedcba0987654321fedcba09
  Name: Tutorial Art
  Symbol: ART
  Collection Size: 100 NFTs
  Minted: 0 / 100
  Status: Active
```

### Mint Your First NFT

```bash
# Save NFT asset ID
export TUTORIAL_NFT_ID="987fcdeb65432109876543210fedcba0987654321fedcba0987654321fedcba09"

# Mint NFT #1
bnap mint nft \
    --asset-id "$TUTORIAL_NFT_ID" \
    --nft-id 1 \
    --recipient "$RECIPIENT_ADDRESS" \
    --content-hash "$CONTENT_HASH"
```

Example output:
```
🎨 Creating NFT mint transaction...
📝 NFT Details:
  Collection: Tutorial Art (ART)
  NFT ID: #1
  Content Hash: a1b2c3...
  Recipient: tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

✅ NFT minted successfully!
Transaction ID: abc123456789abcdef123456789abcdef0123456789abcdef123456789abcdef
```

## Step 6: Verify Your Assets

### Check Your Token Balance

```bash
# Query assets by recipient address
bnap query balance --address "$RECIPIENT_ADDRESS"

# Or check specific asset
bnap query balance \
    --address "$RECIPIENT_ADDRESS" \
    --asset-id "$TUTORIAL_ASSET_ID"
```

### View Your NFT

```bash
# Check NFT ownership
bnap query nft \
    --asset-id "$TUTORIAL_NFT_ID" \
    --nft-id 1

# View collection status
bnap asset info --asset-id "$TUTORIAL_NFT_ID"
```

### Generate Summary Report

```bash
# Create summary of tutorial progress
bnap report generate \
    --output-file ~/bnap_tutorial_report.html \
    --include-assets \
    --include-transactions \
    --format html
```

## Next Steps

Congratulations! 🎉 You've successfully:

- ✅ Installed and configured BNAP
- ✅ Created a fungible token (REWARD)
- ✅ Minted your first tokens
- ✅ Created an NFT collection (Tutorial Art)
- ✅ Minted your first NFT

### Explore Advanced Features

1. **[Allowlist Management](allowlists.md)**: Control who can receive your assets
2. **[NFT Collections](nft-collections.md)**: Advanced NFT creation and management
3. **[Transfer Operations](transfers.md)**: Move assets between addresses
4. **[Batch Operations](batch-operations.md)**: Process multiple transactions efficiently

### Common Next Tasks

#### Set Up Production Environment

```bash
# Switch to mainnet configuration
bnap config generate-template \
    --environment production \
    --network mainnet \
    --output-file ~/.bnap/production_config.json
```

#### Create More Assets

```bash
# Create utility token
bnap asset create-fungible \
    --name "Utility Token" \
    --symbol "UTIL" \
    --max-supply 100000000 \
    --per-mint-limit 1000000

# Create limited edition NFT collection
bnap asset create-nft \
    --name "Limited Edition" \
    --symbol "LIMITED" \
    --collection-size 10
```

#### Implement Allowlists

```bash
# Create allowlist for exclusive distribution
bnap allowlist create \
    --asset-id "$TUTORIAL_ASSET_ID" \
    --addresses-file allowed_addresses.txt
```

## Troubleshooting

### Common Issues

#### "Bitcoin RPC connection failed"

```bash
# Check Bitcoin is running
pgrep bitcoind

# Verify RPC configuration
bitcoin-cli getblockchaininfo

# Check BNAP configuration
bnap config show --format table
```

#### "Insufficient balance for fees"

```bash
# Get testnet Bitcoin from faucet
# Visit: https://testnet-faucet.mempool.co/

# Check Bitcoin balance
bitcoin-cli getbalance

# Generate test blocks (regtest only)
bitcoin-cli -regtest generatetoaddress 101 $(bitcoin-cli -regtest getnewaddress)
```

#### "Asset not found"

```bash
# Verify asset ID is correct
bnap registry query --format json | jq '.assets[].asset_id'

# Check registry status
bnap registry status
```

#### "Validation failed"

```bash
# Check validator status
bnap validator status

# Verify keys are loaded
ls -la ~/.bnap/validator_keys.json

# Test validation manually
bnap validator test --asset-id "$TUTORIAL_ASSET_ID"
```

## Getting Help

- **Documentation**: [docs.bnap.org](https://docs.bnap.org)
- **CLI Help**: `bnap --help` or `bnap COMMAND --help`
- **Community**: [Discord](https://discord.gg/bnap)
- **Issues**: [GitHub](https://github.com/bnap/bnap/issues)

### Debug Mode

For detailed troubleshooting, enable debug mode:

```bash
# Enable verbose logging
export BNAP_LOG_LEVEL=DEBUG

# Run commands with extra output
bnap --verbose asset create-fungible ...
```

## What You've Learned

- Basic BNAP installation and configuration
- Creating and configuring Bitcoin nodes for development
- Understanding asset types (fungible tokens vs NFTs)
- Transaction creation, validation, and broadcasting
- Registry management and asset tracking
- Basic troubleshooting and debugging

You're now ready to build more complex asset management workflows with BNAP! 🚀