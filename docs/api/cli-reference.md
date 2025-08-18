# CLI Reference

Complete command reference for the BNAP Command Line Interface, based on the actual implementation in `cli/commands/`.

## Global Options

Available for all commands:

```bash
bnap [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--config-file`, `-c` | Path to configuration file | `~/.bnap/config.json` |
| `--output-format`, `-o` | Output format: table, json, yaml, csv | `table` |
| `--verbose`, `-v` | Increase verbosity (-v for INFO, -vv for DEBUG) | `0` |
| `--version` | Show version information | - |
| `--show-examples` | Show usage examples | - |

## Asset Management (`bnap asset`)

Manage fungible tokens and NFT collections.

### Create Fungible Token

```bash
bnap asset create-fungible [OPTIONS]
```

Create a new fungible token asset with configurable supply limits.

**Options:**
- `--name` (required): Token name (e.g., "My Bitcoin Token")
- `--symbol` (required): Token symbol (e.g., "MBT", 2-10 characters)
- `--max-supply`: Maximum token supply (0 for unlimited)
- `--per-mint-limit`: Maximum tokens per mint operation
- `--description`: Token description
- `--icon-uri`: URI to token icon image
- `--website`: Project website URL
- `--from-file`: Load token definition from JSON file
- `--output-file`: Save asset configuration to file
- `--dry-run`: Validate inputs without creating asset
- `--show-examples`: Show usage examples

**Examples:**

```bash
# Create basic fungible token
bnap asset create-fungible \
  --name "Test Token" \
  --symbol "TEST" \
  --max-supply 1000000 \
  --per-mint-limit 10000

# Create from JSON file
bnap asset create-fungible \
  --from-file token-config.json \
  --output-file created-asset.json

# Dry run validation
bnap asset create-fungible \
  --name "Demo Token" \
  --symbol "DEMO" \
  --dry-run
```

**JSON Configuration Format:**
```json
{
  "name": "My Token",
  "symbol": "MTK",
  "max_supply": 1000000,
  "per_mint_limit": 10000,
  "description": "A test token for BNAP",
  "icon_uri": "https://example.com/icon.png",
  "website": "https://mytoken.org"
}
```

### Create NFT Collection

```bash
bnap asset create-nft [OPTIONS]
```

Create a new NFT collection for unique digital assets.

**Options:**
- `--name` (required): Collection name
- `--symbol` (required): Collection symbol
- `--collection-size`: Maximum NFTs in collection
- `--description`: Collection description
- `--base-uri`: Base URI for NFT metadata
- `--manifest-file`: Collection manifest JSON file
- `--content-hash`: Content hash for verification
- `--from-file`: Load collection definition from JSON file
- `--output-file`: Save collection configuration to file

**Examples:**

```bash
# Create NFT collection
bnap asset create-nft \
  --name "Art Collection" \
  --symbol "ART" \
  --collection-size 100 \
  --base-uri "ipfs://QmHash/"

# Create with manifest
bnap asset create-nft \
  --name "Digital Art" \
  --symbol "DART" \
  --manifest-file collection-manifest.json
```

### List Assets

```bash
bnap asset list [OPTIONS]
```

List all registered assets with filtering options.

**Options:**
- `--asset-type`: Filter by type (fungible, nft)
- `--status`: Filter by status (active, inactive, deprecated)
- `--issuer`: Filter by issuer public key
- `--format`: Output format override
- `--limit`: Maximum number of results
- `--offset`: Number of results to skip

**Examples:**

```bash
# List all assets
bnap asset list

# List only fungible tokens
bnap asset list --asset-type fungible

# List in JSON format
bnap asset list --format json

# Paginated results
bnap asset list --limit 10 --offset 20
```

### Asset Details

```bash
bnap asset show <asset_id> [OPTIONS]
```

Show detailed information about a specific asset.

**Options:**
- `--include-state`: Include current supply and transaction history
- `--include-transactions`: Show recent transactions
- `--format`: Output format

**Examples:**

```bash
# Show asset details
bnap asset show abc123...

# Include state information
bnap asset show abc123... --include-state

# Show with transaction history
bnap asset show abc123... --include-transactions --format json
```

## Minting Operations (`bnap mint`)

Execute minting transactions for assets.

### Mint Fungible Tokens

```bash
bnap mint fungible [OPTIONS]
```

Mint fungible tokens to a recipient address.

**Options:**
- `--asset-id` (required): Asset identifier
- `--amount` (required): Amount to mint
- `--recipient` (required): Recipient Bitcoin address
- `--funding-utxo`: UTXO for transaction fees (txid:vout:amount)
- `--allowlist-proof`: Merkle proof for allowlist verification
- `--metadata`: Additional metadata (JSON string)
- `--fee-rate`: Fee rate in sat/byte
- `--broadcast`: Broadcast transaction immediately
- `--wait-confirmation`: Wait for transaction confirmation
- `--output-file`: Save PSBT to file

**Examples:**

```bash
# Basic token mint
bnap mint fungible \
  --asset-id abc123... \
  --amount 1000 \
  --recipient bc1qtest... \
  --broadcast

# Mint with allowlist proof
bnap mint fungible \
  --asset-id abc123... \
  --amount 500 \
  --recipient bc1qtest... \
  --allowlist-proof '["0xproof1", "0xproof2"]' \
  --broadcast

# Create PSBT without broadcasting
bnap mint fungible \
  --asset-id abc123... \
  --amount 100 \
  --recipient bc1qtest... \
  --output-file mint.psbt
```

### Mint NFT

```bash
bnap mint nft [OPTIONS]
```

Mint a specific NFT from a collection.

**Options:**
- `--collection-id` (required): NFT collection identifier
- `--token-id` (required): Unique token ID within collection
- `--recipient` (required): Recipient Bitcoin address
- `--content-hash`: SHA-256 hash of NFT content
- `--content-uri`: URI to NFT content (IPFS, HTTP, etc.)
- `--metadata`: NFT metadata (JSON string)
- `--funding-utxo`: UTXO for transaction fees
- `--broadcast`: Broadcast transaction immediately
- `--output-file`: Save PSBT to file

**Examples:**

```bash
# Mint NFT
bnap mint nft \
  --collection-id def456... \
  --token-id 42 \
  --recipient bc1qtest... \
  --content-hash 0x1234... \
  --content-uri "ipfs://QmNFT..." \
  --broadcast

# Mint with custom metadata
bnap mint nft \
  --collection-id def456... \
  --token-id 43 \
  --recipient bc1qtest... \
  --metadata '{"name": "Rare Art", "attributes": [{"trait": "color", "value": "blue"}]}' \
  --broadcast
```

## Registry Operations (`bnap registry`)

Query and manage the asset registry.

### Initialize Registry

```bash
bnap registry init [OPTIONS]
```

Initialize a new asset registry.

**Options:**
- `--registry-file`: Path to registry file
- `--validator-id`: Validator identifier
- `--validator-pubkey`: Validator public key
- `--network`: Bitcoin network (mainnet, testnet, regtest)
- `--overwrite`: Overwrite existing registry

**Examples:**

```bash
# Initialize new registry
bnap registry init \
  --validator-id "my_validator" \
  --validator-pubkey 0x... \
  --network testnet

# Initialize with custom file
bnap registry init \
  --registry-file /path/to/registry.json \
  --validator-id "validator_1"
```

### Query Registry

```bash
bnap registry query [OPTIONS]
```

Query assets and state from the registry.

**Options:**
- `--asset-type`: Filter by asset type (fungible, nft)
- `--status`: Filter by status
- `--search`: Search in asset names/symbols
- `--show-state`: Include current state information
- `--format`: Output format
- `--export`: Export to file

**Examples:**

```bash
# Query all assets
bnap registry query

# Search for specific assets
bnap registry query --search "test"

# Export fungible tokens
bnap registry query \
  --asset-type fungible \
  --format json \
  --export fungible-tokens.json
```

### Update Registry

```bash
bnap registry update [OPTIONS]
```

Update registry configuration or state.

**Options:**
- `--add-validator`: Add new validator
- `--remove-validator`: Remove validator
- `--update-asset`: Update asset configuration
- `--backup`: Create backup before update

## Validator Operations (`bnap validator`)

Manage validator operations and configuration.

### Start Validator

```bash
bnap validator start [OPTIONS]
```

Start the validator service.

**Options:**
- `--config-file`: Validator configuration file
- `--network`: Bitcoin network
- `--rpc-host`: Bitcoin RPC host
- `--rpc-port`: Bitcoin RPC port
- `--rpc-user`: Bitcoin RPC username
- `--rpc-password`: Bitcoin RPC password
- `--daemon`: Run as daemon process
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR)

**Examples:**

```bash
# Start validator for testnet
bnap validator start \
  --network testnet \
  --rpc-host localhost \
  --rpc-port 18332

# Start as daemon
bnap validator start \
  --config-file validator.json \
  --daemon \
  --log-level INFO
```

### Validator Status

```bash
bnap validator status [OPTIONS]
```

Check validator status and health.

**Options:**
- `--detailed`: Show detailed status information
- `--format`: Output format

**Examples:**

```bash
# Basic status check
bnap validator status

# Detailed status
bnap validator status --detailed --format json
```

### Sign Transaction

```bash
bnap validator sign [OPTIONS]
```

Manually sign a PSBT transaction.

**Options:**
- `--psbt-file` (required): PSBT file to sign
- `--output-file`: Output signed PSBT file
- `--broadcast`: Broadcast after signing
- `--validate-first`: Validate before signing

**Examples:**

```bash
# Sign PSBT file
bnap validator sign \
  --psbt-file unsigned.psbt \
  --output-file signed.psbt

# Sign and broadcast
bnap validator sign \
  --psbt-file mint.psbt \
  --broadcast \
  --validate-first
```

## Configuration Management (`bnap config`)

Manage BNAP configuration files and settings.

### Show Configuration

```bash
bnap config show [OPTIONS]
```

Display current configuration.

**Options:**
- `--section`: Show specific configuration section
- `--format`: Output format
- `--show-sensitive`: Include sensitive values (masked by default)

### Set Configuration

```bash
bnap config set <key> <value> [OPTIONS]
```

Set configuration values.

**Options:**
- `--section`: Configuration section
- `--type`: Value type (string, int, bool)
- `--global`: Set global configuration

**Examples:**

```bash
# Set network configuration
bnap config set network.rpc_host localhost
bnap config set network.rpc_port 18332 --type int

# Set validator configuration
bnap config set validator.id "my_validator"
bnap config set validator.enable_audit true --type bool
```

## Output Formats

BNAP CLI supports multiple output formats:

### Table Format (Default)

```
Asset ID                                          Name        Symbol  Type      Supply
abc123...                                         Test Token  TEST    fungible  1000000
def456...                                         Art Coll.   ART     nft       100
```

### JSON Format

```json
{
  "status": "success",
  "data": [
    {
      "asset_id": "abc123...",
      "name": "Test Token",
      "symbol": "TEST",
      "asset_type": "fungible",
      "maximum_supply": 1000000
    }
  ]
}
```

### CSV Format

```csv
asset_id,name,symbol,asset_type,maximum_supply
abc123...,Test Token,TEST,fungible,1000000
def456...,Art Collection,ART,nft,100
```

## Environment Variables

Configure BNAP using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `BNAP_CONFIG_FILE` | Default configuration file | `~/.bnap/config.json` |
| `BNAP_NETWORK` | Bitcoin network | `regtest` |
| `BNAP_RPC_HOST` | Bitcoin RPC host | `localhost` |
| `BNAP_RPC_PORT` | Bitcoin RPC port | `18443` |
| `BNAP_RPC_USER` | Bitcoin RPC username | - |
| `BNAP_RPC_PASSWORD` | Bitcoin RPC password | - |
| `BNAP_VALIDATOR_ID` | Default validator ID | - |
| `BNAP_LOG_LEVEL` | Logging level | `INFO` |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Network error |
| 5 | Validation error |
| 130 | Interrupted by user (Ctrl+C) |

## Configuration File Format

Default configuration file (`~/.bnap/config.json`):

```json
{
  "network": {
    "type": "regtest",
    "rpc_host": "localhost",
    "rpc_port": 18443,
    "rpc_user": "bitcoin",
    "rpc_password": "password"
  },
  "validator": {
    "id": "bnap_validator_v1",
    "enable_audit": true,
    "max_validation_time": 30
  },
  "cli": {
    "output_format": "table",
    "color_output": true,
    "verbose": 0
  },
  "registry": {
    "file_path": "~/.bnap/registry.json",
    "backup_enabled": true
  }
}
```

This CLI reference provides complete documentation for all BNAP command-line operations with practical examples and configuration options.