# Complete CLI Reference

This comprehensive reference covers all BNAP CLI commands with detailed options, examples, and use cases.

## Global Options

All BNAP commands support these global options:

```bash
--config-file PATH          # Path to configuration file (default: ~/.bnap/config.json)
--network NETWORK           # Bitcoin network: mainnet, testnet, regtest (default: testnet)
--verbose, -v               # Enable verbose output (use -vv for debug level)
--quiet, -q                 # Suppress non-essential output
--format FORMAT             # Output format: table, json, yaml, csv (default: table)
--output-file FILE          # Save output to file instead of stdout
--dry-run                   # Show what would be done without executing
--help, -h                  # Show help message
--version                   # Show version information
```

## Command Categories

### Configuration Commands

#### `bnap config`

Manage BNAP configuration settings.

##### `bnap config generate-keys`

Generate validator signing keys.

```bash
bnap config generate-keys [OPTIONS]

Options:
  --validator-id TEXT         Unique validator identifier [required]
  --key-type [ecdsa|schnorr] Key type (default: schnorr)
  --output-file PATH         Output file for keys (default: ~/.bnap/validator_keys.json)
  --passphrase TEXT          Passphrase for key encryption
  --entropy-source [system|hardware|file] Entropy source for key generation
  --backup-keys              Generate backup keys
```

**Examples:**

```bash
# Generate Schnorr keys for production
bnap config generate-keys \
    --validator-id "prod_validator_$(hostname)" \
    --key-type schnorr \
    --output-file /etc/bnap/validator_keys.json \
    --passphrase "secure_passphrase" \
    --backup-keys

# Generate keys with hardware entropy
bnap config generate-keys \
    --validator-id "secure_validator" \
    --entropy-source hardware \
    --output-file ~/.bnap/hw_keys.json
```

##### `bnap config generate-template`

Generate configuration file templates.

```bash
bnap config generate-template [OPTIONS]

Options:
  --environment [development|staging|production] Deployment environment
  --network [mainnet|testnet|regtest]            Bitcoin network
  --output-file PATH                             Output configuration file
  --enable-encryption                            Enable key encryption
  --hsm-support                                  Include HSM configuration
  --monitoring                                   Include monitoring settings
```

**Examples:**

```bash
# Generate production template
bnap config generate-template \
    --environment production \
    --network mainnet \
    --enable-encryption \
    --hsm-support \
    --output-file /etc/bnap/config.json

# Generate development template
bnap config generate-template \
    --environment development \
    --network regtest \
    --output-file ~/.bnap/dev_config.json
```

##### `bnap config validate`

Validate configuration files.

```bash
bnap config validate [OPTIONS]

Options:
  --config-file PATH          Configuration file to validate
  --check-connections         Test all external connections
  --check-permissions         Verify file permissions
  --comprehensive             Perform comprehensive validation
  --fix-issues               Automatically fix detected issues
```

##### `bnap config show`

Display current configuration.

```bash
bnap config show [OPTIONS]

Options:
  --show-secrets             Include sensitive values (use with caution)
  --show-sources             Show configuration value sources
  --section TEXT             Show specific configuration section
```

### Registry Commands

#### `bnap registry`

Manage the asset registry.

##### `bnap registry init`

Initialize a new asset registry.

```bash
bnap registry init [OPTIONS]

Options:
  --validator-id TEXT         Validator identifier [required]
  --network [mainnet|testnet|regtest] Bitcoin network
  --registry-file PATH        Registry file location
  --force                     Overwrite existing registry
  --backup-existing           Backup existing registry before init
```

**Examples:**

```bash
# Initialize testnet registry
bnap registry init \
    --validator-id "test_validator" \
    --network testnet \
    --registry-file ~/.bnap/testnet_registry.json

# Initialize production registry with backup
bnap registry init \
    --validator-id "prod_validator" \
    --network mainnet \
    --registry-file /var/lib/bnap/registry.json \
    --backup-existing
```

##### `bnap registry query`

Query registry contents.

```bash
bnap registry query [OPTIONS]

Options:
  --asset-type [fungible|nft|all]  Filter by asset type
  --status [active|inactive|all]    Filter by asset status
  --issuer TEXT                     Filter by issuer public key
  --created-after DATE              Assets created after date
  --created-before DATE             Assets created before date
  --limit INTEGER                   Maximum number of results
  --offset INTEGER                  Result offset for pagination
  --sort-by [name|symbol|created|supply] Sort field
  --sort-order [asc|desc]           Sort order
```

**Examples:**

```bash
# Query all active fungible assets
bnap registry query \
    --asset-type fungible \
    --status active \
    --format table

# Query recent NFT collections
bnap registry query \
    --asset-type nft \
    --created-after "2024-01-01" \
    --sort-by created \
    --sort-order desc \
    --limit 10

# Export all assets to CSV
bnap registry query \
    --asset-type all \
    --format csv \
    --output-file all_assets.csv
```

##### `bnap registry backup`

Create registry backups.

```bash
bnap registry backup [OPTIONS]

Options:
  --output-file PATH          Backup file location
  --compress                  Compress backup file
  --encrypt                   Encrypt backup
  --include-keys              Include signing keys in backup
  --verification-hash         Include verification hash
```

##### `bnap registry restore`

Restore registry from backup.

```bash
bnap registry restore [OPTIONS]

Options:
  --backup-file PATH          Backup file to restore [required]
  --verify-integrity          Verify backup integrity before restore
  --dry-run                   Show what would be restored
  --force                     Overwrite existing registry
```

### Asset Commands

#### `bnap asset`

Manage BNAP assets.

##### `bnap asset create-fungible`

Create a new fungible token.

```bash
bnap asset create-fungible [OPTIONS]

Options:
  --name TEXT                 Asset name [required]
  --symbol TEXT               Asset symbol [required]
  --max-supply INTEGER        Maximum total supply [required]
  --per-mint-limit INTEGER    Maximum per-mint amount [required]
  --decimal-places INTEGER    Number of decimal places (0-18, default: 0)
  --issuer-description TEXT   Description of the asset issuer
  --allowlist-file PATH       File containing allowed addresses
  --allowlist-name TEXT       Name for the allowlist
  --script-format [p2tr|p2wsh] Bitcoin script format (default: p2tr)
  --mint-price FLOAT          Price per token in BTC
  --royalty-rate FLOAT        Royalty percentage (0-10)
  --royalty-recipient TEXT    Address to receive royalties
```

**Examples:**

```bash
# Create basic fungible token
bnap asset create-fungible \
    --name "Utility Token" \
    --symbol "UTIL" \
    --max-supply 1000000 \
    --per-mint-limit 10000 \
    --decimal-places 2

# Create token with allowlist and pricing
bnap asset create-fungible \
    --name "Premium Token" \
    --symbol "PREM" \
    --max-supply 100000 \
    --per-mint-limit 1000 \
    --allowlist-file premium_users.txt \
    --allowlist-name "Premium Users" \
    --mint-price 0.001 \
    --royalty-rate 2.5 \
    --royalty-recipient "bc1qroyaltyaddress"
```

##### `bnap asset create-nft`

Create a new NFT collection.

```bash
bnap asset create-nft [OPTIONS]

Options:
  --name TEXT                 Collection name [required]
  --symbol TEXT               Collection symbol [required]
  --collection-size INTEGER   Maximum NFTs in collection [required]
  --issuer-description TEXT   Description of the collection issuer
  --content-hash TEXT         SHA-256 hash of collection manifest
  --content-uri TEXT          URI pointing to collection manifest
  --manifest-hash TEXT        Hash of collection metadata manifest
  --manifest-uri TEXT         URI of collection metadata manifest
  --allowlist-file PATH       File containing allowed addresses
  --allowlist-name TEXT       Name for the allowlist
  --royalty-rate FLOAT        Royalty percentage (0-10)
  --royalty-recipient TEXT    Address to receive royalties
  --max-per-address INTEGER   Maximum NFTs per address
```

**Examples:**

```bash
# Create basic NFT collection
bnap asset create-nft \
    --name "Digital Art Gallery" \
    --symbol "ART" \
    --collection-size 1000 \
    --royalty-rate 5.0 \
    --royalty-recipient "bc1qartistaddress"

# Create exclusive NFT collection
bnap asset create-nft \
    --name "Exclusive Collection" \
    --symbol "EXCL" \
    --collection-size 100 \
    --allowlist-file vip_collectors.txt \
    --allowlist-name "VIP Collectors" \
    --max-per-address 3 \
    --content-hash "a1b2c3d4e5f6..." \
    --manifest-uri "ipfs://QmManifestHash"
```

##### `bnap asset info`

Get detailed asset information.

```bash
bnap asset info [OPTIONS]

Options:
  --asset-id TEXT             Asset identifier [required]
  --include-state             Include current state information
  --include-transactions      Include transaction history
  --include-holders           Include holder information (NFTs)
  --include-metadata          Include metadata details
  --transaction-limit INTEGER Limit transaction history results
```

**Examples:**

```bash
# Get basic asset info
bnap asset info --asset-id "abc123..."

# Get comprehensive asset details
bnap asset info \
    --asset-id "abc123..." \
    --include-state \
    --include-transactions \
    --include-metadata \
    --format json \
    --output-file asset_details.json
```

##### `bnap asset update`

Update asset properties.

```bash
bnap asset update [OPTIONS]

Options:
  --asset-id TEXT             Asset identifier [required]
  --description TEXT          Update asset description
  --external-url TEXT         Update external URL
  --royalty-rate FLOAT        Update royalty rate
  --royalty-recipient TEXT    Update royalty recipient
  --status [active|inactive]  Update asset status
```

### Minting Commands

#### `bnap mint`

Mint assets.

##### `bnap mint fungible`

Mint fungible tokens.

```bash
bnap mint fungible [OPTIONS]

Options:
  --asset-id TEXT             Asset identifier [required]
  --amount INTEGER            Amount to mint [required]
  --recipient TEXT            Recipient Bitcoin address [required]
  --allowlist-proof PATH      Merkle proof file (if allowlisted)
  --allowlist-name TEXT       Name of allowlist to use
  --fee-rate INTEGER          Fee rate in sat/vB (default: estimate)
  --rbf                       Enable Replace-By-Fee
  --wait-for-confirmation     Wait for transaction confirmation
  --confirmation-target INTEGER Target confirmations (default: 1)
```

**Examples:**

```bash
# Basic fungible mint
bnap mint fungible \
    --asset-id "abc123..." \
    --amount 1000 \
    --recipient "bc1qrecipientaddress" \
    --fee-rate 20

# Mint with allowlist proof
bnap mint fungible \
    --asset-id "abc123..." \
    --amount 500 \
    --recipient "bc1qallowlistedaddress" \
    --allowlist-proof proof.json \
    --allowlist-name "Early Adopters" \
    --wait-for-confirmation
```

##### `bnap mint nft`

Mint NFTs.

```bash
bnap mint nft [OPTIONS]

Options:
  --asset-id TEXT             Collection asset identifier [required]
  --nft-id INTEGER            NFT ID within collection [required]
  --recipient TEXT            Recipient Bitcoin address [required]
  --content-hash TEXT         SHA-256 hash of NFT content
  --content-uri TEXT          URI pointing to NFT metadata
  --allowlist-proof PATH      Merkle proof file (if allowlisted)
  --allowlist-name TEXT       Name of allowlist to use
  --fee-rate INTEGER          Fee rate in sat/vB (default: estimate)
  --rbf                       Enable Replace-By-Fee
  --wait-for-confirmation     Wait for transaction confirmation
```

**Examples:**

```bash
# Basic NFT mint
bnap mint nft \
    --asset-id "nft123..." \
    --nft-id 1 \
    --recipient "bc1qcollectoraddress" \
    --content-hash "def456..." \
    --content-uri "ipfs://QmNFTMetadata"

# Mint to allowlisted collector
bnap mint nft \
    --asset-id "nft123..." \
    --nft-id 42 \
    --recipient "bc1qvipaddress" \
    --content-hash "ghi789..." \
    --allowlist-proof vip_proof.json \
    --allowlist-name "VIP Collectors"
```

##### `bnap mint batch`

Batch minting operations.

```bash
bnap mint batch [OPTIONS]

Options:
  --batch-file PATH           CSV file with batch operations [required]
  --asset-type [fungible|nft] Type of assets to mint
  --max-batch-size INTEGER    Maximum operations per batch (default: 25)
  --fee-rate INTEGER          Fee rate in sat/vB
  --parallel                  Process batches in parallel
  --continue-on-error         Continue processing if individual mints fail
```

**Batch File Format (CSV):**

For fungible tokens:
```csv
asset_id,recipient,amount,allowlist_proof,allowlist_name
abc123...,bc1qaddr1,1000,,
abc123...,bc1qaddr2,2000,proof2.json,Early Adopters
```

For NFTs:
```csv
asset_id,nft_id,recipient,content_hash,content_uri,allowlist_proof
nft123...,1,bc1qaddr1,hash1,ipfs://meta1,
nft123...,2,bc1qaddr2,hash2,ipfs://meta2,proof2.json
```

### Query Commands

#### `bnap query`

Query blockchain and registry data.

##### `bnap query balance`

Query asset balances.

```bash
bnap query balance [OPTIONS]

Options:
  --address TEXT              Bitcoin address [required]
  --asset-id TEXT             Specific asset ID (optional)
  --asset-type [fungible|nft|all] Filter by asset type
  --confirmed-only            Show only confirmed balances
  --include-pending           Include pending transactions
  --block-height INTEGER      Query balance at specific block height
```

**Examples:**

```bash
# Query all balances for address
bnap query balance --address "bc1qaddress..."

# Query specific asset balance
bnap query balance \
    --address "bc1qaddress..." \
    --asset-id "abc123..." \
    --confirmed-only

# Query NFT holdings
bnap query balance \
    --address "bc1qcollector..." \
    --asset-type nft \
    --format json
```

##### `bnap query transactions`

Query transaction history.

```bash
bnap query transactions [OPTIONS]

Options:
  --asset-id TEXT             Filter by asset ID
  --address TEXT              Filter by address
  --transaction-type [mint|transfer|burn] Filter by transaction type
  --start-date DATE           Start date filter
  --end-date DATE             End date filter
  --start-block INTEGER       Start block height
  --end-block INTEGER         End block height
  --limit INTEGER             Maximum results (default: 100)
  --offset INTEGER            Result offset
  --include-pending           Include unconfirmed transactions
```

**Examples:**

```bash
# Query recent asset transactions
bnap query transactions \
    --asset-id "abc123..." \
    --limit 50 \
    --format table

# Query address transaction history
bnap query transactions \
    --address "bc1qaddress..." \
    --start-date "2024-01-01" \
    --include-pending \
    --format csv \
    --output-file tx_history.csv
```

##### `bnap query nft`

Query NFT-specific information.

```bash
bnap query nft [OPTIONS]

Options:
  --asset-id TEXT             Collection asset ID [required]
  --nft-id INTEGER            Specific NFT ID (optional)
  --owner TEXT                Filter by current owner
  --trait-type TEXT           Filter by trait type
  --trait-value TEXT          Filter by trait value
  --include-metadata          Include NFT metadata
  --include-history           Include ownership history
```

**Examples:**

```bash
# Query specific NFT
bnap query nft \
    --asset-id "nft123..." \
    --nft-id 42 \
    --include-metadata \
    --include-history

# Query NFTs by trait
bnap query nft \
    --asset-id "nft123..." \
    --trait-type "Rarity" \
    --trait-value "Legendary" \
    --format json
```

### Validator Commands

#### `bnap validator`

Manage validator operations.

##### `bnap validator start`

Start the validator service.

```bash
bnap validator start [OPTIONS]

Options:
  --config-file PATH          Configuration file
  --daemon                    Run as daemon process
  --pid-file PATH             PID file location
  --log-file PATH             Log file location
  --port INTEGER              API port (default: 8080)
  --workers INTEGER           Number of worker processes
  --max-concurrent INTEGER    Max concurrent validations
```

##### `bnap validator stop`

Stop the validator service.

```bash
bnap validator stop [OPTIONS]

Options:
  --pid-file PATH             PID file location
  --force                     Force stop if graceful shutdown fails
  --timeout INTEGER           Shutdown timeout in seconds
```

##### `bnap validator status`

Check validator status.

```bash
bnap validator status [OPTIONS]

Options:
  --detailed                  Show detailed status information
  --include-stats             Include validation statistics
  --check-health              Perform health checks
```

##### `bnap validator health-check`

Perform comprehensive health check.

```bash
bnap validator health-check [OPTIONS]

Options:
  --check-bitcoin             Check Bitcoin RPC connection
  --check-keys                Verify signing keys
  --check-registry            Verify registry access
  --check-permissions         Check file permissions
  --timeout INTEGER           Health check timeout
```

### Allowlist Commands

#### `bnap allowlist`

Manage allowlists.

##### `bnap allowlist create`

Create a new allowlist.

```bash
bnap allowlist create [OPTIONS]

Options:
  --asset-id TEXT             Asset identifier [required]
  --addresses-file PATH       File containing addresses [required]
  --allowlist-name TEXT       Name for the allowlist [required]
  --per-address-limit INTEGER Limit per address
  --start-time DATETIME       Allowlist start time
  --end-time DATETIME         Allowlist end time
  --description TEXT          Allowlist description
```

##### `bnap allowlist generate-proof`

Generate Merkle proof for address.

```bash
bnap allowlist generate-proof [OPTIONS]

Options:
  --asset-id TEXT             Asset identifier [required]
  --allowlist-name TEXT       Allowlist name [required]
  --address TEXT              Address to generate proof for [required]
  --output-file PATH          Output file for proof
  --verify-proof              Verify generated proof
```

##### `bnap allowlist verify-proof`

Verify a Merkle proof.

```bash
bnap allowlist verify-proof [OPTIONS]

Options:
  --proof-file PATH           Proof file to verify [required]
  --merkle-root TEXT          Expected Merkle root
  --address TEXT              Address being proven
  --verbose                   Show detailed verification steps
```

### Transaction Commands

#### `bnap transaction`

Manage transactions.

##### `bnap transaction status`

Check transaction status.

```bash
bnap transaction status [OPTIONS]

Options:
  --txid TEXT                 Transaction ID [required]
  --wait-for-confirmation     Wait until confirmed
  --confirmation-target INTEGER Required confirmations (default: 1)
  --include-details           Include transaction details
```

##### `bnap transaction broadcast`

Broadcast a signed transaction.

```bash
bnap transaction broadcast [OPTIONS]

Options:
  --transaction-hex TEXT      Raw transaction hex [required]
  --wait-for-confirmation     Wait for confirmation
  --max-fee-rate INTEGER      Maximum acceptable fee rate
```

##### `bnap transaction estimate-fee`

Estimate transaction fees.

```bash
bnap transaction estimate-fee [OPTIONS]

Options:
  --transaction-type [mint|transfer] Transaction type
  --target-blocks INTEGER     Confirmation target blocks
  --size-bytes INTEGER        Transaction size estimate
```

### Utility Commands

#### `bnap address`

Address utilities.

##### `bnap address validate`

Validate Bitcoin addresses.

```bash
bnap address validate [OPTIONS]

Options:
  --address TEXT              Address to validate [required]
  --network [mainnet|testnet|regtest] Expected network
  --check-format              Check address format only
  --check-reachability        Check if address is reachable
```

##### `bnap address generate`

Generate new Bitcoin addresses.

```bash
bnap address generate [OPTIONS]

Options:
  --count INTEGER             Number of addresses to generate (default: 1)
  --address-type [p2pkh|p2sh|p2wpkh|p2wsh|p2tr] Address type
  --network [mainnet|testnet|regtest] Bitcoin network
  --derivation-path TEXT      HD derivation path
  --seed TEXT                 Seed for address generation
```

#### `bnap report`

Generate reports.

##### `bnap report generate`

Generate comprehensive reports.

```bash
bnap report generate [OPTIONS]

Options:
  --report-type [asset|validator|system|custom] Report type
  --output-file PATH          Output file location
  --format [html|pdf|csv|json] Report format
  --include-charts            Include charts and graphs
  --time-period TEXT          Time period for data (e.g., "30d", "1y")
  --assets TEXT               Comma-separated asset IDs to include
```

#### `bnap backup`

Backup utilities.

##### `bnap backup create`

Create system backups.

```bash
bnap backup create [OPTIONS]

Options:
  --output-file PATH          Backup file location [required]
  --include-registry          Include asset registry
  --include-keys              Include validator keys
  --include-config            Include configuration files
  --include-logs              Include log files
  --compress                  Compress backup
  --encrypt                   Encrypt backup
  --exclude-sensitive         Exclude sensitive data
```

##### `bnap backup restore`

Restore from backups.

```bash
bnap backup restore [OPTIONS]

Options:
  --backup-file PATH          Backup file to restore [required]
  --target-directory PATH     Restore target directory
  --verify-integrity          Verify backup integrity
  --dry-run                   Show what would be restored
  --selective TEXT            Comma-separated components to restore
```

## Environment Variables

BNAP CLI respects these environment variables:

```bash
BNAP_CONFIG_FILE            # Default configuration file path
BNAP_NETWORK                # Default Bitcoin network
BNAP_LOG_LEVEL              # Logging level (DEBUG, INFO, WARNING, ERROR)
BNAP_VALIDATOR_ID           # Default validator identifier
BNAP_BITCOIN_RPC_HOST       # Bitcoin RPC host
BNAP_BITCOIN_RPC_PORT       # Bitcoin RPC port
BNAP_BITCOIN_RPC_USER       # Bitcoin RPC username
BNAP_BITCOIN_RPC_PASSWORD   # Bitcoin RPC password
BNAP_OUTPUT_FORMAT          # Default output format
BNAP_VERBOSE                # Enable verbose output (true/false)
```

## Exit Codes

BNAP CLI uses these exit codes:

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | General error |
| 2    | Invalid command line arguments |
| 3    | Configuration error |
| 4    | Network/connection error |
| 5    | Validation error |
| 6    | Authentication/permission error |
| 7    | Resource not found |
| 8    | Resource already exists |
| 9    | Insufficient balance/resources |
| 10   | Transaction failed |

## Configuration File Format

Example complete configuration file:

```json
{
  "version": "1.0",
  "environment": "production",
  "network": {
    "type": "mainnet",
    "rpc_host": "127.0.0.1",
    "rpc_port": 8332,
    "rpc_user": "bnap_user",
    "rpc_password": "secure_password",
    "rpc_timeout": 30,
    "max_retries": 3
  },
  "validator": {
    "id": "validator_prod_001",
    "enable_audit": true,
    "max_validation_time": 30,
    "signing_keys_file": "/etc/bnap/validator_keys.json"
  },
  "registry": {
    "file_path": "/var/lib/bnap/registry.json",
    "backup_enabled": true,
    "backup_interval": 3600
  },
  "cli": {
    "output_format": "table",
    "color_output": true,
    "verbose": 1
  }
}
```

This complete CLI reference provides comprehensive coverage of all BNAP commands and options for effective asset management and system administration.