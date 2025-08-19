# Allowlist Management Guide

This guide covers creating and managing allowlists for BNAP assets using Merkle proofs, enabling controlled distribution and exclusive access patterns.

## Understanding Allowlists

Allowlists in BNAP use **Merkle trees** to efficiently validate that an address is authorized to receive assets without storing the entire list on-chain. This provides:

- **Privacy**: Individual addresses aren't revealed until used
- **Efficiency**: O(log n) verification with compact proofs
- **Flexibility**: Dynamic list updates without on-chain changes

## Basic Allowlist Creation

### Step 1: Prepare Address List

Create a file with authorized addresses:

```bash
# Create allowlist addresses
cat > allowed_addresses.txt << EOF
bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el
bc1qflh8s6lz7qf2xzqjsxvxe5d8qjr0l4j2v9p8x3
bc1q7v5k8w2n6r9t4x1c3a7e0j5h9m2p8l6q4y8u5i
EOF
```

### Step 2: Create Allowlist for Existing Asset

```bash
# Create allowlist for a fungible token
bnap allowlist create \
    --asset-id "your_asset_id_here" \
    --addresses-file allowed_addresses.txt \
    --allowlist-name "Early Adopters"
```

Example output:
```
🔒 Creating allowlist...
📊 Processing 5 addresses...
🌳 Building Merkle tree...

✅ Allowlist created successfully!

Allowlist Details:
  Asset ID: a1b2c3d4e5f6...
  Name: Early Adopters
  Addresses: 5
  Merkle Root: 7f8a9b2c1d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9
  
💾 Merkle proofs saved to: ~/.bnap/proofs/a1b2c3d4e5f6_proofs.json
```

### Step 3: Create Asset with Allowlist

You can also create an asset with an allowlist from the beginning:

```bash
# Create fungible token with immediate allowlist
bnap asset create-fungible \
    --name "Exclusive Token" \
    --symbol "EXCL" \
    --max-supply 10000 \
    --per-mint-limit 1000 \
    --allowlist-file allowed_addresses.txt \
    --allowlist-name "VIP Members"
```

## Advanced Allowlist Patterns

### Tiered Access Allowlists

Create multiple allowlists with different permissions:

```bash
# Tier 1: High-value investors (large allocations)
cat > tier1_addresses.txt << EOF
bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
EOF

# Tier 2: Community members (medium allocations)
cat > tier2_addresses.txt << EOF
bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el
bc1qflh8s6lz7qf2xzqjsxvxe5d8qjr0l4j2v9p8x3
bc1q7v5k8w2n6r9t4x1c3a7e0j5h9m2p8l6q4y8u5i
EOF

# Create asset with tier 1 allowlist
ASSET_ID=$(bnap asset create-fungible \
    --name "Tiered Token" \
    --symbol "TIER" \
    --max-supply 1000000 \
    --per-mint-limit 50000 \
    --allowlist-file tier1_addresses.txt \
    --allowlist-name "Tier 1 Investors" \
    --format json | jq -r '.asset_id')

# Add tier 2 allowlist
bnap allowlist create \
    --asset-id "$ASSET_ID" \
    --addresses-file tier2_addresses.txt \
    --allowlist-name "Tier 2 Community" \
    --per-address-limit 5000
```

### Time-Based Allowlists

Implement time-based access controls:

```bash
# Early access phase (first 24 hours)
bnap allowlist create \
    --asset-id "$ASSET_ID" \
    --addresses-file early_access.txt \
    --allowlist-name "Early Access" \
    --start-time "2024-01-15T00:00:00Z" \
    --end-time "2024-01-16T00:00:00Z" \
    --per-address-limit 1000

# Public sale phase  
bnap allowlist create \
    --asset-id "$ASSET_ID" \
    --addresses-file public_sale.txt \
    --allowlist-name "Public Sale" \
    --start-time "2024-01-16T00:00:00Z" \
    --end-time "2024-01-30T23:59:59Z" \
    --per-address-limit 100
```

### Dynamic Address Lists

Generate allowlists from external sources:

```bash
# From CSV file
bnap allowlist import-csv \
    --csv-file investors.csv \
    --address-column "bitcoin_address" \
    --amount-column "allocation" \
    --output-file processed_allowlist.txt

# From API endpoint
curl -s "https://api.yourproject.com/allowlist" | \
    jq -r '.addresses[]' > api_allowlist.txt

bnap allowlist create \
    --asset-id "$ASSET_ID" \
    --addresses-file api_allowlist.txt \
    --allowlist-name "API Generated"
```

## Minting with Allowlists

### Generate Merkle Proof

Before minting to an allowlisted address, generate its proof:

```bash
# Generate proof for specific address
TARGET_ADDRESS="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

bnap allowlist generate-proof \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --address "$TARGET_ADDRESS" \
    --output-file proof.json
```

Example proof output:
```json
{
  "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
  "merkle_root": "7f8a9b2c1d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
  "proof": [
    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"
  ],
  "leaf_index": 0,
  "valid": true
}
```

### Mint with Proof

```bash
# Mint tokens using allowlist proof
bnap mint fungible \
    --asset-id "$ASSET_ID" \
    --amount 1000 \
    --recipient "$TARGET_ADDRESS" \
    --allowlist-proof proof.json \
    --allowlist-name "Early Adopters"
```

Expected output:
```
🔒 Validating allowlist proof...
✅ Address authorized: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
✅ Merkle proof valid
✅ Allowlist limits: OK (1000 / 5000 remaining)

🏭 Creating mint transaction...
✅ Transaction created and broadcast successfully!
```

### Batch Minting to Allowlist

```bash
# Mint to all addresses in allowlist
bnap mint batch-allowlist \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --amount-per-address 500 \
    --max-fee-rate 20 \
    --dry-run

# Execute batch mint (remove --dry-run)
bnap mint batch-allowlist \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --amount-per-address 500 \
    --max-fee-rate 20
```

## NFT Allowlists

### Create NFT Collection with Allowlist

```bash
# Create exclusive NFT collection
bnap asset create-nft \
    --name "Exclusive Art" \
    --symbol "EXCL" \
    --collection-size 50 \
    --allowlist-file vip_collectors.txt \
    --allowlist-name "VIP Collectors" \
    --max-per-address 3
```

### NFT Allowlist Minting

```bash
# Generate proof for NFT mint
bnap allowlist generate-proof \
    --asset-id "$NFT_ASSET_ID" \
    --allowlist-name "VIP Collectors" \
    --address "$COLLECTOR_ADDRESS" \
    --output-file nft_proof.json

# Mint NFT with allowlist proof
bnap mint nft \
    --asset-id "$NFT_ASSET_ID" \
    --nft-id 1 \
    --recipient "$COLLECTOR_ADDRESS" \
    --allowlist-proof nft_proof.json \
    --content-hash "your_content_hash_here"
```

## Allowlist Management Operations

### View Allowlist Status

```bash
# List all allowlists for an asset
bnap allowlist list --asset-id "$ASSET_ID"

# Get allowlist details
bnap allowlist info \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters"

# Check address allowlist status
bnap allowlist check-address \
    --asset-id "$ASSET_ID" \
    --address "$TARGET_ADDRESS"
```

### Update Allowlists

```bash
# Add addresses to existing allowlist
echo "bc1qnew1address..." > new_addresses.txt
echo "bc1qnew2address..." >> new_addresses.txt

bnap allowlist update \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --add-addresses-file new_addresses.txt

# Remove addresses
echo "bc1qremove1..." > remove_addresses.txt

bnap allowlist update \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --remove-addresses-file remove_addresses.txt

# Update limits
bnap allowlist update \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --per-address-limit 2000
```

### Export and Backup

```bash
# Export allowlist data
bnap allowlist export \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --output-file allowlist_backup.json \
    --include-proofs

# Export Merkle tree data
bnap allowlist export-tree \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --output-file merkle_tree.json
```

## Verification and Auditing

### Verify Allowlist Integrity

```bash
# Verify Merkle tree integrity
bnap allowlist verify \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters"

# Verify specific proof
bnap allowlist verify-proof \
    --merkle-root "7f8a9b2c..." \
    --address "$TARGET_ADDRESS" \
    --proof-file proof.json

# Audit allowlist usage
bnap allowlist audit \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --output-file audit_report.csv
```

### Generate Usage Reports

```bash
# Generate allowlist usage report
bnap report allowlist-usage \
    --asset-id "$ASSET_ID" \
    --format html \
    --output-file allowlist_report.html \
    --include-charts

# Export mint history by allowlist
bnap query transactions \
    --asset-id "$ASSET_ID" \
    --filter-allowlist "Early Adopters" \
    --format csv \
    --output-file early_adopter_mints.csv
```

## Advanced Patterns

### Programmable Allowlists

Create dynamic allowlists based on conditions:

```bash
# Create conditional allowlist
cat > allowlist_conditions.json << EOF
{
  "name": "Conditional Access",
  "conditions": {
    "min_bitcoin_balance": 0.001,
    "max_previous_mints": 5,
    "required_nft_holdings": [
      "collection_asset_id_here"
    ],
    "time_restrictions": {
      "start": "2024-01-15T00:00:00Z",
      "end": "2024-01-31T23:59:59Z"
    }
  },
  "limits": {
    "per_address": 1000,
    "per_day": 500
  }
}
EOF

bnap allowlist create-conditional \
    --asset-id "$ASSET_ID" \
    --conditions-file allowlist_conditions.json
```

### Cross-Asset Allowlists

Share allowlists across multiple assets:

```bash
# Create shared allowlist
bnap allowlist create-shared \
    --name "Premium Members" \
    --addresses-file premium_addresses.txt \
    --description "Shared across all premium assets"

# Apply to multiple assets
bnap allowlist apply-shared \
    --shared-name "Premium Members" \
    --asset-ids "$ASSET1_ID,$ASSET2_ID,$ASSET3_ID"
```

### Integration with External Systems

```bash
# Sync with membership system
bnap allowlist sync \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Members" \
    --source-api "https://api.membership.com/active" \
    --auth-header "Authorization: Bearer $API_KEY" \
    --sync-interval 3600  # 1 hour

# Webhook notifications for allowlist changes
bnap allowlist webhook add \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --webhook-url "https://api.yourproject.com/allowlist-webhook" \
    --events "address_added,address_removed,mint_occurred"
```

## Security Best Practices

### Allowlist Security

```bash
# Encrypt allowlist data
bnap allowlist encrypt \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --encryption-key-file ~/.bnap/allowlist_key.enc

# Backup allowlist securely
bnap allowlist backup \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --backup-location "s3://secure-backup/allowlists/" \
    --encrypt

# Audit access logs
bnap allowlist audit-access \
    --asset-id "$ASSET_ID" \
    --since "2024-01-01" \
    --output-file access_audit.log
```

### Proof Management

```bash
# Secure proof generation
bnap allowlist generate-proof \
    --asset-id "$ASSET_ID" \
    --address "$TARGET_ADDRESS" \
    --secure-mode \
    --output-encrypted proof_encrypted.json

# Batch proof pre-generation
bnap allowlist generate-all-proofs \
    --asset-id "$ASSET_ID" \
    --allowlist-name "Early Adopters" \
    --output-directory ~/.bnap/proofs/ \
    --encrypt
```

## Troubleshooting

### Common Issues

#### "Invalid Merkle proof"

```bash
# Regenerate proof
bnap allowlist generate-proof \
    --asset-id "$ASSET_ID" \
    --address "$TARGET_ADDRESS" \
    --force-regenerate

# Verify tree integrity
bnap allowlist verify-tree --asset-id "$ASSET_ID"
```

#### "Address not in allowlist"

```bash
# Check address format
bnap address validate --address "$TARGET_ADDRESS"

# Verify allowlist contains address
bnap allowlist check-address \
    --asset-id "$ASSET_ID" \
    --address "$TARGET_ADDRESS" \
    --verbose
```

#### "Allowlist limit exceeded"

```bash
# Check current usage
bnap allowlist usage \
    --asset-id "$ASSET_ID" \
    --address "$TARGET_ADDRESS"

# View remaining allocation
bnap allowlist allocation \
    --asset-id "$ASSET_ID" \
    --address "$TARGET_ADDRESS"
```

## Best Practices Summary

1. **Privacy**: Use allowlists to maintain address privacy until minting
2. **Efficiency**: Leverage Merkle proofs for scalable verification
3. **Flexibility**: Implement tiered access and time-based restrictions
4. **Security**: Encrypt sensitive allowlist data and backup regularly
5. **Auditing**: Monitor allowlist usage and maintain access logs
6. **Testing**: Always test allowlist functionality before production deployment

Allowlists provide powerful control over asset distribution while maintaining efficiency and privacy. Use them to create exclusive access patterns, implement fair launches, and manage complex distribution scenarios.