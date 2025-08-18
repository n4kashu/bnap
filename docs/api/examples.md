# API Examples

This document provides comprehensive examples for using the BNAP API across different interfaces and use cases.

## Python API Examples

### Basic Asset Creation and Minting

#### Create Fungible Token

```python
from registry.manager import RegistryManager
from registry.schema import FungibleAsset, ScriptFormat
from crypto.keys import PrivateKey
from validator.core import ValidationEngine

# Initialize components
registry = RegistryManager()
validator = ValidationEngine()

# Generate issuer key
issuer_key = PrivateKey.generate()

# Create fungible token
asset_data = {
    "name": "Bitcoin Test Token",
    "symbol": "BTT",
    "asset_type": "fungible",
    "maximum_supply": 1000000,
    "per_mint_limit": 10000,
    "decimal_places": 2,
    "issuer_pubkey": issuer_key.public_key.hex(),
    "script_format": "p2tr",
    "metadata": {
        "description": "A test token for demonstration",
        "website": "https://testtoken.org",
        "icon": "https://testtoken.org/icon.png"
    }
}

# Register asset
asset_id = registry.create_asset(asset_data)
print(f"Created asset: {asset_id}")

# Verify asset creation
asset = registry.get_asset(asset_id)
print(f"Asset name: {asset.name}")
print(f"Max supply: {asset.maximum_supply:,}")
```

#### Mint Fungible Tokens

```python
from psbt.fungible_mint import FungibleMintPSBT, FungibleMintRequest
from network.broadcaster import TransactionBroadcaster

# Create mint request
mint_request = FungibleMintRequest(
    asset_id=asset_id,
    amount=1000,
    recipient_address="bc1qtest123...",
    funding_utxo={
        "txid": "previous_tx_id",
        "vout": 0,
        "amount": 100000,  # 0.001 BTC for fees
        "script_pubkey": "witness_script_hex"
    },
    metadata={"batch": "initial_distribution"}
)

# Build PSBT
builder = FungibleMintPSBT(asset, issuer_key)
psbt = builder.create_mint_transaction(mint_request)

# Validate transaction
validation_result = validator.validate_mint_transaction(psbt.to_base64())

if validation_result.has_errors():
    print(f"Validation failed: {validation_result.validation_errors}")
else:
    print("Transaction validated successfully")
    
    # Sign and broadcast
    signed_psbt = psbt.sign(issuer_key)
    tx_hex = signed_psbt.finalize()
    
    broadcaster = TransactionBroadcaster([bitcoin_rpc])
    result = broadcaster.broadcast_transaction(tx_hex)
    
    if result.success:
        print(f"Transaction broadcast: {result.tx_id}")
        
        # Update registry state
        from registry.schema import TransactionEntry
        tx_entry = TransactionEntry(
            tx_id=result.tx_id,
            amount=mint_request.amount,
            recipient=mint_request.recipient_address
        )
        registry.update_asset_state(asset_id, tx_entry)
    else:
        print(f"Broadcast failed: {result.errors}")
```

### NFT Collection and Minting

#### Create NFT Collection

```python
from registry.schema import NFTAsset

# Create NFT collection
nft_data = {
    "name": "Digital Art Collection",
    "symbol": "DART",
    "asset_type": "nft",
    "collection_size": 100,
    "issuer_pubkey": issuer_key.public_key.hex(),
    "script_format": "p2tr",
    "manifest_hash": "0x1234567890abcdef...",
    "manifest_uri": "ipfs://QmManifest...",
    "metadata": {
        "description": "Unique digital artworks",
        "artist": "Digital Artist",
        "website": "https://artcollection.org"
    }
}

collection_id = registry.create_asset(nft_data)
print(f"Created NFT collection: {collection_id}")
```

#### Mint NFT

```python
from psbt.nft_mint import NFTMintPSBT, NFTMintRequest
import hashlib

# Prepare NFT content
nft_content = b"unique_digital_art_data"
content_hash = hashlib.sha256(nft_content).digest()

# Create NFT mint request
nft_mint_request = NFTMintRequest(
    collection_id=collection_id,
    token_id=1,
    recipient_address="bc1qnft_owner...",
    content_hash=content_hash,
    content_uri="ipfs://QmNFTContent...",
    metadata={
        "name": "Rare Digital Art #1",
        "description": "First piece in the collection",
        "attributes": [
            {"trait_type": "Color", "value": "Blue"},
            {"trait_type": "Rarity", "value": "Legendary"}
        ]
    },
    funding_utxo={
        "txid": "funding_tx_id",
        "vout": 0,
        "amount": 50000
    }
)

# Build and validate NFT mint
nft_collection = registry.get_asset(collection_id)
nft_builder = NFTMintPSBT(nft_collection, issuer_key)
nft_psbt = nft_builder.create_mint_transaction(nft_mint_request)

validation_result = validator.validate_mint_transaction(nft_psbt.to_base64())

if not validation_result.has_errors():
    # Sign and broadcast NFT mint
    signed_nft_psbt = nft_psbt.sign(issuer_key)
    nft_tx_hex = signed_nft_psbt.finalize()
    
    nft_result = broadcaster.broadcast_transaction(nft_tx_hex)
    print(f"NFT minted: {nft_result.tx_id}")
    
    # Update NFT state
    nft_tx_entry = TransactionEntry(
        tx_id=nft_result.tx_id,
        amount=1,  # NFTs always have amount = 1
        recipient=nft_mint_request.recipient_address
    )
    
    # Mark NFT as issued
    collection_state = registry.get_asset_state(collection_id)
    collection_state.issue_nft(nft_mint_request.token_id, nft_tx_entry)
    
    print(f"NFT #{nft_mint_request.token_id} issued successfully")
```

### Allowlist Management

#### Create Merkle Tree Allowlist

```python
from crypto.merkle import MerkleTree
from crypto.keys import hash160

# Define allowlist addresses
allowlist_addresses = [
    "bc1qallowed1...",
    "bc1qallowed2...",
    "bc1qallowed3...",
    "bc1qallowed4...",
    "bc1qallowed5..."
]

# Create Merkle tree
address_hashes = [hash160(addr.encode()) for addr in allowlist_addresses]
allowlist_tree = MerkleTree(address_hashes)

print(f"Allowlist root: {allowlist_tree.root.hex()}")

# Generate proof for specific address
target_address = "bc1qallowed3..."
target_index = allowlist_addresses.index(target_address)
proof = allowlist_tree.generate_proof(target_index)

print(f"Proof for {target_address}: {[p.hex() for p in proof]}")

# Verify proof
target_hash = hash160(target_address.encode())
is_valid = MerkleTree.verify_proof(target_hash, proof, allowlist_tree.root, target_index)
print(f"Proof verification: {is_valid}")
```

#### Mint with Allowlist Verification

```python
# Create asset with allowlist
allowlist_asset_data = {
    "name": "Exclusive Token",
    "symbol": "EXCL",
    "asset_type": "fungible",
    "maximum_supply": 10000,
    "per_mint_limit": 100,
    "issuer_pubkey": issuer_key.public_key.hex(),
    "allowlist_root": allowlist_tree.root.hex(),
    "script_format": "p2wsh"
}

exclusive_asset_id = registry.create_asset(allowlist_asset_data)

# Mint to allowlisted address
allowlisted_mint_request = FungibleMintRequest(
    asset_id=exclusive_asset_id,
    amount=50,
    recipient_address=target_address,
    allowlist_proof=proof,
    funding_utxo={
        "txid": "funding_tx",
        "vout": 0,
        "amount": 75000
    }
)

# The validator will automatically verify the allowlist proof
exclusive_asset = registry.get_asset(exclusive_asset_id)
exclusive_builder = FungibleMintPSBT(exclusive_asset, issuer_key)
exclusive_psbt = exclusive_builder.create_mint_transaction(allowlisted_mint_request)

validation_result = validator.validate_mint_transaction(exclusive_psbt.to_base64())
print(f"Allowlist validation: {'PASSED' if not validation_result.has_errors() else 'FAILED'}")
```

## CLI Examples

### Complete Asset Lifecycle

#### 1. Initialize Environment

```bash
# Initialize BNAP configuration
bnap config set network.type testnet
bnap config set network.rpc_host localhost
bnap config set network.rpc_port 18332
bnap config set validator.id "my_validator"

# Initialize registry
bnap registry init \
  --validator-id "my_validator" \
  --validator-pubkey 0x... \
  --network testnet
```

#### 2. Create Fungible Token

```bash
# Create token configuration file
cat > my_token.json << EOF
{
  "name": "Community Token",
  "symbol": "COMM",
  "max_supply": 500000,
  "per_mint_limit": 5000,
  "description": "Community governance token",
  "website": "https://community.org"
}
EOF

# Create the asset
bnap asset create-fungible \
  --from-file my_token.json \
  --output-file created_token.json

# Extract asset ID
ASSET_ID=$(jq -r '.asset_id' created_token.json)
echo "Created asset: $ASSET_ID"
```

#### 3. Mint Tokens to Multiple Recipients

```bash
#!/bin/bash
# Batch minting script

RECIPIENTS=(
    "bc1qrecipient1..."
    "bc1qrecipient2..."
    "bc1qrecipient3..."
)

for recipient in "${RECIPIENTS[@]}"; do
    echo "Minting 1000 tokens to $recipient"
    
    bnap mint fungible \
      --asset-id "$ASSET_ID" \
      --amount 1000 \
      --recipient "$recipient" \
      --fee-rate 10 \
      --broadcast \
      --wait-confirmation
    
    if [ $? -eq 0 ]; then
        echo "✅ Successfully minted to $recipient"
    else
        echo "❌ Failed to mint to $recipient"
    fi
    
    # Small delay between mints
    sleep 2
done
```

#### 4. Query Asset State

```bash
# Check asset details and current state
bnap asset show "$ASSET_ID" --include-state --format json | jq '.'

# Query all assets
bnap asset list --asset-type fungible --format table

# Export registry data
bnap registry query --export registry_backup.json
```

### NFT Collection Workflow

#### 1. Create Collection Manifest

```bash
# Create collection manifest
cat > art_collection_manifest.json << EOF
{
  "name": "Pixel Art Collection",
  "description": "Unique 8-bit style pixel art NFTs",
  "image": "ipfs://QmCollectionImage...",
  "external_url": "https://pixelart.org",
  "attributes": [
    {
      "trait_type": "Style",
      "values": ["Classic", "Modern", "Retro"]
    },
    {
      "trait_type": "Color Scheme",
      "values": ["Monochrome", "RGB", "Sepia"]
    }
  ],
  "tokens": [
    {
      "token_id": 1,
      "name": "Pixel Hero #1",
      "description": "Classic pixel art hero",
      "image": "ipfs://QmToken1...",
      "attributes": [
        {"trait_type": "Style", "value": "Classic"},
        {"trait_type": "Color Scheme", "value": "RGB"}
      ]
    }
  ]
}
EOF
```

#### 2. Create NFT Collection

```bash
# Create NFT collection
bnap asset create-nft \
  --name "Pixel Art Collection" \
  --symbol "PIXEL" \
  --collection-size 1000 \
  --manifest-file art_collection_manifest.json \
  --base-uri "ipfs://QmBaseURI/" \
  --output-file created_collection.json

COLLECTION_ID=$(jq -r '.asset_id' created_collection.json)
echo "Created collection: $COLLECTION_ID"
```

#### 3. Mint NFTs

```bash
# Mint specific NFT from collection
bnap mint nft \
  --collection-id "$COLLECTION_ID" \
  --token-id 1 \
  --recipient "bc1qcollector..." \
  --content-hash 0x1234567890abcdef... \
  --content-uri "ipfs://QmToken1..." \
  --metadata '{"name": "Pixel Hero #1", "rarity": "common"}' \
  --broadcast

# Batch mint multiple NFTs
for i in {1..10}; do
    bnap mint nft \
      --collection-id "$COLLECTION_ID" \
      --token-id "$i" \
      --recipient "bc1qbatch_recipient..." \
      --content-uri "ipfs://QmToken${i}..." \
      --broadcast
done
```

### Advanced Scenarios

#### Cross-Chain Integration Preparation

```bash
# Create asset with metadata for cross-chain bridge
cat > bridge_token.json << EOF
{
  "name": "Bridge Test Token",
  "symbol": "BRIDGE",
  "max_supply": 1000000,
  "per_mint_limit": 10000,
  "metadata": {
    "bridge_compatible": true,
    "ethereum_contract": "0x...",
    "polygon_contract": "0x...",
    "bridging_enabled": true
  }
}
EOF

bnap asset create-fungible --from-file bridge_token.json
```

#### Conditional Minting with Scripts

```bash
#!/bin/bash
# Conditional minting based on external criteria

ASSET_ID="your_asset_id"
MIN_BALANCE=1000  # Minimum Bitcoin balance required

function check_balance() {
    local address=$1
    # Use Bitcoin RPC to check balance
    bitcoin-cli getreceivedbyaddress "$address" 0
}

function conditional_mint() {
    local recipient=$1
    local amount=$2
    
    balance=$(check_balance "$recipient")
    
    if (( $(echo "$balance >= $MIN_BALANCE" | bc -l) )); then
        echo "Balance sufficient ($balance BTC), minting $amount tokens"
        
        bnap mint fungible \
          --asset-id "$ASSET_ID" \
          --amount "$amount" \
          --recipient "$recipient" \
          --broadcast
    else
        echo "Insufficient balance ($balance BTC), minimum $MIN_BALANCE required"
    fi
}

# Example usage
conditional_mint "bc1qrecipient..." 500
```

#### Automated Market Making Setup

```bash
# Create paired tokens for AMM
bnap asset create-fungible \
  --name "Token A" \
  --symbol "TOKA" \
  --max-supply 1000000 \
  --output-file token_a.json

bnap asset create-fungible \
  --name "Token B" \
  --symbol "TOKB" \
  --max-supply 1000000 \
  --output-file token_b.json

# Initial liquidity provision
ASSET_A=$(jq -r '.asset_id' token_a.json)
ASSET_B=$(jq -r '.asset_id' token_b.json)

# Mint initial liquidity
bnap mint fungible --asset-id "$ASSET_A" --amount 50000 --recipient "bc1qliquidity_pool..." --broadcast
bnap mint fungible --asset-id "$ASSET_B" --amount 50000 --recipient "bc1qliquidity_pool..." --broadcast
```

## Integration Examples

### Web Application Integration

#### Frontend JavaScript

```javascript
// Web application integration
class BNAPClient {
  constructor(apiUrl, apiKey) {
    this.apiUrl = apiUrl;
    this.apiKey = apiKey;
  }
  
  async createAsset(assetData) {
    const response = await fetch(`${this.apiUrl}/api/v1/assets`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
        'X-API-Version': '1.0'
      },
      body: JSON.stringify(assetData)
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Asset creation failed: ${error.message}`);
    }
    
    return response.json();
  }
  
  async mintTokens(assetId, amount, recipient) {
    const mintData = {
      asset_id: assetId,
      amount: amount,
      recipient: recipient
    };
    
    const response = await fetch(`${this.apiUrl}/api/v1/mint`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      },
      body: JSON.stringify(mintData)
    });
    
    return response.json();
  }
  
  async getAssetState(assetId) {
    const response = await fetch(
      `${this.apiUrl}/api/v1/assets/${assetId}/state`,
      {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`
        }
      }
    );
    
    return response.json();
  }
}

// Usage example
const client = new BNAPClient('https://api.bnap.org', 'your_api_key');

async function setupTokenSale() {
  try {
    // Create sale token
    const tokenData = {
      name: 'Sale Token',
      symbol: 'SALE',
      max_supply: 100000,
      per_mint_limit: 1000
    };
    
    const asset = await client.createAsset(tokenData);
    console.log('Token created:', asset.asset_id);
    
    // Mint tokens for sale
    const mintResult = await client.mintTokens(
      asset.asset_id,
      10000,
      'bc1qsale_contract...'
    );
    
    console.log('Tokens minted:', mintResult.transaction_id);
    
    // Monitor asset state
    const state = await client.getAssetState(asset.asset_id);
    console.log('Current supply:', state.minted_supply);
    
  } catch (error) {
    console.error('Token sale setup failed:', error.message);
  }
}
```

#### Backend Python Service

```python
# Flask backend service
from flask import Flask, request, jsonify
from bnap.validator import ValidationEngine
from bnap.registry import RegistryManager
import uuid

app = Flask(__name__)

# Initialize BNAP components
validator = ValidationEngine()
registry = RegistryManager()

@app.route('/api/v1/assets', methods=['POST'])
def create_asset():
    try:
        asset_data = request.json
        
        # Validate required fields
        required_fields = ['name', 'symbol', 'asset_type']
        for field in required_fields:
            if field not in asset_data:
                return jsonify({
                    'error': 'MISSING_REQUIRED_FIELD',
                    'message': f'Missing required field: {field}'
                }), 400
        
        # Create asset
        asset_id = registry.create_asset(asset_data)
        
        return jsonify({
            'status': 'success',
            'asset_id': asset_id,
            'data': asset_data
        }), 201
        
    except Exception as e:
        return jsonify({
            'error': 'ASSET_CREATION_FAILED',
            'message': str(e)
        }), 500

@app.route('/api/v1/mint', methods=['POST'])
def mint_tokens():
    try:
        mint_data = request.json
        
        # Validate mint request
        asset_id = mint_data.get('asset_id')
        amount = mint_data.get('amount')
        recipient = mint_data.get('recipient')
        
        if not all([asset_id, amount, recipient]):
            return jsonify({
                'error': 'INVALID_MINT_REQUEST',
                'message': 'Missing required mint parameters'
            }), 400
        
        # Create and validate PSBT
        psbt = create_mint_psbt(asset_id, amount, recipient)
        validation_result = validator.validate_mint_transaction(psbt)
        
        if validation_result.has_errors():
            return jsonify({
                'error': 'VALIDATION_FAILED',
                'message': 'Mint validation failed',
                'details': validation_result.validation_errors
            }), 422
        
        # Sign and broadcast
        signed_psbt = sign_psbt(psbt)
        tx_result = broadcast_transaction(signed_psbt)
        
        if tx_result.success:
            # Update registry
            update_asset_state(asset_id, amount, recipient, tx_result.tx_id)
            
            return jsonify({
                'status': 'success',
                'transaction_id': tx_result.tx_id,
                'amount': amount,
                'recipient': recipient
            }), 200
        else:
            return jsonify({
                'error': 'BROADCAST_FAILED',
                'message': 'Transaction broadcast failed',
                'details': tx_result.errors
            }), 500
            
    except Exception as e:
        return jsonify({
            'error': 'MINT_FAILED',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
```

These comprehensive examples demonstrate the full range of BNAP functionality across different interfaces and integration scenarios, providing practical templates for real-world usage.