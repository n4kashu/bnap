# Python API Reference

This document provides comprehensive documentation for the BNAP Python API, extracted from the actual implementation modules.

## Core Modules

### Validation Engine (`validator.core`)

The ValidationEngine is the central component for validating and processing asset transactions.

#### Class: ValidationEngine

```python
from validator.core import ValidationEngine

# Initialize with configuration
config = {
    "validator_id": "bnap_validator_v1",
    "max_validation_time": 30,
    "enable_audit_logging": True
}

validator = ValidationEngine(config)
```

**Constructor Parameters:**
- `config` (Dict[str, Any], optional): Validator configuration dictionary

**Key Methods:**

##### validate_mint_transaction()

```python
def validate_mint_transaction(self, psbt_hex: str, **kwargs) -> ValidationContext:
    """
    Validate a mint transaction PSBT.
    
    Args:
        psbt_hex (str): Hex-encoded PSBT data
        **kwargs: Additional validation parameters
        
    Returns:
        ValidationContext: Validation results with errors/warnings
        
    Raises:
        ValidationError: If validation fails
        PSBTError: If PSBT format is invalid
    """
```

**Example:**
```python
# Validate a mint transaction
result = validator.validate_mint_transaction(psbt_hex)

if result.has_errors():
    print(f"Validation failed: {result.validation_errors}")
else:
    print("Transaction approved for signing")
    # Proceed with signing
```

##### register_rule()

```python
def register_rule(self, rule: ValidationRule) -> None:
    """
    Register a custom validation rule.
    
    Args:
        rule (ValidationRule): Validation rule instance
    """
```

##### get_statistics()

```python
def get_statistics(self) -> Dict[str, Any]:
    """
    Get validation statistics.
    
    Returns:
        Dict containing validation metrics
    """
```

**Example:**
```python
stats = validator.get_statistics()
print(f"Total validations: {stats['total_validations']}")
print(f"Success rate: {stats['approved_validations'] / stats['total_validations']:.2%}")
```

#### Class: ValidationContext

Container for validation state and results.

**Properties:**
- `psbt_data` (Dict): Parsed PSBT data
- `asset_id` (bytes): Asset identifier being processed  
- `asset_type` (AssetType): FUNGIBLE or NFT
- `amount` (int): Asset amount for operation
- `validation_errors` (List[str]): Validation error messages
- `validation_warnings` (List[str]): Validation warnings

**Methods:**

##### has_errors()

```python
def has_errors(self) -> bool:
    """Check if validation has errors."""
```

##### get_summary()

```python
def get_summary(self) -> Dict[str, Any]:
    """Get validation summary with results."""
```

### Registry Manager (`registry.manager`)

Manages asset definitions, state tracking, and persistence.

#### Class: RegistryManager

```python
from registry.manager import RegistryManager

# Initialize with registry file
registry = RegistryManager(registry_path="registry.json")
```

**Key Methods:**

##### create_asset()

```python
def create_asset(self, asset_data: Dict[str, Any]) -> str:
    """
    Create a new asset in the registry.
    
    Args:
        asset_data: Asset configuration dictionary
        
    Returns:
        str: Generated asset ID
        
    Raises:
        RegistryError: If asset creation fails
        ValidationError: If asset data is invalid
    """
```

**Example:**
```python
# Create fungible token
fungible_data = {
    "name": "Test Token",
    "symbol": "TEST",
    "asset_type": "fungible",
    "maximum_supply": 1000000,
    "per_mint_limit": 10000,
    "issuer_pubkey": "0x...",
    "script_format": "p2tr"
}

asset_id = registry.create_asset(fungible_data)
print(f"Created asset: {asset_id}")
```

##### get_asset()

```python
def get_asset(self, asset_id: str) -> Optional[Asset]:
    """
    Retrieve asset by ID.
    
    Args:
        asset_id: Asset identifier
        
    Returns:
        Asset object or None if not found
    """
```

##### update_asset_state()

```python
def update_asset_state(self, asset_id: str, transaction: TransactionEntry) -> None:
    """
    Update asset state after successful transaction.
    
    Args:
        asset_id: Asset identifier
        transaction: Transaction details
    """
```

##### query_assets()

```python
def query_assets(self, filters: Dict[str, Any] = None) -> List[Asset]:
    """
    Query assets with optional filters.
    
    Args:
        filters: Query filters (asset_type, status, etc.)
        
    Returns:
        List of matching assets
    """
```

**Example:**
```python
# Query all fungible tokens
fungible_assets = registry.query_assets({"asset_type": "fungible"})

for asset in fungible_assets:
    state = registry.get_asset_state(asset.asset_id)
    print(f"{asset.name}: {state.minted_supply}/{asset.maximum_supply}")
```

### PSBT Builder (`psbt.builder`)

Constructs Partially Signed Bitcoin Transactions for BNAP operations.

#### Class: PSBTBuilder

```python
from psbt.builder import PSBTBuilder
from psbt.fungible_mint import FungibleMintPSBT

# Create PSBT for fungible mint
builder = FungibleMintPSBT(asset_config, validator_key)
```

##### create_mint_transaction()

```python
def create_mint_transaction(self, mint_request: MintRequest) -> PSBT:
    """
    Create PSBT for minting operation.
    
    Args:
        mint_request: Mint request parameters
        
    Returns:
        PSBT: Constructed transaction
        
    Raises:
        PSBTError: If PSBT construction fails
    """
```

**Example:**
```python
from psbt.fungible_mint import FungibleMintPSBT, FungibleMintRequest
from crypto.keys import PrivateKey

# Set up mint request
mint_request = FungibleMintRequest(
    asset_id="abc123...",
    amount=1000,
    recipient_address="bc1q...",
    funding_utxo={
        "txid": "def456...",
        "vout": 0,
        "amount": 100000  # 0.001 BTC
    }
)

# Create PSBT
validator_key = PrivateKey.from_hex("...")
builder = FungibleMintPSBT(asset_config, validator_key)
psbt = builder.create_mint_transaction(mint_request)

print(f"PSBT created: {psbt.to_base64()}")
```

### Cryptographic Module (`crypto.keys`)

Key management and cryptographic operations.

#### Class: PrivateKey

```python
from crypto.keys import PrivateKey, PublicKey

# Generate new private key
private_key = PrivateKey.generate()

# Load from hex
private_key = PrivateKey.from_hex("your_hex_key")

# Load from WIF
private_key = PrivateKey.from_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
```

**Key Methods:**

##### sign()

```python
def sign(self, message_hash: bytes, use_schnorr: bool = True) -> bytes:
    """
    Sign message hash.
    
    Args:
        message_hash: 32-byte hash to sign
        use_schnorr: Use Schnorr signatures (default: True)
        
    Returns:
        Signature bytes
    """
```

##### public_key

```python
@property
def public_key(self) -> PublicKey:
    """Get corresponding public key."""
```

**Example:**
```python
# Sign a transaction hash
tx_hash = bytes.fromhex("abc123...")
signature = private_key.sign(tx_hash, use_schnorr=True)

# Verify signature
public_key = private_key.public_key
is_valid = public_key.verify(signature, tx_hash)
print(f"Signature valid: {is_valid}")
```

#### HD Key Derivation

```python
from crypto.keys import HDPrivateKey

# Create from mnemonic
mnemonic = "abandon abandon abandon ... art"
seed = HDPrivateKey.mnemonic_to_seed(mnemonic)
master_key = HDPrivateKey.from_seed(seed)

# Derive child keys
account_key = master_key.derive_path("m/86'/0'/0'")  # Taproot
address_key = account_key.derive_child(0).derive_child(0)

print(f"Address: {address_key.to_address('p2tr')}")
```

### Asset Commitments (`crypto.commitments`)

Cryptographic asset commitments for privacy.

#### Functions

##### create_asset_commitment()

```python
def create_asset_commitment(asset_id: bytes, amount: int, 
                          metadata: bytes = b"") -> bytes:
    """
    Create asset commitment hash.
    
    Args:
        asset_id: 32-byte asset identifier
        amount: Asset amount  
        metadata: Additional metadata
        
    Returns:
        32-byte commitment hash
    """
```

##### create_taproot_commitment()

```python
def create_taproot_commitment(internal_key: bytes, 
                            commitment: AssetCommitment) -> TaprootOutput:
    """
    Create Taproot output with asset commitment.
    
    Args:
        internal_key: Internal public key
        commitment: Asset commitment data
        
    Returns:
        TaprootOutput with tweaked key
    """
```

**Example:**
```python
from crypto.commitments import AssetCommitment, create_taproot_commitment

# Create asset commitment
commitment = AssetCommitment(
    asset_id=bytes.fromhex("abc123..."),
    amount=1000,
    operation=OperationType.MINT,
    nonce=b"random_nonce",
    metadata=b""
)

# Create Taproot output
internal_key = private_key.public_key.compressed
taproot_output = create_taproot_commitment(internal_key, commitment)

print(f"Taproot address: {taproot_output.to_address()}")
```

### Merkle Proofs (`crypto.merkle`)

Allowlist verification using Merkle trees.

#### Class: MerkleTree

```python
from crypto.merkle import MerkleTree

# Create allowlist tree
addresses = ["bc1q...", "bc1q...", "bc1q..."]
address_hashes = [hash160(addr.encode()) for addr in addresses]
tree = MerkleTree(address_hashes)

print(f"Merkle root: {tree.root.hex()}")
```

##### generate_proof()

```python
def generate_proof(self, leaf_index: int) -> List[bytes]:
    """
    Generate Merkle proof for leaf.
    
    Args:
        leaf_index: Index of leaf to prove
        
    Returns:
        List of proof hashes
    """
```

##### verify_proof()

```python
@staticmethod
def verify_proof(leaf: bytes, proof: List[bytes], root: bytes, 
                leaf_index: int) -> bool:
    """
    Verify Merkle proof.
    
    Args:
        leaf: Leaf hash to verify
        proof: Proof path hashes
        root: Expected root hash
        leaf_index: Leaf position in tree
        
    Returns:
        True if proof is valid
    """
```

**Example:**
```python
# Generate proof for address
target_address = "bc1qtest..."
target_index = addresses.index(target_address)
proof = tree.generate_proof(target_index)

# Verify proof
target_hash = hash160(target_address.encode())
is_valid = MerkleTree.verify_proof(target_hash, proof, tree.root, target_index)
print(f"Proof valid: {is_valid}")
```

## Data Models (`registry.schema`)

### Asset Models

#### FungibleAsset

```python
from registry.schema import FungibleAsset, AssetStatus, ScriptFormat

# Create fungible asset
asset = FungibleAsset(
    asset_id="generated_id",
    name="Test Token",
    symbol="TEST",
    issuer_pubkey="0x...",
    maximum_supply=1000000,
    per_mint_limit=10000,
    decimal_places=2,
    status=AssetStatus.ACTIVE,
    script_format=ScriptFormat.P2TR
)
```

**Fields:**
- `asset_id` (str): 64-character hex asset identifier
- `name` (str): Human-readable asset name (1-100 chars)
- `symbol` (str): Asset symbol (1-10 chars, uppercase)
- `maximum_supply` (int): Hard cap on total supply
- `per_mint_limit` (int): Maximum amount per mint transaction
- `decimal_places` (int): Number of decimal places (0-18)

#### NFTAsset

```python
from registry.schema import NFTAsset

# Create NFT collection
nft_asset = NFTAsset(
    asset_id="generated_id",
    name="Art Collection",
    symbol="ART",
    issuer_pubkey="0x...",
    collection_size=100,
    content_hash="0x...",
    content_uri="ipfs://...",
    manifest_hash="0x..."
)
```

**Fields:**
- `collection_size` (int): Maximum NFTs in collection
- `content_hash` (str): SHA-256 hash of content (optional)
- `content_uri` (str): Content location (IPFS/HTTP)
- `manifest_hash` (str): Collection manifest hash

### State Models

#### StateEntry

```python
from registry.schema import StateEntry, TransactionEntry

# Asset state tracking
state = StateEntry(
    asset_id="abc123...",
    minted_supply=5000,
    transaction_count=25,
    issued_nft_ids=[1, 2, 3, 5, 8]  # For NFT collections
)

# Add transaction
tx_entry = TransactionEntry(
    tx_id="def456...",
    amount=100,
    recipient="bc1q...",
    block_height=750000
)

state.add_transaction(tx_entry)
```

## Error Handling

### Exception Hierarchy

```python
from validator.exceptions import ValidationError
from registry.exceptions import RegistryError
from psbt.exceptions import PSBTError
from crypto.exceptions import CryptoError
from network.exceptions import NetworkError

# All BNAP exceptions inherit from BNAPError
from bnap.exceptions import BNAPError
```

### Common Exception Patterns

```python
try:
    # Validation operation
    result = validator.validate_mint_transaction(psbt_hex)
    
except ValidationError as e:
    # Handle validation-specific errors
    print(f"Validation failed: {e}")
    
except PSBTError as e:
    # Handle PSBT format errors
    print(f"Invalid PSBT: {e}")
    
except NetworkError as e:
    # Handle network connectivity errors
    print(f"Network error: {e}")
    # Implement retry logic
    
except BNAPError as e:
    # Handle any BNAP-related error
    print(f"BNAP error: {e}")
    
except Exception as e:
    # Handle unexpected errors
    print(f"Unexpected error: {e}")
```

## Configuration

### Validator Configuration

```python
validator_config = {
    # Core settings
    "validator_id": "bnap_validator_v1",
    "max_validation_time": 30,
    "enable_audit_logging": True,
    
    # Signing keys
    "signing_keys": {
        "primary": "0xabcd1234...",
        "backup": "0xefgh5678..."
    },
    
    # Network settings
    "network": {
        "rpc_host": "localhost",
        "rpc_port": 18443,
        "rpc_user": "bitcoin",
        "rpc_password": "password"
    },
    
    # Performance tuning
    "max_supply_cap": 21_000_000,
    "max_per_mint_cap": 1_000_000,
    "cache_size": 1000
}
```

### Registry Configuration

```python
registry_config = {
    "registry_path": "/path/to/registry.json",
    "backup_enabled": True,
    "backup_interval": 3600,  # 1 hour
    "max_backup_files": 24,
    "concurrency_timeout": 30
}
```

## Testing Utilities

### Mock Objects

```python
from bnap.testing import MockValidator, TestAssets, TestTransactions

# Create mock validator for testing
validator = MockValidator()

# Create test assets
fungible_asset = TestAssets.create_fungible_token()
nft_asset = TestAssets.create_nft_collection()

# Create test transactions
mint_psbt = TestTransactions.create_fungible_mint(
    asset_id=fungible_asset.asset_id,
    amount=1000
)
```

### Integration Testing

```python
import pytest
from bnap.testing import IntegrationTestCase

class TestMintingWorkflow(IntegrationTestCase):
    def test_complete_mint_workflow(self):
        # Create asset
        asset_id = self.registry.create_asset(self.test_fungible_config)
        
        # Create mint PSBT
        psbt = self.create_mint_psbt(asset_id, 1000)
        
        # Validate transaction
        result = self.validator.validate_mint_transaction(psbt)
        assert not result.has_errors()
        
        # Check state update
        state = self.registry.get_asset_state(asset_id)
        assert state.minted_supply == 1000
```

This Python API documentation provides comprehensive coverage of all BNAP modules with practical examples and usage patterns.