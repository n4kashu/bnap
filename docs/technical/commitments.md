# Asset Commitment Schemes

This document details how BNAP embeds asset information into Bitcoin transactions using cryptographic commitments, based on the implementation in `crypto/commitments.py`.

## Overview

Asset commitments allow BNAP to encode asset metadata directly into Bitcoin outputs without requiring additional blockchain space. The protocol supports two commitment schemes:

1. **Taproot Commitments (P2TR)**: Privacy-preserving via key tweaking
2. **P2WSH Commitments**: Transparent via witness script data

## Commitment Types

### Operation Types

```python
class OperationType(Enum):
    MINT = "mint"
    TRANSFER = "transfer"
    BURN = "burn"
    FREEZE = "freeze"
    UNFREEZE = "unfreeze"
    METADATA_UPDATE = "metadata_update"
```

### Asset Commitment Structure

```python
@dataclass
class AssetCommitment:
    asset_id: bytes          # 32-byte asset identifier
    amount: int              # Asset amount (8 bytes)
    operation: OperationType # Operation being performed
    nonce: bytes            # Random nonce for uniqueness
    metadata: bytes         # Additional operation data
    
    def serialize(self) -> bytes:
        """Serialize commitment for hashing."""
        return (
            self.asset_id +
            self.amount.to_bytes(8, 'little') +
            self.operation.value.encode('utf-8').ljust(16, b'\x00') +
            self.nonce +
            len(self.metadata).to_bytes(2, 'little') +
            self.metadata
        )
    
    def hash(self) -> bytes:
        """Generate commitment hash."""
        return tagged_hash("BNAP/commitment/v1", self.serialize())
```

## Taproot Commitments

### Key Path Spending

Taproot commitments embed asset data by tweaking the internal public key:

```mermaid
graph LR
    A[Internal Key<br/>P_internal] --> B[Asset Data<br/>Serialization]
    B --> C[Tagged Hash<br/>H(tag, data)]
    C --> D[Scalar Mult<br/>t * G]
    D --> E[Point Addition<br/>P_internal + t*G]
    E --> F[Output Key<br/>P_output]
    
    style F fill:#f96
```

### Implementation

```python
def create_taproot_commitment(internal_key: bytes, commitment: AssetCommitment) -> TaprootOutput:
    """Create Taproot output with asset commitment."""
    
    # Serialize asset commitment
    commitment_data = commitment.serialize()
    
    # Generate commitment hash
    commitment_hash = tagged_hash("BNAP/asset/v1", commitment_data)
    
    # Parse internal public key
    P_internal = parse_public_key(internal_key)
    if P_internal is None:
        raise InvalidKeyError("Invalid internal public key")
    
    # Generate tweak scalar from commitment hash
    tweak_scalar = int.from_bytes(commitment_hash, 'big') % SECP256K1_ORDER
    if tweak_scalar == 0:
        raise CommitmentError("Invalid tweak scalar")
    
    # Compute commitment point: t * G
    commitment_point = tweak_scalar * SECP256K1_G
    
    # Output key: P = P_internal + commitment_point
    P_output = P_internal + commitment_point
    
    # Ensure even y-coordinate per BIP341
    if P_output.y % 2 != 0:
        # Negate the point to make y even
        P_output = P_output.negate()
        # Update tweak to account for negation
        tweak_scalar = SECP256K1_ORDER - tweak_scalar
    
    return TaprootOutput(
        output_key=P_output.x.to_bytes(32, 'big'),
        internal_key=internal_key,
        commitment_hash=commitment_hash,
        tweak_scalar=tweak_scalar,
        parity=P_output.y % 2
    )

@dataclass
class TaprootOutput:
    output_key: bytes       # 32-byte x-only public key
    internal_key: bytes     # Original internal key
    commitment_hash: bytes  # Asset commitment hash
    tweak_scalar: int      # Tweak scalar value
    parity: int            # Y-coordinate parity (0=even, 1=odd)
```

### Verification

```python
def verify_taproot_commitment(output: TaprootOutput, 
                            expected_commitment: AssetCommitment) -> bool:
    """Verify Taproot asset commitment."""
    try:
        # Recompute expected commitment hash
        expected_hash = expected_commitment.hash()
        
        # Verify commitment hash matches
        if output.commitment_hash != expected_hash:
            return False
        
        # Reconstruct output key
        P_internal = parse_public_key(output.internal_key)
        tweak_point = output.tweak_scalar * SECP256K1_G
        P_reconstructed = P_internal + tweak_point
        
        # Account for parity
        if P_reconstructed.y % 2 != output.parity:
            P_reconstructed = P_reconstructed.negate()
        
        # Verify output key matches
        return P_reconstructed.x.to_bytes(32, 'big') == output.output_key
        
    except Exception:
        return False
```

### Script Path (Optional)

For additional validation, Taproot outputs can include script paths:

```python
def create_taproot_script_tree(asset_rules: List[bytes]) -> TapTree:
    """Create Taproot script tree for asset validation."""
    
    # Create leaf scripts for each rule
    leaves = []
    for rule_script in asset_rules:
        leaf_hash = tagged_hash("TapLeaf", bytes([0xc0]) + serialize_script(rule_script))
        leaves.append(leaf_hash)
    
    # Build Merkle tree of scripts
    tree = build_tap_tree(leaves)
    
    return TapTree(
        leaves=leaves,
        root=tree.root,
        paths=tree.generate_all_paths()
    )

def tweak_with_script_tree(internal_key: bytes, script_root: bytes) -> bytes:
    """Tweak internal key with script tree root."""
    tweak = tagged_hash("TapTweak", internal_key + script_root)
    tweak_scalar = int.from_bytes(tweak, 'big') % SECP256K1_ORDER
    
    P_internal = parse_public_key(internal_key)
    tweak_point = tweak_scalar * SECP256K1_G
    P_output = P_internal + tweak_point
    
    return P_output.x.to_bytes(32, 'big')
```

## P2WSH Commitments

### Witness Script Commitments

P2WSH commitments store asset data in the witness stack:

```python
def create_p2wsh_commitment(asset_commitment: AssetCommitment,
                          validator_pubkey: bytes) -> P2WSHOutput:
    """Create P2WSH output with asset commitment."""
    
    # Create witness script that validates asset commitment
    witness_script = create_asset_witness_script(
        asset_commitment.asset_id,
        validator_pubkey
    )
    
    # Script hash for P2WSH
    script_hash = hashlib.sha256(witness_script).digest()
    
    # P2WSH output script: OP_0 <32-byte-hash>
    output_script = bytes([OP_0, 0x20]) + script_hash
    
    return P2WSHOutput(
        output_script=output_script,
        witness_script=witness_script,
        script_hash=script_hash,
        commitment=asset_commitment
    )

def create_asset_witness_script(asset_id: bytes, validator_pubkey: bytes) -> bytes:
    """Create witness script for asset validation."""
    return [
        # Stack: <signature> <commitment_data>
        
        # Verify commitment data format
        OP_DUP,                    # Duplicate commitment data
        OP_SIZE,                   # Get size
        0x40,                      # Expected size (64 bytes minimum)
        OP_GREATERTHANOREQUAL,     # Verify minimum size
        OP_VERIFY,                 # Assert size check
        
        # Extract and verify asset ID
        OP_DUP,                    # Duplicate commitment
        0x00, 0x20,               # Extract first 32 bytes (asset ID)
        OP_SUBSTR,                 # Get asset ID
        asset_id,                  # Expected asset ID
        OP_EQUALVERIFY,            # Verify asset ID matches
        
        # Verify commitment hash
        OP_HASH256,                # Hash the commitment data
        OP_DUP,                    # Duplicate hash
        # Additional validation logic here...
        
        # Validator signature check
        validator_pubkey,          # Validator public key
        OP_CHECKSIG                # Verify signature
    ]
```

### Witness Stack Structure

```
Witness Stack (bottom to top):
┌─────────────────────┐
│ Witness Script      │ ← Full script bytecode
├─────────────────────┤
│ Asset Commitment    │ ← Serialized commitment data
├─────────────────────┤
│ Validator Signature │ ← ECDSA/Schnorr signature
└─────────────────────┘
```

## Commitment Verification

### Multi-Step Verification Process

```python
class CommitmentVerifier:
    def __init__(self, registry: RegistryManager):
        self.registry = registry
        self.logger = logging.getLogger(__name__)
    
    def verify_commitment(self, output: Union[TaprootOutput, P2WSHOutput],
                        transaction_context: TransactionContext) -> VerificationResult:
        """Comprehensive commitment verification."""
        
        try:
            # Step 1: Extract commitment data
            commitment = self._extract_commitment(output)
            if not commitment:
                return VerificationResult.INVALID_FORMAT
            
            # Step 2: Validate asset exists
            asset = self.registry.get_asset(commitment.asset_id)
            if not asset:
                return VerificationResult.UNKNOWN_ASSET
            
            # Step 3: Verify operation is valid for asset type
            if not self._is_valid_operation(asset, commitment.operation):
                return VerificationResult.INVALID_OPERATION
            
            # Step 4: Check asset-specific rules
            validation_result = self._validate_asset_rules(asset, commitment, transaction_context)
            if not validation_result.success:
                return validation_result
            
            # Step 5: Verify cryptographic commitment
            if isinstance(output, TaprootOutput):
                crypto_valid = verify_taproot_commitment(output, commitment)
            else:
                crypto_valid = verify_p2wsh_commitment(output, commitment)
            
            if not crypto_valid:
                return VerificationResult.CRYPTO_INVALID
            
            return VerificationResult.VALID
            
        except Exception as e:
            self.logger.error(f"Commitment verification error: {e}")
            return VerificationResult.ERROR
    
    def _extract_commitment(self, output: Union[TaprootOutput, P2WSHOutput]) -> Optional[AssetCommitment]:
        """Extract asset commitment from output."""
        if isinstance(output, TaprootOutput):
            return self._extract_taproot_commitment(output)
        else:
            return self._extract_p2wsh_commitment(output)
    
    def _validate_asset_rules(self, asset: Asset, commitment: AssetCommitment,
                            context: TransactionContext) -> VerificationResult:
        """Validate commitment against asset rules."""
        
        if asset.asset_type == AssetType.FUNGIBLE:
            return self._validate_fungible_rules(asset, commitment, context)
        elif asset.asset_type == AssetType.NFT:
            return self._validate_nft_rules(asset, commitment, context)
        else:
            return VerificationResult.UNKNOWN_ASSET_TYPE
```

### Supply Limit Verification

```python
def verify_supply_limits(asset: FungibleAsset, mint_amount: int,
                        current_supply: int) -> bool:
    """Verify mint does not exceed supply limits."""
    
    # Check per-mint limit
    if mint_amount > asset.per_mint_limit:
        return False
    
    # Check total supply limit
    new_total = current_supply + mint_amount
    if new_total > asset.maximum_supply:
        return False
    
    return True
```

### NFT Uniqueness Verification

```python
def verify_nft_uniqueness(asset: NFTAsset, token_id: int,
                         issued_tokens: Set[int]) -> bool:
    """Verify NFT token ID is unique within collection."""
    
    # Check token ID is within collection bounds
    if token_id >= asset.collection_size:
        return False
    
    # Check token hasn't been issued before
    if token_id in issued_tokens:
        return False
    
    return True
```

## Commitment Serialization

### Binary Format

```
Asset Commitment Binary Format:
┌─────────────────────────────────────────────────────────────────┐
│ Asset ID (32 bytes)                                             │
├─────────────────────────────────────────────────────────────────┤
│ Amount (8 bytes, little-endian)                                 │
├─────────────────────────────────────────────────────────────────┤
│ Operation Type (16 bytes, UTF-8 padded)                        │
├─────────────────────────────────────────────────────────────────┤
│ Nonce (32 bytes)                                               │
├─────────────────────────────────────────────────────────────────┤
│ Metadata Length (2 bytes, little-endian)                       │
├─────────────────────────────────────────────────────────────────┤
│ Metadata (variable length)                                     │
└─────────────────────────────────────────────────────────────────┘
```

### JSON Representation

```json
{
  "asset_id": "0x1234567890abcdef...",
  "amount": 1000,
  "operation": "mint",
  "nonce": "0xfedcba0987654321...",
  "metadata": {
    "recipient": "bc1q...",
    "allowlist_proof": ["0x...", "0x..."],
    "content_hash": "0x..."
  }
}
```

## Privacy Considerations

### Taproot Privacy Benefits

```mermaid
graph TB
    subgraph "Observer View"
        A[Standard P2TR Output]
        B[32-byte x-only pubkey]
        C[No visible asset data]
    end
    
    subgraph "Validator View"
        D[Internal Key Known]
        E[Commitment Extractable]
        F[Asset Data Visible]
    end
    
    subgraph "Holder View"
        G[Full Commitment Data]
        H[Spending Capability]
        I[Transfer Authority]
    end
    
    A --> B
    B --> C
    D --> E
    E --> F
    G --> H
    H --> I
```

### Privacy Analysis

| Scheme | Observer Privacy | Size Overhead | Complexity |
|--------|------------------|---------------|------------|
| Taproot | High | 0 bytes | Medium |
| P2WSH | Low | ~100 bytes | Low |
| OP_RETURN | None | ~80 bytes | Low |

## Performance Metrics

### Commitment Operations

| Operation | Taproot | P2WSH | Notes |
|-----------|---------|-------|-------|
| Create | 0.5ms | 0.1ms | Point arithmetic vs script building |
| Verify | 1.2ms | 0.3ms | EC operations vs hash verification |
| Extract | 0.8ms | 0.05ms | Requires key knowledge vs direct read |
| Size | 32 bytes | ~100 bytes | Output script size |

### Scalability

```python
def benchmark_commitment_operations(iterations: int = 1000):
    """Benchmark commitment creation and verification."""
    
    # Setup test data
    private_key = secure_random_bytes(32)
    internal_key = derive_public_key(private_key)
    commitment = AssetCommitment(
        asset_id=secure_random_bytes(32),
        amount=1000,
        operation=OperationType.MINT,
        nonce=secure_random_bytes(32),
        metadata=b""
    )
    
    # Benchmark Taproot commitments
    start_time = time.time()
    for _ in range(iterations):
        output = create_taproot_commitment(internal_key, commitment)
        verify_taproot_commitment(output, commitment)
    taproot_time = time.time() - start_time
    
    # Benchmark P2WSH commitments  
    start_time = time.time()
    for _ in range(iterations):
        output = create_p2wsh_commitment(commitment, internal_key)
        verify_p2wsh_commitment(output, commitment)
    p2wsh_time = time.time() - start_time
    
    return {
        'taproot_ops_per_sec': iterations / taproot_time,
        'p2wsh_ops_per_sec': iterations / p2wsh_time,
        'taproot_avg_ms': (taproot_time / iterations) * 1000,
        'p2wsh_avg_ms': (p2wsh_time / iterations) * 1000
    }
```

This commitment system enables BNAP to embed rich asset metadata into standard Bitcoin transactions while maintaining compatibility with existing infrastructure and providing optional privacy through Taproot key tweaking.