# Error Codes and Exception Handling

This document provides comprehensive documentation for BNAP error codes, exception handling patterns, and troubleshooting guidance.

## Error Response Format

All BNAP APIs return errors in a consistent format:

```json
{
  "status": "error",
  "error_code": "SUPPLY_EXCEEDED",
  "message": "Mint amount would exceed maximum supply",
  "details": {
    "asset_id": "abc123...",
    "requested_amount": 15000,
    "current_supply": 990000,
    "maximum_supply": 1000000,
    "available_supply": 10000
  },
  "timestamp": "2024-01-01T12:00:00Z",
  "validator_id": "bnap_validator_v1",
  "request_id": "req_123456789"
}
```

## Error Code Categories

### Asset Validation Errors (1000-1999)

Errors related to asset definition and validation.

#### 1001 - INVALID_ASSET_ID

**Description**: Asset identifier is malformed or not found in registry.

**Causes:**
- Asset ID is not 64-character hex string
- Asset has not been registered
- Asset has been deprecated or removed

**Resolution:**
- Verify asset ID format (32 bytes hex)
- Check registry for asset existence
- Use `bnap asset list` to find valid asset IDs

**Example:**
```json
{
  "error_code": "INVALID_ASSET_ID",
  "message": "Asset not found in registry",
  "details": {
    "asset_id": "invalid_id",
    "expected_format": "64-character hex string"
  }
}
```

#### 1002 - ASSET_ALREADY_EXISTS

**Description**: Attempt to create asset with existing ID.

**Causes:**
- Asset ID collision (extremely rare)
- Duplicate asset creation request

**Resolution:**
- Generate new asset ID
- Check existing assets first

#### 1003 - INVALID_ASSET_TYPE

**Description**: Unsupported or invalid asset type specified.

**Causes:**
- Asset type not "fungible" or "nft"
- Typo in asset type field

**Resolution:**
- Use valid asset types: "fungible" or "nft"
- Check spelling and case sensitivity

### Supply and Mint Limit Errors (2000-2999)

Errors related to token supply and minting constraints.

#### 2001 - SUPPLY_EXCEEDED

**Description**: Mint operation would exceed maximum supply limit.

**Causes:**
- Requested mint amount + current supply > maximum supply
- Concurrent minting operations causing race condition

**Resolution:**
- Reduce mint amount
- Check current supply before minting
- Implement proper concurrency handling

**Example:**
```json
{
  "error_code": "SUPPLY_EXCEEDED",
  "message": "Mint would exceed maximum supply",
  "details": {
    "requested_amount": 5000,
    "current_supply": 998000,
    "maximum_supply": 1000000,
    "available_supply": 2000
  }
}
```

#### 2002 - MINT_LIMIT_EXCEEDED

**Description**: Single mint operation exceeds per-mint limit.

**Causes:**
- Mint amount > asset's per_mint_limit
- Incorrect per-mint limit configuration

**Resolution:**
- Split large mints into multiple smaller transactions
- Increase per-mint limit (if appropriate)
- Use batch minting for large amounts

#### 2003 - INSUFFICIENT_SUPPLY

**Description**: Not enough tokens available for operation.

**Causes:**
- Transfer amount exceeds available balance
- NFT already minted or transferred

**Resolution:**
- Check available balance
- Verify token ownership
- Use correct amounts for transfers

### Allowlist and Access Control Errors (3000-3999)

Errors related to allowlist validation and access control.

#### 3001 - ALLOWLIST_VIOLATION

**Description**: Address is not included in the asset's allowlist.

**Causes:**
- Recipient address not in Merkle tree allowlist
- Invalid or missing Merkle proof
- Allowlist not properly configured

**Resolution:**
- Add address to allowlist
- Generate valid Merkle proof
- Verify allowlist configuration

**Example:**
```json
{
  "error_code": "ALLOWLIST_VIOLATION",
  "message": "Address not in allowlist",
  "details": {
    "recipient_address": "bc1qtest...",
    "allowlist_root": "0xabc123...",
    "proof_provided": false
  }
}
```

#### 3002 - INVALID_MERKLE_PROOF

**Description**: Provided Merkle proof is invalid or doesn't verify.

**Causes:**
- Incorrect proof path
- Proof generated from wrong tree
- Corrupted proof data

**Resolution:**
- Regenerate Merkle proof
- Verify proof against correct tree root
- Check proof format and encoding

#### 3003 - ALLOWLIST_NOT_CONFIGURED

**Description**: Asset requires allowlist but none is configured.

**Causes:**
- Asset created without allowlist_root
- Allowlist configuration missing

**Resolution:**
- Configure allowlist for asset
- Remove allowlist requirement
- Update asset configuration

### NFT-Specific Errors (4000-4999)

Errors specific to NFT operations.

#### 4001 - DUPLICATE_NFT_ID

**Description**: Attempt to mint NFT with already-used token ID.

**Causes:**
- Token ID already minted in collection
- Concurrent minting of same token ID

**Resolution:**
- Use different token ID
- Check issued token IDs before minting
- Implement proper token ID management

**Example:**
```json
{
  "error_code": "DUPLICATE_NFT_ID",
  "message": "NFT token ID already issued",
  "details": {
    "collection_id": "def456...",
    "token_id": 42,
    "issued_tokens": [1, 2, 3, 42, 50]
  }
}
```

#### 4002 - CONTENT_HASH_MISMATCH

**Description**: NFT content hash doesn't match expected value.

**Causes:**
- Content modified after hash generation
- Incorrect hash algorithm used
- Hash verification failed

**Resolution:**
- Regenerate content hash
- Verify content integrity
- Use correct hashing algorithm (SHA-256)

#### 4003 - COLLECTION_SIZE_EXCEEDED

**Description**: NFT mint would exceed collection size limit.

**Causes:**
- Too many NFTs minted in collection
- Collection size limit reached

**Resolution:**
- Check remaining slots in collection
- Create new collection if needed
- Verify collection configuration

### Transaction and PSBT Errors (5000-5999)

Errors related to transaction construction and validation.

#### 5001 - INVALID_PSBT_FORMAT

**Description**: PSBT data is malformed or corrupt.

**Causes:**
- Invalid base64 encoding
- Corrupted PSBT data
- Incorrect PSBT structure

**Resolution:**
- Regenerate PSBT
- Verify base64 encoding
- Check PSBT construction logic

**Example:**
```json
{
  "error_code": "INVALID_PSBT_FORMAT",
  "message": "PSBT parsing failed",
  "details": {
    "error": "Invalid base64 encoding",
    "position": 156
  }
}
```

#### 5002 - INSUFFICIENT_BALANCE

**Description**: Not enough Bitcoin for transaction fees.

**Causes:**
- Funding UTXO value too low
- High fee rate requirements
- Multiple outputs requiring dust amounts

**Resolution:**
- Add more funding UTXOs
- Reduce fee rate (if acceptable)
- Combine UTXOs for larger amounts

#### 5003 - TRANSACTION_TOO_LARGE

**Description**: Transaction exceeds size limits.

**Causes:**
- Too many inputs or outputs
- Large witness data (scripts, proofs)
- Excessive OP_RETURN data

**Resolution:**
- Split into multiple transactions
- Optimize witness data
- Reduce OP_RETURN payload

#### 5004 - INVALID_SIGNATURE

**Description**: Transaction signature verification failed.

**Causes:**
- Wrong private key used
- Incorrect signature algorithm
- Tampered transaction data

**Resolution:**
- Use correct signing key
- Verify signature algorithm (ECDSA/Schnorr)
- Regenerate transaction

### Network and Connectivity Errors (6000-6999)

Errors related to Bitcoin network connectivity.

#### 6001 - NETWORK_ERROR

**Description**: Failed to connect to Bitcoin node.

**Causes:**
- Bitcoin node offline
- Network connectivity issues
- Incorrect RPC configuration

**Resolution:**
- Check Bitcoin node status
- Verify network connectivity
- Update RPC configuration

**Example:**
```json
{
  "error_code": "NETWORK_ERROR",
  "message": "Failed to connect to Bitcoin node",
  "details": {
    "rpc_host": "localhost",
    "rpc_port": 8332,
    "timeout": 30,
    "last_error": "Connection refused"
  }
}
```

#### 6002 - RPC_ERROR

**Description**: Bitcoin RPC call failed.

**Causes:**
- Invalid RPC method
- Authentication failure
- Bitcoin node error

**Resolution:**
- Check RPC credentials
- Verify Bitcoin node configuration
- Review Bitcoin node logs

#### 6003 - BROADCAST_FAILED

**Description**: Transaction broadcast to network failed.

**Causes:**
- Invalid transaction
- Network congestion
- Insufficient fee

**Resolution:**
- Validate transaction locally
- Increase transaction fee
- Retry broadcast after delay

### Cryptographic Errors (7000-7999)

Errors related to cryptographic operations.

#### 7001 - INVALID_KEY_FORMAT

**Description**: Private or public key format is invalid.

**Causes:**
- Incorrect key encoding
- Wrong key length
- Invalid key data

**Resolution:**
- Verify key format (hex, WIF, etc.)
- Check key length (32 bytes for private)
- Regenerate keys if corrupted

#### 7002 - SIGNATURE_VERIFICATION_FAILED

**Description**: Cryptographic signature verification failed.

**Causes:**
- Signature doesn't match message
- Wrong public key used
- Corrupted signature data

**Resolution:**
- Verify signature generation
- Use correct public key
- Check message integrity

#### 7003 - KEY_DERIVATION_FAILED

**Description**: HD key derivation failed.

**Causes:**
- Invalid derivation path
- Corrupted master key
- Derivation index out of range

**Resolution:**
- Use valid derivation path format
- Verify master key integrity
- Check derivation indices

## Exception Hierarchy

### Python Exception Classes

```python
from bnap.exceptions import (
    BNAPError,           # Base exception
    ValidationError,     # Validation failures
    RegistryError,       # Registry operations
    PSBTError,          # PSBT construction/parsing
    CryptoError,        # Cryptographic operations
    NetworkError        # Network connectivity
)

# Exception hierarchy
BNAPError
├── ValidationError
│   ├── SupplyExceededError
│   ├── MintLimitExceededError
│   └── AllowlistViolationError
├── RegistryError
│   ├── AssetNotFoundError
│   └── AssetAlreadyExistsError
├── PSBTError
│   ├── InvalidPSBTFormatError
│   └── TransactionTooLargeError
├── CryptoError
│   ├── InvalidKeyFormatError
│   └── SignatureVerificationError
└── NetworkError
    ├── RPCError
    └── BroadcastFailedError
```

### Error Handling Patterns

#### Basic Error Handling

```python
from bnap.exceptions import ValidationError, NetworkError

try:
    result = validator.validate_mint_transaction(psbt_hex)
    
except ValidationError as e:
    if e.error_code == "SUPPLY_EXCEEDED":
        # Handle supply limit error
        available = e.details.get("available_supply", 0)
        print(f"Only {available} tokens available")
    else:
        # Handle other validation errors
        print(f"Validation failed: {e.message}")
        
except NetworkError as e:
    # Handle network errors with retry
    if e.error_code == "NETWORK_ERROR":
        retry_with_backoff(operation)
    else:
        raise
```

#### Comprehensive Error Handling

```python
from bnap.exceptions import BNAPError
import logging

logger = logging.getLogger(__name__)

def safe_mint_operation(asset_id: str, amount: int, recipient: str):
    try:
        return perform_mint(asset_id, amount, recipient)
        
    except ValidationError as e:
        logger.error(f"Validation error: {e.error_code} - {e.message}")
        return {"status": "failed", "reason": "validation", "details": e.details}
        
    except NetworkError as e:
        logger.error(f"Network error: {e.error_code} - {e.message}")
        return {"status": "failed", "reason": "network", "retry": True}
        
    except BNAPError as e:
        logger.error(f"BNAP error: {e.error_code} - {e.message}")
        return {"status": "failed", "reason": "system", "details": e.details}
        
    except Exception as e:
        logger.exception("Unexpected error in mint operation")
        return {"status": "failed", "reason": "unexpected", "error": str(e)}
```

#### Retry Logic with Exponential Backoff

```python
import time
import random
from typing import Callable, Any

def retry_with_backoff(operation: Callable, max_retries: int = 3) -> Any:
    """Retry operation with exponential backoff."""
    
    for attempt in range(max_retries):
        try:
            return operation()
            
        except NetworkError as e:
            if attempt == max_retries - 1:
                raise  # Last attempt, re-raise the error
            
            # Calculate backoff delay
            base_delay = 2 ** attempt
            jitter = random.uniform(0.1, 0.9)
            delay = base_delay + jitter
            
            logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.1f}s")
            time.sleep(delay)
            
        except BNAPError as e:
            # Don't retry validation or other non-network errors
            raise
```

## Troubleshooting Guide

### Common Issues and Solutions

#### Issue: "Asset not found" errors

**Symptoms:**
- Error code: INVALID_ASSET_ID
- Asset operations fail with "not found"

**Diagnosis:**
```bash
# Check if asset exists
bnap asset list --search "token_name"

# Verify asset ID format
echo "asset_id" | wc -c  # Should be 65 (64 chars + newline)
```

**Solutions:**
1. Verify asset has been created and registered
2. Check asset ID spelling and format
3. Ensure using correct registry file

#### Issue: Supply limit exceeded

**Symptoms:**
- Error code: SUPPLY_EXCEEDED
- Mint operations rejected

**Diagnosis:**
```bash
# Check current supply
bnap asset show <asset_id> --include-state

# Calculate available supply
bnap registry query --asset-id <asset_id> --format json
```

**Solutions:**
1. Reduce mint amount
2. Wait for supply to become available
3. Increase maximum supply (if appropriate)

#### Issue: Allowlist violations

**Symptoms:**
- Error code: ALLOWLIST_VIOLATION
- Mints rejected for valid addresses

**Diagnosis:**
```python
# Verify address is in allowlist
from crypto.merkle import MerkleTree, verify_merkle_proof

# Check proof generation
addresses = ["bc1q...", "bc1q...", ...]
tree = MerkleTree([hash160(addr.encode()) for addr in addresses])
proof = tree.generate_proof(target_index)
```

**Solutions:**
1. Add address to allowlist
2. Regenerate Merkle proof
3. Verify allowlist configuration

#### Issue: Network connectivity problems

**Symptoms:**
- Error code: NETWORK_ERROR
- Timeouts and connection failures

**Diagnosis:**
```bash
# Test Bitcoin node connectivity
bitcoin-cli getblockchaininfo

# Check RPC configuration
bnap config show network --format json
```

**Solutions:**
1. Start Bitcoin node
2. Update RPC configuration
3. Check firewall settings

### Debugging Tools

#### Enable Debug Logging

```bash
# CLI debug mode
bnap --verbose=2 <command>

# Python logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

#### Transaction Analysis

```python
# Analyze failed PSBT
from psbt.parser import PSBTParser

parser = PSBTParser()
psbt_data = parser.parse(psbt_base64)

# Check inputs and outputs
print(f"Inputs: {len(psbt_data['inputs'])}")
print(f"Outputs: {len(psbt_data['outputs'])}")

# Validate transaction structure
from psbt.validator import PSBTValidator
validator = PSBTValidator()
result = validator.validate_psbt(psbt_data)
print(f"Validation errors: {result.errors}")
```

#### Registry Inspection

```bash
# Dump registry contents
bnap registry query --format json --export full_registry.json

# Check asset state
bnap asset show <asset_id> --include-state --include-transactions
```

This error documentation provides comprehensive coverage of all BNAP error conditions with practical troubleshooting guidance and code examples.