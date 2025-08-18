# API Overview

The Bitcoin Native Asset Protocol (BNAP) provides multiple API interfaces for interacting with the system. This document provides an overview of all available APIs and their intended use cases.

## API Interfaces

### 1. Python API

The core Python API provides direct access to all BNAP functionality through Python modules:

- **Validation Engine** (`validator.core`): Transaction validation and signing
- **Registry Manager** (`registry.manager`): Asset state and configuration management
- **PSBT Builder** (`psbt.builder`): Transaction construction utilities
- **Cryptographic Primitives** (`crypto.*`): Key management and signatures
- **Network Integration** (`network.*`): Bitcoin node interaction

**Use Cases:**
- Building custom validators
- Integrating BNAP into existing Python applications
- Creating automated trading systems
- Developing asset management tools

### 2. Command Line Interface (CLI)

The BNAP CLI provides a complete command-line interface for all operations:

```bash
bnap asset create --name "MyToken" --symbol "MTK" --max-supply 1000000
bnap mint fungible --asset-id abc123 --amount 1000 --recipient bc1q...
bnap registry query --asset-type fungible
```

**Use Cases:**
- Manual asset management
- Scripting and automation
- Development and testing
- System administration

### 3. REST API (Planned)

A REST API for web-based integrations:

- **Asset Management**: Create and query assets
- **Minting Operations**: Execute mint transactions
- **Transaction Status**: Track confirmation status
- **Registry Queries**: Access asset state information

**Use Cases:**
- Web applications
- Mobile app backends
- Third-party integrations
- Microservice architectures

## Authentication & Security

### Validator Authentication

Most operations require validator authentication:

```python
from validator.core import ValidationEngine
from crypto.keys import PrivateKey

# Load validator private key
validator_key = PrivateKey.from_hex("your_private_key_hex")

# Initialize validation engine
validator = ValidationEngine({
    "validator_id": "your_validator_id",
    "signing_keys": {
        "primary": validator_key
    }
})
```

### API Key Management

For REST API access (when implemented):

```http
Authorization: Bearer your_api_key_here
X-Validator-ID: your_validator_id
```

## Response Formats

### Success Response

```json
{
  "status": "success",
  "data": {
    "transaction_id": "abc123...",
    "asset_id": "def456...",
    "amount": 1000
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response

```json
{
  "status": "error",
  "error_code": "SUPPLY_EXCEEDED",
  "message": "Mint amount would exceed maximum supply",
  "details": {
    "requested_amount": 15000,
    "available_supply": 10000
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Rate Limits

| API Type | Rate Limit | Burst Limit |
|----------|------------|-------------|
| CLI | No limit | N/A |
| Python API | No limit | N/A |
| REST API | 100 req/min | 20 req/sec |

## Error Codes

### Common Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_ASSET_ID` | Asset not found | 404 |
| `SUPPLY_EXCEEDED` | Exceeds maximum supply | 400 |
| `MINT_LIMIT_EXCEEDED` | Exceeds per-mint limit | 400 |
| `ALLOWLIST_VIOLATION` | Address not allowlisted | 403 |
| `INSUFFICIENT_BALANCE` | Not enough Bitcoin for fees | 400 |
| `NETWORK_ERROR` | Bitcoin node connection failed | 503 |
| `VALIDATION_FAILED` | Transaction validation failed | 422 |

### Error Handling Best Practices

```python
from validator.core import ValidationEngine
from validator.exceptions import ValidationError, NetworkError

try:
    result = validator.validate_mint_transaction(psbt_hex)
    if result.has_errors():
        print(f"Validation failed: {result.validation_errors}")
    else:
        print("Transaction validated successfully")
        
except NetworkError as e:
    print(f"Network error: {e}")
    # Implement retry logic
    
except ValidationError as e:
    print(f"Validation error: {e}")
    # Handle validation failure
```

## API Versioning

BNAP uses semantic versioning for API compatibility:

- **Major Version** (v1, v2): Breaking changes
- **Minor Version** (v1.1, v1.2): New features, backward compatible
- **Patch Version** (v1.1.1, v1.1.2): Bug fixes

Current API version: **v1.0.0**

### Version Headers

```http
Accept: application/vnd.bnap.v1+json
API-Version: 1.0
```

## SDKs and Libraries

### Python SDK (Core)

The core Python implementation serves as the primary SDK:

```python
pip install bnap-core
```

### JavaScript/TypeScript SDK (Planned)

```bash
npm install @bnap/sdk
```

```typescript
import { BNAPClient } from '@bnap/sdk';

const client = new BNAPClient({
  apiKey: 'your_api_key',
  network: 'testnet'
});

const asset = await client.assets.create({
  name: 'MyToken',
  symbol: 'MTK',
  maxSupply: 1000000
});
```

## Integration Examples

### Web Application Integration

```javascript
// Frontend (React/Vue/Angular)
async function mintTokens(assetId, amount, recipient) {
  const response = await fetch('/api/v1/mint', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      asset_id: assetId,
      amount: amount,
      recipient: recipient
    })
  });
  
  return response.json();
}
```

### Python Application Integration

```python
# Backend service integration
from bnap.validator import ValidationEngine
from bnap.registry import RegistryManager

class AssetService:
    def __init__(self):
        self.validator = ValidationEngine()
        self.registry = RegistryManager()
    
    def mint_asset(self, asset_id: str, amount: int, recipient: str):
        # Validate mint request
        asset = self.registry.get_asset(asset_id)
        if not asset:
            raise ValueError("Asset not found")
        
        # Create and validate PSBT
        psbt = self.create_mint_psbt(asset_id, amount, recipient)
        result = self.validator.validate_mint_transaction(psbt)
        
        if result.has_errors():
            raise ValidationError(result.validation_errors)
        
        return result
```

### CLI Automation

```bash
#!/bin/bash
# Automated minting script

ASSET_ID="your_asset_id_here"
RECIPIENTS=("bc1q..." "bc1q..." "bc1q...")

for recipient in "${RECIPIENTS[@]}"; do
    echo "Minting to $recipient"
    bnap mint fungible \
        --asset-id "$ASSET_ID" \
        --amount 100 \
        --recipient "$recipient" \
        --wait-for-confirmation
    
    if [ $? -eq 0 ]; then
        echo "Successfully minted to $recipient"
    else
        echo "Failed to mint to $recipient"
    fi
done
```

## Development Tools

### Interactive API Explorer

Access the interactive API documentation at:
- Local: `http://localhost:8000/api/docs`
- Production: `https://docs.bnap.org/api/playground`

### Testing Tools

```python
# Unit testing with pytest
import pytest
from bnap.testing import MockValidator, TestAssets

def test_mint_fungible_token():
    validator = MockValidator()
    asset = TestAssets.create_fungible_token()
    
    result = validator.mint_asset(
        asset_id=asset.asset_id,
        amount=1000,
        recipient="bc1qtest..."
    )
    
    assert result.success
    assert result.amount == 1000
```

### Development Environment

```bash
# Set up development environment
git clone https://github.com/bnap/bnap.git
cd bnap
python -m venv venv
source venv/bin/activate
pip install -e .

# Start development services
bnap validator start --network regtest
bnap registry init --config dev-config.json
```

## Performance Considerations

### Throughput Limits

| Operation | Max TPS | Notes |
|-----------|---------|-------|
| Validation | 50 TPS | Single validator |
| PSBT Creation | 100 TPS | CPU bound |
| Registry Queries | 1000 QPS | I/O bound |
| Signature Generation | 100 TPS | Cryptographic operations |

### Optimization Tips

1. **Batch Operations**: Group multiple operations together
2. **Connection Pooling**: Reuse Bitcoin RPC connections
3. **Caching**: Cache frequently accessed registry data
4. **Async Processing**: Use async patterns for I/O operations

### Monitoring

```python
# Performance monitoring
from bnap.monitoring import MetricsCollector

metrics = MetricsCollector()

@metrics.time_operation
def mint_asset(asset_id, amount):
    # Your minting logic here
    pass

# View metrics
print(metrics.get_stats())
```

This API overview provides the foundation for understanding how to interact with BNAP programmatically. The following sections provide detailed documentation for each API interface.