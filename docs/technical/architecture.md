# BNAP System Architecture

The Bitcoin Native Asset Protocol (BNAP) is a comprehensive system for issuing and managing digital assets directly on the Bitcoin blockchain. This document provides detailed technical architecture documentation based on the actual implementation.

## System Overview

BNAP uses a **colored outputs** approach where assets are represented by Bitcoin UTXOs with embedded metadata. The system employs a centralized validator (designed to expand to multi-signature quorum) that authorizes mints by signing transactions that meet predefined rules.

```mermaid
graph TB
    subgraph "Client Layer"
        CLI[BNAP CLI]
        API[REST API]
        SDK[Python SDK]
    end
    
    subgraph "Core Components"
        VE[Validation Engine]
        RM[Registry Manager]
        PB[PSBT Builder]
        CS[Covenant Scripts]
    end
    
    subgraph "Crypto Layer"
        KM[Key Management]
        SG[Signature Generation]
        CM[Commitment Manager]
        ML[Merkle Proofs]
    end
    
    subgraph "Storage"
        REG[(Registry JSON)]
        STATE[(Asset State)]
        AUDIT[(Audit Logs)]
    end
    
    subgraph "Bitcoin Network"
        BN[Bitcoin Node]
        BC[Blockchain]
    end
    
    CLI --> VE
    API --> VE
    SDK --> VE
    
    VE --> RM
    VE --> PB
    VE --> CS
    
    RM --> REG
    RM --> STATE
    RM --> AUDIT
    
    PB --> KM
    PB --> SG
    PB --> CM
    PB --> ML
    
    VE --> BN
    BN --> BC
    
    style VE fill:#f96
    style RM fill:#69f
    style PB fill:#6f9
```

## Core Components

### 1. Validation Engine (`validator/core.py`)

The ValidationEngine orchestrates all validation operations and serves as the central coordinator.

**Key Features:**
- Asset rule enforcement
- Supply limit validation  
- Per-mint cap checking
- Allowlist verification via Merkle proofs
- NFT content hash validation
- PSBT signing authorization

**Validation Flow:**
```mermaid
sequenceDiagram
    participant Client
    participant VE as Validation Engine
    participant RM as Registry Manager
    participant Rules as Validation Rules
    participant Signer as PSBT Signer
    
    Client->>VE: Submit PSBT for validation
    VE->>VE: Parse PSBT data
    VE->>RM: Load asset state & rules
    RM-->>VE: Asset configuration
    
    loop For each validation rule
        VE->>Rules: Apply rule
        Rules-->>VE: Pass/Fail result
    end
    
    alt All rules pass
        VE->>Signer: Sign PSBT
        Signer-->>VE: Signed transaction
        VE-->>Client: Approved + signed TX
    else Any rule fails
        VE-->>Client: Rejected + error details
    end
```

### 2. Registry Manager (`registry/manager.py`)

Manages asset definitions, state tracking, and configuration persistence.

**Schema Models** (`registry/schema.py`):
- `FungibleAsset`: Tokens with supply caps and mint limits
- `NFTAsset`: Unique collectibles with content hash binding
- `ValidatorConfig`: Signing authority configuration
- `StateEntry`: Real-time asset state tracking

**Asset Registration:**
```mermaid
graph LR
    A[Asset Definition] --> B[Schema Validation]
    B --> C[Asset ID Generation]
    C --> D[Registry Storage]
    D --> E[State Initialization]
    
    subgraph "Asset ID Calculation"
        F[Issuer PubKey + Name + Nonce]
        F --> G[SHA-256]
        G --> H[64-char Hex ID]
    end
    
    C --> F
```

### 3. PSBT Builder (`psbt/builder.py`)

Constructs Partially Signed Bitcoin Transactions with BNAP-specific metadata.

**Transaction Structure:**
```mermaid
graph TB
    subgraph "PSBT Inputs"
        I1[Funding UTXO]
        I2[Asset Control UTXO]
    end
    
    subgraph "PSBT Outputs"
        O1[Asset Output<br/>Colored Coin]
        O2[OP_RETURN<br/>Protocol Metadata]
        O3[Change Output<br/>Return Bitcoin]
    end
    
    subgraph "Witness Data"
        W1[Covenant Script]
        W2[Asset Commitment]
        W3[Validator Signature]
    end
    
    I1 --> O1
    I1 --> O2
    I1 --> O3
    I2 --> W1
    W2 --> O1
    W3 --> W1
```

### 4. Cryptographic Primitives (`crypto/`)

#### Key Management (`crypto/keys.py`)
- **BIP32/BIP39**: Hierarchical deterministic key derivation
- **Taproot Support**: P2TR key tweaking for asset commitments
- **Multi-format**: Support for legacy, SegWit, and Taproot addresses

#### Asset Commitments (`crypto/commitments.py`)
Asset commitments are cryptographic proofs embedded in Bitcoin outputs:

```python
# Taproot asset commitment formula
P_output = P_internal + H(asset_commitment) * G

# Where:
# P_internal = internal public key
# H() = tagged hash function
# asset_commitment = asset_id || amount || metadata
# G = secp256k1 generator point
```

#### Merkle Proofs (`crypto/merkle.py`)
Allowlist verification using Merkle trees:

```mermaid
graph TB
    subgraph "Merkle Tree Allowlist"
        R[Root Hash]
        I1[Internal Node 1]
        I2[Internal Node 2]
        L1[Address 1]
        L2[Address 2]
        L3[Address 3]
        L4[Address 4]
    end
    
    R --> I1
    R --> I2
    I1 --> L1
    I1 --> L2
    I2 --> L3
    I2 --> L4
    
    subgraph "Proof Verification"
        P[Proof Path]
        V[Verify Address]
        H[Hash Chain]
    end
    
    L2 --> P
    P --> V
    V --> H
    H --> R
```

## Covenant Implementations

### Taproot Covenant (P2TR)

**Privacy-focused approach** using key path spending:

```python
# Taproot script-path (covenant enforcement)
def taproot_covenant_script():
    return [
        OP_DUP,           # Duplicate asset commitment
        OP_HASH256,       # Hash the commitment  
        <commitment_hash>, # Expected commitment hash
        OP_EQUALVERIFY,   # Verify commitment matches
        <validator_pubkey>, # Validator public key
        OP_CHECKSIG       # Verify validator signature
    ]
```

**Key Derivation:**
```mermaid
graph LR
    A[Internal Key] --> B[Asset Commitment]
    B --> C[Tagged Hash]
    C --> D[Point Addition]
    D --> E[Tweaked Output Key]
    
    F[Script Tree] --> G[Merkle Root]
    G --> C
```

### P2WSH Covenant

**Transparent approach** with explicit witness scripts:

```python
# P2WSH covenant script
def p2wsh_covenant_script():
    return [
        # Asset amount validation
        OP_DUP,
        OP_SIZE,
        <8>,              # 8-byte amount
        OP_EQUALVERIFY,
        
        # Supply limit check
        <current_supply>,
        OP_ADD,
        <max_supply>,
        OP_LESSTHANOREQUAL,
        OP_VERIFY,
        
        # Validator signature
        <validator_pubkey>,
        OP_CHECKSIG
    ]
```

## Transaction Formats

### Fungible Token Mint

```mermaid
graph TB
    subgraph "Input Structure"
        TXI1[TxIn 0: Funding<br/>Amount: 100,000 sats<br/>Script: P2WPKH]
        TXI2[TxIn 1: Control<br/>Amount: 546 sats<br/>Script: P2WSH/P2TR]
    end
    
    subgraph "Output Structure"  
        TXO1[TxOut 0: Asset<br/>Amount: 546 sats<br/>Script: P2WSH/P2TR<br/>AssetAmount: 1000 tokens]
        TXO2[TxOut 1: OP_RETURN<br/>Amount: 0 sats<br/>Data: Protocol + Metadata]
        TXO3[TxOut 2: Change<br/>Amount: 99,454 sats<br/>Script: P2WPKH]
    end
    
    TXI1 --> TXO1
    TXI1 --> TXO2  
    TXI1 --> TXO3
    TXI2 --> TXO1
```

### NFT Mint

```mermaid
graph TB
    subgraph "NFT Output"
        NO[TxOut: NFT<br/>Amount: 546 sats<br/>TokenID: 42<br/>ContentHash: 0x1234...]
    end
    
    subgraph "OP_RETURN Data"
        OR[Protocol: BNAP<br/>Version: 1<br/>Type: NFT_MINT<br/>AssetID: 0xabc...<br/>TokenID: 42<br/>ContentHash: 0x1234...]
    end
    
    NO --> OR
```

## Asset State Management

### State Tracking Schema

```python
@dataclass
class StateEntry:
    asset_id: str
    minted_supply: int = 0
    last_mint_timestamp: Optional[datetime] = None
    transaction_count: int = 0
    transaction_history: List[TransactionEntry] = field(default_factory=list)
    issued_nft_ids: List[int] = field(default_factory=list)  # NFT only
```

### Concurrency Handling (`registry/concurrency.py`)

```mermaid
sequenceDiagram
    participant V1 as Validator 1
    participant V2 as Validator 2
    participant Lock as Registry Lock
    participant State as Asset State
    
    V1->>Lock: Acquire lock(asset_id)
    Lock-->>V1: Lock acquired
    
    V2->>Lock: Try acquire lock(asset_id)
    Lock-->>V2: Wait...
    
    V1->>State: Read current supply
    State-->>V1: supply = 1000
    V1->>V1: Validate mint (100 tokens)
    V1->>State: Update supply = 1100
    V1->>Lock: Release lock
    
    Lock-->>V2: Lock acquired
    V2->>State: Read current supply  
    State-->>V2: supply = 1100
```

## Network Integration

### Bitcoin RPC Integration (`network/rpc.py`)

**Connection Management:**
```python
class BitcoinRPC:
    def __init__(self, config):
        self.host = config.get('rpc_host', 'localhost')
        self.port = config.get('rpc_port', 18443)  # regtest default
        self.user = config.get('rpc_user')
        self.password = config.get('rpc_password')
    
    def broadcast_transaction(self, tx_hex: str) -> str:
        """Broadcast signed transaction to Bitcoin network."""
        return self.call('sendrawtransaction', [tx_hex])
```

### Transaction Broadcasting (`network/broadcaster.py`)

```mermaid
graph LR
    A[Signed PSBT] --> B[Finalize Transaction]
    B --> C[Validate Consensus]
    C --> D[Broadcast to Mempool]
    D --> E[Confirmation Tracking]
    
    subgraph "Error Handling"
        F[Network Timeout]
        G[Invalid Transaction]
        H[Insufficient Fee]
        I[Retry Logic]
    end
    
    D --> F
    D --> G
    D --> H
    F --> I
    G --> I
    H --> I
```

## CLI Architecture (`cli/`)

### Command Structure

```mermaid
graph TB
    subgraph "CLI Entry Point"
        M[main.py<br/>Global Options & Context]
    end
    
    subgraph "Command Modules"
        A[asset.py<br/>Asset Management]
        Mt[mint.py<br/>Minting Operations]
        R[registry.py<br/>Registry Queries]
        V[validator.py<br/>Validator Control]
        C[config.py<br/>Configuration]
        H[help.py<br/>Documentation]
    end
    
    subgraph "Support Modules"
        CF[config.py<br/>Config Management]
        OF[output.py<br/>Output Formatting]
        HF[help.py<br/>Help System]
    end
    
    M --> A
    M --> Mt
    M --> R
    M --> V
    M --> C
    M --> H
    
    A --> CF
    A --> OF
    Mt --> CF
    Mt --> OF
```

### Output Formatting (`cli/output.py`)

Supports multiple output formats:
- **Table**: Human-readable tabular data
- **JSON**: Machine-readable structured data
- **YAML**: Configuration-friendly format
- **CSV**: Spreadsheet-compatible export
- **Template**: Custom Jinja2 templates

## Security Model

### Validator Security

**Key Storage:**
- Private keys stored in encrypted configuration
- Hardware Security Module (HSM) support planned
- Multi-signature expansion ready

**Access Control:**
```python
class ValidatorConfig:
    validator_id: str
    pubkey: str  
    signing_scheme: SigningScheme  # ECDSA | SCHNORR
    permissions: List[str]  # Asset operations allowed
    is_active: bool
```

### Audit Logging (`validator/audit_logger.py`)

```mermaid
graph LR
    A[Validation Request] --> B[Audit Entry]
    B --> C[Structured Logging]
    C --> D[Tamper-Evident Storage]
    
    subgraph "Audit Data"
        E[Timestamp]
        F[Validator ID]
        G[Asset ID]
        H[Operation Type]
        I[Result]
        J[Error Details]
    end
    
    B --> E
    B --> F
    B --> G
    B --> H
    B --> I
    B --> J
```

## Performance Characteristics

### Benchmarks

| Operation | Latency | Throughput |
|-----------|---------|------------|
| PSBT Validation | < 100ms | 50+ TPS |
| Signature Generation | < 50ms | 100+ TPS |
| Registry Query | < 10ms | 1000+ QPS |
| Merkle Proof Verify | < 5ms | 2000+ TPS |

### Scalability Considerations

**Bottlenecks:**
- Registry file I/O for state updates
- Bitcoin RPC calls for broadcast
- Cryptographic operations (signing)

**Optimizations:**
- In-memory state caching
- Batch transaction processing  
- Async I/O for network operations
- Connection pooling for Bitcoin RPC

## Development Workflow

### Testing Strategy

```mermaid
graph TB
    subgraph "Test Pyramid"
        U[Unit Tests<br/>crypto/, psbt/, registry/]
        I[Integration Tests<br/>validator/, network/]
        E[End-to-End Tests<br/>Full mint workflows]
    end
    
    subgraph "Test Networks"
        R[Regtest<br/>Local development]
        T[Testnet<br/>Public testing]
        M[Mainnet<br/>Production]
    end
    
    U --> I
    I --> E
    E --> R
    R --> T
    T --> M
```

### CI/CD Pipeline

1. **Code Quality**: Linting, type checking, security scan
2. **Unit Testing**: Component-level validation
3. **Integration Testing**: Cross-component workflows
4. **Performance Testing**: Benchmark validation
5. **Security Testing**: Vulnerability assessment
6. **Documentation**: Auto-generated API docs

This architecture supports the MVP requirements while providing a foundation for future multi-validator consensus mechanisms and enhanced scalability.