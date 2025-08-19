# Frequently Asked Questions (FAQ)

Common questions and answers about the Bitcoin Native Asset Protocol (BNAP) covering technical, operational, and integration topics.

## General Questions

### What is BNAP?

**Q: What is the Bitcoin Native Asset Protocol (BNAP)?**

A: BNAP is a protocol for creating, minting, and managing digital assets directly on the Bitcoin blockchain without requiring sidechains or Layer 2 solutions. It uses Bitcoin's native features like Taproot and PSBT to implement colored coins with cryptographic validation.

**Q: How is BNAP different from other asset protocols?**

A: BNAP is unique because it:
- Runs entirely on Bitcoin mainnet without sidechains
- Uses Taproot for privacy and efficiency
- Implements Merkle tree allowlists for scalable access control
- Supports both fungible tokens and NFTs
- Maintains full Bitcoin security guarantees
- Requires no token bridges or wrapped assets

**Q: Is BNAP production-ready?**

A: BNAP is currently in active development. The core protocol is functional on testnet with comprehensive testing. Production deployment should wait for:
- Security audit completion
- Extensive real-world testing
- Community consensus on protocol standards
- Wallet ecosystem integration

### Asset Types

**Q: What types of assets can I create with BNAP?**

A: BNAP supports two primary asset types:

1. **Fungible Tokens**: Interchangeable units like currencies, utility tokens, or reward points
2. **NFTs (Non-Fungible Tokens)**: Unique digital assets like art, collectibles, or certificates

Each type has specific features:
- Fungible: Supply caps, per-mint limits, decimal places, allowlists
- NFT: Collection size, content hash binding, metadata, royalties

**Q: Can I create stablecoins with BNAP?**

A: BNAP provides the technical infrastructure for fungible tokens, but creating a stablecoin requires additional mechanisms:
- Price stability mechanism (algorithmic, collateralized, etc.)
- Oracle integration for price feeds
- Reserve management
- Regulatory compliance

BNAP handles the asset layer; stability mechanisms are implementation-specific.

**Q: What's the maximum supply I can set for an asset?**

A: BNAP supports very large supply caps:
- Maximum supply: 2^53 - 1 (approximately 9 quadrillion units)
- With 18 decimal places: effectively unlimited for practical purposes
- Per-mint limits can be set independently of total supply

## Technical Questions

### Bitcoin Integration

**Q: Which Bitcoin features does BNAP require?**

A: BNAP requires:
- **Bitcoin Core 24.0+** for Taproot support
- **Taproot activation** (activated on mainnet November 2021)
- **PSBT support** for transaction construction
- **SegWit** for transaction efficiency
- **RPC access** for validator operations

**Q: Does BNAP require a soft fork or Bitcoin protocol changes?**

A: No. BNAP uses existing Bitcoin features without requiring any protocol modifications:
- Taproot for smart contracts
- OP_RETURN for metadata
- Standard Bitcoin transactions
- Existing signature schemes (ECDSA, Schnorr)

**Q: How does BNAP handle Bitcoin network fees?**

A: BNAP transactions are regular Bitcoin transactions requiring standard fees:
- Fee rates determined by network congestion
- Larger transactions (batch mints) cost more
- Fee estimation integrated into CLI tools
- Support for Replace-by-Fee (RBF) fee bumping

### Security

**Q: How secure are BNAP assets?**

A: BNAP assets inherit Bitcoin's security model:
- **Proof of Work**: Protected by Bitcoin's massive hash rate
- **Cryptographic validation**: All operations cryptographically verified
- **No new attack vectors**: Uses only proven Bitcoin primitives
- **Validator security**: Private key management is critical
- **Open source**: Code is auditable and transparent

**Q: What happens if a validator is compromised?**

A: Validator compromise impacts:
- **Asset creation**: Attackers could create unauthorized assets
- **Minting**: Could violate supply limits or allowlist rules
- **No fund theft**: Cannot steal existing assets or Bitcoin
- **Recovery**: New validator can be established with community consensus

Mitigation strategies:
- Use HSMs for key storage
- Implement multisig validators (future feature)
- Regular key rotation procedures
- Comprehensive monitoring and alerts

**Q: Can BNAP assets be double-spent?**

A: No. BNAP assets use Bitcoin's UTXO model, which prevents double-spending:
- Each asset unit exists as a specific UTXO
- Spending requires valid signatures
- Bitcoin network validates all transactions
- Consensus rules prevent conflicting spends

### Scalability

**Q: How many transactions can BNAP handle?**

A: BNAP throughput is limited by Bitcoin's capacity:
- **Bitcoin limit**: ~7 transactions per second
- **BNAP overhead**: Slightly larger transactions due to metadata
- **Batch operations**: Multiple assets can be minted in one transaction
- **Layer 2**: Future Lightning Network integration possible

**Q: How do allowlists scale to millions of addresses?**

A: BNAP uses Merkle trees for efficient allowlist scaling:
- **Proof size**: O(log n) - only ~20 hashes for 1 million addresses
- **Verification**: Fast cryptographic proof checking
- **Privacy**: Individual addresses not revealed until used
- **Storage**: Compact tree storage regardless of list size

## Operational Questions

### Installation and Setup

**Q: What are the minimum system requirements?**

A: For development:
- 2 CPU cores, 4 GB RAM, 50 GB storage
- Python 3.8+, Bitcoin Core 24.0+
- Linux, macOS, or Windows WSL2

For production:
- 4+ CPU cores, 8+ GB RAM, 1+ TB SSD
- Reliable network connection
- Proper security hardening

**Q: Can I run BNAP without running a full Bitcoin node?**

A: No, BNAP validators require direct Bitcoin node access for:
- Transaction validation and broadcasting
- Block monitoring and confirmations
- UTXO set verification
- Fee estimation

You can use:
- Local Bitcoin Core node (recommended)
- Trusted remote node (less secure)
- Bitcoin Core in pruned mode (saves disk space)

**Q: How long does initial setup take?**

A: Setup time depends on Bitcoin sync:
- **Regtest**: ~5 minutes (development)
- **Testnet**: 2-4 hours (30 GB download)
- **Mainnet**: 24-48 hours (500+ GB download)

BNAP installation itself takes 5-10 minutes once Bitcoin is synced.

### Asset Management

**Q: Can I modify an asset after creation?**

A: Asset rules are generally immutable for security, but some properties can be updated:

**Immutable**: Asset ID, maximum supply, symbol, fundamental rules
**Updatable**: Description, external URLs, royalty rates (with validator approval)

**Q: How do I backup my assets and data?**

A: Critical data to backup:
- **Validator private keys**: Secure, encrypted backup essential
- **Asset registry**: Contains all asset definitions and state
- **Configuration files**: System and network settings
- **Transaction history**: For audit and recovery purposes

Use BNAP's built-in backup tools with encryption.

**Q: What happens if I lose my validator keys?**

A: Lost validator keys result in:
- Cannot mint new assets
- Cannot create new assets
- Existing assets remain valid and transferable
- Registry becomes read-only

Prevention:
- Multiple secure backups
- Hardware security modules (HSMs)
- Key splitting/multisig (future feature)

### Trading and Transfers

**Q: How do I transfer BNAP assets to another address?**

A: Asset transfers work like Bitcoin transactions:
```bash
# Basic transfer
bnap transfer fungible \
    --asset-id "your_asset_id" \
    --amount 1000 \
    --recipient "bc1qrecipientaddress"

# NFT transfer
bnap transfer nft \
    --asset-id "nft_collection_id" \
    --nft-id 42 \
    --recipient "bc1qcollectoraddress"
```

**Q: Do BNAP assets appear in regular Bitcoin wallets?**

A: BNAP assets appear as Bitcoin UTXOs in standard wallets, but:
- **Standard wallets**: See only Bitcoin value, not asset information
- **BNAP-aware wallets**: Display asset type, amount, and metadata
- **Wallet integration**: Requires BNAP protocol support

**Q: Can I sell BNAP assets on exchanges?**

A: Currently, BNAP asset trading requires:
- BNAP-compatible exchanges (in development)
- P2P trading with BNAP-aware participants
- Custom marketplace implementations

Standard Bitcoin exchanges don't recognize BNAP assets yet.

## Integration Questions

### Development

**Q: How do I integrate BNAP into my application?**

A: BNAP provides multiple integration options:

1. **Python API**: Direct library integration
```python
from bnap.validator import ValidationEngine
from bnap.registry import RegistryManager

validator = ValidationEngine(config)
registry = RegistryManager()
```

2. **CLI Interface**: Command-line automation
```bash
bnap asset create-fungible --name "MyToken" --symbol "MTK"
```

3. **REST API**: HTTP/JSON interface (planned)
```javascript
fetch('/api/v1/assets', {
  method: 'POST',
  body: JSON.stringify({name: 'MyToken', symbol: 'MTK'})
})
```

**Q: What programming languages are supported?**

A: Current support:
- **Python**: Full native support with complete API
- **JavaScript/Node.js**: Planned SDK development
- **Command Line**: Universal shell integration
- **Other languages**: Can use CLI interface or REST API

**Q: How do I test my BNAP integration?**

A: Testing strategies:
1. **Regtest**: Local Bitcoin network for rapid testing
2. **Testnet**: Public test network with realistic conditions
3. **Mock validators**: Simulated environment for unit tests
4. **Integration tests**: End-to-end workflow validation

### Enterprise

**Q: Is BNAP suitable for enterprise use?**

A: BNAP offers enterprise-grade features:
- **Audit logging**: Comprehensive transaction tracking
- **Access controls**: Allowlist-based permissions
- **HSM support**: Hardware security module integration
- **High availability**: Multi-validator configurations
- **Compliance**: Regulatory-friendly audit trails

**Q: What about regulatory compliance?**

A: BNAP supports compliance through:
- **AML/KYC**: Allowlist integration with identity verification
- **Audit trails**: Complete transaction history
- **Asset controls**: Transfer restrictions and limits
- **Reporting**: Comprehensive analytics and reports

Specific compliance requirements depend on jurisdiction and use case.

**Q: Can BNAP integrate with existing enterprise systems?**

A: Yes, through multiple integration points:
- **API integration**: RESTful interfaces for existing applications
- **Database exports**: CSV/JSON data for accounting systems
- **Webhook notifications**: Real-time event integration
- **SSO integration**: Enterprise authentication systems

## Troubleshooting

### Common Issues

**Q: "Bitcoin RPC connection failed" error?**

A: Check these items:
1. Bitcoin Core is running: `pgrep bitcoind`
2. RPC settings in bitcoin.conf:
   ```ini
   server=1
   rpcuser=your_username
   rpcpassword=your_password
   rpcallowip=127.0.0.1
   ```
3. Network accessibility: `bitcoin-cli getblockchaininfo`
4. BNAP configuration matches Bitcoin settings

**Q: "Asset not found" when querying?**

A: Verify:
1. Asset ID is correct (64-character hex)
2. Registry file is accessible
3. Asset was successfully created
4. Network matches (mainnet vs testnet)

Use: `bnap registry query --format json` to list all assets

**Q: High transaction fees?**

A: Reduce fees by:
1. Using lower fee rates during low congestion
2. Batching multiple operations
3. Using SegWit/Taproot addresses
4. Implementing fee estimation logic

Monitor: https://mempool.space for current fee rates

**Q: Slow transaction confirmation?**

A: Confirmation speed depends on:
1. **Fee rate**: Higher fees = faster confirmation
2. **Network congestion**: Weekend/evening delays common
3. **Transaction size**: Larger transactions may need higher fees
4. **RBF**: Use Replace-by-Fee to bump stuck transactions

### Performance

**Q: How can I improve BNAP performance?**

A: Optimization strategies:
1. **Hardware**: SSD storage, sufficient RAM for Bitcoin node
2. **Configuration**: Adjust dbcache, maxconnections in bitcoin.conf
3. **Batching**: Group operations to reduce transaction overhead
4. **Caching**: Enable asset registry caching
5. **Monitoring**: Use metrics to identify bottlenecks

**Q: What's the maximum batch size for operations?**

A: Batch limits depend on:
- **Bitcoin transaction size**: ~100KB practical limit
- **Fee constraints**: Larger batches = higher fees
- **BNAP recommended**: 25-50 operations per batch
- **Custom limits**: Configure based on use case

## Future Development

**Q: What features are planned for future releases?**

A: Roadmap includes:
- **Multi-signature validators**: Distributed validation
- **Lightning Network integration**: Layer 2 transfers
- **Advanced smart contracts**: More complex asset rules
- **Cross-chain bridges**: Integration with other networks
- **Enhanced privacy**: Additional privacy features
- **Wallet ecosystem**: Broader wallet support

**Q: How can I contribute to BNAP development?**

A: Contribution opportunities:
- **Code contributions**: Submit PRs on GitHub
- **Testing**: Report bugs and test new features
- **Documentation**: Improve guides and examples
- **Integration**: Build wallets and applications
- **Community**: Help answer questions and support users

**Q: Is there a bug bounty program?**

A: Bug bounty details:
- **Security vulnerabilities**: Contact security@bnap.org
- **Critical bugs**: Eligible for rewards
- **Coordinated disclosure**: Required for security issues
- **Recognition**: Contributors credited in releases

## Getting Help

**Q: Where can I get support?**

A: Support channels:
- **Documentation**: https://docs.bnap.org (this site)
- **GitHub Issues**: https://github.com/bnap/bnap/issues
- **Community Discord**: https://discord.gg/bnap
- **Email Support**: support@bnap.org
- **Stack Overflow**: Use tag `bnap`

**Q: How do I report a bug?**

A: Include this information:
1. **BNAP version**: `bnap --version`
2. **Operating system**: Linux/macOS/Windows version
3. **Bitcoin Core version**: `bitcoin-cli --version`
4. **Network**: mainnet/testnet/regtest
5. **Error message**: Complete error output
6. **Steps to reproduce**: Detailed reproduction steps
7. **Configuration**: Relevant config (remove secrets)

**Q: Is there professional support available?**

A: Professional support options:
- **Enterprise support**: Available for production deployments
- **Custom development**: Integration and customization services
- **Training and consulting**: Team training and best practices
- **SLA agreements**: Guaranteed response times

Contact: enterprise@bnap.org for details.

---

*This FAQ is regularly updated. For the latest information, check the documentation website or join our community channels.*