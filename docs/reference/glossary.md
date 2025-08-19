# BNAP Glossary

Comprehensive definitions of terms, concepts, and technical terminology used in the Bitcoin Native Asset Protocol (BNAP) system.

## A

**Allowlist**  
A cryptographically-secured list of Bitcoin addresses authorized to receive specific assets. BNAP uses Merkle trees to implement efficient allowlist verification without revealing the complete list on-chain.

**Asset Commitment**  
A cryptographic commitment that binds asset information (ID, amount, operation type) into a hash used for Taproot key tweaking or P2WSH script construction.

**Asset ID**  
A unique 64-character hexadecimal identifier for each BNAP asset, derived from the asset creation transaction and validator signature.

**Asset Registry**  
A database that tracks all BNAP assets, their current state, transaction history, and configuration parameters. Maintained by validators.

**Audit Logging**  
Comprehensive logging of all validator operations, asset state changes, and transactions for compliance and security monitoring.

## B

**Base58**  
An encoding scheme used in Bitcoin for representing addresses and other data in a human-readable format, avoiding visually ambiguous characters.

**bech32**  
A Bitcoin address format introduced with SegWit, using only lowercase letters and numbers. BNAP primarily uses bech32 addresses for compatibility.

**Bitcoin Core**  
The reference implementation of Bitcoin protocol software. BNAP requires Bitcoin Core 24.0+ for Taproot support.

**Bitcoin Script**  
The programming language used by Bitcoin to define spending conditions. BNAP uses Bitcoin Script for covenant enforcement.

**Block Height**  
The sequential number of a block in the Bitcoin blockchain. Used by BNAP for timestamp verification and state tracking.

**BNAP (Bitcoin Native Asset Protocol)**  
The complete protocol for creating, minting, and managing assets directly on the Bitcoin blockchain without requiring sidechains or Layer 2 solutions.

## C

**Colored Coins**  
The fundamental approach used by BNAP where Bitcoin UTXOs are "colored" with asset information through metadata and covenant scripts.

**Commitment Transaction**  
A Bitcoin transaction that commits to specific asset operations through embedded metadata and cryptographic proofs.

**Covenant**  
A Bitcoin script that enforces specific spending conditions, ensuring assets can only be transferred according to BNAP rules.

**Content Hash**  
A SHA-256 hash of NFT content (images, metadata, etc.) that provides cryptographic verification of content integrity and immutability.

## D

**Decimal Places**  
The number of decimal subdivisions supported by a fungible asset. For example, 2 decimal places allows amounts like 10.25 tokens.

**Deterministic Wallet**  
A wallet that generates all keys from a single seed, allowing backup and recovery of all addresses and private keys.

**Double Spending**  
The act of spending the same Bitcoin output twice. BNAP prevents asset double-spending through Bitcoin's native UTXO model.

## E

**ECDSA (Elliptic Curve Digital Signature Algorithm)**  
A digital signature algorithm used in Bitcoin for transaction authorization. BNAP supports both ECDSA and Schnorr signatures.

**Entropy**  
Random data used for generating cryptographic keys. Higher entropy increases security against brute-force attacks.

## F

**Fee Rate**  
The Bitcoin transaction fee expressed in satoshis per virtual byte (sat/vB). BNAP transactions require Bitcoin fees for blockchain inclusion.

**Fungible Asset**  
An asset type where individual units are interchangeable and identical. Examples include tokens, currencies, and utility assets.

**FQDN (Fully Qualified Domain Name)**  
A complete domain name that specifies an exact location in the DNS hierarchy, used for validator identification.

## G

**Genesis Block**  
The first block in a blockchain. In BNAP context, refers to the first transaction creating an asset.

**Genesis NFT**  
The first NFT minted in a collection, often with special properties or significance.

## H

**Hash Function**  
A mathematical function that converts input data into a fixed-size string. BNAP uses SHA-256 for content verification and Merkle trees.

**HD Keys (Hierarchical Deterministic Keys)**  
A key derivation system that generates child keys from parent keys in a tree structure, enabling organized key management.

**HSM (Hardware Security Module)**  
Specialized hardware for secure key storage and cryptographic operations. BNAP supports HSM integration for validator keys.

**HTLC (Hash Time Locked Contract)**  
A conditional payment mechanism using hash locks and time locks, potentially useful for BNAP escrow scenarios.

## I

**IPFS (InterPlanetary File System)**  
A distributed storage system commonly used for storing NFT metadata and images. BNAP supports IPFS URIs for content references.

**Issuer**  
The entity or validator responsible for creating and managing an asset. Identified by their public key in BNAP.

## J

**JSON (JavaScript Object Notation)**  
A data interchange format used for BNAP configuration files, metadata, and API responses.

**JSON-RPC**  
The protocol used for communicating with Bitcoin Core nodes. BNAP validators use JSON-RPC for blockchain interaction.

## K

**Key Derivation**  
The process of generating cryptographic keys from seed material or parent keys. BNAP uses BIP32 for hierarchical key derivation.

**Key Pair**  
A matched pair of cryptographic keys: a private key (kept secret) and a public key (shared publicly) used for digital signatures.

## L

**Leaf Node**  
The bottom level of a Merkle tree containing the actual data (e.g., addresses in an allowlist).

**Lightning Network**  
A Layer 2 payment protocol for Bitcoin. BNAP assets could potentially be transferred over Lightning in future implementations.

**Locktime**  
A Bitcoin transaction field that prevents the transaction from being mined until a specific block height or timestamp.

## M

**Mainnet**  
The primary Bitcoin network where real-value transactions occur. Opposite of testnet or regtest.

**Merkle Proof**  
A cryptographic proof that demonstrates inclusion of specific data in a Merkle tree without revealing the entire tree.

**Merkle Root**  
The top hash of a Merkle tree that represents the entire tree's contents. Used in BNAP for efficient allowlist verification.

**Merkle Tree**  
A binary tree structure where each leaf contains data and each non-leaf node contains a hash of its children. Enables efficient verification.

**Metadata**  
Additional information about an asset, such as name, description, images, and attributes. Stored off-chain with content hash verification.

**Mint**  
The process of creating new asset units (tokens or NFTs) according to the asset's rules and supply limits.

**Multisig (Multi-signature)**  
A Bitcoin address type requiring multiple signatures for spending. Future BNAP versions may support multisig validators.

## N

**NFT (Non-Fungible Token)**  
A unique digital asset where each token has distinct properties and cannot be exchanged on a one-to-one basis with other tokens.

**Node**  
A computer running Bitcoin software that maintains a copy of the blockchain. BNAP validators require access to a Bitcoin node.

**Nonce**  
A number used once in cryptographic operations to ensure uniqueness and prevent replay attacks.

## O

**OP_RETURN**  
A Bitcoin script opcode that allows embedding arbitrary data in transactions. BNAP uses OP_RETURN for asset metadata.

**Orphan Transaction**  
A transaction that references outputs not yet confirmed in the blockchain. BNAP validators must handle orphan scenarios.

**Output**  
In Bitcoin, an output defines where coins are sent and under what conditions they can be spent. BNAP assets are represented as colored outputs.

## P

**P2PKH (Pay to Public Key Hash)**  
A standard Bitcoin address type that pays to a hash of a public key. Less common in modern BNAP usage.

**P2SH (Pay to Script Hash)**  
A Bitcoin address type that pays to a script hash, enabling complex spending conditions.

**P2TR (Pay to Taproot)**  
The most recent Bitcoin address format supporting advanced scripting and privacy. BNAP's preferred format for new assets.

**P2WSH (Pay to Witness Script Hash)**  
A SegWit script format that enables complex spending conditions with improved efficiency. Used by BNAP for explicit covenants.

**Per-Mint Limit**  
The maximum amount of a fungible asset that can be minted in a single transaction, enforced by validator rules.

**Private Key**  
A secret number that allows spending of Bitcoin and signing of BNAP transactions. Must be kept secure.

**Proof of Work**  
Bitcoin's consensus mechanism requiring computational work to create blocks. BNAP inherits this security model.

**PSBT (Partially Signed Bitcoin Transaction)**  
A Bitcoin standard for constructing transactions that require multiple parties or steps. BNAP uses PSBTs for validation workflows.

**Public Key**  
The public component of a key pair, derived from the private key. Used for address generation and signature verification.

## Q

**QR Code**  
A two-dimensional barcode commonly used for encoding Bitcoin addresses and payment information.

## R

**RBF (Replace-by-Fee)**  
A Bitcoin feature allowing transaction replacement with higher fees. BNAP supports RBF for fee bumping.

**Regtest (Regression Test Mode)**  
A Bitcoin testing mode where blocks can be generated on demand. Useful for BNAP development and testing.

**Registry**  
See "Asset Registry"

**Reorg (Reorganization)**  
A blockchain event where a previously confirmed block is replaced by a different valid block, potentially affecting BNAP asset state.

**RPC (Remote Procedure Call)**  
The interface used to communicate with Bitcoin Core. BNAP validators use RPC for blockchain operations.

## S

**Satoshi**  
The smallest unit of Bitcoin (0.00000001 BTC). Bitcoin transaction fees are measured in satoshis.

**Schnorr Signature**  
An advanced digital signature scheme supported by Taproot, offering improved efficiency and privacy. BNAP's preferred signature type.

**Script**  
See "Bitcoin Script"

**ScriptSig**  
The signature script in a Bitcoin transaction that provides data to satisfy a locking script.

**Seed Phrase**  
A human-readable backup of a wallet's master key, typically 12 or 24 words following BIP39 standards.

**SegWit (Segregated Witness)**  
A Bitcoin protocol upgrade that increases transaction capacity and enables new features like Taproot.

**Supply Cap**  
The maximum total amount of a fungible asset that can ever be minted, set at asset creation time.

## T

**Taproot**  
Bitcoin's most recent major upgrade enabling advanced scripting, improved privacy, and signature aggregation. Core to BNAP's design.

**Tapscript**  
The scripting language used within Taproot, enabling more complex smart contracts while maintaining efficiency.

**Testnet**  
A parallel Bitcoin network used for testing purposes where coins have no real value. Ideal for BNAP development.

**Transaction ID (TXID)**  
A unique identifier for each Bitcoin transaction, calculated as the hash of the transaction data.

**Transfer**  
The process of moving asset ownership from one address to another while maintaining asset integrity and rules.

## U

**UTXO (Unspent Transaction Output)**  
Bitcoin's fundamental unit representing spendable coins. BNAP assets are implemented as colored UTXOs.

**URI (Uniform Resource Identifier)**  
A string identifying a resource location, used in BNAP for referencing off-chain content like IPFS links.

## V

**Validator**  
An entity responsible for verifying and authorizing BNAP asset operations according to predefined rules.

**Validation Rules**  
The set of conditions that must be met for an asset operation to be considered valid (supply limits, allowlists, etc.).

**Vanity Address**  
A Bitcoin address with a custom prefix or pattern, sometimes used for branding purposes.

**Virtual Size (vsize)**  
A measure of Bitcoin transaction size that accounts for SegWit's weight discount, used for fee calculation.

## W

**Wallet**  
Software or hardware that manages Bitcoin private keys and addresses. BNAP assets appear in compatible wallets.

**Watch-only Wallet**  
A wallet that monitors addresses without storing private keys, useful for tracking BNAP asset balances.

**Witness**  
The signature and script data in SegWit transactions, stored separately from the main transaction data.

**WIF (Wallet Import Format)**  
A format for encoding private keys for easy backup and import between Bitcoin wallets.

## X

**xpub (Extended Public Key)**  
A public key that can generate child public keys in HD wallets, useful for receiving BNAP assets without exposing spending keys.

## Z

**Zero-Confirmation**  
Transactions that have been broadcast but not yet included in a block. BNAP typically requires confirmations for security.

**ZMQ (ZeroMQ)**  
A messaging protocol used by Bitcoin Core for real-time transaction and block notifications. BNAP validators can use ZMQ for monitoring.

---

## Common Abbreviations

| Term | Full Form |
|------|-----------|
| BIP | Bitcoin Improvement Proposal |
| BTC | Bitcoin |
| CLI | Command Line Interface |
| CSV | Comma-Separated Values |
| JSON | JavaScript Object Notation |
| MIME | Multipurpose Internet Mail Extensions |
| REST | Representational State Transfer |
| SDK | Software Development Kit |
| SQL | Structured Query Language |
| SSL | Secure Sockets Layer |
| TLS | Transport Layer Security |
| URL | Uniform Resource Locator |
| UUID | Universally Unique Identifier |
| XML | Extensible Markup Language |
| YAML | YAML Ain't Markup Language |

---

## Units and Measurements

**Bitcoin Units:**
- 1 BTC = 100,000,000 satoshis
- 1 mBTC (milli-bitcoin) = 100,000 satoshis
- 1 μBTC (micro-bitcoin) = 100 satoshis

**Time Units:**
- Block time: ~10 minutes average
- Difficulty adjustment: Every 2016 blocks (~2 weeks)

**Fee Units:**
- sat/vB: Satoshis per virtual byte
- BTC/kB: Bitcoin per kilobyte (legacy)

**Size Units:**
- vB: Virtual bytes (SegWit-adjusted)
- WU: Weight units (1 vB = 4 WU)

This glossary provides essential terminology for understanding and working with BNAP. For technical implementation details, refer to the API documentation and technical specifications.