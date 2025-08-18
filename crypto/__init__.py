"""
Bitcoin Native Asset Protocol - Cryptographic Operations Module

This module provides cryptographic utilities for BNAP including:
- Taproot key tweaking and asset commitments
- ECDSA and Schnorr signature operations  
- BIP32/BIP39 key derivation
- MuSig2 multi-signature support
- Secure key storage and management

Dependencies:
- coincurve: Fast secp256k1 operations
- hashlib: Cryptographic hash functions
- hmac: HMAC operations for key derivation
- secrets: Secure random number generation
"""

from .exceptions import (
    CryptoError,
    InvalidKeyError,
    InvalidSignatureError,
    DerivationError,
    CommitmentError,
)

# Import main classes and functions when available
try:
    from .keys import (
        PrivateKey,
        PublicKey,
        derive_key_from_path,
        generate_mnemonic,
        mnemonic_to_seed,
    )
except ImportError:
    # Module not yet implemented
    pass

try:
    from .commitments import (
        AssetCommitment,
        generate_asset_commitment,
        commit_to_asset,
    )
except ImportError:
    # Module not yet implemented  
    pass

try:
    from .signatures import (
        ECDSASignature,
        SchnorrSignature,
        sign_ecdsa,
        sign_schnorr,
        verify_ecdsa,
        verify_schnorr,
    )
except ImportError:
    # Module not yet implemented
    pass

try:
    from .musig2 import (
        MuSig2Nonce,
        MuSig2Session,
        generate_nonce_pair,
        aggregate_partial_signatures,
    )
except ImportError:
    # Module not yet implemented
    pass

try:
    from .storage import (
        SecureKeyStorage,
        KeyDerivationPath,
        encrypt_private_key,
        decrypt_private_key,
    )
except ImportError:
    # Module not yet implemented
    pass

__version__ = "0.1.0"
__all__ = [
    # Exceptions
    "CryptoError",
    "InvalidKeyError", 
    "InvalidSignatureError",
    "DerivationError",
    "CommitmentError",
    
    # Keys (when available)
    "PrivateKey",
    "PublicKey",
    "derive_key_from_path",
    "generate_mnemonic",
    "mnemonic_to_seed",
    
    # Commitments (when available)
    "AssetCommitment",
    "generate_asset_commitment",
    "commit_to_asset",
    
    # Signatures (when available)  
    "ECDSASignature",
    "SchnorrSignature",
    "sign_ecdsa",
    "sign_schnorr",
    "verify_ecdsa", 
    "verify_schnorr",
    
    # MuSig2 (when available)
    "MuSig2Nonce",
    "MuSig2Session", 
    "generate_nonce_pair",
    "aggregate_partial_signatures",
    
    # Storage (when available)
    "SecureKeyStorage",
    "KeyDerivationPath",
    "encrypt_private_key",
    "decrypt_private_key",
]