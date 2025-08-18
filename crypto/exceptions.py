"""
Cryptographic Exceptions for BNAP

This module defines custom exceptions for cryptographic operations.
"""


class CryptoError(Exception):
    """Base exception for all cryptographic errors."""
    pass


class InvalidKeyError(CryptoError):
    """Raised when a key is invalid or malformed."""
    pass


class InvalidSignatureError(CryptoError):
    """Raised when a signature is invalid or verification fails."""
    pass


class DerivationError(CryptoError):
    """Raised when key derivation fails."""
    pass


class CommitmentError(CryptoError):
    """Raised when asset commitment operations fail."""
    pass


class NonceGenerationError(CryptoError):
    """Raised when nonce generation fails."""
    pass


class MuSig2Error(CryptoError):
    """Raised when MuSig2 operations fail."""
    pass


class KeyStorageError(CryptoError):
    """Raised when key storage operations fail."""
    pass