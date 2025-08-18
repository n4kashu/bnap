"""
Bitcoin Native Asset Protocol - PSBT Exceptions

This module defines custom exceptions for PSBT construction and parsing operations.
"""


class PSBTError(Exception):
    """Base exception for PSBT-related errors."""
    pass


class PSBTConstructionError(PSBTError):
    """Exception raised during PSBT construction."""
    pass


class PSBTParsingError(PSBTError):
    """Exception raised during PSBT parsing."""
    pass


class PSBTValidationError(PSBTError):
    """Exception raised when PSBT validation fails."""
    pass


class InvalidScriptError(PSBTError):
    """Exception raised for invalid script operations."""
    pass


class InsufficientFundsError(PSBTError):
    """Exception raised when transaction inputs are insufficient to cover outputs and fees."""
    
    def __init__(self, required: int, available: int, message: str = None):
        self.required = required
        self.available = available
        if message is None:
            message = f"Insufficient funds: required {required} satoshis, available {available} satoshis"
        super().__init__(message)


class UnsupportedScriptTypeError(PSBTError):
    """Exception raised for unsupported script types."""
    pass


class ProprietaryFieldError(PSBTError):
    """Exception raised for proprietary field handling errors."""
    pass


class AssetMetadataError(PSBTError):
    """Exception raised for asset metadata related errors."""
    pass


class MetadataError(PSBTError):
    """Exception raised for metadata encoding/decoding errors."""
    pass


class PSBTBuildError(PSBTError):
    """Exception raised during PSBT building operations."""
    pass


class InsufficientFundsError(PSBTError):
    """Exception raised when insufficient funds for transfer."""
    def __init__(self, message: str = "Insufficient funds"):
        super().__init__(message)