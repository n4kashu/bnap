"""
Bitcoin Native Asset Protocol - NFT Management System

This package provides comprehensive NFT functionality including metadata management,
content storage, collection handling, and content integrity verification.
"""

from .metadata import (
    NFTMetadata,
    NFTAttribute,
    MetadataSchema,
    MetadataValidator,
    CollectionMetadata
)

__version__ = "1.0.0"

__all__ = [
    # Metadata components
    "NFTMetadata",
    "NFTAttribute", 
    "MetadataSchema",
    "MetadataValidator",
    "CollectionMetadata"
]