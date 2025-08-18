"""
Bitcoin Native Asset Protocol - NFT Management System

This package provides comprehensive NFT functionality including metadata management,
content storage, collection handling, and content integrity verification.
"""

# Core NFT functionality
from .metadata import (
    NFTMetadata,
    NFTAttribute,
    MetadataSchema,
    MetadataValidator,
    CollectionMetadata
)

from .content import (
    ContentHasher,
    ContentStorage,
    ContentManager,
    MerkleTree,
    StorageType,
    LocalStorage,
    IPFSStorage,
    HTTPStorage,
    TaprootStorage
)

from .collections import (
    CollectionManifest,
    TokenTracker,
    CollectionManager,
    MintingRule
)

# Enhanced IPFS integration
try:
    from .ipfs import EnhancedIPFSStorage, IPFSConfig, IPFSCluster
    ENHANCED_IPFS_AVAILABLE = True
except ImportError:
    ENHANCED_IPFS_AVAILABLE = False

# HTTP Gateway and URI handling
try:
    from .gateway import (
        URIResolver,
        HTTPGatewayStorage,
        HTTPGatewayConfig,
        ContentCache,
        resolve_nft_content
    )
    GATEWAY_AVAILABLE = True
except ImportError:
    GATEWAY_AVAILABLE = False

__version__ = "1.0.0"

__all__ = [
    # Metadata components
    "NFTMetadata",
    "NFTAttribute", 
    "MetadataSchema",
    "MetadataValidator",
    "CollectionMetadata",
    
    # Content management
    "ContentHasher",
    "ContentStorage", 
    "ContentManager",
    "MerkleTree",
    "StorageType",
    "LocalStorage",
    "IPFSStorage", 
    "HTTPStorage",
    "TaprootStorage",
    
    # Collections
    "CollectionManifest",
    "TokenTracker",
    "CollectionManager", 
    "MintingRule"
]

# Add enhanced features if available
if ENHANCED_IPFS_AVAILABLE:
    __all__.extend(["EnhancedIPFSStorage", "IPFSConfig", "IPFSCluster"])

if GATEWAY_AVAILABLE:
    __all__.extend(["URIResolver", "HTTPGatewayStorage", "HTTPGatewayConfig", "ContentCache", "resolve_nft_content"])