"""
Bitcoin Native Asset Protocol - NFT Content Management

This module provides comprehensive content management for NFTs including content hashing,
storage abstraction, and content integrity verification.
"""

import hashlib
import mimetypes
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, BinaryIO
from urllib.parse import urlparse

try:
    import ipfshttpclient
    IPFS_AVAILABLE = True
except ImportError:
    ipfshttpclient = None
    IPFS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False


class StorageType(str, Enum):
    """Content storage types."""
    LOCAL = "local"
    IPFS = "ipfs"
    HTTP = "http"
    TAPROOT = "taproot"
    ARWEAVE = "arweave"


class HashAlgorithm(str, Enum):
    """Supported hash algorithms."""
    SHA256 = "sha256"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"
    MD5 = "md5"  # For compatibility only


@dataclass
class ContentHash:
    """Represents a content hash with metadata."""
    
    hash_value: str
    algorithm: HashAlgorithm = HashAlgorithm.SHA256
    content_type: Optional[str] = None
    content_size: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self):
        """Validate hash format."""
        expected_lengths = {
            HashAlgorithm.SHA256: 64,
            HashAlgorithm.SHA512: 128,
            HashAlgorithm.BLAKE2B: 128,
            HashAlgorithm.MD5: 32
        }
        
        expected_length = expected_lengths.get(self.algorithm)
        if expected_length and len(self.hash_value) != expected_length:
            raise ValueError(f"{self.algorithm} hash must be {expected_length} characters, got {len(self.hash_value)}")
        
        # Validate hex format
        try:
            int(self.hash_value, 16)
        except ValueError:
            raise ValueError(f"Hash value must be hexadecimal: {self.hash_value}")
    
    def to_dict(self) -> Dict[str, any]:
        """Convert to dictionary format."""
        return {
            "hash": self.hash_value,
            "algorithm": self.algorithm.value,
            "content_type": self.content_type,
            "content_size": self.content_size,
            "created_at": self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, any]) -> 'ContentHash':
        """Create from dictionary."""
        created_at = datetime.now(timezone.utc)
        if 'created_at' in data:
            try:
                created_at = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        
        return cls(
            hash_value=data['hash'],
            algorithm=HashAlgorithm(data.get('algorithm', 'sha256')),
            content_type=data.get('content_type'),
            content_size=data.get('content_size'),
            created_at=created_at
        )


@dataclass 
class ContentInfo:
    """Comprehensive content information."""
    
    content_hash: ContentHash
    uri: str
    storage_type: StorageType
    content_type: str
    content_size: int
    filename: Optional[str] = None
    metadata: Dict[str, any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, any]:
        """Convert to dictionary format."""
        return {
            "content_hash": self.content_hash.to_dict(),
            "uri": self.uri,
            "storage_type": self.storage_type.value,
            "content_type": self.content_type,
            "content_size": self.content_size,
            "filename": self.filename,
            "metadata": self.metadata
        }


class ContentHasher:
    """Generates and verifies content hashes."""
    
    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.algorithm = algorithm
        self._hash_functions = {
            HashAlgorithm.SHA256: hashlib.sha256,
            HashAlgorithm.SHA512: hashlib.sha512,
            HashAlgorithm.BLAKE2B: hashlib.blake2b,
            HashAlgorithm.MD5: hashlib.md5
        }
    
    def hash_content(self, content: Union[bytes, BinaryIO], 
                    content_type: Optional[str] = None) -> ContentHash:
        """
        Generate hash for content.
        
        Args:
            content: Content to hash (bytes or file-like object)
            content_type: MIME type of content
            
        Returns:
            ContentHash object
        """
        hash_func = self._hash_functions[self.algorithm]()
        content_size = 0
        
        if isinstance(content, bytes):
            hash_func.update(content)
            content_size = len(content)
        else:
            # File-like object
            while True:
                chunk = content.read(8192)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode('utf-8')
                hash_func.update(chunk)
                content_size += len(chunk)
        
        return ContentHash(
            hash_value=hash_func.hexdigest(),
            algorithm=self.algorithm,
            content_type=content_type,
            content_size=content_size
        )
    
    def hash_file(self, file_path: Union[str, Path]) -> ContentHash:
        """
        Generate hash for file.
        
        Args:
            file_path: Path to file
            
        Returns:
            ContentHash object
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Detect content type
        content_type, _ = mimetypes.guess_type(str(file_path))
        
        with open(file_path, 'rb') as f:
            return self.hash_content(f, content_type)
    
    def verify_content(self, content: Union[bytes, BinaryIO], 
                      expected_hash: Union[str, ContentHash]) -> bool:
        """
        Verify content against expected hash.
        
        Args:
            content: Content to verify
            expected_hash: Expected hash value or ContentHash object
            
        Returns:
            True if content matches hash
        """
        if isinstance(expected_hash, str):
            expected_hash = ContentHash(hash_value=expected_hash, algorithm=self.algorithm)
        
        calculated_hash = self.hash_content(content)
        return calculated_hash.hash_value == expected_hash.hash_value
    
    def verify_file(self, file_path: Union[str, Path], 
                   expected_hash: Union[str, ContentHash]) -> bool:
        """
        Verify file against expected hash.
        
        Args:
            file_path: Path to file
            expected_hash: Expected hash value or ContentHash object
            
        Returns:
            True if file matches hash
        """
        if isinstance(expected_hash, str):
            expected_hash = ContentHash(hash_value=expected_hash, algorithm=self.algorithm)
        
        calculated_hash = self.hash_file(file_path)
        return calculated_hash.hash_value == expected_hash.hash_value


class MerkleTree:
    """Merkle tree for multi-file content integrity."""
    
    def __init__(self, hasher: Optional[ContentHasher] = None):
        self.hasher = hasher or ContentHasher()
        self.leaves: List[ContentHash] = []
        self.tree_levels: List[List[str]] = []
        self.root_hash: Optional[str] = None
    
    def add_content(self, content: Union[bytes, BinaryIO], 
                   content_type: Optional[str] = None) -> ContentHash:
        """Add content to the merkle tree."""
        content_hash = self.hasher.hash_content(content, content_type)
        self.leaves.append(content_hash)
        self.root_hash = None  # Invalidate cached root
        return content_hash
    
    def add_file(self, file_path: Union[str, Path]) -> ContentHash:
        """Add file to the merkle tree."""
        content_hash = self.hasher.hash_file(file_path)
        self.leaves.append(content_hash)
        self.root_hash = None  # Invalidate cached root
        return content_hash
    
    def add_hash(self, content_hash: ContentHash) -> None:
        """Add existing hash to the merkle tree."""
        self.leaves.append(content_hash)
        self.root_hash = None  # Invalidate cached root
    
    def calculate_root(self) -> str:
        """Calculate merkle root hash."""
        if not self.leaves:
            raise ValueError("No content added to merkle tree")
        
        # Use leaf hashes as starting level
        current_level = [leaf.hash_value for leaf in self.leaves]
        self.tree_levels = [current_level.copy()]
        
        # Build tree bottom-up
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                
                # Concatenate and hash
                combined = left + right
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(parent_hash)
            
            self.tree_levels.append(next_level.copy())
            current_level = next_level
        
        self.root_hash = current_level[0]
        return self.root_hash
    
    def get_root(self) -> Optional[str]:
        """Get cached root hash."""
        if self.root_hash is None and self.leaves:
            return self.calculate_root()
        return self.root_hash
    
    def generate_proof(self, leaf_index: int) -> List[Tuple[str, str]]:
        """
        Generate merkle proof for a leaf.
        
        Args:
            leaf_index: Index of leaf to prove
            
        Returns:
            List of (hash, position) tuples for proof path
        """
        if not self.tree_levels:
            self.calculate_root()
        
        if leaf_index >= len(self.leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range")
        
        proof = []
        current_index = leaf_index
        
        # Generate proof path from leaf to root
        for level in self.tree_levels[:-1]:  # Exclude root level
            # Find sibling
            if current_index % 2 == 0:
                # Left child, sibling is right
                sibling_index = current_index + 1
                position = "right"
            else:
                # Right child, sibling is left
                sibling_index = current_index - 1
                position = "left"
            
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
            else:
                sibling_hash = level[current_index]  # Duplicate for odd count
            
            proof.append((sibling_hash, position))
            current_index = current_index // 2
        
        return proof
    
    def verify_proof(self, leaf_hash: str, leaf_index: int, 
                    proof: List[Tuple[str, str]], root_hash: str) -> bool:
        """
        Verify merkle proof.
        
        Args:
            leaf_hash: Hash of the leaf to verify
            leaf_index: Original index of the leaf
            proof: Proof path from generate_proof
            root_hash: Expected root hash
            
        Returns:
            True if proof is valid
        """
        current_hash = leaf_hash
        current_index = leaf_index
        
        for sibling_hash, position in proof:
            if position == "left":
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash
            
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
            current_index = current_index // 2
        
        return current_hash == root_hash
    
    def to_dict(self) -> Dict[str, any]:
        """Convert tree to dictionary format."""
        return {
            "leaves": [leaf.to_dict() for leaf in self.leaves],
            "root_hash": self.get_root(),
            "tree_levels": self.tree_levels
        }


class ContentStorage(ABC):
    """Abstract base class for content storage systems."""
    
    @abstractmethod
    def store(self, content: Union[bytes, BinaryIO], 
              filename: Optional[str] = None, 
              content_type: Optional[str] = None) -> ContentInfo:
        """Store content and return content info."""
        pass
    
    @abstractmethod
    def retrieve(self, uri: str) -> bytes:
        """Retrieve content by URI."""
        pass
    
    @abstractmethod
    def exists(self, uri: str) -> bool:
        """Check if content exists at URI."""
        pass
    
    @abstractmethod
    def get_storage_type(self) -> StorageType:
        """Get storage type identifier."""
        pass


class LocalStorage(ContentStorage):
    """Local filesystem storage."""
    
    def __init__(self, base_path: Union[str, Path]):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.hasher = ContentHasher()
    
    def store(self, content: Union[bytes, BinaryIO], 
              filename: Optional[str] = None, 
              content_type: Optional[str] = None) -> ContentInfo:
        """Store content locally."""
        # Generate content hash first
        if isinstance(content, bytes):
            content_data = content
        else:
            content_data = content.read()
            if hasattr(content, 'seek'):
                content.seek(0)
        
        content_hash = self.hasher.hash_content(content_data, content_type)
        
        # Use hash as filename if not provided
        if not filename:
            ext = mimetypes.guess_extension(content_type) if content_type else ''
            filename = f"{content_hash.hash_value[:16]}{ext}"
        
        file_path = self.base_path / filename
        
        # Write content to file
        with open(file_path, 'wb') as f:
            f.write(content_data)
        
        uri = f"file://{file_path.absolute()}"
        
        return ContentInfo(
            content_hash=content_hash,
            uri=uri,
            storage_type=self.get_storage_type(),
            content_type=content_type or 'application/octet-stream',
            content_size=content_hash.content_size,
            filename=filename
        )
    
    def retrieve(self, uri: str) -> bytes:
        """Retrieve content from local storage."""
        if not uri.startswith('file://'):
            raise ValueError(f"Invalid local URI: {uri}")
        
        file_path = Path(uri[7:])  # Remove 'file://' prefix
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            return f.read()
    
    def exists(self, uri: str) -> bool:
        """Check if file exists locally."""
        if not uri.startswith('file://'):
            return False
        
        file_path = Path(uri[7:])
        return file_path.exists()
    
    def get_storage_type(self) -> StorageType:
        return StorageType.LOCAL


class IPFSStorage(ContentStorage):
    """IPFS distributed storage."""
    
    def __init__(self, gateway_url: str = '/ip4/127.0.0.1/tcp/5001/http'):
        if not IPFS_AVAILABLE:
            raise ImportError("ipfshttpclient required for IPFS storage. Install with: pip install ipfshttpclient")
        
        self.client = ipfshttpclient.connect(gateway_url)
        self.hasher = ContentHasher()
    
    def store(self, content: Union[bytes, BinaryIO], 
              filename: Optional[str] = None, 
              content_type: Optional[str] = None) -> ContentInfo:
        """Store content on IPFS."""
        # Generate content hash first
        if isinstance(content, bytes):
            content_data = content
        else:
            content_data = content.read()
            if hasattr(content, 'seek'):
                content.seek(0)
        
        content_hash = self.hasher.hash_content(content_data, content_type)
        
        # Add to IPFS
        result = self.client.add_bytes(content_data)
        ipfs_hash = result['Hash']
        
        uri = f"ipfs://{ipfs_hash}"
        
        metadata = {
            'ipfs_hash': ipfs_hash,
            'ipfs_size': result.get('Size', len(content_data))
        }
        
        return ContentInfo(
            content_hash=content_hash,
            uri=uri,
            storage_type=self.get_storage_type(),
            content_type=content_type or 'application/octet-stream',
            content_size=content_hash.content_size,
            filename=filename,
            metadata=metadata
        )
    
    def retrieve(self, uri: str) -> bytes:
        """Retrieve content from IPFS."""
        if not uri.startswith('ipfs://'):
            raise ValueError(f"Invalid IPFS URI: {uri}")
        
        ipfs_hash = uri[7:]  # Remove 'ipfs://' prefix
        return self.client.cat(ipfs_hash)
    
    def exists(self, uri: str) -> bool:
        """Check if content exists on IPFS."""
        if not uri.startswith('ipfs://'):
            return False
        
        try:
            ipfs_hash = uri[7:]
            # Try to get object stats
            self.client.object.stat(ipfs_hash)
            return True
        except Exception:
            return False
    
    def get_storage_type(self) -> StorageType:
        return StorageType.IPFS


class HTTPStorage(ContentStorage):
    """HTTP/HTTPS remote storage."""
    
    def __init__(self):
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests required for HTTP storage. Install with: pip install requests")
        
        self.hasher = ContentHasher()
    
    def store(self, content: Union[bytes, BinaryIO], 
              filename: Optional[str] = None, 
              content_type: Optional[str] = None) -> ContentInfo:
        """HTTP storage requires external upload - not implemented."""
        raise NotImplementedError("HTTP storage requires external upload mechanism")
    
    def retrieve(self, uri: str) -> bytes:
        """Retrieve content via HTTP."""
        if not uri.startswith(('http://', 'https://')):
            raise ValueError(f"Invalid HTTP URI: {uri}")
        
        response = requests.get(uri, timeout=30)
        response.raise_for_status()
        return response.content
    
    def exists(self, uri: str) -> bool:
        """Check if HTTP resource exists."""
        if not uri.startswith(('http://', 'https://')):
            return False
        
        try:
            response = requests.head(uri, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def get_storage_type(self) -> StorageType:
        return StorageType.HTTP


class TaprootStorage(ContentStorage):
    """Taproot envelope storage for small content."""
    
    def __init__(self, max_size: int = 400):  # Bitcoin script size limit
        self.max_size = max_size
        self.hasher = ContentHasher()
    
    def store(self, content: Union[bytes, BinaryIO], 
              filename: Optional[str] = None, 
              content_type: Optional[str] = None) -> ContentInfo:
        """Store small content in Taproot envelope format."""
        if isinstance(content, bytes):
            content_data = content
        else:
            content_data = content.read()
        
        if len(content_data) > self.max_size:
            raise ValueError(f"Content too large for Taproot storage: {len(content_data)} > {self.max_size}")
        
        content_hash = self.hasher.hash_content(content_data, content_type)
        
        # Create Taproot envelope (simplified)
        envelope_data = self._create_envelope(content_data, content_type)
        envelope_hash = hashlib.sha256(envelope_data).hexdigest()
        
        uri = f"taproot://{envelope_hash}"
        
        metadata = {
            'envelope_data': envelope_data.hex(),
            'envelope_size': len(envelope_data)
        }
        
        return ContentInfo(
            content_hash=content_hash,
            uri=uri,
            storage_type=self.get_storage_type(),
            content_type=content_type or 'application/octet-stream',
            content_size=len(content_data),
            filename=filename,
            metadata=metadata
        )
    
    def retrieve(self, uri: str) -> bytes:
        """Retrieve content from Taproot envelope."""
        raise NotImplementedError("Taproot retrieval requires blockchain integration")
    
    def exists(self, uri: str) -> bool:
        """Check if Taproot envelope exists."""
        return uri.startswith('taproot://')
    
    def get_storage_type(self) -> StorageType:
        return StorageType.TAPROOT
    
    def _create_envelope(self, content: bytes, content_type: Optional[str]) -> bytes:
        """Create Taproot envelope data structure."""
        # Simplified envelope format: type_length + type + content_length + content
        type_bytes = (content_type or '').encode('utf-8')
        type_length = len(type_bytes).to_bytes(1, 'big')
        content_length = len(content).to_bytes(2, 'big')
        
        envelope = type_length + type_bytes + content_length + content
        return envelope


class ContentManager:
    """Manages content across multiple storage systems."""
    
    def __init__(self):
        self.storage_backends: Dict[StorageType, ContentStorage] = {}
        self.hasher = ContentHasher()
    
    def add_storage_backend(self, backend: ContentStorage):
        """Add a storage backend."""
        self.storage_backends[backend.get_storage_type()] = backend
    
    def store_content(self, content: Union[bytes, BinaryIO, str, Path], 
                     storage_type: StorageType = StorageType.LOCAL,
                     filename: Optional[str] = None,
                     content_type: Optional[str] = None) -> ContentInfo:
        """
        Store content using specified storage backend.
        
        Args:
            content: Content to store (bytes, file-like, or file path)
            storage_type: Storage backend to use
            filename: Optional filename
            content_type: MIME type
            
        Returns:
            ContentInfo with storage details
        """
        if storage_type not in self.storage_backends:
            raise ValueError(f"Storage backend not configured: {storage_type}")
        
        backend = self.storage_backends[storage_type]
        
        # Handle file path input
        if isinstance(content, (str, Path)):
            file_path = Path(content)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Auto-detect content type and filename
            if not content_type:
                content_type, _ = mimetypes.guess_type(str(file_path))
            if not filename:
                filename = file_path.name
            
            with open(file_path, 'rb') as f:
                return backend.store(f, filename, content_type)
        
        return backend.store(content, filename, content_type)
    
    def retrieve_content(self, uri: str) -> bytes:
        """Retrieve content by URI."""
        # Determine storage type from URI scheme
        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()
        
        storage_type_map = {
            'file': StorageType.LOCAL,
            'ipfs': StorageType.IPFS,
            'http': StorageType.HTTP,
            'https': StorageType.HTTP,
            'taproot': StorageType.TAPROOT,
            'ar': StorageType.ARWEAVE
        }
        
        storage_type = storage_type_map.get(scheme)
        if not storage_type or storage_type not in self.storage_backends:
            raise ValueError(f"No storage backend for URI: {uri}")
        
        backend = self.storage_backends[storage_type]
        return backend.retrieve(uri)
    
    def verify_content_integrity(self, uri: str, expected_hash: Union[str, ContentHash]) -> bool:
        """Verify content integrity by retrieving and hashing."""
        try:
            content = self.retrieve_content(uri)
            return self.hasher.verify_content(content, expected_hash)
        except Exception:
            return False
    
    def create_merkle_tree(self, content_list: List[Union[str, bytes, Path]]) -> MerkleTree:
        """Create merkle tree from multiple content items."""
        tree = MerkleTree(self.hasher)
        
        for content in content_list:
            if isinstance(content, (str, Path)):
                tree.add_file(content)
            else:
                tree.add_content(content)
        
        return tree


# Utility functions

def detect_content_type(content: Union[bytes, str, Path]) -> Optional[str]:
    """Detect content type from content or filename."""
    if isinstance(content, (str, Path)):
        content_type, _ = mimetypes.guess_type(str(content))
        return content_type
    
    if isinstance(content, bytes):
        # Simple magic number detection
        if content.startswith(b'\xff\xd8\xff'):
            return 'image/jpeg'
        elif content.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image/png'
        elif content.startswith(b'GIF8'):
            return 'image/gif'
        elif content.startswith(b'%PDF-'):
            return 'application/pdf'
        elif content.startswith(b'RIFF') and b'WEBP' in content[:12]:
            return 'image/webp'
    
    return None


def create_content_uri(content_info: ContentInfo, gateway: Optional[str] = None) -> str:
    """Create appropriate URI for content based on storage type and gateway."""
    if content_info.storage_type == StorageType.IPFS and gateway:
        ipfs_hash = content_info.uri[7:]  # Remove 'ipfs://'
        return f"{gateway.rstrip('/')}/ipfs/{ipfs_hash}"
    
    return content_info.uri


# CLI and testing interface

def main():
    """CLI interface for content operations."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="BNAP NFT Content Tools")
    parser.add_argument("command", choices=["hash", "merkle", "store", "verify", "test"])
    parser.add_argument("--file", help="File to process")
    parser.add_argument("--algorithm", choices=["sha256", "sha512", "blake2b", "md5"], default="sha256")
    parser.add_argument("--storage", choices=["local", "ipfs"], default="local")
    parser.add_argument("--hash-value", help="Hash value for verification")
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    args = parser.parse_args()
    
    if args.command == "test":
        test_content_system()
    elif args.command == "hash" and args.file:
        hash_file_cli(args.file, args.algorithm)
    elif args.command == "verify" and args.file and args.hash_value:
        verify_file_cli(args.file, args.hash_value, args.algorithm)
    elif args.command == "merkle":
        test_merkle_tree()
    elif args.command == "store" and args.file:
        store_file_cli(args.file, args.storage)


def hash_file_cli(file_path: str, algorithm: str):
    """Hash file via CLI."""
    try:
        hasher = ContentHasher(HashAlgorithm(algorithm))
        content_hash = hasher.hash_file(file_path)
        print(f"{algorithm.upper()}: {content_hash.hash_value}")
        print(f"Size: {content_hash.content_size} bytes")
        print(f"Type: {content_hash.content_type}")
    except Exception as e:
        print(f"Error: {e}")


def verify_file_cli(file_path: str, expected_hash: str, algorithm: str):
    """Verify file via CLI."""
    try:
        hasher = ContentHasher(HashAlgorithm(algorithm))
        valid = hasher.verify_file(file_path, expected_hash)
        print(f"✓ File verified: {valid}")
    except Exception as e:
        print(f"Error: {e}")


def store_file_cli(file_path: str, storage_type: str):
    """Store file via CLI."""
    try:
        manager = ContentManager()
        
        # Add local storage
        if storage_type == "local":
            local_storage = LocalStorage("./content_storage")
            manager.add_storage_backend(local_storage)
            storage_enum = StorageType.LOCAL
        elif storage_type == "ipfs":
            if IPFS_AVAILABLE:
                ipfs_storage = IPFSStorage()
                manager.add_storage_backend(ipfs_storage)
                storage_enum = StorageType.IPFS
            else:
                print("IPFS not available")
                return
        
        content_info = manager.store_content(file_path, storage_enum)
        print(f"✓ Stored: {content_info.uri}")
        print(f"Hash: {content_info.content_hash.hash_value}")
        print(f"Size: {content_info.content_size} bytes")
        
    except Exception as e:
        print(f"Error: {e}")


def test_merkle_tree():
    """Test merkle tree functionality."""
    print("Testing Merkle Tree...")
    
    # Create test content
    test_files = [
        b"file1 content",
        b"file2 content", 
        b"file3 content"
    ]
    
    tree = MerkleTree()
    hashes = []
    
    for i, content in enumerate(test_files):
        content_hash = tree.add_content(content, "text/plain")
        hashes.append(content_hash)
        print(f"Added file {i+1}: {content_hash.hash_value}")
    
    root = tree.calculate_root()
    print(f"Merkle root: {root}")
    
    # Test proof generation and verification
    proof = tree.generate_proof(0)
    valid = tree.verify_proof(hashes[0].hash_value, 0, proof, root)
    print(f"Proof verification: {valid}")


def test_content_system():
    """Test the content management system."""
    print("Testing NFT Content Management System...")
    print("=" * 50)
    
    try:
        # Test content hashing
        hasher = ContentHasher()
        test_content = b"Test NFT content for hashing"
        
        content_hash = hasher.hash_content(test_content, "text/plain")
        print(f"✓ Content hash: {content_hash.hash_value}")
        
        # Test verification
        verified = hasher.verify_content(test_content, content_hash)
        print(f"✓ Hash verification: {verified}")
        
        # Test content manager
        manager = ContentManager()
        local_storage = LocalStorage("./test_content")
        manager.add_storage_backend(local_storage)
        
        # Store test content
        content_info = manager.store_content(test_content, StorageType.LOCAL, 
                                           "test.txt", "text/plain")
        print(f"✓ Stored content: {content_info.uri}")
        
        # Retrieve and verify
        retrieved = manager.retrieve_content(content_info.uri)
        print(f"✓ Retrieved content: {retrieved == test_content}")
        
        # Test integrity verification
        integrity = manager.verify_content_integrity(content_info.uri, content_hash)
        print(f"✓ Content integrity: {integrity}")
        
        # Test merkle tree
        tree = MerkleTree()
        tree.add_content(b"content1")
        tree.add_content(b"content2") 
        tree.add_content(b"content3")
        
        root = tree.calculate_root()
        print(f"✓ Merkle root: {root}")
        
        print("\nAll content system tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    main()