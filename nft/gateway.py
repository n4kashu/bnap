"""
Bitcoin Native Asset Protocol - HTTP Gateway and URI Handling

This module provides HTTP gateway integration for NFT content retrieval with
comprehensive URI resolution, caching, content validation, and CDN support.
"""

import asyncio
import hashlib
import json
import logging
import mimetypes
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, BinaryIO
from urllib.parse import urlparse, urljoin, quote, unquote
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    HTTPAdapter = None
    Retry = None
    REQUESTS_AVAILABLE = False

try:
    from .content import ContentStorage, ContentInfo, ContentHash, ContentHasher, StorageType
except ImportError:
    # For standalone testing
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from content import ContentStorage, ContentInfo, ContentHash, ContentHasher, StorageType


class URIScheme(str, Enum):
    """Supported URI schemes."""
    HTTP = "http"
    HTTPS = "https"
    IPFS = "ipfs"
    ARWEAVE = "ar"
    TAPROOT = "taproot"
    FILE = "file"
    DATA = "data"


class CacheStrategy(str, Enum):
    """Content caching strategies."""
    NONE = "none"
    MEMORY = "memory"
    DISK = "disk"
    HYBRID = "hybrid"


class GatewayType(str, Enum):
    """HTTP gateway types."""
    IPFS_GATEWAY = "ipfs_gateway"
    ARWEAVE_GATEWAY = "arweave_gateway"
    CDN = "cdn"
    DIRECT = "direct"
    PROXY = "proxy"


@dataclass
class CacheEntry:
    """Cache entry for content."""
    
    content: bytes
    content_type: str
    content_hash: str
    uri: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False
    
    def access(self) -> None:
        """Mark cache entry as accessed."""
        self.last_accessed = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "uri": self.uri,
            "content_type": self.content_type,
            "content_hash": self.content_hash,
            "content_size": len(self.content),
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata
        }


@dataclass
class HTTPGatewayConfig:
    """HTTP gateway configuration."""
    
    name: str
    base_url: str
    gateway_type: GatewayType = GatewayType.DIRECT
    priority: int = 1
    timeout: int = 30
    max_content_size: int = 100 * 1024 * 1024  # 100MB
    
    # Authentication
    requires_auth: bool = False
    api_key: Optional[str] = None
    api_key_header: str = "Authorization"
    
    # Rate limiting
    rate_limit: Optional[int] = None  # requests per minute
    
    # Custom headers
    headers: Dict[str, str] = field(default_factory=dict)
    
    # CDN settings
    cdn_cache_ttl: int = 3600  # seconds
    
    def construct_url(self, path: str, scheme: URIScheme = URIScheme.HTTPS) -> str:
        """Construct full URL for content."""
        base_url = self.base_url.rstrip('/')
        
        if scheme == URIScheme.IPFS:
            if not base_url.endswith('/ipfs'):
                base_url += '/ipfs'
            return f"{base_url}/{path}"
        elif scheme == URIScheme.ARWEAVE:
            return f"{base_url}/{path}"
        else:
            return urljoin(base_url, path)
    
    def get_headers(self) -> Dict[str, str]:
        """Get headers for requests."""
        headers = self.headers.copy()
        
        if self.requires_auth and self.api_key:
            headers[self.api_key_header] = self.api_key
        
        headers.update({
            "User-Agent": "BNAP-NFT-Gateway/1.0",
            "Accept": "*/*",
            "Cache-Control": f"max-age={self.cdn_cache_ttl}"
        })
        
        return headers


class ContentCache:
    """Content cache with configurable strategies."""
    
    def __init__(self, strategy: CacheStrategy = CacheStrategy.MEMORY,
                 max_size: int = 50 * 1024 * 1024,  # 50MB
                 max_entries: int = 1000,
                 default_ttl: int = 3600):
        self.strategy = strategy
        self.max_size = max_size
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self.current_size = 0
        
        # Memory cache
        self._memory_cache: Dict[str, CacheEntry] = {}
        
        # Disk cache directory
        self._disk_cache_dir: Optional[Path] = None
        if strategy in [CacheStrategy.DISK, CacheStrategy.HYBRID]:
            self._disk_cache_dir = Path.cwd() / ".bnap_cache"
            self._disk_cache_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
    
    def _generate_cache_key(self, uri: str) -> str:
        """Generate cache key for URI."""
        return hashlib.sha256(uri.encode()).hexdigest()
    
    def get(self, uri: str) -> Optional[CacheEntry]:
        """Get content from cache."""
        cache_key = self._generate_cache_key(uri)
        
        # Check memory cache first
        if cache_key in self._memory_cache:
            entry = self._memory_cache[cache_key]
            if not entry.is_expired():
                entry.access()
                return entry
            else:
                del self._memory_cache[cache_key]
                self.current_size -= len(entry.content)
        
        # Check disk cache
        if self.strategy in [CacheStrategy.DISK, CacheStrategy.HYBRID]:
            disk_path = self._disk_cache_dir / f"{cache_key}.cache"
            if disk_path.exists():
                try:
                    with open(disk_path, 'rb') as f:
                        cache_data = json.loads(f.read().decode())
                    
                    # Load content
                    content_path = self._disk_cache_dir / f"{cache_key}.content"
                    with open(content_path, 'rb') as f:
                        content = f.read()
                    
                    # Create cache entry
                    entry = CacheEntry(
                        content=content,
                        content_type=cache_data["content_type"],
                        content_hash=cache_data["content_hash"],
                        uri=uri,
                        created_at=datetime.fromisoformat(cache_data["created_at"]),
                        expires_at=datetime.fromisoformat(cache_data["expires_at"]) if cache_data["expires_at"] else None,
                        metadata=cache_data.get("metadata", {})
                    )
                    
                    if not entry.is_expired():
                        entry.access()
                        
                        # Load into memory cache if hybrid strategy
                        if self.strategy == CacheStrategy.HYBRID:
                            self._memory_cache[cache_key] = entry
                            self.current_size += len(entry.content)
                        
                        return entry
                    else:
                        # Clean up expired disk cache
                        disk_path.unlink(missing_ok=True)
                        content_path.unlink(missing_ok=True)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to load disk cache for {uri}: {e}")
        
        return None
    
    def put(self, uri: str, content: bytes, content_type: str, 
            content_hash: str, ttl: Optional[int] = None) -> None:
        """Store content in cache."""
        cache_key = self._generate_cache_key(uri)
        ttl = ttl or self.default_ttl
        
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        
        entry = CacheEntry(
            content=content,
            content_type=content_type,
            content_hash=content_hash,
            uri=uri,
            expires_at=expires_at
        )
        
        # Memory cache
        if self.strategy in [CacheStrategy.MEMORY, CacheStrategy.HYBRID]:
            # Evict if necessary
            self._evict_if_needed(len(content))
            
            self._memory_cache[cache_key] = entry
            self.current_size += len(content)
        
        # Disk cache
        if self.strategy in [CacheStrategy.DISK, CacheStrategy.HYBRID]:
            try:
                # Save metadata
                cache_path = self._disk_cache_dir / f"{cache_key}.cache"
                with open(cache_path, 'wb') as f:
                    f.write(json.dumps(entry.to_dict()).encode())
                
                # Save content
                content_path = self._disk_cache_dir / f"{cache_key}.content"
                with open(content_path, 'wb') as f:
                    f.write(content)
                    
            except Exception as e:
                self.logger.warning(f"Failed to save disk cache for {uri}: {e}")
    
    def _evict_if_needed(self, incoming_size: int) -> None:
        """Evict entries if cache is full."""
        # Check size limit
        while (self.current_size + incoming_size > self.max_size or 
               len(self._memory_cache) >= self.max_entries):
            
            if not self._memory_cache:
                break
            
            # Evict least recently used
            lru_key = min(self._memory_cache.keys(), 
                         key=lambda k: self._memory_cache[k].last_accessed)
            
            entry = self._memory_cache.pop(lru_key)
            self.current_size -= len(entry.content)
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._memory_cache.clear()
        self.current_size = 0
        
        if self._disk_cache_dir and self._disk_cache_dir.exists():
            for cache_file in self._disk_cache_dir.glob("*.cache"):
                cache_file.unlink(missing_ok=True)
            for content_file in self._disk_cache_dir.glob("*.content"):
                content_file.unlink(missing_ok=True)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "strategy": self.strategy.value,
            "memory_entries": len(self._memory_cache),
            "memory_size": self.current_size,
            "max_size": self.max_size,
            "max_entries": self.max_entries,
            "disk_cache_dir": str(self._disk_cache_dir) if self._disk_cache_dir else None
        }


class URIResolver:
    """Universal URI resolver with gateway fallback."""
    
    def __init__(self, cache_strategy: CacheStrategy = CacheStrategy.MEMORY):
        self.gateways: Dict[GatewayType, List[HTTPGatewayConfig]] = {
            GatewayType.IPFS_GATEWAY: [],
            GatewayType.ARWEAVE_GATEWAY: [],
            GatewayType.CDN: [],
            GatewayType.DIRECT: []
        }
        
        self.cache = ContentCache(cache_strategy)
        self.hasher = ContentHasher()
        self.logger = logging.getLogger(__name__)
        
        # Request session with retry logic
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        else:
            self.session = None
        
        # Initialize default gateways
        self._init_default_gateways()
        
        # Statistics
        self._stats = {
            "resolutions": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "gateway_failures": 0,
            "total_bytes_served": 0
        }
    
    def _init_default_gateways(self):
        """Initialize default HTTP gateways."""
        # IPFS gateways
        ipfs_gateways = [
            HTTPGatewayConfig("IPFS.io", "https://ipfs.io", GatewayType.IPFS_GATEWAY, 1),
            HTTPGatewayConfig("Cloudflare", "https://cloudflare-ipfs.com", GatewayType.IPFS_GATEWAY, 2),
            HTTPGatewayConfig("Pinata", "https://gateway.pinata.cloud", GatewayType.IPFS_GATEWAY, 3),
            HTTPGatewayConfig("Infura", "https://ipfs.infura.io", GatewayType.IPFS_GATEWAY, 4),
            HTTPGatewayConfig("Fleek", "https://ipfs.fleek.co", GatewayType.IPFS_GATEWAY, 5)
        ]
        
        # Arweave gateways
        arweave_gateways = [
            HTTPGatewayConfig("Arweave.net", "https://arweave.net", GatewayType.ARWEAVE_GATEWAY, 1),
            HTTPGatewayConfig("ViewBlock", "https://viewblock.io/arweave/tx", GatewayType.ARWEAVE_GATEWAY, 2)
        ]
        
        self.gateways[GatewayType.IPFS_GATEWAY].extend(ipfs_gateways)
        self.gateways[GatewayType.ARWEAVE_GATEWAY].extend(arweave_gateways)
        
        # Sort by priority
        for gateway_list in self.gateways.values():
            gateway_list.sort(key=lambda g: g.priority)
    
    def add_gateway(self, gateway: HTTPGatewayConfig):
        """Add custom HTTP gateway."""
        self.gateways[gateway.gateway_type].append(gateway)
        self.gateways[gateway.gateway_type].sort(key=lambda g: g.priority)
    
    def resolve_uri(self, uri: str, verify_hash: Optional[str] = None) -> Tuple[bytes, str, Dict[str, Any]]:
        """
        Resolve URI to content with caching and fallback.
        
        Args:
            uri: URI to resolve
            verify_hash: Optional hash to verify content integrity
            
        Returns:
            Tuple of (content, content_type, metadata)
        """
        self._stats["resolutions"] += 1
        
        # Check cache first
        cached = self.cache.get(uri)
        if cached:
            self._stats["cache_hits"] += 1
            self._stats["total_bytes_served"] += len(cached.content)
            
            # Verify hash if provided
            if verify_hash and cached.content_hash != verify_hash:
                self.logger.warning(f"Cached content hash mismatch for {uri}")
                # Continue to fresh retrieval
            else:
                return cached.content, cached.content_type, cached.metadata
        
        self._stats["cache_misses"] += 1
        
        # Parse URI
        parsed = urlparse(uri)
        scheme = URIScheme(parsed.scheme.lower())
        
        # Resolve based on scheme
        content, content_type, metadata = self._resolve_by_scheme(uri, scheme, parsed)
        
        # Verify content hash if provided
        if verify_hash:
            calculated_hash = self.hasher.hash_content(content).hash_value
            if calculated_hash != verify_hash:
                raise ValueError(f"Content hash verification failed: expected {verify_hash}, got {calculated_hash}")
            metadata["verified_hash"] = verify_hash
        
        # Generate hash for caching
        content_hash = self.hasher.hash_content(content).hash_value
        
        # Cache the result
        self.cache.put(uri, content, content_type, content_hash)
        
        self._stats["total_bytes_served"] += len(content)
        
        return content, content_type, metadata
    
    def _resolve_by_scheme(self, uri: str, scheme: URIScheme, 
                          parsed: Any) -> Tuple[bytes, str, Dict[str, Any]]:
        """Resolve URI based on scheme."""
        if scheme in [URIScheme.HTTP, URIScheme.HTTPS]:
            return self._resolve_http(uri)
        
        elif scheme == URIScheme.IPFS:
            return self._resolve_ipfs(parsed.netloc)
        
        elif scheme == URIScheme.ARWEAVE:
            return self._resolve_arweave(parsed.netloc)
        
        elif scheme == URIScheme.FILE:
            return self._resolve_file(parsed.path)
        
        elif scheme == URIScheme.DATA:
            return self._resolve_data(uri)
        
        else:
            raise ValueError(f"Unsupported URI scheme: {scheme}")
    
    def _resolve_http(self, uri: str) -> Tuple[bytes, str, Dict[str, Any]]:
        """Resolve HTTP/HTTPS URI."""
        if not self.session:
            raise RuntimeError("HTTP client not available")
        
        try:
            response = self.session.get(uri, timeout=30)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', 'application/octet-stream').split(';')[0]
            
            metadata = {
                "source": "direct_http",
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": len(response.content)
            }
            
            return response.content, content_type, metadata
            
        except Exception as e:
            raise RuntimeError(f"Failed to resolve HTTP URI {uri}: {e}")
    
    def _resolve_ipfs(self, cid: str) -> Tuple[bytes, str, Dict[str, Any]]:
        """Resolve IPFS URI with gateway fallback."""
        errors = []
        
        for gateway in self.gateways[GatewayType.IPFS_GATEWAY]:
            try:
                url = gateway.construct_url(cid, URIScheme.IPFS)
                
                if not self.session:
                    # Fallback to urllib
                    req = Request(url, headers=gateway.get_headers())
                    with urlopen(req, timeout=gateway.timeout) as response:
                        content = response.read()
                        content_type = response.headers.get('content-type', 'application/octet-stream')
                else:
                    response = self.session.get(
                        url, 
                        headers=gateway.get_headers(),
                        timeout=gateway.timeout
                    )
                    response.raise_for_status()
                    content = response.content
                    content_type = response.headers.get('content-type', 'application/octet-stream').split(';')[0]
                
                metadata = {
                    "source": "ipfs_gateway",
                    "gateway": gateway.name,
                    "gateway_url": url,
                    "content_length": len(content)
                }
                
                return content, content_type, metadata
                
            except Exception as e:
                error_msg = f"{gateway.name}: {str(e)}"
                errors.append(error_msg)
                self._stats["gateway_failures"] += 1
                continue
        
        raise RuntimeError(f"All IPFS gateways failed for {cid}: {'; '.join(errors)}")
    
    def _resolve_arweave(self, tx_id: str) -> Tuple[bytes, str, Dict[str, Any]]:
        """Resolve Arweave URI with gateway fallback."""
        errors = []
        
        for gateway in self.gateways[GatewayType.ARWEAVE_GATEWAY]:
            try:
                url = gateway.construct_url(tx_id, URIScheme.ARWEAVE)
                
                if not self.session:
                    # Fallback to urllib
                    req = Request(url, headers=gateway.get_headers())
                    with urlopen(req, timeout=gateway.timeout) as response:
                        content = response.read()
                        content_type = response.headers.get('content-type', 'application/octet-stream')
                else:
                    response = self.session.get(
                        url,
                        headers=gateway.get_headers(), 
                        timeout=gateway.timeout
                    )
                    response.raise_for_status()
                    content = response.content
                    content_type = response.headers.get('content-type', 'application/octet-stream').split(';')[0]
                
                metadata = {
                    "source": "arweave_gateway",
                    "gateway": gateway.name,
                    "gateway_url": url,
                    "content_length": len(content)
                }
                
                return content, content_type, metadata
                
            except Exception as e:
                error_msg = f"{gateway.name}: {str(e)}"
                errors.append(error_msg)
                self._stats["gateway_failures"] += 1
                continue
        
        raise RuntimeError(f"All Arweave gateways failed for {tx_id}: {'; '.join(errors)}")
    
    def _resolve_file(self, file_path: str) -> Tuple[bytes, str, Dict[str, Any]]:
        """Resolve file:// URI."""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        with open(path, 'rb') as f:
            content = f.read()
        
        content_type = mimetypes.guess_type(str(path))[0] or 'application/octet-stream'
        
        metadata = {
            "source": "local_file",
            "file_path": str(path.absolute()),
            "content_length": len(content),
            "modified_time": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        }
        
        return content, content_type, metadata
    
    def _resolve_data(self, uri: str) -> Tuple[bytes, str, Dict[str, Any]]:
        """Resolve data:// URI."""
        # Parse data URI format: data:[<mediatype>][;base64],<data>
        if not uri.startswith('data:'):
            raise ValueError(f"Invalid data URI: {uri}")
        
        header, data = uri[5:].split(',', 1)
        
        if ';base64' in header:
            import base64
            content = base64.b64decode(data)
            content_type = header.replace(';base64', '') or 'application/octet-stream'
        else:
            content = unquote(data).encode('utf-8')
            content_type = header or 'text/plain'
        
        metadata = {
            "source": "data_uri",
            "content_length": len(content),
            "encoding": "base64" if ';base64' in header else "url_encoded"
        }
        
        return content, content_type, metadata
    
    def batch_resolve(self, uris: List[str], 
                     verify_hashes: Optional[Dict[str, str]] = None) -> Dict[str, Tuple[bytes, str, Dict[str, Any]]]:
        """Batch resolve multiple URIs."""
        results = {}
        verify_hashes = verify_hashes or {}
        
        for uri in uris:
            try:
                verify_hash = verify_hashes.get(uri)
                content, content_type, metadata = self.resolve_uri(uri, verify_hash)
                results[uri] = (content, content_type, metadata)
            except Exception as e:
                self.logger.error(f"Failed to resolve {uri}: {e}")
                results[uri] = None
        
        return results
    
    def preload_cache(self, uris: List[str]) -> Dict[str, bool]:
        """Preload URIs into cache."""
        results = {}
        
        for uri in uris:
            try:
                self.resolve_uri(uri)
                results[uri] = True
            except Exception as e:
                self.logger.warning(f"Failed to preload {uri}: {e}")
                results[uri] = False
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get resolver statistics."""
        return {
            "resolver": self._stats.copy(),
            "cache": self.cache.get_stats(),
            "gateways": {
                gateway_type.value: len(gateways) 
                for gateway_type, gateways in self.gateways.items()
            }
        }
    
    def close(self):
        """Close HTTP session."""
        if self.session:
            self.session.close()


class HTTPGatewayStorage(ContentStorage):
    """Content storage using HTTP gateways."""
    
    def __init__(self, resolver: Optional[URIResolver] = None):
        self.resolver = resolver or URIResolver()
    
    def store(self, content: Union[bytes, BinaryIO], 
              filename: Optional[str] = None, 
              content_type: Optional[str] = None) -> ContentInfo:
        """HTTP storage requires external upload."""
        raise NotImplementedError("HTTP gateway storage requires external upload mechanism")
    
    def retrieve(self, uri: str) -> bytes:
        """Retrieve content via HTTP gateway."""
        content, _, _ = self.resolver.resolve_uri(uri)
        return content
    
    def exists(self, uri: str) -> bool:
        """Check if content exists via HTTP."""
        try:
            self.resolver.resolve_uri(uri)
            return True
        except Exception:
            return False
    
    def get_storage_type(self) -> StorageType:
        return StorageType.HTTP


# Utility functions

def create_default_resolver(cache_strategy: CacheStrategy = CacheStrategy.MEMORY) -> URIResolver:
    """Create URI resolver with default configuration."""
    return URIResolver(cache_strategy)


def resolve_nft_content(metadata_uri: str, image_uri: Optional[str] = None,
                       animation_uri: Optional[str] = None) -> Dict[str, Any]:
    """Resolve all NFT content URIs."""
    resolver = create_default_resolver()
    
    results = {
        "metadata": None,
        "image": None,
        "animation": None,
        "errors": []
    }
    
    # Resolve metadata
    try:
        content, content_type, metadata = resolver.resolve_uri(metadata_uri)
        results["metadata"] = {
            "content": content,
            "content_type": content_type,
            "metadata": metadata
        }
    except Exception as e:
        results["errors"].append(f"Metadata resolution failed: {e}")
    
    # Resolve image if provided
    if image_uri:
        try:
            content, content_type, metadata = resolver.resolve_uri(image_uri)
            results["image"] = {
                "content": content,
                "content_type": content_type,
                "metadata": metadata
            }
        except Exception as e:
            results["errors"].append(f"Image resolution failed: {e}")
    
    # Resolve animation if provided
    if animation_uri:
        try:
            content, content_type, metadata = resolver.resolve_uri(animation_uri)
            results["animation"] = {
                "content": content,
                "content_type": content_type,
                "metadata": metadata
            }
        except Exception as e:
            results["errors"].append(f"Animation resolution failed: {e}")
    
    resolver.close()
    return results


def test_gateway_system():
    """Test HTTP gateway and URI handling system."""
    print("Testing HTTP Gateway and URI Handling System...")
    print("=" * 60)
    
    try:
        # Test URI resolver
        resolver = URIResolver(CacheStrategy.MEMORY)
        print(f"✓ Created URI resolver with {len(resolver.gateways[GatewayType.IPFS_GATEWAY])} IPFS gateways")
        
        # Test gateway configuration
        custom_gateway = HTTPGatewayConfig(
            name="Custom",
            base_url="https://example.com",
            gateway_type=GatewayType.CDN,
            priority=1
        )
        resolver.add_gateway(custom_gateway)
        print(f"✓ Added custom gateway: {custom_gateway.name}")
        
        # Test data URI resolution
        data_uri = "data:text/plain;base64,SGVsbG8gQk5BUCBORlQ="
        try:
            content, content_type, metadata = resolver.resolve_uri(data_uri)
            decoded = content.decode('utf-8')
            print(f"✓ Data URI resolved: '{decoded}' ({content_type})")
        except Exception as e:
            print(f"! Data URI resolution: {e}")
        
        # Test file URI (if test file exists)
        test_file = Path("sample_nft_metadata.json")
        if test_file.exists():
            file_uri = f"file://{test_file.absolute()}"
            try:
                content, content_type, metadata = resolver.resolve_uri(file_uri)
                print(f"✓ File URI resolved: {len(content)} bytes ({content_type})")
            except Exception as e:
                print(f"! File URI resolution: {e}")
        
        # Test cache functionality
        cache = ContentCache(CacheStrategy.MEMORY)
        test_content = b"Sample cache content"
        cache.put("test://cache", test_content, "text/plain", "testhash123")
        
        cached_entry = cache.get("test://cache")
        if cached_entry:
            print(f"✓ Cache working: {len(cached_entry.content)} bytes cached")
        
        # Test statistics
        stats = resolver.get_statistics()
        print(f"✓ Resolver stats: {stats['resolver']['resolutions']} resolutions")
        
        # Test HTTP gateway storage
        gateway_storage = HTTPGatewayStorage(resolver)
        print(f"✓ HTTP gateway storage created ({gateway_storage.get_storage_type().value})")
        
        # Test gateway URL construction
        ipfs_gateway = resolver.gateways[GatewayType.IPFS_GATEWAY][0]
        test_cid = "QmTestHashForGateway"
        url = ipfs_gateway.construct_url(test_cid, URIScheme.IPFS)
        print(f"✓ Gateway URL: {url}")
        
        print("\n✓ All HTTP gateway system components working correctly")
        print("ℹ️  Note: Network resolution requires internet connectivity")
        
        resolver.close()
        print("\nHTTP gateway and URI handling tests completed!")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        success = test_gateway_system()
        sys.exit(0 if success else 1)
    else:
        print("HTTP Gateway and URI Handling for BNAP NFTs")
        print("Usage: python gateway.py test")
        print("\nFeatures:")
        print("- Universal URI resolver with multiple scheme support")
        print("- HTTP gateway fallback for IPFS and Arweave content")
        print("- Content caching with memory/disk strategies")
        print("- CDN integration and custom gateway support")
        print("- Batch resolution and content preloading")
        print("- Comprehensive error handling and statistics")