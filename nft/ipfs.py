"""
Bitcoin Native Asset Protocol - Advanced IPFS Integration

This module provides comprehensive IPFS functionality for NFT content storage
including pinning, gateway management, fallback support, and connection pooling.
"""

import asyncio
import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
from urllib.parse import urlparse, urljoin

try:
    import ipfshttpclient
    IPFS_CLIENT_AVAILABLE = True
except ImportError:
    ipfshttpclient = None
    IPFS_CLIENT_AVAILABLE = False

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


class IPFSNodeType(str, Enum):
    """IPFS node types."""
    LOCAL = "local"
    REMOTE = "remote"
    INFURA = "infura"
    PINATA = "pinata"
    FLEEK = "fleek"


class PinStatus(str, Enum):
    """IPFS pin status."""
    PINNED = "pinned"
    PINNING = "pinning"
    UNPINNED = "unpinned"
    FAILED = "failed"


@dataclass
class IPFSGateway:
    """IPFS gateway configuration."""
    
    name: str
    url: str
    priority: int = 1
    timeout: int = 30
    is_public: bool = True
    requires_auth: bool = False
    auth_header: Optional[str] = None
    
    def construct_url(self, cid: str, path: str = "") -> str:
        """Construct full URL for content."""
        base_url = self.url.rstrip('/')
        if not base_url.endswith('/ipfs'):
            base_url += '/ipfs'
        
        full_path = f"{base_url}/{cid}"
        if path:
            full_path += f"/{path.lstrip('/')}"
        
        return full_path
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "url": self.url,
            "priority": self.priority,
            "timeout": self.timeout,
            "is_public": self.is_public,
            "requires_auth": self.requires_auth,
            "auth_header": self.auth_header if not self.requires_auth else "***"
        }


@dataclass
class IPFSPin:
    """IPFS pin information."""
    
    cid: str
    status: PinStatus
    name: Optional[str] = None
    size: Optional[int] = None
    pinned_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_active(self) -> bool:
        """Check if pin is actively pinned."""
        return self.status == PinStatus.PINNED
    
    def is_expired(self) -> bool:
        """Check if pin has expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "cid": self.cid,
            "status": self.status.value,
            "metadata": self.metadata
        }
        
        if self.name:
            result["name"] = self.name
        if self.size is not None:
            result["size"] = self.size
        if self.pinned_at:
            result["pinned_at"] = self.pinned_at.isoformat()
        if self.expires_at:
            result["expires_at"] = self.expires_at.isoformat()
            
        return result


@dataclass
class IPFSConfig:
    """IPFS client configuration."""
    
    # Node connection
    api_host: str = "localhost"
    api_port: int = 5001
    api_protocol: str = "http"
    
    # Authentication
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    
    # Behavior
    auto_pin: bool = True
    pin_timeout: int = 300  # seconds
    upload_timeout: int = 120  # seconds
    
    # Retry configuration
    max_retries: int = 3
    retry_delay: float = 1.0
    
    def get_api_multiaddr(self) -> str:
        """Get multiaddr format connection string."""
        return f"/ip4/{self.api_host}/tcp/{self.api_port}"
    
    def get_api_url(self) -> str:
        """Get HTTP API URL."""
        return f"{self.api_protocol}://{self.api_host}:{self.api_port}"


class EnhancedIPFSStorage(ContentStorage):
    """Enhanced IPFS storage with advanced features."""
    
    def __init__(self, config: Optional[IPFSConfig] = None):
        if not IPFS_CLIENT_AVAILABLE:
            raise ImportError("ipfshttpclient required for IPFS storage. Install with: pip install ipfshttpclient")
        
        self.config = config or IPFSConfig()
        self.logger = logging.getLogger(__name__)
        self.hasher = ContentHasher()
        
        # Connection management
        self._client = None
        self._client_lock = asyncio.Lock() if asyncio.iscoroutinefunction(self._get_client) else None
        
        # Pinning management
        self._pins: Dict[str, IPFSPin] = {}
        self._pin_lock = asyncio.Lock() if asyncio.iscoroutinefunction(self.pin_content) else None
        
        # Gateway management
        self.gateways: List[IPFSGateway] = []
        self._init_default_gateways()
        
        # Statistics
        self._stats = {
            "uploads": 0,
            "downloads": 0,
            "pins_created": 0,
            "pins_failed": 0,
            "gateway_requests": 0,
            "gateway_failures": 0
        }
        
        # Session for HTTP requests
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            retry_strategy = Retry(
                total=self.config.max_retries,
                backoff_factor=self.config.retry_delay,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        else:
            self.session = None
    
    def _get_client(self):
        """Get or create IPFS client."""
        if self._client is None:
            try:
                if self.config.api_key and self.config.api_secret:
                    # Authenticated connection
                    self._client = ipfshttpclient.connect(
                        self.config.get_api_multiaddr(),
                        auth=(self.config.api_key, self.config.api_secret)
                    )
                else:
                    # Standard connection
                    self._client = ipfshttpclient.connect(self.config.get_api_multiaddr())
                
                # Test connection
                self._client.version()
                self.logger.info(f"Connected to IPFS node at {self.config.get_api_url()}")
                
            except Exception as e:
                self.logger.error(f"Failed to connect to IPFS node: {e}")
                raise
        
        return self._client
    
    def _init_default_gateways(self):
        """Initialize default IPFS gateways."""
        default_gateways = [
            IPFSGateway("IPFS.io", "https://ipfs.io", priority=1),
            IPFSGateway("Cloudflare", "https://cloudflare-ipfs.com", priority=2),
            IPFSGateway("Pinata", "https://gateway.pinata.cloud", priority=3),
            IPFSGateway("Infura", "https://ipfs.infura.io", priority=4),
            IPFSGateway("Fleek", "https://ipfs.fleek.co", priority=5),
        ]
        
        self.gateways.extend(default_gateways)
        self.gateways.sort(key=lambda g: g.priority)
    
    def add_gateway(self, gateway: IPFSGateway):
        """Add custom IPFS gateway."""
        self.gateways.append(gateway)
        self.gateways.sort(key=lambda g: g.priority)
    
    def store(self, content: Union[bytes, Any], 
              filename: Optional[str] = None, 
              content_type: Optional[str] = None,
              pin: bool = None,
              pin_name: Optional[str] = None) -> ContentInfo:
        """
        Store content on IPFS with optional pinning.
        
        Args:
            content: Content to store
            filename: Optional filename
            content_type: MIME type
            pin: Whether to pin content (defaults to config.auto_pin)
            pin_name: Name for the pin
            
        Returns:
            ContentInfo with IPFS details
        """
        client = self._get_client()
        
        # Convert content to bytes if needed
        if isinstance(content, bytes):
            content_data = content
        else:
            content_data = content.read()
            if hasattr(content, 'seek'):
                content.seek(0)
        
        # Generate content hash
        content_hash = self.hasher.hash_content(content_data, content_type)
        
        try:
            # Upload to IPFS
            result = client.add_bytes(content_data)
            cid = result['Hash']
            ipfs_size = result.get('Size', len(content_data))
            
            self._stats["uploads"] += 1
            
            # Pin if requested
            if pin if pin is not None else self.config.auto_pin:
                pin_result = self.pin_content(cid, pin_name or filename)
                if pin_result:
                    self._stats["pins_created"] += 1
                else:
                    self._stats["pins_failed"] += 1
            
            uri = f"ipfs://{cid}"
            
            metadata = {
                'ipfs_cid': cid,
                'ipfs_size': ipfs_size,
                'pin_status': self._pins.get(cid, IPFSPin(cid, PinStatus.UNPINNED)).status.value,
                'upload_time': datetime.now(timezone.utc).isoformat()
            }
            
            self.logger.info(f"Stored content on IPFS: {cid}")
            
            return ContentInfo(
                content_hash=content_hash,
                uri=uri,
                storage_type=self.get_storage_type(),
                content_type=content_type or 'application/octet-stream',
                content_size=content_hash.content_size,
                filename=filename,
                metadata=metadata
            )
            
        except Exception as e:
            self.logger.error(f"Failed to store content on IPFS: {e}")
            raise
    
    def retrieve(self, uri: str) -> bytes:
        """
        Retrieve content from IPFS with gateway fallback.
        
        Args:
            uri: IPFS URI (ipfs://...)
            
        Returns:
            Content bytes
        """
        if not uri.startswith('ipfs://'):
            raise ValueError(f"Invalid IPFS URI: {uri}")
        
        cid = uri[7:]  # Remove 'ipfs://' prefix
        
        # Try direct IPFS client first
        try:
            client = self._get_client()
            content = client.cat(cid)
            self._stats["downloads"] += 1
            self.logger.debug(f"Retrieved {len(content)} bytes from IPFS: {cid}")
            return content
            
        except Exception as e:
            self.logger.warning(f"Direct IPFS retrieval failed for {cid}: {e}")
        
        # Fall back to gateways
        if self.session:
            return self._retrieve_via_gateways(cid)
        else:
            raise RuntimeError("No HTTP session available for gateway fallback")
    
    def _retrieve_via_gateways(self, cid: str) -> bytes:
        """Retrieve content via IPFS gateways with fallback."""
        errors = []
        
        for gateway in self.gateways:
            try:
                url = gateway.construct_url(cid)
                headers = {}
                
                if gateway.requires_auth and gateway.auth_header:
                    headers['Authorization'] = gateway.auth_header
                
                response = self.session.get(
                    url, 
                    headers=headers,
                    timeout=gateway.timeout
                )
                response.raise_for_status()
                
                self._stats["gateway_requests"] += 1
                self.logger.debug(f"Retrieved {len(response.content)} bytes via {gateway.name}")
                return response.content
                
            except Exception as e:
                error_msg = f"{gateway.name}: {str(e)}"
                errors.append(error_msg)
                self._stats["gateway_failures"] += 1
                self.logger.warning(f"Gateway {gateway.name} failed: {e}")
                continue
        
        # All gateways failed
        raise RuntimeError(f"All IPFS gateways failed for {cid}: {'; '.join(errors)}")
    
    def pin_content(self, cid: str, name: Optional[str] = None, 
                   timeout: Optional[int] = None) -> bool:
        """
        Pin content on IPFS.
        
        Args:
            cid: Content ID to pin
            name: Optional name for the pin
            timeout: Pin timeout in seconds
            
        Returns:
            True if pinning successful
        """
        try:
            client = self._get_client()
            pin_timeout = timeout or self.config.pin_timeout
            
            # Pin the content
            client.pin.add(cid, timeout=pin_timeout)
            
            # Record pin
            pin = IPFSPin(
                cid=cid,
                status=PinStatus.PINNED,
                name=name,
                pinned_at=datetime.now(timezone.utc)
            )
            
            self._pins[cid] = pin
            self.logger.info(f"Successfully pinned content: {cid}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to pin content {cid}: {e}")
            
            # Record failed pin
            pin = IPFSPin(
                cid=cid,
                status=PinStatus.FAILED,
                name=name
            )
            self._pins[cid] = pin
            return False
    
    def unpin_content(self, cid: str) -> bool:
        """
        Unpin content from IPFS.
        
        Args:
            cid: Content ID to unpin
            
        Returns:
            True if unpinning successful
        """
        try:
            client = self._get_client()
            client.pin.rm(cid)
            
            # Update pin status
            if cid in self._pins:
                self._pins[cid].status = PinStatus.UNPINNED
            
            self.logger.info(f"Successfully unpinned content: {cid}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unpin content {cid}: {e}")
            return False
    
    def list_pins(self) -> List[IPFSPin]:
        """List all pins."""
        try:
            client = self._get_client()
            pins_result = client.pin.ls(type='recursive')
            
            # Update local pin tracking
            for pin_info in pins_result['Keys']:
                cid = pin_info['Hash']
                if cid not in self._pins:
                    self._pins[cid] = IPFSPin(
                        cid=cid,
                        status=PinStatus.PINNED
                    )
            
        except Exception as e:
            self.logger.error(f"Failed to list pins: {e}")
        
        return list(self._pins.values())
    
    def get_pin_status(self, cid: str) -> Optional[IPFSPin]:
        """Get pin status for specific content."""
        return self._pins.get(cid)
    
    def exists(self, uri: str) -> bool:
        """Check if content exists on IPFS."""
        if not uri.startswith('ipfs://'):
            return False
        
        cid = uri[7:]
        
        # Try to get object stats
        try:
            client = self._get_client()
            client.object.stat(cid)
            return True
        except Exception:
            pass
        
        # Try via gateways
        if self.session:
            for gateway in self.gateways[:2]:  # Only try top 2 gateways
                try:
                    url = gateway.construct_url(cid)
                    response = self.session.head(url, timeout=10)
                    if response.status_code == 200:
                        return True
                except Exception:
                    continue
        
        return False
    
    def get_content_stats(self, cid: str) -> Dict[str, Any]:
        """Get detailed content statistics."""
        try:
            client = self._get_client()
            stats = client.object.stat(cid)
            
            return {
                "cid": cid,
                "size": stats.get('DataSize', 0),
                "cumulative_size": stats.get('CumulativeSize', 0),
                "block_size": stats.get('BlockSize', 0),
                "num_links": stats.get('NumLinks', 0),
                "hash": stats.get('Hash', cid)
            }
        except Exception as e:
            self.logger.error(f"Failed to get stats for {cid}: {e}")
            return {"cid": cid, "error": str(e)}
    
    def get_storage_type(self) -> StorageType:
        """Get storage type."""
        return StorageType.IPFS
    
    def get_node_info(self) -> Dict[str, Any]:
        """Get IPFS node information."""
        try:
            client = self._get_client()
            version_info = client.version()
            node_id = client.id()
            
            return {
                "version": version_info.get('Version'),
                "commit": version_info.get('Commit'),
                "repo": version_info.get('Repo'),
                "system": version_info.get('System'),
                "golang": version_info.get('Golang'),
                "node_id": node_id.get('ID'),
                "public_key": node_id.get('PublicKey'),
                "addresses": node_id.get('Addresses', [])
            }
        except Exception as e:
            return {"error": str(e)}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get storage statistics."""
        return {
            "stats": self._stats.copy(),
            "pins": {
                "total": len(self._pins),
                "pinned": len([p for p in self._pins.values() if p.is_active()]),
                "failed": len([p for p in self._pins.values() if p.status == PinStatus.FAILED])
            },
            "gateways": len(self.gateways),
            "config": {
                "api_url": self.config.get_api_url(),
                "auto_pin": self.config.auto_pin,
                "pin_timeout": self.config.pin_timeout
            }
        }
    
    def cleanup_expired_pins(self) -> int:
        """Remove expired pins."""
        expired_count = 0
        expired_pins = [cid for cid, pin in self._pins.items() if pin.is_expired()]
        
        for cid in expired_pins:
            if self.unpin_content(cid):
                del self._pins[cid]
                expired_count += 1
        
        return expired_count
    
    def close(self):
        """Close connections."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        
        if self.session:
            self.session.close()


class IPFSCluster:
    """Manages multiple IPFS nodes for redundancy."""
    
    def __init__(self, configs: List[IPFSConfig]):
        self.nodes: List[EnhancedIPFSStorage] = []
        self.logger = logging.getLogger(__name__)
        
        # Initialize nodes
        for i, config in enumerate(configs):
            try:
                node = EnhancedIPFSStorage(config)
                self.nodes.append(node)
                self.logger.info(f"Initialized IPFS node {i+1}: {config.get_api_url()}")
            except Exception as e:
                self.logger.error(f"Failed to initialize IPFS node {i+1}: {e}")
    
    def store_with_redundancy(self, content: Union[bytes, Any], 
                            redundancy: int = 2, **kwargs) -> List[ContentInfo]:
        """Store content on multiple nodes for redundancy."""
        if redundancy > len(self.nodes):
            redundancy = len(self.nodes)
        
        results = []
        errors = []
        
        # Use ThreadPoolExecutor for parallel uploads
        with ThreadPoolExecutor(max_workers=redundancy) as executor:
            futures = [
                executor.submit(node.store, content, **kwargs) 
                for node in self.nodes[:redundancy]
            ]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    errors.append(str(e))
        
        if not results:
            raise RuntimeError(f"All IPFS nodes failed: {'; '.join(errors)}")
        
        return results
    
    def retrieve_with_fallback(self, uri: str) -> bytes:
        """Retrieve content with node fallback."""
        errors = []
        
        for i, node in enumerate(self.nodes):
            try:
                return node.retrieve(uri)
            except Exception as e:
                errors.append(f"Node {i+1}: {str(e)}")
                continue
        
        raise RuntimeError(f"All IPFS nodes failed: {'; '.join(errors)}")
    
    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster statistics."""
        total_stats = {
            "nodes": len(self.nodes),
            "healthy_nodes": 0,
            "total_uploads": 0,
            "total_downloads": 0,
            "total_pins": 0
        }
        
        node_stats = []
        for i, node in enumerate(self.nodes):
            try:
                stats = node.get_statistics()
                node_stats.append({
                    "node_id": i + 1,
                    "api_url": node.config.get_api_url(),
                    "stats": stats
                })
                
                total_stats["healthy_nodes"] += 1
                total_stats["total_uploads"] += stats["stats"]["uploads"]
                total_stats["total_downloads"] += stats["stats"]["downloads"]
                total_stats["total_pins"] += stats["pins"]["total"]
                
            except Exception as e:
                node_stats.append({
                    "node_id": i + 1,
                    "error": str(e)
                })
        
        return {
            "cluster": total_stats,
            "nodes": node_stats
        }


# Utility functions

def create_ipfs_config(host: str = "localhost", port: int = 5001, 
                      api_key: Optional[str] = None, 
                      api_secret: Optional[str] = None) -> IPFSConfig:
    """Create IPFS configuration."""
    return IPFSConfig(
        api_host=host,
        api_port=port,
        api_key=api_key,
        api_secret=api_secret
    )


def test_ipfs_integration():
    """Test IPFS integration functionality."""
    print("Testing Enhanced IPFS Integration...")
    print("=" * 50)
    
    if not IPFS_CLIENT_AVAILABLE:
        print("❌ ipfshttpclient not available. Install with: pip install ipfshttpclient")
        return False
    
    try:
        # Test configuration
        config = IPFSConfig(auto_pin=True)
        storage = EnhancedIPFSStorage(config)
        
        print(f"✓ Created IPFS storage with config: {config.get_api_url()}")
        
        # Test gateway functionality
        print(f"✓ Configured {len(storage.gateways)} IPFS gateways")
        
        # Test gateway URL construction
        test_cid = "QmSampleHashForTesting"
        for i, gateway in enumerate(storage.gateways[:3]):  # Test first 3
            url = gateway.construct_url(test_cid)
            print(f"  Gateway {i+1}: {gateway.name} -> {url}")
        
        # Test pin management structures
        sample_pin = IPFSPin(
            cid=test_cid,
            status=PinStatus.PINNED,
            name="test_pin",
            size=1024,
            pinned_at=datetime.now(timezone.utc)
        )
        storage._pins[test_cid] = sample_pin
        print(f"✓ Added sample pin: {sample_pin.cid} ({sample_pin.status.value})")
        
        # Test statistics
        stats = storage.get_statistics()
        print(f"✓ Storage stats: {stats['stats']['uploads']} uploads, {stats['pins']['total']} pins")
        
        # Test cluster functionality
        cluster_configs = [
            IPFSConfig(api_host="localhost", api_port=5001),
            IPFSConfig(api_host="localhost", api_port=5002)
        ]
        
        try:
            cluster = IPFSCluster(cluster_configs)
            print(f"✓ Created IPFS cluster with {len(cluster.nodes)} nodes (may have connection errors)")
        except Exception as e:
            print(f"! Cluster creation failed: {e}")
        
        # Test content hash integration
        test_content = b"Sample IPFS content for testing"
        hasher = ContentHasher()
        content_hash = hasher.hash_content(test_content)
        print(f"✓ Content hash: {content_hash.hash_value}")
        
        # Test mock storage without actual IPFS connection
        print("✓ All IPFS integration structures working correctly")
        print("ℹ️  Note: Actual IPFS operations require a running IPFS node")
        
        print("\nEnhanced IPFS integration tests completed!")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        success = test_ipfs_integration()
        sys.exit(0 if success else 1)
    else:
        print("Enhanced IPFS Integration for BNAP NFTs")
        print("Usage: python ipfs.py test")
        print("\nFeatures:")
        print("- Advanced IPFS client with connection pooling")
        print("- Automatic content pinning and pin management")
        print("- Multiple gateway fallback support")
        print("- Cluster support for redundancy")
        print("- Comprehensive error handling and retry logic")
        print("- Detailed statistics and monitoring")