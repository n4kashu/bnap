"""
Bitcoin Native Asset Protocol - Proof Caching and Optimization System

This module provides advanced caching and optimization features for Merkle proofs
including LRU caching, batch optimization, proof compression, and performance monitoring.
"""

import hashlib
import json
import logging
import time
import threading
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from collections import OrderedDict
import weakref
import pickle
import gzip
from pathlib import Path

try:
    from .merkle import MerkleProof, MerkleTree, MerkleHasher
    from .allowlist import AllowlistManager
except ImportError:
    # For standalone testing
    from merkle import MerkleProof, MerkleTree, MerkleHasher
    from allowlist import AllowlistManager


class CacheStrategy(Enum):
    """Caching strategies for proof storage."""
    LRU = "lru"           # Least Recently Used
    LFU = "lfu"           # Least Frequently Used
    TTL = "ttl"           # Time To Live
    ADAPTIVE = "adaptive" # Adaptive strategy based on usage patterns


class CompressionType(Enum):
    """Types of proof compression."""
    NONE = "none"
    GZIP = "gzip"
    PICKLE = "pickle"
    CUSTOM = "custom"


@dataclass
class CacheStats:
    """Statistics for cache performance monitoring."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_requests: int = 0
    cache_size: int = 0
    max_size: int = 0
    hit_rate: float = 0.0
    average_proof_size: float = 0.0
    total_memory_usage: int = 0
    
    def update_hit_rate(self):
        """Update hit rate calculation."""
        if self.total_requests > 0:
            self.hit_rate = self.hits / self.total_requests
        else:
            self.hit_rate = 0.0


@dataclass
class CachedProof:
    """Represents a cached Merkle proof with metadata."""
    proof: MerkleProof
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    compressed_size: Optional[int] = None
    compression_type: CompressionType = CompressionType.NONE
    
    def __post_init__(self):
        """Initialize additional fields."""
        if not self.last_accessed:
            self.last_accessed = self.created_at
    
    def mark_accessed(self):
        """Mark proof as accessed."""
        self.last_accessed = datetime.now(timezone.utc)
        self.access_count += 1
    
    def get_age_seconds(self) -> float:
        """Get age of cached proof in seconds."""
        return (datetime.now(timezone.utc) - self.created_at).total_seconds()
    
    def get_idle_time_seconds(self) -> float:
        """Get idle time since last access in seconds."""
        return (datetime.now(timezone.utc) - self.last_accessed).total_seconds()


class ProofCompressor:
    """Handles compression and decompression of Merkle proofs."""
    
    def __init__(self, compression_type: CompressionType = CompressionType.GZIP):
        """Initialize proof compressor."""
        self.compression_type = compression_type
        self.logger = logging.getLogger(__name__)
    
    def compress_proof(self, proof: MerkleProof) -> Tuple[bytes, int]:
        """
        Compress a Merkle proof.
        
        Args:
            proof: MerkleProof to compress
            
        Returns:
            Tuple of (compressed_data, original_size)
        """
        # Serialize proof to bytes
        proof_data = self._serialize_proof(proof)
        original_size = len(proof_data)
        
        if self.compression_type == CompressionType.NONE:
            return proof_data, original_size
        
        elif self.compression_type == CompressionType.GZIP:
            compressed_data = gzip.compress(proof_data)
            
        elif self.compression_type == CompressionType.PICKLE:
            compressed_data = gzip.compress(pickle.dumps(proof))
            
        else:
            # Custom compression (simple run-length encoding for demonstration)
            compressed_data = self._custom_compress(proof_data)
        
        compression_ratio = len(compressed_data) / original_size
        self.logger.debug(f"Compressed proof: {original_size} -> {len(compressed_data)} bytes ({compression_ratio:.2f}x)")
        
        return compressed_data, original_size
    
    def decompress_proof(self, compressed_data: bytes, original_size: int) -> MerkleProof:
        """
        Decompress a Merkle proof.
        
        Args:
            compressed_data: Compressed proof data
            original_size: Original size before compression
            
        Returns:
            Decompressed MerkleProof
        """
        if self.compression_type == CompressionType.NONE:
            proof_data = compressed_data
            
        elif self.compression_type == CompressionType.GZIP:
            proof_data = gzip.decompress(compressed_data)
            
        elif self.compression_type == CompressionType.PICKLE:
            return pickle.loads(gzip.decompress(compressed_data))
            
        else:
            # Custom decompression
            proof_data = self._custom_decompress(compressed_data)
        
        return self._deserialize_proof(proof_data)
    
    def _serialize_proof(self, proof: MerkleProof) -> bytes:
        """Serialize MerkleProof to bytes."""
        # Create a dictionary representation
        proof_dict = {
            'leaf_data': proof.leaf_data.hex(),
            'leaf_hash': proof.leaf_hash.hex(),
            'proof_hashes': [h.hex() for h in proof.proof_hashes],
            'proof_indices': proof.proof_indices,
            'root_hash': proof.root_hash.hex(),
            'leaf_index': proof.leaf_index,
            'tree_size': proof.tree_size
        }
        
        # Convert to JSON and then to bytes
        json_str = json.dumps(proof_dict, separators=(',', ':'))
        return json_str.encode('utf-8')
    
    def _deserialize_proof(self, proof_data: bytes) -> MerkleProof:
        """Deserialize bytes to MerkleProof."""
        # Parse JSON
        json_str = proof_data.decode('utf-8')
        proof_dict = json.loads(json_str)
        
        # Convert hex strings back to bytes
        return MerkleProof(
            leaf_data=bytes.fromhex(proof_dict['leaf_data']),
            leaf_hash=bytes.fromhex(proof_dict['leaf_hash']),
            proof_hashes=[bytes.fromhex(h) for h in proof_dict['proof_hashes']],
            proof_indices=proof_dict['proof_indices'],
            root_hash=bytes.fromhex(proof_dict['root_hash']),
            leaf_index=proof_dict['leaf_index'],
            tree_size=proof_dict['tree_size']
        )
    
    def _custom_compress(self, data: bytes) -> bytes:
        """Custom compression implementation (simple RLE)."""
        compressed = bytearray()
        i = 0
        while i < len(data):
            count = 1
            current_byte = data[i]
            
            # Count consecutive identical bytes
            while i + count < len(data) and data[i + count] == current_byte and count < 255:
                count += 1
            
            # Store count and byte
            compressed.append(count)
            compressed.append(current_byte)
            i += count
        
        return bytes(compressed)
    
    def _custom_decompress(self, data: bytes) -> bytes:
        """Custom decompression implementation."""
        decompressed = bytearray()
        i = 0
        while i < len(data) - 1:
            count = data[i]
            byte_value = data[i + 1]
            decompressed.extend([byte_value] * count)
            i += 2
        
        return bytes(decompressed)


class LRUProofCache:
    """
    LRU (Least Recently Used) cache for Merkle proofs with compression support.
    """
    
    def __init__(
        self,
        max_size: int = 1000,
        ttl_seconds: Optional[int] = None,
        compression_type: CompressionType = CompressionType.GZIP
    ):
        """
        Initialize LRU proof cache.
        
        Args:
            max_size: Maximum number of proofs to cache
            ttl_seconds: Time-to-live for cached proofs (None = no expiration)
            compression_type: Type of compression to use
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.compression_type = compression_type
        
        # Thread-safe cache storage
        self._cache: OrderedDict[str, CachedProof] = OrderedDict()
        self._lock = threading.RLock()
        
        # Statistics
        self.stats = CacheStats(max_size=max_size)
        
        # Compression
        self.compressor = ProofCompressor(compression_type)
        
        # Background cleanup
        self._cleanup_thread = None
        self._shutdown = False
        
        self.logger = logging.getLogger(__name__)
        
        if ttl_seconds:
            self._start_cleanup_thread()
    
    def get(self, key: str) -> Optional[MerkleProof]:
        """
        Get a proof from cache.
        
        Args:
            key: Cache key (typically address or hash)
            
        Returns:
            MerkleProof if found and valid, None otherwise
        """
        with self._lock:
            self.stats.total_requests += 1
            
            cached_proof = self._cache.get(key)
            if cached_proof is None:
                self.stats.misses += 1
                self.stats.update_hit_rate()
                return None
            
            # Check TTL expiration
            if self._is_expired(cached_proof):
                self._remove_key(key)
                self.stats.misses += 1
                self.stats.evictions += 1
                self.stats.update_hit_rate()
                return None
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            cached_proof.mark_accessed()
            
            self.stats.hits += 1
            self.stats.update_hit_rate()
            
            return cached_proof.proof
    
    def put(self, key: str, proof: MerkleProof) -> bool:
        """
        Put a proof in cache.
        
        Args:
            key: Cache key
            proof: MerkleProof to cache
            
        Returns:
            True if successfully cached
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            
            # Create cached proof entry
            cached_proof = CachedProof(
                proof=proof,
                created_at=now,
                last_accessed=now,
                compression_type=self.compression_type
            )
            
            # Handle compression if enabled
            if self.compression_type != CompressionType.NONE:
                try:
                    compressed_data, original_size = self.compressor.compress_proof(proof)
                    cached_proof.compressed_size = len(compressed_data)
                except Exception as e:
                    self.logger.warning(f"Compression failed for key {key}: {e}")
                    return False
            
            # Check if we need to evict
            if key not in self._cache and len(self._cache) >= self.max_size:
                self._evict_lru()
            
            # Add/update entry
            self._cache[key] = cached_proof
            self._cache.move_to_end(key)
            
            # Update stats
            self.stats.cache_size = len(self._cache)
            self._update_memory_stats()
            
            return True
    
    def invalidate(self, key: str) -> bool:
        """
        Invalidate a specific cache entry.
        
        Args:
            key: Cache key to invalidate
            
        Returns:
            True if entry was found and removed
        """
        with self._lock:
            if key in self._cache:
                self._remove_key(key)
                return True
            return False
    
    def clear(self):
        """Clear all cached proofs."""
        with self._lock:
            self._cache.clear()
            self.stats.cache_size = 0
            self.stats.total_memory_usage = 0
    
    def get_statistics(self) -> CacheStats:
        """Get current cache statistics."""
        with self._lock:
            self._update_memory_stats()
            return self.stats
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        if not self.ttl_seconds:
            return 0
        
        removed_count = 0
        with self._lock:
            expired_keys = []
            
            for key, cached_proof in self._cache.items():
                if self._is_expired(cached_proof):
                    expired_keys.append(key)
            
            for key in expired_keys:
                self._remove_key(key)
                removed_count += 1
                self.stats.evictions += 1
        
        if removed_count > 0:
            self.logger.debug(f"Cleaned up {removed_count} expired cache entries")
        
        return removed_count
    
    def get_cache_keys(self) -> List[str]:
        """Get all cache keys."""
        with self._lock:
            return list(self._cache.keys())
    
    def get_cache_info(self, key: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a cached entry."""
        with self._lock:
            cached_proof = self._cache.get(key)
            if not cached_proof:
                return None
            
            return {
                "created_at": cached_proof.created_at.isoformat(),
                "last_accessed": cached_proof.last_accessed.isoformat(),
                "access_count": cached_proof.access_count,
                "age_seconds": cached_proof.get_age_seconds(),
                "idle_time_seconds": cached_proof.get_idle_time_seconds(),
                "compression_type": cached_proof.compression_type.value,
                "compressed_size": cached_proof.compressed_size,
                "proof_path_length": cached_proof.proof.get_path_length()
            }
    
    def _evict_lru(self):
        """Evict least recently used entry."""
        if self._cache:
            lru_key = next(iter(self._cache))
            self._remove_key(lru_key)
            self.stats.evictions += 1
    
    def _remove_key(self, key: str):
        """Remove key from cache and update stats."""
        if key in self._cache:
            del self._cache[key]
            self.stats.cache_size = len(self._cache)
    
    def _is_expired(self, cached_proof: CachedProof) -> bool:
        """Check if cached proof has expired."""
        if not self.ttl_seconds:
            return False
        
        return cached_proof.get_age_seconds() > self.ttl_seconds
    
    def _update_memory_stats(self):
        """Update memory usage statistics."""
        total_memory = 0
        total_proof_sizes = 0
        
        for cached_proof in self._cache.values():
            if cached_proof.compressed_size:
                total_memory += cached_proof.compressed_size
                total_proof_sizes += cached_proof.compressed_size
            else:
                # Estimate uncompressed size
                estimated_size = len(cached_proof.proof.proof_hashes) * 32 + 200
                total_memory += estimated_size
                total_proof_sizes += estimated_size
        
        self.stats.total_memory_usage = total_memory
        if len(self._cache) > 0:
            self.stats.average_proof_size = total_proof_sizes / len(self._cache)
    
    def _start_cleanup_thread(self):
        """Start background thread for cleanup."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        def cleanup_worker():
            while not self._shutdown:
                try:
                    time.sleep(60)  # Cleanup every minute
                    if not self._shutdown:
                        self.cleanup_expired()
                except Exception as e:
                    self.logger.error(f"Cache cleanup error: {e}")
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
    
    def shutdown(self):
        """Shutdown cache and cleanup threads."""
        self._shutdown = True
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=1.0)


class AdaptiveProofCache:
    """
    Adaptive cache that adjusts strategy based on usage patterns.
    """
    
    def __init__(self, max_size: int = 1000):
        """Initialize adaptive cache."""
        self.max_size = max_size
        self.logger = logging.getLogger(__name__)
        
        # Multiple cache strategies
        self.lru_cache = LRUProofCache(max_size // 2, compression_type=CompressionType.GZIP)
        self.lfu_cache = {}  # Simple LFU implementation
        self.access_patterns = {}
        
        # Strategy selection
        self.current_strategy = CacheStrategy.LRU
        self.strategy_stats = {strategy: CacheStats() for strategy in CacheStrategy}
        
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[MerkleProof]:
        """Get proof using adaptive strategy."""
        with self._lock:
            # Record access pattern
            self._record_access(key)
            
            # Try current strategy first
            if self.current_strategy == CacheStrategy.LRU:
                return self.lru_cache.get(key)
            
            # Add other strategies as needed
            return None
    
    def put(self, key: str, proof: MerkleProof) -> bool:
        """Put proof using adaptive strategy."""
        with self._lock:
            if self.current_strategy == CacheStrategy.LRU:
                return self.lru_cache.put(key, proof)
            
            return False
    
    def _record_access(self, key: str):
        """Record access pattern for adaptive optimization."""
        now = datetime.now(timezone.utc)
        
        if key not in self.access_patterns:
            self.access_patterns[key] = {
                'count': 0,
                'first_access': now,
                'last_access': now
            }
        
        pattern = self.access_patterns[key]
        pattern['count'] += 1
        pattern['last_access'] = now
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get adaptive cache statistics."""
        return {
            'current_strategy': self.current_strategy.value,
            'lru_stats': self.lru_cache.get_statistics().__dict__,
            'access_patterns': len(self.access_patterns),
            'strategy_effectiveness': self._calculate_strategy_effectiveness()
        }
    
    def _calculate_strategy_effectiveness(self) -> Dict[str, float]:
        """Calculate effectiveness of different caching strategies."""
        # This would implement ML-based strategy selection
        # For now, return simple metrics
        return {
            'lru_effectiveness': self.lru_cache.stats.hit_rate,
            'lfu_effectiveness': 0.0,  # Placeholder
            'ttl_effectiveness': 0.0   # Placeholder
        }


class BatchProofOptimizer:
    """
    Optimizes batch proof operations for better performance.
    """
    
    def __init__(self, cache: LRUProofCache):
        """Initialize batch optimizer."""
        self.cache = cache
        self.logger = logging.getLogger(__name__)
    
    def generate_batch_proofs(
        self, 
        tree: MerkleTree, 
        addresses: List[str],
        use_cache: bool = True
    ) -> Dict[str, Optional[MerkleProof]]:
        """
        Generate proofs for multiple addresses with optimization.
        
        Args:
            tree: MerkleTree to generate proofs from
            addresses: List of addresses to generate proofs for
            use_cache: Whether to use caching
            
        Returns:
            Dictionary mapping address to proof
        """
        results = {}
        cache_hits = 0
        cache_misses = 0
        
        # Normalize addresses
        normalized_addresses = []
        for addr in addresses:
            normalized = addr.strip().lower() if addr.startswith('bc1') else addr.strip()
            normalized_addresses.append(normalized)
        
        # Check cache for existing proofs
        addresses_to_generate = []
        
        if use_cache:
            for addr in normalized_addresses:
                cached_proof = self.cache.get(addr)
                if cached_proof:
                    results[addr] = cached_proof
                    cache_hits += 1
                else:
                    addresses_to_generate.append(addr)
                    cache_misses += 1
        else:
            addresses_to_generate = normalized_addresses
        
        # Generate missing proofs
        if addresses_to_generate:
            # Convert to bytes for tree lookup
            addr_data = [addr.encode('utf-8') for addr in addresses_to_generate]
            
            # Use tree's batch proof generation
            batch_proofs = tree.generate_batch_proofs(addr_data)
            
            # Process results and cache
            for addr_bytes, proof in batch_proofs.items():
                addr = addr_bytes.decode('utf-8')
                results[addr] = proof
                
                if proof and use_cache:
                    self.cache.put(addr, proof)
        
        self.logger.debug(
            f"Batch proof generation: {len(addresses)} total, "
            f"{cache_hits} cache hits, {cache_misses} cache misses, "
            f"{len(addresses_to_generate)} generated"
        )
        
        return results
    
    def prefetch_proofs(
        self, 
        tree: MerkleTree, 
        likely_addresses: List[str],
        priority_addresses: Optional[List[str]] = None
    ):
        """
        Prefetch proofs for addresses likely to be requested.
        
        Args:
            tree: MerkleTree to generate proofs from
            likely_addresses: Addresses likely to be requested soon
            priority_addresses: High-priority addresses to cache first
        """
        # Process priority addresses first
        if priority_addresses:
            self.generate_batch_proofs(tree, priority_addresses, use_cache=True)
        
        # Then process likely addresses in batches
        batch_size = 50
        for i in range(0, len(likely_addresses), batch_size):
            batch = likely_addresses[i:i + batch_size]
            self.generate_batch_proofs(tree, batch, use_cache=True)
            
            # Small delay to prevent overwhelming the system
            time.sleep(0.01)


# Convenience functions

def create_optimized_cache(
    max_size: int = 1000,
    ttl_seconds: Optional[int] = 3600,  # 1 hour default
    compression: bool = True
) -> LRUProofCache:
    """
    Create an optimized proof cache with recommended settings.
    
    Args:
        max_size: Maximum cache size
        ttl_seconds: Time-to-live in seconds
        compression: Enable compression
        
    Returns:
        Configured LRUProofCache
    """
    compression_type = CompressionType.GZIP if compression else CompressionType.NONE
    return LRUProofCache(max_size, ttl_seconds, compression_type)


def benchmark_cache_performance(
    cache: LRUProofCache,
    tree: MerkleTree,
    test_addresses: List[str],
    iterations: int = 1000
) -> Dict[str, Any]:
    """
    Benchmark cache performance with real proof operations.
    
    Args:
        cache: Cache to benchmark
        tree: MerkleTree for proof generation
        test_addresses: Addresses to use for testing
        iterations: Number of test iterations
        
    Returns:
        Performance metrics
    """
    import random
    
    start_time = time.time()
    
    # Warm up cache
    for addr in test_addresses[:10]:
        proof = tree.generate_proof_for_address(addr)
        if proof:
            cache.put(addr, proof)
    
    # Benchmark random accesses
    cache_ops = []
    for _ in range(iterations):
        addr = random.choice(test_addresses)
        
        op_start = time.time()
        proof = cache.get(addr)
        
        if proof is None:
            # Generate and cache
            proof = tree.generate_proof_for_address(addr)
            if proof:
                cache.put(addr, proof)
        
        op_time = time.time() - op_start
        cache_ops.append(op_time)
    
    total_time = time.time() - start_time
    stats = cache.get_statistics()
    
    return {
        'total_time_seconds': total_time,
        'average_op_time_ms': (sum(cache_ops) / len(cache_ops)) * 1000,
        'operations_per_second': iterations / total_time,
        'cache_hit_rate': stats.hit_rate,
        'cache_size': stats.cache_size,
        'memory_usage_bytes': stats.total_memory_usage,
        'cache_efficiency': stats.hits / (stats.hits + stats.misses) if (stats.hits + stats.misses) > 0 else 0
    }


# Testing and utilities

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("Testing Proof Caching and Optimization System...")
        
        # Create test cache
        cache = create_optimized_cache(max_size=100, ttl_seconds=60, compression=True)
        
        # Create test tree with known addresses
        test_addresses = [f"bc1qtest{i:010d}" for i in range(20)]
        
        from merkle import MerkleTree
        tree = MerkleTree()
        tree.build_from_addresses(test_addresses)
        
        # Generate some proofs
        for addr in test_addresses[:5]:
            proof = tree.generate_proof_for_address(addr)
            if proof:
                success = cache.put(addr, proof)
                print(f"✓ Cached proof for {addr}: {'success' if success else 'failed'}")
        
        # Test cache retrieval
        for addr in test_addresses[:5]:
            cached_proof = cache.get(addr)
            print(f"✓ Retrieved proof for {addr}: {'found' if cached_proof else 'not found'}")
        
        # Test batch optimization
        optimizer = BatchProofOptimizer(cache)
        batch_results = optimizer.generate_batch_proofs(tree, test_addresses[:10])
        print(f"✓ Batch generated {len([p for p in batch_results.values() if p])} proofs")
        
        # Performance benchmark
        perf_results = benchmark_cache_performance(cache, tree, test_addresses, 100)
        print(f"✓ Performance test:")
        print(f"  - Operations per second: {perf_results['operations_per_second']:.1f}")
        print(f"  - Cache hit rate: {perf_results['cache_hit_rate']:.2f}")
        print(f"  - Average operation time: {perf_results['average_op_time_ms']:.2f}ms")
        
        # Statistics
        stats = cache.get_statistics()
        print(f"✓ Cache statistics:")
        print(f"  - Size: {stats.cache_size}/{stats.max_size}")
        print(f"  - Hit rate: {stats.hit_rate:.2f}")
        print(f"  - Memory usage: {stats.total_memory_usage} bytes")
        
        cache.shutdown()
        print("Proof caching system test completed successfully!")
    
    else:
        print("Proof Caching and Optimization System")
        print("Usage: python proof_cache.py test")