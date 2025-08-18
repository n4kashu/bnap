"""
Bitcoin Native Asset Protocol - Security Measures and Performance Testing

This module provides comprehensive security validations, attack prevention,
and performance benchmarking for the Merkle proof system.
"""

import hashlib
import logging
import time
import threading
import random
import secrets
from typing import Dict, List, Optional, Set, Tuple, Union, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from collections import defaultdict, deque
import weakref
from pathlib import Path

try:
    from .merkle import MerkleTree, MerkleProof, MerkleHasher
    from .allowlist import AllowlistManager
    from .proof_cache import LRUProofCache, BatchProofOptimizer
except ImportError:
    # For standalone testing
    from merkle import MerkleTree, MerkleProof, MerkleHasher
    from allowlist import AllowlistManager
    from proof_cache import LRUProofCache, BatchProofOptimizer


class SecurityThreat(Enum):
    """Types of security threats to monitor."""
    BRUTE_FORCE = "brute_force"
    REPLAY_ATTACK = "replay_attack"
    DOS_ATTACK = "dos_attack"
    PROOF_FORGERY = "proof_forgery"
    SECOND_PREIMAGE = "second_preimage"
    COLLISION = "collision"
    TIMING_ATTACK = "timing_attack"
    CACHE_POISONING = "cache_poisoning"


class SecurityLevel(Enum):
    """Security levels for different operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """Represents a security-related event."""
    threat_type: SecurityThreat
    severity: SecurityLevel
    timestamp: datetime
    source_id: str
    details: Dict[str, Any]
    resolved: bool = False
    
    def __post_init__(self):
        """Initialize event."""
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class PerformanceMetrics:
    """Performance metrics for system operations."""
    operation_name: str
    total_operations: int = 0
    total_time_seconds: float = 0.0
    min_time_ms: float = float('inf')
    max_time_ms: float = 0.0
    avg_time_ms: float = 0.0
    operations_per_second: float = 0.0
    success_count: int = 0
    error_count: int = 0
    memory_usage_bytes: int = 0
    
    def update(self, execution_time_ms: float, success: bool = True, memory_bytes: int = 0):
        """Update metrics with new operation data."""
        self.total_operations += 1
        self.total_time_seconds += execution_time_ms / 1000.0
        
        self.min_time_ms = min(self.min_time_ms, execution_time_ms)
        self.max_time_ms = max(self.max_time_ms, execution_time_ms)
        
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
        
        if memory_bytes > 0:
            self.memory_usage_bytes = max(self.memory_usage_bytes, memory_bytes)
        
        # Recalculate averages
        self.avg_time_ms = (self.total_time_seconds * 1000) / self.total_operations
        if self.total_time_seconds > 0:
            self.operations_per_second = self.total_operations / self.total_time_seconds
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance metrics summary."""
        return {
            "operation": self.operation_name,
            "total_ops": self.total_operations,
            "success_rate": self.success_count / self.total_operations if self.total_operations > 0 else 0,
            "avg_time_ms": round(self.avg_time_ms, 2),
            "min_time_ms": round(self.min_time_ms, 2),
            "max_time_ms": round(self.max_time_ms, 2),
            "ops_per_second": round(self.operations_per_second, 1),
            "memory_usage_mb": round(self.memory_usage_bytes / (1024 * 1024), 2)
        }


class RateLimiter:
    """Rate limiter for preventing DoS attacks."""
    
    def __init__(self, max_requests: int = 100, time_window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests per time window
            time_window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.RLock()
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed for given identifier.
        
        Args:
            identifier: Unique identifier for the requester
            
        Returns:
            True if request is allowed
        """
        now = time.time()
        
        with self._lock:
            # Clean old requests
            request_times = self.requests[identifier]
            while request_times and request_times[0] < now - self.time_window:
                request_times.popleft()
            
            # Check rate limit
            if len(request_times) >= self.max_requests:
                return False
            
            # Add current request
            request_times.append(now)
            return True
    
    def get_stats(self, identifier: str) -> Dict[str, Any]:
        """Get rate limiting stats for identifier."""
        now = time.time()
        
        with self._lock:
            request_times = self.requests[identifier]
            # Clean old requests first
            while request_times and request_times[0] < now - self.time_window:
                request_times.popleft()
            
            return {
                "requests_in_window": len(request_times),
                "max_requests": self.max_requests,
                "time_window_seconds": self.time_window,
                "remaining_requests": max(0, self.max_requests - len(request_times)),
                "reset_time": request_times[0] + self.time_window if request_times else now
            }


class SecurityValidator:
    """
    Comprehensive security validator for Merkle proof operations.
    """
    
    def __init__(self):
        """Initialize security validator."""
        self.logger = logging.getLogger(__name__)
        self.hasher = MerkleHasher()
        
        # Security configuration
        self.max_proof_size = 10000  # Maximum proof size in bytes
        self.max_tree_height = 64    # Maximum tree height
        self.min_entropy_bits = 128  # Minimum entropy for random values
        
        # Threat tracking
        self.security_events: List[SecurityEvent] = []
        self.known_attacks: Set[str] = set()
        
        # Rate limiting
        self.rate_limiter = RateLimiter(max_requests=1000, time_window_seconds=60)
        
        self._lock = threading.RLock()
    
    def validate_proof_integrity(self, proof: MerkleProof) -> Tuple[bool, List[str]]:
        """
        Validate proof integrity and detect potential attacks.
        
        Args:
            proof: MerkleProof to validate
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        # Basic structure validation
        if not proof.leaf_data:
            issues.append("Empty leaf data")
        
        if not proof.leaf_hash or len(proof.leaf_hash) != 32:
            issues.append("Invalid leaf hash length")
        
        if not proof.root_hash or len(proof.root_hash) != 32:
            issues.append("Invalid root hash length")
        
        if len(proof.proof_hashes) != len(proof.proof_indices):
            issues.append("Proof hashes and indices length mismatch")
        
        # Security-specific validations
        if len(proof.proof_hashes) > self.max_tree_height:
            issues.append(f"Proof path too long: {len(proof.proof_hashes)} > {self.max_tree_height}")
            self._record_security_event(SecurityThreat.DOS_ATTACK, SecurityLevel.MEDIUM, "Excessive proof path length")
        
        # Check for duplicate hashes in proof path (potential attack)
        hash_set = set()
        for i, proof_hash in enumerate(proof.proof_hashes):
            if len(proof_hash) != 32:
                issues.append(f"Invalid proof hash length at index {i}")
            
            if proof_hash in hash_set:
                issues.append(f"Duplicate hash in proof path at index {i}")
                self._record_security_event(SecurityThreat.PROOF_FORGERY, SecurityLevel.HIGH, "Duplicate hash in proof")
            
            hash_set.add(proof_hash)
        
        # Validate leaf hash consistency
        expected_leaf_hash = self.hasher.hash_leaf(proof.leaf_data)
        if expected_leaf_hash != proof.leaf_hash:
            issues.append("Leaf hash does not match leaf data")
            self._record_security_event(SecurityThreat.PROOF_FORGERY, SecurityLevel.CRITICAL, "Leaf hash mismatch")
        
        # Check for zero hashes (potential weakness)
        zero_hash = b'\x00' * 32
        if any(h == zero_hash for h in proof.proof_hashes):
            issues.append("Zero hash found in proof path")
            self._record_security_event(SecurityThreat.PROOF_FORGERY, SecurityLevel.MEDIUM, "Zero hash in proof")
        
        # Validate tree size consistency
        if proof.tree_size <= 0:
            issues.append("Invalid tree size")
        
        max_leaf_index = proof.tree_size - 1
        if proof.leaf_index < 0 or proof.leaf_index > max_leaf_index:
            issues.append(f"Leaf index {proof.leaf_index} out of range [0, {max_leaf_index}]")
        
        return len(issues) == 0, issues
    
    def validate_tree_security(self, tree: MerkleTree) -> Tuple[bool, List[str]]:
        """
        Validate Merkle tree security properties.
        
        Args:
            tree: MerkleTree to validate
            
        Returns:
            Tuple of (is_secure, list_of_issues)
        """
        issues = []
        
        if not tree.root:
            issues.append("Tree has no root")
            return False, issues
        
        # Check tree balance (security against certain attacks)
        if tree.get_height() > self.max_tree_height:
            issues.append(f"Tree height {tree.get_height()} exceeds maximum {self.max_tree_height}")
        
        # Validate tree structure
        is_valid, structure_errors = tree.validate_tree_structure()
        if not is_valid:
            issues.extend(structure_errors)
        
        # Check for duplicate leaves (potential attack)
        leaf_hashes = set()
        duplicate_count = 0
        for leaf in tree.leaves:
            if leaf.hash in leaf_hashes:
                duplicate_count += 1
            leaf_hashes.add(leaf.hash)
        
        if duplicate_count > 0:
            issues.append(f"Found {duplicate_count} duplicate leaf hashes")
            self._record_security_event(SecurityThreat.COLLISION, SecurityLevel.MEDIUM, f"Duplicate leaves: {duplicate_count}")
        
        # Check entropy of leaf data
        entropy_issues = self._check_entropy(tree)
        issues.extend(entropy_issues)
        
        return len(issues) == 0, issues
    
    def detect_timing_attack(
        self, 
        operation_times: List[float], 
        threshold_std: float = 2.0
    ) -> bool:
        """
        Detect potential timing attacks by analyzing operation times.
        
        Args:
            operation_times: List of operation times in seconds
            threshold_std: Standard deviation threshold for detection
            
        Returns:
            True if timing attack detected
        """
        if len(operation_times) < 10:
            return False
        
        import statistics
        
        mean_time = statistics.mean(operation_times)
        std_time = statistics.stdev(operation_times)
        
        # Look for patterns that suggest timing attacks
        outliers = [t for t in operation_times if abs(t - mean_time) > threshold_std * std_time]
        outlier_ratio = len(outliers) / len(operation_times)
        
        if outlier_ratio > 0.1:  # More than 10% outliers
            self._record_security_event(
                SecurityThreat.TIMING_ATTACK, 
                SecurityLevel.MEDIUM, 
                f"Timing anomaly detected: {outlier_ratio:.2%} outliers"
            )
            return True
        
        return False
    
    def validate_proof_uniqueness(self, proof: MerkleProof, identifier: str) -> bool:
        """
        Validate proof uniqueness to prevent replay attacks.
        
        Args:
            proof: MerkleProof to check
            identifier: Unique identifier for the proof
            
        Returns:
            True if proof is unique
        """
        # Create proof signature for uniqueness checking
        proof_signature = self._create_proof_signature(proof)
        
        if proof_signature in self.known_attacks:
            self._record_security_event(
                SecurityThreat.REPLAY_ATTACK, 
                SecurityLevel.HIGH, 
                f"Replay attack detected: {identifier}"
            )
            return False
        
        # Add to known proofs (with size limit to prevent memory exhaustion)
        self.known_attacks.add(proof_signature)
        if len(self.known_attacks) > 10000:  # Limit memory usage
            # Remove oldest entries (simplified LRU)
            oldest_entries = list(self.known_attacks)[:1000]
            for entry in oldest_entries:
                self.known_attacks.discard(entry)
        
        return True
    
    def check_rate_limiting(self, identifier: str) -> bool:
        """
        Check if request is within rate limits.
        
        Args:
            identifier: Unique identifier for rate limiting
            
        Returns:
            True if request is allowed
        """
        allowed = self.rate_limiter.is_allowed(identifier)
        
        if not allowed:
            self._record_security_event(
                SecurityThreat.DOS_ATTACK, 
                SecurityLevel.MEDIUM, 
                f"Rate limit exceeded: {identifier}"
            )
        
        return allowed
    
    def get_security_report(self) -> Dict[str, Any]:
        """Get comprehensive security report."""
        with self._lock:
            threat_counts = defaultdict(int)
            severity_counts = defaultdict(int)
            
            for event in self.security_events:
                threat_counts[event.threat_type.value] += 1
                severity_counts[event.severity.value] += 1
            
            recent_events = [
                event for event in self.security_events 
                if event.timestamp > datetime.now(timezone.utc) - timedelta(hours=24)
            ]
            
            return {
                "total_events": len(self.security_events),
                "recent_events_24h": len(recent_events),
                "threat_distribution": dict(threat_counts),
                "severity_distribution": dict(severity_counts),
                "active_threats": len([e for e in recent_events if not e.resolved]),
                "known_attack_signatures": len(self.known_attacks),
                "rate_limit_config": {
                    "max_requests": self.rate_limiter.max_requests,
                    "time_window": self.rate_limiter.time_window
                }
            }
    
    def _record_security_event(
        self, 
        threat: SecurityThreat, 
        severity: SecurityLevel, 
        details: str,
        source_id: Optional[str] = None
    ):
        """Record a security event."""
        event = SecurityEvent(
            threat_type=threat,
            severity=severity,
            timestamp=datetime.now(timezone.utc),
            source_id=source_id or "unknown",
            details={"message": details}
        )
        
        with self._lock:
            self.security_events.append(event)
            
            # Log critical events
            if severity == SecurityLevel.CRITICAL:
                self.logger.critical(f"Security threat detected: {threat.value} - {details}")
            elif severity == SecurityLevel.HIGH:
                self.logger.error(f"Security threat detected: {threat.value} - {details}")
            else:
                self.logger.warning(f"Security event: {threat.value} - {details}")
    
    def _create_proof_signature(self, proof: MerkleProof) -> str:
        """Create unique signature for proof to detect replays."""
        signature_data = (
            proof.leaf_hash + 
            proof.root_hash + 
            b''.join(proof.proof_hashes) + 
            bytes(proof.proof_indices)
        )
        return hashlib.sha256(signature_data).hexdigest()
    
    def _check_entropy(self, tree: MerkleTree) -> List[str]:
        """Check entropy of tree data to detect potential weaknesses."""
        issues = []
        
        if len(tree.leaves) < 2:
            return issues
        
        # Sample some leaves for entropy analysis
        sample_size = min(100, len(tree.leaves))
        sample_leaves = random.sample(tree.leaves, sample_size)
        
        # Check for low entropy in leaf data
        entropy_scores = []
        for leaf in sample_leaves:
            if leaf.data and len(leaf.data) > 0:
                entropy = self._calculate_entropy(leaf.data)
                entropy_scores.append(entropy)
        
        if entropy_scores:
            avg_entropy = sum(entropy_scores) / len(entropy_scores)
            min_entropy_bits = self.min_entropy_bits / 8  # Convert to bytes
            
            if avg_entropy < min_entropy_bits:
                issues.append(f"Low entropy detected: {avg_entropy:.2f} < {min_entropy_bits}")
                self._record_security_event(
                    SecurityThreat.SECOND_PREIMAGE, 
                    SecurityLevel.MEDIUM, 
                    f"Low entropy: {avg_entropy:.2f}"
                )
        
        return issues
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count frequency of each byte
        frequency = defaultdict(int)
        for byte in data:
            frequency[byte] += 1
        
        # Calculate entropy using Shannon's formula
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency.values():
            if count > 0:
                probability = count / data_len
                if probability > 0:
                    import math
                    entropy -= probability * math.log2(probability)
        
        return entropy


class PerformanceBenchmark:
    """
    Comprehensive performance benchmark suite for Merkle operations.
    """
    
    def __init__(self):
        """Initialize performance benchmark."""
        self.logger = logging.getLogger(__name__)
        self.metrics: Dict[str, PerformanceMetrics] = {}
        self.security_validator = SecurityValidator()
    
    def benchmark_tree_construction(
        self, 
        sizes: List[int], 
        iterations: int = 3
    ) -> Dict[int, Dict[str, Any]]:
        """
        Benchmark Merkle tree construction for different sizes.
        
        Args:
            sizes: List of tree sizes to benchmark
            iterations: Number of iterations per size
            
        Returns:
            Performance results by tree size
        """
        results = {}
        
        for size in sizes:
            print(f"Benchmarking tree construction for size {size}...")
            
            size_metrics = PerformanceMetrics(f"tree_construction_{size}")
            
            for iteration in range(iterations):
                # Generate test addresses
                addresses = [f"bc1q{secrets.token_hex(20)}" for _ in range(size)]
                
                # Measure construction time
                start_time = time.time()
                tree = MerkleTree()
                tree.build_from_addresses(addresses)
                end_time = time.time()
                
                execution_time_ms = (end_time - start_time) * 1000
                size_metrics.update(execution_time_ms, success=True)
            
            results[size] = size_metrics.get_summary()
            
        return results
    
    def benchmark_proof_generation(
        self, 
        tree_size: int, 
        num_proofs: int, 
        iterations: int = 3
    ) -> Dict[str, Any]:
        """
        Benchmark proof generation performance.
        
        Args:
            tree_size: Size of the Merkle tree
            num_proofs: Number of proofs to generate per iteration
            iterations: Number of benchmark iterations
            
        Returns:
            Performance metrics
        """
        print(f"Benchmarking proof generation: tree_size={tree_size}, proofs={num_proofs}")
        
        # Create test tree
        addresses = [f"bc1q{secrets.token_hex(20)}" for _ in range(tree_size)]
        tree = MerkleTree()
        tree.build_from_addresses(addresses)
        
        # Benchmark proof generation
        metrics = PerformanceMetrics("proof_generation")
        
        for iteration in range(iterations):
            # Select random addresses
            test_addresses = random.sample(addresses, min(num_proofs, len(addresses)))
            
            for addr in test_addresses:
                start_time = time.time()
                proof = tree.generate_proof_for_address(addr)
                end_time = time.time()
                
                execution_time_ms = (end_time - start_time) * 1000
                success = proof is not None
                metrics.update(execution_time_ms, success)
        
        return metrics.get_summary()
    
    def benchmark_proof_verification(
        self, 
        tree_size: int, 
        num_verifications: int,
        iterations: int = 3
    ) -> Dict[str, Any]:
        """
        Benchmark proof verification performance.
        
        Args:
            tree_size: Size of the Merkle tree
            num_verifications: Number of verifications per iteration
            iterations: Number of benchmark iterations
            
        Returns:
            Performance metrics
        """
        print(f"Benchmarking proof verification: tree_size={tree_size}, verifications={num_verifications}")
        
        # Create test tree and proofs
        addresses = [f"bc1q{secrets.token_hex(20)}" for _ in range(tree_size)]
        tree = MerkleTree()
        tree.build_from_addresses(addresses)
        
        # Generate test proofs
        test_proofs = []
        for i in range(min(num_verifications, len(addresses))):
            addr = addresses[i]
            proof = tree.generate_proof_for_address(addr)
            if proof:
                test_proofs.append((addr, proof))
        
        # Benchmark verification
        metrics = PerformanceMetrics("proof_verification")
        
        for iteration in range(iterations):
            for addr, proof in test_proofs:
                start_time = time.time()
                is_valid = tree.verify_proof(proof)
                end_time = time.time()
                
                execution_time_ms = (end_time - start_time) * 1000
                metrics.update(execution_time_ms, success=is_valid)
        
        return metrics.get_summary()
    
    def benchmark_cache_performance(
        self, 
        cache_size: int, 
        tree_size: int, 
        operations: int
    ) -> Dict[str, Any]:
        """
        Benchmark cache performance with various access patterns.
        
        Args:
            cache_size: Maximum cache size
            tree_size: Size of test tree
            operations: Number of cache operations
            
        Returns:
            Performance metrics
        """
        print(f"Benchmarking cache performance: cache_size={cache_size}, operations={operations}")
        
        # Create test setup
        addresses = [f"bc1q{secrets.token_hex(20)}" for _ in range(tree_size)]
        tree = MerkleTree()
        tree.build_from_addresses(addresses)
        
        cache = LRUProofCache(max_size=cache_size, ttl_seconds=3600)
        optimizer = BatchProofOptimizer(cache)
        
        # Benchmark different access patterns
        patterns = {
            "random": lambda: random.choice(addresses),
            "sequential": lambda i=iter(addresses): next(i, addresses[0]),
            "hot_set": lambda: random.choice(addresses[:min(10, len(addresses))])
        }
        
        results = {}
        
        for pattern_name, address_generator in patterns.items():
            metrics = PerformanceMetrics(f"cache_{pattern_name}")
            
            # Reset pattern generator for sequential
            if pattern_name == "sequential":
                address_generator = iter(addresses * (operations // len(addresses) + 1))
            
            for _ in range(operations):
                if pattern_name == "sequential":
                    addr = next(address_generator)
                else:
                    addr = address_generator()
                
                start_time = time.time()
                proof = cache.get(addr)
                
                if proof is None:
                    proof = tree.generate_proof_for_address(addr)
                    if proof:
                        cache.put(addr, proof)
                
                end_time = time.time()
                
                execution_time_ms = (end_time - start_time) * 1000
                success = proof is not None
                metrics.update(execution_time_ms, success)
            
            results[pattern_name] = metrics.get_summary()
            cache.clear()  # Reset for next pattern
        
        cache.shutdown()
        return results
    
    def benchmark_security_validation(
        self, 
        num_proofs: int = 1000
    ) -> Dict[str, Any]:
        """
        Benchmark security validation performance.
        
        Args:
            num_proofs: Number of proofs to validate
            
        Returns:
            Performance metrics
        """
        print(f"Benchmarking security validation: {num_proofs} proofs")
        
        # Create test proofs
        tree_size = 100
        addresses = [f"bc1q{secrets.token_hex(20)}" for _ in range(tree_size)]
        tree = MerkleTree()
        tree.build_from_addresses(addresses)
        
        test_proofs = []
        for i in range(min(num_proofs, len(addresses))):
            addr = addresses[i % len(addresses)]
            proof = tree.generate_proof_for_address(addr)
            if proof:
                test_proofs.append(proof)
        
        # Benchmark validation
        metrics = PerformanceMetrics("security_validation")
        
        for proof in test_proofs:
            start_time = time.time()
            is_valid, issues = self.security_validator.validate_proof_integrity(proof)
            end_time = time.time()
            
            execution_time_ms = (end_time - start_time) * 1000
            metrics.update(execution_time_ms, success=is_valid)
        
        return metrics.get_summary()
    
    def run_comprehensive_benchmark(self) -> Dict[str, Any]:
        """
        Run comprehensive performance benchmark suite.
        
        Returns:
            Complete benchmark results
        """
        print("Running Comprehensive Performance Benchmark Suite...")
        print("=" * 60)
        
        results = {}
        
        # Tree construction benchmarks
        print("\n1. Tree Construction Performance")
        print("-" * 30)
        tree_sizes = [10, 50, 100, 500, 1000]
        results["tree_construction"] = self.benchmark_tree_construction(tree_sizes, iterations=3)
        
        # Proof generation benchmarks  
        print("\n2. Proof Generation Performance")
        print("-" * 30)
        results["proof_generation"] = self.benchmark_proof_generation(
            tree_size=1000, num_proofs=100, iterations=3
        )
        
        # Proof verification benchmarks
        print("\n3. Proof Verification Performance") 
        print("-" * 30)
        results["proof_verification"] = self.benchmark_proof_verification(
            tree_size=1000, num_verifications=100, iterations=3
        )
        
        # Cache performance benchmarks
        print("\n4. Cache Performance")
        print("-" * 30)
        results["cache_performance"] = self.benchmark_cache_performance(
            cache_size=100, tree_size=200, operations=1000
        )
        
        # Security validation benchmarks
        print("\n5. Security Validation Performance")
        print("-" * 30)
        results["security_validation"] = self.benchmark_security_validation(num_proofs=500)
        
        print("\n" + "=" * 60)
        print("Comprehensive benchmark completed!")
        
        return results


# Convenience functions

def run_security_audit(tree: MerkleTree, proofs: List[MerkleProof]) -> Dict[str, Any]:
    """
    Run comprehensive security audit on tree and proofs.
    
    Args:
        tree: MerkleTree to audit
        proofs: List of proofs to validate
        
    Returns:
        Security audit results
    """
    validator = SecurityValidator()
    
    # Validate tree security
    tree_valid, tree_issues = validator.validate_tree_security(tree)
    
    # Validate proof integrity
    proof_results = []
    for i, proof in enumerate(proofs):
        proof_valid, proof_issues = validator.validate_proof_integrity(proof)
        proof_results.append({
            "index": i,
            "valid": proof_valid,
            "issues": proof_issues
        })
    
    # Generate security report
    security_report = validator.get_security_report()
    
    return {
        "tree_security": {
            "valid": tree_valid,
            "issues": tree_issues
        },
        "proof_validation": proof_results,
        "security_report": security_report,
        "total_proofs_validated": len(proofs),
        "valid_proofs": sum(1 for r in proof_results if r["valid"]),
        "audit_timestamp": datetime.now(timezone.utc).isoformat()
    }


def create_security_config() -> Dict[str, Any]:
    """Create recommended security configuration."""
    return {
        "rate_limiting": {
            "max_requests_per_minute": 1000,
            "max_requests_per_hour": 10000
        },
        "validation": {
            "max_proof_size_bytes": 10000,
            "max_tree_height": 64,
            "min_entropy_bits": 128
        },
        "monitoring": {
            "log_security_events": True,
            "alert_on_critical_events": True,
            "retention_days": 30
        },
        "caching": {
            "enable_proof_cache": True,
            "cache_size": 10000,
            "cache_ttl_seconds": 3600
        }
    }


# Testing and CLI interface

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "benchmark":
        # Run comprehensive benchmark
        benchmark = PerformanceBenchmark()
        results = benchmark.run_comprehensive_benchmark()
        
        # Print summary
        print("\nBenchmark Summary:")
        print("=" * 50)
        
        for category, data in results.items():
            print(f"\n{category.replace('_', ' ').title()}:")
            if isinstance(data, dict) and "ops_per_second" in data:
                print(f"  Operations/sec: {data['ops_per_second']}")
                print(f"  Avg time (ms): {data['avg_time_ms']}")
                print(f"  Success rate: {data['success_rate']:.2%}")
            else:
                # Handle nested results
                for key, value in data.items():
                    if isinstance(value, dict) and "ops_per_second" in value:
                        print(f"  {key}: {value['ops_per_second']:.1f} ops/sec")
    
    elif len(sys.argv) > 1 and sys.argv[1] == "security":
        # Run security tests
        print("Running Security Validation Tests...")
        
        # Create test tree and proofs
        from merkle import MerkleTree
        addresses = [f"bc1q{secrets.token_hex(20)}" for _ in range(50)]
        tree = MerkleTree()
        tree.build_from_addresses(addresses)
        
        # Generate test proofs
        test_proofs = []
        for i in range(10):
            addr = addresses[i]
            proof = tree.generate_proof_for_address(addr)
            if proof:
                test_proofs.append(proof)
        
        # Run security audit
        audit_results = run_security_audit(tree, test_proofs)
        
        print(f"✓ Tree Security: {'PASS' if audit_results['tree_security']['valid'] else 'FAIL'}")
        print(f"✓ Valid Proofs: {audit_results['valid_proofs']}/{audit_results['total_proofs_validated']}")
        print(f"✓ Security Events: {audit_results['security_report']['total_events']}")
        
        if audit_results['tree_security']['issues']:
            print("Issues found:")
            for issue in audit_results['tree_security']['issues']:
                print(f"  - {issue}")
        
        print("Security validation completed!")
    
    else:
        print("Bitcoin Native Asset Protocol - Security and Performance Testing")
        print("Usage: python security.py <command>")
        print("Commands:")
        print("  benchmark - Run comprehensive performance benchmark")
        print("  security  - Run security validation tests")