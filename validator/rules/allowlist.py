"""
Allowlist Validation Rule with Merkle Proof Verification

This module implements the AllowlistRule class that validates whether
recipients are authorized to receive asset mints via Merkle proof verification
against a pre-committed allowlist root hash.
"""

import logging
import hashlib
import time
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum

from validator.core import ValidationRule, ValidationContext
from registry.schema import AssetType
from crypto.commitments import OperationType


class HashFunction(str, Enum):
    """Supported hash functions for Merkle tree construction."""
    SHA256 = "sha256"
    SHA3_256 = "sha3_256"
    BLAKE2B = "blake2b"
    KECCAK256 = "keccak256"


class ProofFormat(str, Enum):
    """Supported Merkle proof formats."""
    BINARY = "binary"           # Raw binary hashes
    HEX = "hex"                # Hex-encoded hashes
    BASE64 = "base64"          # Base64-encoded hashes


@dataclass
class MerkleProof:
    """Represents a Merkle proof for allowlist verification."""
    leaf_hash: bytes
    proof_hashes: List[bytes]
    leaf_index: int
    tree_size: int
    hash_function: HashFunction = HashFunction.SHA256
    
    def __post_init__(self):
        """Validate proof structure after initialization."""
        if self.leaf_index < 0 or self.leaf_index >= self.tree_size:
            raise ValueError(f"Invalid leaf index {self.leaf_index} for tree size {self.tree_size}")
        
        expected_proof_length = self.tree_size.bit_length() - 1
        if len(self.proof_hashes) > expected_proof_length:
            raise ValueError(f"Proof too long: got {len(self.proof_hashes)}, max {expected_proof_length}")


@dataclass
class AllowlistEntry:
    """Represents an entry in the allowlist cache."""
    address: str
    proof: MerkleProof
    verified: bool = False
    last_verified: Optional[float] = None
    verification_count: int = 0
    
    def mark_verified(self):
        """Mark this entry as verified."""
        self.verified = True
        self.last_verified = time.time()
        self.verification_count += 1


class AllowlistRule(ValidationRule):
    """
    Validation rule that enforces recipient allowlists using Merkle proofs.
    
    This rule ensures that mint recipients are authorized by verifying
    cryptographic Merkle proofs against a pre-committed allowlist root hash.
    Supports multiple hash functions, proof formats, and includes caching
    for performance optimization.
    """
    
    def __init__(self, 
                 enable_caching: bool = True,
                 cache_ttl: int = 3600,
                 strict_verification: bool = True,
                 max_proof_size: int = 64):
        """
        Initialize the allowlist rule.
        
        Args:
            enable_caching: Whether to cache verified addresses
            cache_ttl: Cache time-to-live in seconds (default: 1 hour)
            strict_verification: If True, requires proofs for all recipients
            max_proof_size: Maximum allowed proof size (number of hashes)
        """
        super().__init__(
            name="allowlist",
            description="Enforces recipient allowlists using Merkle proof verification"
        )
        
        self.enable_caching = enable_caching
        self.cache_ttl = cache_ttl
        self.strict_verification = strict_verification
        self.max_proof_size = max_proof_size
        
        # Cache for verified addresses
        self.allowlist_cache: Dict[str, Dict[str, AllowlistEntry]] = {}  # asset_id -> address -> entry
        
        # Statistics tracking
        self.stats = {
            "validations_performed": 0,
            "proofs_verified": 0,
            "proofs_failed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "addresses_verified": 0,
            "addresses_rejected": 0
        }
    
    def is_applicable(self, context: ValidationContext) -> bool:
        """
        Check if this rule applies to the given validation context.
        
        This rule applies to:
        - Mint operations only
        - Assets with defined allowlist root hashes
        
        Args:
            context: Validation context
            
        Returns:
            True if this rule should be applied
        """
        if not self.enabled:
            return False
        
        # Only apply to mint operations
        if context.operation != OperationType.MINT:
            return False
        
        # Must have asset ID
        if not context.asset_id:
            return False
        
        # Must have allowlist root defined (None means no allowlist required)
        if context.allowlist_root is None:
            return False
        
        return True
    
    def validate(self, context: ValidationContext) -> bool:
        """
        Validate that all mint recipients are on the allowlist.
        
        Args:
            context: Validation context containing transaction data
            
        Returns:
            True if validation passes, False otherwise
        """
        self.stats["validations_performed"] += 1
        
        try:
            # Extract recipient addresses from transaction
            recipients = self._extract_recipients(context)
            if not recipients:
                if self.strict_verification:
                    context.add_error(self.name, "No recipients found in mint transaction")
                    return False
                else:
                    # Non-strict mode allows transactions with no clear recipients
                    return True
            
            # Get allowlist root for verification
            allowlist_root = context.allowlist_root
            if not allowlist_root:
                context.add_error(self.name, "No allowlist root hash configured for asset")
                return False
            
            # Verify each recipient
            all_verified = True
            for address, proof_data in recipients.items():
                if not self._verify_recipient(address, proof_data, allowlist_root, context):
                    all_verified = False
                    self.stats["addresses_rejected"] += 1
                else:
                    self.stats["addresses_verified"] += 1
            
            if all_verified:
                self.logger.debug(f"Allowlist validation passed for {len(recipients)} recipients")
                return True
            else:
                self.logger.debug(f"Allowlist validation failed for some recipients")
                return False
                
        except Exception as e:
            self.logger.error(f"Allowlist validation error: {e}")
            context.add_error(self.name, f"Allowlist validation failed: {str(e)}")
            return False
    
    def _extract_recipients(self, context: ValidationContext) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Extract recipient addresses and proof data from PSBT transaction.
        
        Args:
            context: Validation context
            
        Returns:
            Dictionary mapping addresses to proof data (if available)
        """
        recipients = {}
        
        try:
            # In production, this would parse PSBT outputs and extract recipient addresses
            # For now, simulate recipient extraction based on context
            
            psbt_data = context.psbt_data
            outputs = psbt_data.get("outputs", [])
            
            # Simulate recipient address extraction
            # In production, this would:
            # 1. Parse each output script to extract recipient address
            # 2. Look for OP_RETURN outputs containing Merkle proofs
            # 3. Associate proofs with corresponding recipient addresses
            
            # Look for proof data in PSBT proprietary fields first
            # This is where Merkle proofs would be embedded in real transactions
            proprietary = psbt_data.get("proprietary", {})
            if "allowlist_proofs" in proprietary:
                proof_data = proprietary["allowlist_proofs"]
                for address, proof in proof_data.items():
                    recipients[address] = proof
            
            # If no explicit proof data and context has amount, simulate a recipient
            elif not outputs and context.amount:
                # Simulate a single recipient for testing
                recipient_address = "bc1qexampleallowlist123456789"
                recipients[recipient_address] = None  # No proof data in context yet
            
            self.logger.debug(f"Extracted {len(recipients)} recipients from PSBT")
            return recipients
            
        except Exception as e:
            self.logger.error(f"Failed to extract recipients: {e}")
            return {}
    
    def _verify_recipient(self, address: str, proof_data: Optional[Dict[str, Any]], 
                         allowlist_root: bytes, context: ValidationContext) -> bool:
        """
        Verify a single recipient against the allowlist.
        
        Args:
            address: Recipient address to verify
            proof_data: Merkle proof data (if available)
            allowlist_root: Allowlist Merkle root hash
            context: Validation context
            
        Returns:
            True if recipient is verified
        """
        asset_id_hex = context.asset_id.hex()
        
        # Check cache first if enabled
        if self.enable_caching:
            cached_entry = self._get_cached_entry(asset_id_hex, address)
            if cached_entry and not self._is_cache_expired(cached_entry):
                self.stats["cache_hits"] += 1
                if cached_entry.verified:
                    cached_entry.verification_count += 1
                    return True
                else:
                    context.add_error(
                        self.name,
                        f"Address {address[:10]}... previously failed allowlist verification"
                    )
                    return False
        
        self.stats["cache_misses"] += 1
        
        # Require proof data in strict mode
        if not proof_data and self.strict_verification:
            context.add_error(
                self.name,
                f"No Merkle proof provided for address {address[:10]}... (strict mode enabled)"
            )
            return False
        
        # Skip verification if no proof data in non-strict mode
        if not proof_data and not self.strict_verification:
            self.logger.debug(f"No proof for {address[:10]}..., allowing in non-strict mode")
            return True
        
        # Parse and verify Merkle proof
        try:
            merkle_proof = self._parse_proof_data(address, proof_data)
            if not merkle_proof:
                context.add_error(self.name, f"Invalid proof format for address {address[:10]}...")
                return False
            
            # Verify proof against allowlist root
            is_valid = self._verify_merkle_proof(merkle_proof, allowlist_root)
            
            if is_valid:
                self.stats["proofs_verified"] += 1
                self.logger.debug(f"Merkle proof verified for address {address[:10]}...")
                
                # Cache successful verification
                if self.enable_caching:
                    self._cache_verification(asset_id_hex, address, merkle_proof, True)
                
                return True
            else:
                self.stats["proofs_failed"] += 1
                context.add_error(
                    self.name,
                    f"Invalid Merkle proof for address {address[:10]}... "
                    f"(proof verification failed against allowlist root)"
                )
                
                # Cache failed verification
                if self.enable_caching:
                    self._cache_verification(asset_id_hex, address, merkle_proof, False)
                
                return False
                
        except Exception as e:
            self.logger.error(f"Proof verification error for {address[:10]}...: {e}")
            context.add_error(
                self.name,
                f"Proof verification error for address {address[:10]}...: {str(e)}"
            )
            return False
    
    def _parse_proof_data(self, address: str, proof_data: Dict[str, Any]) -> Optional[MerkleProof]:
        """
        Parse proof data into a MerkleProof object.
        
        Args:
            address: Recipient address
            proof_data: Raw proof data
            
        Returns:
            MerkleProof object or None if parsing failed
        """
        try:
            # Extract required fields
            leaf_hash_hex = proof_data.get("leaf_hash")
            proof_hashes_hex = proof_data.get("proof_hashes", [])
            leaf_index = proof_data.get("leaf_index", 0)
            tree_size = proof_data.get("tree_size", 1)
            hash_function = HashFunction(proof_data.get("hash_function", "sha256"))
            
            if not leaf_hash_hex or not isinstance(proof_hashes_hex, list):
                raise ValueError("Missing required proof fields")
            
            # Convert hex strings to bytes
            leaf_hash = bytes.fromhex(leaf_hash_hex.replace("0x", ""))
            proof_hashes = [bytes.fromhex(h.replace("0x", "")) for h in proof_hashes_hex]
            
            # Validate proof size
            if len(proof_hashes) > self.max_proof_size:
                raise ValueError(f"Proof too large: {len(proof_hashes)} hashes (max {self.max_proof_size})")
            
            # Create and validate proof
            merkle_proof = MerkleProof(
                leaf_hash=leaf_hash,
                proof_hashes=proof_hashes,
                leaf_index=leaf_index,
                tree_size=tree_size,
                hash_function=hash_function
            )
            
            # Verify leaf hash matches address
            expected_leaf = self._hash_address(address, hash_function)
            if merkle_proof.leaf_hash != expected_leaf:
                raise ValueError("Leaf hash doesn't match address")
            
            return merkle_proof
            
        except Exception as e:
            self.logger.error(f"Failed to parse proof data: {e}")
            return None
    
    def _verify_merkle_proof(self, proof: MerkleProof, root: bytes) -> bool:
        """
        Verify a Merkle proof against the given root hash.
        
        Args:
            proof: Merkle proof to verify
            root: Expected root hash
            
        Returns:
            True if proof is valid
        """
        try:
            # Start with the leaf hash
            current_hash = proof.leaf_hash
            leaf_index = proof.leaf_index
            
            # Process each level of the tree
            for i, sibling_hash in enumerate(proof.proof_hashes):
                if len(sibling_hash) != len(current_hash):
                    self.logger.error(f"Hash length mismatch at level {i}")
                    return False
                
                # Determine if current node is left or right child
                is_left_child = (leaf_index & (1 << i)) == 0
                
                # Combine hashes in correct order
                if is_left_child:
                    combined = current_hash + sibling_hash
                else:
                    combined = sibling_hash + current_hash
                
                # Hash the combination
                current_hash = self._hash_data(combined, proof.hash_function)
            
            # Compare final hash with root
            return current_hash == root
            
        except Exception as e:
            self.logger.error(f"Merkle proof verification failed: {e}")
            return False
    
    def _hash_address(self, address: str, hash_function: HashFunction) -> bytes:
        """Hash an address using the specified hash function."""
        return self._hash_data(address.encode('utf-8'), hash_function)
    
    def _hash_data(self, data: bytes, hash_function: HashFunction) -> bytes:
        """Hash data using the specified hash function."""
        if hash_function == HashFunction.SHA256:
            return hashlib.sha256(data).digest()
        elif hash_function == HashFunction.SHA3_256:
            return hashlib.sha3_256(data).digest()
        elif hash_function == HashFunction.BLAKE2B:
            return hashlib.blake2b(data, digest_size=32).digest()
        elif hash_function == HashFunction.KECCAK256:
            # Note: This would use a proper Keccak256 implementation in production
            return hashlib.sha3_256(data).digest()  # Placeholder using SHA3-256
        else:
            raise ValueError(f"Unsupported hash function: {hash_function}")
    
    def _get_cached_entry(self, asset_id: str, address: str) -> Optional[AllowlistEntry]:
        """Get cached allowlist entry."""
        asset_cache = self.allowlist_cache.get(asset_id)
        if asset_cache:
            return asset_cache.get(address)
        return None
    
    def _is_cache_expired(self, entry: AllowlistEntry) -> bool:
        """Check if cache entry is expired."""
        if not entry.last_verified:
            return True
        return time.time() - entry.last_verified > self.cache_ttl
    
    def _cache_verification(self, asset_id: str, address: str, proof: MerkleProof, verified: bool):
        """Cache verification result."""
        if asset_id not in self.allowlist_cache:
            self.allowlist_cache[asset_id] = {}
        
        entry = AllowlistEntry(
            address=address,
            proof=proof,
            verified=verified
        )
        
        if verified:
            entry.mark_verified()
        
        self.allowlist_cache[asset_id][address] = entry
    
    def clear_cache(self, asset_id: Optional[str] = None, address: Optional[str] = None):
        """
        Clear allowlist cache.
        
        Args:
            asset_id: Optional specific asset ID to clear
            address: Optional specific address to clear
        """
        if asset_id and address:
            # Clear specific entry
            if asset_id in self.allowlist_cache:
                self.allowlist_cache[asset_id].pop(address, None)
        elif asset_id:
            # Clear all entries for asset
            self.allowlist_cache.pop(asset_id, None)
        else:
            # Clear entire cache
            self.allowlist_cache.clear()
        
        self.logger.debug(f"Cleared allowlist cache: asset={asset_id}, address={address}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rule statistics."""
        cache_total = self.stats["cache_hits"] + self.stats["cache_misses"]
        hit_rate = (self.stats["cache_hits"] / cache_total * 100) if cache_total > 0 else 0
        
        proof_total = self.stats["proofs_verified"] + self.stats["proofs_failed"]
        verification_rate = (self.stats["proofs_verified"] / proof_total * 100) if proof_total > 0 else 0
        
        return {
            **self.stats,
            "cache_hit_rate_percent": round(hit_rate, 2),
            "proof_verification_rate_percent": round(verification_rate, 2),
            "cached_assets": len(self.allowlist_cache),
            "total_cached_addresses": sum(len(addresses) for addresses in self.allowlist_cache.values()),
            "enable_caching": self.enable_caching,
            "strict_verification": self.strict_verification,
            "cache_ttl_seconds": self.cache_ttl
        }
    
    def get_cached_allowlists(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Get information about cached allowlist entries."""
        result = {}
        for asset_id, addresses in self.allowlist_cache.items():
            result[asset_id] = {}
            for address, entry in addresses.items():
                result[asset_id][address] = {
                    "verified": entry.verified,
                    "last_verified": entry.last_verified,
                    "verification_count": entry.verification_count,
                    "expired": self._is_cache_expired(entry),
                    "proof_hashes_count": len(entry.proof.proof_hashes),
                    "hash_function": entry.proof.hash_function.value
                }
        return result


# Utility functions for allowlist validation

def create_allowlist_rule(config: Optional[Dict[str, Any]] = None) -> AllowlistRule:
    """
    Create an AllowlistRule with configuration.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured AllowlistRule instance
    """
    config = config or {}
    
    enable_caching = config.get("enable_caching", True)
    cache_ttl = config.get("cache_ttl", 3600)
    strict_verification = config.get("strict_verification", True)
    max_proof_size = config.get("max_proof_size", 64)
    
    return AllowlistRule(
        enable_caching=enable_caching,
        cache_ttl=cache_ttl,
        strict_verification=strict_verification,
        max_proof_size=max_proof_size
    )


def build_merkle_tree(addresses: List[str], hash_function: HashFunction = HashFunction.SHA256) -> Tuple[bytes, Dict[str, Dict[str, Any]]]:
    """
    Build a Merkle tree from a list of addresses and return root hash and proofs.
    
    Args:
        addresses: List of addresses to include in allowlist
        hash_function: Hash function to use for tree construction
        
    Returns:
        Tuple of (root_hash, proofs_dict) where proofs_dict maps addresses to proof data
    """
    if not addresses:
        raise ValueError("Cannot build Merkle tree from empty address list")
    
    # Create AllowlistRule instance for hash function access
    rule = AllowlistRule()
    
    # Hash all addresses to create leaves
    leaves = [rule._hash_address(addr, hash_function) for addr in addresses]
    original_size = len(leaves)
    
    # Pad to power of 2 if necessary
    while len(leaves) & (len(leaves) - 1):
        leaves.append(leaves[-1])  # Duplicate last leaf
    
    # Build tree level by level
    tree = [leaves[:]]  # Store all levels
    current_level = leaves[:]
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = left + right
            next_level.append(rule._hash_data(combined, hash_function))
        tree.append(next_level)
        current_level = next_level
    
    root_hash = current_level[0]
    
    # Generate proofs for each address
    proofs = {}
    for i, address in enumerate(addresses[:original_size]):  # Only original addresses
        proof_hashes = []
        leaf_index = i
        
        # Collect sibling hashes at each level
        for level in range(len(tree) - 1):
            level_size = len(tree[level])
            sibling_index = leaf_index ^ 1  # XOR with 1 to get sibling
            
            if sibling_index < level_size:
                proof_hashes.append(tree[level][sibling_index].hex())
            
            leaf_index >>= 1  # Move up to parent index
        
        proofs[address] = {
            "leaf_hash": rule._hash_address(address, hash_function).hex(),
            "proof_hashes": proof_hashes,
            "leaf_index": i,
            "tree_size": len(leaves),
            "hash_function": hash_function.value
        }
    
    return root_hash, proofs


def verify_allowlist_proof(address: str, proof_data: Dict[str, Any], allowlist_root: str) -> bool:
    """
    Quick allowlist proof verification utility.
    
    Args:
        address: Address to verify
        proof_data: Merkle proof data
        allowlist_root: Hex-encoded allowlist root hash
        
    Returns:
        True if proof is valid
    """
    try:
        rule = AllowlistRule()
        merkle_proof = rule._parse_proof_data(address, proof_data)
        if not merkle_proof:
            return False
        
        root_bytes = bytes.fromhex(allowlist_root.replace("0x", ""))
        return rule._verify_merkle_proof(merkle_proof, root_bytes)
        
    except Exception:
        return False