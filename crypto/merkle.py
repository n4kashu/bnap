"""
Bitcoin Native Asset Protocol - Merkle Tree Implementation

This module provides a comprehensive Merkle tree implementation for allowlist-based
asset distribution with cryptographic proof generation and verification capabilities.
"""

import hashlib
import logging
import math
from typing import List, Optional, Tuple, Union, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod


class MerkleLeafType(Enum):
    """Types of Merkle tree leaves."""
    ADDRESS = "address"
    HASH = "hash"
    DATA = "data"


@dataclass
class MerkleNode:
    """
    Represents a node in the Merkle tree.
    
    For leaf nodes: contains the original data and its hash
    For internal nodes: contains the combined hash of children
    """
    hash: bytes
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    data: Optional[bytes] = None
    is_leaf: bool = False
    level: int = 0
    index: int = 0
    
    def __post_init__(self):
        """Validate node structure."""
        if len(self.hash) != 32:
            raise ValueError("Node hash must be 32 bytes")
        
        if self.is_leaf and self.data is None:
            raise ValueError("Leaf nodes must have data")
        
        if not self.is_leaf and (self.left is None or self.right is None):
            # Internal nodes must have both children (except during construction)
            pass
    
    def is_internal(self) -> bool:
        """Check if this is an internal node."""
        return not self.is_leaf
    
    def has_children(self) -> bool:
        """Check if node has both children."""
        return self.left is not None and self.right is not None
    
    def get_sibling_hash(self) -> Optional[bytes]:
        """Get hash of sibling node (used in proof generation)."""
        # This is set during proof generation
        return getattr(self, '_sibling_hash', None)
    
    def set_sibling_hash(self, sibling_hash: bytes):
        """Set sibling hash for proof generation."""
        self._sibling_hash = sibling_hash


@dataclass
class MerkleProof:
    """
    Represents a Merkle proof for a specific leaf.
    
    Contains the path from leaf to root with sibling hashes.
    """
    leaf_data: bytes
    leaf_hash: bytes
    proof_hashes: List[bytes]
    proof_indices: List[int]  # 0 = left sibling, 1 = right sibling
    root_hash: bytes
    leaf_index: int
    tree_size: int
    
    def __post_init__(self):
        """Validate proof structure."""
        if len(self.proof_hashes) != len(self.proof_indices):
            raise ValueError("Proof hashes and indices must have same length")
        
        if len(self.root_hash) != 32:
            raise ValueError("Root hash must be 32 bytes")
        
        if len(self.leaf_hash) != 32:
            raise ValueError("Leaf hash must be 32 bytes")
        
        if not all(len(h) == 32 for h in self.proof_hashes):
            raise ValueError("All proof hashes must be 32 bytes")
    
    def get_path_length(self) -> int:
        """Get length of proof path."""
        return len(self.proof_hashes)
    
    def is_valid_for_tree_size(self, tree_size: int) -> bool:
        """Check if proof is valid for given tree size."""
        max_height = math.ceil(math.log2(max(1, tree_size)))
        return self.get_path_length() <= max_height


class MerkleHasher:
    """
    Handles all hashing operations for the Merkle tree.
    
    Implements domain separation to prevent second-preimage attacks.
    """
    
    def __init__(self):
        """Initialize hasher."""
        self.logger = logging.getLogger(__name__)
    
    def hash_leaf(self, data: bytes) -> bytes:
        """
        Hash leaf data with domain separation.
        
        Uses 0x00 prefix to distinguish from internal nodes.
        Format: SHA256(0x00 || data)
        
        Args:
            data: Raw leaf data
            
        Returns:
            32-byte hash with leaf domain separation
        """
        return hashlib.sha256(b'\x00' + data).digest()
    
    def hash_internal(self, left_hash: bytes, right_hash: bytes) -> bytes:
        """
        Hash internal node from children.
        
        Uses 0x01 prefix to distinguish from leaf nodes.
        Format: SHA256(0x01 || left_hash || right_hash)
        
        Args:
            left_hash: Hash of left child (32 bytes)
            right_hash: Hash of right child (32 bytes)
            
        Returns:
            32-byte hash with internal node domain separation
        """
        if len(left_hash) != 32 or len(right_hash) != 32:
            raise ValueError("Child hashes must be 32 bytes")
        
        return hashlib.sha256(b'\x01' + left_hash + right_hash).digest()
    
    def hash_address(self, address: str) -> bytes:
        """
        Hash Bitcoin address for inclusion in allowlist.
        
        Args:
            address: Bitcoin address string
            
        Returns:
            32-byte hash of address
        """
        # Normalize address (lowercase for consistency)
        normalized = address.lower().strip()
        address_bytes = normalized.encode('utf-8')
        
        return self.hash_leaf(address_bytes)
    
    def hash_raw_data(self, data: bytes) -> bytes:
        """
        Hash raw data for tree inclusion.
        
        Args:
            data: Raw data bytes
            
        Returns:
            32-byte hash of data
        """
        return self.hash_leaf(data)


class MerkleTree:
    """
    Efficient Merkle tree implementation for allowlist proofs.
    
    Features:
    - Domain-separated hashing to prevent second-preimage attacks
    - Efficient construction for large datasets (10k+ items)
    - Memory-optimized node storage
    - Fast proof generation and verification
    - Support for incremental updates
    """
    
    def __init__(self, hasher: Optional[MerkleHasher] = None):
        """
        Initialize empty Merkle tree.
        
        Args:
            hasher: Custom hasher instance (optional)
        """
        self.hasher = hasher or MerkleHasher()
        self.logger = logging.getLogger(__name__)
        
        # Tree structure
        self.root: Optional[MerkleNode] = None
        self.leaves: List[MerkleNode] = []
        self.node_count: int = 0
        self.height: int = 0
        
        # Performance tracking
        self.construction_time: float = 0.0
        self.last_proof_time: float = 0.0
        
        # Indexing for fast lookups
        self._leaf_index: Dict[bytes, int] = {}  # hash -> leaf index
        self._data_index: Dict[bytes, int] = {}  # data -> leaf index
    
    def build_from_addresses(self, addresses: List[str]) -> bytes:
        """
        Build Merkle tree from list of Bitcoin addresses.
        
        Args:
            addresses: List of Bitcoin address strings
            
        Returns:
            Root hash of constructed tree
        """
        if not addresses:
            raise ValueError("Cannot build tree from empty address list")
        
        import time
        start_time = time.time()
        
        self.logger.info(f"Building Merkle tree from {len(addresses)} addresses")
        
        # Sort addresses for deterministic tree construction
        sorted_addresses = sorted(set(addresses))  # Remove duplicates and sort
        
        if len(sorted_addresses) != len(addresses):
            self.logger.warning(f"Removed {len(addresses) - len(sorted_addresses)} duplicate addresses")
        
        # Create leaf nodes
        leaf_data = []
        for addr in sorted_addresses:
            addr_bytes = addr.encode('utf-8')
            leaf_data.append(addr_bytes)
        
        root_hash = self._build_tree(leaf_data, MerkleLeafType.ADDRESS)
        
        self.construction_time = time.time() - start_time
        self.logger.info(f"Tree construction completed in {self.construction_time:.3f}s")
        
        return root_hash
    
    def build_from_hashes(self, hashes: List[bytes]) -> bytes:
        """
        Build Merkle tree from pre-computed hashes.
        
        Args:
            hashes: List of 32-byte hashes
            
        Returns:
            Root hash of constructed tree
        """
        if not hashes:
            raise ValueError("Cannot build tree from empty hash list")
        
        # Validate all hashes are 32 bytes
        for i, h in enumerate(hashes):
            if len(h) != 32:
                raise ValueError(f"Hash at index {i} is not 32 bytes")
        
        # Sort hashes for deterministic construction
        sorted_hashes = sorted(set(hashes))
        
        return self._build_tree(sorted_hashes, MerkleLeafType.HASH)
    
    def build_from_data(self, data_items: List[bytes]) -> bytes:
        """
        Build Merkle tree from arbitrary data items.
        
        Args:
            data_items: List of data items as bytes
            
        Returns:
            Root hash of constructed tree
        """
        if not data_items:
            raise ValueError("Cannot build tree from empty data list")
        
        # Sort data for deterministic construction
        sorted_data = sorted(set(data_items))
        
        return self._build_tree(sorted_data, MerkleLeafType.DATA)
    
    def _build_tree(self, items: List[bytes], leaf_type: MerkleLeafType) -> bytes:
        """
        Internal tree construction method.
        
        Args:
            items: Sorted list of items to include
            leaf_type: Type of leaf data
            
        Returns:
            Root hash
        """
        self.logger.debug(f"Building tree with {len(items)} items of type {leaf_type.value}")
        
        # Clear existing state
        self.leaves.clear()
        self._leaf_index.clear()
        self._data_index.clear()
        
        # Create leaf nodes
        for i, item in enumerate(items):
            if leaf_type == MerkleLeafType.HASH:
                # Item is already a hash
                leaf_hash = item
                leaf_data = item  # Store hash as data too
            else:
                # Hash the item
                leaf_hash = self.hasher.hash_leaf(item)
                leaf_data = item
            
            leaf_node = MerkleNode(
                hash=leaf_hash,
                data=leaf_data,
                is_leaf=True,
                level=0,  # Leaves are always at level 0
                index=i
            )
            
            self.leaves.append(leaf_node)
            self._leaf_index[leaf_hash] = i
            self._data_index[leaf_data] = i
        
        self.node_count = len(self.leaves)
        
        # Build tree bottom-up
        if len(self.leaves) == 1:
            # Single leaf case
            self.root = self.leaves[0]
            self.root.level = 0  # Single leaf is both leaf and root at level 0
            self.height = 1
        else:
            # Start recursive build from level 1 (above leaves at level 0)
            self.root = self._build_tree_recursive(self.leaves, 1)
            self.height = self.root.level + 1
        
        self.logger.debug(f"Tree built: height={self.height}, nodes={self.node_count}")
        
        return self.root.hash
    
    def _build_tree_recursive(self, nodes: List[MerkleNode], level: int) -> MerkleNode:
        """
        Recursively build tree from bottom level up.
        
        Args:
            nodes: Nodes at current level
            level: Current tree level (0 = leaves)
            
        Returns:
            Root node of subtree
        """
        if len(nodes) == 1:
            # Don't update the level - return the node as-is
            # It already has the correct level from when it was created
            return nodes[0]
        
        next_level = []
        
        # Pair up nodes
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            
            if i + 1 < len(nodes):
                # Pair exists
                right = nodes[i + 1]
            else:
                # Odd number of nodes - duplicate last node
                right = nodes[i]
            
            # Create internal node
            internal_hash = self.hasher.hash_internal(left.hash, right.hash)
            internal_node = MerkleNode(
                hash=internal_hash,
                left=left,
                right=right,
                is_leaf=False,
                level=level,
                index=i // 2
            )
            
            next_level.append(internal_node)
            self.node_count += 1
        
        return self._build_tree_recursive(next_level, level + 1)
    
    def get_root_hash(self) -> Optional[bytes]:
        """Get root hash of tree."""
        return self.root.hash if self.root else None
    
    def get_leaf_count(self) -> int:
        """Get number of leaves in tree."""
        return len(self.leaves)
    
    def get_height(self) -> int:
        """Get height of tree."""
        return self.height
    
    def get_node_count(self) -> int:
        """Get total number of nodes in tree."""
        return self.node_count
    
    def find_leaf_by_data(self, data: bytes) -> Optional[MerkleNode]:
        """
        Find leaf node by original data.
        
        Args:
            data: Original leaf data
            
        Returns:
            Leaf node if found, None otherwise
        """
        index = self._data_index.get(data)
        if index is not None and index < len(self.leaves):
            return self.leaves[index]
        return None
    
    def find_leaf_by_hash(self, leaf_hash: bytes) -> Optional[MerkleNode]:
        """
        Find leaf node by hash.
        
        Args:
            leaf_hash: Hash of leaf
            
        Returns:
            Leaf node if found, None otherwise
        """
        index = self._leaf_index.get(leaf_hash)
        if index is not None and index < len(self.leaves):
            return self.leaves[index]
        return None
    
    def find_leaf_by_address(self, address: str) -> Optional[MerkleNode]:
        """
        Find leaf node by Bitcoin address.
        
        Args:
            address: Bitcoin address string
            
        Returns:
            Leaf node if found, None otherwise
        """
        addr_bytes = address.encode('utf-8')
        return self.find_leaf_by_data(addr_bytes)
    
    def contains_address(self, address: str) -> bool:
        """Check if tree contains given address."""
        return self.find_leaf_by_address(address) is not None
    
    def contains_data(self, data: bytes) -> bool:
        """Check if tree contains given data."""
        return self.find_leaf_by_data(data) is not None
    
    def get_tree_info(self) -> Dict[str, Any]:
        """Get comprehensive information about the tree."""
        return {
            "root_hash": self.root.hash.hex() if self.root else None,
            "leaf_count": self.get_leaf_count(),
            "height": self.get_height(),
            "node_count": self.get_node_count(),
            "construction_time_ms": self.construction_time * 1000,
            "last_proof_time_ms": self.last_proof_time * 1000,
            "memory_efficient": self.node_count > 0
        }
    
    def validate_tree_structure(self) -> Tuple[bool, List[str]]:
        """
        Validate internal tree structure for consistency.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if not self.root:
            errors.append("Tree has no root")
            return False, errors
        
        if len(self.leaves) == 0:
            errors.append("Tree has no leaves")
            return False, errors
        
        # Check root hash consistency
        if len(self.leaves) == 1:
            if self.root != self.leaves[0]:
                errors.append("Single leaf tree root mismatch")
        else:
            # Verify tree structure recursively
            # Root should be at the highest level (height - 1)
            root_level = self.height - 1
            tree_errors = self._validate_node_recursive(self.root, root_level)
            errors.extend(tree_errors)
        
        # Check leaf indexing
        for i, leaf in enumerate(self.leaves):
            if leaf.index != i:
                errors.append(f"Leaf {i} has incorrect index {leaf.index}")
        
        return len(errors) == 0, errors
    
    def _validate_node_recursive(self, node: MerkleNode, expected_level: int) -> List[str]:
        """Recursively validate node structure."""
        errors = []
        
        if node.level != expected_level:
            errors.append(f"Node at level {node.level} expected at level {expected_level}")
        
        if node.is_leaf:
            if node.left is not None or node.right is not None:
                errors.append("Leaf node has children")
            if node.data is None:
                errors.append("Leaf node missing data")
            if expected_level != 0:
                errors.append(f"Leaf node at level {expected_level}, should be at level 0")
        else:
            if node.left is None or node.right is None:
                errors.append("Internal node missing children")
            else:
                # Verify hash computation
                expected_hash = self.hasher.hash_internal(node.left.hash, node.right.hash)
                if node.hash != expected_hash:
                    errors.append(f"Internal node hash mismatch at level {node.level}")
                
                # Recurse to children - children should be at level-1
                errors.extend(self._validate_node_recursive(node.left, expected_level - 1))
                errors.extend(self._validate_node_recursive(node.right, expected_level - 1))
        
        return errors
    
    def generate_proof(self, leaf_data: bytes) -> Optional[MerkleProof]:
        """
        Generate Merkle proof for a specific leaf.
        
        Args:
            leaf_data: Original leaf data to generate proof for
            
        Returns:
            MerkleProof if leaf found, None otherwise
        """
        import time
        start_time = time.time()
        
        # Find the leaf node
        leaf_node = self.find_leaf_by_data(leaf_data)
        if not leaf_node:
            return None
        
        # Get leaf index
        leaf_index = self._data_index[leaf_data]
        
        # Generate proof path
        proof_hashes, proof_indices = self._generate_proof_path(leaf_index)
        
        proof = MerkleProof(
            leaf_data=leaf_data,
            leaf_hash=leaf_node.hash,
            proof_hashes=proof_hashes,
            proof_indices=proof_indices,
            root_hash=self.root.hash,
            leaf_index=leaf_index,
            tree_size=len(self.leaves)
        )
        
        self.last_proof_time = time.time() - start_time
        return proof
    
    def generate_proof_for_address(self, address: str) -> Optional[MerkleProof]:
        """
        Generate Merkle proof for a Bitcoin address.
        
        Args:
            address: Bitcoin address string
            
        Returns:
            MerkleProof if address found, None otherwise
        """
        addr_bytes = address.encode('utf-8')
        return self.generate_proof(addr_bytes)
    
    def generate_proof_for_hash(self, leaf_hash: bytes) -> Optional[MerkleProof]:
        """
        Generate Merkle proof for a leaf hash.
        
        Args:
            leaf_hash: Hash of the leaf to generate proof for
            
        Returns:
            MerkleProof if hash found, None otherwise
        """
        leaf_node = self.find_leaf_by_hash(leaf_hash)
        if not leaf_node:
            return None
        
        return self.generate_proof(leaf_node.data)
    
    def generate_batch_proofs(self, leaf_data_list: List[bytes]) -> Dict[bytes, Optional[MerkleProof]]:
        """
        Generate proofs for multiple leaves efficiently.
        
        Args:
            leaf_data_list: List of leaf data to generate proofs for
            
        Returns:
            Dictionary mapping leaf_data to MerkleProof (None if not found)
        """
        results = {}
        
        for leaf_data in leaf_data_list:
            results[leaf_data] = self.generate_proof(leaf_data)
        
        return results
    
    def _generate_proof_path(self, leaf_index: int) -> Tuple[List[bytes], List[int]]:
        """
        Generate proof path from leaf to root.
        
        Args:
            leaf_index: Index of the leaf in the leaves array
            
        Returns:
            Tuple of (proof_hashes, proof_indices)
            proof_indices: 0 = sibling is on the left, 1 = sibling is on the right
        """
        proof_hashes = []
        proof_indices = []
        
        if len(self.leaves) == 1:
            # Single leaf tree has no proof path
            return proof_hashes, proof_indices
        
        # Start with leaf level
        current_index = leaf_index
        current_level_size = len(self.leaves)
        
        # Walk up the tree
        while current_level_size > 1:
            # Find sibling index
            if current_index % 2 == 0:
                # Current node is left child, sibling is right
                sibling_index = current_index + 1
                proof_indices.append(1)  # Sibling is on the right
            else:
                # Current node is right child, sibling is left
                sibling_index = current_index - 1
                proof_indices.append(0)  # Sibling is on the left
            
            # Get sibling hash
            if sibling_index < current_level_size:
                # Sibling exists
                sibling_hash = self._get_node_hash_at_level_and_index(
                    self._get_level_from_size(current_level_size), 
                    sibling_index
                )
            else:
                # No sibling (odd number of nodes), sibling is the same as current
                sibling_hash = self._get_node_hash_at_level_and_index(
                    self._get_level_from_size(current_level_size), 
                    current_index
                )
            
            proof_hashes.append(sibling_hash)
            
            # Move up to parent level
            current_index = current_index // 2
            current_level_size = (current_level_size + 1) // 2
        
        return proof_hashes, proof_indices
    
    def _get_level_from_size(self, level_size: int) -> int:
        """Calculate level number from level size."""
        return math.ceil(math.log2(max(1, len(self.leaves)))) - math.ceil(math.log2(max(1, level_size)))
    
    def _get_node_hash_at_level_and_index(self, level: int, index: int) -> bytes:
        """
        Get hash of node at specific level and index.
        
        This is a simplified implementation that rebuilds the tree path.
        For production, consider caching intermediate nodes.
        """
        if level == 0:
            # Leaf level
            if index < len(self.leaves):
                return self.leaves[index].hash
            else:
                # Duplicate last leaf for odd number of leaves
                return self.leaves[-1].hash
        
        # Calculate child indices
        left_child_index = index * 2
        right_child_index = index * 2 + 1
        
        # Get child hashes
        left_hash = self._get_node_hash_at_level_and_index(level - 1, left_child_index)
        
        # Check if right child exists at the child level
        child_level_size = 2 ** (level - 1) if level > 0 else len(self.leaves)
        max_child_level_size = len(self.leaves) >> (level - 1) if level > 1 else len(self.leaves)
        
        if right_child_index < max_child_level_size:
            right_hash = self._get_node_hash_at_level_and_index(level - 1, right_child_index)
        else:
            # No right child, duplicate left
            right_hash = left_hash
        
        # Compute internal node hash
        return self.hasher.hash_internal(left_hash, right_hash)
    
    def verify_proof(self, proof: MerkleProof) -> bool:
        """
        Verify a Merkle proof against this tree's root.
        
        Args:
            proof: MerkleProof to verify
            
        Returns:
            True if proof is valid for this tree
        """
        if not self.root:
            return False
        
        # Check if proof is for this tree
        if proof.root_hash != self.root.hash:
            return False
        
        # Verify leaf hash
        expected_leaf_hash = self.hasher.hash_leaf(proof.leaf_data)
        if expected_leaf_hash != proof.leaf_hash:
            return False
        
        # Reconstruct root hash from proof
        current_hash = proof.leaf_hash
        
        for sibling_hash, is_right_sibling in zip(proof.proof_hashes, proof.proof_indices):
            if is_right_sibling:
                # Sibling is on the right
                current_hash = self.hasher.hash_internal(current_hash, sibling_hash)
            else:
                # Sibling is on the left
                current_hash = self.hasher.hash_internal(sibling_hash, current_hash)
        
        return current_hash == proof.root_hash

    def get_statistics(self) -> Dict[str, Any]:
        """Get tree statistics for performance analysis."""
        if not self.root:
            return {"status": "empty_tree"}
        
        return {
            "leaf_count": len(self.leaves),
            "internal_node_count": self.node_count - len(self.leaves),
            "total_nodes": self.node_count,
            "height": self.height,
            "max_theoretical_height": math.ceil(math.log2(max(1, len(self.leaves)))),
            "is_balanced": self._check_balance(),
            "construction_time_seconds": self.construction_time,
            "last_proof_time_seconds": self.last_proof_time,
            "memory_usage_estimate_bytes": self._estimate_memory_usage()
        }
    
    def _check_balance(self) -> bool:
        """Check if tree is reasonably balanced."""
        if not self.root or len(self.leaves) <= 1:
            return True
        
        theoretical_height = math.ceil(math.log2(len(self.leaves)))
        # Allow up to 2 levels above theoretical minimum
        return self.height <= theoretical_height + 2
    
    def _estimate_memory_usage(self) -> int:
        """Estimate memory usage of tree in bytes."""
        # Rough estimation: each node ~100 bytes + hash data
        return self.node_count * 100 + len(self.leaves) * 64  # Rough estimate


# Convenience functions

def build_address_merkle_tree(addresses: List[str]) -> Tuple[MerkleTree, bytes]:
    """
    Convenience function to build Merkle tree from addresses.
    
    Args:
        addresses: List of Bitcoin addresses
        
    Returns:
        Tuple of (tree, root_hash)
    """
    tree = MerkleTree()
    root_hash = tree.build_from_addresses(addresses)
    return tree, root_hash


def build_data_merkle_tree(data_items: List[bytes]) -> Tuple[MerkleTree, bytes]:
    """
    Convenience function to build Merkle tree from data.
    
    Args:
        data_items: List of data items
        
    Returns:
        Tuple of (tree, root_hash)
    """
    tree = MerkleTree()
    root_hash = tree.build_from_data(data_items)
    return tree, root_hash


def verify_merkle_proof_standalone(
    leaf_data: bytes,
    proof_hashes: List[bytes],
    proof_indices: List[int],
    root_hash: bytes,
    hasher: Optional[MerkleHasher] = None
) -> bool:
    """
    Verify a Merkle proof without needing the full tree.
    
    Args:
        leaf_data: Original leaf data
        proof_hashes: List of sibling hashes in proof path
        proof_indices: List indicating sibling positions (0=left, 1=right)
        root_hash: Expected root hash
        hasher: Custom hasher (optional)
        
    Returns:
        True if proof is valid
    """
    if not hasher:
        hasher = MerkleHasher()
    
    # Compute leaf hash
    current_hash = hasher.hash_leaf(leaf_data)
    
    # Reconstruct root hash
    for sibling_hash, is_right_sibling in zip(proof_hashes, proof_indices):
        if is_right_sibling:
            # Sibling is on the right
            current_hash = hasher.hash_internal(current_hash, sibling_hash)
        else:
            # Sibling is on the left
            current_hash = hasher.hash_internal(sibling_hash, current_hash)
    
    return current_hash == root_hash


def verify_merkle_proof(proof: MerkleProof, hasher: Optional[MerkleHasher] = None) -> bool:
    """
    Verify a MerkleProof object.
    
    Args:
        proof: MerkleProof to verify
        hasher: Custom hasher (optional)
        
    Returns:
        True if proof is valid
    """
    return verify_merkle_proof_standalone(
        proof.leaf_data,
        proof.proof_hashes,
        proof.proof_indices,
        proof.root_hash,
        hasher
    )


def generate_address_proof(tree: MerkleTree, address: str) -> Optional[MerkleProof]:
    """
    Generate proof for a Bitcoin address in the allowlist.
    
    Args:
        tree: Merkle tree containing the allowlist
        address: Bitcoin address to generate proof for
        
    Returns:
        MerkleProof if address found, None otherwise
    """
    return tree.generate_proof_for_address(address)


def verify_address_allowlist(
    address: str,
    proof: MerkleProof,
    allowlist_root: bytes,
    hasher: Optional[MerkleHasher] = None
) -> bool:
    """
    Verify that an address is in the allowlist using a Merkle proof.
    
    Args:
        address: Bitcoin address to verify
        proof: Merkle proof for the address
        allowlist_root: Root hash of the allowlist Merkle tree
        hasher: Custom hasher (optional)
        
    Returns:
        True if address is proven to be in the allowlist
    """
    # Check that proof is for the correct root
    if proof.root_hash != allowlist_root:
        return False
    
    # Check that proof is for the correct address
    addr_bytes = address.encode('utf-8')
    if proof.leaf_data != addr_bytes:
        return False
    
    return verify_merkle_proof(proof, hasher)


def create_allowlist_tree_from_addresses(addresses: List[str]) -> Tuple[MerkleTree, bytes, Dict[str, MerkleProof]]:
    """
    Create allowlist Merkle tree and generate proofs for all addresses.
    
    Args:
        addresses: List of Bitcoin addresses for the allowlist
        
    Returns:
        Tuple of (tree, root_hash, proofs_dict)
        proofs_dict maps address -> MerkleProof
    """
    tree = MerkleTree()
    root_hash = tree.build_from_addresses(addresses)
    
    # Generate proofs for all addresses
    proofs = {}
    for addr in addresses:
        proof = tree.generate_proof_for_address(addr)
        if proof:
            proofs[addr] = proof
    
    return tree, root_hash, proofs


def verify_merkle_tree_integrity(tree: MerkleTree) -> bool:
    """
    Verify that a Merkle tree has correct structure and hashes.
    
    Args:
        tree: Merkle tree to verify
        
    Returns:
        True if tree is valid
    """
    is_valid, errors = tree.validate_tree_structure()
    if errors:
        logger = logging.getLogger(__name__)
        for error in errors:
            logger.error(f"Tree validation error: {error}")
    
    return is_valid


# Testing and debugging utilities

def create_test_tree(size: int) -> MerkleTree:
    """Create a test Merkle tree with given number of leaves."""
    import secrets
    
    # Generate test addresses
    addresses = []
    for i in range(size):
        # Generate fake address-like strings
        addr = f"bc1q{secrets.token_hex(20)}"
        addresses.append(addr)
    
    tree = MerkleTree()
    tree.build_from_addresses(addresses)
    return tree


def benchmark_tree_construction(sizes: List[int]) -> Dict[int, float]:
    """Benchmark tree construction for different sizes."""
    results = {}
    
    for size in sizes:
        tree = create_test_tree(size)
        results[size] = tree.construction_time
    
    return results


def benchmark_proof_generation(tree_size: int, num_proofs: int) -> Dict[str, float]:
    """
    Benchmark proof generation performance.
    
    Args:
        tree_size: Number of leaves in test tree
        num_proofs: Number of proofs to generate
        
    Returns:
        Dictionary with timing results
    """
    import time
    import random
    import secrets
    
    # Create test tree
    tree = create_test_tree(tree_size)
    
    # Select random addresses to generate proofs for
    addresses = []
    for i in range(tree_size):
        addr = f"bc1q{secrets.token_hex(20)}"
        addresses.append(addr)
    
    tree.build_from_addresses(addresses)
    
    # Random selection for proof generation
    test_addresses = random.sample(addresses, min(num_proofs, len(addresses)))
    
    # Benchmark single proof generation
    start_time = time.time()
    for addr in test_addresses:
        proof = tree.generate_proof_for_address(addr)
    single_proof_time = time.time() - start_time
    
    # Benchmark batch proof generation
    start_time = time.time()
    batch_data = [addr.encode('utf-8') for addr in test_addresses]
    batch_proofs = tree.generate_batch_proofs(batch_data)
    batch_proof_time = time.time() - start_time
    
    return {
        "tree_size": tree_size,
        "num_proofs": num_proofs,
        "single_proof_total_time": single_proof_time,
        "single_proof_avg_time": single_proof_time / num_proofs,
        "batch_proof_total_time": batch_proof_time,
        "batch_proof_avg_time": batch_proof_time / num_proofs,
        "batch_speedup": single_proof_time / batch_proof_time if batch_proof_time > 0 else 0
    }


def test_proof_generation_and_verification():
    """Test proof generation and verification functionality."""
    import secrets
    
    print("Testing Merkle Proof Generation and Verification")
    print("=" * 60)
    
    # Test with small tree
    test_addresses = [
        "bc1qaddr1example123456789012345",
        "bc1qaddr2example123456789012345", 
        "bc1qaddr3example123456789012345",
        "bc1qaddr4example123456789012345",
        "bc1qaddr5example123456789012345"
    ]
    
    tree, root_hash, all_proofs = create_allowlist_tree_from_addresses(test_addresses)
    
    print(f"Created allowlist tree with {len(test_addresses)} addresses")
    print(f"Root hash: {root_hash.hex()}")
    print(f"Generated {len(all_proofs)} proofs")
    
    # Test individual proof verification
    test_addr = test_addresses[0]
    proof = all_proofs[test_addr]
    
    # Verify using tree method
    tree_verification = tree.verify_proof(proof)
    
    # Verify using standalone method  
    standalone_verification = verify_merkle_proof(proof)
    
    # Verify using allowlist method
    allowlist_verification = verify_address_allowlist(test_addr, proof, root_hash)
    
    print(f"\nProof verification for {test_addr}:")
    print(f"  Tree method: {'PASS' if tree_verification else 'FAIL'}")
    print(f"  Standalone method: {'PASS' if standalone_verification else 'FAIL'}")
    print(f"  Allowlist method: {'PASS' if allowlist_verification else 'FAIL'}")
    
    # Test proof for non-existent address
    fake_addr = "bc1qfakeaddress123456789012345"
    fake_proof = tree.generate_proof_for_address(fake_addr)
    print(f"  Proof for non-existent address: {'None' if fake_proof is None else 'ERROR'}")
    
    # Test with invalid proof
    try:
        # Modify proof data to make it invalid
        invalid_proof = MerkleProof(
            leaf_data=proof.leaf_data,
            leaf_hash=proof.leaf_hash,
            proof_hashes=proof.proof_hashes[:-1] + [b'\\x00' * 32],  # Wrong last hash
            proof_indices=proof.proof_indices,
            root_hash=proof.root_hash,
            leaf_index=proof.leaf_index,
            tree_size=proof.tree_size
        )
        
        invalid_verification = verify_merkle_proof(invalid_proof)
        print(f"  Invalid proof verification: {'FAIL' if not invalid_verification else 'ERROR'}")
        
    except Exception as e:
        print(f"  Invalid proof test: PASS (caught exception: {e})")
    
    # Performance test
    print(f"\nPerformance test:")
    perf_results = benchmark_proof_generation(100, 20)
    print(f"  Tree size: {perf_results['tree_size']} leaves")
    print(f"  Proofs generated: {perf_results['num_proofs']}")
    print(f"  Avg single proof time: {perf_results['single_proof_avg_time']:.4f}s")
    print(f"  Avg batch proof time: {perf_results['batch_proof_avg_time']:.4f}s")
    
    return all([tree_verification, standalone_verification, allowlist_verification])


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test-proofs":
        # Run comprehensive proof tests
        success = test_proof_generation_and_verification()
        sys.exit(0 if success else 1)
    
    # Quick test and demonstration
    print("Merkle Tree Implementation Test")
    print("=" * 40)
    
    # Create small test tree
    test_addresses = [
        "bc1qaddr1example123456789012345",
        "bc1qaddr2example123456789012345", 
        "bc1qaddr3example123456789012345",
        "bc1qaddr4example123456789012345"
    ]
    
    tree, root_hash = build_address_merkle_tree(test_addresses)
    
    print(f"Built tree with {len(test_addresses)} addresses")
    print(f"Root hash: {root_hash.hex()}")
    print(f"Tree height: {tree.get_height()}")
    print(f"Construction time: {tree.construction_time:.3f}s")
    
    # Validate tree
    is_valid = verify_merkle_tree_integrity(tree)
    print(f"Tree validation: {'PASS' if is_valid else 'FAIL'}")
    
    # Test address lookup
    test_addr = test_addresses[0]
    found = tree.contains_address(test_addr)
    print(f"Address lookup test: {'PASS' if found else 'FAIL'}")
    
    # Test proof generation
    proof = tree.generate_proof_for_address(test_addr)
    if proof:
        proof_valid = tree.verify_proof(proof)
        print(f"Proof generation test: {'PASS' if proof_valid else 'FAIL'}")
        print(f"Proof path length: {proof.get_path_length()}")
    else:
        print("Proof generation test: FAIL (no proof generated)")
    
    print("\nBasic tests completed successfully!")
    print("Run 'python merkle.py test-proofs' for comprehensive proof testing.")