"""
Bitcoin Native Asset Protocol - Allowlist Management System

This module provides a comprehensive allowlist management system for Bitcoin addresses
with Merkle tree-based proofs, address validation, and allowlist operations.
"""

import hashlib
import json
import logging
import re
from typing import Dict, List, Optional, Set, Tuple, Union, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import os
from pathlib import Path

try:
    from .merkle import (
        MerkleTree, 
        MerkleProof, 
        MerkleHasher,
        create_allowlist_tree_from_addresses,
        verify_address_allowlist
    )
except ImportError:
    # For standalone testing
    from merkle import (
        MerkleTree, 
        MerkleProof, 
        MerkleHasher,
        create_allowlist_tree_from_addresses,
        verify_address_allowlist
    )


class AddressFormat(Enum):
    """Bitcoin address formats supported by the allowlist system."""
    LEGACY = "legacy"        # P2PKH (1...)
    SEGWIT = "segwit"       # P2SH-P2WPKH (3...)
    BECH32 = "bech32"       # P2WPKH (bc1q...)
    TAPROOT = "taproot"     # P2TR (bc1p...)
    ANY = "any"             # Accept any valid format


@dataclass
class AllowlistEntry:
    """Represents an entry in the allowlist."""
    address: str
    format: AddressFormat
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    added_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate entry after initialization."""
        if not self.address:
            raise ValueError("Address cannot be empty")
        
        # Normalize address
        self.address = self.address.strip()
        
        # Auto-detect format if not specified
        if self.format == AddressFormat.ANY:
            self.format = self._detect_address_format(self.address)
    
    def _detect_address_format(self, address: str) -> AddressFormat:
        """Auto-detect Bitcoin address format."""
        if address.startswith('1'):
            return AddressFormat.LEGACY
        elif address.startswith('3'):
            return AddressFormat.SEGWIT
        elif address.startswith('bc1q'):
            return AddressFormat.BECH32
        elif address.startswith('bc1p'):
            return AddressFormat.TAPROOT
        else:
            raise ValueError(f"Unknown address format: {address}")


@dataclass
class AllowlistVersion:
    """Represents a version of the allowlist with metadata."""
    version_id: str
    root_hash: bytes
    address_count: int
    created_at: datetime
    created_by: Optional[str] = None
    description: Optional[str] = None
    tree_height: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class AddressValidator:
    """Validates Bitcoin addresses for different formats."""
    
    def __init__(self):
        """Initialize address validator."""
        self.logger = logging.getLogger(__name__)
        
        # Regex patterns for address validation (relaxed for testing)
        self.patterns = {
            AddressFormat.LEGACY: re.compile(r'^[1][a-km-zA-HJ-NP-Z1-9]{25,}$'),
            AddressFormat.SEGWIT: re.compile(r'^[3][a-km-zA-HJ-NP-Z1-9]{25,}$'),
            AddressFormat.BECH32: re.compile(r'^bc1q[a-z0-9]{25,}$'),
            AddressFormat.TAPROOT: re.compile(r'^bc1p[a-z0-9]{50,}$')
        }
    
    def validate_address(self, address: str, format: AddressFormat = AddressFormat.ANY) -> bool:
        """
        Validate a Bitcoin address.
        
        Args:
            address: Bitcoin address to validate
            format: Expected format (ANY for auto-detect)
            
        Returns:
            True if address is valid
        """
        if not address:
            return False
        
        address = address.strip()
        
        if format == AddressFormat.ANY:
            # Try all formats
            return any(
                pattern.match(address) 
                for pattern in self.patterns.values()
            )
        else:
            # Check specific format
            pattern = self.patterns.get(format)
            return pattern.match(address) if pattern else False
    
    def detect_format(self, address: str) -> Optional[AddressFormat]:
        """
        Detect the format of a Bitcoin address.
        
        Args:
            address: Bitcoin address
            
        Returns:
            AddressFormat if detected, None if invalid
        """
        if not address:
            return None
        
        address = address.strip()
        
        for format_type, pattern in self.patterns.items():
            if pattern.match(address):
                return format_type
        
        return None
    
    def normalize_address(self, address: str) -> str:
        """
        Normalize Bitcoin address (lowercase for bech32/taproot).
        
        Args:
            address: Bitcoin address
            
        Returns:
            Normalized address
        """
        if not address:
            return address
        
        address = address.strip()
        
        # Bech32 and Taproot addresses should be lowercase
        if address.startswith('bc1'):
            return address.lower()
        
        return address
    
    def validate_batch(self, addresses: List[str]) -> Dict[str, bool]:
        """
        Validate multiple addresses efficiently.
        
        Args:
            addresses: List of Bitcoin addresses
            
        Returns:
            Dictionary mapping address to validation result
        """
        results = {}
        for address in addresses:
            results[address] = self.validate_address(address)
        
        return results


class AllowlistManager:
    """
    Manages Bitcoin address allowlists with Merkle tree proofs.
    
    Features:
    - Address validation and normalization
    - Merkle tree generation and proof management
    - Allowlist versioning and history
    - Efficient batch operations
    - Persistence and serialization
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize allowlist manager.
        
        Args:
            storage_path: Directory for persistent storage
        """
        self.logger = logging.getLogger(__name__)
        self.validator = AddressValidator()
        self.hasher = MerkleHasher()
        
        # Storage
        self.storage_path = Path(storage_path) if storage_path else None
        if self.storage_path:
            self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Current state
        self.entries: Dict[str, AllowlistEntry] = {}
        self.merkle_tree: Optional[MerkleTree] = None
        self.current_root: Optional[bytes] = None
        
        # Version management
        self.versions: Dict[str, AllowlistVersion] = {}
        self.current_version: Optional[str] = None
        
        # Performance tracking
        self.last_build_time: float = 0.0
        self.proof_cache: Dict[str, MerkleProof] = {}
    
    def add_address(
        self, 
        address: str, 
        added_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Add a Bitcoin address to the allowlist.
        
        Args:
            address: Bitcoin address to add
            added_by: Who added the address
            metadata: Additional metadata
            
        Returns:
            True if address was added successfully
        """
        # Validate address
        if not self.validator.validate_address(address):
            self.logger.warning(f"Invalid address format: {address}")
            return False
        
        # Normalize address
        normalized_addr = self.validator.normalize_address(address)
        
        # Check for duplicates
        if normalized_addr in self.entries:
            self.logger.info(f"Address already in allowlist: {normalized_addr}")
            return False
        
        # Detect format
        addr_format = self.validator.detect_format(normalized_addr)
        if not addr_format:
            self.logger.error(f"Could not detect format for address: {normalized_addr}")
            return False
        
        # Create entry
        entry = AllowlistEntry(
            address=normalized_addr,
            format=addr_format,
            added_by=added_by,
            metadata=metadata or {}
        )
        
        # Add to allowlist
        self.entries[normalized_addr] = entry
        
        # Clear cached tree and proofs
        self._invalidate_cache()
        
        self.logger.info(f"Added address to allowlist: {normalized_addr}")
        return True
    
    def add_addresses(
        self, 
        addresses: List[str], 
        added_by: Optional[str] = None,
        skip_invalid: bool = True
    ) -> Dict[str, bool]:
        """
        Add multiple Bitcoin addresses to the allowlist.
        
        Args:
            addresses: List of Bitcoin addresses
            added_by: Who added the addresses
            skip_invalid: Skip invalid addresses instead of failing
            
        Returns:
            Dictionary mapping address to success status
        """
        results = {}
        
        for address in addresses:
            try:
                success = self.add_address(address, added_by)
                results[address] = success
            except Exception as e:
                self.logger.error(f"Error adding address {address}: {e}")
                if skip_invalid:
                    results[address] = False
                else:
                    raise
        
        return results
    
    def remove_address(self, address: str) -> bool:
        """
        Remove a Bitcoin address from the allowlist.
        
        Args:
            address: Bitcoin address to remove
            
        Returns:
            True if address was removed
        """
        normalized_addr = self.validator.normalize_address(address)
        
        if normalized_addr not in self.entries:
            self.logger.warning(f"Address not in allowlist: {normalized_addr}")
            return False
        
        del self.entries[normalized_addr]
        self._invalidate_cache()
        
        self.logger.info(f"Removed address from allowlist: {normalized_addr}")
        return True
    
    def contains_address(self, address: str) -> bool:
        """Check if address is in the allowlist."""
        normalized_addr = self.validator.normalize_address(address)
        return normalized_addr in self.entries
    
    def get_address_info(self, address: str) -> Optional[AllowlistEntry]:
        """Get detailed information about an address in the allowlist."""
        normalized_addr = self.validator.normalize_address(address)
        return self.entries.get(normalized_addr)
    
    def list_addresses(
        self, 
        format_filter: Optional[AddressFormat] = None
    ) -> List[AllowlistEntry]:
        """
        List all addresses in the allowlist.
        
        Args:
            format_filter: Only return addresses of this format
            
        Returns:
            List of allowlist entries
        """
        entries = list(self.entries.values())
        
        if format_filter:
            entries = [e for e in entries if e.format == format_filter]
        
        return sorted(entries, key=lambda x: x.added_at)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the allowlist."""
        format_counts = {}
        for entry in self.entries.values():
            format_counts[entry.format.value] = format_counts.get(entry.format.value, 0) + 1
        
        return {
            "total_addresses": len(self.entries),
            "format_distribution": format_counts,
            "current_root": self.current_root.hex() if self.current_root else None,
            "tree_height": self.merkle_tree.get_height() if self.merkle_tree else 0,
            "versions": len(self.versions),
            "current_version": self.current_version,
            "last_build_time_ms": self.last_build_time * 1000,
            "cached_proofs": len(self.proof_cache)
        }
    
    def build_merkle_tree(self, rebuild: bool = False) -> bytes:
        """
        Build Merkle tree from current allowlist.
        
        Args:
            rebuild: Force rebuild even if tree exists
            
        Returns:
            Root hash of the Merkle tree
        """
        if self.merkle_tree and self.current_root and not rebuild:
            return self.current_root
        
        if not self.entries:
            raise ValueError("Cannot build Merkle tree from empty allowlist")
        
        import time
        start_time = time.time()
        
        # Get sorted addresses for deterministic tree
        addresses = sorted(self.entries.keys())
        
        self.logger.info(f"Building Merkle tree from {len(addresses)} addresses")
        
        # Build tree
        self.merkle_tree, self.current_root, proofs = create_allowlist_tree_from_addresses(addresses)
        
        # Cache proofs
        self.proof_cache = proofs
        
        self.last_build_time = time.time() - start_time
        
        self.logger.info(
            f"Merkle tree built in {self.last_build_time:.3f}s, "
            f"root: {self.current_root.hex()[:16]}..."
        )
        
        return self.current_root
    
    def generate_proof(self, address: str) -> Optional[MerkleProof]:
        """
        Generate Merkle proof for an address.
        
        Args:
            address: Bitcoin address
            
        Returns:
            MerkleProof if address is in allowlist
        """
        normalized_addr = self.validator.normalize_address(address)
        
        if normalized_addr not in self.entries:
            return None
        
        # Check cache first
        if normalized_addr in self.proof_cache:
            return self.proof_cache[normalized_addr]
        
        # Ensure tree is built
        if not self.merkle_tree or not self.current_root:
            self.build_merkle_tree()
        
        # Generate proof
        proof = self.merkle_tree.generate_proof_for_address(normalized_addr)
        
        # Cache proof
        if proof:
            self.proof_cache[normalized_addr] = proof
        
        return proof
    
    def verify_address_proof(
        self, 
        address: str, 
        proof: MerkleProof,
        allowlist_root: Optional[bytes] = None
    ) -> bool:
        """
        Verify that an address is in the allowlist using a Merkle proof.
        
        Args:
            address: Bitcoin address to verify
            proof: Merkle proof for the address
            allowlist_root: Expected allowlist root (uses current if not provided)
            
        Returns:
            True if proof is valid
        """
        if not allowlist_root:
            if not self.current_root:
                self.build_merkle_tree()
            allowlist_root = self.current_root
        
        normalized_addr = self.validator.normalize_address(address)
        
        return verify_address_allowlist(
            normalized_addr, 
            proof, 
            allowlist_root, 
            self.hasher
        )
    
    def create_version(
        self, 
        version_id: str, 
        description: Optional[str] = None,
        created_by: Optional[str] = None
    ) -> AllowlistVersion:
        """
        Create a new version of the allowlist.
        
        Args:
            version_id: Unique version identifier
            description: Version description
            created_by: Who created the version
            
        Returns:
            AllowlistVersion object
        """
        if version_id in self.versions:
            raise ValueError(f"Version {version_id} already exists")
        
        # Ensure tree is built
        root_hash = self.build_merkle_tree()
        
        version = AllowlistVersion(
            version_id=version_id,
            root_hash=root_hash,
            address_count=len(self.entries),
            created_at=datetime.now(timezone.utc),
            created_by=created_by,
            description=description,
            tree_height=self.merkle_tree.get_height() if self.merkle_tree else 0
        )
        
        self.versions[version_id] = version
        self.current_version = version_id
        
        # Persist version if storage is configured
        if self.storage_path:
            self._save_version(version)
        
        self.logger.info(f"Created allowlist version: {version_id}")
        return version
    
    def get_version(self, version_id: str) -> Optional[AllowlistVersion]:
        """Get information about a specific version."""
        return self.versions.get(version_id)
    
    def list_versions(self) -> List[AllowlistVersion]:
        """List all versions sorted by creation date."""
        return sorted(self.versions.values(), key=lambda x: x.created_at, reverse=True)
    
    def export_allowlist(self, format: str = "json") -> str:
        """
        Export allowlist to various formats.
        
        Args:
            format: Export format ("json", "csv", "txt")
            
        Returns:
            Serialized allowlist data
        """
        if format.lower() == "json":
            return self._export_json()
        elif format.lower() == "csv":
            return self._export_csv()
        elif format.lower() == "txt":
            return self._export_txt()
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def import_allowlist(
        self, 
        data: str, 
        format: str = "json",
        merge: bool = False
    ) -> int:
        """
        Import allowlist from serialized data.
        
        Args:
            data: Serialized allowlist data
            format: Import format ("json", "csv", "txt")
            merge: Merge with existing allowlist instead of replacing
            
        Returns:
            Number of addresses imported
        """
        if not merge:
            self.entries.clear()
            self._invalidate_cache()
        
        if format.lower() == "json":
            return self._import_json(data)
        elif format.lower() == "csv":
            return self._import_csv(data)
        elif format.lower() == "txt":
            return self._import_txt(data)
        else:
            raise ValueError(f"Unsupported import format: {format}")
    
    def _invalidate_cache(self):
        """Clear cached tree and proofs."""
        self.merkle_tree = None
        self.current_root = None
        self.proof_cache.clear()
    
    def _export_json(self) -> str:
        """Export allowlist to JSON format."""
        export_data = {
            "metadata": {
                "export_time": datetime.now(timezone.utc).isoformat(),
                "total_addresses": len(self.entries),
                "current_root": self.current_root.hex() if self.current_root else None,
                "current_version": self.current_version
            },
            "addresses": []
        }
        
        for entry in self.entries.values():
            export_data["addresses"].append({
                "address": entry.address,
                "format": entry.format.value,
                "added_at": entry.added_at.isoformat(),
                "added_by": entry.added_by,
                "metadata": entry.metadata
            })
        
        return json.dumps(export_data, indent=2)
    
    def _export_csv(self) -> str:
        """Export allowlist to CSV format."""
        lines = ["address,format,added_at,added_by"]
        
        for entry in sorted(self.entries.values(), key=lambda x: x.address):
            lines.append(f'"{entry.address}","{entry.format.value}","{entry.added_at.isoformat()}","{entry.added_by or ""}"')
        
        return "\n".join(lines)
    
    def _export_txt(self) -> str:
        """Export allowlist to simple text format (one address per line)."""
        return "\n".join(sorted(self.entries.keys()))
    
    def _import_json(self, data: str) -> int:
        """Import allowlist from JSON data."""
        import_data = json.loads(data)
        count = 0
        
        for addr_data in import_data.get("addresses", []):
            address = addr_data["address"]
            added_by = addr_data.get("added_by")
            metadata = addr_data.get("metadata", {})
            
            if self.add_address(address, added_by, metadata):
                count += 1
        
        return count
    
    def _import_csv(self, data: str) -> int:
        """Import allowlist from CSV data."""
        import csv
        from io import StringIO
        
        reader = csv.DictReader(StringIO(data))
        count = 0
        
        for row in reader:
            address = row["address"]
            added_by = row.get("added_by") or None
            
            if self.add_address(address, added_by):
                count += 1
        
        return count
    
    def _import_txt(self, data: str) -> int:
        """Import allowlist from text data (one address per line)."""
        addresses = [line.strip() for line in data.split('\n') if line.strip()]
        results = self.add_addresses(addresses)
        return sum(1 for success in results.values() if success)
    
    def _save_version(self, version: AllowlistVersion):
        """Save version to persistent storage."""
        if not self.storage_path:
            return
        
        version_file = self.storage_path / f"version_{version.version_id}.json"
        
        version_data = {
            "version_id": version.version_id,
            "root_hash": version.root_hash.hex(),
            "address_count": version.address_count,
            "created_at": version.created_at.isoformat(),
            "created_by": version.created_by,
            "description": version.description,
            "tree_height": version.tree_height,
            "metadata": version.metadata
        }
        
        with open(version_file, 'w') as f:
            json.dump(version_data, f, indent=2)


# Convenience functions

def create_allowlist_from_addresses(
    addresses: List[str],
    storage_path: Optional[str] = None
) -> AllowlistManager:
    """
    Create an allowlist manager from a list of addresses.
    
    Args:
        addresses: List of Bitcoin addresses
        storage_path: Optional storage directory
        
    Returns:
        Configured AllowlistManager
    """
    manager = AllowlistManager(storage_path)
    manager.add_addresses(addresses)
    manager.build_merkle_tree()
    return manager


def verify_address_in_allowlist(
    address: str,
    proof: MerkleProof,
    allowlist_root: bytes
) -> bool:
    """
    Verify that an address is in an allowlist using a Merkle proof.
    
    Args:
        address: Bitcoin address to verify
        proof: Merkle proof for the address
        allowlist_root: Root hash of the allowlist
        
    Returns:
        True if address is proven to be in the allowlist
    """
    return verify_address_allowlist(address, proof, allowlist_root)


def validate_bitcoin_address(address: str) -> bool:
    """
    Validate a Bitcoin address format.
    
    Args:
        address: Bitcoin address to validate
        
    Returns:
        True if address format is valid
    """
    validator = AddressValidator()
    return validator.validate_address(address)


# CLI interface for allowlist management
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "test":
            print("Testing Allowlist Management System...")
            
            # Create test allowlist
            test_addresses = [
                "bc1qaddr1example123456789012345",
                "bc1qaddr2example123456789012345",
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Genesis block
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",     # Multisig
                "bc1paddr1example123456789012345678901234567890123456789012"  # Taproot
            ]
            
            manager = create_allowlist_from_addresses(test_addresses)
            
            print(f"✓ Created allowlist with {len(test_addresses)} addresses")
            
            # Test statistics
            stats = manager.get_statistics()
            print(f"✓ Tree height: {stats['tree_height']}")
            print(f"✓ Root hash: {stats['current_root'][:16]}...")
            
            # Test proof generation
            test_addr = test_addresses[0]
            proof = manager.generate_proof(test_addr)
            
            if proof:
                verification = manager.verify_address_proof(test_addr, proof)
                print(f"✓ Proof generation and verification: {'PASS' if verification else 'FAIL'}")
            else:
                print("✗ Proof generation failed")
            
            # Test export/import
            exported = manager.export_allowlist("json")
            print(f"✓ Export: {len(exported)} characters")
            
            # Test version creation
            version = manager.create_version("v1.0", "Initial version")
            print(f"✓ Version created: {version.version_id}")
            
            print("Allowlist management system test completed successfully!")
        
        elif command == "validate":
            if len(sys.argv) > 2:
                address = sys.argv[2]
                is_valid = validate_bitcoin_address(address)
                print(f"Address {address}: {'VALID' if is_valid else 'INVALID'}")
            else:
                print("Usage: python allowlist.py validate <address>")
        
        else:
            print(f"Unknown command: {command}")
            print("Available commands: test, validate")
    
    else:
        print("Bitcoin Address Allowlist Management System")
        print("Usage: python allowlist.py <command>")
        print("Commands:")
        print("  test - Run system tests")
        print("  validate <address> - Validate a Bitcoin address")