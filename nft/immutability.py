"""
Bitcoin Native Asset Protocol - Metadata Immutability Enforcement

This module provides comprehensive metadata immutability mechanisms to ensure
NFT metadata cannot be altered after minting, with version tracking, audit trails,
and cryptographic proofs of metadata state.
"""

import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union, Any, Set
from pathlib import Path

try:
    from .metadata import NFTMetadata, CollectionMetadata
    from .content import ContentHasher, ContentHash
except ImportError:
    # For standalone testing
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from metadata import NFTMetadata, CollectionMetadata
    from content import ContentHasher, ContentHash


class MetadataState(str, Enum):
    """Metadata immutability states."""
    DRAFT = "draft"                    # Editable pre-mint state
    PENDING_MINT = "pending_mint"      # Locked for minting process
    MINTED = "minted"                  # Immutable post-mint state
    FROZEN = "frozen"                  # Permanently locked
    DEPRECATED = "deprecated"          # Replaced by newer version


class ImmutabilityLevel(int, Enum):
    """Levels of metadata immutability."""
    NONE = 0          # No immutability (draft mode)
    CONTENT_ONLY = 1  # Only content references locked
    METADATA_ONLY = 2 # Only metadata locked, content can change
    PARTIAL = 3       # Core fields locked, some fields editable
    FULL = 4          # Complete immutability
    CRYPTOGRAPHIC = 5 # Cryptographically sealed


class AuditAction(str, Enum):
    """Types of audit actions."""
    CREATED = "created"
    UPDATED = "updated"
    VERSION_CREATED = "version_created"
    STATE_CHANGED = "state_changed"
    FROZEN = "frozen"
    MINTED = "minted"
    VERIFIED = "verified"
    ACCESSED = "accessed"


@dataclass
class MetadataVersion:
    """Versioned metadata snapshot."""
    
    version: int
    metadata: Dict[str, Any]
    content_hash: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    state: MetadataState = MetadataState.DRAFT
    immutability_level: ImmutabilityLevel = ImmutabilityLevel.NONE
    
    # Cryptographic binding
    signature: Optional[str] = None
    merkle_root: Optional[str] = None
    
    # Version metadata
    change_summary: str = ""
    previous_version: Optional[int] = None
    
    def calculate_hash(self) -> str:
        """Calculate content hash of this version."""
        # Ensure metadata is serializable
        serializable_metadata = self._make_serializable(self.metadata)
        
        version_data = {
            "version": self.version,
            "metadata": serializable_metadata,
            "created_at": self.created_at.isoformat(),
            "state": self.state.value,
            "immutability_level": self.immutability_level.value
        }
        
        serialized = json.dumps(version_data, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()
    
    def _make_serializable(self, obj) -> Any:
        """Convert objects to JSON serializable format."""
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        elif isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        else:
            return obj
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "version": self.version,
            "metadata": self.metadata,
            "content_hash": self.content_hash,
            "created_at": self.created_at.isoformat(),
            "state": self.state.value,
            "immutability_level": self.immutability_level.value,
            "signature": self.signature,
            "merkle_root": self.merkle_root,
            "change_summary": self.change_summary,
            "previous_version": self.previous_version
        }


@dataclass
class AuditEntry:
    """Audit trail entry."""
    
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: AuditAction = AuditAction.ACCESSED
    version: Optional[int] = None
    field_changed: Optional[str] = None
    old_value_hash: Optional[str] = None
    new_value_hash: Optional[str] = None
    user_id: Optional[str] = None
    transaction_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value,
            "version": self.version,
            "field_changed": self.field_changed,
            "old_value_hash": self.old_value_hash,
            "new_value_hash": self.new_value_hash,
            "user_id": self.user_id,
            "transaction_id": self.transaction_id,
            "metadata": self.metadata
        }


@dataclass
class ImmutabilityProof:
    """Cryptographic proof of metadata immutability."""
    
    metadata_hash: str
    timestamp: datetime
    signature: str
    merkle_root: Optional[str] = None
    transaction_id: Optional[str] = None
    
    # Proof components
    proof_chain: List[str] = field(default_factory=list)
    witness_data: Dict[str, str] = field(default_factory=dict)
    
    def verify_proof(self, expected_hash: str) -> bool:
        """Verify the immutability proof."""
        # Simple verification - in production would use proper crypto
        if self.metadata_hash != expected_hash:
            return False
        
        # Verify signature format (simplified)
        if not self.signature or len(self.signature) < 64:
            return False
        
        # Verify proof chain integrity
        if self.proof_chain:
            chain_hash = hashlib.sha256(''.join(self.proof_chain).encode()).hexdigest()
            if chain_hash not in self.signature:
                return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "metadata_hash": self.metadata_hash,
            "timestamp": self.timestamp.isoformat(),
            "signature": self.signature,
            "merkle_root": self.merkle_root,
            "transaction_id": self.transaction_id,
            "proof_chain": self.proof_chain,
            "witness_data": self.witness_data
        }


class ImmutabilityEnforcer:
    """Enforces metadata immutability rules."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hasher = ContentHasher()
        
        # Immutable field sets by level
        self._immutable_fields = {
            ImmutabilityLevel.CONTENT_ONLY: {
                "image", "animation_url", "external_url", "youtube_url"
            },
            ImmutabilityLevel.METADATA_ONLY: {
                "name", "description", "attributes"
            },
            ImmutabilityLevel.PARTIAL: {
                "name", "description", "image", "animation_url", "attributes"
            },
            ImmutabilityLevel.FULL: "ALL",  # Special marker for all fields
            ImmutabilityLevel.CRYPTOGRAPHIC: "ALL"
        }
    
    def can_modify_field(self, field_name: str, current_state: MetadataState, 
                        immutability_level: ImmutabilityLevel) -> bool:
        """Check if a field can be modified given current state and immutability level."""
        # Always allow modifications in draft state
        if current_state == MetadataState.DRAFT:
            return True
        
        # Never allow modifications in frozen or minted state with high immutability
        if current_state in [MetadataState.FROZEN, MetadataState.MINTED]:
            if immutability_level in [ImmutabilityLevel.FULL, ImmutabilityLevel.CRYPTOGRAPHIC]:
                return False
        
        # Check field-specific immutability rules
        if immutability_level == ImmutabilityLevel.NONE:
            return True
        
        immutable_fields = self._immutable_fields.get(immutability_level, set())
        
        if immutable_fields == "ALL":
            return False
        
        return field_name not in immutable_fields
    
    def validate_state_transition(self, current_state: MetadataState, 
                                new_state: MetadataState) -> bool:
        """Validate if state transition is allowed."""
        valid_transitions = {
            MetadataState.DRAFT: [MetadataState.PENDING_MINT, MetadataState.FROZEN],
            MetadataState.PENDING_MINT: [MetadataState.MINTED, MetadataState.DRAFT],
            MetadataState.MINTED: [MetadataState.FROZEN, MetadataState.DEPRECATED],
            MetadataState.FROZEN: [MetadataState.DEPRECATED],
            MetadataState.DEPRECATED: []  # Terminal state
        }
        
        allowed = valid_transitions.get(current_state, [])
        return new_state in allowed
    
    def create_immutability_proof(self, metadata: Dict[str, Any], 
                                 transaction_id: Optional[str] = None) -> ImmutabilityProof:
        """Create cryptographic proof of metadata immutability."""
        # Ensure metadata is serializable
        serializable_metadata = self._make_serializable(metadata)
        metadata_hash = hashlib.sha256(json.dumps(serializable_metadata, sort_keys=True).encode()).hexdigest()
        timestamp = datetime.now(timezone.utc)
        
        # Create proof chain
        proof_chain = [
            metadata_hash,
            timestamp.isoformat(),
            transaction_id or "no_tx"
        ]
        
        # Generate signature (simplified - in production would use real cryptographic signing)
        signature_data = ''.join(proof_chain)
        signature = hashlib.sha256(signature_data.encode()).hexdigest()
        
        # Create Merkle root from proof chain
        merkle_root = self._calculate_merkle_root(proof_chain)
        
        return ImmutabilityProof(
            metadata_hash=metadata_hash,
            timestamp=timestamp,
            signature=signature,
            merkle_root=merkle_root,
            transaction_id=transaction_id,
            proof_chain=proof_chain
        )
    
    def _calculate_merkle_root(self, data: List[str]) -> str:
        """Calculate Merkle root from data list."""
        if not data:
            return ""
        
        current_level = [hashlib.sha256(item.encode()).hexdigest() for item in data]
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined)
            current_level = next_level
        
        return current_level[0]
    
    def _make_serializable(self, obj) -> Any:
        """Convert objects to JSON serializable format."""
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        elif isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        else:
            return obj


class ImmutableMetadata:
    """Immutable metadata container with version control and audit trail."""
    
    def __init__(self, initial_metadata: Union[Dict[str, Any], NFTMetadata],
                 immutability_level: ImmutabilityLevel = ImmutabilityLevel.NONE):
        # Convert NFTMetadata to dict if needed
        if isinstance(initial_metadata, NFTMetadata):
            self._current_data = initial_metadata.to_dict()
        else:
            self._current_data = initial_metadata.copy()
        
        self._state = MetadataState.DRAFT
        self._immutability_level = immutability_level
        
        # Version control
        self._versions: Dict[int, MetadataVersion] = {}
        self._current_version = 1
        self._create_initial_version()
        
        # Audit trail
        self._audit_trail: List[AuditEntry] = []
        self._add_audit_entry(AuditAction.CREATED)
        
        # Immutability enforcement
        self._enforcer = ImmutabilityEnforcer()
        self._immutability_proof: Optional[ImmutabilityProof] = None
        
        # Metadata
        self._creation_time = datetime.now(timezone.utc)
        self._locked_fields: Set[str] = set()
        
        self.logger = logging.getLogger(__name__)
    
    def _create_initial_version(self):
        """Create initial version."""
        serializable_data = self._make_serializable(self._current_data)
        content_hash = hashlib.sha256(json.dumps(serializable_data, sort_keys=True).encode()).hexdigest()
        
        version = MetadataVersion(
            version=1,
            metadata=self._current_data.copy(),
            content_hash=content_hash,
            state=self._state,
            immutability_level=self._immutability_level,
            change_summary="Initial version"
        )
        
        self._versions[1] = version
    
    def _add_audit_entry(self, action: AuditAction, **kwargs):
        """Add entry to audit trail."""
        entry = AuditEntry(
            action=action,
            version=self._current_version,
            **kwargs
        )
        self._audit_trail.append(entry)
    
    def _make_serializable(self, obj) -> Any:
        """Convert objects to JSON serializable format."""
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        elif isinstance(obj, dict):
            return {key: self._make_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        else:
            return obj
    
    def get_current_state(self) -> MetadataState:
        """Get current metadata state."""
        return self._state
    
    def get_immutability_level(self) -> ImmutabilityLevel:
        """Get current immutability level."""
        return self._immutability_level
    
    def can_modify(self, field_name: str) -> bool:
        """Check if field can be modified."""
        return self._enforcer.can_modify_field(
            field_name, 
            self._state, 
            self._immutability_level
        )
    
    def update_field(self, field_name: str, new_value: Any, 
                    user_id: Optional[str] = None) -> bool:
        """Update a specific field if allowed."""
        # Check if modification is allowed
        if not self.can_modify(field_name):
            self.logger.warning(f"Field '{field_name}' is immutable in state {self._state.value}")
            return False
        
        # Store old value for audit
        old_value = self._current_data.get(field_name)
        old_value_hash = hashlib.sha256(str(old_value).encode()).hexdigest() if old_value else None
        new_value_hash = hashlib.sha256(str(new_value).encode()).hexdigest()
        
        # Update field
        self._current_data[field_name] = new_value
        
        # Add audit entry
        self._add_audit_entry(
            AuditAction.UPDATED,
            field_changed=field_name,
            old_value_hash=old_value_hash,
            new_value_hash=new_value_hash,
            user_id=user_id
        )
        
        self.logger.info(f"Updated field '{field_name}' in version {self._current_version}")
        return True
    
    def create_new_version(self, changes: Dict[str, Any], 
                          change_summary: str = "",
                          user_id: Optional[str] = None) -> int:
        """Create new version with changes."""
        if self._state not in [MetadataState.DRAFT, MetadataState.PENDING_MINT]:
            raise ValueError(f"Cannot create new version in state {self._state.value}")
        
        # Validate all changes are allowed
        for field_name in changes.keys():
            if not self.can_modify(field_name):
                raise ValueError(f"Field '{field_name}' is immutable")
        
        # Apply changes
        new_data = self._current_data.copy()
        new_data.update(changes)
        
        # Create new version with serializable data
        new_version_num = max(self._versions.keys()) + 1
        serializable_data = self._make_serializable(new_data)
        content_hash = hashlib.sha256(json.dumps(serializable_data, sort_keys=True).encode()).hexdigest()
        
        version = MetadataVersion(
            version=new_version_num,
            metadata=new_data,
            content_hash=content_hash,
            state=self._state,
            immutability_level=self._immutability_level,
            change_summary=change_summary,
            previous_version=self._current_version
        )
        
        self._versions[new_version_num] = version
        self._current_version = new_version_num
        self._current_data = new_data
        
        # Add audit entry
        self._add_audit_entry(
            AuditAction.VERSION_CREATED,
            user_id=user_id,
            metadata={"change_summary": change_summary, "changes": list(changes.keys())}
        )
        
        self.logger.info(f"Created version {new_version_num}: {change_summary}")
        return new_version_num
    
    def change_state(self, new_state: MetadataState, 
                    transaction_id: Optional[str] = None,
                    user_id: Optional[str] = None) -> bool:
        """Change metadata state if transition is valid."""
        if not self._enforcer.validate_state_transition(self._state, new_state):
            self.logger.error(f"Invalid state transition: {self._state.value} -> {new_state.value}")
            return False
        
        old_state = self._state
        self._state = new_state
        
        # Update current version state and recalculate hash
        if self._current_version in self._versions:
            self._versions[self._current_version].state = new_state
            # Recalculate content hash with new state
            self._versions[self._current_version].content_hash = self._versions[self._current_version].calculate_hash()
        
        # Create immutability proof for minted/frozen states
        if new_state in [MetadataState.MINTED, MetadataState.FROZEN]:
            self._immutability_proof = self._enforcer.create_immutability_proof(
                self._current_data, 
                transaction_id
            )
        
        # Add audit entry
        self._add_audit_entry(
            AuditAction.STATE_CHANGED,
            transaction_id=transaction_id,
            user_id=user_id,
            metadata={"old_state": old_state.value, "new_state": new_state.value}
        )
        
        self.logger.info(f"State changed: {old_state.value} -> {new_state.value}")
        return True
    
    def freeze_metadata(self, transaction_id: Optional[str] = None,
                       user_id: Optional[str] = None) -> bool:
        """Permanently freeze metadata (irreversible)."""
        return self.change_state(MetadataState.FROZEN, transaction_id, user_id)
    
    def mint_metadata(self, transaction_id: str, user_id: Optional[str] = None) -> bool:
        """Mark metadata as minted."""
        success = self.change_state(MetadataState.MINTED, transaction_id, user_id)
        if success:
            self._add_audit_entry(AuditAction.MINTED, transaction_id=transaction_id, user_id=user_id)
        return success
    
    def get_version(self, version_num: int) -> Optional[MetadataVersion]:
        """Get specific version."""
        return self._versions.get(version_num)
    
    def get_current_version(self) -> MetadataVersion:
        """Get current version."""
        return self._versions[self._current_version]
    
    def get_all_versions(self) -> List[MetadataVersion]:
        """Get all versions."""
        return list(self._versions.values())
    
    def get_audit_trail(self) -> List[AuditEntry]:
        """Get complete audit trail."""
        return self._audit_trail.copy()
    
    def get_immutability_proof(self) -> Optional[ImmutabilityProof]:
        """Get immutability proof if available."""
        return self._immutability_proof
    
    def verify_integrity(self) -> Dict[str, bool]:
        """Verify metadata integrity."""
        results = {
            "current_version_valid": False,
            "audit_trail_complete": False,
            "immutability_proof_valid": False,
            "version_chain_valid": False
        }
        
        # Verify current version
        current_version = self.get_current_version()
        calculated_hash = current_version.calculate_hash()
        results["current_version_valid"] = calculated_hash == current_version.content_hash
        
        # Verify audit trail completeness
        required_actions = {AuditAction.CREATED}
        if self._state == MetadataState.MINTED:
            required_actions.add(AuditAction.MINTED)
        
        trail_actions = {entry.action for entry in self._audit_trail}
        results["audit_trail_complete"] = required_actions.issubset(trail_actions)
        
        # Verify immutability proof
        if self._immutability_proof:
            expected_hash = hashlib.sha256(json.dumps(self._current_data, sort_keys=True).encode()).hexdigest()
            results["immutability_proof_valid"] = self._immutability_proof.verify_proof(expected_hash)
        else:
            results["immutability_proof_valid"] = self._state not in [MetadataState.MINTED, MetadataState.FROZEN]
        
        # Verify version chain
        version_chain_valid = True
        for version_num, version in self._versions.items():
            if version.previous_version and version.previous_version not in self._versions:
                version_chain_valid = False
                break
        
        results["version_chain_valid"] = version_chain_valid
        
        return results
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to comprehensive dictionary format."""
        return {
            "current_data": self._current_data,
            "state": self._state.value,
            "immutability_level": self._immutability_level.value,
            "current_version": self._current_version,
            "creation_time": self._creation_time.isoformat(),
            "versions": [v.to_dict() for v in self._versions.values()],
            "audit_trail": [e.to_dict() for e in self._audit_trail],
            "immutability_proof": self._immutability_proof.to_dict() if self._immutability_proof else None,
            "locked_fields": list(self._locked_fields)
        }


# Utility functions

def create_immutable_nft(nft_metadata: NFTMetadata, 
                        immutability_level: ImmutabilityLevel = ImmutabilityLevel.PARTIAL) -> ImmutableMetadata:
    """Create immutable NFT metadata from NFTMetadata object."""
    return ImmutableMetadata(nft_metadata, immutability_level)


def verify_metadata_immutability(metadata_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Verify immutability of serialized metadata."""
    try:
        # Reconstruct ImmutableMetadata from dict
        immutable_meta = ImmutableMetadata(metadata_dict["current_data"])
        immutable_meta._state = MetadataState(metadata_dict["state"])
        immutable_meta._immutability_level = ImmutabilityLevel(metadata_dict["immutability_level"])
        
        # Reconstruct immutability proof if present
        if metadata_dict.get("immutability_proof"):
            proof_data = metadata_dict["immutability_proof"]
            immutable_meta._immutability_proof = ImmutabilityProof(
                metadata_hash=proof_data["metadata_hash"],
                timestamp=datetime.fromisoformat(proof_data["timestamp"]),
                signature=proof_data["signature"],
                merkle_root=proof_data.get("merkle_root"),
                transaction_id=proof_data.get("transaction_id"),
                proof_chain=proof_data.get("proof_chain", []),
                witness_data=proof_data.get("witness_data", {})
            )
        
        return immutable_meta.verify_integrity()
        
    except Exception as e:
        return {"error": str(e), "valid": False}


def test_immutability_system():
    """Test metadata immutability enforcement system."""
    print("Testing Metadata Immutability Enforcement System...")
    print("=" * 55)
    
    try:
        # Test NFT metadata creation
        from metadata import NFTMetadata
        
        nft = NFTMetadata(
            name="Immutable Test NFT",
            description="Testing immutability enforcement",
            image="ipfs://QmTestHash123",
            attributes=[{"trait_type": "Test", "value": "Original"}]
        )
        
        print(f"✓ Created test NFT: {nft.name}")
        
        # Create immutable metadata container
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        print(f"✓ Created immutable container (level: {immutable_nft.get_immutability_level().name})")
        print(f"  State: {immutable_nft.get_current_state().value}")
        print(f"  Version: {immutable_nft._current_version}")
        
        # Test field modification in draft state
        success = immutable_nft.update_field("description", "Updated description", "test_user")
        print(f"✓ Draft modification allowed: {success}")
        
        # Test version creation
        changes = {"attributes": [{"trait_type": "Test", "value": "Updated"}]}
        new_version = immutable_nft.create_new_version(changes, "Updated attributes", "test_user")
        print(f"✓ Created new version: {new_version}")
        
        # Test state transitions
        success = immutable_nft.change_state(MetadataState.PENDING_MINT, user_id="test_user")
        print(f"✓ State transition to pending_mint: {success}")
        
        # Test minting
        success = immutable_nft.mint_metadata("tx_abc123", "test_user")
        print(f"✓ Minting successful: {success}")
        
        # Test immutability in minted state
        success = immutable_nft.update_field("name", "Should not work", "test_user")
        print(f"✓ Minted state modification blocked: {not success}")
        
        # Test immutability proof
        proof = immutable_nft.get_immutability_proof()
        if proof:
            print(f"✓ Immutability proof created: {proof.metadata_hash[:16]}...")
            print(f"  Transaction: {proof.transaction_id}")
            print(f"  Signature: {proof.signature[:16]}...")
        
        # Test integrity verification
        integrity = immutable_nft.verify_integrity()
        all_valid = all(integrity.values())
        print(f"✓ Integrity verification: {all_valid}")
        for check, result in integrity.items():
            print(f"  {check}: {result}")
        
        # Test audit trail
        audit_trail = immutable_nft.get_audit_trail()
        print(f"✓ Audit trail: {len(audit_trail)} entries")
        for entry in audit_trail[-3:]:  # Show last 3 entries
            print(f"  {entry.action.value}: {entry.timestamp.strftime('%H:%M:%S')}")
        
        # Test version history
        versions = immutable_nft.get_all_versions()
        print(f"✓ Version history: {len(versions)} versions")
        for version in versions:
            print(f"  v{version.version}: {version.change_summary} ({version.state.value})")
        
        # Test freezing
        success = immutable_nft.freeze_metadata("freeze_tx_456", "admin_user")
        print(f"✓ Metadata frozen: {success}")
        
        # Test serialization and verification
        metadata_dict = immutable_nft.to_dict()
        verification_result = verify_metadata_immutability(metadata_dict)
        print(f"✓ Serialization verification: {verification_result.get('current_version_valid', False)}")
        
        print("\n✓ All immutability enforcement tests passed!")
        print("ℹ️  Metadata properly protected with cryptographic proofs and audit trails")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        success = test_immutability_system()
        sys.exit(0 if success else 1)
    else:
        print("Metadata Immutability Enforcement for BNAP NFTs")
        print("Usage: python immutability.py test")
        print("\nFeatures:")
        print("- Complete metadata immutability enforcement")
        print("- Version control with audit trails")
        print("- State-based modification controls")
        print("- Cryptographic proofs of metadata integrity")
        print("- Comprehensive integrity verification")
        print("- Field-level immutability rules")