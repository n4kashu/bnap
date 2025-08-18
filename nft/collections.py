"""
Bitcoin Native Asset Protocol - NFT Collection Management

This module provides comprehensive NFT collection management including collection manifests,
token ID tracking, minting rules, and collection-level metadata inheritance.
"""

import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Union, Any, Callable
from uuid import uuid4

try:
    from .metadata import NFTMetadata, CollectionMetadata, NFTAttribute
    from .content import ContentHash, ContentManager, StorageType
except ImportError:
    # For standalone testing
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    
    from metadata import NFTMetadata, CollectionMetadata, NFTAttribute
    from content import ContentHash, ContentManager, StorageType


class TokenIDStrategy(str, Enum):
    """Token ID assignment strategies."""
    SEQUENTIAL = "sequential"
    RANDOM = "random"
    CUSTOM = "custom"


class MintingPhase(str, Enum):
    """Collection minting phases."""
    PRE_MINT = "pre_mint"
    ALLOWLIST = "allowlist" 
    PUBLIC = "public"
    CLOSED = "closed"


class CollectionStatus(str, Enum):
    """Collection status values."""
    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETE = "complete"
    PAUSED = "paused"
    DEPRECATED = "deprecated"


@dataclass
class MintingRule:
    """Rules for minting tokens in a collection."""
    
    max_per_wallet: Optional[int] = None
    max_per_transaction: Optional[int] = None
    price_per_token: Optional[float] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    phase: MintingPhase = MintingPhase.PUBLIC
    
    # Allowlist specific
    allowlist_addresses: Set[str] = field(default_factory=set)
    allowlist_merkle_root: Optional[str] = None
    
    def is_active(self, current_time: Optional[datetime] = None) -> bool:
        """Check if minting rule is currently active."""
        if current_time is None:
            current_time = datetime.now(timezone.utc)
        
        if self.start_time and current_time < self.start_time:
            return False
            
        if self.end_time and current_time > self.end_time:
            return False
            
        return True
    
    def can_mint(self, wallet_address: str, quantity: int, 
                wallet_balance: int = 0) -> tuple[bool, str]:
        """
        Check if wallet can mint specified quantity.
        
        Args:
            wallet_address: Wallet address attempting to mint
            quantity: Number of tokens to mint
            wallet_balance: Current token balance for this wallet
            
        Returns:
            (can_mint, reason) tuple
        """
        # Check allowlist for allowlist phase
        if self.phase == MintingPhase.ALLOWLIST:
            if wallet_address not in self.allowlist_addresses:
                return False, "Address not in allowlist"
        
        # Check per-transaction limit
        if self.max_per_transaction and quantity > self.max_per_transaction:
            return False, f"Exceeds max per transaction ({self.max_per_transaction})"
        
        # Check per-wallet limit
        if self.max_per_wallet and wallet_balance + quantity > self.max_per_wallet:
            return False, f"Exceeds max per wallet ({self.max_per_wallet})"
        
        return True, "Allowed"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            "phase": self.phase.value
        }
        
        if self.max_per_wallet is not None:
            result["max_per_wallet"] = self.max_per_wallet
        
        if self.max_per_transaction is not None:
            result["max_per_transaction"] = self.max_per_transaction
            
        if self.price_per_token is not None:
            result["price_per_token"] = self.price_per_token
        
        if self.start_time:
            result["start_time"] = self.start_time.isoformat()
        
        if self.end_time:
            result["end_time"] = self.end_time.isoformat()
        
        if self.allowlist_addresses:
            result["allowlist_addresses"] = list(self.allowlist_addresses)
            
        if self.allowlist_merkle_root:
            result["allowlist_merkle_root"] = self.allowlist_merkle_root
        
        return result


@dataclass
class TokenInfo:
    """Information about an individual NFT token."""
    
    token_id: int
    owner: Optional[str] = None
    metadata_uri: Optional[str] = None
    content_hash: Optional[str] = None
    minted_at: Optional[datetime] = None
    minted_by: Optional[str] = None
    transfer_count: int = 0
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            "token_id": self.token_id,
            "transfer_count": self.transfer_count
        }
        
        optional_fields = [
            "owner", "metadata_uri", "content_hash", "minted_by"
        ]
        
        for field_name in optional_fields:
            value = getattr(self, field_name)
            if value is not None:
                result[field_name] = value
        
        if self.minted_at:
            result["minted_at"] = self.minted_at.isoformat()
        
        if self.attributes:
            result["attributes"] = self.attributes
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenInfo':
        """Create TokenInfo from dictionary."""
        minted_at = None
        if 'minted_at' in data:
            try:
                minted_at = datetime.fromisoformat(data['minted_at'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        
        return cls(
            token_id=data['token_id'],
            owner=data.get('owner'),
            metadata_uri=data.get('metadata_uri'),
            content_hash=data.get('content_hash'),
            minted_at=minted_at,
            minted_by=data.get('minted_by'),
            transfer_count=data.get('transfer_count', 0),
            attributes=data.get('attributes', {})
        )


@dataclass
class CollectionManifest:
    """Complete manifest for an NFT collection."""
    
    # Collection identification
    collection_id: str
    metadata: CollectionMetadata
    
    # Supply and strategy
    max_supply: int
    token_id_strategy: TokenIDStrategy = TokenIDStrategy.SEQUENTIAL
    
    # Minting configuration
    minting_rules: List[MintingRule] = field(default_factory=list)
    status: CollectionStatus = CollectionStatus.DRAFT
    
    # Token tracking
    tokens_minted: int = 0
    next_token_id: int = 1
    available_token_ids: Set[int] = field(default_factory=set)
    reserved_token_ids: Set[int] = field(default_factory=set)
    
    # Metadata inheritance
    base_metadata_template: Optional[NFTMetadata] = None
    inherited_attributes: List[NFTAttribute] = field(default_factory=list)
    
    # Administrative
    creator_address: Optional[str] = None
    admin_addresses: Set[str] = field(default_factory=set)
    royalty_percentage: Optional[float] = None
    royalty_address: Optional[str] = None
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self):
        """Initialize collection after creation."""
        # Initialize available token IDs for random strategy
        if self.token_id_strategy == TokenIDStrategy.RANDOM:
            self.available_token_ids = set(range(1, self.max_supply + 1))
    
    def get_next_token_id(self, custom_id: Optional[int] = None) -> int:
        """
        Get next token ID based on strategy.
        
        Args:
            custom_id: Custom token ID for CUSTOM strategy
            
        Returns:
            Next token ID to mint
            
        Raises:
            ValueError: If no more tokens available or invalid custom ID
        """
        if self.tokens_minted >= self.max_supply:
            raise ValueError("Collection is fully minted")
        
        if self.token_id_strategy == TokenIDStrategy.SEQUENTIAL:
            token_id = self.next_token_id
            self.next_token_id += 1
            
        elif self.token_id_strategy == TokenIDStrategy.RANDOM:
            if not self.available_token_ids:
                raise ValueError("No token IDs available")
            
            token_id = random.choice(list(self.available_token_ids))
            self.available_token_ids.remove(token_id)
            
        elif self.token_id_strategy == TokenIDStrategy.CUSTOM:
            if custom_id is None:
                raise ValueError("Custom token ID required for CUSTOM strategy")
            
            if custom_id < 1 or custom_id > self.max_supply:
                raise ValueError(f"Token ID {custom_id} out of range [1, {self.max_supply}]")
            
            if custom_id in self.reserved_token_ids:
                raise ValueError(f"Token ID {custom_id} already minted")
            
            token_id = custom_id
            self.reserved_token_ids.add(token_id)
            
        else:
            raise ValueError(f"Unknown token ID strategy: {self.token_id_strategy}")
        
        return token_id
    
    def reserve_token_id(self, token_id: int) -> bool:
        """
        Reserve a specific token ID.
        
        Args:
            token_id: Token ID to reserve
            
        Returns:
            True if successfully reserved
        """
        if token_id < 1 or token_id > self.max_supply:
            return False
        
        if token_id in self.reserved_token_ids:
            return False
        
        # Remove from available IDs if using random strategy
        if self.token_id_strategy == TokenIDStrategy.RANDOM:
            self.available_token_ids.discard(token_id)
        
        self.reserved_token_ids.add(token_id)
        return True
    
    def can_mint(self, wallet_address: str, quantity: int = 1, 
                wallet_balance: int = 0) -> tuple[bool, str]:
        """
        Check if wallet can mint from this collection.
        
        Args:
            wallet_address: Wallet address attempting to mint
            quantity: Number of tokens to mint
            wallet_balance: Current token balance for this wallet
            
        Returns:
            (can_mint, reason) tuple
        """
        # Check collection status
        if self.status != CollectionStatus.ACTIVE:
            return False, f"Collection is {self.status.value}"
        
        # Check supply
        if self.tokens_minted + quantity > self.max_supply:
            available = self.max_supply - self.tokens_minted
            return False, f"Insufficient supply (available: {available})"
        
        # Check active minting rules
        current_time = datetime.now(timezone.utc)
        active_rules = [rule for rule in self.minting_rules if rule.is_active(current_time)]
        
        if not active_rules:
            return False, "No active minting rules"
        
        # Check against all active rules (must pass at least one)
        for rule in active_rules:
            can_mint, reason = rule.can_mint(wallet_address, quantity, wallet_balance)
            if can_mint:
                return True, "Allowed"
        
        return False, "Does not meet any active minting rule requirements"
    
    def create_token_metadata(self, token_id: int, 
                            custom_metadata: Optional[Dict[str, Any]] = None) -> NFTMetadata:
        """
        Create metadata for a token using inheritance and customization.
        
        Args:
            token_id: Token ID
            custom_metadata: Custom metadata overrides
            
        Returns:
            Complete NFTMetadata for the token
        """
        # Start with base template or create new
        if self.base_metadata_template:
            metadata = NFTMetadata(
                name=self.base_metadata_template.name.replace("{token_id}", str(token_id)),
                description=self.base_metadata_template.description.replace("{token_id}", str(token_id)),
                image=self.base_metadata_template.image.replace("{token_id}", str(token_id)),
                external_url=self.base_metadata_template.external_url,
                attributes=self.base_metadata_template.attributes.copy(),
                background_color=self.base_metadata_template.background_color,
                animation_url=self.base_metadata_template.animation_url,
                youtube_url=self.base_metadata_template.youtube_url,
                content_hash=self.base_metadata_template.content_hash,
                content_type=self.base_metadata_template.content_type,
                schema_version=self.base_metadata_template.schema_version,
                properties=self.base_metadata_template.properties.copy()
            )
        else:
            metadata = NFTMetadata(
                name=f"{self.metadata.name} #{token_id}",
                description=f"Token #{token_id} from {self.metadata.name} collection",
                image=f"https://example.com/collection/{self.collection_id}/{token_id}.png"
            )
        
        # Add inherited attributes
        for attr in self.inherited_attributes:
            metadata.add_attribute(
                attr.trait_type,
                attr.value,
                display_type=attr.display_type,
                attribute_type=attr.attribute_type,
                max_value=attr.max_value
            )
        
        # Add collection-specific attributes
        metadata.add_attribute("Collection", self.metadata.name)
        metadata.add_attribute("Collection Size", self.max_supply)
        metadata.add_attribute("Token ID", token_id)
        
        # Apply custom metadata overrides
        if custom_metadata:
            for key, value in custom_metadata.items():
                if key in ["name", "description", "image", "external_url"]:
                    setattr(metadata, key, value)
                elif key == "attributes":
                    # Merge custom attributes
                    for attr_data in value:
                        metadata.add_attribute(
                            attr_data.get("trait_type", "Custom"),
                            attr_data.get("value", ""),
                            display_type=attr_data.get("display_type"),
                            max_value=attr_data.get("max_value")
                        )
                elif key == "properties":
                    metadata.properties.update(value)
        
        return metadata
    
    def add_minting_rule(self, rule: MintingRule) -> None:
        """Add a minting rule to the collection."""
        self.minting_rules.append(rule)
        self.updated_at = datetime.now(timezone.utc)
    
    def update_status(self, status: CollectionStatus) -> None:
        """Update collection status."""
        self.status = status
        self.updated_at = datetime.now(timezone.utc)
    
    def get_completion_percentage(self) -> float:
        """Get collection minting completion percentage."""
        if self.max_supply == 0:
            return 100.0
        return (self.tokens_minted / self.max_supply) * 100.0
    
    def get_available_supply(self) -> int:
        """Get remaining mintable supply."""
        return max(0, self.max_supply - self.tokens_minted)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        result = {
            "collection_id": self.collection_id,
            "metadata": self.metadata.to_dict(),
            "max_supply": self.max_supply,
            "token_id_strategy": self.token_id_strategy.value,
            "minting_rules": [rule.to_dict() for rule in self.minting_rules],
            "status": self.status.value,
            "tokens_minted": self.tokens_minted,
            "next_token_id": self.next_token_id,
            "available_token_ids": list(self.available_token_ids),
            "reserved_token_ids": list(self.reserved_token_ids),
            "inherited_attributes": [attr.to_dict() for attr in self.inherited_attributes],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
        
        # Optional fields
        if self.base_metadata_template:
            result["base_metadata_template"] = self.base_metadata_template.to_dict()
        
        if self.creator_address:
            result["creator_address"] = self.creator_address
        
        if self.admin_addresses:
            result["admin_addresses"] = list(self.admin_addresses)
        
        if self.royalty_percentage is not None:
            result["royalty_percentage"] = self.royalty_percentage
        
        if self.royalty_address:
            result["royalty_address"] = self.royalty_address
        
        return result
    
    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CollectionManifest':
        """Create CollectionManifest from dictionary."""
        # Parse timestamps
        created_at = datetime.now(timezone.utc)
        updated_at = created_at
        
        if 'created_at' in data:
            try:
                created_at = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        
        if 'updated_at' in data:
            try:
                updated_at = datetime.fromisoformat(data['updated_at'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        
        # Parse metadata
        metadata = CollectionMetadata(**data['metadata'])
        
        # Parse minting rules
        minting_rules = []
        for rule_data in data.get('minting_rules', []):
            # Parse timestamps for rules
            rule_start = None
            rule_end = None
            
            if 'start_time' in rule_data:
                try:
                    rule_start = datetime.fromisoformat(rule_data['start_time'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            if 'end_time' in rule_data:
                try:
                    rule_end = datetime.fromisoformat(rule_data['end_time'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass
            
            rule = MintingRule(
                max_per_wallet=rule_data.get('max_per_wallet'),
                max_per_transaction=rule_data.get('max_per_transaction'),
                price_per_token=rule_data.get('price_per_token'),
                start_time=rule_start,
                end_time=rule_end,
                phase=MintingPhase(rule_data.get('phase', 'public')),
                allowlist_addresses=set(rule_data.get('allowlist_addresses', [])),
                allowlist_merkle_root=rule_data.get('allowlist_merkle_root')
            )
            minting_rules.append(rule)
        
        # Parse inherited attributes
        inherited_attributes = []
        for attr_data in data.get('inherited_attributes', []):
            attr = NFTAttribute(
                trait_type=attr_data['trait_type'],
                value=attr_data['value'],
                display_type=attr_data.get('display_type'),
                max_value=attr_data.get('max_value')
            )
            inherited_attributes.append(attr)
        
        # Parse base metadata template
        base_metadata_template = None
        if 'base_metadata_template' in data:
            base_metadata_template = NFTMetadata.from_dict(data['base_metadata_template'])
        
        return cls(
            collection_id=data['collection_id'],
            metadata=metadata,
            max_supply=data['max_supply'],
            token_id_strategy=TokenIDStrategy(data.get('token_id_strategy', 'sequential')),
            minting_rules=minting_rules,
            status=CollectionStatus(data.get('status', 'draft')),
            tokens_minted=data.get('tokens_minted', 0),
            next_token_id=data.get('next_token_id', 1),
            available_token_ids=set(data.get('available_token_ids', [])),
            reserved_token_ids=set(data.get('reserved_token_ids', [])),
            base_metadata_template=base_metadata_template,
            inherited_attributes=inherited_attributes,
            creator_address=data.get('creator_address'),
            admin_addresses=set(data.get('admin_addresses', [])),
            royalty_percentage=data.get('royalty_percentage'),
            royalty_address=data.get('royalty_address'),
            created_at=created_at,
            updated_at=updated_at
        )


class TokenTracker:
    """Tracks individual NFT tokens within a collection."""
    
    def __init__(self):
        self.tokens: Dict[int, TokenInfo] = {}
        self.owner_tokens: Dict[str, Set[int]] = {}
        
    def mint_token(self, token_id: int, owner: str, metadata_uri: Optional[str] = None,
                  content_hash: Optional[str] = None, minted_by: Optional[str] = None) -> TokenInfo:
        """
        Record a newly minted token.
        
        Args:
            token_id: Token ID
            owner: Initial owner address
            metadata_uri: URI to token metadata
            content_hash: Content hash for verification
            minted_by: Address that minted the token
            
        Returns:
            TokenInfo object
        """
        if token_id in self.tokens:
            raise ValueError(f"Token {token_id} already exists")
        
        token_info = TokenInfo(
            token_id=token_id,
            owner=owner,
            metadata_uri=metadata_uri,
            content_hash=content_hash,
            minted_at=datetime.now(timezone.utc),
            minted_by=minted_by or owner
        )
        
        self.tokens[token_id] = token_info
        
        # Update owner tracking
        if owner not in self.owner_tokens:
            self.owner_tokens[owner] = set()
        self.owner_tokens[owner].add(token_id)
        
        return token_info
    
    def transfer_token(self, token_id: int, new_owner: str) -> bool:
        """
        Transfer token to new owner.
        
        Args:
            token_id: Token ID
            new_owner: New owner address
            
        Returns:
            True if transfer successful
        """
        if token_id not in self.tokens:
            return False
        
        token_info = self.tokens[token_id]
        old_owner = token_info.owner
        
        # Update token info
        token_info.owner = new_owner
        token_info.transfer_count += 1
        
        # Update owner tracking
        if old_owner and old_owner in self.owner_tokens:
            self.owner_tokens[old_owner].discard(token_id)
            if not self.owner_tokens[old_owner]:
                del self.owner_tokens[old_owner]
        
        if new_owner not in self.owner_tokens:
            self.owner_tokens[new_owner] = set()
        self.owner_tokens[new_owner].add(token_id)
        
        return True
    
    def get_token_info(self, token_id: int) -> Optional[TokenInfo]:
        """Get token information."""
        return self.tokens.get(token_id)
    
    def get_owner_tokens(self, owner: str) -> Set[int]:
        """Get all tokens owned by address."""
        return self.owner_tokens.get(owner, set())
    
    def get_token_owner(self, token_id: int) -> Optional[str]:
        """Get owner of token."""
        token_info = self.tokens.get(token_id)
        return token_info.owner if token_info else None
    
    def token_exists(self, token_id: int) -> bool:
        """Check if token exists."""
        return token_id in self.tokens
    
    def get_total_supply(self) -> int:
        """Get total minted supply."""
        return len(self.tokens)
    
    def get_holder_count(self) -> int:
        """Get number of unique holders."""
        return len(self.owner_tokens)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "tokens": {str(k): v.to_dict() for k, v in self.tokens.items()},
            "owner_tokens": {k: list(v) for k, v in self.owner_tokens.items()}
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenTracker':
        """Create TokenTracker from dictionary."""
        tracker = cls()
        
        # Load tokens
        for token_id_str, token_data in data.get("tokens", {}).items():
            token_id = int(token_id_str)
            token_info = TokenInfo.from_dict(token_data)
            tracker.tokens[token_id] = token_info
        
        # Load owner mapping
        for owner, token_ids in data.get("owner_tokens", {}).items():
            tracker.owner_tokens[owner] = set(token_ids)
        
        return tracker


class CollectionManager:
    """Manages multiple NFT collections."""
    
    def __init__(self):
        self.collections: Dict[str, CollectionManifest] = {}
        self.token_trackers: Dict[str, TokenTracker] = {}
        self.collection_by_creator: Dict[str, Set[str]] = {}
    
    def create_collection(self, metadata: CollectionMetadata, max_supply: int,
                         creator_address: str, **kwargs) -> CollectionManifest:
        """
        Create a new NFT collection.
        
        Args:
            metadata: Collection metadata
            max_supply: Maximum tokens in collection
            creator_address: Creator's address
            **kwargs: Additional collection parameters
            
        Returns:
            CollectionManifest object
        """
        collection_id = kwargs.get('collection_id') or self._generate_collection_id(metadata.name)
        
        if collection_id in self.collections:
            raise ValueError(f"Collection {collection_id} already exists")
        
        # Create manifest
        manifest = CollectionManifest(
            collection_id=collection_id,
            metadata=metadata,
            max_supply=max_supply,
            creator_address=creator_address,
            **{k: v for k, v in kwargs.items() if k != 'collection_id'}
        )
        
        # Store collection
        self.collections[collection_id] = manifest
        self.token_trackers[collection_id] = TokenTracker()
        
        # Update creator tracking
        if creator_address not in self.collection_by_creator:
            self.collection_by_creator[creator_address] = set()
        self.collection_by_creator[creator_address].add(collection_id)
        
        return manifest
    
    def get_collection(self, collection_id: str) -> Optional[CollectionManifest]:
        """Get collection manifest."""
        return self.collections.get(collection_id)
    
    def get_token_tracker(self, collection_id: str) -> Optional[TokenTracker]:
        """Get token tracker for collection."""
        return self.token_trackers.get(collection_id)
    
    def mint_token(self, collection_id: str, owner: str, 
                  custom_token_id: Optional[int] = None,
                  custom_metadata: Optional[Dict[str, Any]] = None,
                  **kwargs) -> tuple[TokenInfo, NFTMetadata]:
        """
        Mint a new token in collection.
        
        Args:
            collection_id: Collection ID
            owner: Token owner address
            custom_token_id: Custom token ID (for CUSTOM strategy)
            custom_metadata: Custom metadata overrides
            **kwargs: Additional mint parameters
            
        Returns:
            (TokenInfo, NFTMetadata) tuple
        """
        manifest = self.collections.get(collection_id)
        if not manifest:
            raise ValueError(f"Collection {collection_id} not found")
        
        tracker = self.token_trackers.get(collection_id)
        if not tracker:
            raise ValueError(f"Token tracker not found for collection {collection_id}")
        
        # Get next token ID
        token_id = manifest.get_next_token_id(custom_token_id)
        
        # Create token metadata
        metadata = manifest.create_token_metadata(token_id, custom_metadata)
        
        # Mint token
        token_info = tracker.mint_token(
            token_id=token_id,
            owner=owner,
            metadata_uri=kwargs.get('metadata_uri'),
            content_hash=kwargs.get('content_hash'),
            minted_by=kwargs.get('minted_by', owner)
        )
        
        # Update manifest
        manifest.tokens_minted += 1
        manifest.updated_at = datetime.now(timezone.utc)
        
        return token_info, metadata
    
    def get_collections_by_creator(self, creator_address: str) -> List[CollectionManifest]:
        """Get all collections by creator."""
        collection_ids = self.collection_by_creator.get(creator_address, set())
        return [self.collections[cid] for cid in collection_ids if cid in self.collections]
    
    def get_collection_stats(self, collection_id: str) -> Dict[str, Any]:
        """Get collection statistics."""
        manifest = self.collections.get(collection_id)
        tracker = self.token_trackers.get(collection_id)
        
        if not manifest or not tracker:
            return {}
        
        return {
            "collection_id": collection_id,
            "name": manifest.metadata.name,
            "max_supply": manifest.max_supply,
            "tokens_minted": manifest.tokens_minted,
            "available_supply": manifest.get_available_supply(),
            "completion_percentage": manifest.get_completion_percentage(),
            "holder_count": tracker.get_holder_count(),
            "status": manifest.status.value,
            "created_at": manifest.created_at.isoformat(),
            "updated_at": manifest.updated_at.isoformat()
        }
    
    def _generate_collection_id(self, name: str) -> str:
        """Generate unique collection ID."""
        # Create deterministic but unique ID
        base = f"{name}-{datetime.now(timezone.utc).isoformat()}-{uuid4().hex[:8]}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]


# Utility functions

def create_sample_collection() -> CollectionManifest:
    """Create a sample collection for testing."""
    # Create collection metadata
    metadata = CollectionMetadata(
        name="Sample NFT Collection",
        description="A sample collection for testing BNAP NFT functionality",
        image="ipfs://QmSampleCollectionImage",
        collection_size=1000,
        creator="Sample Creator"
    )
    
    # Create base metadata template
    base_metadata = NFTMetadata(
        name="Sample NFT #{token_id}",
        description="Token #{token_id} from Sample NFT Collection",
        image="ipfs://QmSampleImage{token_id}"
    )
    
    # Create minting rules
    allowlist_rule = MintingRule(
        phase=MintingPhase.ALLOWLIST,
        max_per_wallet=2,
        max_per_transaction=1,
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc) + timedelta(days=7),
        allowlist_addresses={"0x123...", "0x456..."}
    )
    
    public_rule = MintingRule(
        phase=MintingPhase.PUBLIC,
        max_per_wallet=5,
        max_per_transaction=3,
        start_time=datetime.now(timezone.utc) + timedelta(days=7)
    )
    
    # Create collection manifest
    manifest = CollectionManifest(
        collection_id="sample_collection_001",
        metadata=metadata,
        max_supply=1000,
        token_id_strategy=TokenIDStrategy.SEQUENTIAL,
        base_metadata_template=base_metadata,
        creator_address="0xCreator123",
        royalty_percentage=5.0,
        royalty_address="0xRoyalty456"
    )
    
    manifest.add_minting_rule(allowlist_rule)
    manifest.add_minting_rule(public_rule)
    manifest.update_status(CollectionStatus.ACTIVE)
    
    return manifest


# CLI and testing interface

def main():
    """CLI interface for collection operations."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="BNAP NFT Collection Tools")
    parser.add_argument("command", choices=["create-sample", "mint", "info", "test"])
    parser.add_argument("--collection", help="Collection ID")
    parser.add_argument("--owner", help="Token owner address")
    parser.add_argument("--quantity", type=int, default=1, help="Number of tokens to mint")
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    args = parser.parse_args()
    
    if args.command == "test":
        test_collection_system()
    elif args.command == "create-sample":
        create_sample_collection_file()
    elif args.command == "info" and args.collection:
        show_collection_info(args.collection)


def create_sample_collection_file():
    """Create sample collection manifest file."""
    manifest = create_sample_collection()
    
    with open("sample_collection_manifest.json", "w") as f:
        f.write(manifest.to_json(indent=2))
    
    print("✓ Created sample_collection_manifest.json")


def show_collection_info(collection_file: str):
    """Show collection information."""
    try:
        with open(collection_file, 'r') as f:
            data = json.load(f)
        
        manifest = CollectionManifest.from_dict(data)
        
        print(f"Collection: {manifest.metadata.name}")
        print(f"ID: {manifest.collection_id}")
        print(f"Max Supply: {manifest.max_supply}")
        print(f"Minted: {manifest.tokens_minted}")
        print(f"Available: {manifest.get_available_supply()}")
        print(f"Completion: {manifest.get_completion_percentage():.1f}%")
        print(f"Status: {manifest.status.value}")
        print(f"Strategy: {manifest.token_id_strategy.value}")
        print(f"Rules: {len(manifest.minting_rules)}")
        
    except Exception as e:
        print(f"Error reading collection: {e}")


def test_collection_system():
    """Test the collection management system."""
    print("Testing NFT Collection Management System...")
    print("=" * 50)
    
    try:
        # Test collection creation
        manager = CollectionManager()
        
        metadata = CollectionMetadata(
            name="Test Collection",
            description="A test collection",
            image="ipfs://test",
            collection_size=100
        )
        
        manifest = manager.create_collection(
            metadata=metadata,
            max_supply=100,
            creator_address="0xCreator123",
            token_id_strategy=TokenIDStrategy.SEQUENTIAL
        )
        
        print(f"✓ Created collection: {manifest.collection_id}")
        
        # Test minting rules
        rule = MintingRule(
            phase=MintingPhase.PUBLIC,
            max_per_wallet=5,
            max_per_transaction=2
        )
        
        manifest.add_minting_rule(rule)
        manifest.update_status(CollectionStatus.ACTIVE)
        
        print("✓ Added minting rule and activated collection")
        
        # Test minting
        can_mint, reason = manifest.can_mint("0xWallet123", 2)
        print(f"✓ Can mint check: {can_mint} ({reason})")
        
        if can_mint:
            token_info, metadata = manager.mint_token(
                manifest.collection_id,
                "0xWallet123"
            )
            
            print(f"✓ Minted token {token_info.token_id} for {token_info.owner}")
        
        # Test token tracking
        tracker = manager.get_token_tracker(manifest.collection_id)
        total_supply = tracker.get_total_supply()
        holder_count = tracker.get_holder_count()
        
        print(f"✓ Total supply: {total_supply}")
        print(f"✓ Holder count: {holder_count}")
        
        # Test collection stats
        stats = manager.get_collection_stats(manifest.collection_id)
        print(f"✓ Collection completion: {stats['completion_percentage']:.1f}%")
        
        # Test metadata inheritance
        custom_metadata = {"name": "Special Token #1"}
        token_metadata = manifest.create_token_metadata(2, custom_metadata)
        print(f"✓ Generated metadata: {token_metadata.name}")
        
        # Test JSON serialization
        json_data = manifest.to_json(indent=2)
        parsed_manifest = CollectionManifest.from_dict(json.loads(json_data))
        print(f"✓ JSON serialization: {parsed_manifest.collection_id}")
        
        print("\nAll collection system tests passed!")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    main()