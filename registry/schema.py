"""
Bitcoin Native Asset Protocol - Registry Schema Models

This module defines the Pydantic models for asset definitions, validator configurations,
and state tracking within the registry system.
"""

import hashlib
import re
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class AssetType(str, Enum):
    """Asset type enumeration."""
    FUNGIBLE = "fungible"
    NFT = "nft"


class SigningScheme(str, Enum):
    """Cryptographic signing scheme enumeration."""
    ECDSA = "ecdsa"
    SCHNORR = "schnorr"


class AssetStatus(str, Enum):
    """Asset status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPRECATED = "deprecated"


class ScriptFormat(str, Enum):
    """Script format enumeration."""
    P2WSH = "p2wsh"
    P2TR = "p2tr"  # Taproot


class TransactionEntry(BaseModel):
    """Individual transaction record."""
    
    tx_id: str = Field(..., description="Transaction ID (hex)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    amount: int = Field(..., ge=0, description="Amount minted/transferred")
    recipient: Optional[str] = Field(None, description="Recipient address")
    block_height: Optional[int] = Field(None, ge=0, description="Block height when confirmed")
    
    @field_validator('tx_id')
    @classmethod
    def validate_tx_id(cls, v):
        """Validate transaction ID format."""
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError('Transaction ID must be 64-character hex string')
        return v.lower()


class ValidatorConfig(BaseModel):
    """Validator configuration model."""
    
    validator_id: str = Field(..., description="Unique validator identifier")
    pubkey: str = Field(..., description="Validator public key (hex)")
    signing_scheme: SigningScheme = Field(default=SigningScheme.SCHNORR)
    permissions: List[str] = Field(default_factory=list, description="List of permissions")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True)
    
    @field_validator('pubkey')
    @classmethod
    def validate_pubkey(cls, v):
        """Validate public key format."""
        # Remove 0x prefix if present
        if v.startswith('0x'):
            v = v[2:]
        
        # For Schnorr (32 bytes) or ECDSA compressed (33 bytes)
        if not re.match(r'^[a-fA-F0-9]{64,66}$', v):
            raise ValueError('Public key must be 32-33 byte hex string')
        return v.lower()
    
    @field_validator('validator_id')
    @classmethod
    def validate_validator_id(cls, v):
        """Validate validator ID format."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Validator ID must contain only alphanumeric characters, hyphens, and underscores')
        return v


class StateEntry(BaseModel):
    """Asset state tracking model."""
    
    asset_id: str = Field(..., description="Asset identifier")
    minted_supply: int = Field(default=0, ge=0, description="Total minted supply")
    last_mint_timestamp: Optional[datetime] = Field(None)
    transaction_count: int = Field(default=0, ge=0)
    transaction_history: List[TransactionEntry] = Field(default_factory=list)
    issued_nft_ids: List[int] = Field(default_factory=list, description="For NFT collections: list of issued token IDs")
    
    def add_transaction(self, tx_entry: TransactionEntry) -> None:
        """Add a transaction to the history."""
        self.transaction_history.append(tx_entry)
        self.transaction_count += 1
        self.minted_supply += tx_entry.amount
        self.last_mint_timestamp = tx_entry.timestamp
    
    def issue_nft(self, token_id: int, tx_entry: TransactionEntry) -> None:
        """Issue a specific NFT token ID."""
        if token_id in self.issued_nft_ids:
            raise ValueError(f"NFT token ID {token_id} already issued")
        
        self.issued_nft_ids.append(token_id)
        self.add_transaction(tx_entry)


class BaseAsset(BaseModel):
    """Base asset model with common fields."""
    
    asset_id: str = Field(..., description="32-byte SHA-256 asset identifier (hex)")
    name: str = Field(..., min_length=1, max_length=100, description="Asset name")
    symbol: str = Field(..., min_length=1, max_length=10, description="Asset symbol")
    issuer_pubkey: str = Field(..., description="Issuer public key (hex)")
    creation_timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    status: AssetStatus = Field(default=AssetStatus.ACTIVE)
    script_format: ScriptFormat = Field(default=ScriptFormat.P2TR)
    allowlist_root: Optional[str] = Field(None, description="Merkle root for allowlist (hex)")
    
    @field_validator('asset_id')
    @classmethod
    def validate_asset_id(cls, v):
        """Validate asset ID format (32-byte SHA-256)."""
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError('Asset ID must be 64-character hex string (32 bytes)')
        return v.lower()
    
    @field_validator('issuer_pubkey')
    @classmethod
    def validate_issuer_pubkey(cls, v):
        """Validate issuer public key format."""
        if v.startswith('0x'):
            v = v[2:]
        
        if not re.match(r'^[a-fA-F0-9]{64,66}$', v):
            raise ValueError('Issuer public key must be 32-33 byte hex string')
        return v.lower()
    
    @field_validator('allowlist_root')
    @classmethod
    def validate_allowlist_root(cls, v):
        """Validate allowlist root format if provided."""
        if v is None:
            return v
        
        if v.startswith('0x'):
            v = v[2:]
        
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError('Allowlist root must be 64-character hex string (32 bytes)')
        return v.lower()
    
    @field_validator('symbol')
    @classmethod
    def validate_symbol(cls, v):
        """Validate symbol format."""
        if not re.match(r'^[A-Z0-9]+$', v):
            raise ValueError('Symbol must contain only uppercase letters and numbers')
        return v.upper()


class FungibleAsset(BaseAsset):
    """Fungible asset model for currencies and utility tokens."""
    
    asset_type: Literal[AssetType.FUNGIBLE] = Field(default=AssetType.FUNGIBLE)
    maximum_supply: int = Field(..., gt=0, le=10**18, description="Maximum total supply")
    per_mint_limit: int = Field(..., gt=0, description="Maximum amount per mint transaction")
    decimal_places: int = Field(default=0, ge=0, le=18, description="Number of decimal places")
    
    @model_validator(mode='after')
    def validate_supply_constraints(self):
        """Validate supply constraint relationships."""
        if self.per_mint_limit > self.maximum_supply:
            raise ValueError('Per-mint limit cannot exceed maximum supply')
        
        return self


class NFTAsset(BaseAsset):
    """NFT asset model for unique digital collectibles."""
    
    asset_type: Literal[AssetType.NFT] = Field(default=AssetType.NFT)
    collection_size: int = Field(..., gt=0, le=1000000, description="Maximum number of NFTs in collection")
    content_hash: Optional[str] = Field(None, description="Content hash for individual NFT")
    content_uri: Optional[str] = Field(None, description="Content URI (IPFS, HTTP, etc.)")
    manifest_hash: Optional[str] = Field(None, description="Collection manifest hash")
    manifest_uri: Optional[str] = Field(None, description="Collection manifest URI")
    
    @field_validator('content_hash', 'manifest_hash')
    @classmethod
    def validate_content_hash(cls, v):
        """Validate content hash format if provided."""
        if v is None:
            return v
        
        if v.startswith('0x'):
            v = v[2:]
        
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError('Content hash must be 64-character hex string (32 bytes)')
        return v.lower()


# Union type for any asset
Asset = Union[FungibleAsset, NFTAsset]


class RegistryMetadata(BaseModel):
    """Registry metadata model."""
    
    version: str = Field(default="1.0.0", description="Registry schema version")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    description: str = Field(default="Bitcoin Native Asset Protocol Registry")
    network: str = Field(default="regtest", description="Bitcoin network")
    
    def update_timestamp(self) -> None:
        """Update the last modified timestamp."""
        self.updated_at = datetime.utcnow()


class Registry(BaseModel):
    """Complete registry model."""
    
    metadata: RegistryMetadata = Field(default_factory=RegistryMetadata)
    validators: Dict[str, ValidatorConfig] = Field(default_factory=dict)
    assets: Dict[str, Asset] = Field(default_factory=dict)
    state: Dict[str, StateEntry] = Field(default_factory=dict)
    
    def add_asset(self, asset: Asset) -> None:
        """Add an asset to the registry."""
        if asset.asset_id in self.assets:
            raise ValueError(f"Asset {asset.asset_id} already exists")
        
        self.assets[asset.asset_id] = asset
        self.state[asset.asset_id] = StateEntry(asset_id=asset.asset_id)
        self.metadata.update_timestamp()
    
    def add_validator(self, validator: ValidatorConfig) -> None:
        """Add a validator to the registry."""
        if validator.validator_id in self.validators:
            raise ValueError(f"Validator {validator.validator_id} already exists")
        
        self.validators[validator.validator_id] = validator
        self.metadata.update_timestamp()
    
    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Get an asset by ID."""
        return self.assets.get(asset_id)
    
    def get_state(self, asset_id: str) -> Optional[StateEntry]:
        """Get asset state by ID."""
        return self.state.get(asset_id)
    
    def get_validator(self, validator_id: str) -> Optional[ValidatorConfig]:
        """Get a validator by ID."""
        return self.validators.get(validator_id)
    
    def list_assets(self, asset_type: Optional[AssetType] = None) -> List[Asset]:
        """List all assets, optionally filtered by type."""
        assets = list(self.assets.values())
        
        if asset_type:
            assets = [a for a in assets if a.asset_type == asset_type]
        
        return assets
    
    def generate_asset_id(self, issuer_pubkey: str, name: str, nonce: Optional[str] = None) -> str:
        """Generate a deterministic asset ID."""
        if nonce is None:
            nonce = str(uuid4())
        
        data = f"{issuer_pubkey}{name}{nonce}".encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    class Config:
        """Pydantic config."""
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }
        use_enum_values = True