"""
Bitcoin Native Asset Protocol - Registry Manager

This module provides the main registry manager interface with asset registration,
updates, query capabilities, and caching for optimal performance.
"""

import hashlib
import time
from datetime import datetime, timedelta
from threading import RLock
from typing import Dict, List, Optional, Set, Union, Any, Callable
from uuid import uuid4

from .schema import (
    Asset, AssetType, AssetStatus, FungibleAsset, NFTAsset,
    StateEntry, TransactionEntry, ValidatorConfig,
    Registry, RegistryMetadata
)
from .storage import RegistryStorage, StorageError


class RegistryError(Exception):
    """Base registry exception."""
    pass


class AssetExistsError(RegistryError):
    """Asset already exists exception."""
    pass


class AssetNotFoundError(RegistryError):
    """Asset not found exception."""
    pass


class ValidatorError(RegistryError):
    """Validator operation exception."""
    pass


class CacheEntry:
    """Cache entry with TTL support."""
    
    def __init__(self, value: Any, ttl_seconds: float = 300.0):
        self.value = value
        self.created_at = time.time()
        self.ttl_seconds = ttl_seconds
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return time.time() - self.created_at > self.ttl_seconds


class RegistryCache:
    """Thread-safe caching layer with TTL support."""
    
    def __init__(self, default_ttl: float = 300.0):
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry and not entry.is_expired():
                return entry.value
            elif entry:
                # Remove expired entry
                del self._cache[key]
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache with TTL."""
        with self._lock:
            ttl = ttl or self.default_ttl
            self._cache[key] = CacheEntry(value, ttl)
    
    def invalidate(self, key: str) -> None:
        """Remove specific key from cache."""
        with self._lock:
            self._cache.pop(key, None)
    
    def invalidate_pattern(self, pattern: str) -> None:
        """Remove keys matching pattern from cache."""
        with self._lock:
            keys_to_remove = [k for k in self._cache.keys() if pattern in k]
            for key in keys_to_remove:
                del self._cache[key]
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed."""
        with self._lock:
            expired_keys = [
                k for k, v in self._cache.items() 
                if v.is_expired()
            ]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)


class RegistryManager:
    """Main registry manager with CRUD operations and caching."""
    
    def __init__(
        self,
        storage_dir: str = "registry_data",
        cache_ttl: float = 300.0,
        enable_cache: bool = True
    ):
        self.storage = RegistryStorage(storage_dir)
        self.cache = RegistryCache(cache_ttl) if enable_cache else None
        self._lock = RLock()
        
        # Load registry on initialization
        self._registry = self.storage.load_registry()
    
    def _invalidate_cache(self, asset_id: Optional[str] = None) -> None:
        """Invalidate relevant cache entries."""
        if not self.cache:
            return
        
        if asset_id:
            self.cache.invalidate(f"asset:{asset_id}")
            self.cache.invalidate(f"state:{asset_id}")
        
        # Invalidate list caches
        self.cache.invalidate_pattern("list:")
        self.cache.invalidate_pattern("find:")
    
    def _cache_get(self, key: str) -> Optional[Any]:
        """Get from cache if enabled."""
        return self.cache.get(key) if self.cache else None
    
    def _cache_set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set in cache if enabled."""
        if self.cache:
            self.cache.set(key, value, ttl)
    
    def generate_asset_id(
        self,
        issuer_pubkey: str,
        name: str,
        asset_type: AssetType,
        nonce: Optional[str] = None
    ) -> str:
        """Generate a deterministic asset ID."""
        if nonce is None:
            nonce = str(uuid4())
        
        # Create unique string for hashing
        data = f"{issuer_pubkey}{name}{asset_type.value}{nonce}".encode('utf-8')
        asset_id = hashlib.sha256(data).hexdigest()
        
        # Ensure uniqueness
        if self.asset_exists(asset_id):
            # Recurse with new nonce if collision detected
            return self.generate_asset_id(issuer_pubkey, name, asset_type)
        
        return asset_id
    
    def register_asset(self, asset: Asset) -> str:
        """Register a new asset in the registry."""
        with self._lock:
            # Check if asset already exists
            if self.asset_exists(asset.asset_id):
                raise AssetExistsError(f"Asset {asset.asset_id} already exists")
            
            def updater(registry: Registry) -> Registry:
                registry.add_asset(asset)
                return registry
            
            # Update storage atomically
            checksum = self.storage.update_registry(updater)
            
            # Update local registry
            self._registry.add_asset(asset)
            
            # Invalidate caches
            self._invalidate_cache(asset.asset_id)
            
            return checksum
    
    def register_validator(self, validator: ValidatorConfig) -> str:
        """Register a new validator in the registry."""
        with self._lock:
            def updater(registry: Registry) -> Registry:
                registry.add_validator(validator)
                return registry
            
            # Update storage atomically
            checksum = self.storage.update_registry(updater)
            
            # Update local registry
            self._registry.add_validator(validator)
            
            # Invalidate validator caches
            if self.cache:
                self.cache.invalidate_pattern("validator:")
            
            return checksum
    
    def update_asset_state(
        self,
        asset_id: str,
        tx_entry: TransactionEntry,
        nft_token_id: Optional[int] = None
    ) -> str:
        """Update asset minting state with a new transaction."""
        with self._lock:
            asset = self.get_asset_by_id(asset_id)
            if not asset:
                raise AssetNotFoundError(f"Asset {asset_id} not found")
            
            def updater(registry: Registry) -> Registry:
                state = registry.state.get(asset_id)
                if not state:
                    state = StateEntry(asset_id=asset_id)
                    registry.state[asset_id] = state
                
                # For NFTs, track token ID
                if isinstance(asset, NFTAsset) and nft_token_id is not None:
                    state.issue_nft(nft_token_id, tx_entry)
                else:
                    state.add_transaction(tx_entry)
                
                registry.metadata.update_timestamp()
                return registry
            
            # Update storage atomically
            checksum = self.storage.update_registry(updater)
            
            # Update local registry
            state = self._registry.state.get(asset_id)
            if not state:
                state = StateEntry(asset_id=asset_id)
                self._registry.state[asset_id] = state
            
            if isinstance(asset, NFTAsset) and nft_token_id is not None:
                state.issue_nft(nft_token_id, tx_entry)
            else:
                state.add_transaction(tx_entry)
            
            self._registry.metadata.update_timestamp()
            
            # Invalidate caches
            self._invalidate_cache(asset_id)
            
            return checksum
    
    def get_asset_by_id(self, asset_id: str) -> Optional[Asset]:
        """Get asset by ID with caching."""
        cache_key = f"asset:{asset_id}"
        
        # Try cache first
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        
        # Get from registry
        asset = self._registry.get_asset(asset_id)
        
        # Cache result
        self._cache_set(cache_key, asset)
        
        return asset
    
    def get_asset_state(self, asset_id: str) -> Optional[StateEntry]:
        """Get asset state by ID with caching."""
        cache_key = f"state:{asset_id}"
        
        # Try cache first
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        
        # Get from registry
        state = self._registry.get_state(asset_id)
        
        # Cache result
        self._cache_set(cache_key, state)
        
        return state
    
    def get_validator(self, validator_id: str) -> Optional[ValidatorConfig]:
        """Get validator by ID with caching."""
        cache_key = f"validator:{validator_id}"
        
        # Try cache first
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        
        # Get from registry
        validator = self._registry.get_validator(validator_id)
        
        # Cache result
        self._cache_set(cache_key, validator)
        
        return validator
    
    def list_assets(
        self,
        asset_type: Optional[AssetType] = None,
        status: Optional[AssetStatus] = None,
        limit: Optional[int] = None,
        offset: int = 0
    ) -> List[Asset]:
        """List assets with optional filtering and pagination."""
        cache_key = f"list:assets:{asset_type}:{status}:{limit}:{offset}"
        
        # Try cache first
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        
        # Get from registry
        assets = self._registry.list_assets(asset_type)
        
        # Apply status filter
        if status:
            assets = [a for a in assets if a.status == status]
        
        # Apply pagination
        if offset > 0:
            assets = assets[offset:]
        if limit:
            assets = assets[:limit]
        
        # Cache result
        self._cache_set(cache_key, assets)
        
        return assets
    
    def find_assets_by_issuer(self, issuer_pubkey: str) -> List[Asset]:
        """Find all assets by issuer public key."""
        cache_key = f"find:issuer:{issuer_pubkey}"
        
        # Try cache first
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        
        # Search registry
        assets = [
            asset for asset in self._registry.assets.values()
            if asset.issuer_pubkey == issuer_pubkey.lower()
        ]
        
        # Cache result
        self._cache_set(cache_key, assets)
        
        return assets
    
    def find_assets_by_symbol(self, symbol: str) -> List[Asset]:
        """Find all assets by symbol."""
        cache_key = f"find:symbol:{symbol}"
        
        # Try cache first
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        
        # Search registry
        assets = [
            asset for asset in self._registry.assets.values()
            if asset.symbol.upper() == symbol.upper()
        ]
        
        # Cache result
        self._cache_set(cache_key, assets)
        
        return assets
    
    def asset_exists(self, asset_id: str) -> bool:
        """Check if asset exists."""
        return self.get_asset_by_id(asset_id) is not None
    
    def get_asset_supply_info(self, asset_id: str) -> Dict[str, Any]:
        """Get comprehensive supply information for an asset."""
        asset = self.get_asset_by_id(asset_id)
        state = self.get_asset_state(asset_id)
        
        if not asset:
            raise AssetNotFoundError(f"Asset {asset_id} not found")
        
        info = {
            'asset_id': asset_id,
            'asset_type': asset.asset_type,
            'minted_supply': state.minted_supply if state else 0,
            'transaction_count': state.transaction_count if state else 0,
        }
        
        if isinstance(asset, FungibleAsset):
            info.update({
                'maximum_supply': asset.maximum_supply,
                'per_mint_limit': asset.per_mint_limit,
                'remaining_supply': asset.maximum_supply - (state.minted_supply if state else 0),
                'decimal_places': asset.decimal_places,
            })
        elif isinstance(asset, NFTAsset):
            info.update({
                'collection_size': asset.collection_size,
                'issued_nft_count': len(state.issued_nft_ids) if state else 0,
                'available_nft_count': asset.collection_size - (len(state.issued_nft_ids) if state else 0),
                'issued_nft_ids': state.issued_nft_ids[:] if state else [],
            })
        
        return info
    
    def batch_register_assets(self, assets: List[Asset]) -> str:
        """Register multiple assets in a single atomic operation."""
        with self._lock:
            # Validate all assets first
            for asset in assets:
                if self.asset_exists(asset.asset_id):
                    raise AssetExistsError(f"Asset {asset.asset_id} already exists")
            
            def updater(registry: Registry) -> Registry:
                for asset in assets:
                    registry.add_asset(asset)
                return registry
            
            # Update storage atomically
            checksum = self.storage.update_registry(updater)
            
            # Update local registry
            for asset in assets:
                self._registry.add_asset(asset)
            
            # Invalidate all caches
            if self.cache:
                self.cache.clear()
            
            return checksum
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get comprehensive registry statistics."""
        total_assets = len(self._registry.assets)
        fungible_count = len([a for a in self._registry.assets.values() if a.asset_type == AssetType.FUNGIBLE])
        nft_count = len([a for a in self._registry.assets.values() if a.asset_type == AssetType.NFT])
        
        active_assets = len([a for a in self._registry.assets.values() if a.status == AssetStatus.ACTIVE])
        total_validators = len(self._registry.validators)
        active_validators = len([v for v in self._registry.validators.values() if v.is_active])
        
        # Calculate total transactions
        total_transactions = sum(
            state.transaction_count 
            for state in self._registry.state.values()
        )
        
        storage_info = self.storage.get_storage_info()
        
        return {
            'total_assets': total_assets,
            'fungible_assets': fungible_count,
            'nft_assets': nft_count,
            'active_assets': active_assets,
            'total_validators': total_validators,
            'active_validators': active_validators,
            'total_transactions': total_transactions,
            'registry_version': self._registry.metadata.version,
            'created_at': self._registry.metadata.created_at,
            'updated_at': self._registry.metadata.updated_at,
            'storage_info': storage_info,
            'cache_info': {
                'enabled': self.cache is not None,
                'entries': len(self.cache._cache) if self.cache else 0,
            }
        }
    
    def cleanup_cache(self) -> int:
        """Clean up expired cache entries."""
        if not self.cache:
            return 0
        return self.cache.cleanup_expired()
    
    def reload_registry(self) -> None:
        """Reload registry from storage."""
        with self._lock:
            self._registry = self.storage.load_registry()
            if self.cache:
                self.cache.clear()
    
    def backup_registry(self) -> bool:
        """Create a backup of the registry."""
        return self.storage.backup_registry()
    
    def restore_backup(self, timestamp: str) -> bool:
        """Restore registry from backup."""
        with self._lock:
            success = self.storage.restore_backup(timestamp)
            if success:
                self.reload_registry()
            return success
    
    def list_backups(self) -> List[str]:
        """List available backup timestamps."""
        return self.storage.list_backups()