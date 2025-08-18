"""
Supply Limit Enforcement Rule

This module implements the SupplyLimitRule class that validates whether
mint operations would exceed the maximum supply cap defined for an asset.
"""

import logging
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass
from threading import Lock

from validator.core import ValidationRule, ValidationContext
from registry.schema import AssetType, FungibleAsset, NFTAsset
from crypto.commitments import OperationType


@dataclass
class SupplyState:
    """Cached supply state for an asset."""
    current_supply: int
    maximum_supply: int
    last_updated: float
    lock: Lock
    
    def __init__(self, current_supply: int, maximum_supply: int):
        self.current_supply = current_supply
        self.maximum_supply = maximum_supply
        self.last_updated = time.time()
        self.lock = Lock()
    
    def is_expired(self, ttl_seconds: int = 300) -> bool:
        """Check if cached data is expired."""
        return time.time() - self.last_updated > ttl_seconds


class SupplyLimitRule(ValidationRule):
    """
    Validation rule that enforces maximum supply limits for assets.
    
    This rule ensures that mint operations do not cause the total supply
    of an asset to exceed its defined maximum supply cap. It includes
    caching for performance and handles concurrent access safely.
    """
    
    def __init__(self, cache_ttl: int = 300, enable_caching: bool = True):
        """
        Initialize the supply limit rule.
        
        Args:
            cache_ttl: Cache time-to-live in seconds (default: 5 minutes)
            enable_caching: Whether to enable supply state caching
        """
        super().__init__(
            name="supply_limit", 
            description="Enforces maximum supply limits for assets"
        )
        
        self.cache_ttl = cache_ttl
        self.enable_caching = enable_caching
        self.supply_cache: Dict[str, SupplyState] = {}
        self.cache_lock = Lock()
        
        # Statistics tracking
        self.stats = {
            "validations_performed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "rejected_over_limit": 0,
            "approved_within_limit": 0
        }
    
    def is_applicable(self, context: ValidationContext) -> bool:
        """
        Check if this rule applies to the given validation context.
        
        This rule applies to:
        - Mint operations only
        - Assets with defined maximum supply limits
        
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
        
        # Must have asset ID and amount
        if not context.asset_id or context.amount is None:
            return False
        
        # Must have supply cap defined
        if context.supply_cap is None:
            return False
        
        return True
    
    def validate(self, context: ValidationContext) -> bool:
        """
        Validate that the mint operation doesn't exceed supply limits.
        
        Args:
            context: Validation context containing transaction data
            
        Returns:
            True if validation passes, False otherwise
        """
        self.stats["validations_performed"] += 1
        
        try:
            # Get current supply state
            supply_state = self._get_supply_state(context)
            if supply_state is None:
                context.add_error(self.name, "Failed to retrieve asset supply state")
                return False
            
            # Calculate new supply after mint
            current_supply = supply_state.current_supply
            mint_amount = context.amount
            maximum_supply = supply_state.maximum_supply
            new_supply = current_supply + mint_amount
            
            # Validate against maximum supply
            if new_supply > maximum_supply:
                self.stats["rejected_over_limit"] += 1
                remaining_capacity = maximum_supply - current_supply
                
                context.add_error(
                    self.name,
                    f"Mint amount {mint_amount} would exceed maximum supply. "
                    f"Current: {current_supply}, Maximum: {maximum_supply}, "
                    f"Remaining capacity: {remaining_capacity}"
                )
                
                # Add detailed information for debugging
                context.add_warning(
                    self.name,
                    f"Asset supply details - Current: {current_supply:,}, "
                    f"Requested: {mint_amount:,}, "
                    f"Would result in: {new_supply:,}, "
                    f"Maximum allowed: {maximum_supply:,}"
                )
                
                return False
            
            # Validation passed
            self.stats["approved_within_limit"] += 1
            self.logger.debug(
                f"Supply limit validation passed: {current_supply} + {mint_amount} = "
                f"{new_supply} <= {maximum_supply}"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Supply limit validation error: {e}")
            context.add_error(self.name, f"Supply validation failed: {str(e)}")
            return False
    
    def _get_supply_state(self, context: ValidationContext) -> Optional[SupplyState]:
        """
        Get current supply state for an asset with caching.
        
        Args:
            context: Validation context
            
        Returns:
            SupplyState object or None if retrieval failed
        """
        asset_id_hex = context.asset_id.hex()
        
        # Try cache first if enabled
        if self.enable_caching:
            cached_state = self._get_cached_supply(asset_id_hex)
            if cached_state:
                self.stats["cache_hits"] += 1
                return cached_state
        
        # Cache miss - fetch from registry
        self.stats["cache_misses"] += 1
        return self._fetch_supply_state(context, asset_id_hex)
    
    def _get_cached_supply(self, asset_id_hex: str) -> Optional[SupplyState]:
        """Get supply state from cache if available and not expired."""
        with self.cache_lock:
            supply_state = self.supply_cache.get(asset_id_hex)
            if supply_state and not supply_state.is_expired(self.cache_ttl):
                return supply_state
            elif supply_state:
                # Remove expired entry
                del self.supply_cache[asset_id_hex]
        
        return None
    
    def _fetch_supply_state(self, context: ValidationContext, asset_id_hex: str) -> Optional[SupplyState]:
        """
        Fetch supply state from registry and update cache.
        
        Args:
            context: Validation context
            asset_id_hex: Asset ID as hex string
            
        Returns:
            SupplyState object or None if fetch failed
        """
        try:
            # Get current supply from context (already loaded by validator engine)
            current_supply = context.current_supply or 0
            maximum_supply = context.supply_cap
            
            if maximum_supply is None:
                self.logger.warning(f"No supply cap found for asset {asset_id_hex}")
                return None
            
            # Create supply state
            supply_state = SupplyState(
                current_supply=current_supply,
                maximum_supply=maximum_supply
            )
            
            # Cache it if caching is enabled
            if self.enable_caching:
                with self.cache_lock:
                    self.supply_cache[asset_id_hex] = supply_state
            
            self.logger.debug(
                f"Fetched supply state for {asset_id_hex}: "
                f"current={current_supply}, max={maximum_supply}"
            )
            
            return supply_state
            
        except Exception as e:
            self.logger.error(f"Failed to fetch supply state for {asset_id_hex}: {e}")
            return None
    
    def clear_cache(self, asset_id: Optional[str] = None):
        """
        Clear supply state cache.
        
        Args:
            asset_id: Optional specific asset ID to clear. If None, clears all.
        """
        with self.cache_lock:
            if asset_id:
                self.supply_cache.pop(asset_id, None)
                self.logger.debug(f"Cleared supply cache for asset {asset_id}")
            else:
                self.supply_cache.clear()
                self.logger.debug("Cleared entire supply cache")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rule statistics."""
        cache_total = self.stats["cache_hits"] + self.stats["cache_misses"]
        hit_rate = (self.stats["cache_hits"] / cache_total * 100) if cache_total > 0 else 0
        
        return {
            **self.stats,
            "cache_hit_rate_percent": round(hit_rate, 2),
            "cached_assets": len(self.supply_cache),
            "cache_enabled": self.enable_caching,
            "cache_ttl_seconds": self.cache_ttl
        }
    
    def get_cached_assets(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently cached assets."""
        with self.cache_lock:
            return {
                asset_id: {
                    "current_supply": state.current_supply,
                    "maximum_supply": state.maximum_supply,
                    "last_updated": state.last_updated,
                    "age_seconds": time.time() - state.last_updated,
                    "expired": state.is_expired(self.cache_ttl)
                }
                for asset_id, state in self.supply_cache.items()
            }
    
    def validate_asset_configuration(self, asset_data: Dict[str, Any]) -> bool:
        """
        Validate asset configuration for supply limits.
        
        Args:
            asset_data: Asset configuration data
            
        Returns:
            True if configuration is valid
        """
        try:
            asset_type = asset_data.get("asset_type")
            maximum_supply = asset_data.get("maximum_supply")
            
            if asset_type == AssetType.FUNGIBLE.value:
                if not isinstance(maximum_supply, int) or maximum_supply <= 0:
                    self.logger.error(f"Invalid maximum_supply for fungible asset: {maximum_supply}")
                    return False
                    
                if maximum_supply > 10**18:  # Reasonable upper limit
                    self.logger.error(f"Maximum supply too large: {maximum_supply}")
                    return False
                    
            elif asset_type == AssetType.NFT.value:
                collection_size = asset_data.get("collection_size")
                if not isinstance(collection_size, int) or collection_size <= 0:
                    self.logger.error(f"Invalid collection_size for NFT: {collection_size}")
                    return False
                    
                if collection_size > 1_000_000:  # Reasonable upper limit for NFT collections
                    self.logger.error(f"Collection size too large: {collection_size}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Asset configuration validation error: {e}")
            return False
    
    def estimate_remaining_capacity(self, context: ValidationContext) -> Optional[int]:
        """
        Estimate remaining minting capacity for an asset.
        
        Args:
            context: Validation context
            
        Returns:
            Remaining capacity or None if unavailable
        """
        try:
            supply_state = self._get_supply_state(context)
            if supply_state:
                return max(0, supply_state.maximum_supply - supply_state.current_supply)
            return None
        except Exception as e:
            self.logger.error(f"Error estimating remaining capacity: {e}")
            return None


# Utility functions for supply limit validation

def create_supply_limit_rule(config: Optional[Dict[str, Any]] = None) -> SupplyLimitRule:
    """
    Create a SupplyLimitRule with configuration.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured SupplyLimitRule instance
    """
    config = config or {}
    
    cache_ttl = config.get("cache_ttl", 300)
    enable_caching = config.get("enable_caching", True)
    
    return SupplyLimitRule(
        cache_ttl=cache_ttl,
        enable_caching=enable_caching
    )


def validate_supply_limit_quick(
    current_supply: int, 
    mint_amount: int, 
    maximum_supply: int
) -> tuple[bool, str]:
    """
    Quick supply limit validation without full rule context.
    
    Args:
        current_supply: Current total supply
        mint_amount: Amount to mint
        maximum_supply: Maximum allowed supply
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if current_supply < 0 or mint_amount <= 0 or maximum_supply <= 0:
        return False, "Invalid supply parameters"
    
    new_supply = current_supply + mint_amount
    
    # Check against maximum
    if new_supply > maximum_supply:
        remaining = maximum_supply - current_supply
        return False, f"Would exceed maximum supply by {new_supply - maximum_supply}. Remaining capacity: {remaining}"
    
    return True, ""