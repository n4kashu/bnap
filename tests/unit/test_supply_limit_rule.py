"""
Tests for Supply Limit Rule

Tests the SupplyLimitRule validation logic including caching,
concurrent access handling, and edge cases.
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch

from validator.core import ValidationContext
from validator.rules.supply_limit import (
    SupplyLimitRule,
    SupplyState,
    create_supply_limit_rule,
    validate_supply_limit_quick
)
from registry.schema import AssetType
from crypto.commitments import OperationType


class TestSupplyState:
    """Test SupplyState data class."""
    
    def test_supply_state_creation(self):
        """Test basic supply state creation."""
        state = SupplyState(current_supply=1000, maximum_supply=10000)
        
        assert state.current_supply == 1000
        assert state.maximum_supply == 10000
        assert isinstance(state.last_updated, float)
        assert state.last_updated <= time.time()
        assert hasattr(state, 'lock')
    
    def test_supply_state_expiration(self):
        """Test supply state expiration logic."""
        state = SupplyState(current_supply=1000, maximum_supply=10000)
        
        # Fresh state should not be expired
        assert not state.is_expired(300)
        
        # Manually age the state
        state.last_updated = time.time() - 400
        assert state.is_expired(300)
        
        # Should not be expired with longer TTL
        assert not state.is_expired(500)


class TestSupplyLimitRule:
    """Test SupplyLimitRule functionality."""
    
    def test_rule_creation(self):
        """Test basic rule creation."""
        rule = SupplyLimitRule()
        
        assert rule.name == "supply_limit"
        assert "supply limits" in rule.description.lower()
        assert rule.enabled is True
        assert rule.cache_ttl == 300
        assert rule.enable_caching is True
        assert isinstance(rule.supply_cache, dict)
        assert len(rule.supply_cache) == 0
    
    def test_rule_creation_with_config(self):
        """Test rule creation with custom configuration."""
        rule = SupplyLimitRule(cache_ttl=600, enable_caching=False)
        
        assert rule.cache_ttl == 600
        assert rule.enable_caching is False
    
    def test_applicability_mint_operation(self):
        """Test rule applicability for mint operations."""
        rule = SupplyLimitRule()
        
        # Valid mint operation
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000
        )
        
        assert rule.is_applicable(context) is True
    
    def test_applicability_non_mint_operation(self):
        """Test rule applicability for non-mint operations."""
        rule = SupplyLimitRule()
        
        # Transfer operation should not be applicable
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.TRANSFER,
            amount=1000,
            supply_cap=10000
        )
        
        assert rule.is_applicable(context) is False
    
    def test_applicability_missing_data(self):
        """Test rule applicability with missing required data."""
        rule = SupplyLimitRule()
        
        # Missing asset_id
        context = ValidationContext(
            psbt_data={},
            asset_id=None,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000
        )
        assert rule.is_applicable(context) is False
        
        # Missing amount
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=None,
            supply_cap=10000
        )
        assert rule.is_applicable(context) is False
        
        # Missing supply cap
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=None
        )
        assert rule.is_applicable(context) is False
    
    def test_validation_success(self):
        """Test successful validation within supply limits."""
        rule = SupplyLimitRule(enable_caching=False)
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000,
            current_supply=5000
        )
        
        result = rule.validate(context)
        
        assert result is True
        assert not context.has_errors()
        assert rule.stats["approved_within_limit"] == 1
        assert rule.stats["validations_performed"] == 1
    
    def test_validation_failure_over_limit(self):
        """Test validation failure when exceeding supply limit."""
        rule = SupplyLimitRule(enable_caching=False)
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=6000,
            supply_cap=10000,
            current_supply=5000
        )
        
        result = rule.validate(context)
        
        assert result is False
        assert context.has_errors()
        assert rule.stats["rejected_over_limit"] == 1
        assert rule.stats["validations_performed"] == 1
        
        # Check error message content
        errors = context.validation_errors
        assert len(errors) == 1
        assert "exceed maximum supply" in errors[0]
        assert "6000" in errors[0]
        assert "10000" in errors[0]
        assert "5000" in errors[0]
    
    def test_validation_exactly_at_limit(self):
        """Test validation when mint would exactly reach the limit."""
        rule = SupplyLimitRule(enable_caching=False)
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=5000,
            supply_cap=10000,
            current_supply=5000
        )
        
        result = rule.validate(context)
        
        assert result is True
        assert not context.has_errors()
    
    def test_validation_integer_overflow(self):
        """Test validation handles potential integer overflow scenarios."""
        rule = SupplyLimitRule(enable_caching=False)
        
        # Python handles large integers automatically, so create a scenario
        # that would exceed supply limits with large numbers
        max_int = 2**63 - 1
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=max_int,
            current_supply=max_int - 500  # This + 1000 exceeds the cap
        )
        
        result = rule.validate(context)
        
        assert result is False
        assert context.has_errors()
        # Should fail due to exceeding supply cap, not overflow
        assert "exceed maximum supply" in context.validation_errors[0].lower()
    
    def test_caching_enabled(self):
        """Test supply state caching functionality."""
        rule = SupplyLimitRule(enable_caching=True, cache_ttl=300)
        
        asset_id = b'\\x01' * 32
        context = ValidationContext(
            psbt_data={},
            asset_id=asset_id,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000,
            current_supply=5000
        )
        
        # First validation should be a cache miss
        result1 = rule.validate(context)
        assert result1 is True
        assert rule.stats["cache_misses"] == 1
        assert rule.stats["cache_hits"] == 0
        
        # Second validation should be a cache hit
        result2 = rule.validate(context)
        assert result2 is True
        assert rule.stats["cache_misses"] == 1
        assert rule.stats["cache_hits"] == 1
        
        # Check cache content
        cached_assets = rule.get_cached_assets()
        assert asset_id.hex() in cached_assets
    
    def test_caching_disabled(self):
        """Test behavior when caching is disabled."""
        rule = SupplyLimitRule(enable_caching=False)
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000,
            current_supply=5000
        )
        
        # All validations should be cache misses
        rule.validate(context)
        rule.validate(context)
        
        assert rule.stats["cache_misses"] == 2
        assert rule.stats["cache_hits"] == 0
        assert len(rule.supply_cache) == 0
    
    def test_cache_expiration(self):
        """Test cache entry expiration."""
        rule = SupplyLimitRule(enable_caching=True, cache_ttl=1)  # 1 second TTL
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000,
            current_supply=5000
        )
        
        # First validation
        rule.validate(context)
        assert rule.stats["cache_misses"] == 1
        
        # Wait for cache to expire
        time.sleep(1.1)
        
        # Second validation should be another cache miss
        rule.validate(context)
        assert rule.stats["cache_misses"] == 2
        assert rule.stats["cache_hits"] == 0
    
    def test_clear_cache(self):
        """Test cache clearing functionality."""
        rule = SupplyLimitRule(enable_caching=True)
        
        # Populate cache
        asset_id1 = b'\\x01' * 32
        asset_id2 = b'\\x02' * 32
        
        context1 = ValidationContext(
            psbt_data={},
            asset_id=asset_id1,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000,
            current_supply=5000
        )
        
        context2 = ValidationContext(
            psbt_data={},
            asset_id=asset_id2,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=20000,
            current_supply=8000
        )
        
        rule.validate(context1)
        rule.validate(context2)
        
        assert len(rule.supply_cache) == 2
        
        # Clear specific asset
        rule.clear_cache(asset_id1.hex())
        assert len(rule.supply_cache) == 1
        assert asset_id2.hex() in rule.supply_cache
        
        # Clear all
        rule.clear_cache()
        assert len(rule.supply_cache) == 0
    
    def test_statistics(self):
        """Test statistics tracking and reporting."""
        rule = SupplyLimitRule()
        
        stats = rule.get_statistics()
        
        expected_keys = [
            "validations_performed",
            "cache_hits",
            "cache_misses",
            "rejected_over_limit",
            "approved_within_limit",
            "cache_hit_rate_percent",
            "cached_assets",
            "cache_enabled",
            "cache_ttl_seconds"
        ]
        
        for key in expected_keys:
            assert key in stats
        
        # Test after some operations
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000,
            current_supply=5000
        )
        
        rule.validate(context)
        rule.validate(context)
        
        updated_stats = rule.get_statistics()
        assert updated_stats["validations_performed"] == 2
        assert updated_stats["cache_hit_rate_percent"] == 50.0  # 1 hit, 1 miss
    
    def test_concurrent_access(self):
        """Test thread-safe concurrent access to cache."""
        rule = SupplyLimitRule(enable_caching=True)
        
        def validate_concurrently(thread_id):
            context = ValidationContext(
                psbt_data={},
                asset_id=b'\\x01' * 32,
                operation=OperationType.MINT,
                amount=100,
                supply_cap=10000,
                current_supply=1000
            )
            return rule.validate(context)
        
        # Run multiple threads concurrently
        threads = []
        results = []
        
        for i in range(10):
            thread = threading.Thread(target=lambda i=i: results.append(validate_concurrently(i)))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # All validations should succeed
        assert all(results)
        assert len(results) == 10
        
        # Should have some cache hits
        stats = rule.get_statistics()
        assert stats["validations_performed"] == 10
        assert stats["cache_hits"] > 0
    
    def test_asset_configuration_validation(self):
        """Test asset configuration validation."""
        rule = SupplyLimitRule()
        
        # Valid fungible asset
        valid_fungible = {
            "asset_type": "fungible",
            "maximum_supply": 1000000
        }
        assert rule.validate_asset_configuration(valid_fungible) is True
        
        # Valid NFT asset
        valid_nft = {
            "asset_type": "nft",
            "collection_size": 10000
        }
        assert rule.validate_asset_configuration(valid_nft) is True
        
        # Invalid fungible asset - negative supply
        invalid_fungible = {
            "asset_type": "fungible",
            "maximum_supply": -1000
        }
        assert rule.validate_asset_configuration(invalid_fungible) is False
        
        # Invalid fungible asset - too large supply
        invalid_large = {
            "asset_type": "fungible",
            "maximum_supply": 10**19
        }
        assert rule.validate_asset_configuration(invalid_large) is False
        
        # Invalid NFT asset - too large collection
        invalid_nft = {
            "asset_type": "nft",
            "collection_size": 2_000_000
        }
        assert rule.validate_asset_configuration(invalid_nft) is False
    
    def test_remaining_capacity_estimation(self):
        """Test remaining capacity estimation."""
        rule = SupplyLimitRule(enable_caching=False)
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            supply_cap=10000,
            current_supply=3000
        )
        
        capacity = rule.estimate_remaining_capacity(context)
        assert capacity == 7000  # 10000 - 3000
        
        # Test with no capacity
        context.current_supply = 10000
        capacity = rule.estimate_remaining_capacity(context)
        assert capacity == 0
        
        # Test with over-capacity (shouldn't happen but handle gracefully)
        context.current_supply = 12000
        capacity = rule.estimate_remaining_capacity(context)
        assert capacity == 0


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_create_supply_limit_rule(self):
        """Test supply limit rule creation utility."""
        rule = create_supply_limit_rule()
        assert isinstance(rule, SupplyLimitRule)
        assert rule.cache_ttl == 300
        assert rule.enable_caching is True
        
        # With custom config
        config = {
            "cache_ttl": 600,
            "enable_caching": False
        }
        rule = create_supply_limit_rule(config)
        assert rule.cache_ttl == 600
        assert rule.enable_caching is False
    
    def test_validate_supply_limit_quick(self):
        """Test quick supply limit validation utility."""
        # Valid case
        is_valid, error = validate_supply_limit_quick(5000, 2000, 10000)
        assert is_valid is True
        assert error == ""
        
        # Invalid - exceeds limit
        is_valid, error = validate_supply_limit_quick(8000, 3000, 10000)
        assert is_valid is False
        assert "exceed maximum supply" in error
        assert "1000" in error  # Amount over limit
        assert "2000" in error  # Remaining capacity
        
        # Invalid - exactly at limit should pass
        is_valid, error = validate_supply_limit_quick(7000, 3000, 10000)
        assert is_valid is True
        assert error == ""
        
        # Invalid parameters
        is_valid, error = validate_supply_limit_quick(-1, 1000, 10000)
        assert is_valid is False
        assert "Invalid supply parameters" in error
        
        is_valid, error = validate_supply_limit_quick(5000, 0, 10000)
        assert is_valid is False
        assert "Invalid supply parameters" in error
        
        is_valid, error = validate_supply_limit_quick(5000, 1000, -1)
        assert is_valid is False
        assert "Invalid supply parameters" in error
        
        # Test large numbers that exceed limits
        max_int = 2**63 - 1
        is_valid, error = validate_supply_limit_quick(max_int - 100, 1000, max_int)
        assert is_valid is False
        assert "exceed maximum supply" in error.lower()


class TestIntegration:
    """Integration tests with ValidationEngine."""
    
    def test_rule_integration(self):
        """Test supply limit rule integration with ValidationEngine."""
        from validator.core import ValidationEngine
        
        engine = ValidationEngine()
        
        # Check that SupplyLimitRule is registered by default
        rule_names = [rule.name for rule in engine.rules]
        assert "supply_limit" in rule_names
        
        # Get the supply limit rule
        supply_rule = engine.rule_registry["supply_limit"]
        assert isinstance(supply_rule, SupplyLimitRule)
        
        # Test statistics access
        stats = supply_rule.get_statistics()
        assert isinstance(stats, dict)
        assert "validations_performed" in stats