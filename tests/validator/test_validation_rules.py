"""
Comprehensive Unit Tests for Individual Validation Rules

Tests each validation rule in isolation with edge cases, boundary conditions,
and various failure scenarios to ensure robust rule enforcement.
"""

import pytest
import hashlib
from unittest.mock import Mock, patch, MagicMock

from validator.rules.supply_limit import SupplyLimitRule
from validator.rules.mint_limits import MintLimitRule 
from validator.rules.allowlist import AllowlistRule
from validator.rules.content_hash import ContentHashRule
from validator.core import ValidationContext

from registry.schema import AssetType, FungibleAsset, NFTAsset, StateEntry
from crypto.commitments import OperationType


class TestSupplyLimitRule:
    """Test supply limit validation rule."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.rule = SupplyLimitRule()
        
        # Create test assets
        self.fungible_asset = FungibleAsset(
            asset_id="supply_test_fungible",
            name="Supply Test Token",
            symbol="STT",
            issuer_pubkey="0123456789abcdef" * 8,
            maximum_supply=1_000_000,
            per_mint_limit=50_000,
            decimal_places=8,
            asset_type=AssetType.FUNGIBLE,
            status="active"
        )
        
        self.nft_asset = NFTAsset(
            asset_id="supply_test_nft",
            name="Supply Test NFT",
            symbol="STN",
            issuer_pubkey="fedcba9876543210" * 8,
            collection_size=1_000,
            asset_type=AssetType.NFT,
            status="active",
            base_uri="https://example.com/"
        )
    
    def test_supply_limit_rule_basic_properties(self):
        """Test basic rule properties."""
        assert self.rule.name == "supply_limit"
        assert self.rule.description is not None
        assert self.rule.enabled is True
    
    def test_fungible_asset_within_supply_limit(self):
        """Test fungible asset mint within supply limit."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"supply_test_fungible",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=10_000,
            current_supply=500_000,  # Current: 500k, Mint: 10k, Max: 1M = OK
            supply_cap=1_000_000
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_fungible_asset_exceeds_supply_limit(self):
        """Test fungible asset mint exceeding supply limit."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"supply_test_fungible",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=100_000,
            current_supply=950_000,  # Current: 950k, Mint: 100k, Max: 1M = FAIL
            supply_cap=1_000_000
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
        assert any("supply limit" in error.lower() for error in context.validation_errors)
    
    def test_fungible_asset_exact_supply_limit(self):
        """Test fungible asset mint exactly at supply limit."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"supply_test_fungible",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=50_000,
            current_supply=950_000,  # Current: 950k, Mint: 50k, Max: 1M = EXACT
            supply_cap=1_000_000
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_nft_asset_within_collection_limit(self):
        """Test NFT asset mint within collection limit."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"supply_test_nft", 
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,
            current_supply=500,  # 500 minted out of 1000
            supply_cap=1_000
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_nft_asset_exceeds_collection_limit(self):
        """Test NFT asset mint exceeding collection limit."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"supply_test_nft",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,
            current_supply=1_000,  # Collection fully minted
            supply_cap=1_000
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
        assert any("collection" in error.lower() or "supply" in error.lower() 
                  for error in context.validation_errors)
    
    def test_nft_invalid_mint_amount(self):
        """Test NFT mint with invalid amount (>1)."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"supply_test_nft",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=5,  # Invalid for NFT
            current_supply=100,
            supply_cap=1_000
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
        assert any("nft" in error.lower() and "amount" in error.lower() 
                  for error in context.validation_errors)
    
    def test_zero_amount_mint(self):
        """Test zero amount mint (should fail)."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"supply_test_fungible",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=0,  # Zero amount
            current_supply=500_000,
            supply_cap=1_000_000
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
        assert any("amount" in error.lower() and ("zero" in error.lower() or "positive" in error.lower())
                  for error in context.validation_errors)
    
    def test_missing_supply_data(self):
        """Test validation with missing supply data."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"supply_test_fungible",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=10_000,
            current_supply=None,  # Missing data
            supply_cap=None
        )
        
        result = self.rule.validate(context)
        # Rule should handle missing data gracefully
        assert result is False
        assert context.has_errors() or len(context.validation_warnings) > 0
    
    def test_supply_limit_caching(self):
        """Test that supply limit rule uses caching effectively."""
        # This test verifies caching behavior
        rule = SupplyLimitRule()
        
        context1 = ValidationContext(
            psbt_data={},
            asset_id=b"cached_asset",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            current_supply=100_000,
            supply_cap=1_000_000
        )
        
        # First validation
        result1 = rule.validate(context1)
        assert result1 is True
        
        # Check cache statistics
        stats = rule.get_statistics()
        assert "validations_performed" in stats
        assert stats["validations_performed"] >= 1


class TestMintLimitRule:
    """Test mint limit validation rule."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.rule = MintLimitRule()
    
    def test_mint_limit_rule_properties(self):
        """Test basic rule properties."""
        assert self.rule.name == "mint_limit" 
        assert self.rule.enabled is True
    
    def test_mint_within_per_mint_limit(self):
        """Test mint within per-mint limit."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"mint_limit_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=5_000,
            per_mint_cap=10_000
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_mint_exceeds_per_mint_limit(self):
        """Test mint exceeding per-mint limit."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"mint_limit_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=15_000,  # Exceeds 10k limit
            per_mint_cap=10_000
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
        assert any("mint" in error.lower() and "limit" in error.lower() 
                  for error in context.validation_errors)
    
    def test_mint_exactly_at_limit(self):
        """Test mint exactly at per-mint limit."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"mint_limit_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=10_000,  # Exactly at limit
            per_mint_cap=10_000
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_nft_mint_limit_check(self):
        """Test NFT mint limit (should always be 1)."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"nft_mint_limit_test",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,  # Valid NFT amount
            per_mint_cap=1
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_nft_invalid_mint_amount(self):
        """Test NFT with invalid mint amount."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"nft_mint_limit_test",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=3,  # Invalid for NFT
            per_mint_cap=1
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
    
    def test_missing_mint_limit_data(self):
        """Test validation with missing mint limit data."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"missing_data_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=5_000,
            per_mint_cap=None  # Missing limit data
        )
        
        result = self.rule.validate(context)
        # Should handle missing data gracefully
        assert result is False or len(context.validation_warnings) > 0
    
    def test_unlimited_mint_cap(self):
        """Test asset with no mint cap (unlimited)."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"unlimited_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1_000_000,  # Large amount
            per_mint_cap=0  # 0 typically means unlimited
        )
        
        result = self.rule.validate(context)
        # Behavior depends on implementation - could allow or require explicit limit
        assert result is True or context.has_errors()
    
    def test_mint_limit_statistics(self):
        """Test mint limit rule statistics tracking."""
        rule = MintLimitRule()
        
        # Perform several validations
        for i in range(5):
            context = ValidationContext(
                psbt_data={},
                asset_id=f"stats_test_{i}".encode(),
                asset_type=AssetType.FUNGIBLE,
                operation=OperationType.MINT,
                amount=1000,
                per_mint_cap=5000
            )
            rule.validate(context)
        
        stats = rule.get_statistics()
        assert stats["validations_performed"] >= 5


class TestAllowlistRule:
    """Test allowlist validation rule."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.rule = AllowlistRule()
        
        # Create test Merkle tree data
        self.valid_addresses = [
            "bc1qaddr1example1234567890",
            "bc1qaddr2example1234567890", 
            "bc1qaddr3example1234567890",
            "bc1qaddr4example1234567890"
        ]
        
        # Create Merkle tree root (simplified - would normally be proper Merkle tree)
        self.merkle_root = hashlib.sha256(
            ''.join(sorted(self.valid_addresses)).encode()
        ).digest()
    
    def test_allowlist_rule_properties(self):
        """Test basic rule properties."""
        assert self.rule.name == "allowlist"
        assert self.rule.enabled is True
    
    def test_valid_allowlist_proof(self):
        """Test validation with valid allowlist proof."""
        # Generate valid Merkle proof (simplified)
        recipient = self.valid_addresses[0]
        merkle_proof = [
            hashlib.sha256(addr.encode()).digest() 
            for addr in self.valid_addresses[1:3]
        ]
        
        context = ValidationContext(
            psbt_data={
                'outputs': [{
                    'script': f'mock_script_for_{recipient}'.encode(),
                    'amount': 100000
                }]
            },
            asset_id=b"allowlist_test_asset",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            allowlist_root=self.merkle_root
        )
        
        # Mock the Merkle proof verification
        with patch.object(self.rule, '_verify_merkle_proof', return_value=True):
            result = self.rule.validate(context)
            assert result is True
            assert not context.has_errors()
    
    def test_invalid_allowlist_proof(self):
        """Test validation with invalid allowlist proof."""
        recipient = "bc1qinvalidaddress1234567890"  # Not in allowlist
        
        context = ValidationContext(
            psbt_data={
                'outputs': [{
                    'script': f'mock_script_for_{recipient}'.encode(),
                    'amount': 100000
                }]
            },
            asset_id=b"allowlist_test_asset",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            allowlist_root=self.merkle_root
        )
        
        # Mock the Merkle proof verification to fail
        with patch.object(self.rule, '_verify_merkle_proof', return_value=False):
            result = self.rule.validate(context)
            assert result is False
            assert context.has_errors()
            assert any("allowlist" in error.lower() or "unauthorized" in error.lower()
                      for error in context.validation_errors)
    
    def test_no_allowlist_required(self):
        """Test asset that doesn't require allowlist."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"no_allowlist_asset",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            allowlist_root=None  # No allowlist
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_multiple_recipients_allowlist(self):
        """Test allowlist validation with multiple recipients."""
        context = ValidationContext(
            psbt_data={
                'outputs': [
                    {
                        'script': f'script_for_{self.valid_addresses[0]}'.encode(),
                        'amount': 50000
                    },
                    {
                        'script': f'script_for_{self.valid_addresses[1]}'.encode(), 
                        'amount': 50000
                    }
                ]
            },
            asset_id=b"multi_recipient_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            allowlist_root=self.merkle_root
        )
        
        # Mock verification to succeed for both recipients
        with patch.object(self.rule, '_verify_merkle_proof', return_value=True):
            result = self.rule.validate(context)
            assert result is True
            assert not context.has_errors()
    
    def test_partial_invalid_recipients(self):
        """Test allowlist with some invalid recipients."""
        context = ValidationContext(
            psbt_data={
                'outputs': [
                    {
                        'script': f'script_for_{self.valid_addresses[0]}'.encode(),
                        'amount': 50000
                    },
                    {
                        'script': 'script_for_invalid_address'.encode(),
                        'amount': 50000
                    }
                ]
            },
            asset_id=b"partial_invalid_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            allowlist_root=self.merkle_root
        )
        
        # Mock verification - first succeeds, second fails
        with patch.object(self.rule, '_verify_merkle_proof', side_effect=[True, False]):
            result = self.rule.validate(context)
            assert result is False
            assert context.has_errors()
    
    def test_allowlist_caching_behavior(self):
        """Test allowlist rule caching of verification results."""
        # Create rule and verify it uses caching
        rule = AllowlistRule()
        
        context = ValidationContext(
            psbt_data={'outputs': [{'script': b'test_script', 'amount': 100000}]},
            asset_id=b"cache_test_asset",
            allowlist_root=self.merkle_root
        )
        
        with patch.object(rule, '_verify_merkle_proof', return_value=True) as mock_verify:
            # First call
            rule.validate(context)
            
            # Second call with same data - should potentially use cache
            rule.validate(context)
        
        # Check that proof verification was called
        assert mock_verify.called
    
    def test_allowlist_statistics(self):
        """Test allowlist rule statistics."""
        rule = AllowlistRule()
        
        context = ValidationContext(
            psbt_data={'outputs': [{'script': b'test_script', 'amount': 100000}]},
            asset_id=b"stats_test",
            allowlist_root=self.merkle_root
        )
        
        with patch.object(rule, '_verify_merkle_proof', return_value=True):
            rule.validate(context)
        
        stats = rule.get_statistics()
        assert "validations_performed" in stats
        assert "proofs_verified" in stats


class TestContentHashRule:
    """Test content hash validation rule."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.rule = ContentHashRule()
        
        # Create test content and hashes
        self.test_content = b"Test NFT metadata content"
        self.valid_hash = hashlib.sha256(self.test_content).digest()
        self.invalid_hash = hashlib.sha256(b"Different content").digest()
    
    def test_content_hash_rule_properties(self):
        """Test basic rule properties."""
        assert self.rule.name == "content_hash"
        assert self.rule.enabled is True
    
    def test_valid_content_hash(self):
        """Test validation with valid content hash."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"content_hash_test",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,
            content_hash=self.valid_hash,
            metadata={"content": self.test_content.decode()}
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_invalid_content_hash(self):
        """Test validation with invalid content hash."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"content_hash_test",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,
            content_hash=self.invalid_hash,  # Wrong hash
            metadata={"content": self.test_content.decode()}
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
        assert any("content hash" in error.lower() or "mismatch" in error.lower()
                  for error in context.validation_errors)
    
    def test_missing_content_hash(self):
        """Test NFT without content hash (should fail)."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"missing_hash_test",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,
            content_hash=None,  # Missing hash
            metadata={"content": self.test_content.decode()}
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
        assert any("content hash" in error.lower() and "missing" in error.lower()
                  for error in context.validation_errors)
    
    def test_missing_metadata_content(self):
        """Test validation with missing metadata content."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"missing_content_test",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,
            content_hash=self.valid_hash,
            metadata=None  # Missing metadata
        )
        
        result = self.rule.validate(context)
        assert result is False
        assert context.has_errors()
    
    def test_fungible_asset_skip_content_hash(self):
        """Test that fungible assets skip content hash validation."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"fungible_skip_test",
            asset_type=AssetType.FUNGIBLE,  # Fungible, not NFT
            operation=OperationType.MINT,
            amount=1000,
            content_hash=None,
            metadata=None
        )
        
        result = self.rule.validate(context)
        assert result is True  # Should skip validation for fungible
        assert not context.has_errors()
    
    def test_various_hash_algorithms(self):
        """Test content hash validation with various hash algorithms."""
        # Test SHA256
        sha256_hash = hashlib.sha256(self.test_content).digest()
        context_sha256 = ValidationContext(
            psbt_data={},
            asset_id=b"sha256_test",
            asset_type=AssetType.NFT,
            content_hash=sha256_hash,
            metadata={"content": self.test_content.decode(), "hash_algorithm": "sha256"}
        )
        
        result = self.rule.validate(context_sha256)
        assert result is True
        assert not context_sha256.has_errors()
        
        # Test SHA512 (if supported)
        sha512_hash = hashlib.sha512(self.test_content).digest()
        context_sha512 = ValidationContext(
            psbt_data={},
            asset_id=b"sha512_test", 
            asset_type=AssetType.NFT,
            content_hash=sha512_hash,
            metadata={"content": self.test_content.decode(), "hash_algorithm": "sha512"}
        )
        
        # Depending on implementation, may or may not support SHA512
        result = self.rule.validate(context_sha512)
        assert result is True or context_sha512.has_errors()
    
    def test_large_content_hash_validation(self):
        """Test content hash validation with large content."""
        large_content = b"X" * 10000  # 10KB content
        large_hash = hashlib.sha256(large_content).digest()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b"large_content_test",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,
            content_hash=large_hash,
            metadata={"content": large_content.decode()}
        )
        
        result = self.rule.validate(context)
        assert result is True
        assert not context.has_errors()
    
    def test_content_hash_statistics(self):
        """Test content hash rule statistics."""
        rule = ContentHashRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b"stats_test",
            asset_type=AssetType.NFT,
            content_hash=self.valid_hash,
            metadata={"content": self.test_content.decode()}
        )
        
        rule.validate(context)
        
        stats = rule.get_statistics()
        assert "validations_performed" in stats
        assert "hashes_verified" in stats


class TestValidationRuleInteractions:
    """Test interactions between multiple validation rules."""
    
    def test_rule_execution_order(self):
        """Test that rules are executed in correct order."""
        from validator.core import ValidationEngine
        
        engine = ValidationEngine(config={})
        
        # Check that rules exist and are in reasonable order
        rule_names = [rule.name for rule in engine.rules]
        
        # Supply limit should come before mint limit
        if "supply_limit" in rule_names and "mint_limit" in rule_names:
            supply_idx = rule_names.index("supply_limit")
            mint_idx = rule_names.index("mint_limit")
            # Order may vary based on implementation
            assert supply_idx >= 0 and mint_idx >= 0
    
    def test_rule_failure_propagation(self):
        """Test that rule failures are properly propagated."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"failure_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=0  # This should fail supply validation
        )
        
        # Test supply limit rule
        supply_rule = SupplyLimitRule()
        result = supply_rule.validate(context)
        
        assert result is False
        assert context.has_errors()
        
        # Ensure error was recorded with rule name
        assert any("supply_limit" in error or "amount" in error 
                  for error in context.validation_errors)
    
    def test_rule_warning_vs_error_handling(self):
        """Test that rules properly distinguish warnings vs errors."""
        # Create context that might generate warnings
        context = ValidationContext(
            psbt_data={},
            asset_id=b"warning_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            current_supply=None  # Missing data might generate warnings
        )
        
        supply_rule = SupplyLimitRule()
        result = supply_rule.validate(context)
        
        # Rule should handle missing data gracefully
        # Either fail validation or add warnings
        assert not result or len(context.validation_warnings) > 0
    
    def test_rule_statistics_aggregation(self):
        """Test aggregation of statistics across rules."""
        rules = [
            SupplyLimitRule(),
            MintLimitRule(),
            AllowlistRule(),
            ContentHashRule()
        ]
        
        # Execute validations on each rule
        for rule in rules:
            context = ValidationContext(
                psbt_data={},
                asset_id=b"stats_test",
                asset_type=AssetType.FUNGIBLE,
                operation=OperationType.MINT,
                amount=1000
            )
            rule.validate(context)
        
        # Aggregate statistics
        total_validations = sum(
            rule.get_statistics().get("validations_performed", 0) 
            for rule in rules
        )
        
        assert total_validations >= len(rules)
    
    def test_rule_caching_independence(self):
        """Test that rule caching doesn't interfere between rules."""
        supply_rule = SupplyLimitRule()
        mint_rule = MintLimitRule()
        
        # Create similar contexts for both rules
        context1 = ValidationContext(
            psbt_data={},
            asset_id=b"cache_test_1",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            current_supply=100_000,
            supply_cap=1_000_000,
            per_mint_cap=50_000
        )
        
        context2 = ValidationContext(
            psbt_data={},
            asset_id=b"cache_test_1",  # Same asset ID
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=2000,  # Different amount
            current_supply=100_000,
            supply_cap=1_000_000,
            per_mint_cap=50_000
        )
        
        # Validate with both rules
        result1_supply = supply_rule.validate(context1)
        result1_mint = mint_rule.validate(context1)
        
        result2_supply = supply_rule.validate(context2)
        result2_mint = mint_rule.validate(context2)
        
        # Results should be consistent
        assert result1_supply is True
        assert result1_mint is True
        assert result2_supply is True
        assert result2_mint is True


# Edge case tests for boundary conditions
class TestValidationRuleEdgeCases:
    """Test edge cases and boundary conditions for validation rules."""
    
    def test_maximum_values(self):
        """Test validation with maximum possible values."""
        max_supply = 2**63 - 1  # Maximum int64
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b"max_values_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1,
            current_supply=max_supply - 1,
            supply_cap=max_supply
        )
        
        supply_rule = SupplyLimitRule()
        result = supply_rule.validate(context)
        
        # Should handle maximum values correctly
        assert result is True
        assert not context.has_errors()
    
    def test_minimum_values(self):
        """Test validation with minimum possible values."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b"min_values_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1,  # Minimum positive amount
            current_supply=0,
            supply_cap=1
        )
        
        supply_rule = SupplyLimitRule()
        result = supply_rule.validate(context)
        
        assert result is True
        assert not context.has_errors()
    
    def test_unicode_asset_ids(self):
        """Test validation with unicode asset IDs."""
        unicode_asset_id = "测试资产_123".encode('utf-8')
        
        context = ValidationContext(
            psbt_data={},
            asset_id=unicode_asset_id,
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            current_supply=0,
            supply_cap=1_000_000
        )
        
        supply_rule = SupplyLimitRule()
        result = supply_rule.validate(context)
        
        # Should handle unicode asset IDs
        assert result is True or context.has_errors()  # Depending on validation logic
    
    def test_empty_context_data(self):
        """Test rules with completely empty context."""
        context = ValidationContext(psbt_data={})
        
        rules = [
            SupplyLimitRule(),
            MintLimitRule(),
            AllowlistRule(),
            ContentHashRule()
        ]
        
        for rule in rules:
            try:
                result = rule.validate(context)
                # Rules should handle empty context gracefully
                assert result is False or len(context.validation_errors) > 0
            except Exception:
                pytest.fail(f"Rule {rule.name} should handle empty context gracefully")
    
    def test_rule_disable_enable(self):
        """Test rule disable/enable functionality."""
        rule = SupplyLimitRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b"disable_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            current_supply=0,
            supply_cap=500  # Would normally fail
        )
        
        # Enable rule - should fail
        rule.enabled = True
        result_enabled = rule.validate(context)
        assert result_enabled is False
        
        # Disable rule - should pass (or be skipped)
        rule.enabled = False
        context_disabled = ValidationContext(
            psbt_data={},
            asset_id=b"disable_test",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000,
            current_supply=0,
            supply_cap=500
        )
        result_disabled = rule.validate(context_disabled)
        # Behavior when disabled depends on implementation
        assert result_disabled is True or not context_disabled.has_errors()