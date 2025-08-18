"""
Tests for Mint Limit Rule

Tests the MintLimitRule validation logic including transaction analysis,
batch mint handling, and per-address validation.
"""

import pytest
from unittest.mock import Mock, patch

from validator.core import ValidationContext
from validator.rules.mint_limits import (
    MintLimitRule,
    MintOutput,
    MintAnalysis,
    LimitType,
    create_mint_limit_rule,
    validate_mint_limit_quick,
    analyze_mint_outputs
)
from registry.schema import AssetType
from crypto.commitments import OperationType


class TestMintOutput:
    """Test MintOutput data class."""
    
    def test_mint_output_creation(self):
        """Test basic mint output creation."""
        output = MintOutput(
            address="bc1qexample123",
            amount=1000,
            asset_id=b'\\x01' * 32,
            output_index=0
        )
        
        assert output.address == "bc1qexample123"
        assert output.amount == 1000
        assert output.asset_id == b'\\x01' * 32
        assert output.output_index == 0


class TestMintAnalysis:
    """Test MintAnalysis data class."""
    
    def test_mint_analysis_creation(self):
        """Test basic mint analysis creation."""
        outputs = [
            MintOutput("address1", 500, b'\\x01' * 32, 0),
            MintOutput("address2", 750, b'\\x01' * 32, 1)
        ]
        
        analysis = MintAnalysis(
            total_amount=1250,
            outputs=outputs,
            unique_addresses=2,
            max_amount_per_address=750,
            is_batch_mint=True
        )
        
        assert analysis.total_amount == 1250
        assert len(analysis.outputs) == 2
        assert analysis.unique_addresses == 2
        assert analysis.max_amount_per_address == 750
        assert analysis.is_batch_mint is True
    
    def test_get_amount_by_address(self):
        """Test amount aggregation by address."""
        outputs = [
            MintOutput("address1", 500, b'\\x01' * 32, 0),
            MintOutput("address1", 300, b'\\x01' * 32, 1),  # Same address
            MintOutput("address2", 750, b'\\x01' * 32, 2)
        ]
        
        analysis = MintAnalysis(
            total_amount=1550,
            outputs=outputs,
            unique_addresses=2,
            max_amount_per_address=800,
            is_batch_mint=True
        )
        
        amounts = analysis.get_amount_by_address()
        
        assert amounts["address1"] == 800  # 500 + 300
        assert amounts["address2"] == 750
        assert len(amounts) == 2


class TestMintLimitRule:
    """Test MintLimitRule functionality."""
    
    def test_rule_creation(self):
        """Test basic rule creation."""
        rule = MintLimitRule()
        
        assert rule.name == "mint_limit"
        assert "per-mint" in rule.description.lower()
        assert rule.enabled is True
        assert rule.strict_mode is True
        assert rule.allow_batch_mints is True
    
    def test_rule_creation_with_config(self):
        """Test rule creation with custom configuration."""
        rule = MintLimitRule(strict_mode=False, allow_batch_mints=False)
        
        assert rule.strict_mode is False
        assert rule.allow_batch_mints is False
    
    def test_applicability_mint_operation(self):
        """Test rule applicability for mint operations."""
        rule = MintLimitRule()
        
        # Valid mint operation
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            per_mint_cap=5000
        )
        
        assert rule.is_applicable(context) is True
    
    def test_applicability_non_mint_operation(self):
        """Test rule applicability for non-mint operations."""
        rule = MintLimitRule()
        
        # Transfer operation should not be applicable
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.TRANSFER,
            amount=1000,
            per_mint_cap=5000
        )
        
        assert rule.is_applicable(context) is False
    
    def test_applicability_missing_data(self):
        """Test rule applicability with missing required data."""
        rule = MintLimitRule()
        
        # Missing asset_id
        context = ValidationContext(
            psbt_data={},
            asset_id=None,
            operation=OperationType.MINT,
            amount=1000,
            per_mint_cap=5000
        )
        assert rule.is_applicable(context) is False
        
        # Missing amount
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=None,
            per_mint_cap=5000
        )
        assert rule.is_applicable(context) is False
        
        # Missing per-mint cap
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=1000,
            per_mint_cap=None
        )
        assert rule.is_applicable(context) is False
    
    def test_validation_success(self):
        """Test successful validation within mint limits."""
        rule = MintLimitRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=3000,
            per_mint_cap=5000
        )
        
        result = rule.validate(context)
        
        assert result is True
        assert not context.has_errors()
        assert rule.stats["approved_within_limit"] == 1
        assert rule.stats["validations_performed"] == 1
        assert rule.stats["single_mints_processed"] == 1
    
    def test_validation_failure_over_limit(self):
        """Test validation failure when exceeding mint limit."""
        rule = MintLimitRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=6000,
            per_mint_cap=5000
        )
        
        result = rule.validate(context)
        
        assert result is False
        assert context.has_errors()
        assert rule.stats["rejected_over_limit"] == 1
        assert rule.stats["validations_performed"] == 1
        
        # Check error message content
        errors = context.validation_errors
        assert len(errors) == 1
        assert "exceeds per-mint limit" in errors[0]
        assert "6000" in errors[0]
        assert "5000" in errors[0]
    
    def test_validation_exactly_at_limit(self):
        """Test validation when mint exactly reaches the limit."""
        rule = MintLimitRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=5000,
            per_mint_cap=5000
        )
        
        result = rule.validate(context)
        
        assert result is True
        assert not context.has_errors()
    
    def test_batch_mints_allowed(self):
        """Test batch mints when allowed."""
        rule = MintLimitRule(allow_batch_mints=True)
        
        # Mock the mint analysis to return a batch mint
        with patch.object(rule, '_analyze_mint_transaction') as mock_analyze:
            outputs = [
                MintOutput("address1", 2000, b'\\x01' * 32, 0),
                MintOutput("address2", 1500, b'\\x01' * 32, 1)
            ]
            
            mock_analysis = MintAnalysis(
                total_amount=3500,
                outputs=outputs,
                unique_addresses=2,
                max_amount_per_address=2000,
                is_batch_mint=True
            )
            mock_analyze.return_value = mock_analysis
            
            context = ValidationContext(
                psbt_data={},
                asset_id=b'\\x01' * 32,
                operation=OperationType.MINT,
                amount=3500,
                per_mint_cap=5000
            )
            
            result = rule.validate(context)
            
            assert result is True
            assert not context.has_errors()
            assert rule.stats["batch_mints_processed"] == 1
    
    def test_batch_mints_not_allowed(self):
        """Test batch mints when not allowed."""
        rule = MintLimitRule(allow_batch_mints=False)
        
        # Mock the mint analysis to return a batch mint
        with patch.object(rule, '_analyze_mint_transaction') as mock_analyze:
            outputs = [
                MintOutput("address1", 2000, b'\\x01' * 32, 0),
                MintOutput("address2", 1500, b'\\x01' * 32, 1)
            ]
            
            mock_analysis = MintAnalysis(
                total_amount=3500,
                outputs=outputs,
                unique_addresses=2,
                max_amount_per_address=2000,
                is_batch_mint=True
            )
            mock_analyze.return_value = mock_analysis
            
            context = ValidationContext(
                psbt_data={},
                asset_id=b'\\x01' * 32,
                operation=OperationType.MINT,
                amount=3500,
                per_mint_cap=5000
            )
            
            result = rule.validate(context)
            
            assert result is False
            assert context.has_errors()
            assert rule.stats["rejected_batch_not_allowed"] == 1
            
            # Check error message
            errors = context.validation_errors
            assert "Batch mints not allowed" in errors[0]
    
    def test_strict_mode_address_validation(self):
        """Test strict mode per-address validation."""
        rule = MintLimitRule(strict_mode=True)
        
        # Mock analysis with one address exceeding limit
        with patch.object(rule, '_analyze_mint_transaction') as mock_analyze:
            outputs = [
                MintOutput("address1", 3000, b'\\x01' * 32, 0),
                MintOutput("address1", 3500, b'\\x01' * 32, 1)  # Same address, total 6500
            ]
            
            mock_analysis = MintAnalysis(
                total_amount=6500,
                outputs=outputs,
                unique_addresses=1,
                max_amount_per_address=6500,
                is_batch_mint=False
            )
            mock_analyze.return_value = mock_analysis
            
            context = ValidationContext(
                psbt_data={},
                asset_id=b'\\x01' * 32,
                operation=OperationType.MINT,
                amount=6500,
                per_mint_cap=5000  # Address gets 6500 > 5000 limit
            )
            
            result = rule.validate(context)
            
            assert result is False
            assert context.has_errors()
            assert "exceeds per-mint limit" in context.validation_errors[0]
    
    def test_non_strict_mode(self):
        """Test non-strict mode skips per-address validation."""
        rule = MintLimitRule(strict_mode=False)
        
        # Mock analysis where total is within limit but individual addresses might exceed in strict mode
        with patch.object(rule, '_analyze_mint_transaction') as mock_analyze:
            outputs = [
                MintOutput("address1", 4000, b'\\x01' * 32, 0)  # Single output within limit
            ]
            
            mock_analysis = MintAnalysis(
                total_amount=4000,  # Total matches context amount
                outputs=outputs,
                unique_addresses=1,
                max_amount_per_address=4000,
                is_batch_mint=False
            )
            mock_analyze.return_value = mock_analysis
            
            context = ValidationContext(
                psbt_data={},
                asset_id=b'\\x01' * 32,
                operation=OperationType.MINT,
                amount=4000,  # Total transaction is under limit
                per_mint_cap=5000
            )
            
            result = rule.validate(context)
            
            # Should pass in non-strict mode when total is within limit
            assert result is True
            assert not context.has_errors()
    
    def test_statistics(self):
        """Test statistics tracking."""
        rule = MintLimitRule()
        
        stats = rule.get_statistics()
        
        expected_keys = [
            "validations_performed",
            "rejected_over_limit",
            "rejected_batch_not_allowed",
            "approved_within_limit",
            "batch_mints_processed",
            "single_mints_processed",
            "batch_mint_rate_percent",
            "strict_mode",
            "allow_batch_mints"
        ]
        
        for key in expected_keys:
            assert key in stats
        
        # Initial state
        assert stats["batch_mint_rate_percent"] == 0.0
        assert stats["strict_mode"] is True
        assert stats["allow_batch_mints"] is True
    
    def test_asset_configuration_validation(self):
        """Test asset configuration validation."""
        rule = MintLimitRule()
        
        # Valid fungible asset
        valid_fungible = {
            "asset_type": "fungible",
            "per_mint_limit": 100000,
            "maximum_supply": 1000000
        }
        assert rule.validate_asset_configuration(valid_fungible) is True
        
        # Valid NFT asset
        valid_nft = {
            "asset_type": "nft",
            "per_mint_limit": 10,
            "collection_size": 10000
        }
        assert rule.validate_asset_configuration(valid_nft) is True
        
        # Invalid - negative per-mint limit
        invalid_negative = {
            "asset_type": "fungible",
            "per_mint_limit": -100
        }
        assert rule.validate_asset_configuration(invalid_negative) is False
        
        # Invalid - per-mint limit exceeds maximum supply
        invalid_limit = {
            "asset_type": "fungible",
            "per_mint_limit": 2000000,
            "maximum_supply": 1000000
        }
        assert rule.validate_asset_configuration(invalid_limit) is False
        
        # Invalid - too large per-mint limit for fungible
        invalid_large_fungible = {
            "asset_type": "fungible",
            "per_mint_limit": 10**16
        }
        assert rule.validate_asset_configuration(invalid_large_fungible) is False
        
        # Invalid - too large per-mint limit for NFT
        invalid_large_nft = {
            "asset_type": "nft",
            "per_mint_limit": 2000
        }
        assert rule.validate_asset_configuration(invalid_large_nft) is False
        
        # Valid - no per-mint limit specified
        no_limit = {
            "asset_type": "fungible",
            "maximum_supply": 1000000
        }
        assert rule.validate_asset_configuration(no_limit) is True
    
    def test_estimate_max_transactions(self):
        """Test transaction estimation utility."""
        rule = MintLimitRule()
        
        # Exact division
        assert rule.estimate_max_transactions_needed(10000, 2500) == 4
        
        # With remainder
        assert rule.estimate_max_transactions_needed(10001, 2500) == 5
        
        # Less than limit
        assert rule.estimate_max_transactions_needed(1000, 2500) == 1
        
        # Invalid limit
        assert rule.estimate_max_transactions_needed(10000, 0) == -1
        assert rule.estimate_max_transactions_needed(10000, -100) == -1
    
    def test_suggest_mint_strategy(self):
        """Test mint strategy suggestion."""
        rule = MintLimitRule()
        
        # Single transaction needed
        strategy = rule.suggest_mint_strategy(3000, 5000)
        assert strategy["transactions_needed"] == 1
        assert strategy["strategy"] == "single"
        assert strategy["amounts"] == [3000]
        assert strategy["remainder"] == 0
        
        # Multiple transactions needed
        strategy = rule.suggest_mint_strategy(12000, 5000)
        assert strategy["transactions_needed"] == 3
        assert strategy["strategy"] == "batch"
        assert strategy["amounts"] == [5000, 5000, 2000]
        assert strategy["remainder"] == 2000
        
        # Exact division
        strategy = rule.suggest_mint_strategy(15000, 5000)
        assert strategy["transactions_needed"] == 3
        assert strategy["strategy"] == "batch"
        assert strategy["amounts"] == [5000, 5000, 5000]
        assert strategy["remainder"] == 0
        
        # Invalid limit
        strategy = rule.suggest_mint_strategy(10000, 0)
        assert "error" in strategy


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_create_mint_limit_rule(self):
        """Test mint limit rule creation utility."""
        rule = create_mint_limit_rule()
        assert isinstance(rule, MintLimitRule)
        assert rule.strict_mode is True
        assert rule.allow_batch_mints is True
        
        # With custom config
        config = {
            "strict_mode": False,
            "allow_batch_mints": False
        }
        rule = create_mint_limit_rule(config)
        assert rule.strict_mode is False
        assert rule.allow_batch_mints is False
    
    def test_validate_mint_limit_quick(self):
        """Test quick mint limit validation utility."""
        # Valid case
        is_valid, error = validate_mint_limit_quick(3000, 5000)
        assert is_valid is True
        assert error == ""
        
        # Invalid - exceeds limit
        is_valid, error = validate_mint_limit_quick(6000, 5000)
        assert is_valid is False
        assert "exceeds limit" in error
        assert "1000" in error  # Excess amount
        
        # At limit - should pass
        is_valid, error = validate_mint_limit_quick(5000, 5000)
        assert is_valid is True
        assert error == ""
        
        # Invalid parameters
        is_valid, error = validate_mint_limit_quick(-100, 5000)
        assert is_valid is False
        assert "Invalid mint parameters" in error
        
        is_valid, error = validate_mint_limit_quick(1000, -100)
        assert is_valid is False
        assert "Invalid mint parameters" in error
        
        is_valid, error = validate_mint_limit_quick(0, 5000)
        assert is_valid is False
        assert "Invalid mint parameters" in error
    
    def test_analyze_mint_outputs(self):
        """Test mint output analysis utility."""
        outputs = [
            {"amount": 1000, "address": "address1"},
            {"amount": 1500, "address": "address2"},
            {"amount": 500, "address": "address1"}  # Same address as first
        ]
        
        asset_id = b'\\x01' * 32
        analysis = analyze_mint_outputs(outputs, asset_id)
        
        assert analysis.total_amount == 3000  # 1000 + 1500 + 500
        assert len(analysis.outputs) == 3
        assert analysis.unique_addresses == 2
        assert analysis.max_amount_per_address == 1500  # address1: 1500, address2: 1500
        assert analysis.is_batch_mint is True
        
        # Test amounts by address
        amounts = analysis.get_amount_by_address()
        assert amounts["address1"] == 1500  # 1000 + 500
        assert amounts["address2"] == 1500


class TestIntegration:
    """Integration tests with ValidationEngine."""
    
    def test_rule_integration(self):
        """Test mint limit rule integration with ValidationEngine."""
        from validator.core import ValidationEngine
        
        engine = ValidationEngine()
        
        # Check that MintLimitRule is registered by default
        rule_names = [rule.name for rule in engine.rules]
        assert "mint_limit" in rule_names
        
        # Get the mint limit rule
        mint_rule = engine.rule_registry["mint_limit"]
        assert isinstance(mint_rule, MintLimitRule)
        
        # Test statistics access
        stats = mint_rule.get_statistics()
        assert isinstance(stats, dict)
        assert "validations_performed" in stats


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_analysis_failure_handling(self):
        """Test handling of mint analysis failures."""
        rule = MintLimitRule()
        
        # Mock analyze method to return None
        with patch.object(rule, '_analyze_mint_transaction', return_value=None):
            context = ValidationContext(
                psbt_data={},
                asset_id=b'\\x01' * 32,
                operation=OperationType.MINT,
                amount=1000,
                per_mint_cap=5000
            )
            
            result = rule.validate(context)
            
            assert result is False
            assert context.has_errors()
            assert "Failed to analyze mint transaction" in context.validation_errors[0]
    
    def test_extract_mint_outputs_empty(self):
        """Test mint output extraction with empty PSBT data."""
        rule = MintLimitRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            amount=0
        )
        
        outputs = rule._extract_mint_outputs(context)
        assert isinstance(outputs, list)
        # Should handle gracefully even with no data
    
    def test_zero_amount_handling(self):
        """Test handling of zero amounts."""
        rule = MintLimitRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            amount=0,
            per_mint_cap=5000
        )
        
        # Zero amount should be considered invalid for mints
        assert rule.is_applicable(context) is False
        
        # Negative amount should also be invalid
        context.amount = -100
        assert rule.is_applicable(context) is False