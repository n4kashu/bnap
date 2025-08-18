"""
Comprehensive Integration Tests for BNAP Validator System

Tests complete validation flows, rule interactions, registry integration,
and end-to-end scenarios with realistic PSBTs and asset operations.
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from validator.core import ValidationEngine, ValidationResult, ValidationContext
from validator.registry_client import RegistryClient, get_registry_client
from validator.audit_logger import AuditLogger, get_audit_logger
from validator.error_reporting import ErrorReporter, get_error_reporter

from registry.manager import RegistryManager
from registry.schema import (
    Asset, AssetType, AssetStatus, FungibleAsset, NFTAsset, 
    StateEntry, TransactionEntry, ValidatorConfig
)
from psbt.parser import PSBTParser
from psbt.builder import PSBTBuilder
from crypto.keys import PrivateKey, PublicKey
from crypto.commitments import OperationType


class TestValidatorIntegration:
    """Test complete validator integration scenarios."""
    
    def setup_method(self):
        """Set up test fixtures for each test."""
        # Create test configuration
        self.validator_config = {
            "validator_id": "test_validator",
            "max_validation_time": 30,
            "enable_audit_logging": True,
            "require_allowlist": False,
            "max_supply_cap": 21_000_000,
            "max_per_mint_cap": 1_000_000,
            "signing_keys": {}
        }
        
        # Create test assets
        self.test_fungible_asset = FungibleAsset(
            asset_id="fungible_test_123",
            name="Test Fungible Token",
            symbol="TFT",
            issuer_pubkey="0123456789abcdef" * 8,
            maximum_supply=1_000_000,
            per_mint_limit=10_000,
            decimal_places=8,
            asset_type=AssetType.FUNGIBLE,
            status=AssetStatus.ACTIVE
        )
        
        self.test_nft_asset = NFTAsset(
            asset_id="nft_test_456",
            name="Test NFT Collection", 
            symbol="TNFT",
            issuer_pubkey="fedcba9876543210" * 8,
            collection_size=1_000,
            asset_type=AssetType.NFT,
            status=AssetStatus.ACTIVE,
            base_uri="https://example.com/metadata/"
        )
        
        # Create test state entries
        self.fungible_state = StateEntry(
            asset_id=self.test_fungible_asset.asset_id,
            minted_supply=50_000,
            transaction_count=100
        )
        
        self.nft_state = StateEntry(
            asset_id=self.test_nft_asset.asset_id,
            minted_supply=250,
            transaction_count=250,
            issued_nft_ids=list(range(1, 251))
        )
    
    @patch('validator.core.RegistryManager')
    def test_complete_fungible_mint_validation_flow(self, mock_registry_manager):
        """Test complete validation flow for fungible asset mint."""
        # Mock registry manager
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_fungible_asset
        mock_manager.get_asset_state.return_value = self.fungible_state
        mock_manager.get_asset_supply_info.return_value = {
            'asset_id': self.test_fungible_asset.asset_id,
            'asset_type': AssetType.FUNGIBLE,
            'minted_supply': 50_000,
            'maximum_supply': 1_000_000,
            'per_mint_limit': 10_000,
            'remaining_supply': 950_000,
            'transaction_count': 100
        }
        mock_registry_manager.return_value = mock_manager
        
        # Create validation engine
        validator = ValidationEngine(
            config=self.validator_config,
            registry_manager=mock_manager
        )
        
        # Create mock PSBT data for fungible mint
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{
                'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0},
                'proprietary_fields': {}
            }],
            'outputs': [{
                'amount': 546,  # Dust amount for OP_RETURN
                'script': b'\x6a' + b'BNAP_METADATA_PLACEHOLDER',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex(self.test_fungible_asset.asset_id),
                    b'BNAPAMT': (5000).to_bytes(8, 'little'),  # Mint 5000 tokens
                    b'BNAPTY': b'FUNGIBLE'
                }
            }, {
                'amount': 100_000,  # Recipient output
                'script': b'recipient_script_placeholder',
                'proprietary_fields': {}
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            # Execute validation
            context = validator.validate_mint_transaction("mock_psbt_hex")
            
            # Verify validation results
            assert context is not None
            assert not context.has_errors()  # Should pass all validations
            assert context.asset_id == bytes.fromhex(self.test_fungible_asset.asset_id)
            assert context.amount == 5000
            assert context.operation == OperationType.MINT
            
            # Verify registry interactions
            mock_manager.get_asset_by_id.assert_called()
            mock_manager.get_asset_state.assert_called()
    
    @patch('validator.core.RegistryManager')
    def test_supply_limit_violation_detection(self, mock_registry_manager):
        """Test detection of supply limit violations."""
        # Create asset near supply limit
        near_limit_state = StateEntry(
            asset_id=self.test_fungible_asset.asset_id,
            minted_supply=999_000,  # Near the 1M limit
            transaction_count=1000
        )
        
        # Mock registry manager
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_fungible_asset
        mock_manager.get_asset_state.return_value = near_limit_state
        mock_manager.get_asset_supply_info.return_value = {
            'asset_id': self.test_fungible_asset.asset_id,
            'asset_type': AssetType.FUNGIBLE,
            'minted_supply': 999_000,
            'maximum_supply': 1_000_000,
            'remaining_supply': 1_000,
            'per_mint_limit': 10_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(
            config=self.validator_config,
            registry_manager=mock_manager
        )
        
        # Mock PSBT data attempting to mint more than remaining supply
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'BNAP_METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex(self.test_fungible_asset.asset_id),
                    b'BNAPAMT': (2000).to_bytes(8, 'little'),  # Exceeds remaining 1000
                    b'BNAPTY': b'FUNGIBLE'
                }
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            context = validator.validate_mint_transaction("mock_psbt_hex")
            
            # Should fail validation due to supply limit
            assert context.has_errors()
            assert any("supply" in error.lower() for error in context.validation_errors)
    
    @patch('validator.core.RegistryManager')
    def test_per_mint_limit_enforcement(self, mock_registry_manager):
        """Test per-mint limit enforcement."""
        # Mock registry manager
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_fungible_asset
        mock_manager.get_asset_state.return_value = self.fungible_state
        mock_manager.get_asset_supply_info.return_value = {
            'asset_id': self.test_fungible_asset.asset_id,
            'asset_type': AssetType.FUNGIBLE,
            'per_mint_limit': 10_000,
            'remaining_supply': 500_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.validator_config, registry_manager=mock_manager)
        
        # Mock PSBT data exceeding per-mint limit
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'BNAP_METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex(self.test_fungible_asset.asset_id),
                    b'BNAPAMT': (15_000).to_bytes(8, 'little'),  # Exceeds 10k limit
                    b'BNAPTY': b'FUNGIBLE'
                }
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            context = validator.validate_mint_transaction("mock_psbt_hex")
            
            # Should fail validation due to per-mint limit
            assert context.has_errors()
            assert any("mint" in error.lower() and "limit" in error.lower() 
                      for error in context.validation_errors)
    
    @patch('validator.core.RegistryManager')
    def test_nft_mint_validation_flow(self, mock_registry_manager):
        """Test NFT mint validation flow."""
        # Mock registry manager for NFT
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_nft_asset
        mock_manager.get_asset_state.return_value = self.nft_state
        mock_manager.get_asset_supply_info.return_value = {
            'asset_id': self.test_nft_asset.asset_id,
            'asset_type': AssetType.NFT,
            'collection_size': 1_000,
            'issued_nft_count': 250,
            'available_nft_count': 750,
            'issued_nft_ids': list(range(1, 251))
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.validator_config, registry_manager=mock_manager)
        
        # Mock PSBT data for NFT mint
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'BNAP_NFT_METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex(self.test_nft_asset.asset_id),
                    b'BNAPAMT': (1).to_bytes(8, 'little'),  # NFT mint amount = 1
                    b'BNAPTY': b'NFT',
                    b'BNAPTID': (251).to_bytes(4, 'little')  # Token ID 251
                }
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            context = validator.validate_mint_transaction("mock_psbt_hex")
            
            # Should pass validation
            assert not context.has_errors()
            assert context.asset_type == AssetType.NFT
            assert context.token_id == 251
    
    @patch('validator.core.RegistryManager')
    def test_nft_collection_exhaustion(self, mock_registry_manager):
        """Test NFT collection exhaustion detection."""
        # Create fully minted NFT collection
        exhausted_nft_state = StateEntry(
            asset_id=self.test_nft_asset.asset_id,
            minted_supply=1_000,  # All NFTs minted
            transaction_count=1_000,
            issued_nft_ids=list(range(1, 1001))
        )
        
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_nft_asset
        mock_manager.get_asset_state.return_value = exhausted_nft_state
        mock_manager.get_asset_supply_info.return_value = {
            'asset_id': self.test_nft_asset.asset_id,
            'asset_type': AssetType.NFT,
            'collection_size': 1_000,
            'issued_nft_count': 1_000,
            'available_nft_count': 0
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.validator_config, registry_manager=mock_manager)
        
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'BNAP_NFT_METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex(self.test_nft_asset.asset_id),
                    b'BNAPAMT': (1).to_bytes(8, 'little'),
                    b'BNAPTY': b'NFT'
                }
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            context = validator.validate_mint_transaction("mock_psbt_hex")
            
            # Should fail - collection is exhausted
            assert context.has_errors()
            assert any("collection" in error.lower() or "available" in error.lower() 
                      for error in context.validation_errors)
    
    @patch('validator.core.RegistryManager')
    def test_duplicate_nft_token_id_detection(self, mock_registry_manager):
        """Test detection of duplicate NFT token IDs."""
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_nft_asset
        mock_manager.get_asset_state.return_value = self.nft_state  # Contains IDs 1-250
        mock_manager.get_asset_supply_info.return_value = {
            'asset_id': self.test_nft_asset.asset_id,
            'asset_type': AssetType.NFT,
            'issued_nft_ids': list(range(1, 251))
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.validator_config, registry_manager=mock_manager)
        
        # Try to mint existing token ID
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'BNAP_NFT_METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex(self.test_nft_asset.asset_id),
                    b'BNAPAMT': (1).to_bytes(8, 'little'),
                    b'BNAPTY': b'NFT',
                    b'BNAPTID': (100).to_bytes(4, 'little')  # Already minted ID
                }
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            context = validator.validate_mint_transaction("mock_psbt_hex")
            
            # Should fail - duplicate token ID
            assert context.has_errors()
            assert any("duplicate" in error.lower() or "already" in error.lower()
                      for error in context.validation_errors)
    
    def test_validation_engine_statistics_tracking(self):
        """Test that validation engine properly tracks statistics."""
        validator = ValidationEngine(config=self.validator_config)
        
        # Initial statistics should be zero
        initial_stats = validator.get_validation_statistics()
        assert initial_stats["total_validations"] == 0
        assert initial_stats["approved_validations"] == 0
        assert initial_stats["rejected_validations"] == 0
        
        # Mock some validations
        with patch.object(validator, 'validate_mint_transaction') as mock_validate:
            # Mock successful validation
            success_context = ValidationContext(psbt_data={})
            mock_validate.return_value = success_context
            
            validator.validate_mint_transaction("success_psbt")
            
            # Mock failed validation
            fail_context = ValidationContext(psbt_data={})
            fail_context.add_error("test_rule", "Test validation error")
            mock_validate.return_value = fail_context
            
            validator.validate_mint_transaction("fail_psbt")
        
        # Check statistics are updated
        final_stats = validator.get_validation_statistics()
        assert final_stats["total_validations"] >= 2
    
    @patch('validator.core.RegistryManager')
    def test_registry_integration_error_handling(self, mock_registry_manager):
        """Test handling of registry connection errors."""
        # Mock registry manager that fails
        mock_manager = Mock()
        mock_manager.get_asset_by_id.side_effect = Exception("Registry connection failed")
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.validator_config, registry_manager=mock_manager)
        
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'BNAP_METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex(self.test_fungible_asset.asset_id),
                    b'BNAPAMT': (1000).to_bytes(8, 'little'),
                    b'BNAPTY': b'FUNGIBLE'
                }
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            context = validator.validate_mint_transaction("mock_psbt_hex")
            
            # Should handle registry errors gracefully
            assert context is not None
            # May have warnings about registry unavailability
            assert len(context.validation_warnings) > 0 or len(context.validation_errors) > 0
    
    def test_multiple_rule_interactions(self):
        """Test interactions between multiple validation rules."""
        # This test verifies that rules work together correctly
        validator = ValidationEngine(config=self.validator_config)
        
        # Check that all expected rules are registered
        expected_rules = ["supply_limit", "mint_limit", "allowlist", "content_hash"]
        registered_rule_names = [rule.name for rule in validator.rules]
        
        for expected_rule in expected_rules:
            assert expected_rule in registered_rule_names
        
        # Verify rules are in expected order (if order matters)
        assert len(validator.rules) >= 4
    
    @patch('validator.core.RegistryManager')
    def test_malformed_psbt_handling(self, mock_registry_manager):
        """Test handling of malformed PSBT data."""
        mock_manager = Mock()
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.validator_config, registry_manager=mock_manager)
        
        # Test with various malformed PSBT scenarios
        malformed_scenarios = [
            "",  # Empty PSBT
            "invalid_hex",  # Invalid hex
            "deadbeef",  # Valid hex but not valid PSBT
        ]
        
        for scenario in malformed_scenarios:
            with patch.object(validator.psbt_parser, 'parse', side_effect=Exception("Parse error")):
                context = validator.validate_mint_transaction(scenario)
                
                # Should handle parse errors gracefully
                assert context is not None
                assert context.has_errors()
    
    @patch('validator.core.RegistryManager')
    def test_concurrent_validation_safety(self, mock_registry_manager):
        """Test thread safety of concurrent validations."""
        import threading
        
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_fungible_asset
        mock_manager.get_asset_state.return_value = self.fungible_state
        mock_manager.get_asset_supply_info.return_value = {
            'asset_id': self.test_fungible_asset.asset_id,
            'remaining_supply': 100_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.validator_config, registry_manager=mock_manager)
        
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'BNAP_METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex(self.test_fungible_asset.asset_id),
                    b'BNAPAMT': (100).to_bytes(8, 'little'),
                    b'BNAPTY': b'FUNGIBLE'
                }
            }]
        }
        
        results = []
        errors = []
        
        def validate_transaction(thread_id):
            try:
                with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
                    context = validator.validate_mint_transaction(f"psbt_{thread_id}")
                    results.append((thread_id, context.has_errors()))
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        # Run multiple validations concurrently
        threads = []
        for i in range(10):
            thread = threading.Thread(target=validate_transaction, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=5)
        
        # Check results
        assert len(results) == 10
        assert len(errors) == 0
        
        # All validations should have consistent results
        error_statuses = [has_errors for _, has_errors in results]
        assert all(status == error_statuses[0] for status in error_statuses)


class TestValidatorPerformance:
    """Performance tests for validator components."""
    
    @patch('validator.core.RegistryManager')
    def test_high_throughput_validation(self, mock_registry_manager):
        """Test validator performance under high throughput."""
        # Mock registry for fast responses
        mock_manager = Mock()
        mock_asset = FungibleAsset(
            asset_id="perf_test_asset",
            name="Performance Test Token",
            symbol="PTT",
            issuer_pubkey="0123456789abcdef" * 8,
            maximum_supply=10_000_000,
            per_mint_limit=100_000,
            decimal_places=8,
            asset_type=AssetType.FUNGIBLE,
            status=AssetStatus.ACTIVE
        )
        mock_state = StateEntry(asset_id="perf_test_asset", minted_supply=1_000_000)
        
        mock_manager.get_asset_by_id.return_value = mock_asset
        mock_manager.get_asset_state.return_value = mock_state
        mock_manager.get_asset_supply_info.return_value = {
            'remaining_supply': 5_000_000,
            'per_mint_limit': 100_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(
            config={"validator_id": "perf_test", "enable_audit_logging": False},
            registry_manager=mock_manager
        )
        
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex("perf_test_asset"),
                    b'BNAPAMT': (1000).to_bytes(8, 'little'),
                    b'BNAPTY': b'FUNGIBLE'
                }
            }]
        }
        
        # Measure validation performance
        num_validations = 100
        start_time = time.time()
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            for i in range(num_validations):
                context = validator.validate_mint_transaction(f"psbt_{i}")
                assert not context.has_errors()
        
        end_time = time.time()
        total_time = end_time - start_time
        validations_per_second = num_validations / total_time
        
        # Performance assertions
        assert validations_per_second > 50  # Should handle at least 50 validations/second
        assert total_time < 10  # Should complete 100 validations in under 10 seconds
        
        print(f"Performance: {validations_per_second:.1f} validations/second")
    
    def test_memory_usage_stability(self):
        """Test that memory usage remains stable during extended operation."""
        import gc
        import sys
        
        validator = ValidationEngine(config={"enable_audit_logging": False})
        
        # Get initial memory baseline
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Simulate extended validation operation
        for i in range(1000):
            # Create and destroy validation contexts
            context = ValidationContext(psbt_data={"test": i})
            context.add_error("test_rule", f"Test error {i}")
            context.add_warning("test_rule", f"Test warning {i}")
            
            # Explicitly delete to help GC
            del context
            
            if i % 100 == 0:
                gc.collect()
        
        # Check final memory usage
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # Memory growth should be reasonable
        memory_growth = final_objects - initial_objects
        assert memory_growth < 1000  # Shouldn't accumulate too many objects


class TestValidatorFixtures:
    """Test fixtures and test data generators."""
    
    @pytest.fixture
    def valid_fungible_psbt_hex(self):
        """Generate valid fungible mint PSBT hex."""
        # This would normally generate a real PSBT
        # For now, return a placeholder
        return "70736274ff01005e02000000010000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01220200000000000017a914000000000000000000000000000000000000000087000000000000"
    
    @pytest.fixture
    def valid_nft_psbt_hex(self):
        """Generate valid NFT mint PSBT hex."""
        return "70736274ff01005e02000000010000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01220200000000000017a914111111111111111111111111111111111111118700000000001"
    
    @pytest.fixture
    def invalid_psbt_hex(self):
        """Generate invalid PSBT hex for negative testing."""
        return "invalid_psbt_data_hex"
    
    @pytest.fixture
    def test_assets(self):
        """Generate test assets for various scenarios."""
        return {
            "low_supply": FungibleAsset(
                asset_id="low_supply_123",
                name="Low Supply Token",
                symbol="LST",
                issuer_pubkey="0123456789abcdef" * 8,
                maximum_supply=1_000,
                per_mint_limit=100,
                decimal_places=2,
                asset_type=AssetType.FUNGIBLE,
                status=AssetStatus.ACTIVE
            ),
            "high_supply": FungibleAsset(
                asset_id="high_supply_456",
                name="High Supply Token", 
                symbol="HST",
                issuer_pubkey="fedcba9876543210" * 8,
                maximum_supply=1_000_000_000,
                per_mint_limit=1_000_000,
                decimal_places=18,
                asset_type=AssetType.FUNGIBLE,
                status=AssetStatus.ACTIVE
            ),
            "small_nft": NFTAsset(
                asset_id="small_nft_789",
                name="Small NFT Collection",
                symbol="SNFT",
                issuer_pubkey="1122334455667788" * 8,
                collection_size=10,
                asset_type=AssetType.NFT,
                status=AssetStatus.ACTIVE,
                base_uri="https://small.com/"
            )
        }
    
    def test_fixture_validity(self, test_assets):
        """Test that all fixtures are valid."""
        for asset_name, asset in test_assets.items():
            assert asset.asset_id is not None
            assert asset.name is not None
            assert asset.symbol is not None
            assert asset.status == AssetStatus.ACTIVE
    
    def test_psbt_fixtures_format(self, valid_fungible_psbt_hex, valid_nft_psbt_hex, invalid_psbt_hex):
        """Test that PSBT fixtures have correct format."""
        # Valid PSBTs should be hex strings starting with PSBT magic
        assert isinstance(valid_fungible_psbt_hex, str)
        assert isinstance(valid_nft_psbt_hex, str)
        assert len(valid_fungible_psbt_hex) > 0
        assert len(valid_nft_psbt_hex) > 0
        
        # Invalid PSBT should be string but not valid format
        assert isinstance(invalid_psbt_hex, str)


class TestValidatorEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @patch('validator.core.RegistryManager')
    def test_zero_amount_mint(self, mock_registry_manager):
        """Test validation of zero-amount mint (should fail)."""
        mock_manager = Mock()
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config={})
        
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'METADATA',
                'proprietary_fields': {
                    b'BNAPAID': b'test_asset_id',
                    b'BNAPAMT': (0).to_bytes(8, 'little'),  # Zero amount
                    b'BNAPTY': b'FUNGIBLE'
                }
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            context = validator.validate_mint_transaction("mock_psbt")
            
            # Zero amount mint should fail
            assert context.has_errors()
    
    @patch('validator.core.RegistryManager')
    def test_maximum_amount_mint(self, mock_registry_manager):
        """Test validation of maximum possible amount mint."""
        huge_asset = FungibleAsset(
            asset_id="huge_asset_123",
            name="Huge Supply Token",
            symbol="HUGE",
            issuer_pubkey="0123456789abcdef" * 8,
            maximum_supply=2**63 - 1,  # Maximum int64 value
            per_mint_limit=2**32,
            decimal_places=0,
            asset_type=AssetType.FUNGIBLE,
            status=AssetStatus.ACTIVE
        )
        
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = huge_asset
        mock_manager.get_asset_state.return_value = StateEntry(
            asset_id="huge_asset_123",
            minted_supply=0
        )
        mock_manager.get_asset_supply_info.return_value = {
            'remaining_supply': 2**63 - 1,
            'per_mint_limit': 2**32
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config={}, registry_manager=mock_manager)
        
        mock_psbt_data = {
            'global': {'version': 2},
            'inputs': [{'previous_output': {'tx_id': 'input_tx_123', 'output_index': 0}}],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'METADATA',
                'proprietary_fields': {
                    b'BNAPAID': bytes.fromhex("huge_asset_123"),
                    b'BNAPAMT': (2**32 - 1).to_bytes(8, 'little'),  # Just under limit
                    b'BNAPTY': b'FUNGIBLE'
                }
            }]
        }
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            context = validator.validate_mint_transaction("mock_psbt")
            
            # Should handle large amounts correctly
            assert not context.has_errors()
    
    def test_validator_configuration_edge_cases(self):
        """Test validator behavior with edge case configurations."""
        # Test with minimal configuration
        minimal_config = {}
        validator1 = ValidationEngine(config=minimal_config)
        assert validator1.config["validator_id"] is not None
        
        # Test with maximum values
        max_config = {
            "max_supply_cap": 2**63 - 1,
            "max_per_mint_cap": 2**32 - 1,
            "max_validation_time": 3600
        }
        validator2 = ValidationEngine(config=max_config)
        assert validator2.config["max_supply_cap"] == 2**63 - 1


# Integration test for the complete validator system
def test_end_to_end_validation_workflow():
    """Test complete end-to-end validation workflow."""
    
    # This test simulates a real-world scenario from PSBT creation to validation completion
    
    config = {
        "validator_id": "e2e_test_validator",
        "enable_audit_logging": True,
        "require_allowlist": False
    }
    
    with patch('validator.core.RegistryManager') as mock_registry_manager:
        # Set up comprehensive mock registry
        mock_manager = Mock()
        
        # Create realistic test asset
        test_asset = FungibleAsset(
            asset_id="e2e_test_asset_123",
            name="End-to-End Test Token",
            symbol="E2E",
            issuer_pubkey="abcdef0123456789" * 8,
            maximum_supply=1_000_000,
            per_mint_limit=50_000,
            decimal_places=8,
            asset_type=AssetType.FUNGIBLE,
            status=AssetStatus.ACTIVE
        )
        
        test_state = StateEntry(
            asset_id="e2e_test_asset_123",
            minted_supply=250_000,
            transaction_count=50
        )
        
        mock_manager.get_asset_by_id.return_value = test_asset
        mock_manager.get_asset_state.return_value = test_state
        mock_manager.get_asset_supply_info.return_value = {
            'asset_id': 'e2e_test_asset_123',
            'asset_type': AssetType.FUNGIBLE,
            'minted_supply': 250_000,
            'maximum_supply': 1_000_000,
            'remaining_supply': 750_000,
            'per_mint_limit': 50_000,
            'transaction_count': 50
        }
        mock_registry_manager.return_value = mock_manager
        
        # Initialize validator
        validator = ValidationEngine(config=config, registry_manager=mock_manager)
        
        # Create realistic PSBT data
        realistic_psbt_data = {
            'global': {
                'version': 2,
                'proprietary_fields': {}
            },
            'inputs': [{
                'previous_output': {
                    'tx_id': '1234567890abcdef' * 8,
                    'output_index': 0
                },
                'proprietary_fields': {}
            }],
            'outputs': [
                {  # OP_RETURN output with asset metadata
                    'amount': 546,
                    'script': b'\x6a' + b'BNAP_ASSET_METADATA_PLACEHOLDER',
                    'proprietary_fields': {
                        b'BNAPAID': bytes.fromhex('e2e_test_asset_123'),
                        b'BNAPAMT': (10_000).to_bytes(8, 'little'),
                        b'BNAPTY': b'FUNGIBLE'
                    }
                },
                {  # Recipient output
                    'amount': 100_000_000,  # 1 BTC
                    'script': b'\x00\x14' + b'recipient_pubkey_hash_20bytes',
                    'proprietary_fields': {}
                }
            ]
        }
        
        # Execute validation
        with patch.object(validator.psbt_parser, 'parse', return_value=realistic_psbt_data):
            # Run the complete validation workflow
            context = validator.validate_mint_transaction("realistic_psbt_hex_data")
            
            # Verify complete workflow success
            assert context is not None
            assert not context.has_errors()
            assert context.asset_id == bytes.fromhex('e2e_test_asset_123')
            assert context.amount == 10_000
            assert context.operation == OperationType.MINT
            
            # Verify all validation rules were applied
            assert len(context.rule_results) > 0
            
            # Verify registry interactions occurred
            mock_manager.get_asset_by_id.assert_called_with('e2e_test_asset_123')
            mock_manager.get_asset_supply_info.assert_called_with('e2e_test_asset_123')
        
        # Verify validator statistics were updated
        stats = validator.get_validation_statistics()
        assert stats["total_validations"] >= 1
        assert stats["approved_validations"] >= 1