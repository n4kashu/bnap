"""
Tests for Validator Core Engine

Tests the main ValidationEngine class and core validation functionality
including context management, rule registration, and basic validation workflows.
"""

import pytest
import json
import time
from unittest.mock import Mock, patch

from validator.core import (
    ValidationEngine,
    ValidationContext,
    ValidationRule,
    ValidationResult,
    ValidationError,
    RuleViolationError,
    ConfigurationError,
    create_default_validator,
    validate_psbt_quick
)
from registry.schema import AssetType
from crypto.commitments import OperationType


class TestValidationContext:
    """Test ValidationContext functionality."""
    
    def test_context_creation(self):
        """Test basic context creation."""
        context = ValidationContext(psbt_data={"test": "data"})
        
        assert context.psbt_data == {"test": "data"}
        assert context.validation_errors == []
        assert context.validation_warnings == []
        assert context.rule_results == {}
        assert not context.has_errors()
    
    def test_error_management(self):
        """Test error addition and tracking."""
        context = ValidationContext(psbt_data={})
        
        assert not context.has_errors()
        
        context.add_error("test_rule", "Test error message")
        
        assert context.has_errors()
        assert len(context.validation_errors) == 1
        assert context.validation_errors[0] == "test_rule: Test error message"
        assert context.rule_results["test_rule"] is False
    
    def test_warning_management(self):
        """Test warning addition."""
        context = ValidationContext(psbt_data={})
        
        context.add_warning("test_rule", "Test warning message")
        
        assert not context.has_errors()  # Warnings don't count as errors
        assert len(context.validation_warnings) == 1
        assert context.validation_warnings[0] == "test_rule: Test warning message"
    
    def test_rule_passing(self):
        """Test rule passing tracking."""
        context = ValidationContext(psbt_data={})
        
        context.mark_rule_passed("test_rule")
        
        assert context.rule_results["test_rule"] is True
        assert not context.has_errors()
    
    def test_summary_generation(self):
        """Test validation summary generation."""
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\x01' * 32,
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000
        )
        
        context.add_error("rule1", "Error 1")
        context.add_warning("rule1", "Warning 1")
        context.mark_rule_passed("rule2")
        
        summary = context.get_summary()
        
        assert summary["asset_id"] == ('01' * 32)
        assert summary["asset_type"] == "fungible"
        assert summary["operation"] == "mint"
        assert summary["amount"] == 1000
        assert len(summary["errors"]) == 1
        assert len(summary["warnings"]) == 1
        assert summary["rules_passed"] == 1
        assert summary["rules_total"] == 2
        assert summary["validation_result"] == "rejected"  # Has errors


class MockValidationRule(ValidationRule):
    """Mock validation rule for testing."""
    
    def __init__(self, name: str, should_pass: bool = True, should_apply: bool = True):
        super().__init__(name, f"Mock rule {name}")
        self.should_pass = should_pass
        self.should_apply = should_apply
    
    def validate(self, context: ValidationContext) -> bool:
        if self.should_pass:
            context.mark_rule_passed(self.name)
            return True
        else:
            context.add_error(self.name, "Mock validation failed")
            return False
    
    def is_applicable(self, context: ValidationContext) -> bool:
        return self.should_apply


class TestValidationRule:
    """Test ValidationRule base class."""
    
    def test_rule_creation(self):
        """Test basic rule creation."""
        rule = MockValidationRule("test_rule")
        
        assert rule.name == "test_rule"
        assert rule.description == "Mock rule test_rule"
        assert rule.enabled is True
    
    def test_rule_validation_pass(self):
        """Test rule validation success."""
        rule = MockValidationRule("pass_rule", should_pass=True)
        context = ValidationContext(psbt_data={})
        
        result = rule.validate(context)
        
        assert result is True
        assert context.rule_results["pass_rule"] is True
        assert not context.has_errors()
    
    def test_rule_validation_fail(self):
        """Test rule validation failure."""
        rule = MockValidationRule("fail_rule", should_pass=False)
        context = ValidationContext(psbt_data={})
        
        result = rule.validate(context)
        
        assert result is False
        assert context.rule_results["fail_rule"] is False
        assert context.has_errors()
    
    def test_rule_applicability(self):
        """Test rule applicability checking."""
        applicable_rule = MockValidationRule("applicable", should_apply=True)
        not_applicable_rule = MockValidationRule("not_applicable", should_apply=False)
        
        context = ValidationContext(psbt_data={})
        
        assert applicable_rule.is_applicable(context) is True
        assert not_applicable_rule.is_applicable(context) is False


class TestValidationEngine:
    """Test ValidationEngine functionality."""
    
    def test_engine_creation(self):
        """Test basic engine creation."""
        engine = ValidationEngine()
        
        assert engine.config is not None
        assert engine.psbt_parser is not None
        assert isinstance(engine.rules, list)
        assert isinstance(engine.rule_registry, dict)
        assert isinstance(engine.signing_keys, dict)
    
    def test_engine_with_config(self):
        """Test engine creation with configuration."""
        config = {
            "validator_id": "test_validator",
            "max_validation_time": 60,
            "enable_audit_logging": False
        }
        
        engine = ValidationEngine(config)
        
        assert engine.config["validator_id"] == "test_validator"
        assert engine.config["max_validation_time"] == 60
        assert engine.config["enable_audit_logging"] is False
    
    def test_rule_registration(self):
        """Test rule registration and unregistration."""
        engine = ValidationEngine()
        initial_rules_count = len(engine.rules)  # Account for default rules
        
        rule = MockValidationRule("test_rule")
        
        # Register rule
        engine.register_rule(rule)
        
        assert len(engine.rules) == initial_rules_count + 1
        assert "test_rule" in engine.rule_registry
        assert engine.rule_registry["test_rule"] == rule
        
        # Unregister rule
        result = engine.unregister_rule("test_rule")
        
        assert result is True
        assert len(engine.rules) == initial_rules_count
        assert "test_rule" not in engine.rule_registry
        
        # Try to unregister non-existent rule
        result = engine.unregister_rule("non_existent")
        assert result is False
    
    @patch('validator.core.PSBTParser')
    def test_validate_mint_transaction_success(self, mock_parser_class):
        """Test successful mint transaction validation."""
        # Mock PSBT parser
        mock_parser = Mock()
        mock_parser.parse.return_value = {"version": 2, "inputs": [], "outputs": []}
        mock_parser_class.return_value = mock_parser
        
        engine = ValidationEngine()
        
        # Add a passing rule
        passing_rule = MockValidationRule("pass_rule", should_pass=True)
        engine.register_rule(passing_rule)
        
        # Validate
        context = engine.validate_mint_transaction("deadbeef")
        
        assert not context.has_errors()
        assert context.rule_results["pass_rule"] is True
        assert engine.validation_stats["approved_validations"] == 1
    
    @patch('validator.core.PSBTParser')
    def test_validate_mint_transaction_failure(self, mock_parser_class):
        """Test failed mint transaction validation."""
        # Mock PSBT parser
        mock_parser = Mock()
        mock_parser.parse.return_value = {"version": 2, "inputs": [], "outputs": []}
        mock_parser_class.return_value = mock_parser
        
        engine = ValidationEngine()
        
        # Add a failing rule
        failing_rule = MockValidationRule("fail_rule", should_pass=False)
        engine.register_rule(failing_rule)
        
        # Validate
        context = engine.validate_mint_transaction("deadbeef")
        
        assert context.has_errors()
        assert context.rule_results["fail_rule"] is False
        assert engine.validation_stats["rejected_validations"] == 1
    
    @patch('validator.core.PSBTParser')
    def test_validate_psbt_parser_error(self, mock_parser_class):
        """Test validation with PSBT parser error."""
        # Mock PSBT parser to raise exception
        mock_parser = Mock()
        mock_parser.parse.side_effect = Exception("Parser error")
        mock_parser_class.return_value = mock_parser
        
        engine = ValidationEngine()
        
        # Validate
        context = engine.validate_mint_transaction("invalid")
        
        assert context.has_errors()
        assert "engine" in [error.split(":")[0] for error in context.validation_errors]
        assert engine.validation_stats["error_validations"] == 1
    
    def test_process_validation_request_success(self):
        """Test successful validation request processing."""
        engine = ValidationEngine()
        
        # Mock successful validation
        with patch.object(engine, 'validate_psbt') as mock_validate:
            mock_context = ValidationContext(psbt_data={})
            mock_context.timestamp = 1234567890
            mock_validate.return_value = mock_context
            
            request = {
                "psbt": "deadbeef",
                "parameters": {"test": "param"}
            }
            
            response = engine.process_validation_request(request)
            
            assert response["status"] == "success"
            assert "validation_result" in response
            assert response["timestamp"] == 1234567890
    
    def test_process_validation_request_error(self):
        """Test validation request processing with error."""
        engine = ValidationEngine()
        
        # Request without PSBT
        request = {"parameters": {}}
        
        response = engine.process_validation_request(request)
        
        assert response["status"] == "error"
        assert "No PSBT provided" in response["error"]
    
    def test_statistics(self):
        """Test statistics tracking."""
        engine = ValidationEngine()
        
        initial_stats = engine.get_statistics()
        assert initial_stats["total_validations"] == 0
        assert initial_stats["approved_validations"] == 0
        assert initial_stats["rejected_validations"] == 0
        assert initial_stats["error_validations"] == 0
        assert initial_stats["registered_rules"] >= 0  # May have default rules
        assert initial_stats["signing_keys"] == 0
    
    def test_config_safety(self):
        """Test configuration safety (no sensitive data exposure)."""
        config = {
            "validator_id": "test",
            "signing_keys": {
                "key1": "deadbeef" * 8,
                "key2": {"private_key": "cafebabe" * 8}
            }
        }
        
        engine = ValidationEngine(config)
        safe_config = engine.get_config()
        
        assert safe_config["validator_id"] == "test"
        assert safe_config["signing_keys"]["key1"] == "***REDACTED***"
        assert safe_config["signing_keys"]["key2"] == "***REDACTED***"
    
    def test_health_check(self):
        """Test health check functionality."""
        engine = ValidationEngine()
        
        health = engine.health_check()
        
        assert health["status"] in ["healthy", "degraded"]
        assert "components" in health
        assert "timestamp" in health
        assert "psbt_parser" in health["components"]
        assert "registry_manager" in health["components"]
        assert "signing_keys" in health["components"]
        assert "validation_rules" in health["components"]


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_create_default_validator(self):
        """Test default validator creation."""
        validator = create_default_validator()
        
        assert isinstance(validator, ValidationEngine)
        assert validator.config["validator_id"] == "bnap_default_validator"
        assert validator.config["enable_audit_logging"] is True
        assert validator.config["max_validation_time"] == 30
    
    def test_create_default_validator_with_config(self):
        """Test default validator creation with config override."""
        config = {"validator_id": "custom_validator"}
        validator = create_default_validator(config)
        
        assert validator.config["validator_id"] == "custom_validator"
        assert validator.config["enable_audit_logging"] is True  # Still has defaults
    
    @patch('validator.core.create_default_validator')
    def test_validate_psbt_quick_success(self, mock_create_validator):
        """Test quick PSBT validation success."""
        # Mock validator and context
        mock_context = ValidationContext(psbt_data={})  # No errors
        mock_validator = Mock()
        mock_validator.validate_psbt.return_value = mock_context
        mock_create_validator.return_value = mock_validator
        
        result = validate_psbt_quick("deadbeef")
        
        assert result is True
    
    @patch('validator.core.create_default_validator')
    def test_validate_psbt_quick_failure(self, mock_create_validator):
        """Test quick PSBT validation failure."""
        # Mock validator and context with errors
        mock_context = ValidationContext(psbt_data={})
        mock_context.add_error("test", "Error")
        mock_validator = Mock()
        mock_validator.validate_psbt.return_value = mock_context
        mock_create_validator.return_value = mock_validator
        
        result = validate_psbt_quick("deadbeef")
        
        assert result is False


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_empty_rules_validation(self):
        """Test validation with no rules registered."""
        engine = ValidationEngine()
        
        with patch.object(engine, '_apply_validation_rules') as mock_apply:
            with patch.object(engine.psbt_parser, 'parse', return_value={}):
                context = engine.validate_mint_transaction("deadbeef")
                
                # Should complete without errors even with no rules
                mock_apply.assert_called_once()
                assert not context.has_errors()
    
    def test_rule_exception_handling(self):
        """Test handling of exceptions in validation rules."""
        class ExceptionRule(ValidationRule):
            def __init__(self):
                super().__init__("exception_rule", "Rule that throws")
            
            def validate(self, context):
                raise Exception("Rule execution error")
        
        engine = ValidationEngine()
        engine.register_rule(ExceptionRule())
        
        with patch.object(engine.psbt_parser, 'parse', return_value={}):
            context = engine.validate_mint_transaction("deadbeef")
            
            assert context.has_errors()
            error_found = any("Rule execution error" in error for error in context.validation_errors)
            assert error_found
    
    def test_registry_manager_failure(self):
        """Test handling of registry manager failures."""
        engine = ValidationEngine()
        
        # Mock registry manager that fails
        engine.registry_manager = Mock()
        engine.registry_manager.get_asset_state.side_effect = Exception("Registry error")
        
        # Mock PSBT parser with basic structure
        with patch.object(engine.psbt_parser, 'parse', return_value={}):
            # Manually set asset_id on context to trigger registry calls
            with patch.object(engine, '_extract_transaction_info') as mock_extract:
                def set_asset_id(context):
                    context.asset_id = b'\x01' * 32  # Set fake asset ID
                mock_extract.side_effect = set_asset_id
                
                context = engine.validate_mint_transaction("deadbeef")
                
                # Should handle registry errors gracefully with warnings
                assert not context.has_errors()  # Registry failures should be warnings, not errors
                warning_found = any("Registry error" in warning for warning in context.validation_warnings)
                assert warning_found


class TestConfigurationValidation:
    """Test configuration validation and loading."""
    
    def test_signing_key_loading_hex(self):
        """Test loading signing keys from hex strings."""
        config = {
            "signing_keys": {
                "key1": "01" * 32  # Valid hex private key
            }
        }
        
        engine = ValidationEngine(config)
        
        assert "key1" in engine.signing_keys
        assert isinstance(engine.signing_keys["key1"], type(engine.signing_keys.get("key1")))
    
    def test_signing_key_loading_dict(self):
        """Test loading signing keys from dictionary config."""
        config = {
            "signing_keys": {
                "key1": {
                    "private_key": "02" * 32,
                    "description": "Test key"
                }
            }
        }
        
        engine = ValidationEngine(config)
        
        assert "key1" in engine.signing_keys
    
    def test_signing_key_loading_invalid(self):
        """Test handling of invalid signing key configurations."""
        config = {
            "signing_keys": {
                "key1": "invalid_hex",
                "key2": {"no_private_key": "data"},
                "key3": 12345  # Invalid type
            }
        }
        
        engine = ValidationEngine(config)
        
        # Should handle invalid keys gracefully
        assert len(engine.signing_keys) == 0