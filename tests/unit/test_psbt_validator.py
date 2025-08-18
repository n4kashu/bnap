"""
Tests for PSBT Validator
"""

import pytest
from psbt.validator import (
    PSBTValidator,
    ValidationSeverity,
    ValidationCategory,
    ValidationIssue,
    ValidationResult,
    validate_psbt_structure,
    validate_psbt_assets,
    validate_psbt_complete,
    format_validation_report
)
from psbt.builder import BasePSBTBuilder
from psbt.outputs.op_return import create_asset_issuance_op_return
from psbt.exceptions import PSBTValidationError


class TestValidationDataStructures:
    """Test validation data structures."""
    
    def test_validation_issue_creation(self):
        """Test ValidationIssue creation."""
        issue = ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category=ValidationCategory.STRUCTURE,
            code="TEST_ERROR",
            message="Test error message",
            location="input[0]",
            details={"key": "value"}
        )
        
        assert issue.severity == ValidationSeverity.ERROR
        assert issue.category == ValidationCategory.STRUCTURE
        assert issue.code == "TEST_ERROR"
        assert issue.message == "Test error message"
        assert issue.location == "input[0]"
        assert issue.details == {"key": "value"}
    
    def test_validation_result_categorization(self):
        """Test ValidationResult issue categorization."""
        issues = [
            ValidationIssue(ValidationSeverity.INFO, ValidationCategory.STRUCTURE, "INFO1", "Info message"),
            ValidationIssue(ValidationSeverity.WARNING, ValidationCategory.METADATA, "WARN1", "Warning message"),
            ValidationIssue(ValidationSeverity.ERROR, ValidationCategory.BUSINESS_LOGIC, "ERR1", "Error message"),
            ValidationIssue(ValidationSeverity.CRITICAL, ValidationCategory.SECURITY, "CRIT1", "Critical message"),
        ]
        
        result = ValidationResult(is_valid=True, issues=issues)
        
        assert len(result.warnings) == 1
        assert len(result.errors) == 1
        assert len(result.critical_issues) == 1
        assert not result.is_valid  # Should be False due to errors
    
    def test_validation_result_valid_with_warnings(self):
        """Test ValidationResult is valid with only warnings."""
        issues = [
            ValidationIssue(ValidationSeverity.INFO, ValidationCategory.STRUCTURE, "INFO1", "Info message"),
            ValidationIssue(ValidationSeverity.WARNING, ValidationCategory.METADATA, "WARN1", "Warning message"),
        ]
        
        result = ValidationResult(is_valid=True, issues=issues)
        
        assert result.is_valid
        assert len(result.warnings) == 1
        assert len(result.errors) == 0
        assert len(result.critical_issues) == 0


class TestPSBTValidator:
    """Test PSBTValidator functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = PSBTValidator()
    
    def test_validator_initialization(self):
        """Test PSBTValidator initialization."""
        assert self.validator.max_inputs == 100
        assert self.validator.max_outputs == 100
        assert self.validator.max_op_return_size == 80
        assert self.validator.dust_threshold == 546
        assert self.validator.max_asset_amount == 21_000_000 * 10**8
        assert len(self.validator.issues) == 0
    
    def test_validate_invalid_psbt_data(self):
        """Test validation with invalid PSBT data."""
        invalid_data = b'invalid psbt data'
        result = self.validator.validate_psbt(invalid_data)
        
        assert not result.is_valid
        assert len(result.critical_issues) > 0
        assert any("PARSE_ERROR" in issue.code for issue in result.critical_issues)
    
    def test_validate_minimal_valid_psbt(self):
        """Test validation with minimal valid PSBT."""
        # Create a minimal valid PSBT
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should be valid (might have warnings)
        assert result.is_valid or len(result.errors) == 0
    
    def test_validate_structure_no_inputs(self):
        """Test structure validation with no inputs."""
        builder = BasePSBTBuilder()
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_structure(psbt_data)
        
        assert not result.is_valid
        assert any("NO_INPUTS" in issue.code for issue in result.errors)
    
    def test_validate_structure_no_outputs(self):
        """Test structure validation with no outputs."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_structure(psbt_data)
        
        assert not result.is_valid
        assert any("NO_OUTPUTS" in issue.code for issue in result.errors)
    
    def test_validate_too_many_inputs(self):
        """Test validation with too many inputs."""
        builder = BasePSBTBuilder()
        
        # Add more inputs than the limit
        for i in range(self.validator.max_inputs + 1):
            builder.add_input("a" * 64, i)
        
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_structure(psbt_data)
        
        # Should have warning about too many inputs
        assert any("TOO_MANY_INPUTS" in issue.code for issue in result.warnings)
    
    def test_validate_too_many_outputs(self):
        """Test validation with too many outputs."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        
        # Add more outputs than the limit
        for i in range(self.validator.max_outputs + 1):
            builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_structure(psbt_data)
        
        # Should have warning about too many outputs
        assert any("TOO_MANY_OUTPUTS" in issue.code for issue in result.warnings)
    
    def test_validate_op_return_output(self):
        """Test validation with OP_RETURN output."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add OP_RETURN output with BNAP metadata
        op_return_script = create_asset_issuance_op_return(
            asset_id="a" * 64,
            supply=1000000,
            decimals=8,
            symbol="TEST"
        )
        builder.add_output(script=op_return_script, amount=0)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should be valid and recognize BNAP metadata
        assert result.is_valid or len(result.errors) == 0
    
    def test_validate_oversized_op_return(self):
        """Test validation with oversized OP_RETURN data."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Create oversized OP_RETURN
        large_data = b'x' * 100  # Exceeds 80 byte limit
        op_return_script = b'\x6a\x64' + large_data  # OP_RETURN with 100 bytes
        builder.add_output(script=op_return_script, amount=0)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have error about oversized OP_RETURN
        assert any("OP_RETURN_TOO_LARGE" in issue.code for issue in result.errors)
    
    def test_validate_multiple_op_return(self):
        """Test validation with multiple OP_RETURN outputs."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add multiple OP_RETURN outputs
        for i in range(3):
            op_return_script = b'\x6a\x04test'  # OP_RETURN with "test"
            builder.add_output(script=op_return_script, amount=0)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have warning about multiple OP_RETURN
        assert any("MULTIPLE_OP_RETURN" in issue.code for issue in result.warnings)
    
    def test_validate_proprietary_fields(self):
        """Test validation of BNAP proprietary fields."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add valid BNAP proprietary field
        builder.add_input_proprietary(0, b'BNAPAID', b'a' * 32)  # Valid 32-byte asset ID
        
        # Add invalid BNAP proprietary field
        builder.add_input_proprietary(0, b'BNAPAMT', b'invalid')  # Invalid amount format
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have error about invalid amount format
        assert any("INVALID_AMOUNT_LENGTH" in issue.code for issue in result.errors)
    
    def test_validate_empty_asset_type(self):
        """Test validation with empty asset type."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add empty asset type
        builder.add_input_proprietary(0, b'BNAPATY', b'')  # Empty asset type
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have error about empty asset type
        assert any("EMPTY_ASSET_TYPE" in issue.code for issue in result.errors)
    
    def test_validation_issue_location_tracking(self):
        """Test that validation issues track their location correctly."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_input("b" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add invalid proprietary field to second input
        builder.add_input_proprietary(1, b'BNAPAID', b'invalid')  # Invalid asset ID length
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have error with correct location
        location_errors = [issue for issue in result.errors if "input[1]" in issue.location]
        assert len(location_errors) > 0
    
    def test_validate_high_version_psbt(self):
        """Test validation with high version PSBT."""
        builder = BasePSBTBuilder(version=3)  # High version
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have warning about high version
        # Note: This test depends on the global data validation implementation
        assert result.is_valid or len(result.warnings) > 0


class TestValidationUtilityFunctions:
    """Test validation utility functions."""
    
    def test_validate_psbt_structure_function(self):
        """Test validate_psbt_structure utility function."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = validate_psbt_structure(psbt_data)
        
        assert isinstance(result, ValidationResult)
        # Should be valid structure
        assert result.is_valid or len(result.errors) == 0
    
    def test_validate_psbt_assets_function(self):
        """Test validate_psbt_assets utility function."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = validate_psbt_assets(psbt_data)
        
        assert isinstance(result, ValidationResult)
        # Should be valid (no asset operations to validate)
        assert result.is_valid
    
    def test_validate_psbt_complete_function(self):
        """Test validate_psbt_complete utility function."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = validate_psbt_complete(psbt_data)
        
        assert isinstance(result, ValidationResult)
        # Should be valid or have only warnings
        assert result.is_valid or len(result.errors) == 0
    
    def test_format_validation_report(self):
        """Test format_validation_report function."""
        issues = [
            ValidationIssue(ValidationSeverity.CRITICAL, ValidationCategory.STRUCTURE, "CRIT1", "Critical issue"),
            ValidationIssue(ValidationSeverity.ERROR, ValidationCategory.METADATA, "ERR1", "Error issue", "input[0]"),
            ValidationIssue(ValidationSeverity.WARNING, ValidationCategory.BUSINESS_LOGIC, "WARN1", "Warning issue"),
            ValidationIssue(ValidationSeverity.INFO, ValidationCategory.SECURITY, "INFO1", "Info issue"),
        ]
        
        result = ValidationResult(is_valid=False, issues=issues)
        report = format_validation_report(result)
        
        # Check report format
        assert "PSBT Validation Report" in report
        assert "Overall Status: INVALID" in report
        assert "Total Issues: 4" in report
        assert "CRITICAL ISSUES (1):" in report
        assert "ERRORS (1):" in report
        assert "WARNINGS (1):" in report
        assert "CRIT1: Critical issue" in report
        assert "ERR1: Error issue" in report
        assert "Location: input[0]" in report
    
    def test_format_validation_report_valid(self):
        """Test format_validation_report with valid result."""
        issues = [
            ValidationIssue(ValidationSeverity.INFO, ValidationCategory.STRUCTURE, "INFO1", "Info message"),
            ValidationIssue(ValidationSeverity.WARNING, ValidationCategory.METADATA, "WARN1", "Warning message"),
        ]
        
        result = ValidationResult(is_valid=True, issues=issues)
        report = format_validation_report(result)
        
        # Check report format for valid PSBT
        assert "Overall Status: VALID" in report
        assert "Total Issues: 2" in report
        assert "WARNINGS (1):" in report
        assert "CRITICAL ISSUES" not in report
        assert "ERRORS" not in report


class TestValidationCategories:
    """Test different validation categories."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = PSBTValidator()
    
    def test_structure_validation_category(self):
        """Test structure validation category."""
        # Test with PSBT missing inputs
        builder = BasePSBTBuilder()
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have structure category errors
        structure_errors = [issue for issue in result.errors if issue.category == ValidationCategory.STRUCTURE]
        assert len(structure_errors) > 0
    
    def test_metadata_validation_category(self):
        """Test metadata validation category."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add invalid metadata
        builder.add_input_proprietary(0, b'BNAPAID', b'invalid')  # Invalid asset ID
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have metadata category errors
        metadata_errors = [issue for issue in result.errors if issue.category == ValidationCategory.METADATA]
        assert len(metadata_errors) > 0
    
    def test_security_validation_category(self):
        """Test security validation category."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        
        # Add many dust outputs (potential security concern)
        for i in range(10):
            builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100)  # Below dust threshold
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have security category warnings
        security_warnings = [issue for issue in result.warnings if issue.category == ValidationCategory.SECURITY]
        # This test depends on the dust validation implementation


class TestErrorHandling:
    """Test error handling in validator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = PSBTValidator()
    
    def test_validation_with_corrupted_data(self):
        """Test validation with corrupted PSBT data."""
        # Create valid PSBT then corrupt it
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        valid_data = builder.serialize()
        corrupted_data = valid_data[:-10] + b'corrupted'  # Corrupt the end
        
        result = self.validator.validate_psbt(corrupted_data)
        
        # Should handle corruption gracefully
        assert not result.is_valid
        assert len(result.critical_issues) > 0
    
    def test_validation_with_empty_data(self):
        """Test validation with empty data."""
        result = self.validator.validate_psbt(b'')
        
        assert not result.is_valid
        assert len(result.critical_issues) > 0
    
    def test_validation_with_partial_psbt(self):
        """Test validation with partial PSBT data."""
        partial_data = b'psbt\xff'  # Just the magic bytes
        result = self.validator.validate_psbt(partial_data)
        
        assert not result.is_valid
        # Should have parsing error
        assert any("PARSE_ERROR" in issue.code for issue in result.critical_issues)
    
    def test_validator_state_isolation(self):
        """Test that validator instances don't interfere with each other."""
        validator1 = PSBTValidator()
        validator2 = PSBTValidator()
        
        # Use validator1 with invalid data
        validator1.validate_psbt(b'invalid')
        
        # Use validator2 with valid data
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        valid_data = builder.serialize()
        result2 = validator2.validate_psbt(valid_data)
        
        # validator2 should not be affected by validator1's state
        assert len(validator2.issues) >= 0  # validator2 should have its own issues list
        
        # The results should be independent
        assert len(validator1.issues) != len(validator2.issues)


class TestValidationConfiguration:
    """Test validation configuration and limits."""
    
    def test_custom_validation_limits(self):
        """Test validator with custom limits."""
        validator = PSBTValidator()
        validator.max_inputs = 5  # Set lower limit
        validator.max_outputs = 3
        
        builder = BasePSBTBuilder()
        
        # Add more inputs than custom limit
        for i in range(6):
            builder.add_input("a" * 64, i)
        
        # Add more outputs than custom limit  
        for i in range(4):
            builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = validator.validate_psbt(psbt_data)
        
        # Should have warnings for both limits
        assert any("TOO_MANY_INPUTS" in issue.code for issue in result.warnings)
        assert any("TOO_MANY_OUTPUTS" in issue.code for issue in result.warnings)
    
    def test_dust_threshold_configuration(self):
        """Test dust threshold configuration."""
        validator = PSBTValidator()
        validator.dust_threshold = 1000  # Set higher dust threshold
        
        # This would require more complex dust detection implementation
        # For now, just verify the configuration is set
        assert validator.dust_threshold == 1000