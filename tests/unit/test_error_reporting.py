"""
Tests for BNAP Validator Error Reporting System

Comprehensive tests covering error collection, aggregation, reporting,
and integration with the validator system.
"""

import pytest
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from validator.error_reporting import (
    ErrorReporter,
    ErrorReport,
    ErrorSummary,
    ErrorContext,
    ErrorReportingLevel,
    ReportFormat,
    get_error_reporter,
    configure_error_reporter,
    report_validation_error,
    report_crypto_error,
    report_parsing_error,
    report_system_error
)
from psbt.validator import ValidationSeverity, ValidationCategory, ValidationIssue, ValidationResult
from crypto.exceptions import InvalidKeyError
from psbt.exceptions import PSBTValidationError


class TestErrorReport:
    """Test ErrorReport data class."""
    
    def test_error_report_creation(self):
        """Test basic error report creation."""
        report = ErrorReport(
            report_id="test_001",
            timestamp=1234567890.0,
            context=ErrorContext.VALIDATION,
            component="test_component",
            operation="test_operation",
            severity=ValidationSeverity.ERROR,
            category=ValidationCategory.STRUCTURE,
            code="TEST_ERROR",
            message="Test error message"
        )
        
        assert report.report_id == "test_001"
        assert report.timestamp == 1234567890.0
        assert report.context == ErrorContext.VALIDATION
        assert report.component == "test_component"
        assert report.operation == "test_operation"
        assert report.severity == ValidationSeverity.ERROR
        assert report.category == ValidationCategory.STRUCTURE
        assert report.code == "TEST_ERROR"
        assert report.message == "Test error message"
        assert report.details == {}
        assert report.suggestions == []
    
    def test_error_report_auto_generation(self):
        """Test auto-generation of report ID and timestamp."""
        report = ErrorReport(
            report_id="",
            timestamp=0,
            context=ErrorContext.PARSING,
            component="parser",
            operation="parse",
            severity=ValidationSeverity.WARNING,
            category=ValidationCategory.METADATA,
            code="PARSE_WARNING",
            message="Parse warning"
        )
        
        # ID should be auto-generated
        assert report.report_id.startswith("parsing_")
        assert len(report.report_id) > 10
        
        # Timestamp should be set to current time
        assert report.timestamp > 0
        assert abs(report.timestamp - time.time()) < 1  # Within 1 second


class TestErrorReporter:
    """Test ErrorReporter functionality."""
    
    def test_error_reporter_initialization(self):
        """Test error reporter initialization."""
        reporter = ErrorReporter()
        
        assert reporter.error_reports == []
        assert reporter.validation_results == []
        assert reporter.max_stored_reports == 10000
        assert reporter.auto_save_enabled is False
        assert reporter.reporting_level == ErrorReportingLevel.STANDARD
        assert reporter.stats["reports_created"] == 0
    
    def test_error_reporter_with_config(self):
        """Test error reporter with custom configuration."""
        config = {
            "max_stored_reports": 5000,
            "auto_save_enabled": True,
            "save_path": "/tmp/test_errors",
            "reporting_level": "detailed"
        }
        
        reporter = ErrorReporter(config)
        
        assert reporter.max_stored_reports == 5000
        assert reporter.auto_save_enabled is True
        assert reporter.save_path == "/tmp/test_errors"
        assert reporter.reporting_level == ErrorReportingLevel.DETAILED
    
    def test_report_error_with_string(self):
        """Test reporting an error with string message."""
        reporter = ErrorReporter()
        
        report_id = reporter.report_error(
            context=ErrorContext.VALIDATION,
            component="validator",
            operation="validate_structure",
            error="Invalid PSBT structure",
            severity=ValidationSeverity.ERROR,
            code="INVALID_STRUCTURE"
        )
        
        assert len(report_id) > 0
        assert len(reporter.error_reports) == 1
        
        report = reporter.error_reports[0]
        assert report.report_id == report_id
        assert report.message == "Invalid PSBT structure"
        assert report.code == "INVALID_STRUCTURE"
        assert report.stack_trace is None
        assert reporter.stats["reports_created"] == 1
    
    def test_report_error_with_exception(self):
        """Test reporting an error with exception object."""
        reporter = ErrorReporter()
        
        try:
            raise ValueError("Test exception message")
        except ValueError as e:
            report_id = reporter.report_error(
                context=ErrorContext.CRYPTOGRAPHY,
                component="key_manager",
                operation="validate_key",
                error=e,
                location="key_manager.py:123"
            )
        
        assert len(reporter.error_reports) == 1
        
        report = reporter.error_reports[0]
        assert report.message == "Test exception message"
        assert report.code == "ValueError"
        assert report.stack_trace is not None
        assert "raise ValueError" in report.stack_trace
        assert report.location == "key_manager.py:123"
    
    def test_report_validation_result(self):
        """Test processing validation results."""
        reporter = ErrorReporter()
        
        # Create validation issues
        issues = [
            ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category=ValidationCategory.STRUCTURE,
                code="MISSING_INPUT",
                message="PSBT missing required input",
                location="input[0]"
            ),
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.METADATA,
                code="DEPRECATED_FIELD",
                message="Using deprecated field",
                details={"field": "legacy_field"}
            )
        ]
        
        validation_result = ValidationResult(is_valid=False, issues=issues)
        
        reporter.report_validation_result(validation_result, ErrorContext.VALIDATION, "psbt_validator")
        
        assert len(reporter.validation_results) == 1
        assert len(reporter.error_reports) == 2
        assert reporter.stats["validations_processed"] == 1
        
        # Check converted reports
        error_report = next(r for r in reporter.error_reports if r.code == "MISSING_INPUT")
        assert error_report.message == "PSBT missing required input"
        assert error_report.location == "input[0]"
        assert error_report.component == "psbt_validator"
        
        warning_report = next(r for r in reporter.error_reports if r.code == "DEPRECATED_FIELD")
        assert warning_report.details["field"] == "legacy_field"
    
    def test_error_handlers(self):
        """Test custom error handlers."""
        reporter = ErrorReporter()
        handled_errors = []
        
        def test_handler(report: ErrorReport):
            handled_errors.append(report.code)
        
        def wildcard_handler(report: ErrorReport):
            handled_errors.append(f"wildcard:{report.code}")
        
        # Add handlers
        reporter.add_error_handler("TEST_ERROR", test_handler)
        reporter.add_error_handler("*", wildcard_handler)
        
        # Report errors
        reporter.report_error(
            context=ErrorContext.SYSTEM,
            component="test",
            operation="test",
            error="Test error",
            code="TEST_ERROR"
        )
        
        reporter.report_error(
            context=ErrorContext.SYSTEM,
            component="test",
            operation="test",
            error="Other error",
            code="OTHER_ERROR"
        )
        
        # Check handlers were called
        assert "TEST_ERROR" in handled_errors
        assert "wildcard:TEST_ERROR" in handled_errors
        assert "wildcard:OTHER_ERROR" in handled_errors
        assert len([e for e in handled_errors if e == "OTHER_ERROR"]) == 0  # Specific handler not called
    
    def test_get_error_summary(self):
        """Test error summary generation."""
        reporter = ErrorReporter()
        
        # Add various errors
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Error 1", ValidationSeverity.ERROR)
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Error 2", ValidationSeverity.ERROR)
        reporter.report_error(ErrorContext.CRYPTOGRAPHY, "crypto", "sign", "Warning 1", ValidationSeverity.WARNING)
        reporter.report_error(ErrorContext.PARSING, "parser", "parse", "Critical 1", ValidationSeverity.CRITICAL)
        
        summary = reporter.get_error_summary()
        
        assert summary.total_errors == 4
        assert summary.by_severity[ValidationSeverity.ERROR.value] == 2
        assert summary.by_severity[ValidationSeverity.WARNING.value] == 1
        assert summary.by_severity[ValidationSeverity.CRITICAL.value] == 1
        assert summary.by_context[ErrorContext.VALIDATION.value] == 2
        assert summary.by_context[ErrorContext.CRYPTOGRAPHY.value] == 1
        assert summary.by_context[ErrorContext.PARSING.value] == 1
        assert summary.by_component["validator"] == 2
        assert summary.by_component["crypto"] == 1
        assert summary.by_component["parser"] == 1
    
    def test_get_error_summary_with_filters(self):
        """Test error summary with time and context filters."""
        reporter = ErrorReporter()
        
        base_time = time.time()
        
        # Add errors at different times
        with patch('time.time', return_value=base_time):
            reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Old error", ValidationSeverity.ERROR)
        
        with patch('time.time', return_value=base_time + 100):
            reporter.report_error(ErrorContext.CRYPTOGRAPHY, "crypto", "sign", "New error", ValidationSeverity.ERROR)
        
        # Test time filtering
        summary = reporter.get_error_summary(since=base_time + 50)
        assert summary.total_errors == 1
        assert summary.by_context[ErrorContext.CRYPTOGRAPHY.value] == 1
        
        # Test context filtering
        summary = reporter.get_error_summary(context_filter=ErrorContext.VALIDATION)
        assert summary.total_errors == 1
        assert summary.by_context[ErrorContext.VALIDATION.value] == 1
        
        # Test severity filtering
        reporter.report_error(ErrorContext.PARSING, "parser", "parse", "Warning", ValidationSeverity.WARNING)
        summary = reporter.get_error_summary(severity_filter=ValidationSeverity.WARNING)
        assert summary.total_errors == 1
        assert summary.by_severity[ValidationSeverity.WARNING.value] == 1
    
    def test_get_recent_errors(self):
        """Test getting recent errors."""
        reporter = ErrorReporter()
        
        # Add errors with different timestamps
        base_time = time.time()
        for i in range(10):
            with patch('time.time', return_value=base_time + i):
                reporter.report_error(
                    ErrorContext.VALIDATION,
                    "validator",
                    "validate",
                    f"Error {i}",
                    ValidationSeverity.ERROR,
                    code=f"ERROR_{i}"
                )
        
        # Get recent errors
        recent = reporter.get_recent_errors(count=5)
        assert len(recent) == 5
        
        # Should be in reverse chronological order
        assert recent[0].code == "ERROR_9"
        assert recent[1].code == "ERROR_8"
        assert recent[4].code == "ERROR_5"
        
        # Test severity filtering
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Critical", ValidationSeverity.CRITICAL)
        recent_critical = reporter.get_recent_errors(count=10, severity_filter=ValidationSeverity.CRITICAL)
        assert len(recent_critical) == 1
        assert recent_critical[0].severity == ValidationSeverity.CRITICAL
    
    def test_clear_reports(self):
        """Test clearing reports."""
        reporter = ErrorReporter()
        
        base_time = time.time()
        
        # Add errors at different times
        with patch('time.time', return_value=base_time):
            reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Old error", ValidationSeverity.ERROR)
        
        with patch('time.time', return_value=base_time + 100):
            reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "New error", ValidationSeverity.ERROR)
        
        # Clear all
        cleared = reporter.clear_reports()
        assert cleared == 2
        assert len(reporter.error_reports) == 0
        
        # Add more errors
        with patch('time.time', return_value=base_time):
            reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Old error", ValidationSeverity.ERROR)
        
        with patch('time.time', return_value=base_time + 100):
            reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "New error", ValidationSeverity.ERROR)
        
        # Clear only old errors
        cleared = reporter.clear_reports(older_than=base_time + 50)
        assert cleared == 1
        assert len(reporter.error_reports) == 1
        assert reporter.error_reports[0].message == "New error"
    
    def test_storage_size_management(self):
        """Test automatic storage size management."""
        config = {"max_stored_reports": 5}
        reporter = ErrorReporter(config)
        
        # Add more reports than the limit
        for i in range(10):
            reporter.report_error(
                ErrorContext.VALIDATION,
                "validator",
                "validate",
                f"Error {i}",
                code=f"ERROR_{i}"
            )
        
        # Should only keep the most recent reports
        assert len(reporter.error_reports) == 5
        
        # Check we have the most recent ones
        codes = [r.code for r in reporter.error_reports]
        assert "ERROR_9" in codes
        assert "ERROR_8" in codes
        assert "ERROR_0" not in codes
        assert "ERROR_1" not in codes


class TestReportGeneration:
    """Test report generation in various formats."""
    
    def test_generate_text_report(self):
        """Test text format report generation."""
        reporter = ErrorReporter()
        
        # Add some errors
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Test error", ValidationSeverity.ERROR)
        reporter.report_error(ErrorContext.CRYPTOGRAPHY, "crypto", "sign", "Crypto warning", ValidationSeverity.WARNING)
        
        report = reporter.generate_report(format=ReportFormat.TEXT)
        
        assert "BNAP Validator Error Report" in report
        assert "Total Reports: 2" in report
        assert "SUMMARY STATISTICS" in report
        assert "DETAILED REPORTS" in report
        assert "Test error" in report
        assert "Crypto warning" in report
    
    def test_generate_json_report(self):
        """Test JSON format report generation."""
        reporter = ErrorReporter()
        
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Test error", ValidationSeverity.ERROR)
        
        report_json = reporter.generate_report(format=ReportFormat.JSON)
        data = json.loads(report_json)
        
        assert "metadata" in data
        assert data["metadata"]["total_reports"] == 1
        assert "summary" in data
        assert "reports" in data
        assert len(data["reports"]) == 1
        assert data["reports"][0]["message"] == "Test error"
    
    def test_generate_html_report(self):
        """Test HTML format report generation."""
        reporter = ErrorReporter()
        
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Test error", ValidationSeverity.ERROR)
        
        report = reporter.generate_report(format=ReportFormat.HTML)
        
        assert "<!DOCTYPE html>" in report
        assert "<title>BNAP Validator Error Report</title>" in report
        assert "Test error" in report
        assert "<table>" in report
        assert "class='error'" in report
    
    def test_generate_markdown_report(self):
        """Test Markdown format report generation."""
        reporter = ErrorReporter()
        
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Test error", ValidationSeverity.ERROR)
        
        report = reporter.generate_report(format=ReportFormat.MARKDOWN)
        
        assert "# BNAP Validator Error Report" in report
        assert "## Summary Statistics" in report
        assert "## Error Details" in report
        assert "Test error" in report
        assert "**Severity:** error" in report
    
    def test_generate_csv_report(self):
        """Test CSV format report generation."""
        reporter = ErrorReporter()
        
        reporter.report_error(
            ErrorContext.VALIDATION,
            "validator",
            "validate",
            "Test error",
            ValidationSeverity.ERROR,
            location="test.py:123"
        )
        
        report = reporter.generate_report(format=ReportFormat.CSV)
        
        lines = report.strip().split('\n')
        assert len(lines) == 2  # Header + 1 data row
        
        header = lines[0]
        assert "report_id,timestamp,context,component" in header
        
        data_row = lines[1]
        assert "validation,validator,validate" in data_row
        assert "Test error" in data_row
        assert "test.py:123" in data_row
    
    def test_report_with_filters(self):
        """Test report generation with filters."""
        reporter = ErrorReporter()
        
        base_time = time.time()
        
        # Add errors at different times
        with patch('time.time', return_value=base_time):
            reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Old error", ValidationSeverity.ERROR)
        
        with patch('time.time', return_value=base_time + 100):
            reporter.report_error(ErrorContext.CRYPTOGRAPHY, "crypto", "sign", "New error", ValidationSeverity.ERROR)
        
        # Generate report with time filter
        report = reporter.generate_report(
            format=ReportFormat.TEXT,
            since=base_time + 50
        )
        
        assert "Total Reports: 1" in report
        assert "New error" in report
        assert "Old error" not in report
    
    def test_report_with_different_levels(self):
        """Test report generation with different reporting levels."""
        reporter = ErrorReporter()
        
        # Add errors of different severities
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Critical error", ValidationSeverity.CRITICAL)
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Regular error", ValidationSeverity.ERROR)
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Warning", ValidationSeverity.WARNING)
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Info", ValidationSeverity.INFO)
        
        # Test minimal level (only critical)
        report = reporter.generate_report(level=ErrorReportingLevel.MINIMAL)
        assert "Total Reports: 1" in report
        assert "Critical error" in report
        assert "Regular error" not in report
        
        # Test standard level (critical, error, warning)
        report = reporter.generate_report(level=ErrorReportingLevel.STANDARD)
        assert "Total Reports: 3" in report
        assert "Critical error" in report
        assert "Regular error" in report
        assert "Warning" in report
        assert "Info" not in report
        
        # Test detailed level (all)
        report = reporter.generate_report(level=ErrorReportingLevel.DETAILED)
        assert "Total Reports: 4" in report


class TestReportExport:
    """Test report export functionality."""
    
    def test_export_reports_json(self):
        """Test exporting reports to JSON file."""
        reporter = ErrorReporter()
        
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Test error", ValidationSeverity.ERROR)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            reporter.export_reports(tmp_path, ReportFormat.JSON)
            
            # Verify file was created and contains data
            with open(tmp_path, 'r') as f:
                data = json.load(f)
            
            assert len(data) == 1
            assert data[0]["message"] == "Test error"
            assert data[0]["component"] == "validator"
        finally:
            Path(tmp_path).unlink()
    
    def test_export_reports_text(self):
        """Test exporting reports to text file."""
        reporter = ErrorReporter()
        
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Test error", ValidationSeverity.ERROR)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            reporter.export_reports(tmp_path, ReportFormat.TEXT)
            
            # Verify file was created and contains data
            with open(tmp_path, 'r') as f:
                content = f.read()
            
            assert "BNAP Validator Error Report" in content
            assert "Test error" in content
        finally:
            Path(tmp_path).unlink()
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_auto_save_functionality(self, mock_json_dump, mock_file):
        """Test auto-save functionality."""
        config = {
            "auto_save_enabled": True,
            "save_path": "/tmp/test_reports"
        }
        
        with patch('pathlib.Path.mkdir'):
            reporter = ErrorReporter(config)
        
        # Report an error (should trigger auto-save)
        report_id = reporter.report_error(
            ErrorContext.VALIDATION,
            "validator",
            "validate",
            "Test error",
            ValidationSeverity.ERROR
        )
        
        # Verify file operations
        expected_filename = f"error_report_{report_id}.json"
        mock_file.assert_called_with(Path("/tmp/test_reports") / expected_filename, 'w')
        mock_json_dump.assert_called_once()
        
        assert reporter.stats["reports_saved"] == 1


class TestGlobalReporter:
    """Test global error reporter functionality."""
    
    def test_get_global_error_reporter(self):
        """Test getting global error reporter instance."""
        # Reset global instance
        import validator.error_reporting
        validator.error_reporting._global_error_reporter = None
        
        reporter1 = get_error_reporter()
        reporter2 = get_error_reporter()
        
        # Should return same instance
        assert reporter1 is reporter2
        assert isinstance(reporter1, ErrorReporter)
    
    def test_configure_global_error_reporter(self):
        """Test configuring global error reporter."""
        config = {"max_stored_reports": 1000}
        
        reporter = configure_error_reporter(config)
        
        assert reporter.max_stored_reports == 1000
        assert get_error_reporter() is reporter


class TestConvenienceFunctions:
    """Test convenience functions for common error patterns."""
    
    def test_report_validation_error(self):
        """Test validation error reporting function."""
        # Reset global reporter
        import validator.error_reporting
        validator.error_reporting._global_error_reporter = None
        
        report_id = report_validation_error("psbt_validator", "Invalid PSBT structure")
        
        reporter = get_error_reporter()
        assert len(reporter.error_reports) == 1
        
        report = reporter.error_reports[0]
        assert report.report_id == report_id
        assert report.context == ErrorContext.VALIDATION
        assert report.component == "psbt_validator"
        assert report.message == "Invalid PSBT structure"
        assert report.severity == ValidationSeverity.ERROR
    
    def test_report_crypto_error(self):
        """Test crypto error reporting function."""
        # Reset global reporter
        import validator.error_reporting
        validator.error_reporting._global_error_reporter = None
        
        crypto_error = InvalidKeyError("Invalid private key format")
        report_id = report_crypto_error("key_manager", "validate_key", crypto_error)
        
        reporter = get_error_reporter()
        assert len(reporter.error_reports) == 1
        
        report = reporter.error_reports[0]
        assert report.context == ErrorContext.CRYPTOGRAPHY
        assert report.component == "key_manager"
        assert report.operation == "validate_key"
        assert report.message == "Invalid private key format"
        assert report.code == "InvalidKeyError"
    
    def test_report_parsing_error(self):
        """Test parsing error reporting function."""
        # Reset global reporter
        import validator.error_reporting
        validator.error_reporting._global_error_reporter = None
        
        report_id = report_parsing_error(
            "psbt_parser",
            "Invalid PSBT magic bytes",
            location="parser.py:45"
        )
        
        reporter = get_error_reporter()
        assert len(reporter.error_reports) == 1
        
        report = reporter.error_reports[0]
        assert report.context == ErrorContext.PARSING
        assert report.component == "psbt_parser"
        assert report.operation == "parse"
        assert report.message == "Invalid PSBT magic bytes"
        assert report.location == "parser.py:45"
    
    def test_report_system_error(self):
        """Test system error reporting function."""
        # Reset global reporter
        import validator.error_reporting
        validator.error_reporting._global_error_reporter = None
        
        system_error = OSError("File not found")
        report_id = report_system_error("file_manager", "load_config", system_error)
        
        reporter = get_error_reporter()
        assert len(reporter.error_reports) == 1
        
        report = reporter.error_reports[0]
        assert report.context == ErrorContext.SYSTEM
        assert report.component == "file_manager"
        assert report.operation == "load_config"
        assert report.message == "File not found"
        assert report.severity == ValidationSeverity.CRITICAL


class TestErrorReportingIntegration:
    """Test integration with existing validator components."""
    
    def test_integration_with_validation_result(self):
        """Test integration with ValidationResult from PSBT validator."""
        reporter = ErrorReporter()
        
        # Create a validation result similar to what PSBTValidator produces
        issues = [
            ValidationIssue(
                severity=ValidationSeverity.ERROR,
                category=ValidationCategory.STRUCTURE,
                code="MISSING_GLOBAL",
                message="PSBT missing global data section",
                location="global"
            ),
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                category=ValidationCategory.METADATA,
                code="HIGH_VERSION",
                message="PSBT version 3 is higher than standard",
                details={"version": 3}
            )
        ]
        
        validation_result = ValidationResult(is_valid=False, issues=issues)
        
        # Process the validation result
        reporter.report_validation_result(
            validation_result,
            ErrorContext.VALIDATION,
            "psbt_validator"
        )
        
        # Verify reports were created
        assert len(reporter.error_reports) == 2
        assert len(reporter.validation_results) == 1
        
        # Check error report
        error_report = next(r for r in reporter.error_reports if r.code == "MISSING_GLOBAL")
        assert error_report.severity == ValidationSeverity.ERROR
        assert error_report.category == ValidationCategory.STRUCTURE
        assert error_report.location == "global"
        
        # Check warning report
        warning_report = next(r for r in reporter.error_reports if r.code == "HIGH_VERSION")
        assert warning_report.severity == ValidationSeverity.WARNING
        assert warning_report.details["version"] == 3
    
    def test_statistics_tracking(self):
        """Test that statistics are properly tracked."""
        reporter = ErrorReporter()
        
        initial_stats = reporter.get_statistics()
        assert initial_stats["reports_created"] == 0
        assert initial_stats["validations_processed"] == 0
        assert initial_stats["stored_reports"] == 0
        
        # Add some errors and validations
        reporter.report_error(ErrorContext.VALIDATION, "validator", "validate", "Error 1", ValidationSeverity.ERROR)
        reporter.report_error(ErrorContext.CRYPTOGRAPHY, "crypto", "sign", "Error 2", ValidationSeverity.WARNING)
        
        validation_result = ValidationResult(is_valid=True, issues=[])
        reporter.report_validation_result(validation_result)
        
        updated_stats = reporter.get_statistics()
        assert updated_stats["reports_created"] == 2
        assert updated_stats["validations_processed"] == 1
        assert updated_stats["stored_reports"] == 2
        assert updated_stats["uptime_seconds"] > 0
        assert "config" in updated_stats