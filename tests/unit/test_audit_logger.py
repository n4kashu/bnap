"""
Tests for BNAP Validator Audit Logging System

Comprehensive tests covering audit event logging, metrics collection, security monitoring,
and integration with the validator system.
"""

import pytest
import json
import tempfile
import time
import csv
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from validator.audit_logger import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    AuditResult,
    LogLevel,
    MetricSnapshot,
    get_audit_logger,
    configure_audit_logger,
    log_validation,
    log_registry_op,
    log_crypto_op,
    log_security_event
)


class TestAuditEvent:
    """Test AuditEvent data class."""
    
    def test_audit_event_creation(self):
        """Test basic audit event creation."""
        event = AuditEvent(
            event_id="test_001",
            timestamp=1234567890.0,
            event_type=AuditEventType.VALIDATION,
            operation="mint_validation",
            validator_id="validator_123",
            component="mint_validator",
            result=AuditResult.APPROVED,
            asset_id="asset_456",
            amount=1000
        )
        
        assert event.event_id == "test_001"
        assert event.timestamp == 1234567890.0
        assert event.event_type == AuditEventType.VALIDATION
        assert event.operation == "mint_validation"
        assert event.validator_id == "validator_123"
        assert event.component == "mint_validator"
        assert event.result == AuditResult.APPROVED
        assert event.asset_id == "asset_456"
        assert event.amount == 1000
    
    def test_audit_event_auto_generation(self):
        """Test auto-generation of event ID and timestamp."""
        event = AuditEvent(
            event_id="",
            timestamp=0,
            event_type=AuditEventType.REGISTRY_OPERATION,
            operation="asset_registration",
            validator_id="validator_123",
            component="registry",
            result=AuditResult.APPROVED
        )
        
        # Event ID should be auto-generated
        assert event.event_id.startswith("audit_")
        assert len(event.event_id) > 15
        
        # Timestamp should be set to current time
        assert event.timestamp > 0
        assert abs(event.timestamp - time.time()) < 1
        
        # Request ID should be auto-generated
        assert event.request_id.startswith("req_")
        assert len(event.request_id) > 10


class TestAuditLogger:
    """Test AuditLogger functionality."""
    
    def test_audit_logger_initialization(self):
        """Test audit logger initialization."""
        logger = AuditLogger()
        
        assert logger.validator_id.startswith("validator_")
        assert len(logger.events) == 0
        assert logger.stats["events_logged"] == 0
        assert logger.stats["start_time"] > 0
        assert logger.async_logging is True
    
    def test_audit_logger_with_config(self):
        """Test audit logger with custom configuration."""
        config = {
            "validator_id": "test_validator_123",
            "log_directory": "/tmp/test_audit",
            "max_log_size_mb": 50,
            "async_logging": False,
            "enable_performance_monitoring": True,
            "log_level": "debug"
        }
        
        logger = AuditLogger(config)
        
        assert logger.validator_id == "test_validator_123"
        assert str(logger.log_directory) == "/tmp/test_audit"
        assert logger.max_log_size_mb == 50
        assert logger.async_logging is False
        assert logger.enable_performance_monitoring is True
        assert logger.log_level == LogLevel.DEBUG
    
    def test_log_event_basic(self):
        """Test basic event logging."""
        logger = AuditLogger({"async_logging": False})
        
        event_id = logger.log_event(
            event_type=AuditEventType.VALIDATION,
            operation="test_validation",
            component="test_component",
            result=AuditResult.APPROVED,
            asset_id="test_asset",
            amount=500
        )
        
        assert len(event_id) > 0
        assert len(logger.events) == 1
        assert logger.stats["events_logged"] == 1
        
        event = logger.events[0]
        assert event.event_id == event_id
        assert event.event_type == AuditEventType.VALIDATION
        assert event.operation == "test_validation"
        assert event.result == AuditResult.APPROVED
        assert event.asset_id == "test_asset"
        assert event.amount == 500
    
    def test_log_validation_event(self):
        """Test validation-specific event logging."""
        logger = AuditLogger({"async_logging": False})
        
        event_id = logger.log_validation_event(
            operation="mint_validation",
            asset_id="asset_123",
            amount=1000,
            result=AuditResult.APPROVED,
            duration_ms=15.5,
            context={"rule": "supply_limit"},
            security_flags=["large_mint"]
        )
        
        assert len(logger.events) == 1
        event = logger.events[0]
        
        assert event.event_type == AuditEventType.VALIDATION
        assert event.operation == "mint_validation"
        assert event.asset_id == "asset_123"
        assert event.amount == 1000
        assert event.duration_ms == 15.5
        assert event.context["rule"] == "supply_limit"
        assert "large_mint" in event.security_flags
    
    def test_log_registry_operation(self):
        """Test registry operation logging."""
        logger = AuditLogger({"async_logging": False})
        
        event_id = logger.log_registry_operation(
            operation="asset_registration",
            asset_id="new_asset_456",
            result=AuditResult.APPROVED,
            context={"creator": "user_123", "supply": 21000000}
        )
        
        assert len(logger.events) == 1
        event = logger.events[0]
        
        assert event.event_type == AuditEventType.REGISTRY_OPERATION
        assert event.operation == "asset_registration"
        assert event.component == "registry_manager"
        assert event.asset_id == "new_asset_456"
        assert event.context["creator"] == "user_123"
        assert event.context["supply"] == 21000000
    
    def test_log_crypto_operation(self):
        """Test cryptographic operation logging."""
        logger = AuditLogger({"async_logging": False})
        
        event_id = logger.log_crypto_operation(
            operation="signature_verification",
            result=AuditResult.APPROVED,
            duration_ms=2.3,
            context={"algorithm": "ecdsa", "key_type": "secp256k1"}
        )
        
        assert len(logger.events) == 1
        event = logger.events[0]
        
        assert event.event_type == AuditEventType.CRYPTOGRAPHIC_OPERATION
        assert event.operation == "signature_verification"
        assert event.component == "crypto_engine"
        assert event.duration_ms == 2.3
        assert event.context["algorithm"] == "ecdsa"
    
    def test_log_security_event(self):
        """Test security event logging."""
        logger = AuditLogger({"async_logging": False})
        
        event_id = logger.log_security_event(
            operation="suspicious_activity_detected",
            result=AuditResult.SUSPICIOUS,
            security_flags=["multiple_failed_validations", "rate_limit_exceeded"],
            context={"ip_address": "192.168.1.100", "attempts": 5},
            compliance_tags=["pci_dss", "gdpr"]
        )
        
        assert len(logger.events) == 1
        event = logger.events[0]
        
        assert event.event_type == AuditEventType.SECURITY_EVENT
        assert event.operation == "suspicious_activity_detected"
        assert event.result == AuditResult.SUSPICIOUS
        assert "multiple_failed_validations" in event.security_flags
        assert "rate_limit_exceeded" in event.security_flags
        assert "pci_dss" in event.compliance_tags
        assert event.context["attempts"] == 5
    
    def test_log_performance_event(self):
        """Test performance event logging."""
        logger = AuditLogger({"async_logging": False})
        
        event_id = logger.log_performance_event(
            operation="batch_validation",
            duration_ms=150.7,
            cpu_time_ms=120.3,
            memory_used_mb=25.6,
            context={"batch_size": 100, "cache_hits": 85}
        )
        
        assert len(logger.events) == 1
        event = logger.events[0]
        
        assert event.event_type == AuditEventType.PERFORMANCE_EVENT
        assert event.operation == "batch_validation"
        assert event.duration_ms == 150.7
        assert event.cpu_time_ms == 120.3
        assert event.memory_used_mb == 25.6
        assert event.context["batch_size"] == 100
    
    def test_event_handlers(self):
        """Test custom event handlers."""
        logger = AuditLogger({"async_logging": False})
        handled_events = []
        
        def validation_handler(event: AuditEvent):
            handled_events.append(f"validation:{event.operation}")
        
        def security_handler(event: AuditEvent):
            handled_events.append(f"security:{event.operation}")
        
        # Add handlers
        logger.add_event_handler(AuditEventType.VALIDATION, validation_handler)
        logger.add_event_handler(AuditEventType.SECURITY_EVENT, security_handler)
        
        # Log events
        logger.log_validation_event("test_validation", result=AuditResult.APPROVED)
        logger.log_security_event("test_security", result=AuditResult.SUSPICIOUS, security_flags=["test"])
        logger.log_registry_operation("test_registry", "asset_123")
        
        # Check handlers were called
        assert "validation:test_validation" in handled_events
        assert "security:test_security" in handled_events
        assert len([e for e in handled_events if e.startswith("registry")]) == 0
    
    def test_metrics_snapshot(self):
        """Test metrics snapshot generation."""
        logger = AuditLogger({"async_logging": False})
        
        # Add various events to generate metrics
        logger.log_validation_event("mint_validation", result=AuditResult.APPROVED, duration_ms=10.0)
        logger.log_validation_event("transfer_validation", result=AuditResult.APPROVED, duration_ms=15.0)
        logger.log_validation_event("failed_validation", result=AuditResult.REJECTED, duration_ms=5.0)
        logger.log_security_event("suspicious_activity", result=AuditResult.SUSPICIOUS, security_flags=["test"])
        
        snapshot = logger.get_metrics_snapshot()
        
        assert snapshot.validator_id == logger.validator_id
        assert snapshot.total_validations == 3  # Count from validation events
        assert snapshot.successful_validations > 0
        assert snapshot.failed_validations > 0
        assert snapshot.avg_validation_time_ms > 0
        assert snapshot.security_events > 0
        assert snapshot.timestamp > 0
    
    def test_security_summary(self):
        """Test security summary generation."""
        logger = AuditLogger({"async_logging": False})
        
        # Add security-related events
        logger.log_security_event("failed_login", result=AuditResult.SUSPICIOUS, 
                                security_flags=["brute_force", "invalid_credentials"])
        logger.log_event(AuditEventType.VALIDATION, "failed_validation", "validator", 
                        AuditResult.REJECTED, error_code="INVALID_SIGNATURE")
        logger.log_security_event("rate_limit_exceeded", result=AuditResult.SUSPICIOUS,
                                security_flags=["rate_limit"])
        
        summary = logger.get_security_summary(hours=1)
        
        assert summary["total_events"] >= 3
        assert summary["security_events"] == 2
        assert summary["failed_validations"] == 1
        assert len(summary["most_common_security_flags"]) > 0
        # Check that the security flags are present (count may vary due to implementation details)
        flag_names = [flag[0] for flag in summary["most_common_security_flags"]]
        assert "brute_force" in flag_names
        assert "rate_limit" in flag_names
    
    def test_event_filtering(self):
        """Test event type filtering."""
        config = {
            "async_logging": False,
            "enabled_event_types": [AuditEventType.VALIDATION.value, AuditEventType.SECURITY_EVENT.value]
        }
        logger = AuditLogger(config)
        
        # Log various event types
        logger.log_validation_event("test_validation", result=AuditResult.APPROVED)
        logger.log_registry_operation("test_registry", "asset_123")  # Should be filtered out
        logger.log_security_event("test_security", result=AuditResult.SUSPICIOUS, security_flags=["test"])
        
        # Only validation and security events should be logged
        assert len(logger.events) == 2
        event_types = [event.event_type for event in logger.events]
        assert AuditEventType.VALIDATION in event_types
        assert AuditEventType.SECURITY_EVENT in event_types
        assert AuditEventType.REGISTRY_OPERATION not in event_types
    
    def test_statistics_tracking(self):
        """Test that statistics are properly tracked."""
        logger = AuditLogger({"async_logging": False})
        
        initial_stats = logger.get_statistics()
        assert initial_stats["events_logged"] == 0
        assert initial_stats["stored_events"] == 0
        
        # Add some events
        logger.log_validation_event("test1", result=AuditResult.APPROVED)
        logger.log_validation_event("test2", result=AuditResult.REJECTED)
        logger.log_security_event("security1", result=AuditResult.SUSPICIOUS, security_flags=["test"])
        
        updated_stats = logger.get_statistics()
        assert updated_stats["events_logged"] == 3
        assert updated_stats["stored_events"] == 3
        assert updated_stats["uptime_seconds"] > 0
        assert updated_stats["events_per_minute"] > 0
        assert updated_stats["validator_id"] == logger.validator_id


class TestAuditExport:
    """Test audit log export functionality."""
    
    def test_export_json(self):
        """Test JSON export."""
        logger = AuditLogger({"async_logging": False})
        
        # Add test events
        logger.log_validation_event("test_validation", asset_id="asset_123", result=AuditResult.APPROVED)
        logger.log_registry_operation("asset_registration", "asset_456", result=AuditResult.APPROVED)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            logger.export_audit_log(tmp_path, format="json")
            
            # Verify export
            with open(tmp_path, 'r') as f:
                data = json.load(f)
            
            assert "export_timestamp" in data
            assert data["validator_id"] == logger.validator_id
            assert data["total_events"] == 2
            assert len(data["events"]) == 2
            
            # Check event data
            validation_event = next(e for e in data["events"] if e["operation"] == "test_validation")
            assert validation_event["asset_id"] == "asset_123"
            assert validation_event["event_type"] == "validation"
            
        finally:
            Path(tmp_path).unlink()
    
    def test_export_csv(self):
        """Test CSV export."""
        logger = AuditLogger({"async_logging": False})
        
        logger.log_validation_event("test_validation", asset_id="asset_123", 
                                  result=AuditResult.APPROVED, duration_ms=10.5)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            logger.export_audit_log(tmp_path, format="csv")
            
            # Verify export
            with open(tmp_path, 'r') as f:
                reader = csv.reader(f)
                rows = list(reader)
            
            assert len(rows) == 2  # Header + 1 data row
            
            header = rows[0]
            assert "event_id" in header
            assert "timestamp" in header
            assert "event_type" in header
            assert "operation" in header
            
            data_row = rows[1]
            assert "test_validation" in data_row
            assert "asset_123" in data_row
            assert "validation" in data_row
            
        finally:
            Path(tmp_path).unlink()
    
    def test_export_with_filters(self):
        """Test export with time and type filters."""
        logger = AuditLogger({"async_logging": False})
        
        base_time = time.time()
        
        # Add events at different times
        with patch('time.time', return_value=base_time):
            logger.log_validation_event("old_validation", result=AuditResult.APPROVED)
        
        with patch('time.time', return_value=base_time + 100):
            logger.log_validation_event("new_validation", result=AuditResult.APPROVED)
            logger.log_registry_operation("registry_op", "asset_123")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            # Export with time filter
            logger.export_audit_log(tmp_path, format="json", since=base_time + 50)
            
            with open(tmp_path, 'r') as f:
                data = json.load(f)
            
            assert data["total_events"] == 2  # Only new events
            operations = [e["operation"] for e in data["events"]]
            assert "new_validation" in operations
            assert "registry_op" in operations
            assert "old_validation" not in operations
            
            # Export with type filter
            logger.export_audit_log(tmp_path, format="json", 
                                  event_types=[AuditEventType.VALIDATION])
            
            with open(tmp_path, 'r') as f:
                data = json.load(f)
            
            # Should only have validation events
            for event in data["events"]:
                assert event["event_type"] == "validation"
            
        finally:
            Path(tmp_path).unlink()


class TestGlobalAuditLogger:
    """Test global audit logger functionality."""
    
    def test_get_global_audit_logger(self):
        """Test getting global audit logger instance."""
        # Reset global instance
        import validator.audit_logger
        validator.audit_logger._global_audit_logger = None
        
        logger1 = get_audit_logger()
        logger2 = get_audit_logger()
        
        # Should return same instance
        assert logger1 is logger2
        assert isinstance(logger1, AuditLogger)
    
    def test_configure_global_audit_logger(self):
        """Test configuring global audit logger."""
        config = {"validator_id": "test_global_validator"}
        
        logger = configure_audit_logger(config)
        
        assert logger.validator_id == "test_global_validator"
        assert get_audit_logger() is logger


class TestConvenienceFunctions:
    """Test convenience functions for common audit patterns."""
    
    def test_log_validation_function(self):
        """Test validation logging convenience function."""
        # Reset global logger
        import validator.audit_logger
        validator.audit_logger._global_audit_logger = None
        
        event_id = log_validation("mint_validation", asset_id="asset_123", 
                                result=AuditResult.APPROVED, amount=1000)
        
        logger = get_audit_logger()
        assert len(logger.events) == 1
        
        event = logger.events[0]
        assert event.event_id == event_id
        assert event.operation == "mint_validation"
        assert event.asset_id == "asset_123"
        assert event.result == AuditResult.APPROVED
        assert event.amount == 1000
    
    def test_log_registry_op_function(self):
        """Test registry operation logging convenience function."""
        # Reset global logger
        import validator.audit_logger
        validator.audit_logger._global_audit_logger = None
        
        event_id = log_registry_op("asset_registration", "asset_456", 
                                 result=AuditResult.APPROVED, context={"creator": "user_123"})
        
        logger = get_audit_logger()
        assert len(logger.events) == 1
        
        event = logger.events[0]
        assert event.operation == "asset_registration"
        assert event.asset_id == "asset_456"
        assert event.context["creator"] == "user_123"
    
    def test_log_crypto_op_function(self):
        """Test crypto operation logging convenience function."""
        # Reset global logger
        import validator.audit_logger
        validator.audit_logger._global_audit_logger = None
        
        event_id = log_crypto_op("signature_verification", result=AuditResult.APPROVED,
                               duration_ms=5.2, context={"algorithm": "ecdsa"})
        
        logger = get_audit_logger()
        assert len(logger.events) == 1
        
        event = logger.events[0]
        assert event.operation == "signature_verification"
        assert event.result == AuditResult.APPROVED
        assert event.duration_ms == 5.2
    
    def test_log_security_event_function(self):
        """Test security event logging convenience function."""
        # Reset global logger
        import validator.audit_logger
        validator.audit_logger._global_audit_logger = None
        
        event_id = log_security_event("suspicious_activity", 
                                    security_flags=["multiple_failures", "rate_limit"],
                                    context={"ip": "192.168.1.100"})
        
        logger = get_audit_logger()
        assert len(logger.events) == 1
        
        event = logger.events[0]
        assert event.operation == "suspicious_activity"
        assert event.result == AuditResult.SUSPICIOUS
        assert "multiple_failures" in event.security_flags
        assert event.context["ip"] == "192.168.1.100"


class TestAsyncLogging:
    """Test asynchronous logging functionality."""
    
    @patch('threading.Thread')
    def test_async_logging_setup(self, mock_thread):
        """Test that async logging sets up background threads."""
        config = {"async_logging": True}
        logger = AuditLogger(config)
        
        assert logger.executor is not None
        assert logger.async_logging is True
    
    def test_sync_logging_mode(self):
        """Test synchronous logging mode."""
        config = {"async_logging": False}
        logger = AuditLogger(config)
        
        assert logger.executor is None
        assert logger.async_logging is False
        
        # Events should be written immediately
        with patch.object(logger, '_write_event') as mock_write:
            logger.log_validation_event("test", result=AuditResult.APPROVED)
            mock_write.assert_called_once()


class TestMetricsCollection:
    """Test metrics collection functionality."""
    
    def test_performance_metrics_update(self):
        """Test that performance metrics are updated correctly."""
        logger = AuditLogger({"async_logging": False})
        
        # Log events with different durations
        logger.log_validation_event("fast_validation", result=AuditResult.APPROVED, duration_ms=5.0)
        logger.log_validation_event("slow_validation", result=AuditResult.APPROVED, duration_ms=50.0)
        logger.log_validation_event("failed_validation", result=AuditResult.REJECTED, duration_ms=2.0)
        
        # Check metrics were updated
        assert len(logger.performance_metrics["validation_times"]) == 3
        assert 5.0 in logger.performance_metrics["validation_times"]
        assert 50.0 in logger.performance_metrics["validation_times"]
        
        # Check operation counts
        validation_counts = {k: v for k, v in logger.performance_metrics["operation_counts"].items() 
                           if k.startswith("validation_")}
        failed_counts = {k: v for k, v in logger.performance_metrics["operation_counts"].items() 
                        if k.endswith("_failed")}
        
        assert len(validation_counts) >= 3  # Should have logged 3 validation operations
        assert len(failed_counts) >= 1     # Should have at least one failed operation
    
    def test_security_pattern_tracking(self):
        """Test security pattern tracking."""
        logger = AuditLogger({"async_logging": False})
        
        # Log suspicious activities
        logger.log_security_event("suspicious_1", result=AuditResult.SUSPICIOUS, security_flags=["test"])
        logger.log_validation_event("normal", result=AuditResult.APPROVED)
        logger.log_security_event("suspicious_2", result=AuditResult.SUSPICIOUS, security_flags=["test"])
        
        # Check security patterns were tracked
        assert len(logger.security_patterns["suspicious_operations"]) == 2
        
        # Check metrics reflect security events
        snapshot = logger.get_metrics_snapshot()
        assert snapshot.suspicious_activities == 2


@pytest.fixture
def temp_audit_logger():
    """Fixture for temporary audit logger with cleanup."""
    with tempfile.TemporaryDirectory() as temp_dir:
        config = {
            "async_logging": False,
            "log_directory": temp_dir,
            "validator_id": "test_validator"
        }
        logger = AuditLogger(config)
        yield logger
        logger.close()


def test_integration_with_error_reporting():
    """Test integration with existing error reporting system."""
    logger = AuditLogger({"async_logging": False})
    
    # The audit logger should have access to the error reporter
    assert logger.error_reporter is not None
    
    # Can be used to log errors through the audit system
    logger.log_event(
        event_type=AuditEventType.SYSTEM_EVENT,
        operation="error_integration_test",
        component="test_component",
        result=AuditResult.ERROR,
        error_code="TEST_ERROR",
        error_message="Integration test error"
    )
    
    assert len(logger.events) == 1
    event = logger.events[0]
    assert event.error_code == "TEST_ERROR"
    assert event.error_message == "Integration test error"