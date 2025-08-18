"""
Comprehensive Audit Logging and Monitoring System for BNAP Validator

This module provides detailed audit trails for all validator operations including
validation events, registry operations, cryptographic operations, and security events.
Integrates with the existing error reporting system for unified monitoring.
"""

import json
import logging
import time
import threading
import hashlib
import uuid
from collections import defaultdict, Counter, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union, Set, Callable, Deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import queue
from concurrent.futures import ThreadPoolExecutor

from .error_reporting import ErrorReporter, get_error_reporter


class AuditEventType(Enum):
    """Audit event type categories."""
    VALIDATION = "validation"
    REGISTRY_OPERATION = "registry_operation"
    CRYPTOGRAPHIC_OPERATION = "crypto_operation"
    SECURITY_EVENT = "security_event"
    CONFIGURATION_CHANGE = "configuration_change"
    SYSTEM_EVENT = "system_event"
    PERFORMANCE_EVENT = "performance_event"


class AuditResult(Enum):
    """Audit event result types."""
    APPROVED = "approved"
    REJECTED = "rejected"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    SUSPICIOUS = "suspicious"


class LogLevel(Enum):
    """Audit log levels."""
    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Comprehensive audit event structure."""
    event_id: str
    timestamp: float
    event_type: AuditEventType
    operation: str
    validator_id: str
    component: str
    result: AuditResult
    duration_ms: Optional[float] = None
    
    # Asset-related fields
    asset_id: Optional[str] = None
    asset_type: Optional[str] = None
    amount: Optional[int] = None
    
    # Request identification
    request_id: Optional[str] = None
    request_fingerprint: Optional[str] = None
    
    # Context and metadata
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Security and compliance
    security_flags: List[str] = field(default_factory=list)
    compliance_tags: List[str] = field(default_factory=list)
    
    # Error details
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    
    # Performance metrics
    cpu_time_ms: Optional[float] = None
    memory_used_mb: Optional[float] = None
    
    def __post_init__(self):
        """Initialize derived fields."""
        if not self.event_id:
            self.event_id = f"audit_{int(time.time() * 1000000)}_{uuid.uuid4().hex[:8]}"
        if not self.timestamp:
            self.timestamp = time.time()
        if not self.request_id:
            self.request_id = f"req_{uuid.uuid4().hex[:12]}"


@dataclass
class MetricSnapshot:
    """Point-in-time metrics snapshot."""
    timestamp: float
    validator_id: str
    
    # Performance metrics
    validations_per_second: float = 0.0
    avg_validation_time_ms: float = 0.0
    p95_validation_time_ms: float = 0.0
    p99_validation_time_ms: float = 0.0
    
    # Business metrics
    total_validations: int = 0
    successful_validations: int = 0
    failed_validations: int = 0
    success_rate_percent: float = 0.0
    
    # Resource metrics
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    cache_hit_rate_percent: float = 0.0
    
    # Security metrics
    security_events: int = 0
    suspicious_activities: int = 0
    blocked_operations: int = 0
    
    # Asset metrics
    active_assets: int = 0
    total_mint_volume: int = 0
    unique_validators: int = 0


class AuditLogger:
    """
    Comprehensive audit logging system for BNAP validator operations.
    
    Provides detailed audit trails, performance monitoring, and security event tracking
    with configurable output formats and storage options.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize audit logger.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.validator_id = self.config.get("validator_id", f"validator_{uuid.uuid4().hex[:8]}")
        
        # Storage configuration
        self.log_directory = Path(self.config.get("log_directory", "audit_logs"))
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        self.max_log_size_mb = self.config.get("max_log_size_mb", 100)
        self.max_log_files = self.config.get("max_log_files", 10)
        self.async_logging = self.config.get("async_logging", True)
        self.batch_size = self.config.get("batch_size", 100)
        self.flush_interval_seconds = self.config.get("flush_interval_seconds", 10)
        
        # Monitoring configuration
        self.enable_performance_monitoring = self.config.get("enable_performance_monitoring", True)
        self.metrics_collection_interval = self.config.get("metrics_collection_interval", 60)
        self.enable_security_monitoring = self.config.get("enable_security_monitoring", True)
        
        # Log level and filtering
        self.log_level = LogLevel(self.config.get("log_level", "info"))
        self.enabled_event_types = set(self.config.get("enabled_event_types", [t.value for t in AuditEventType]))
        
        # Event storage and processing
        self.events: Deque[AuditEvent] = deque(maxlen=self.config.get("max_memory_events", 10000))
        self.event_queue = queue.Queue(maxsize=self.config.get("max_queue_size", 1000))
        self.metrics_history: List[MetricSnapshot] = []
        
        # Statistics and monitoring
        self.stats = {
            "events_logged": 0,
            "events_dropped": 0,
            "batch_writes": 0,
            "write_errors": 0,
            "start_time": time.time(),
            "last_flush": time.time()
        }
        
        self.performance_metrics = {
            "validation_times": deque(maxlen=1000),
            "operation_counts": defaultdict(int),
            "error_counts": defaultdict(int),
            "hourly_events": defaultdict(int)
        }
        
        # Security monitoring
        self.security_patterns = {
            "failed_validations": deque(maxlen=100),
            "suspicious_operations": deque(maxlen=50),
            "rate_limit_violations": deque(maxlen=50)
        }
        
        # Event handlers
        self.event_handlers: Dict[AuditEventType, List[Callable]] = defaultdict(list)
        
        # Async processing
        if self.async_logging:
            self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="audit-logger")
            self._start_background_processing()
        else:
            self.executor = None
        
        # Error reporting integration
        self.error_reporter = get_error_reporter()
        
        self.logger.info(f"AuditLogger initialized for validator {self.validator_id}")
    
    def log_event(self, 
                  event_type: AuditEventType,
                  operation: str,
                  component: str,
                  result: AuditResult,
                  **kwargs) -> str:
        """
        Log an audit event.
        
        Args:
            event_type: Type of audit event
            operation: Operation being performed
            component: Component performing the operation
            result: Result of the operation
            **kwargs: Additional event data
            
        Returns:
            Event ID
        """
        if not self._should_log_event(event_type):
            return ""
        
        # Create audit event
        event = AuditEvent(
            event_id="",  # Will be auto-generated
            timestamp=time.time(),
            event_type=event_type,
            operation=operation,
            validator_id=self.validator_id,
            component=component,
            result=result,
            **kwargs
        )
        
        # Process the event
        self._process_event(event)
        
        return event.event_id
    
    def log_validation_event(self,
                           operation: str,
                           asset_id: Optional[str] = None,
                           amount: Optional[int] = None,
                           result: AuditResult = AuditResult.APPROVED,
                           duration_ms: Optional[float] = None,
                           context: Optional[Dict[str, Any]] = None,
                           security_flags: Optional[List[str]] = None) -> str:
        """
        Log a validation event.
        
        Args:
            operation: Validation operation (e.g., "mint_validation", "transfer_validation")
            asset_id: Asset being validated
            amount: Amount being validated
            result: Validation result
            duration_ms: Operation duration
            context: Additional context
            security_flags: Security concerns
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.VALIDATION,
            operation=operation,
            component="validator",
            result=result,
            asset_id=asset_id,
            amount=amount,
            duration_ms=duration_ms,
            context=context or {},
            security_flags=security_flags or []
        )
    
    def log_registry_operation(self,
                             operation: str,
                             asset_id: str,
                             result: AuditResult = AuditResult.APPROVED,
                             context: Optional[Dict[str, Any]] = None) -> str:
        """
        Log a registry operation.
        
        Args:
            operation: Registry operation (e.g., "asset_registration", "supply_update")
            asset_id: Asset involved
            result: Operation result
            context: Additional context
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.REGISTRY_OPERATION,
            operation=operation,
            component="registry_manager",
            result=result,
            asset_id=asset_id,
            context=context or {}
        )
    
    def log_crypto_operation(self,
                           operation: str,
                           result: AuditResult,
                           duration_ms: Optional[float] = None,
                           context: Optional[Dict[str, Any]] = None,
                           error_code: Optional[str] = None,
                           error_message: Optional[str] = None) -> str:
        """
        Log a cryptographic operation.
        
        Args:
            operation: Crypto operation (e.g., "signature_verification", "key_derivation")
            result: Operation result
            duration_ms: Operation duration
            context: Additional context
            error_code: Error code if failed
            error_message: Error message if failed
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.CRYPTOGRAPHIC_OPERATION,
            operation=operation,
            component="crypto_engine",
            result=result,
            duration_ms=duration_ms,
            context=context or {},
            error_code=error_code,
            error_message=error_message
        )
    
    def log_security_event(self,
                          operation: str,
                          result: AuditResult,
                          security_flags: List[str],
                          context: Optional[Dict[str, Any]] = None,
                          compliance_tags: Optional[List[str]] = None) -> str:
        """
        Log a security event.
        
        Args:
            operation: Security operation or event
            result: Event result
            security_flags: Security concerns identified
            context: Additional context
            compliance_tags: Compliance-related tags
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.SECURITY_EVENT,
            operation=operation,
            component="security_monitor",
            result=result,
            security_flags=security_flags,
            compliance_tags=compliance_tags or [],
            context=context or {}
        )
    
    def log_performance_event(self,
                            operation: str,
                            duration_ms: float,
                            cpu_time_ms: Optional[float] = None,
                            memory_used_mb: Optional[float] = None,
                            context: Optional[Dict[str, Any]] = None) -> str:
        """
        Log a performance event.
        
        Args:
            operation: Operation being measured
            duration_ms: Total duration
            cpu_time_ms: CPU time used
            memory_used_mb: Memory used
            context: Additional context
            
        Returns:
            Event ID
        """
        return self.log_event(
            event_type=AuditEventType.PERFORMANCE_EVENT,
            operation=operation,
            component="performance_monitor",
            result=AuditResult.INFO,
            duration_ms=duration_ms,
            cpu_time_ms=cpu_time_ms,
            memory_used_mb=memory_used_mb,
            context=context or {}
        )
    
    def add_event_handler(self, event_type: AuditEventType, handler: Callable[[AuditEvent], None]) -> None:
        """
        Add a custom event handler.
        
        Args:
            event_type: Event type to handle
            handler: Handler function
        """
        self.event_handlers[event_type].append(handler)
    
    def get_metrics_snapshot(self) -> MetricSnapshot:
        """
        Get current metrics snapshot.
        
        Returns:
            Current metrics snapshot
        """
        now = time.time()
        uptime_seconds = now - self.stats["start_time"]
        
        # Calculate validation metrics
        validation_times = list(self.performance_metrics["validation_times"])
        # Count validation operations
        total_validations = sum(count for key, count in self.performance_metrics["operation_counts"].items() 
                              if key.startswith("validation_") and not key.endswith("_failed"))
        
        if validation_times:
            avg_time = sum(validation_times) / len(validation_times)
            sorted_times = sorted(validation_times)
            p95_time = sorted_times[int(0.95 * len(sorted_times))] if sorted_times else 0
            p99_time = sorted_times[int(0.99 * len(sorted_times))] if sorted_times else 0
        else:
            avg_time = p95_time = p99_time = 0
        
        # Calculate rates
        validations_per_second = total_validations / uptime_seconds if uptime_seconds > 0 else 0
        
        successful_ops = sum(self.performance_metrics["operation_counts"][op] 
                           for op in self.performance_metrics["operation_counts"] 
                           if not op.endswith("_failed"))
        failed_ops = sum(self.performance_metrics["operation_counts"][op] 
                        for op in self.performance_metrics["operation_counts"] 
                        if op.endswith("_failed"))
        
        success_rate = (successful_ops / (successful_ops + failed_ops) * 100) if (successful_ops + failed_ops) > 0 else 0
        
        return MetricSnapshot(
            timestamp=now,
            validator_id=self.validator_id,
            validations_per_second=validations_per_second,
            avg_validation_time_ms=avg_time,
            p95_validation_time_ms=p95_time,
            p99_validation_time_ms=p99_time,
            total_validations=total_validations,
            successful_validations=successful_ops,
            failed_validations=failed_ops,
            success_rate_percent=success_rate,
            security_events=len(self.security_patterns["suspicious_operations"]),
            suspicious_activities=sum(1 for event in self.events if event.result == AuditResult.SUSPICIOUS),
            active_assets=len(set(event.asset_id for event in self.events if event.asset_id))
        )
    
    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get security event summary for the specified time period.
        
        Args:
            hours: Time period in hours
            
        Returns:
            Security summary
        """
        cutoff_time = time.time() - (hours * 3600)
        recent_events = [event for event in self.events if event.timestamp >= cutoff_time]
        
        security_events = [event for event in recent_events if event.event_type == AuditEventType.SECURITY_EVENT]
        suspicious_events = [event for event in recent_events if event.result == AuditResult.SUSPICIOUS]
        failed_validations = [event for event in recent_events 
                            if event.event_type == AuditEventType.VALIDATION and event.result == AuditResult.REJECTED]
        
        # Analyze patterns
        security_flag_counts = Counter()
        for event in security_events + suspicious_events:
            for flag in event.security_flags:
                security_flag_counts[flag] += 1
        
        error_code_counts = Counter()
        for event in failed_validations:
            if event.error_code:
                error_code_counts[event.error_code] += 1
        
        return {
            "period_hours": hours,
            "total_events": len(recent_events),
            "security_events": len(security_events),
            "suspicious_activities": len(suspicious_events),
            "failed_validations": len(failed_validations),
            "most_common_security_flags": security_flag_counts.most_common(10),
            "most_common_error_codes": error_code_counts.most_common(10),
            "unique_assets_involved": len(set(event.asset_id for event in security_events + suspicious_events if event.asset_id))
        }
    
    def export_audit_log(self,
                        output_path: str,
                        format: str = "json",
                        since: Optional[float] = None,
                        event_types: Optional[List[AuditEventType]] = None) -> None:
        """
        Export audit log to file.
        
        Args:
            output_path: Output file path
            format: Export format ("json", "csv", "text")
            since: Optional timestamp filter
            event_types: Optional event type filter
        """
        # Apply filters
        filtered_events = list(self.events)
        
        if since:
            filtered_events = [event for event in filtered_events if event.timestamp >= since]
        
        if event_types:
            event_type_set = set(event_types)
            filtered_events = [event for event in filtered_events if event.event_type in event_type_set]
        
        # Export based on format
        if format.lower() == "json":
            self._export_json(filtered_events, output_path)
        elif format.lower() == "csv":
            self._export_csv(filtered_events, output_path)
        elif format.lower() == "text":
            self._export_text(filtered_events, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit logger statistics."""
        uptime = time.time() - self.stats["start_time"]
        
        return {
            **self.stats,
            "validator_id": self.validator_id,
            "uptime_seconds": uptime,
            "events_per_minute": (self.stats["events_logged"] / (uptime / 60)) if uptime > 0 else 0,
            "stored_events": len(self.events),
            "queue_size": self.event_queue.qsize() if self.async_logging else 0,
            "metrics_snapshots": len(self.metrics_history),
            "event_handlers": sum(len(handlers) for handlers in self.event_handlers.values()),
            "enabled_event_types": list(self.enabled_event_types),
            "config": self.config
        }
    
    def flush(self) -> None:
        """Force flush of pending events."""
        if self.async_logging:
            # Process all queued events
            events_to_flush = []
            while not self.event_queue.empty():
                try:
                    events_to_flush.append(self.event_queue.get_nowait())
                except queue.Empty:
                    break
            
            if events_to_flush:
                self._write_events_batch(events_to_flush)
        
        self.stats["last_flush"] = time.time()
    
    def close(self) -> None:
        """Close audit logger and cleanup resources."""
        self.logger.info("Shutting down audit logger")
        
        # Flush remaining events
        self.flush()
        
        # Shutdown async processing
        if self.executor:
            self.executor.shutdown(wait=True)
    
    # Private methods
    
    def _should_log_event(self, event_type: AuditEventType) -> bool:
        """Check if event type should be logged."""
        return event_type.value in self.enabled_event_types
    
    def _process_event(self, event: AuditEvent) -> None:
        """Process an audit event."""
        # Store in memory
        self.events.append(event)
        self.stats["events_logged"] += 1
        
        # Update metrics
        self._update_metrics(event)
        
        # Trigger handlers
        self._trigger_handlers(event)
        
        # Queue for async writing or write immediately
        if self.async_logging:
            try:
                self.event_queue.put_nowait(event)
            except queue.Full:
                self.stats["events_dropped"] += 1
                self.logger.warning("Event queue full, dropping event")
        else:
            self._write_event(event)
    
    def _update_metrics(self, event: AuditEvent) -> None:
        """Update performance metrics with event data."""
        # Track operation counts
        operation_key = f"{event.event_type.value}_{event.operation}"
        self.performance_metrics["operation_counts"][operation_key] += 1
        
        if event.result in [AuditResult.REJECTED, AuditResult.ERROR]:
            self.performance_metrics["operation_counts"][f"{operation_key}_failed"] += 1
        
        # Track validation times
        if event.event_type == AuditEventType.VALIDATION and event.duration_ms:
            self.performance_metrics["validation_times"].append(event.duration_ms)
        
        # Track security events
        if event.result == AuditResult.SUSPICIOUS or event.security_flags:
            self.security_patterns["suspicious_operations"].append(event.timestamp)
        
        # Track hourly events
        hour_key = int(event.timestamp // 3600)
        self.performance_metrics["hourly_events"][hour_key] += 1
    
    def _trigger_handlers(self, event: AuditEvent) -> None:
        """Trigger registered event handlers."""
        for handler in self.event_handlers.get(event.event_type, []):
            try:
                handler(event)
            except Exception as e:
                self.logger.error(f"Event handler failed for {event.event_type}: {e}")
    
    def _write_event(self, event: AuditEvent) -> None:
        """Write single event to storage."""
        try:
            log_file = self.log_directory / f"audit_{datetime.now().strftime('%Y%m%d')}.jsonl"
            with open(log_file, 'a') as f:
                event_dict = asdict(event)
                # Convert enums to string values for JSON serialization
                event_dict['event_type'] = event.event_type.value
                event_dict['result'] = event.result.value
                json.dump(event_dict, f, default=str)
                f.write('\n')
        except Exception as e:
            self.stats["write_errors"] += 1
            self.logger.error(f"Failed to write audit event: {e}")
    
    def _write_events_batch(self, events: List[AuditEvent]) -> None:
        """Write batch of events to storage."""
        if not events:
            return
        
        try:
            log_file = self.log_directory / f"audit_{datetime.now().strftime('%Y%m%d')}.jsonl"
            with open(log_file, 'a') as f:
                for event in events:
                    event_dict = asdict(event)
                    # Convert enums to string values for JSON serialization
                    event_dict['event_type'] = event.event_type.value
                    event_dict['result'] = event.result.value
                    json.dump(event_dict, f, default=str)
                    f.write('\n')
            
            self.stats["batch_writes"] += 1
        except Exception as e:
            self.stats["write_errors"] += 1
            self.logger.error(f"Failed to write audit events batch: {e}")
    
    def _start_background_processing(self) -> None:
        """Start background processing threads."""
        if self.executor:
            # Background event processing
            self.executor.submit(self._background_event_processor)
            
            # Periodic metrics collection
            if self.enable_performance_monitoring:
                self.executor.submit(self._background_metrics_collector)
    
    def _background_event_processor(self) -> None:
        """Background thread for processing queued events."""
        batch = []
        last_flush = time.time()
        
        while True:
            try:
                # Get events from queue with timeout
                timeout = max(1, self.flush_interval_seconds - (time.time() - last_flush))
                try:
                    event = self.event_queue.get(timeout=timeout)
                    batch.append(event)
                except queue.Empty:
                    pass
                
                # Flush batch if needed
                current_time = time.time()
                if (len(batch) >= self.batch_size or 
                    (batch and current_time - last_flush >= self.flush_interval_seconds)):
                    
                    if batch:
                        self._write_events_batch(batch)
                        batch.clear()
                    
                    last_flush = current_time
                
            except Exception as e:
                self.logger.error(f"Background event processor error: {e}")
                time.sleep(1)
    
    def _background_metrics_collector(self) -> None:
        """Background thread for collecting periodic metrics."""
        while True:
            try:
                time.sleep(self.metrics_collection_interval)
                
                # Collect metrics snapshot
                snapshot = self.get_metrics_snapshot()
                self.metrics_history.append(snapshot)
                
                # Limit history size
                max_history = self.config.get("max_metrics_history", 1440)  # 24 hours at 1-minute intervals
                if len(self.metrics_history) > max_history:
                    self.metrics_history = self.metrics_history[-max_history:]
                
            except Exception as e:
                self.logger.error(f"Background metrics collector error: {e}")
    
    def _export_json(self, events: List[AuditEvent], output_path: str) -> None:
        """Export events as JSON."""
        def serialize_event(event):
            """Serialize event with proper enum handling."""
            event_dict = asdict(event)
            # Convert enums to string values
            event_dict['event_type'] = event.event_type.value
            event_dict['result'] = event.result.value
            return event_dict
        
        data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "validator_id": self.validator_id,
            "total_events": len(events),
            "events": [serialize_event(event) for event in events]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _export_csv(self, events: List[AuditEvent], output_path: str) -> None:
        """Export events as CSV."""
        import csv
        
        if not events:
            return
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                "event_id", "timestamp", "event_type", "operation", "validator_id",
                "component", "result", "duration_ms", "asset_id", "amount",
                "error_code", "error_message", "security_flags"
            ])
            
            # Data
            for event in events:
                writer.writerow([
                    event.event_id,
                    datetime.fromtimestamp(event.timestamp).isoformat(),
                    event.event_type.value,
                    event.operation,
                    event.validator_id,
                    event.component,
                    event.result.value,
                    event.duration_ms,
                    event.asset_id,
                    event.amount,
                    event.error_code,
                    event.error_message,
                    "|".join(event.security_flags) if event.security_flags else ""
                ])
    
    def _export_text(self, events: List[AuditEvent], output_path: str) -> None:
        """Export events as human-readable text."""
        with open(output_path, 'w') as f:
            f.write(f"BNAP Validator Audit Log Export\n")
            f.write(f"Validator ID: {self.validator_id}\n")
            f.write(f"Export Time: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"Total Events: {len(events)}\n")
            f.write("=" * 80 + "\n\n")
            
            for event in events:
                timestamp_str = datetime.fromtimestamp(event.timestamp).isoformat()
                f.write(f"Event ID: {event.event_id}\n")
                f.write(f"Time: {timestamp_str}\n")
                f.write(f"Type: {event.event_type.value}\n")
                f.write(f"Operation: {event.operation}\n")
                f.write(f"Component: {event.component}\n")
                f.write(f"Result: {event.result.value}\n")
                
                if event.asset_id:
                    f.write(f"Asset ID: {event.asset_id}\n")
                if event.amount:
                    f.write(f"Amount: {event.amount}\n")
                if event.duration_ms:
                    f.write(f"Duration: {event.duration_ms}ms\n")
                if event.error_code:
                    f.write(f"Error: {event.error_code} - {event.error_message}\n")
                if event.security_flags:
                    f.write(f"Security Flags: {', '.join(event.security_flags)}\n")
                
                f.write("\n" + "-" * 40 + "\n\n")


# Global audit logger instance (singleton pattern)
_global_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _global_audit_logger
    if _global_audit_logger is None:
        _global_audit_logger = AuditLogger()
    return _global_audit_logger


def configure_audit_logger(config: Dict[str, Any]) -> AuditLogger:
    """Configure the global audit logger."""
    global _global_audit_logger
    _global_audit_logger = AuditLogger(config)
    return _global_audit_logger


# Convenience functions for common audit patterns

def log_validation(operation: str, asset_id: str = None, result: AuditResult = AuditResult.APPROVED, **kwargs) -> str:
    """Log a validation operation."""
    return get_audit_logger().log_validation_event(
        operation=operation,
        asset_id=asset_id,
        result=result,
        **kwargs
    )


def log_registry_op(operation: str, asset_id: str, result: AuditResult = AuditResult.APPROVED, **kwargs) -> str:
    """Log a registry operation."""
    return get_audit_logger().log_registry_operation(
        operation=operation,
        asset_id=asset_id,
        result=result,
        **kwargs
    )


def log_crypto_op(operation: str, result: AuditResult, **kwargs) -> str:
    """Log a cryptographic operation."""
    return get_audit_logger().log_crypto_operation(
        operation=operation,
        result=result,
        **kwargs
    )


def log_security_event(operation: str, security_flags: List[str], result: AuditResult = AuditResult.SUSPICIOUS, **kwargs) -> str:
    """Log a security event."""
    return get_audit_logger().log_security_event(
        operation=operation,
        security_flags=security_flags,
        result=result,
        **kwargs
    )