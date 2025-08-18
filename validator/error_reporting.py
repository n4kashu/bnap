"""
Comprehensive Error Reporting System for BNAP Validator

This module provides centralized error collection, aggregation, and reporting
capabilities for the Bitcoin Native Asset Protocol validator system.

Features:
- Unified error collection from all validator components
- Structured error categorization and severity management
- Multiple output formats (JSON, HTML, text reports)
- Error aggregation and pattern analysis
- Integration with logging and monitoring systems
- Extensible reporting framework
"""

import json
import logging
import traceback
import time
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union, Set, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

# Import existing error types
from psbt.exceptions import PSBTError, PSBTValidationError, MetadataError
from crypto.exceptions import CryptoError, InvalidKeyError, InvalidSignatureError
from psbt.validator import ValidationIssue, ValidationResult, ValidationSeverity, ValidationCategory


class ErrorReportingLevel(Enum):
    """Error reporting levels."""
    MINIMAL = "minimal"        # Only critical errors
    STANDARD = "standard"      # Errors and warnings
    DETAILED = "detailed"      # All issues including info
    COMPREHENSIVE = "comprehensive"  # All issues + context + suggestions


class ReportFormat(Enum):
    """Available report formats."""
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    CSV = "csv"
    MARKDOWN = "markdown"


class ErrorContext(Enum):
    """Error context categories."""
    VALIDATION = "validation"
    SIGNING = "signing"
    PARSING = "parsing"
    CONSTRUCTION = "construction"
    CRYPTOGRAPHY = "cryptography"
    METADATA = "metadata"
    NETWORK = "network"
    STORAGE = "storage"
    CONFIGURATION = "configuration"
    SYSTEM = "system"


@dataclass
class ErrorReport:
    """Comprehensive error report structure."""
    report_id: str
    timestamp: float
    context: ErrorContext
    component: str
    operation: str
    severity: ValidationSeverity
    category: ValidationCategory
    code: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    location: str = ""
    stack_trace: Optional[str] = None
    related_errors: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    user_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize derived fields."""
        if not self.report_id:
            self.report_id = f"{self.context.value}_{int(time.time() * 1000000)}"
        if not self.timestamp:
            self.timestamp = time.time()


@dataclass
class ErrorSummary:
    """Summary statistics for error reporting."""
    total_errors: int
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    by_context: Dict[str, int] = field(default_factory=dict)
    by_component: Dict[str, int] = field(default_factory=dict)
    most_common_codes: List[tuple] = field(default_factory=list)
    error_patterns: Dict[str, int] = field(default_factory=dict)
    time_range: tuple = field(default_factory=tuple)


class ErrorReporter:
    """
    Centralized error reporting system for BNAP validator.
    
    Collects, categorizes, and reports errors from all validator components
    with support for multiple output formats and aggregation analysis.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize error reporter.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Error storage
        self.error_reports: List[ErrorReport] = []
        self.validation_results: List[ValidationResult] = []
        
        # Configuration
        self.max_stored_reports = self.config.get("max_stored_reports", 10000)
        self.auto_save_enabled = self.config.get("auto_save_enabled", False)
        self.save_path = self.config.get("save_path", "error_reports")
        self.reporting_level = ErrorReportingLevel(
            self.config.get("reporting_level", "standard")
        )
        
        # Error handlers
        self.error_handlers: Dict[str, List[Callable]] = defaultdict(list)
        
        # Statistics
        self.stats = {
            "reports_created": 0,
            "reports_saved": 0,
            "validations_processed": 0,
            "errors_by_hour": defaultdict(int),
            "start_time": time.time()
        }
        
        # Initialize save directory
        if self.auto_save_enabled:
            Path(self.save_path).mkdir(parents=True, exist_ok=True)
    
    def report_error(self, 
                    context: ErrorContext,
                    component: str,
                    operation: str,
                    error: Union[Exception, str],
                    severity: ValidationSeverity = ValidationSeverity.ERROR,
                    category: ValidationCategory = ValidationCategory.SECURITY,
                    code: Optional[str] = None,
                    location: str = "",
                    details: Optional[Dict[str, Any]] = None,
                    suggestions: Optional[List[str]] = None) -> str:
        """
        Report an error to the central reporting system.
        
        Args:
            context: Error context category
            component: Component name where error occurred
            operation: Operation being performed when error occurred
            error: Exception object or error message
            severity: Error severity level
            category: Error category
            code: Optional error code
            location: Location where error occurred
            details: Additional error details
            suggestions: Suggested fixes or next steps
            
        Returns:
            Unique report ID
        """
        if isinstance(error, Exception):
            message = str(error)
            stack_trace = traceback.format_exc()
            if not code:
                code = error.__class__.__name__
        else:
            message = str(error)
            stack_trace = None
            if not code:
                code = "GENERIC_ERROR"
        
        # Create error report
        report = ErrorReport(
            report_id="",  # Will be auto-generated
            timestamp=time.time(),
            context=context,
            component=component,
            operation=operation,
            severity=severity,
            category=category,
            code=code,
            message=message,
            details=details or {},
            location=location,
            stack_trace=stack_trace,
            suggestions=suggestions or []
        )
        
        # Store report
        self._store_report(report)
        
        # Trigger handlers
        self._trigger_handlers(report)
        
        # Log the error
        self._log_error(report)
        
        return report.report_id
    
    def report_validation_result(self, result: ValidationResult, 
                                context: ErrorContext = ErrorContext.VALIDATION,
                                component: str = "validator") -> None:
        """
        Process and store a validation result.
        
        Args:
            result: ValidationResult to process
            context: Context where validation occurred
            component: Component that performed validation
        """
        # Store the validation result
        self.validation_results.append(result)
        self.stats["validations_processed"] += 1
        
        # Convert ValidationIssues to ErrorReports
        for issue in result.issues:
            # Map ValidationIssue to ErrorReport
            report = ErrorReport(
                report_id="",
                timestamp=time.time(),
                context=context,
                component=component,
                operation="validation",
                severity=issue.severity,
                category=issue.category,
                code=issue.code,
                message=issue.message,
                details=issue.details,
                location=issue.location
            )
            
            self._store_report(report)
            self._trigger_handlers(report)
    
    def add_error_handler(self, error_code: str, handler: Callable[[ErrorReport], None]) -> None:
        """
        Add a custom error handler for specific error codes.
        
        Args:
            error_code: Error code to handle (use '*' for all errors)
            handler: Callback function to handle the error
        """
        self.error_handlers[error_code].append(handler)
    
    def get_error_summary(self, 
                         since: Optional[float] = None,
                         until: Optional[float] = None,
                         context_filter: Optional[ErrorContext] = None,
                         severity_filter: Optional[ValidationSeverity] = None) -> ErrorSummary:
        """
        Generate error summary statistics.
        
        Args:
            since: Start timestamp filter
            until: End timestamp filter  
            context_filter: Filter by context
            severity_filter: Filter by severity
            
        Returns:
            ErrorSummary with statistics
        """
        # Apply filters
        filtered_reports = self._apply_filters(
            self.error_reports, since, until, context_filter, severity_filter
        )
        
        if not filtered_reports:
            return ErrorSummary(total_errors=0)
        
        # Calculate statistics
        by_severity = Counter(r.severity.value for r in filtered_reports)
        by_category = Counter(r.category.value for r in filtered_reports)
        by_context = Counter(r.context.value for r in filtered_reports)
        by_component = Counter(r.component for r in filtered_reports)
        
        # Most common error codes
        code_counts = Counter(r.code for r in filtered_reports)
        most_common_codes = code_counts.most_common(10)
        
        # Error patterns (component + operation combinations)
        patterns = Counter(f"{r.component}:{r.operation}" for r in filtered_reports)
        
        # Time range
        timestamps = [r.timestamp for r in filtered_reports]
        time_range = (min(timestamps), max(timestamps)) if timestamps else (0, 0)
        
        return ErrorSummary(
            total_errors=len(filtered_reports),
            by_severity=dict(by_severity),
            by_category=dict(by_category),
            by_context=dict(by_context),
            by_component=dict(by_component),
            most_common_codes=most_common_codes,
            error_patterns=dict(patterns.most_common(10)),
            time_range=time_range
        )
    
    def generate_report(self, 
                       format: ReportFormat = ReportFormat.TEXT,
                       level: ErrorReportingLevel = None,
                       since: Optional[float] = None,
                       until: Optional[float] = None,
                       include_summary: bool = True,
                       include_details: bool = True,
                       output_path: Optional[str] = None) -> str:
        """
        Generate a comprehensive error report.
        
        Args:
            format: Output format for the report
            level: Reporting level (overrides default)
            since: Start timestamp filter
            until: End timestamp filter
            include_summary: Whether to include summary statistics
            include_details: Whether to include detailed error listings
            output_path: Optional file path to save report
            
        Returns:
            Generated report as string
        """
        reporting_level = level or self.reporting_level
        
        # Get filtered reports
        filtered_reports = self._apply_filters(
            self.error_reports, since, until
        )
        
        # Apply reporting level filtering
        filtered_reports = self._filter_by_reporting_level(filtered_reports, reporting_level)
        
        # Generate report based on format
        if format == ReportFormat.TEXT:
            report = self._generate_text_report(
                filtered_reports, include_summary, include_details
            )
        elif format == ReportFormat.JSON:
            report = self._generate_json_report(
                filtered_reports, include_summary, include_details
            )
        elif format == ReportFormat.HTML:
            report = self._generate_html_report(
                filtered_reports, include_summary, include_details
            )
        elif format == ReportFormat.MARKDOWN:
            report = self._generate_markdown_report(
                filtered_reports, include_summary, include_details
            )
        elif format == ReportFormat.CSV:
            report = self._generate_csv_report(filtered_reports)
        else:
            raise ValueError(f"Unsupported report format: {format}")
        
        # Save report if path provided
        if output_path:
            self._save_report_to_file(report, output_path)
        
        return report
    
    def get_recent_errors(self, 
                         count: int = 50,
                         severity_filter: Optional[ValidationSeverity] = None) -> List[ErrorReport]:
        """
        Get most recent error reports.
        
        Args:
            count: Number of recent errors to return
            severity_filter: Optional severity filter
            
        Returns:
            List of recent error reports
        """
        filtered = self.error_reports
        if severity_filter:
            filtered = [r for r in filtered if r.severity == severity_filter]
        
        # Sort by timestamp (most recent first)
        sorted_reports = sorted(filtered, key=lambda r: r.timestamp, reverse=True)
        
        return sorted_reports[:count]
    
    def clear_reports(self, older_than: Optional[float] = None) -> int:
        """
        Clear stored error reports.
        
        Args:
            older_than: Optional timestamp - only clear reports older than this
            
        Returns:
            Number of reports cleared
        """
        if older_than:
            initial_count = len(self.error_reports)
            self.error_reports = [r for r in self.error_reports if r.timestamp >= older_than]
            cleared = initial_count - len(self.error_reports)
        else:
            cleared = len(self.error_reports)
            self.error_reports = []
            self.validation_results = []
        
        return cleared
    
    def export_reports(self, 
                      output_path: str,
                      format: ReportFormat = ReportFormat.JSON,
                      since: Optional[float] = None) -> None:
        """
        Export error reports to file.
        
        Args:
            output_path: Path to save exported reports
            format: Export format
            since: Optional timestamp filter
        """
        filtered_reports = self._apply_filters(self.error_reports, since)
        
        if format == ReportFormat.JSON:
            data = [asdict(report) for report in filtered_reports]
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        else:
            # Generate formatted report and save
            report_content = self.generate_report(format=format, since=since)
            with open(output_path, 'w') as f:
                f.write(report_content)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get error reporter statistics."""
        uptime = time.time() - self.stats["start_time"]
        
        return {
            **self.stats,
            "stored_reports": len(self.error_reports),
            "validation_results": len(self.validation_results),
            "uptime_seconds": uptime,
            "reports_per_minute": (self.stats["reports_created"] / (uptime / 60)) if uptime > 0 else 0,
            "error_handlers": len(self.error_handlers),
            "config": self.config
        }
    
    # Private methods
    
    def _store_report(self, report: ErrorReport) -> None:
        """Store error report with size management."""
        self.error_reports.append(report)
        self.stats["reports_created"] += 1
        
        # Update hourly statistics
        hour_key = int(report.timestamp // 3600)
        self.stats["errors_by_hour"][hour_key] += 1
        
        # Manage storage size
        if len(self.error_reports) > self.max_stored_reports:
            # Remove oldest reports
            excess = len(self.error_reports) - self.max_stored_reports
            self.error_reports = self.error_reports[excess:]
        
        # Auto-save if enabled
        if self.auto_save_enabled:
            self._auto_save_report(report)
    
    def _trigger_handlers(self, report: ErrorReport) -> None:
        """Trigger registered error handlers."""
        # Trigger specific handlers
        for handler in self.error_handlers.get(report.code, []):
            try:
                handler(report)
            except Exception as e:
                self.logger.error(f"Error handler failed for {report.code}: {e}")
        
        # Trigger wildcard handlers
        for handler in self.error_handlers.get("*", []):
            try:
                handler(report)
            except Exception as e:
                self.logger.error(f"Wildcard error handler failed: {e}")
    
    def _log_error(self, report: ErrorReport) -> None:
        """Log error report to standard logging system."""
        log_message = f"[{report.context.value}:{report.component}] {report.message}"
        
        if report.severity == ValidationSeverity.CRITICAL:
            self.logger.critical(log_message, extra={"error_report_id": report.report_id})
        elif report.severity == ValidationSeverity.ERROR:
            self.logger.error(log_message, extra={"error_report_id": report.report_id})
        elif report.severity == ValidationSeverity.WARNING:
            self.logger.warning(log_message, extra={"error_report_id": report.report_id})
        else:
            self.logger.info(log_message, extra={"error_report_id": report.report_id})
    
    def _apply_filters(self, 
                      reports: List[ErrorReport],
                      since: Optional[float] = None,
                      until: Optional[float] = None,
                      context_filter: Optional[ErrorContext] = None,
                      severity_filter: Optional[ValidationSeverity] = None) -> List[ErrorReport]:
        """Apply filters to error reports."""
        filtered = reports
        
        if since:
            filtered = [r for r in filtered if r.timestamp >= since]
        
        if until:
            filtered = [r for r in filtered if r.timestamp <= until]
        
        if context_filter:
            filtered = [r for r in filtered if r.context == context_filter]
        
        if severity_filter:
            filtered = [r for r in filtered if r.severity == severity_filter]
        
        return filtered
    
    def _filter_by_reporting_level(self, 
                                  reports: List[ErrorReport],
                                  level: ErrorReportingLevel) -> List[ErrorReport]:
        """Filter reports by reporting level."""
        if level == ErrorReportingLevel.MINIMAL:
            return [r for r in reports if r.severity == ValidationSeverity.CRITICAL]
        elif level == ErrorReportingLevel.STANDARD:
            return [r for r in reports if r.severity in [
                ValidationSeverity.CRITICAL, ValidationSeverity.ERROR, ValidationSeverity.WARNING
            ]]
        elif level == ErrorReportingLevel.DETAILED:
            return reports  # All reports
        elif level == ErrorReportingLevel.COMPREHENSIVE:
            return reports  # All reports with full context
        else:
            return reports
    
    def _generate_text_report(self, 
                             reports: List[ErrorReport],
                             include_summary: bool,
                             include_details: bool) -> str:
        """Generate text format report."""
        lines = []
        lines.append("BNAP Validator Error Report")
        lines.append("=" * 50)
        lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"Total Reports: {len(reports)}")
        lines.append("")
        
        if include_summary:
            summary = self.get_error_summary()
            lines.append("SUMMARY STATISTICS")
            lines.append("-" * 20)
            lines.append(f"Total Errors: {summary.total_errors}")
            
            if summary.by_severity:
                lines.append("\nBy Severity:")
                for severity, count in summary.by_severity.items():
                    lines.append(f"  {severity}: {count}")
            
            if summary.by_category:
                lines.append("\nBy Category:")
                for category, count in summary.by_category.items():
                    lines.append(f"  {category}: {count}")
            
            if summary.most_common_codes:
                lines.append("\nMost Common Error Codes:")
                for code, count in summary.most_common_codes[:5]:
                    lines.append(f"  {code}: {count}")
            
            lines.append("")
        
        if include_details and reports:
            lines.append("DETAILED REPORTS")
            lines.append("-" * 20)
            
            for report in sorted(reports, key=lambda r: r.timestamp, reverse=True)[:50]:
                lines.append(f"\nReport ID: {report.report_id}")
                lines.append(f"Timestamp: {datetime.fromtimestamp(report.timestamp).isoformat()}")
                lines.append(f"Context: {report.context.value}")
                lines.append(f"Component: {report.component}")
                lines.append(f"Operation: {report.operation}")
                lines.append(f"Severity: {report.severity.value}")
                lines.append(f"Code: {report.code}")
                lines.append(f"Message: {report.message}")
                if report.location:
                    lines.append(f"Location: {report.location}")
                if report.suggestions:
                    lines.append("Suggestions:")
                    for suggestion in report.suggestions:
                        lines.append(f"  - {suggestion}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _generate_json_report(self, 
                             reports: List[ErrorReport],
                             include_summary: bool,
                             include_details: bool) -> str:
        """Generate JSON format report."""
        data = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_reports": len(reports),
                "reporting_level": self.reporting_level.value
            }
        }
        
        if include_summary:
            summary = self.get_error_summary()
            data["summary"] = asdict(summary)
        
        if include_details:
            data["reports"] = [asdict(report) for report in reports]
        
        return json.dumps(data, indent=2, default=str)
    
    def _generate_html_report(self, 
                             reports: List[ErrorReport],
                             include_summary: bool,
                             include_details: bool) -> str:
        """Generate HTML format report."""
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html><head><title>BNAP Validator Error Report</title>")
        html.append("<style>")
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }")
        html.append(".critical { color: red; font-weight: bold; }")
        html.append(".error { color: darkred; }")
        html.append(".warning { color: orange; }")
        html.append(".info { color: blue; }")
        html.append("table { border-collapse: collapse; width: 100%; }")
        html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html.append("th { background-color: #f2f2f2; }")
        html.append("</style></head><body>")
        
        html.append("<h1>BNAP Validator Error Report</h1>")
        html.append(f"<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>")
        html.append(f"<p>Total Reports: {len(reports)}</p>")
        
        if include_summary:
            summary = self.get_error_summary()
            html.append("<h2>Summary Statistics</h2>")
            html.append(f"<p>Total Errors: {summary.total_errors}</p>")
            
            if summary.by_severity:
                html.append("<h3>By Severity</h3>")
                html.append("<ul>")
                for severity, count in summary.by_severity.items():
                    html.append(f"<li>{severity}: {count}</li>")
                html.append("</ul>")
        
        if include_details and reports:
            html.append("<h2>Error Details</h2>")
            html.append("<table>")
            html.append("<tr><th>Timestamp</th><th>Severity</th><th>Component</th>")
            html.append("<th>Code</th><th>Message</th><th>Location</th></tr>")
            
            for report in sorted(reports, key=lambda r: r.timestamp, reverse=True)[:100]:
                severity_class = report.severity.value.lower()
                timestamp = datetime.fromtimestamp(report.timestamp).strftime("%Y-%m-%d %H:%M:%S")
                html.append(f"<tr class='{severity_class}'>")
                html.append(f"<td>{timestamp}</td>")
                html.append(f"<td>{report.severity.value}</td>")
                html.append(f"<td>{report.component}</td>")
                html.append(f"<td>{report.code}</td>")
                html.append(f"<td>{report.message}</td>")
                html.append(f"<td>{report.location}</td>")
                html.append("</tr>")
            
            html.append("</table>")
        
        html.append("</body></html>")
        
        return "\n".join(html)
    
    def _generate_markdown_report(self, 
                                 reports: List[ErrorReport],
                                 include_summary: bool,
                                 include_details: bool) -> str:
        """Generate Markdown format report."""
        lines = []
        lines.append("# BNAP Validator Error Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"**Total Reports:** {len(reports)}")
        lines.append("")
        
        if include_summary:
            summary = self.get_error_summary()
            lines.append("## Summary Statistics")
            lines.append("")
            lines.append(f"- **Total Errors:** {summary.total_errors}")
            
            if summary.by_severity:
                lines.append("")
                lines.append("### By Severity")
                for severity, count in summary.by_severity.items():
                    lines.append(f"- **{severity}:** {count}")
            
            if summary.most_common_codes:
                lines.append("")
                lines.append("### Most Common Error Codes")
                for code, count in summary.most_common_codes[:5]:
                    lines.append(f"- **{code}:** {count}")
            
            lines.append("")
        
        if include_details and reports:
            lines.append("## Error Details")
            lines.append("")
            
            for report in sorted(reports, key=lambda r: r.timestamp, reverse=True)[:50]:
                timestamp = datetime.fromtimestamp(report.timestamp).strftime("%Y-%m-%d %H:%M:%S")
                lines.append(f"### {report.code} - {timestamp}")
                lines.append("")
                lines.append(f"- **Severity:** {report.severity.value}")
                lines.append(f"- **Context:** {report.context.value}")
                lines.append(f"- **Component:** {report.component}")
                lines.append(f"- **Operation:** {report.operation}")
                lines.append(f"- **Message:** {report.message}")
                if report.location:
                    lines.append(f"- **Location:** {report.location}")
                if report.suggestions:
                    lines.append("- **Suggestions:**")
                    for suggestion in report.suggestions:
                        lines.append(f"  - {suggestion}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _generate_csv_report(self, reports: List[ErrorReport]) -> str:
        """Generate CSV format report."""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "report_id", "timestamp", "context", "component", "operation",
            "severity", "category", "code", "message", "location"
        ])
        
        # Data rows
        for report in reports:
            writer.writerow([
                report.report_id,
                datetime.fromtimestamp(report.timestamp).isoformat(),
                report.context.value,
                report.component,
                report.operation,
                report.severity.value,
                report.category.value,
                report.code,
                report.message,
                report.location
            ])
        
        return output.getvalue()
    
    def _auto_save_report(self, report: ErrorReport) -> None:
        """Auto-save individual report if enabled."""
        try:
            if self.auto_save_enabled:
                filename = f"error_report_{report.report_id}.json"
                filepath = Path(self.save_path) / filename
                
                with open(filepath, 'w') as f:
                    json.dump(asdict(report), f, indent=2, default=str)
                
                self.stats["reports_saved"] += 1
        except Exception as e:
            self.logger.error(f"Failed to auto-save report {report.report_id}: {e}")
    
    def _save_report_to_file(self, content: str, output_path: str) -> None:
        """Save report content to file."""
        try:
            with open(output_path, 'w') as f:
                f.write(content)
            self.logger.info(f"Report saved to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to save report to {output_path}: {e}")


# Global error reporter instance (singleton pattern)
_global_error_reporter: Optional[ErrorReporter] = None


def get_error_reporter() -> ErrorReporter:
    """Get the global error reporter instance."""
    global _global_error_reporter
    if _global_error_reporter is None:
        _global_error_reporter = ErrorReporter()
    return _global_error_reporter


def configure_error_reporter(config: Dict[str, Any]) -> ErrorReporter:
    """Configure the global error reporter."""
    global _global_error_reporter
    _global_error_reporter = ErrorReporter(config)
    return _global_error_reporter


# Convenience functions for common error reporting patterns

def report_validation_error(component: str, message: str, **kwargs) -> str:
    """Report a validation error."""
    return get_error_reporter().report_error(
        context=ErrorContext.VALIDATION,
        component=component,
        operation="validation",
        error=message,
        severity=ValidationSeverity.ERROR,
        category=ValidationCategory.BUSINESS_LOGIC,
        **kwargs
    )


def report_crypto_error(component: str, operation: str, error: Exception, **kwargs) -> str:
    """Report a cryptographic error."""
    return get_error_reporter().report_error(
        context=ErrorContext.CRYPTOGRAPHY,
        component=component,
        operation=operation,
        error=error,
        severity=ValidationSeverity.ERROR,
        category=ValidationCategory.SECURITY,
        **kwargs
    )


def report_parsing_error(component: str, message: str, location: str = "", **kwargs) -> str:
    """Report a parsing error."""
    return get_error_reporter().report_error(
        context=ErrorContext.PARSING,
        component=component,
        operation="parse",
        error=message,
        severity=ValidationSeverity.ERROR,
        category=ValidationCategory.STRUCTURE,
        location=location,
        **kwargs
    )


def report_system_error(component: str, operation: str, error: Exception, **kwargs) -> str:
    """Report a system-level error."""
    return get_error_reporter().report_error(
        context=ErrorContext.SYSTEM,
        component=component,
        operation=operation,
        error=error,
        severity=ValidationSeverity.CRITICAL,
        category=ValidationCategory.SECURITY,
        **kwargs
    )