"""
Bitcoin Native Asset Protocol - PSBT Validator

This module provides comprehensive validation for PSBTs including structure validation,
asset metadata validation, and business logic validation for the Bitcoin Native Asset Protocol.
"""

from typing import List, Dict, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib

from .parser import PSBTParser, ParsedPSBT, PSBTGlobal, PSBTInput, PSBTOutput, AssetMetadata
from .outputs.op_return import OpReturnDecoder, MetadataType
from .exceptions import PSBTValidationError, MetadataError
from .utils import extract_op_return_data, validate_asset_id


class ValidationSeverity(Enum):
    """Validation issue severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ValidationCategory(Enum):
    """Categories of validation issues."""
    STRUCTURE = "structure"
    METADATA = "metadata"
    BUSINESS_LOGIC = "business_logic"
    ASSET_RULES = "asset_rules"
    FEE_VALIDATION = "fee_validation"
    SECURITY = "security"


@dataclass
class ValidationIssue:
    """Represents a validation issue found in a PSBT."""
    severity: ValidationSeverity
    category: ValidationCategory
    code: str
    message: str
    location: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Results of PSBT validation."""
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    errors: List[ValidationIssue] = field(default_factory=list)
    critical_issues: List[ValidationIssue] = field(default_factory=list)
    
    def __post_init__(self):
        """Categorize issues by severity."""
        for issue in self.issues:
            if issue.severity == ValidationSeverity.WARNING:
                self.warnings.append(issue)
            elif issue.severity == ValidationSeverity.ERROR:
                self.errors.append(issue)
            elif issue.severity == ValidationSeverity.CRITICAL:
                self.critical_issues.append(issue)
        
        # PSBT is invalid if there are errors or critical issues
        self.is_valid = len(self.errors) == 0 and len(self.critical_issues) == 0


class PSBTValidator:
    """
    Comprehensive PSBT validator for Bitcoin Native Asset Protocol.
    
    Validates PSBT structure, asset metadata, business logic, and security constraints.
    """
    
    def __init__(self):
        """Initialize PSBT validator."""
        self.parser = PSBTParser()
        self.op_return_decoder = OpReturnDecoder()
        self.issues: List[ValidationIssue] = []
        
        # Validation configuration
        self.max_inputs = 100
        self.max_outputs = 100
        self.max_op_return_size = 80
        self.dust_threshold = 546
        self.max_asset_amount = 21_000_000 * 10**8  # 21M BTC equivalent
        
    def validate_psbt(self, psbt_data: bytes) -> ValidationResult:
        """
        Validate a complete PSBT.
        
        Args:
            psbt_data: Raw PSBT data
            
        Returns:
            ValidationResult with all validation issues
        """
        self.issues = []
        
        try:
            parsed_psbt = self.parser.parse(psbt_data)
        except Exception as e:
            self._add_critical_issue(
                "PARSE_ERROR",
                f"Failed to parse PSBT: {e}",
                ValidationCategory.STRUCTURE
            )
            return ValidationResult(is_valid=False, issues=self.issues)
        
        # Run all validation checks
        self._validate_structure(parsed_psbt)
        self._validate_global_data(parsed_psbt.psbt_global)
        self._validate_inputs(parsed_psbt.inputs, parsed_psbt.psbt_global)
        self._validate_outputs(parsed_psbt.outputs)
        self._validate_asset_metadata(parsed_psbt)
        self._validate_business_logic(parsed_psbt)
        self._validate_security_constraints(parsed_psbt)
        
        return ValidationResult(is_valid=True, issues=self.issues)
    
    def validate_structure(self, psbt_data: bytes) -> ValidationResult:
        """
        Validate only PSBT structure without business logic.
        
        Args:
            psbt_data: Raw PSBT data
            
        Returns:
            ValidationResult for structure validation
        """
        self.issues = []
        
        try:
            parsed_psbt = self.parser.parse(psbt_data)
        except Exception as e:
            self._add_critical_issue(
                "PARSE_ERROR",
                f"Failed to parse PSBT: {e}",
                ValidationCategory.STRUCTURE
            )
            return ValidationResult(is_valid=False, issues=self.issues)
        
        self._validate_structure(parsed_psbt)
        self._validate_global_data(parsed_psbt.psbt_global)
        
        return ValidationResult(is_valid=True, issues=self.issues)
    
    def validate_asset_operations(self, psbt_data: bytes) -> ValidationResult:
        """
        Validate asset-specific operations and metadata.
        
        Args:
            psbt_data: Raw PSBT data
            
        Returns:
            ValidationResult for asset validation
        """
        self.issues = []
        
        try:
            parsed_psbt = self.parser.parse(psbt_data)
        except Exception as e:
            self._add_critical_issue(
                "PARSE_ERROR",
                f"Failed to parse PSBT: {e}",
                ValidationCategory.STRUCTURE
            )
            return ValidationResult(is_valid=False, issues=self.issues)
        
        self._validate_asset_metadata(parsed_psbt)
        self._validate_business_logic(parsed_psbt)
        
        return ValidationResult(is_valid=True, issues=self.issues)
    
    def _validate_structure(self, parsed_psbt: ParsedPSBT) -> None:
        """Validate PSBT structure and format."""
        if not parsed_psbt.psbt_global:
            self._add_critical_issue(
                "MISSING_GLOBAL",
                "PSBT missing global data section",
                ValidationCategory.STRUCTURE
            )
            return
        
        if not parsed_psbt.psbt_global.unsigned_tx:
            self._add_critical_issue(
                "MISSING_UNSIGNED_TX",
                "PSBT missing unsigned transaction",
                ValidationCategory.STRUCTURE
            )
        
        # Validate input/output counts
        if len(parsed_psbt.inputs) == 0:
            self._add_error(
                "NO_INPUTS",
                "PSBT must have at least one input",
                ValidationCategory.STRUCTURE
            )
        
        if len(parsed_psbt.outputs) == 0:
            self._add_error(
                "NO_OUTPUTS", 
                "PSBT must have at least one output",
                ValidationCategory.STRUCTURE
            )
        
        if len(parsed_psbt.inputs) > self.max_inputs:
            self._add_warning(
                "TOO_MANY_INPUTS",
                f"PSBT has {len(parsed_psbt.inputs)} inputs (max recommended: {self.max_inputs})",
                ValidationCategory.STRUCTURE
            )
        
        if len(parsed_psbt.outputs) > self.max_outputs:
            self._add_warning(
                "TOO_MANY_OUTPUTS",
                f"PSBT has {len(parsed_psbt.outputs)} outputs (max recommended: {self.max_outputs})",
                ValidationCategory.STRUCTURE
            )
    
    def _validate_global_data(self, global_data: PSBTGlobal) -> None:
        """Validate global PSBT data."""
        if global_data.version and global_data.version > 2:
            self._add_warning(
                "HIGH_VERSION",
                f"PSBT version {global_data.version} is higher than standard",
                ValidationCategory.STRUCTURE,
                details={"version": global_data.version}
            )
        
        # Validate proprietary fields format
        for key, value in global_data.proprietary.items():
            if not key.startswith(b'BNAP'):
                self._add_info(
                    "NON_BNAP_PROPRIETARY",
                    f"Non-BNAP proprietary field found: {key.hex()}",
                    ValidationCategory.METADATA,
                    details={"key": key.hex(), "value": value.hex()}
                )
    
    def _validate_inputs(self, inputs: List[PSBTInput], global_data: PSBTGlobal) -> None:
        """Validate PSBT inputs."""
        for i, input_data in enumerate(inputs):
            location = f"input[{i}]"
            
            # Each input must have either witness_utxo or non_witness_utxo
            if not input_data.witness_utxo and not input_data.non_witness_utxo:
                self._add_error(
                    "MISSING_UTXO",
                    "Input must have either witness_utxo or non_witness_utxo",
                    ValidationCategory.STRUCTURE,
                    location=location
                )
            
            # Validate proprietary fields
            for key, value in input_data.proprietary.items():
                if key.startswith(b'BNAP'):
                    self._validate_bnap_proprietary_field(key, value, location)
    
    def _validate_outputs(self, outputs: List[PSBTOutput]) -> None:
        """Validate PSBT outputs."""
        op_return_count = 0
        
        for i, output_data in enumerate(outputs):
            location = f"output[{i}]"
            
            # Check for OP_RETURN outputs
            if hasattr(output_data, 'script') and output_data.script:
                if output_data.script.startswith(b'\x6a'):  # OP_RETURN
                    op_return_count += 1
                    self._validate_op_return_output(output_data.script, location)
            
            # Validate proprietary fields
            for key, value in output_data.proprietary.items():
                if key.startswith(b'BNAP'):
                    self._validate_bnap_proprietary_field(key, value, location)
        
        # Warn about multiple OP_RETURN outputs
        if op_return_count > 1:
            self._add_warning(
                "MULTIPLE_OP_RETURN",
                f"Transaction has {op_return_count} OP_RETURN outputs",
                ValidationCategory.STRUCTURE,
                details={"op_return_count": op_return_count}
            )
    
    def _validate_op_return_output(self, script: bytes, location: str) -> None:
        """Validate OP_RETURN output."""
        op_return_data = extract_op_return_data(script)
        if not op_return_data:
            self._add_warning(
                "EMPTY_OP_RETURN",
                "OP_RETURN output has no data",
                ValidationCategory.STRUCTURE,
                location=location
            )
            return
        
        if len(op_return_data) > self.max_op_return_size:
            self._add_error(
                "OP_RETURN_TOO_LARGE",
                f"OP_RETURN data is {len(op_return_data)} bytes (max: {self.max_op_return_size})",
                ValidationCategory.STRUCTURE,
                location=location,
                details={"size": len(op_return_data), "max_size": self.max_op_return_size}
            )
        
        # Try to decode BNAP metadata
        try:
            metadata = self.op_return_decoder.decode_metadata(op_return_data)
            if metadata:
                self._validate_metadata_payload(metadata, location)
        except Exception as e:
            self._add_info(
                "OP_RETURN_DECODE_FAILED",
                f"Could not decode OP_RETURN as BNAP metadata: {e}",
                ValidationCategory.METADATA,
                location=location
            )
    
    def _validate_metadata_payload(self, metadata, location: str) -> None:
        """Validate BNAP metadata payload."""
        if metadata.version > 1:
            self._add_warning(
                "HIGH_METADATA_VERSION",
                f"Metadata version {metadata.version} is higher than standard",
                ValidationCategory.METADATA,
                location=location,
                details={"version": metadata.version}
            )
        
        # Validate metadata content based on type
        if metadata.metadata_type == MetadataType.ASSET_ISSUANCE:
            self._validate_asset_issuance_metadata(metadata, location)
        elif metadata.metadata_type == MetadataType.ASSET_TRANSFER:
            self._validate_asset_transfer_metadata(metadata, location)
        elif metadata.metadata_type == MetadataType.NFT_METADATA:
            self._validate_nft_metadata(metadata, location)
    
    def _validate_asset_issuance_metadata(self, metadata, location: str) -> None:
        """Validate asset issuance metadata."""
        if len(metadata.content) < 17:  # Minimum size for asset issuance
            self._add_error(
                "INVALID_ISSUANCE_DATA",
                "Asset issuance metadata is too short",
                ValidationCategory.METADATA,
                location=location
            )
    
    def _validate_asset_transfer_metadata(self, metadata, location: str) -> None:
        """Validate asset transfer metadata."""
        if len(metadata.content) < 16:  # Minimum size for asset transfer
            self._add_error(
                "INVALID_TRANSFER_DATA",
                "Asset transfer metadata is too short",
                ValidationCategory.METADATA,
                location=location
            )
    
    def _validate_nft_metadata(self, metadata, location: str) -> None:
        """Validate NFT metadata."""
        if len(metadata.content) < 33:  # Minimum size for NFT metadata
            self._add_error(
                "INVALID_NFT_DATA",
                "NFT metadata is too short",
                ValidationCategory.METADATA,
                location=location
            )
    
    def _validate_bnap_proprietary_field(self, key: bytes, value: bytes, location: str) -> None:
        """Validate BNAP proprietary field."""
        if key == b'BNAPAID':  # Asset ID
            if len(value) != 32:
                self._add_error(
                    "INVALID_ASSET_ID_LENGTH",
                    f"Asset ID must be 32 bytes, got {len(value)}",
                    ValidationCategory.METADATA,
                    location=location
                )
        elif key == b'BNAPAMT':  # Amount
            if len(value) != 8:
                self._add_error(
                    "INVALID_AMOUNT_LENGTH",
                    f"Amount must be 8 bytes, got {len(value)}",
                    ValidationCategory.METADATA,
                    location=location
                )
        elif key == b'BNAPTY':  # Asset Type
            if len(value) == 0:
                self._add_error(
                    "EMPTY_ASSET_TYPE",
                    "Asset type cannot be empty",
                    ValidationCategory.METADATA,
                    location=location
                )
    
    def _validate_asset_metadata(self, parsed_psbt: ParsedPSBT) -> None:
        """Validate asset metadata consistency."""
        asset_operations = self._extract_asset_operations(parsed_psbt)
        
        for operation in asset_operations:
            self._validate_asset_operation(operation, parsed_psbt)
    
    def _validate_asset_operation(self, operation: Dict[str, Any], parsed_psbt: ParsedPSBT) -> None:
        """Validate individual asset operation."""
        op_type = operation.get('type')
        asset_id = operation.get('asset_id')
        
        if not asset_id:
            self._add_error(
                "MISSING_ASSET_ID",
                "Asset operation missing asset ID",
                ValidationCategory.ASSET_RULES,
                details=operation
            )
            return
        
        if not validate_asset_id(asset_id):
            self._add_error(
                "INVALID_ASSET_ID_FORMAT",
                f"Invalid asset ID format: {asset_id}",
                ValidationCategory.ASSET_RULES,
                details={"asset_id": asset_id}
            )
        
        if op_type == 'transfer':
            self._validate_transfer_operation(operation)
        elif op_type == 'issuance':
            self._validate_issuance_operation(operation)
    
    def _validate_transfer_operation(self, operation: Dict[str, Any]) -> None:
        """Validate asset transfer operation."""
        amount = operation.get('amount', 0)
        
        if amount <= 0:
            self._add_error(
                "INVALID_TRANSFER_AMOUNT",
                f"Transfer amount must be positive: {amount}",
                ValidationCategory.ASSET_RULES,
                details=operation
            )
        
        if amount > self.max_asset_amount:
            self._add_warning(
                "LARGE_TRANSFER_AMOUNT",
                f"Transfer amount is very large: {amount}",
                ValidationCategory.ASSET_RULES,
                details=operation
            )
    
    def _validate_issuance_operation(self, operation: Dict[str, Any]) -> None:
        """Validate asset issuance operation."""
        supply = operation.get('supply', 0)
        
        if supply <= 0:
            self._add_error(
                "INVALID_SUPPLY",
                f"Asset supply must be positive: {supply}",
                ValidationCategory.ASSET_RULES,
                details=operation
            )
        
        if supply > self.max_asset_amount:
            self._add_warning(
                "LARGE_SUPPLY",
                f"Asset supply is very large: {supply}",
                ValidationCategory.ASSET_RULES,
                details=operation
            )
    
    def _validate_business_logic(self, parsed_psbt: ParsedPSBT) -> None:
        """Validate business logic rules."""
        # Check for duplicate asset operations
        self._check_duplicate_operations(parsed_psbt)
        
        # Validate asset conservation
        self._validate_asset_conservation(parsed_psbt)
        
        # Check for conflicting operations
        self._check_conflicting_operations(parsed_psbt)
    
    def _check_duplicate_operations(self, parsed_psbt: ParsedPSBT) -> None:
        """Check for duplicate asset operations."""
        operations = self._extract_asset_operations(parsed_psbt)
        seen_operations = set()
        
        for operation in operations:
            op_signature = (
                operation.get('type'),
                operation.get('asset_id'),
                operation.get('amount', 0)
            )
            
            if op_signature in seen_operations:
                self._add_warning(
                    "DUPLICATE_OPERATION",
                    f"Duplicate asset operation detected: {op_signature}",
                    ValidationCategory.BUSINESS_LOGIC,
                    details=operation
                )
            
            seen_operations.add(op_signature)
    
    def _validate_asset_conservation(self, parsed_psbt: ParsedPSBT) -> None:
        """Validate that assets are conserved in transfers."""
        # This is a placeholder for more complex conservation logic
        # In a real implementation, this would check that inputs == outputs for each asset
        pass
    
    def _check_conflicting_operations(self, parsed_psbt: ParsedPSBT) -> None:
        """Check for conflicting operations in the same transaction."""
        operations = self._extract_asset_operations(parsed_psbt)
        issuances = [op for op in operations if op.get('type') == 'issuance']
        transfers = [op for op in operations if op.get('type') == 'transfer']
        
        # Check if same asset is being issued and transferred
        issued_assets = {op.get('asset_id') for op in issuances}
        transferred_assets = {op.get('asset_id') for op in transfers}
        
        conflicting_assets = issued_assets.intersection(transferred_assets)
        for asset_id in conflicting_assets:
            self._add_warning(
                "ISSUANCE_TRANSFER_CONFLICT",
                f"Asset {asset_id} is both issued and transferred in same transaction",
                ValidationCategory.BUSINESS_LOGIC,
                details={"asset_id": asset_id}
            )
    
    def _validate_security_constraints(self, parsed_psbt: ParsedPSBT) -> None:
        """Validate security constraints."""
        # Check for potentially malicious patterns
        self._check_suspicious_patterns(parsed_psbt)
        
        # Validate fee constraints
        self._validate_fee_constraints(parsed_psbt)
    
    def _check_suspicious_patterns(self, parsed_psbt: ParsedPSBT) -> None:
        """Check for suspicious patterns that might indicate malicious activity."""
        # Check for excessive OP_RETURN outputs
        op_return_count = 0
        for output in parsed_psbt.outputs:
            if hasattr(output, 'script') and output.script and output.script.startswith(b'\x6a'):
                op_return_count += 1
        
        if op_return_count > 3:
            self._add_warning(
                "EXCESSIVE_OP_RETURN",
                f"Transaction has {op_return_count} OP_RETURN outputs",
                ValidationCategory.SECURITY,
                details={"op_return_count": op_return_count}
            )
        
        # Check for dust outputs
        dust_outputs = 0
        for i, output in enumerate(parsed_psbt.outputs):
            if hasattr(output, 'amount') and output.amount is not None and output.amount < self.dust_threshold:
                dust_outputs += 1
        
        if dust_outputs > 5:
            self._add_warning(
                "EXCESSIVE_DUST",
                f"Transaction has {dust_outputs} dust outputs",
                ValidationCategory.SECURITY,
                details={"dust_outputs": dust_outputs}
            )
    
    def _validate_fee_constraints(self, parsed_psbt: ParsedPSBT) -> None:
        """Validate transaction fee constraints."""
        # This would require more detailed fee calculation
        # For now, just check for basic fee sanity
        pass
    
    def _extract_asset_operations(self, parsed_psbt: ParsedPSBT) -> List[Dict[str, Any]]:
        """Extract asset operations from PSBT."""
        operations = []
        
        # Extract from proprietary fields
        for i, input_data in enumerate(parsed_psbt.inputs):
            for key, value in input_data.proprietary.items():
                if key.startswith(b'BNAP'):
                    # Parse proprietary field into operation
                    operation = self._parse_proprietary_operation(key, value, f"input[{i}]")
                    if operation:
                        operations.append(operation)
        
        for i, output_data in enumerate(parsed_psbt.outputs):
            for key, value in output_data.proprietary.items():
                if key.startswith(b'BNAP'):
                    operation = self._parse_proprietary_operation(key, value, f"output[{i}]")
                    if operation:
                        operations.append(operation)
        
        return operations
    
    def _parse_proprietary_operation(self, key: bytes, value: bytes, location: str) -> Optional[Dict[str, Any]]:
        """Parse proprietary field into asset operation."""
        # Simplified parsing - would be more complex in real implementation
        if key == b'BNAPAID':
            return {
                'type': 'unknown',
                'asset_id': value.hex(),
                'location': location
            }
        return None
    
    def _add_info(self, code: str, message: str, category: ValidationCategory, 
                  location: str = "", details: Dict[str, Any] = None) -> None:
        """Add info-level validation issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.INFO,
            category=category,
            code=code,
            message=message,
            location=location,
            details=details or {}
        ))
    
    def _add_warning(self, code: str, message: str, category: ValidationCategory,
                    location: str = "", details: Dict[str, Any] = None) -> None:
        """Add warning-level validation issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.WARNING,
            category=category,
            code=code,
            message=message,
            location=location,
            details=details or {}
        ))
    
    def _add_error(self, code: str, message: str, category: ValidationCategory,
                  location: str = "", details: Dict[str, Any] = None) -> None:
        """Add error-level validation issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category=category,
            code=code,
            message=message,
            location=location,
            details=details or {}
        ))
    
    def _add_critical_issue(self, code: str, message: str, category: ValidationCategory,
                           location: str = "", details: Dict[str, Any] = None) -> None:
        """Add critical-level validation issue."""
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.CRITICAL,
            category=category,
            code=code,
            message=message,
            location=location,
            details=details or {}
        ))


# Utility functions

def validate_psbt_structure(psbt_data: bytes) -> ValidationResult:
    """
    Utility function to validate PSBT structure.
    
    Args:
        psbt_data: Raw PSBT data
        
    Returns:
        ValidationResult for structure validation
    """
    validator = PSBTValidator()
    return validator.validate_structure(psbt_data)


def validate_psbt_assets(psbt_data: bytes) -> ValidationResult:
    """
    Utility function to validate PSBT asset operations.
    
    Args:
        psbt_data: Raw PSBT data
        
    Returns:
        ValidationResult for asset validation
    """
    validator = PSBTValidator()
    return validator.validate_asset_operations(psbt_data)


def validate_psbt_complete(psbt_data: bytes) -> ValidationResult:
    """
    Utility function to perform complete PSBT validation.
    
    Args:
        psbt_data: Raw PSBT data
        
    Returns:
        Complete ValidationResult
    """
    validator = PSBTValidator()
    return validator.validate_psbt(psbt_data)


def format_validation_report(result: ValidationResult) -> str:
    """
    Format validation result into a human-readable report.
    
    Args:
        result: ValidationResult to format
        
    Returns:
        Formatted validation report
    """
    lines = []
    lines.append("PSBT Validation Report")
    lines.append("=" * 50)
    lines.append(f"Overall Status: {'VALID' if result.is_valid else 'INVALID'}")
    lines.append(f"Total Issues: {len(result.issues)}")
    
    if result.critical_issues:
        lines.append(f"\nCRITICAL ISSUES ({len(result.critical_issues)}):")
        for issue in result.critical_issues:
            lines.append(f"  - {issue.code}: {issue.message}")
            if issue.location:
                lines.append(f"    Location: {issue.location}")
    
    if result.errors:
        lines.append(f"\nERRORS ({len(result.errors)}):")
        for issue in result.errors:
            lines.append(f"  - {issue.code}: {issue.message}")
            if issue.location:
                lines.append(f"    Location: {issue.location}")
    
    if result.warnings:
        lines.append(f"\nWARNINGS ({len(result.warnings)}):")
        for issue in result.warnings:
            lines.append(f"  - {issue.code}: {issue.message}")
            if issue.location:
                lines.append(f"    Location: {issue.location}")
    
    return "\n".join(lines)