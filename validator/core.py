"""
BNAP Validator Core Engine

This module provides the main ValidationEngine class that orchestrates all validation
operations for Bitcoin Native Asset Protocol transactions and PSBTs.

The ValidationEngine acts as the central coordinator for:
- Asset rule enforcement
- Supply limit validation
- Per-mint cap checking
- Allowlist verification
- NFT content hash validation
- PSBT signing authorization
"""

import logging
import time
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import json
import hashlib

# Import from existing modules
from psbt.parser import PSBTParser
from psbt.exceptions import PSBTError
from registry.manager import RegistryManager
from registry.schema import AssetType
from crypto.commitments import OperationType
from crypto.keys import PrivateKey, PublicKey
from crypto.signatures import verify_ecdsa, verify_schnorr


class ValidationResult(Enum):
    """Validation result codes."""
    APPROVED = "approved"
    REJECTED = "rejected"
    PENDING = "pending"
    ERROR = "error"


class ValidationError(Exception):
    """Base exception for validation errors."""
    pass


class RuleViolationError(ValidationError):
    """Raised when a validation rule is violated."""
    pass


class ConfigurationError(ValidationError):
    """Raised when validator configuration is invalid."""
    pass


@dataclass
class ValidationContext:
    """
    Context object passed between validation rules.
    
    Contains all necessary information for validating a transaction,
    including parsed PSBT data, registry state, and configuration.
    """
    # Transaction data
    psbt_data: Dict[str, Any]
    transaction_hex: Optional[str] = None
    
    # Asset information
    asset_id: Optional[bytes] = None
    asset_type: Optional[AssetType] = None
    operation: Optional[OperationType] = None
    amount: Optional[int] = None
    
    # NFT specific
    collection_id: Optional[int] = None
    token_id: Optional[int] = None
    content_hash: Optional[bytes] = None
    metadata: Optional[Union[str, Dict[str, Any]]] = None
    
    # Registry state
    current_supply: Optional[int] = None
    supply_cap: Optional[int] = None
    per_mint_cap: Optional[int] = None
    allowlist_root: Optional[bytes] = None
    
    # Validation state
    validation_errors: List[str] = field(default_factory=list)
    validation_warnings: List[str] = field(default_factory=list)
    rule_results: Dict[str, bool] = field(default_factory=dict)
    
    # Metadata
    timestamp: Optional[int] = None
    validator_id: Optional[str] = None
    
    def add_error(self, rule_name: str, message: str):
        """Add a validation error."""
        self.validation_errors.append(f"{rule_name}: {message}")
        self.rule_results[rule_name] = False
    
    def add_warning(self, rule_name: str, message: str):
        """Add a validation warning."""
        self.validation_warnings.append(f"{rule_name}: {message}")
    
    def mark_rule_passed(self, rule_name: str):
        """Mark a validation rule as passed."""
        self.rule_results[rule_name] = True
    
    def has_errors(self) -> bool:
        """Check if validation has errors."""
        return len(self.validation_errors) > 0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get validation summary."""
        return {
            "asset_id": self.asset_id.hex() if self.asset_id else None,
            "asset_type": self.asset_type.value if self.asset_type else None,
            "operation": self.operation.value if self.operation else None,
            "amount": self.amount,
            "errors": self.validation_errors,
            "warnings": self.validation_warnings,
            "rules_passed": sum(1 for passed in self.rule_results.values() if passed),
            "rules_total": len(self.rule_results),
            "validation_result": ValidationResult.APPROVED.value if not self.has_errors() else ValidationResult.REJECTED.value
        }


class ValidationRule(ABC):
    """
    Abstract base class for validation rules.
    
    Each validation rule implements specific logic for checking
    different aspects of asset transactions.
    """
    
    def __init__(self, name: str, description: str, enabled: bool = True):
        self.name = name
        self.description = description
        self.enabled = enabled
        self.logger = logging.getLogger(f"validator.rules.{name}")
    
    @abstractmethod
    def validate(self, context: ValidationContext) -> bool:
        """
        Validate the transaction context.
        
        Args:
            context: Validation context containing transaction data
            
        Returns:
            True if validation passes, False otherwise
        """
        pass
    
    def is_applicable(self, context: ValidationContext) -> bool:
        """
        Check if this rule applies to the given context.
        
        Override this method to implement rule-specific applicability logic.
        
        Args:
            context: Validation context
            
        Returns:
            True if this rule should be applied
        """
        return self.enabled


class ValidationEngine:
    """
    Main validation engine that orchestrates all validation operations.
    
    The ValidationEngine coordinates between different validation rules,
    manages configuration, and provides the main API for validating
    asset transactions and PSBTs.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the validation engine.
        
        Args:
            config: Configuration dictionary for the validator
        """
        self.config = config or {}
        self.logger = logging.getLogger("validator.engine")
        
        # Initialize components
        self.psbt_parser = PSBTParser()
        self.registry_manager = None
        self.signing_keys: Dict[str, PrivateKey] = {}
        
        # Validation rules
        self.rules: List[ValidationRule] = []
        self.rule_registry: Dict[str, ValidationRule] = {}
        
        # Statistics
        self.validation_stats = {
            "total_validations": 0,
            "approved_validations": 0,
            "rejected_validations": 0,
            "error_validations": 0
        }
        
        self._load_configuration()
        self._initialize_components()
    
    def _load_configuration(self):
        """Load validator configuration."""
        self.logger.info("Loading validator configuration")
        
        # Set default configuration values
        defaults = {
            "validator_id": "bnap_validator_v1",
            "max_validation_time": 30,  # seconds
            "enable_audit_logging": True,
            "require_allowlist": False,
            "max_supply_cap": 21_000_000,  # Maximum allowed supply cap
            "max_per_mint_cap": 1_000_000,  # Maximum allowed per-mint cap
        }
        
        # Merge with provided config
        for key, value in defaults.items():
            if key not in self.config:
                self.config[key] = value
    
    def _initialize_components(self):
        """Initialize validator components."""
        self.logger.info("Initializing validator components")
        
        # Initialize registry manager if not provided
        if not self.registry_manager:
            try:
                self.registry_manager = RegistryManager()
            except Exception as e:
                self.logger.warning(f"Failed to initialize registry manager: {e}")
        
        # Load signing keys from configuration
        self._load_signing_keys()
        
        # Register default validation rules
        self._register_default_rules()
    
    def _load_signing_keys(self):
        """Load signing keys from configuration."""
        signing_keys_config = self.config.get("signing_keys", {})
        
        for key_id, key_data in signing_keys_config.items():
            try:
                if isinstance(key_data, str):
                    # Assume hex-encoded private key
                    private_key = PrivateKey(bytes.fromhex(key_data))
                elif isinstance(key_data, dict):
                    # More complex key configuration
                    key_bytes = bytes.fromhex(key_data["private_key"])
                    private_key = PrivateKey(key_bytes)
                else:
                    continue
                
                self.signing_keys[key_id] = private_key
                self.logger.info(f"Loaded signing key: {key_id}")
                
            except Exception as e:
                self.logger.error(f"Failed to load signing key {key_id}: {e}")
    
    def _register_default_rules(self):
        """Register default validation rules."""
        self.logger.info("Registering default validation rules")
        
        # Import here to avoid circular imports
        from .rules.supply_limit import SupplyLimitRule
        from .rules.mint_limits import MintLimitRule
        from .rules.allowlist import AllowlistRule
        from .rules.content_hash import ContentHashRule
        
        # Register implemented rules
        self.register_rule(SupplyLimitRule())
        self.register_rule(MintLimitRule())
        self.register_rule(AllowlistRule())
        self.register_rule(ContentHashRule())
        
        # Placeholder for remaining rule registrations - will be implemented in subtasks
    
    def register_rule(self, rule: ValidationRule):
        """
        Register a validation rule.
        
        Args:
            rule: Validation rule to register
        """
        if rule.name in self.rule_registry:
            self.logger.warning(f"Rule {rule.name} already registered, replacing")
        
        self.rules.append(rule)
        self.rule_registry[rule.name] = rule
        self.logger.info(f"Registered validation rule: {rule.name}")
    
    def unregister_rule(self, rule_name: str) -> bool:
        """
        Unregister a validation rule.
        
        Args:
            rule_name: Name of the rule to unregister
            
        Returns:
            True if rule was found and removed
        """
        if rule_name in self.rule_registry:
            rule = self.rule_registry[rule_name]
            self.rules.remove(rule)
            del self.rule_registry[rule_name]
            self.logger.info(f"Unregistered validation rule: {rule_name}")
            return True
        
        return False
    
    def validate_mint_transaction(self, psbt_hex: str, **kwargs) -> ValidationContext:
        """
        Validate a mint transaction PSBT.
        
        Args:
            psbt_hex: Hex-encoded PSBT data
            **kwargs: Additional validation parameters
            
        Returns:
            ValidationContext containing validation results
        """
        self.logger.info("Starting mint transaction validation")
        self.validation_stats["total_validations"] += 1
        
        try:
            # Parse PSBT
            psbt_data = self.psbt_parser.parse(psbt_hex)
            
            # Create validation context
            context = self._create_validation_context(psbt_data, **kwargs)
            
            # Extract transaction information
            self._extract_transaction_info(context)
            
            # Load registry state
            self._load_registry_state(context)
            
            # Apply validation rules
            self._apply_validation_rules(context)
            
            # Update statistics
            if context.has_errors():
                self.validation_stats["rejected_validations"] += 1
                self.logger.info(f"Transaction validation rejected: {len(context.validation_errors)} errors")
            else:
                self.validation_stats["approved_validations"] += 1
                self.logger.info("Transaction validation approved")
            
            return context
            
        except Exception as e:
            self.validation_stats["error_validations"] += 1
            self.logger.error(f"Validation error: {e}")
            
            # Create error context
            context = ValidationContext(psbt_data={})
            context.add_error("engine", f"Validation engine error: {str(e)}")
            return context
    
    def validate_psbt(self, psbt_hex: str, **kwargs) -> ValidationContext:
        """
        Validate any PSBT (mint, transfer, burn, etc.).
        
        Args:
            psbt_hex: Hex-encoded PSBT data
            **kwargs: Additional validation parameters
            
        Returns:
            ValidationContext containing validation results
        """
        # For now, delegate to mint validation
        # In the future, this will route to different validators based on operation type
        return self.validate_mint_transaction(psbt_hex, **kwargs)
    
    def process_validation_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a validation request from external systems.
        
        Args:
            request: Validation request containing PSBT and parameters
            
        Returns:
            Validation response with results
        """
        self.logger.info("Processing validation request")
        
        try:
            # Extract request parameters
            psbt_hex = request.get("psbt")
            if not psbt_hex:
                raise ValidationError("No PSBT provided in request")
            
            # Perform validation
            context = self.validate_psbt(psbt_hex, **request.get("parameters", {}))
            
            # Format response
            response = {
                "status": "success",
                "validation_result": context.get_summary(),
                "timestamp": context.timestamp,
                "validator_id": self.config["validator_id"]
            }
            
            return response
            
        except Exception as e:
            self.logger.error(f"Request processing error: {e}")
            return {
                "status": "error",
                "error": str(e),
                "validator_id": self.config["validator_id"]
            }
    
    def _create_validation_context(self, psbt_data: Dict[str, Any], **kwargs) -> ValidationContext:
        """Create validation context from PSBT data and parameters."""
        import time
        
        context = ValidationContext(
            psbt_data=psbt_data,
            timestamp=int(time.time()),
            validator_id=self.config["validator_id"]
        )
        
        # Add any additional parameters from kwargs
        for key, value in kwargs.items():
            if hasattr(context, key):
                setattr(context, key, value)
        
        return context
    
    def _extract_transaction_info(self, context: ValidationContext):
        """Extract transaction information from PSBT."""
        try:
            # Extract basic transaction info from PSBT
            psbt_data = context.psbt_data
            
            # Look for OP_RETURN outputs that might contain asset information
            outputs = psbt_data.get("outputs", [])
            for output in outputs:
                # Check for BNAP OP_RETURN data
                script_pubkey = output.get("script_pubkey", "")
                if script_pubkey.startswith("6a"):  # OP_RETURN
                    # Try to decode asset information
                    # This is a simplified extraction - actual implementation
                    # would use the OP_RETURN encoder/decoder
                    pass
            
            # For now, use placeholder values
            # In a complete implementation, this would parse the actual PSBT
            context.asset_type = AssetType.FUNGIBLE  # Default assumption
            context.operation = OperationType.MINT   # Default assumption
            
        except Exception as e:
            context.add_error("extraction", f"Failed to extract transaction info: {e}")
    
    def _load_registry_state(self, context: ValidationContext):
        """Load relevant registry state for validation."""
        if not self.registry_manager or not context.asset_id:
            return
        
        try:
            # Load asset state from registry
            asset_state = self.registry_manager.get_asset_state(context.asset_id)
            if asset_state:
                context.current_supply = asset_state.get("current_supply", 0)
                context.supply_cap = asset_state.get("supply_cap")
                context.per_mint_cap = asset_state.get("per_mint_cap")
                context.allowlist_root = asset_state.get("allowlist_root")
            
        except Exception as e:
            context.add_warning("registry", f"Failed to load registry state: {e}")
    
    def _apply_validation_rules(self, context: ValidationContext):
        """Apply all applicable validation rules."""
        self.logger.debug(f"Applying {len(self.rules)} validation rules")
        
        for rule in self.rules:
            if not rule.is_applicable(context):
                self.logger.debug(f"Skipping rule {rule.name} - not applicable")
                continue
            
            try:
                self.logger.debug(f"Applying rule: {rule.name}")
                result = rule.validate(context)
                
                if result:
                    context.mark_rule_passed(rule.name)
                    self.logger.debug(f"Rule {rule.name} passed")
                else:
                    self.logger.debug(f"Rule {rule.name} failed")
                
            except Exception as e:
                context.add_error(rule.name, f"Rule execution error: {e}")
                self.logger.error(f"Rule {rule.name} execution error: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get validation statistics."""
        return {
            **self.validation_stats,
            "registered_rules": len(self.rules),
            "signing_keys": len(self.signing_keys)
        }
    
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration (without sensitive data)."""
        safe_config = self.config.copy()
        
        # Remove sensitive information
        if "signing_keys" in safe_config:
            safe_config["signing_keys"] = {
                key_id: "***REDACTED***" 
                for key_id in safe_config["signing_keys"]
            }
        
        return safe_config
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of validator components."""
        health = {
            "status": "healthy",
            "components": {},
            "timestamp": int(time.time())
        }
        
        # Check PSBT parser
        try:
            # Basic test
            health["components"]["psbt_parser"] = "healthy"
        except Exception as e:
            health["components"]["psbt_parser"] = f"error: {e}"
            health["status"] = "degraded"
        
        # Check registry manager
        try:
            if self.registry_manager:
                health["components"]["registry_manager"] = "healthy"
            else:
                health["components"]["registry_manager"] = "not_configured"
        except Exception as e:
            health["components"]["registry_manager"] = f"error: {e}"
            health["status"] = "degraded"
        
        # Check signing keys
        health["components"]["signing_keys"] = f"loaded: {len(self.signing_keys)}"
        
        # Check validation rules
        health["components"]["validation_rules"] = f"registered: {len(self.rules)}"
        
        return health


# Utility functions for validation

def create_default_validator(config: Optional[Dict[str, Any]] = None) -> ValidationEngine:
    """
    Create a ValidationEngine with default configuration.
    
    Args:
        config: Optional configuration overrides
        
    Returns:
        Configured ValidationEngine instance
    """
    default_config = {
        "validator_id": "bnap_default_validator",
        "enable_audit_logging": True,
        "max_validation_time": 30
    }
    
    if config:
        default_config.update(config)
    
    return ValidationEngine(default_config)


def validate_psbt_quick(psbt_hex: str, config: Optional[Dict[str, Any]] = None) -> bool:
    """
    Quick PSBT validation for simple use cases.
    
    Args:
        psbt_hex: Hex-encoded PSBT data
        config: Optional validator configuration
        
    Returns:
        True if validation passes
    """
    validator = create_default_validator(config)
    context = validator.validate_psbt(psbt_hex)
    return not context.has_errors()