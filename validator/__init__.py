"""
BNAP Validator Module

This module provides comprehensive validation logic for Bitcoin Native Asset Protocol
transactions, including asset rule enforcement, supply limit checking, allowlist
verification, and PSBT signing authorization.
"""

from .core import (
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

from .rules import (
    SupplyLimitRule,
    MintLimitRule
)

__all__ = [
    "ValidationEngine",
    "ValidationContext", 
    "ValidationRule",
    "ValidationResult",
    "ValidationError",
    "RuleViolationError",
    "ConfigurationError",
    "create_default_validator",
    "validate_psbt_quick",
    "SupplyLimitRule",
    "MintLimitRule"
]