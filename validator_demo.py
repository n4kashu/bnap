#!/usr/bin/env python3
"""
PSBT Validator Demonstration

This script demonstrates the PSBT validator functionality with various test scenarios.
"""

from psbt.validator import (
    PSBTValidator, 
    ValidationSeverity, 
    ValidationCategory,
    ValidationIssue,
    ValidationResult,
    format_validation_report
)

def demo_validation_basics():
    """Demonstrate basic validation functionality."""
    print("🔍 PSBT Validator Demo - Basic Functionality")
    print("=" * 50)
    
    # Test 1: Invalid PSBT data
    print("Test 1: Invalid PSBT data")
    validator = PSBTValidator()
    result = validator.validate_psbt(b'invalid_psbt_data')
    print(f"  Result: {'VALID' if result.is_valid else 'INVALID'}")
    print(f"  Critical issues: {len(result.critical_issues)}")
    if result.critical_issues:
        print(f"  Error: {result.critical_issues[0].message}")
    print()
    
    # Test 2: Empty data
    print("Test 2: Empty PSBT data")
    result = validator.validate_psbt(b'')
    print(f"  Result: {'VALID' if result.is_valid else 'INVALID'}")
    print(f"  Critical issues: {len(result.critical_issues)}")
    print()
    
    # Test 3: Partial PSBT magic
    print("Test 3: Partial PSBT data (just magic bytes)")
    result = validator.validate_psbt(b'psbt\xff')
    print(f"  Result: {'VALID' if result.is_valid else 'INVALID'}")
    print(f"  Critical issues: {len(result.critical_issues)}")
    print()


def demo_validation_categories():
    """Demonstrate different validation categories."""
    print("📊 PSBT Validator Demo - Validation Categories")
    print("=" * 50)
    
    # Create sample validation issues
    issues = [
        ValidationIssue(
            severity=ValidationSeverity.CRITICAL,
            category=ValidationCategory.STRUCTURE,
            code="PARSE_ERROR",
            message="Failed to parse PSBT data",
            location="global"
        ),
        ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category=ValidationCategory.METADATA,
            code="INVALID_ASSET_ID",
            message="Asset ID has invalid format",
            location="input[0]"
        ),
        ValidationIssue(
            severity=ValidationSeverity.WARNING,
            category=ValidationCategory.BUSINESS_LOGIC,
            code="DUPLICATE_OPERATION",
            message="Duplicate asset operation detected",
            location="output[1]"
        ),
        ValidationIssue(
            severity=ValidationSeverity.INFO,
            category=ValidationCategory.SECURITY,
            code="HIGH_FEE_RATE",
            message="Transaction fee rate is unusually high",
            location="global"
        )
    ]
    
    result = ValidationResult(is_valid=False, issues=issues)
    
    print("Sample validation result:")
    print(f"  Total issues: {len(result.issues)}")
    print(f"  Critical: {len(result.critical_issues)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Warnings: {len(result.warnings)}")
    print(f"  Overall valid: {result.is_valid}")
    print()
    
    # Show issues by category
    categories = {}
    for issue in issues:
        category = issue.category.value
        if category not in categories:
            categories[category] = []
        categories[category].append(issue)
    
    for category, cat_issues in categories.items():
        print(f"  {category.upper()} issues: {len(cat_issues)}")
        for issue in cat_issues:
            print(f"    - {issue.code}: {issue.message}")
    print()


def demo_validation_report():
    """Demonstrate validation report formatting."""
    print("📄 PSBT Validator Demo - Validation Report")
    print("=" * 50)
    
    # Create comprehensive validation result
    issues = [
        ValidationIssue(
            severity=ValidationSeverity.CRITICAL,
            category=ValidationCategory.STRUCTURE,
            code="MISSING_GLOBAL",
            message="PSBT missing global data section",
            location="global"
        ),
        ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category=ValidationCategory.METADATA,
            code="INVALID_ASSET_ID_LENGTH",
            message="Asset ID must be 32 bytes, got 16",
            location="input[0]",
            details={"expected": 32, "actual": 16}
        ),
        ValidationIssue(
            severity=ValidationSeverity.ERROR,
            category=ValidationCategory.STRUCTURE,
            code="NO_OUTPUTS",
            message="PSBT must have at least one output",
            location="global"
        ),
        ValidationIssue(
            severity=ValidationSeverity.WARNING,
            category=ValidationCategory.SECURITY,
            code="EXCESSIVE_DUST",
            message="Transaction has 8 dust outputs",
            location="global",
            details={"dust_outputs": 8}
        ),
        ValidationIssue(
            severity=ValidationSeverity.WARNING,
            category=ValidationCategory.BUSINESS_LOGIC,
            code="HIGH_SUPPLY",
            message="Asset supply is very large: 1000000000000",
            location="output[0]"
        )
    ]
    
    result = ValidationResult(is_valid=False, issues=issues)
    report = format_validation_report(result)
    
    print(report)
    print()


def demo_validator_configuration():
    """Demonstrate validator configuration options."""
    print("⚙️  PSBT Validator Demo - Configuration Options")
    print("=" * 50)
    
    validator = PSBTValidator()
    
    print("Default configuration:")
    print(f"  Max inputs: {validator.max_inputs}")
    print(f"  Max outputs: {validator.max_outputs}")
    print(f"  Max OP_RETURN size: {validator.max_op_return_size} bytes")
    print(f"  Dust threshold: {validator.dust_threshold} satoshis")
    print(f"  Max asset amount: {validator.max_asset_amount:,}")
    print()
    
    # Custom configuration
    validator.max_inputs = 50
    validator.max_outputs = 75
    validator.dust_threshold = 1000
    
    print("Custom configuration:")
    print(f"  Max inputs: {validator.max_inputs}")
    print(f"  Max outputs: {validator.max_outputs}")
    print(f"  Dust threshold: {validator.dust_threshold} satoshis")
    print()


def demo_utility_functions():
    """Demonstrate utility functions."""
    print("🛠️  PSBT Validator Demo - Utility Functions")
    print("=" * 50)
    
    # Test utility imports
    from psbt.validator import (
        validate_psbt_structure,
        validate_psbt_assets,
        validate_psbt_complete
    )
    
    print("Available utility functions:")
    print("  - validate_psbt_structure(psbt_data)")
    print("  - validate_psbt_assets(psbt_data)")
    print("  - validate_psbt_complete(psbt_data)")
    print("  - format_validation_report(result)")
    print()
    
    # Test with invalid data
    test_data = b'invalid'
    
    print("Testing with invalid PSBT data:")
    
    structure_result = validate_psbt_structure(test_data)
    print(f"  Structure validation: {'VALID' if structure_result.is_valid else 'INVALID'}")
    
    asset_result = validate_psbt_assets(test_data)
    print(f"  Asset validation: {'VALID' if asset_result.is_valid else 'INVALID'}")
    
    complete_result = validate_psbt_complete(test_data)
    print(f"  Complete validation: {'VALID' if complete_result.is_valid else 'INVALID'}")
    print()


def main():
    """Run all demonstrations."""
    print("🚀 PSBT Validator Comprehensive Demo")
    print("=" * 60)
    print()
    
    try:
        demo_validation_basics()
        demo_validation_categories() 
        demo_validation_report()
        demo_validator_configuration()
        demo_utility_functions()
        
        print("✅ All demonstrations completed successfully!")
        print()
        print("The PSBT Validator provides:")
        print("  • Comprehensive structure validation")
        print("  • Asset metadata validation") 
        print("  • Business logic validation")
        print("  • Security constraint checking")
        print("  • Detailed error reporting")
        print("  • Configurable validation parameters")
        print("  • Multiple validation modes")
        
    except Exception as e:
        print(f"❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()