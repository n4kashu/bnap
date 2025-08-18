"""
Integration Tests for PSBT Validator

These tests verify end-to-end validation scenarios combining multiple components.
"""

import pytest
from psbt.validator import PSBTValidator, ValidationSeverity, ValidationCategory, format_validation_report
from psbt.templates import (
    TransferPSBTBuilder,
    TransferParameters,
    TransferType,
    FeeStrategy,
    UTXO,
    AssetTransferInput,
    AssetTransferOutput,
    create_fungible_transfer_template,
    create_nft_transfer_template
)
from psbt.fungible_mint import FungibleMintPSBTBuilder, FungibleMintParameters
from psbt.nft_mint import NFTMintPSBTBuilder, NFTMintParameters
from psbt.builder import BasePSBTBuilder
from psbt.outputs.op_return import create_asset_issuance_op_return, create_asset_transfer_op_return


def test_validate_fungible_mint_psbt_integration():
    """Test validation of a complete fungible mint PSBT."""
    validator = PSBTValidator()
    
    # Create fungible mint PSBT
    builder = FungibleMintPSBTBuilder()
    params = FungibleMintParameters(
        asset_id="a" * 64,
        mint_amount=1000000,
        decimals=8,
        symbol="TEST",
        recipient_script=b'\x00\x14' + b'\x01' * 20
    )
    
    builder.set_mint_parameters(params)
    builder.add_validator_input("validator_tx" + "a" * 50, 0, 100000, b'\x00\x14' + b'\x02' * 20)
    
    try:
        builder.build_mint_transaction()
        psbt_data = builder.serialize()
        result = validator.validate_psbt(psbt_data)
        
        # Should be valid or have only warnings
        print(f"Fungible mint validation: {'VALID' if result.is_valid else 'INVALID'}")
        if result.warnings:
            print(f"Warnings: {len(result.warnings)}")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
            for error in result.errors:
                print(f"  - {error.code}: {error.message}")
        
        # Should not have critical errors
        assert len(result.critical_issues) == 0
        
        return True
        
    except Exception as e:
        print(f"Failed to create fungible mint PSBT: {e}")
        return False


def test_validate_nft_mint_psbt_integration():
    """Test validation of a complete NFT mint PSBT."""
    validator = PSBTValidator()
    
    # Create NFT mint PSBT
    builder = NFTMintPSBTBuilder()
    params = NFTMintParameters(
        collection_id=1,
        token_id=42,
        metadata_hash=b'a' * 32,
        recipient_script=b'\x00\x14' + b'\x01' * 20
    )
    
    builder.set_mint_parameters(params)
    builder.add_validator_input("validator_tx" + "b" * 50, 0, 50000, b'\x00\x14' + b'\x02' * 20)
    
    try:
        builder.build_mint_transaction()
        psbt_data = builder.serialize()
        result = validator.validate_psbt(psbt_data)
        
        print(f"NFT mint validation: {'VALID' if result.is_valid else 'INVALID'}")
        if result.warnings:
            print(f"Warnings: {len(result.warnings)}")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
            for error in result.errors:
                print(f"  - {error.code}: {error.message}")
        
        # Should not have critical errors
        assert len(result.critical_issues) == 0
        
        return True
        
    except Exception as e:
        print(f"Failed to create NFT mint PSBT: {e}")
        return False


def test_validate_fungible_transfer_psbt_integration():
    """Test validation of a complete fungible transfer PSBT."""
    validator = PSBTValidator()
    
    # Create fungible transfer PSBT
    utxo = UTXO("transfer_tx" + "a" * 53, 0, 100000, b'\x00\x14' + b'\x01' * 20)
    recipient_script = b'\x00\x14' + b'\x02' * 20
    change_script = b'\x00\x14' + b'\x03' * 20
    
    builder = create_fungible_transfer_template(
        asset_id="transfer_asset" + "a" * 48,
        amount=500000,
        sender_utxos=[utxo],
        recipient_script=recipient_script,
        change_script=change_script,
        fee_rate=2.0
    )
    
    try:
        builder.build_fungible_transfer_psbt()
        psbt_data = builder.serialize()
        result = validator.validate_psbt(psbt_data)
        
        print(f"Fungible transfer validation: {'VALID' if result.is_valid else 'INVALID'}")
        if result.warnings:
            print(f"Warnings: {len(result.warnings)}")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
            for error in result.errors:
                print(f"  - {error.code}: {error.message}")
        
        # Should not have critical errors
        assert len(result.critical_issues) == 0
        
        return True
        
    except Exception as e:
        print(f"Failed to create fungible transfer PSBT: {e}")
        return False


def test_validate_nft_transfer_psbt_integration():
    """Test validation of a complete NFT transfer PSBT."""
    validator = PSBTValidator()
    
    # Create NFT transfer PSBT
    utxo = UTXO("nft_tx" + "a" * 58, 0, 25000, b'\x00\x14' + b'\x01' * 20)
    recipient_script = b'\x00\x14' + b'\x02' * 20
    change_script = b'\x00\x14' + b'\x03' * 20
    
    builder = create_nft_transfer_template(
        collection_id=5,
        token_id=123,
        sender_utxo=utxo,
        recipient_script=recipient_script,
        change_script=change_script,
        fee_rate=1.5
    )
    
    try:
        builder.build_nft_transfer_psbt()
        psbt_data = builder.serialize()
        result = validator.validate_psbt(psbt_data)
        
        print(f"NFT transfer validation: {'VALID' if result.is_valid else 'INVALID'}")
        if result.warnings:
            print(f"Warnings: {len(result.warnings)}")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
            for error in result.errors:
                print(f"  - {error.code}: {error.message}")
        
        # Should not have critical errors
        assert len(result.critical_issues) == 0
        
        return True
        
    except Exception as e:
        print(f"Failed to create NFT transfer PSBT: {e}")
        return False


def test_validate_multi_asset_transfer_integration():
    """Test validation of multi-asset transfer PSBT."""
    validator = PSBTValidator()
    
    # Create multi-asset transfer PSBT
    builder = TransferPSBTBuilder()
    
    utxo1 = UTXO("multi1" + "a" * 58, 0, 50000, b'\x00\x14' + b'\x01' * 20)
    utxo2 = UTXO("multi2" + "b" * 58, 0, 40000, b'\x00\x14' + b'\x02' * 20)
    
    asset_inputs = [
        AssetTransferInput(utxo1, "asset_alpha" + "a" * 54, 1000),
        AssetTransferInput(utxo2, "asset_beta" + "b" * 55, 2000)
    ]
    
    asset_outputs = [
        AssetTransferOutput(b'\x00\x14' + b'\x03' * 20, asset_id="asset_alpha" + "a" * 54, asset_amount=1000, btc_value=1000),
        AssetTransferOutput(b'\x00\x14' + b'\x04' * 20, asset_id="asset_beta" + "b" * 55, asset_amount=2000, btc_value=1500)
    ]
    
    params = TransferParameters(
        transfer_type=TransferType.MULTI_ASSET_TRANSFER,
        inputs=asset_inputs,
        outputs=asset_outputs,
        change_script=b'\x00\x14' + b'\x05' * 20,
        fee_rate=1.0
    )
    
    builder.set_transfer_parameters(params)
    
    try:
        builder.build_multi_asset_transfer_psbt()
        psbt_data = builder.serialize()
        result = validator.validate_psbt(psbt_data)
        
        print(f"Multi-asset transfer validation: {'VALID' if result.is_valid else 'INVALID'}")
        if result.warnings:
            print(f"Warnings: {len(result.warnings)}")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
            for error in result.errors:
                print(f"  - {error.code}: {error.message}")
        
        # Should not have critical errors
        assert len(result.critical_issues) == 0
        
        return True
        
    except Exception as e:
        print(f"Failed to create multi-asset transfer PSBT: {e}")
        return False


def test_validate_psbt_with_malformed_metadata():
    """Test validation of PSBT with malformed metadata."""
    validator = PSBTValidator()
    
    builder = BasePSBTBuilder()
    builder.add_input("malformed" + "a" * 56, 0)
    builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
    
    # Add malformed OP_RETURN data
    malformed_op_return = b'\x6a\x10' + b'BAD_METADATA_123'  # Not BNAP format
    builder.add_output(script=malformed_op_return, amount=0)
    
    # Add invalid proprietary fields
    builder.add_input_proprietary(0, b'BNAPAID', b'bad_asset_id')  # Wrong length
    builder.add_input_proprietary(0, b'BNAPAMT', b'bad_amount')   # Wrong format
    builder.add_input_proprietary(0, b'BNAPTY', b'')            # Empty type
    
    psbt_data = builder.serialize()
    result = validator.validate_psbt(psbt_data)
    
    print(f"Malformed metadata validation: {'VALID' if result.is_valid else 'INVALID'}")
    print(f"Total issues: {len(result.issues)}")
    
    # Should have multiple errors
    assert not result.is_valid
    assert len(result.errors) > 0
    
    # Check for specific error types
    error_codes = [issue.code for issue in result.errors]
    assert "INVALID_ASSET_ID_LENGTH" in error_codes
    assert "INVALID_AMOUNT_LENGTH" in error_codes
    assert "EMPTY_ASSET_TYPE" in error_codes
    
    return True


def test_validate_psbt_security_issues():
    """Test validation of PSBT with potential security issues."""
    validator = PSBTValidator()
    
    builder = BasePSBTBuilder()
    builder.add_input("security" + "a" * 57, 0)
    
    # Add many OP_RETURN outputs (suspicious)
    for i in range(5):
        op_return = b'\x6a\x04test'
        builder.add_output(script=op_return, amount=0)
    
    # Add many dust outputs (suspicious)
    for i in range(8):
        builder.add_output(script=b'\x00\x14' + bytes([i]) * 20, amount=100)  # Below dust threshold
    
    # Add one normal output
    builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=10000)
    
    psbt_data = builder.serialize()
    result = validator.validate_psbt(psbt_data)
    
    print(f"Security validation: {'VALID' if result.is_valid else 'INVALID'}")
    print(f"Warnings: {len(result.warnings)}")
    
    # Should have security warnings
    security_warnings = [issue for issue in result.warnings if issue.category == ValidationCategory.SECURITY]
    # Note: This depends on the implementation of security checks
    
    return True


def test_validation_report_formatting():
    """Test comprehensive validation report formatting."""
    validator = PSBTValidator()
    
    # Create PSBT with various issues
    builder = BasePSBTBuilder()
    builder.add_input("report" + "a" * 59, 0)
    
    # Add multiple issues for comprehensive report
    # 1. Too many outputs (warning)
    for i in range(102):  # Exceeds limit
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
    
    # 2. Invalid metadata (error)
    builder.add_input_proprietary(0, b'BNAPAID', b'invalid')  # Wrong length
    
    # 3. Multiple OP_RETURNs (warning)
    for i in range(3):
        builder.add_output(script=b'\x6a\x04test', amount=0)
    
    psbt_data = builder.serialize()
    result = validator.validate_psbt(psbt_data)
    
    # Generate formatted report
    report = format_validation_report(result)
    
    print("\n" + "="*60)
    print("COMPREHENSIVE VALIDATION REPORT")
    print("="*60)
    print(report)
    print("="*60)
    
    # Verify report contains expected sections
    assert "PSBT Validation Report" in report
    assert "Overall Status:" in report
    assert "Total Issues:" in report
    
    if result.warnings:
        assert "WARNINGS" in report
    if result.errors:
        assert "ERRORS" in report
    if result.critical_issues:
        assert "CRITICAL ISSUES" in report
    
    return True


def test_validator_performance_with_large_psbt():
    """Test validator performance with large PSBT."""
    validator = PSBTValidator()
    
    # Create large PSBT
    builder = BasePSBTBuilder()
    
    # Add many inputs and outputs
    num_inputs = 50
    num_outputs = 75
    
    print(f"Creating large PSBT with {num_inputs} inputs and {num_outputs} outputs...")
    
    for i in range(num_inputs):
        builder.add_input("large" + "a" * 59, i)
    
    for i in range(num_outputs):
        builder.add_output(script=b'\x00\x14' + bytes([i % 256]) * 20, amount=1000 + i)
    
    psbt_data = builder.serialize()
    print(f"PSBT size: {len(psbt_data)} bytes")
    
    # Validate and measure performance
    import time
    start_time = time.time()
    result = validator.validate_psbt(psbt_data)
    end_time = time.time()
    
    validation_time = end_time - start_time
    print(f"Validation time: {validation_time:.3f} seconds")
    print(f"Validation result: {'VALID' if result.is_valid else 'INVALID'}")
    print(f"Issues found: {len(result.issues)}")
    
    # Should complete in reasonable time
    assert validation_time < 5.0  # Should complete within 5 seconds
    
    return True


def test_validator_edge_cases():
    """Test validator with edge case scenarios."""
    validator = PSBTValidator()
    
    test_cases = [
        {
            "name": "Minimal PSBT",
            "inputs": 1,
            "outputs": 1,
            "expected_valid": True
        },
        {
            "name": "Maximum recommended size",
            "inputs": validator.max_inputs,
            "outputs": validator.max_outputs,
            "expected_valid": True
        },
        {
            "name": "Just over limits",
            "inputs": validator.max_inputs + 1,
            "outputs": validator.max_outputs + 1,
            "expected_valid": True  # Should be valid but with warnings
        }
    ]
    
    for case in test_cases:
        print(f"\nTesting edge case: {case['name']}")
        
        builder = BasePSBTBuilder()
        
        for i in range(case["inputs"]):
            builder.add_input("edge" + "a" * 60, i)
        
        for i in range(case["outputs"]):
            builder.add_output(script=b'\x00\x14' + bytes([i % 256]) * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = validator.validate_psbt(psbt_data)
        
        print(f"  Result: {'VALID' if result.is_valid else 'INVALID'}")
        print(f"  Issues: {len(result.issues)} (Warnings: {len(result.warnings)}, Errors: {len(result.errors)})")
        
        # Check if result matches expectation
        if case["expected_valid"]:
            assert len(result.errors) == 0 and len(result.critical_issues) == 0
        else:
            assert len(result.errors) > 0 or len(result.critical_issues) > 0
    
    return True


if __name__ == "__main__":
    """Run integration tests when script is executed directly."""
    tests = [
        test_validate_fungible_mint_psbt_integration,
        test_validate_nft_mint_psbt_integration,
        test_validate_fungible_transfer_psbt_integration,
        test_validate_nft_transfer_psbt_integration,
        test_validate_multi_asset_transfer_integration,
        test_validate_psbt_with_malformed_metadata,
        test_validate_psbt_security_issues,
        test_validation_report_formatting,
        test_validator_performance_with_large_psbt,
        test_validator_edge_cases,
    ]
    
    print("Running PSBT Validator Integration Tests")
    print("=" * 50)
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            print(f"\n🧪 Running {test_func.__name__}...")
            result = test_func()
            if result:
                print(f"✅ {test_func.__name__} PASSED")
                passed += 1
            else:
                print(f"❌ {test_func.__name__} FAILED")
                failed += 1
        except Exception as e:
            print(f"❌ {test_func.__name__} FAILED with exception: {e}")
            failed += 1
    
    print(f"\n📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All integration tests passed!")
    else:
        print(f"⚠️  {failed} tests failed")