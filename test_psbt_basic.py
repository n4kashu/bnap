#!/usr/bin/env python3
"""
Basic test script for PSBT builder functionality.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from psbt.builder import BasePSBTBuilder
from psbt.utils import create_op_return_script, validate_asset_id


def test_basic_psbt_construction():
    """Test basic PSBT construction."""
    print("Testing basic PSBT construction...")
    
    # Create PSBT builder
    builder = BasePSBTBuilder(version=2, locktime=0)
    
    # Add an input (mock UTXO)
    builder.add_input(
        txid="a" * 64,
        vout=0,
        sequence=0xfffffffe,
        witness_utxo=b"mock_witness_utxo_data"
    )
    
    # Add an output
    builder.add_output(
        script=create_op_return_script(b"BNAP test"),
        amount=0
    )
    
    # Add another output (change)
    builder.add_output(
        script=bytes.fromhex("0014") + b"x" * 20,  # P2WPKH
        amount=100000000  # 1 BTC
    )
    
    # Validate structure
    issues = builder.validate_structure()
    if issues:
        print(f"Validation issues: {issues}")
        return False
    
    # Serialize to base64
    try:
        psbt_b64 = builder.to_base64()
        print(f"PSBT serialized successfully. Length: {len(psbt_b64)} characters")
        print(f"PSBT (first 100 chars): {psbt_b64[:100]}...")
        return True
    except Exception as e:
        print(f"Serialization failed: {e}")
        return False


def test_asset_id_validation():
    """Test asset ID validation."""
    print("Testing asset ID validation...")
    
    # Valid asset IDs
    valid_ids = [
        "a" * 64,
        "1234567890abcdef" * 4,
        "0" * 64
    ]
    
    for asset_id in valid_ids:
        if not validate_asset_id(asset_id):
            print(f"Failed: {asset_id} should be valid")
            return False
    
    # Invalid asset IDs
    invalid_ids = [
        "a" * 63,  # Too short
        "a" * 65,  # Too long
        "g" * 64,  # Invalid hex
        "",        # Empty
        123,       # Not string
    ]
    
    for asset_id in invalid_ids:
        if validate_asset_id(asset_id):
            print(f"Failed: {asset_id} should be invalid")
            return False
    
    print("Asset ID validation tests passed")
    return True


def test_proprietary_fields():
    """Test proprietary field handling."""
    print("Testing proprietary fields...")
    
    builder = BasePSBTBuilder()
    
    # Add global proprietary field
    builder.add_global_proprietary(b"test_key", b"test_value")
    
    # Add input and output for proprietary fields
    builder.add_input(txid="b" * 64, vout=0, witness_utxo=b"mock")
    builder.add_output(script=b"\x6a\x00", amount=0)  # Empty OP_RETURN
    
    # Add proprietary fields
    builder.add_input_proprietary(0, b"input_key", b"input_value")
    builder.add_output_proprietary(0, b"output_key", b"output_value")
    
    # Verify fields were added
    if builder.global_proprietary.get(b"test_key") != b"test_value":
        print("Failed: Global proprietary field not set correctly")
        return False
    
    if builder.psbt_inputs[0].proprietary.get(b"input_key") != b"input_value":
        print("Failed: Input proprietary field not set correctly")
        return False
    
    if builder.psbt_outputs[0].proprietary.get(b"output_key") != b"output_value":
        print("Failed: Output proprietary field not set correctly")
        return False
    
    print("Proprietary field tests passed")
    return True


def main():
    """Run all tests."""
    print("Running PSBT builder tests...\n")
    
    tests = [
        test_asset_id_validation,
        test_proprietary_fields,
        test_basic_psbt_construction,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                print("✓ PASSED\n")
                passed += 1
            else:
                print("✗ FAILED\n")
                failed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}\n")
            failed += 1
    
    print(f"Test Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)