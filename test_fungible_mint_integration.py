#!/usr/bin/env python3
"""
Integration test for Fungible Token Mint PSBT Construction
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from psbt.fungible_mint import FungibleMintPSBTBuilder, FungibleMintParameters


def test_fungible_mint_integration():
    """Test complete fungible mint PSBT construction workflow."""
    print("Testing Fungible Mint PSBT Integration...")
    
    # Create builder
    builder = FungibleMintPSBTBuilder(version=2, locktime=0)
    
    # Asset parameters
    asset_id = "1234567890abcdef" * 4  # 64-character hex string
    mint_amount = 1000000  # 1 million tokens
    recipient_script = bytes([0x00, 0x14]) + bytes(20)  # P2WPKH
    
    # Set mint parameters
    params = FungibleMintParameters(
        asset_id=asset_id,
        mint_amount=mint_amount,
        recipient_script=recipient_script,
        fee_rate=2
    )
    
    try:
        builder.set_mint_parameters(params)
        print(f"✓ Set mint parameters: {mint_amount} tokens of asset {asset_id[:16]}...")
    except Exception as e:
        print(f"✗ Failed to set parameters: {e}")
        return False
    
    # Build transaction
    validator_script = b'mock_validator_covenant_script_with_authorization_checks'
    validator_amount = 100000000  # 1 BTC
    fee_amount = 5000  # 0.00005 BTC
    
    try:
        builder.build_mint_transaction(
            validator_txid="a" * 64,
            validator_vout=0,
            validator_script=validator_script,
            validator_amount=validator_amount,
            fee_amount=fee_amount
        )
        print(f"✓ Built complete mint transaction")
    except Exception as e:
        print(f"✗ Failed to build transaction: {e}")
        return False
    
    # Validate transaction
    issues = builder.validate_mint_transaction()
    if issues:
        print(f"✗ Transaction validation failed: {issues}")
        return False
    else:
        print("✓ Transaction validation passed")
    
    # Get transaction summary
    summary = builder.get_mint_summary()
    print(f"✓ Transaction Summary:")
    print(f"  - Asset ID: {summary['asset_id'][:16]}...")
    print(f"  - Mint Amount: {summary['mint_amount']:,} tokens")
    print(f"  - Transaction ID: {summary['transaction_id'][:16]}...")
    print(f"  - Inputs: {summary['num_inputs']}")
    print(f"  - Outputs: {summary['num_outputs']}")
    print(f"  - Fee: {summary.get('fee', 'N/A')} satoshis")
    
    # Test serialization
    try:
        psbt_bytes = builder.serialize()
        psbt_b64 = builder.to_base64()
        print(f"✓ PSBT serialized: {len(psbt_bytes)} bytes, {len(psbt_b64)} chars base64")
        print(f"  - PSBT (first 50 chars): {psbt_b64[:50]}...")
    except Exception as e:
        print(f"✗ Serialization failed: {e}")
        return False
    
    # Test covenant script creation
    try:
        authorized_minter = b'x' * 33  # Mock public key
        max_supply = 21000000
        
        covenant = builder.create_covenant_script(
            asset_id,
            authorized_minter,
            max_supply
        )
        print(f"✓ Created covenant script: {len(covenant)} bytes")
    except Exception as e:
        print(f"✗ Covenant creation failed: {e}")
        return False
    
    return True


def test_error_handling():
    """Test error handling scenarios."""
    print("\nTesting Error Handling...")
    
    builder = FungibleMintPSBTBuilder()
    
    # Test invalid asset ID
    try:
        invalid_params = FungibleMintParameters(
            asset_id="invalid_asset_id",
            mint_amount=1000,
            recipient_script=bytes(22)
        )
        builder.set_mint_parameters(invalid_params)
        print("✗ Should have failed with invalid asset ID")
        return False
    except Exception:
        print("✓ Correctly rejected invalid asset ID")
    
    # Test building without parameters
    try:
        builder.build_mint_transaction(
            validator_txid="b" * 64,
            validator_vout=0,
            validator_script=b'script',
            validator_amount=100000000
        )
        print("✗ Should have failed without parameters")
        return False
    except Exception:
        print("✓ Correctly rejected build without parameters")
    
    # Test insufficient funds
    try:
        valid_params = FungibleMintParameters(
            asset_id="a" * 64,
            mint_amount=1000,
            recipient_script=bytes(22)
        )
        builder.set_mint_parameters(valid_params)
        
        builder.build_mint_transaction(
            validator_txid="c" * 64,
            validator_vout=0,
            validator_script=b'script',
            validator_amount=1000,  # Too small
            fee_amount=10000
        )
        print("✗ Should have failed with insufficient funds")
        return False
    except Exception:
        print("✓ Correctly detected insufficient funds")
    
    return True


def main():
    """Run integration tests."""
    print("Running Fungible Mint PSBT Integration Tests...\n")
    
    tests = [
        test_fungible_mint_integration,
        test_error_handling
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                print("✓ TEST PASSED\n")
                passed += 1
            else:
                print("✗ TEST FAILED\n")
                failed += 1
        except Exception as e:
            print(f"✗ TEST ERROR: {e}\n")
            failed += 1
    
    print(f"Integration Test Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)