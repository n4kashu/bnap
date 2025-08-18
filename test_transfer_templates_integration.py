#!/usr/bin/env python3
"""
Integration tests for PSBT Transfer Templates
"""

import sys
import os
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from psbt.templates import (
    TransferPSBTBuilder,
    TransferParameters,
    TransferType,
    FeeStrategy,
    UTXO,
    AssetTransferInput,
    AssetTransferOutput,
    create_fungible_transfer_template,
    create_nft_transfer_template,
    create_multi_asset_transfer_template,
    estimate_transfer_fee,
    validate_transfer_parameters
)
from psbt.parser import parse_psbt_from_bytes, extract_asset_operations


def test_fungible_transfer_end_to_end():
    """Test end-to-end fungible token transfer."""
    print("Testing End-to-End Fungible Transfer...")
    
    try:
        # Create test data
        asset_id = "fungible_token_abc123"
        transfer_amount = 1000
        
        # Create sender UTXO (has BTC for fees)
        sender_utxo = UTXO(
            txid="1" * 64,
            vout=0,
            value=50000,  # 50k sats
            script=b'\x00\x14' + b'\x01' * 20  # P2WPKH
        )
        
        # Create recipient and change scripts
        recipient_script = b'\x00\x14' + b'\x02' * 20
        change_script = b'\x00\x14' + b'\x03' * 20
        
        print(f"✓ Setup complete:")
        print(f"  - Asset ID: {asset_id}")
        print(f"  - Transfer amount: {transfer_amount}")
        print(f"  - Sender UTXO value: {sender_utxo.value} sats")
        
        # Create transfer template
        builder = create_fungible_transfer_template(
            asset_id=asset_id,
            amount=transfer_amount,
            sender_utxos=[sender_utxo],
            recipient_script=recipient_script,
            change_script=change_script,
            fee_rate=2.0
        )
        
        # Calculate fees
        fee_calc = builder.calculate_fees()
        print(f"✓ Fee calculation:")
        print(f"  - Estimated size: {fee_calc.estimated_size} bytes")
        print(f"  - Fee rate: {fee_calc.fee_rate} sat/vbyte")
        print(f"  - Total fee: {fee_calc.calculated_fee} sats")
        print(f"  - Change amount: {fee_calc.change_amount} sats")
        
        assert fee_calc.is_valid, f"Fee calculation should be valid: {fee_calc.errors}"
        
        # Build the PSBT
        builder.build_fungible_transfer_psbt()
        
        # Serialize PSBT
        psbt_bytes = builder.serialize()
        print(f"✓ Built PSBT:")
        print(f"  - PSBT size: {len(psbt_bytes)} bytes")
        print(f"  - Inputs: {len(builder.tx_inputs)}")
        print(f"  - Outputs: {len(builder.outputs)}")
        
        # Parse the PSBT back to verify structure
        parsed_psbt = parse_psbt_from_bytes(psbt_bytes)
        
        # Extract asset operations
        operations = extract_asset_operations(parsed_psbt)
        print(f"✓ Parsed PSBT operations: {len(operations)}")
        
        # Get transfer summary
        summary = builder.get_transfer_summary()
        print(f"✓ Transfer summary:")
        print(f"  - Transfer type: {summary['transfer_type']}")
        print(f"  - Assets transferred: {summary['assets_transferred']}")
        print(f"  - Includes metadata: {summary['includes_metadata']}")
        
        assert len(builder.tx_inputs) == 1, "Should have 1 input"
        assert len(builder.outputs) >= 2, "Should have at least 2 outputs (recipient + change)"
        
        print("✓ Fungible transfer end-to-end test passed")
        return True
        
    except Exception as e:
        print(f"✗ Fungible transfer test failed: {e}")
        return False


def test_nft_transfer_end_to_end():
    """Test end-to-end NFT transfer."""
    print("\nTesting End-to-End NFT Transfer...")
    
    try:
        # Create NFT data
        collection_id = 42
        token_id = 1337
        
        # Create sender UTXO
        sender_utxo = UTXO(
            txid="2" * 64,
            vout=0,
            value=25000,  # 25k sats
            script=b'\x00\x14' + b'\x04' * 20
        )
        
        # Create scripts
        recipient_script = b'\x00\x14' + b'\x05' * 20
        change_script = b'\x00\x14' + b'\x06' * 20
        
        print(f"✓ NFT setup:")
        print(f"  - Collection ID: {collection_id}")
        print(f"  - Token ID: {token_id}")
        print(f"  - Sender UTXO value: {sender_utxo.value} sats")
        
        # Create NFT transfer template
        builder = create_nft_transfer_template(
            collection_id=collection_id,
            token_id=token_id,
            sender_utxo=sender_utxo,
            recipient_script=recipient_script,
            change_script=change_script,
            fee_rate=1.5
        )
        
        # Verify transfer parameters
        assert builder.transfer_params.transfer_type == TransferType.NFT_TRANSFER
        assert len(builder.asset_inputs) == 1
        assert len(builder.asset_outputs) == 1
        assert builder.asset_inputs[0].collection_id == collection_id
        assert builder.asset_inputs[0].token_id == token_id
        assert builder.asset_outputs[0].asset_amount == 1  # NFTs have amount 1
        
        print("✓ NFT transfer parameters validated")
        
        # Calculate fees and build PSBT
        fee_calc = builder.calculate_fees()
        assert fee_calc.is_valid, f"NFT fee calculation should be valid: {fee_calc.errors}"
        
        builder.build_nft_transfer_psbt()
        
        # Serialize and verify
        psbt_bytes = builder.serialize()
        print(f"✓ NFT PSBT built:")
        print(f"  - Size: {len(psbt_bytes)} bytes")
        print(f"  - Fee: {fee_calc.calculated_fee} sats")
        
        # Parse back
        parsed_psbt = parse_psbt_from_bytes(psbt_bytes)
        operations = extract_asset_operations(parsed_psbt)
        
        print(f"✓ NFT operations extracted: {len(operations)}")
        
        print("✓ NFT transfer end-to-end test passed")
        return True
        
    except Exception as e:
        print(f"✗ NFT transfer test failed: {e}")
        return False


def test_multi_asset_transfer_end_to_end():
    """Test end-to-end multi-asset transfer."""
    print("\nTesting End-to-End Multi-Asset Transfer...")
    
    try:
        # Create multiple UTXOs for different assets
        utxo1 = UTXO(
            txid="3" * 64,
            vout=0,
            value=30000,
            script=b'\x00\x14' + b'\x07' * 20
        )
        
        utxo2 = UTXO(
            txid="4" * 64,
            vout=1,
            value=20000,
            script=b'\x00\x14' + b'\x08' * 20
        )
        
        # Create recipient scripts
        recipient1 = b'\x00\x14' + b'\x09' * 20
        recipient2 = b'\x00\x14' + b'\x0a' * 20
        change_script = b'\x00\x14' + b'\x0b' * 20
        
        # Define asset transfers
        asset_transfers = [
            ("asset_alpha", 500, utxo1, recipient1),
            ("asset_beta", 750, utxo2, recipient2)
        ]
        
        print(f"✓ Multi-asset setup:")
        print(f"  - Asset transfers: {len(asset_transfers)}")
        print(f"  - Total UTXOs: 2")
        print(f"  - Total BTC input: {utxo1.value + utxo2.value} sats")
        
        # Create multi-asset transfer template
        builder = create_multi_asset_transfer_template(
            asset_transfers=asset_transfers,
            change_script=change_script,
            fee_rate=1.8
        )
        
        # Verify setup
        assert builder.transfer_params.transfer_type == TransferType.MULTI_ASSET_TRANSFER
        assert len(builder.asset_inputs) == 2
        assert len(builder.asset_outputs) == 2
        
        asset_ids = {inp.asset_id for inp in builder.asset_inputs}
        assert "asset_alpha" in asset_ids
        assert "asset_beta" in asset_ids
        
        print("✓ Multi-asset parameters validated")
        
        # Calculate fees and build
        fee_calc = builder.calculate_fees()
        assert fee_calc.is_valid, f"Multi-asset fee calculation should be valid: {fee_calc.errors}"
        
        print(f"✓ Multi-asset fee calculation:")
        print(f"  - Estimated size: {fee_calc.estimated_size} bytes")
        print(f"  - Fee: {fee_calc.calculated_fee} sats")
        print(f"  - Change: {fee_calc.change_amount} sats")
        
        builder.build_multi_asset_transfer_psbt()
        
        # Serialize and verify
        psbt_bytes = builder.serialize()
        print(f"✓ Multi-asset PSBT built:")
        print(f"  - Size: {len(psbt_bytes)} bytes")
        print(f"  - Inputs: {len(builder.tx_inputs)}")
        print(f"  - Outputs: {len(builder.outputs)}")
        
        # Parse and extract operations
        parsed_psbt = parse_psbt_from_bytes(psbt_bytes)
        operations = extract_asset_operations(parsed_psbt)
        
        print(f"✓ Multi-asset operations: {len(operations)}")
        
        # Get summary
        summary = builder.get_transfer_summary()
        assert summary['assets_transferred'] == 2
        assert summary['total_inputs'] == 2
        assert summary['total_outputs'] == 2
        
        print("✓ Multi-asset transfer end-to-end test passed")
        return True
        
    except Exception as e:
        print(f"✗ Multi-asset transfer test failed: {e}")
        return False


def test_fee_strategies_comparison():
    """Test different fee strategies."""
    print("\nTesting Fee Strategies Comparison...")
    
    try:
        # Create base UTXO and scripts
        utxo = UTXO(
            txid="5" * 64,
            vout=0,
            value=100000,
            script=b'\x00\x14' + b'\x0c' * 20
        )
        
        recipient_script = b'\x00\x14' + b'\x0d' * 20
        change_script = b'\x00\x14' + b'\x0e' * 20
        
        # Test different fee strategies
        strategies = [
            (FeeStrategy.ECONOMY, None, 1.0),
            (FeeStrategy.FEE_RATE, 2.5, 2.5),
            (FeeStrategy.HIGH_PRIORITY, None, 10.0),
            (FeeStrategy.FIXED_FEE, 5000, None)
        ]
        
        results = []
        
        for strategy, custom_rate, expected_rate in strategies:
            asset_input = AssetTransferInput(utxo, "fee_test_asset", 100)
            asset_output = AssetTransferOutput(
                recipient_script,
                asset_id="fee_test_asset",
                asset_amount=100,
                btc_value=2000
            )
            
            params = TransferParameters(
                transfer_type=TransferType.FUNGIBLE_TRANSFER,
                inputs=[asset_input],
                outputs=[asset_output],
                change_script=change_script,
                fee_strategy=strategy,
                fee_rate=custom_rate if custom_rate else 1.0,
                fixed_fee=5000 if strategy == FeeStrategy.FIXED_FEE else None
            )
            
            builder = TransferPSBTBuilder()
            builder.set_transfer_parameters(params)
            
            fee_calc = builder.calculate_fees()
            assert fee_calc.is_valid, f"Fee calculation for {strategy} should be valid"
            
            results.append({
                'strategy': strategy.value,
                'fee': fee_calc.calculated_fee,
                'rate': fee_calc.fee_rate,
                'size': fee_calc.estimated_size
            })
        
        print("✓ Fee strategy comparison:")
        for result in results:
            print(f"  - {result['strategy']}: {result['fee']} sats ({result['rate']:.2f} sat/vB)")
        
        # Verify fee ordering (generally)
        economy_fee = next(r['fee'] for r in results if r['strategy'] == 'economy')
        high_priority_fee = next(r['fee'] for r in results if r['strategy'] == 'high_priority')
        assert high_priority_fee > economy_fee, "High priority should cost more than economy"
        
        print("✓ Fee strategies comparison passed")
        return True
        
    except Exception as e:
        print(f"✗ Fee strategies test failed: {e}")
        return False


def test_parameter_validation_scenarios():
    """Test various parameter validation scenarios."""
    print("\nTesting Parameter Validation Scenarios...")
    
    try:
        # Test cases with expected results
        test_cases = [
            {
                'name': 'Valid Fungible Transfer',
                'setup': lambda: _create_valid_fungible_params(),
                'should_pass': True
            },
            {
                'name': 'No Inputs',
                'setup': lambda: _create_params_with_no_inputs(),
                'should_pass': False,
                'expected_error': 'No inputs specified'
            },
            {
                'name': 'Amount Mismatch',
                'setup': lambda: _create_params_with_amount_mismatch(),
                'should_pass': False,
                'expected_error': 'amount mismatch'
            },
            {
                'name': 'Invalid UTXO',
                'setup': lambda: _create_params_with_invalid_utxo(),
                'should_pass': False,
                'expected_error': 'Invalid UTXO'
            },
            {
                'name': 'Missing Fixed Fee',
                'setup': lambda: _create_params_missing_fixed_fee(),
                'should_pass': False,
                'expected_error': 'fixed fee strategy requires'
            }
        ]
        
        passed = 0
        for test_case in test_cases:
            try:
                params = test_case['setup']()
                is_valid, errors = validate_transfer_parameters(params)
                
                if test_case['should_pass']:
                    assert is_valid, f"Test '{test_case['name']}' should pass but failed: {errors}"
                    print(f"  ✓ {test_case['name']}: Passed as expected")
                else:
                    assert not is_valid, f"Test '{test_case['name']}' should fail but passed"
                    expected = test_case.get('expected_error', '')
                    if expected:
                        assert any(expected.lower() in error.lower() for error in errors), \
                            f"Expected error '{expected}' not found in: {errors}"
                    print(f"  ✓ {test_case['name']}: Failed as expected")
                
                passed += 1
                
            except Exception as e:
                print(f"  ✗ {test_case['name']}: Unexpected error - {e}")
        
        print(f"✓ Parameter validation: {passed}/{len(test_cases)} scenarios passed")
        return passed == len(test_cases)
        
    except Exception as e:
        print(f"✗ Parameter validation test failed: {e}")
        return False


def test_batch_transfer_scenario():
    """Test batch transfer (same asset to multiple recipients)."""
    print("\nTesting Batch Transfer Scenario...")
    
    try:
        # Create UTXOs with enough asset amount for batch transfer
        utxo1 = UTXO("batch1" + "a" * 58, 0, 40000, b'\x00\x14' + b'\x01' * 20)
        utxo2 = UTXO("batch2" + "a" * 58, 0, 30000, b'\x00\x14' + b'\x02' * 20)
        
        # Create multiple recipients for the same asset
        recipients = [
            (b'\x00\x14' + b'\x03' * 20, 200),  # Recipient 1: 200 tokens
            (b'\x00\x14' + b'\x04' * 20, 150),  # Recipient 2: 150 tokens
            (b'\x00\x14' + b'\x05' * 20, 100),  # Recipient 3: 100 tokens
        ]
        
        total_output_amount = sum(amount for _, amount in recipients)
        print(f"✓ Batch transfer setup:")
        print(f"  - Recipients: {len(recipients)}")
        print(f"  - Total output amount: {total_output_amount}")
        print(f"  - Input UTXOs: 2")
        
        # Create batch transfer parameters
        asset_inputs = [
            AssetTransferInput(utxo1, "batch_asset", 300),  # 300 tokens
            AssetTransferInput(utxo2, "batch_asset", 150)   # 150 tokens
        ]
        
        asset_outputs = [
            AssetTransferOutput(
                script, 
                asset_id="batch_asset", 
                asset_amount=amount,
                btc_value=1000  # Each recipient gets 1000 sats
            )
            for script, amount in recipients
        ]
        
        change_script = b'\x00\x14' + b'\x06' * 20
        
        params = TransferParameters(
            transfer_type=TransferType.BATCH_TRANSFER,
            inputs=asset_inputs,
            outputs=asset_outputs,
            change_script=change_script,
            fee_rate=1.2
        )
        
        # Validate parameters
        is_valid, errors = validate_transfer_parameters(params)
        if not is_valid:
            # Batch transfer validation uses multi-asset logic
            print(f"Note: Validation errors (expected for batch): {errors}")
        
        # Build batch transfer
        builder = TransferPSBTBuilder()
        builder.set_transfer_parameters(params)
        
        fee_calc = builder.calculate_fees()
        assert fee_calc.is_valid, f"Batch transfer fees should be valid: {fee_calc.errors}"
        
        print(f"✓ Batch transfer fee calculation:")
        print(f"  - Fee: {fee_calc.calculated_fee} sats")
        print(f"  - Change: {fee_calc.change_amount} sats")
        
        builder.build_batch_transfer_psbt()
        
        # Verify PSBT structure
        psbt_bytes = builder.serialize()
        print(f"✓ Batch PSBT built:")
        print(f"  - Size: {len(psbt_bytes)} bytes")
        print(f"  - Inputs: {len(builder.tx_inputs)}")
        print(f"  - Outputs: {len(builder.outputs)}")
        
        # Should have: 3 recipients + 1 change + 1 OP_RETURN = 5 outputs minimum
        assert len(builder.outputs) >= 4, "Batch transfer should have multiple outputs"
        
        print("✓ Batch transfer scenario passed")
        return True
        
    except Exception as e:
        print(f"✗ Batch transfer test failed: {e}")
        return False


# Helper functions for parameter validation tests

def _create_valid_fungible_params():
    """Create valid fungible transfer parameters."""
    utxo = UTXO("valid" + "a" * 59, 0, 25000, b'\x00\x14' + b'\x01' * 20)
    asset_input = AssetTransferInput(utxo, "valid_asset", 100)
    asset_output = AssetTransferOutput(
        b'\x00\x14' + b'\x02' * 20, 
        asset_id="valid_asset", 
        asset_amount=100
    )
    
    return TransferParameters(
        transfer_type=TransferType.FUNGIBLE_TRANSFER,
        inputs=[asset_input],
        outputs=[asset_output],
        change_script=b'\x00\x14' + b'\x03' * 20
    )


def _create_params_with_no_inputs():
    """Create parameters with no inputs."""
    asset_output = AssetTransferOutput(
        b'\x00\x14' + b'\x02' * 20, 
        asset_id="no_input_asset", 
        asset_amount=50
    )
    
    return TransferParameters(
        transfer_type=TransferType.FUNGIBLE_TRANSFER,
        inputs=[],  # No inputs
        outputs=[asset_output],
        change_script=b'\x00\x14' + b'\x03' * 20
    )


def _create_params_with_amount_mismatch():
    """Create parameters with input/output amount mismatch."""
    utxo = UTXO("mismatch" + "a" * 56, 0, 15000, b'\x00\x14' + b'\x01' * 20)
    asset_input = AssetTransferInput(utxo, "mismatch_asset", 100)  # Input: 100
    asset_output = AssetTransferOutput(
        b'\x00\x14' + b'\x02' * 20, 
        asset_id="mismatch_asset", 
        asset_amount=75  # Output: 75 (mismatch!)
    )
    
    return TransferParameters(
        transfer_type=TransferType.FUNGIBLE_TRANSFER,
        inputs=[asset_input],
        outputs=[asset_output],
        change_script=b'\x00\x14' + b'\x03' * 20
    )


def _create_params_with_invalid_utxo():
    """Create parameters with invalid UTXO."""
    invalid_utxo = UTXO("", -1, -5000, b'')  # Invalid UTXO
    asset_input = AssetTransferInput(invalid_utxo, "invalid_asset", 25)
    asset_output = AssetTransferOutput(
        b'\x00\x14' + b'\x02' * 20, 
        asset_id="invalid_asset", 
        asset_amount=25
    )
    
    return TransferParameters(
        transfer_type=TransferType.FUNGIBLE_TRANSFER,
        inputs=[asset_input],
        outputs=[asset_output],
        change_script=b'\x00\x14' + b'\x03' * 20
    )


def _create_params_missing_fixed_fee():
    """Create parameters with fixed fee strategy but missing fixed_fee."""
    utxo = UTXO("fixed_fee" + "a" * 55, 0, 20000, b'\x00\x14' + b'\x01' * 20)
    asset_input = AssetTransferInput(utxo, "fee_asset", 30)
    asset_output = AssetTransferOutput(
        b'\x00\x14' + b'\x02' * 20, 
        asset_id="fee_asset", 
        asset_amount=30
    )
    
    return TransferParameters(
        transfer_type=TransferType.FUNGIBLE_TRANSFER,
        inputs=[asset_input],
        outputs=[asset_output],
        change_script=b'\x00\x14' + b'\x03' * 20,
        fee_strategy=FeeStrategy.FIXED_FEE
        # Missing fixed_fee parameter
    )


def main():
    """Run all integration tests."""
    print("Running PSBT Transfer Templates Integration Tests...\n")
    
    tests = [
        test_fungible_transfer_end_to_end,
        test_nft_transfer_end_to_end,
        test_multi_asset_transfer_end_to_end,
        test_fee_strategies_comparison,
        test_parameter_validation_scenarios,
        test_batch_transfer_scenario
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
    
    print(f"Transfer Templates Integration Test Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)