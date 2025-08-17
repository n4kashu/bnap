#!/usr/bin/env python3
"""
Integration test for P2WSH Output Construction Module
"""

import sys
import os
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from psbt.outputs.p2wsh import (
    WitnessScriptBuilder,
    CovenantScriptBuilder,
    P2WSHBuilder,
    create_p2wsh_output,
    create_validator_script,
    create_multisig_script,
    create_asset_commitment_script,
    validate_witness_script,
    calculate_script_hash
)


def test_basic_p2wsh_construction():
    """Test basic P2WSH construction workflow."""
    print("Testing Basic P2WSH Construction...")
    
    # Test data
    validator_pubkey = b'\x02' + b'\x01' * 32  # Mock compressed pubkey
    builder = P2WSHBuilder()
    
    try:
        # Create validator P2WSH output
        p2wsh_script, witness_script, script_hash = builder.create_validator_output(
            validator_pubkey, amount=100000000  # 1 BTC
        )
        
        print(f"✓ Created validator P2WSH output:")
        print(f"  - P2WSH script: {len(p2wsh_script)} bytes")
        print(f"  - Witness script: {len(witness_script)} bytes")
        print(f"  - Script hash: {script_hash.hex()[:16]}...")
        
        # Verify script structure
        assert len(p2wsh_script) == 34, "P2WSH script should be 34 bytes"
        assert p2wsh_script[0] == 0x00, "Should start with OP_0"
        assert p2wsh_script[1] == 0x20, "Should push 32 bytes"
        assert len(script_hash) == 32, "Script hash should be 32 bytes"
        
        # Verify witness script contains expected components
        assert validator_pubkey in witness_script, "Should contain validator pubkey"
        assert witness_script[-1] == 0xac, "Should end with OP_CHECKSIG"
        
        print("✓ Validator P2WSH output validation passed")
        
    except Exception as e:
        print(f"✗ Basic P2WSH construction failed: {e}")
        return False
    
    return True


def test_multisig_p2wsh_construction():
    """Test multisig P2WSH construction."""
    print("\nTesting Multisig P2WSH Construction...")
    
    # Test data
    pubkey1 = b'\x02' + b'\x01' * 32
    pubkey2 = b'\x03' + b'\x02' * 32
    pubkey3 = b'\x02' + b'\x03' * 32
    public_keys = [pubkey1, pubkey2, pubkey3]
    
    builder = P2WSHBuilder()
    
    try:
        # Create 2-of-3 multisig P2WSH output
        p2wsh_script, witness_script, script_hash = builder.create_multisig_output(
            2, public_keys, amount=50000000  # 0.5 BTC
        )
        
        print(f"✓ Created 2-of-3 multisig P2WSH output:")
        print(f"  - Required signatures: 2")
        print(f"  - Total keys: {len(public_keys)}")
        print(f"  - Witness script: {len(witness_script)} bytes")
        print(f"  - Script hash: {script_hash.hex()[:16]}...")
        
        # Verify all public keys are in the script
        for i, pubkey in enumerate(public_keys):
            assert pubkey in witness_script, f"Should contain pubkey {i+1}"
        
        # Verify script ends with OP_CHECKMULTISIG
        assert witness_script[-1] == 0xae, "Should end with OP_CHECKMULTISIG"
        
        # Test script validation
        assert validate_witness_script(witness_script), "Witness script should be valid"
        
        print("✓ Multisig P2WSH output validation passed")
        
    except Exception as e:
        print(f"✗ Multisig P2WSH construction failed: {e}")
        return False
    
    return True


def test_covenant_p2wsh_construction():
    """Test covenant P2WSH construction with asset validation."""
    print("\nTesting Covenant P2WSH Construction...")
    
    # Test data
    validator_pubkey = b'\x02' + b'\x01' * 32
    asset_id = "deadbeefcafebabe" * 4  # 64-character hex string
    max_supply = 21000000
    
    builder = P2WSHBuilder()
    
    try:
        # Create covenant P2WSH output with supply limit
        p2wsh_script, witness_script, script_hash = builder.create_covenant_output(
            asset_id, 
            validator_pubkey, 
            amount=10000000,  # 0.1 BTC
            max_supply=max_supply
        )
        
        print(f"✓ Created covenant P2WSH output:")
        print(f"  - Asset ID: {asset_id[:16]}...")
        print(f"  - Max supply: {max_supply:,}")
        print(f"  - Witness script: {len(witness_script)} bytes")
        print(f"  - Script hash: {script_hash.hex()[:16]}...")
        
        # Verify asset ID is in the script
        asset_id_bytes = bytes.fromhex(asset_id)
        assert asset_id_bytes in witness_script, "Should contain asset ID"
        
        # Verify validator pubkey is in the script
        assert validator_pubkey in witness_script, "Should contain validator pubkey"
        
        # Verify supply limit validation opcodes
        assert bytes([0xa4]) in witness_script, "Should contain OP_LESSTHANOREQUAL"
        assert bytes([0x9a]) in witness_script, "Should contain OP_BOOLAND"
        
        # Test using standalone function
        covenant_script = create_asset_commitment_script(asset_id, validator_pubkey, max_supply)
        assert validate_witness_script(covenant_script), "Covenant script should be valid"
        
        print("✓ Covenant P2WSH output validation passed")
        
    except Exception as e:
        print(f"✗ Covenant P2WSH construction failed: {e}")
        return False
    
    return True


def test_htlc_p2wsh_construction():
    """Test Hash Time Locked Contract P2WSH construction."""
    print("\nTesting HTLC P2WSH Construction...")
    
    # Test data
    secret = b"my_secret_preimage_for_htlc_test"
    hash_lock = hashlib.sha256(secret).digest()
    validator_pubkey = b'\x02' + b'\x01' * 32
    timeout = 500000  # Block height
    
    builder = P2WSHBuilder()
    
    try:
        # Create HTLC P2WSH output
        p2wsh_script, witness_script, script_hash = builder.create_htlc_output(
            hash_lock, 
            validator_pubkey, 
            timeout, 
            amount=25000000  # 0.25 BTC
        )
        
        print(f"✓ Created HTLC P2WSH output:")
        print(f"  - Hash lock: {hash_lock.hex()[:16]}...")
        print(f"  - Timeout: block {timeout}")
        print(f"  - Witness script: {len(witness_script)} bytes")
        print(f"  - Script hash: {script_hash.hex()[:16]}...")
        
        # Verify hash lock is in the script
        assert hash_lock in witness_script, "Should contain hash lock"
        
        # Verify validator pubkey is in the script
        assert validator_pubkey in witness_script, "Should contain validator pubkey"
        
        # Verify conditional opcodes
        assert bytes([0xa8]) in witness_script, "Should contain OP_SHA256"
        assert bytes([0x63]) in witness_script, "Should contain OP_IF"
        assert bytes([0x67]) in witness_script, "Should contain OP_ELSE"
        assert bytes([0x68]) in witness_script, "Should contain OP_ENDIF"
        
        # Verify timeout validation
        assert bytes([0xb1]) in witness_script, "Should contain OP_CHECKLOCKTIMEVERIFY"
        
        print("✓ HTLC P2WSH output validation passed")
        
    except Exception as e:
        print(f"✗ HTLC P2WSH construction failed: {e}")
        return False
    
    return True


def test_witness_script_builder_advanced():
    """Test advanced witness script builder functionality."""
    print("\nTesting Advanced Witness Script Builder...")
    
    builder = WitnessScriptBuilder()
    
    try:
        # Test number encoding
        builder.reset()
        builder.push_number(0)
        script = builder.build()
        assert script == bytes([0x00]), "Should encode 0 as OP_0"
        
        builder.reset()
        builder.push_number(1)
        script = builder.build()
        assert script == bytes([0x51]), "Should encode 1 as OP_1"
        
        builder.reset()
        builder.push_number(16)
        script = builder.build()
        assert script == bytes([0x60]), "Should encode 16 as OP_16"
        
        print("✓ Number encoding tests passed")
        
        # Test data push opcodes
        builder.reset()
        small_data = b'test'
        builder.push_data(small_data)
        script = builder.build()
        assert script == bytes([len(small_data)]) + small_data, "Should use direct push"
        
        builder.reset()
        medium_data = b'x' * 100
        builder.push_data(medium_data)
        script = builder.build()
        assert script.startswith(bytes([0x4c, len(medium_data)])), "Should use OP_PUSHDATA1"
        
        print("✓ Data push opcode tests passed")
        
        # Test timelock script
        validator_pubkey = b'\x02' + b'\x01' * 32
        locktime = 500000
        
        timelock_script = builder.create_timelock_script(validator_pubkey, locktime)
        assert validator_pubkey in timelock_script, "Should contain validator pubkey"
        assert bytes([0xb1]) in timelock_script, "Should contain OP_CHECKLOCKTIMEVERIFY"
        assert bytes([0x75]) in timelock_script, "Should contain OP_DROP"
        assert bytes([0xac]) in timelock_script, "Should contain OP_CHECKSIG"
        
        print("✓ Timelock script construction passed")
        
        # Test sequence-based timelock
        sequence_script = builder.create_timelock_script(
            validator_pubkey, 144, use_sequence=True
        )
        assert bytes([0xb2]) in sequence_script, "Should contain OP_CHECKSEQUENCEVERIFY"
        assert bytes([0xb1]) not in sequence_script, "Should not contain OP_CHECKLOCKTIMEVERIFY"
        
        print("✓ Sequence timelock script construction passed")
        
    except Exception as e:
        print(f"✗ Advanced witness script builder failed: {e}")
        return False
    
    return True


def test_script_hash_consistency():
    """Test script hash calculation consistency."""
    print("\nTesting Script Hash Consistency...")
    
    try:
        # Create various witness scripts
        validator_pubkey = b'\x02' + b'\x01' * 32
        
        # Validator script
        validator_script = create_validator_script(validator_pubkey)
        hash1 = calculate_script_hash(validator_script)
        hash2 = hashlib.sha256(validator_script).digest()
        assert hash1 == hash2, "Script hash calculation should be consistent"
        
        # Multisig script
        pubkey2 = b'\x03' + b'\x02' * 32
        multisig_script = create_multisig_script(2, [validator_pubkey, pubkey2])
        multisig_hash = calculate_script_hash(multisig_script)
        assert len(multisig_hash) == 32, "Multisig script hash should be 32 bytes"
        
        # Covenant script
        asset_id = "1234567890abcdef" * 4
        covenant_script = create_asset_commitment_script(asset_id, validator_pubkey)
        covenant_hash = calculate_script_hash(covenant_script)
        assert len(covenant_hash) == 32, "Covenant script hash should be 32 bytes"
        
        # Verify all hashes are different
        assert hash1 != multisig_hash != covenant_hash, "Different scripts should have different hashes"
        
        print("✓ Script hash consistency tests passed")
        print(f"  - Validator hash: {hash1.hex()[:16]}...")
        print(f"  - Multisig hash: {multisig_hash.hex()[:16]}...")
        print(f"  - Covenant hash: {covenant_hash.hex()[:16]}...")
        
    except Exception as e:
        print(f"✗ Script hash consistency failed: {e}")
        return False
    
    return True


def test_p2wsh_integration_with_psbt():
    """Test P2WSH integration with PSBT builders."""
    print("\nTesting P2WSH Integration with PSBT...")
    
    try:
        # Import PSBT builders
        from psbt.builder import BasePSBTBuilder
        
        # Create P2WSH output
        validator_pubkey = b'\x02' + b'\x01' * 32
        witness_script = create_validator_script(validator_pubkey)
        p2wsh_script, script_hash = create_p2wsh_output(witness_script)
        
        # Create PSBT with P2WSH output
        psbt_builder = BasePSBTBuilder()
        psbt_builder.add_output(script=p2wsh_script, amount=100000000)
        
        # Add witness script to PSBT output
        psbt_builder.psbt_outputs[0].witness_script = witness_script
        
        # Verify PSBT structure
        assert len(psbt_builder.outputs) == 1, "Should have one output"
        assert psbt_builder.outputs[0].script == p2wsh_script, "Should have P2WSH script"
        assert psbt_builder.psbt_outputs[0].witness_script == witness_script, "Should have witness script"
        
        # Test serialization
        psbt_bytes = psbt_builder.serialize()
        assert psbt_bytes.startswith(b'psbt\xff'), "Should be valid PSBT"
        
        print("✓ P2WSH integration with PSBT passed")
        print(f"  - PSBT size: {len(psbt_bytes)} bytes")
        print(f"  - P2WSH script in output: {len(p2wsh_script)} bytes")
        print(f"  - Witness script attached: {len(witness_script)} bytes")
        
    except Exception as e:
        print(f"✗ P2WSH PSBT integration failed: {e}")
        return False
    
    return True


def main():
    """Run integration tests."""
    print("Running P2WSH Output Construction Integration Tests...\n")
    
    tests = [
        test_basic_p2wsh_construction,
        test_multisig_p2wsh_construction,
        test_covenant_p2wsh_construction,
        test_htlc_p2wsh_construction,
        test_witness_script_builder_advanced,
        test_script_hash_consistency,
        test_p2wsh_integration_with_psbt
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