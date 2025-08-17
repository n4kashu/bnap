#!/usr/bin/env python3
"""
Integration test for Taproot Output Construction Module
"""

import sys
import os
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from psbt.outputs.taproot import (
    TaprootScriptBuilder,
    TaprootTreeBuilder,
    TaprootBuilder,
    TapLeaf,
    TapBranch,
    create_taproot_output,
    create_asset_transfer_script,
    create_asset_mint_script,
    validate_taproot_script,
    calculate_tap_leaf_hash
)


def test_basic_taproot_construction():
    """Test basic Taproot construction workflow."""
    print("Testing Basic Taproot Construction...")
    
    # Test data
    internal_pubkey = b'\x01' * 32  # 32-byte x-only pubkey
    builder = TaprootBuilder()
    
    try:
        # Create key-path only P2TR output
        p2tr_script, tweaked_pubkey, merkle_root = builder.create_p2tr_output(
            internal_pubkey, amount=100000000  # 1 BTC
        )
        
        print(f"✓ Created key-path P2TR output:")
        print(f"  - P2TR script: {len(p2tr_script)} bytes")
        print(f"  - Tweaked pubkey: {tweaked_pubkey.hex()[:16]}...")
        print(f"  - Merkle root: {merkle_root.hex()[:16]}... (should be zeros)")
        
        # Verify script structure
        assert len(p2tr_script) == 34, "P2TR script should be 34 bytes"
        assert p2tr_script[0] == 0x51, "Should start with OP_1"
        assert p2tr_script[1] == 0x20, "Should push 32 bytes"
        assert len(tweaked_pubkey) == 32, "Tweaked pubkey should be 32 bytes"
        assert merkle_root == b'\x00' * 32, "Key-path only should have zero merkle root"
        
        print("✓ Key-path P2TR output validation passed")
        
    except Exception as e:
        print(f"✗ Basic Taproot construction failed: {e}")
        return False
    
    return True


def test_asset_transfer_taproot():
    """Test Taproot asset transfer script construction."""
    print("\nTesting Asset Transfer Taproot Script...")
    
    # Test data
    internal_pubkey = b'\x01' * 32
    from_pubkey = b'\x02' * 32
    to_pubkey = b'\x03' * 32
    asset_id = "deadbeefcafebabe" * 4  # 64-character hex string
    transfer_amount = 1000
    
    builder = TaprootBuilder()
    
    try:
        # Create asset transfer P2TR output
        p2tr_script, tweaked_pubkey, transfer_script = builder.create_asset_transfer_output(
            internal_pubkey,
            asset_id,
            from_pubkey,
            to_pubkey,
            transfer_amount,
            script_amount=50000000  # 0.5 BTC
        )
        
        print(f"✓ Created asset transfer P2TR output:")
        print(f"  - Asset ID: {asset_id[:16]}...")
        print(f"  - Transfer amount: {transfer_amount}")
        print(f"  - P2TR script: {len(p2tr_script)} bytes")
        print(f"  - Transfer script: {len(transfer_script)} bytes")
        print(f"  - Tweaked pubkey: {tweaked_pubkey.hex()[:16]}...")
        
        # Verify script contains expected components
        asset_id_bytes = bytes.fromhex(asset_id)
        assert asset_id_bytes in transfer_script, "Should contain asset ID"
        assert from_pubkey in transfer_script, "Should contain from pubkey"
        assert to_pubkey in transfer_script, "Should contain to pubkey"
        
        # Verify Taproot script validation
        assert validate_taproot_script(transfer_script), "Transfer script should be valid"
        
        # Calculate and verify leaf hash
        leaf_hash = calculate_tap_leaf_hash(transfer_script)
        assert len(leaf_hash) == 32, "Leaf hash should be 32 bytes"
        
        print("✓ Asset transfer Taproot validation passed")
        
    except Exception as e:
        print(f"✗ Asset transfer Taproot construction failed: {e}")
        return False
    
    return True


def test_asset_mint_taproot():
    """Test Taproot asset minting script construction."""
    print("\nTesting Asset Mint Taproot Script...")
    
    # Test data
    internal_pubkey = b'\x01' * 32
    minter_pubkey = b'\x02' * 32
    asset_id = "1234567890abcdef" * 4
    mint_amount = 21000000
    max_supply = 100000000
    
    builder = TaprootBuilder()
    
    try:
        # Create asset mint P2TR output with supply limit
        p2tr_script, tweaked_pubkey, mint_script = builder.create_asset_mint_output(
            internal_pubkey,
            asset_id,
            minter_pubkey,
            mint_amount,
            max_supply=max_supply,
            script_amount=10000000  # 0.1 BTC
        )
        
        print(f"✓ Created asset mint P2TR output:")
        print(f"  - Asset ID: {asset_id[:16]}...")
        print(f"  - Mint amount: {mint_amount:,}")
        print(f"  - Max supply: {max_supply:,}")
        print(f"  - P2TR script: {len(p2tr_script)} bytes")
        print(f"  - Mint script: {len(mint_script)} bytes")
        print(f"  - Tweaked pubkey: {tweaked_pubkey.hex()[:16]}...")
        
        # Verify script contains expected components
        asset_id_bytes = bytes.fromhex(asset_id)
        assert asset_id_bytes in mint_script, "Should contain asset ID"
        assert minter_pubkey in mint_script, "Should contain minter pubkey"
        
        # Verify supply limit validation opcodes
        assert bytes([0xa4]) in mint_script, "Should contain OP_LESSTHANOREQUAL for supply limit"
        assert bytes([0x9a]) in mint_script, "Should contain OP_BOOLAND for condition combination"
        
        print("✓ Asset mint Taproot validation passed")
        
    except Exception as e:
        print(f"✗ Asset mint Taproot construction failed: {e}")
        return False
    
    return True


def test_multi_script_taproot_tree():
    """Test Taproot script tree with multiple spending paths."""
    print("\nTesting Multi-Script Taproot Tree...")
    
    # Test data
    internal_pubkey = b'\x01' * 32
    asset_id = "abcdef1234567890" * 4
    pubkey1 = b'\x02' * 32
    pubkey2 = b'\x03' * 32
    pubkey3 = b'\x04' * 32
    
    builder = TaprootBuilder()
    
    try:
        # Create multiple scripts for different spending conditions
        transfer_script = create_asset_transfer_script(
            asset_id, pubkey1, pubkey2, 500
        )
        
        mint_script = create_asset_mint_script(
            asset_id, pubkey1, 1000, max_supply=50000000
        )
        
        burn_script = builder.script_builder.create_asset_burn_script(
            asset_id, pubkey1, 250
        )
        
        scripts = [transfer_script, mint_script, burn_script]
        
        print(f"✓ Created {len(scripts)} different script paths:")
        print(f"  - Transfer script: {len(transfer_script)} bytes")
        print(f"  - Mint script: {len(mint_script)} bytes")
        print(f"  - Burn script: {len(burn_script)} bytes")
        
        # Create multi-path P2TR output
        p2tr_script, tweaked_pubkey, returned_scripts = builder.create_multi_path_output(
            internal_pubkey, scripts, script_amount=25000000  # 0.25 BTC
        )
        
        print(f"✓ Created multi-path P2TR output:")
        print(f"  - P2TR script: {len(p2tr_script)} bytes")
        print(f"  - Tweaked pubkey: {tweaked_pubkey.hex()[:16]}...")
        print(f"  - Script paths: {len(returned_scripts)}")
        
        # Verify all scripts are included
        assert len(returned_scripts) == 3, "Should have 3 script paths"
        assert transfer_script in returned_scripts, "Should include transfer script"
        assert mint_script in returned_scripts, "Should include mint script"
        assert burn_script in returned_scripts, "Should include burn script"
        
        # Verify each script is valid
        for i, script in enumerate(returned_scripts):
            assert validate_taproot_script(script), f"Script {i+1} should be valid"
        
        print("✓ Multi-script Taproot tree validation passed")
        
    except Exception as e:
        print(f"✗ Multi-script Taproot tree construction failed: {e}")
        return False
    
    return True


def test_taproot_tree_builder_advanced():
    """Test advanced Taproot tree building functionality."""
    print("\nTesting Advanced Taproot Tree Builder...")
    
    tree_builder = TaprootTreeBuilder()
    
    try:
        # Create various scripts
        script1 = b'\x20' + b'\x01' * 32 + b'\xac'  # Simple validator
        script2 = b'\x20' + b'\x02' * 32 + b'\xac'  # Another validator
        script3 = b'\x20' + b'\x03' * 32 + b'\xac'  # Third validator
        script4 = b'\x20' + b'\x04' * 32 + b'\xac'  # Fourth validator
        
        # Build tree with multiple leaves
        tree_builder.add_leaf(script1, 0xc0)
        tree_builder.add_leaf(script2, 0xc0)
        tree_builder.add_leaf(script3, 0xc1)  # Different leaf version
        tree_builder.add_leaf(script4, 0xc0)
        
        print(f"✓ Added {len(tree_builder.leaves)} leaves to tree")
        
        # Build the tree structure
        tree = tree_builder.build_tree()
        assert tree is not None, "Tree should be built successfully"
        
        print(f"✓ Built tree structure: {type(tree).__name__}")
        
        # Calculate Merkle root
        merkle_root = tree_builder.calculate_merkle_root(tree)
        assert len(merkle_root) == 32, "Merkle root should be 32 bytes"
        assert merkle_root != b'\x00' * 32, "Merkle root should not be zero"
        
        print(f"✓ Calculated Merkle root: {merkle_root.hex()[:16]}...")
        
        # Test leaf hash calculation for different versions
        leaf_hash_c0 = calculate_tap_leaf_hash(script1, 0xc0)
        leaf_hash_c1 = calculate_tap_leaf_hash(script3, 0xc1)
        
        assert leaf_hash_c0 != leaf_hash_c1, "Different leaf versions should produce different hashes"
        
        print(f"✓ Leaf hash (v0xc0): {leaf_hash_c0.hex()[:16]}...")
        print(f"✓ Leaf hash (v0xc1): {leaf_hash_c1.hex()[:16]}...")
        
        # Test tree consistency
        merkle_root2 = tree_builder.calculate_merkle_root(tree)
        assert merkle_root == merkle_root2, "Merkle root calculation should be deterministic"
        
        print("✓ Advanced tree builder tests passed")
        
    except Exception as e:
        print(f"✗ Advanced tree builder failed: {e}")
        return False
    
    return True


def test_delegation_script_construction():
    """Test delegation script construction for Taproot."""
    print("\nTesting Delegation Script Construction...")
    
    script_builder = TaprootScriptBuilder()
    
    try:
        # Test data
        delegator_pubkey = b'\x01' * 32
        delegate_pubkey = b'\x02' * 32
        permissions = 0x0f  # Some permission flags
        expiry = 650000  # Block height
        
        # Create delegation script without expiry
        delegation_script = script_builder.create_delegation_script(
            delegator_pubkey, delegate_pubkey, permissions
        )
        
        print(f"✓ Created delegation script without expiry:")
        print(f"  - Script length: {len(delegation_script)} bytes")
        print(f"  - Permissions: 0x{permissions:02x}")
        
        # Verify script contains expected components
        assert delegator_pubkey in delegation_script, "Should contain delegator pubkey"
        assert delegate_pubkey in delegation_script, "Should contain delegate pubkey"
        assert bytes([0x9b]) in delegation_script, "Should contain OP_BOOLOR for either/or logic"
        assert bytes([0xac]) in delegation_script, "Should contain OP_CHECKSIG"
        
        # Create delegation script with expiry
        delegation_script_expiry = script_builder.create_delegation_script(
            delegator_pubkey, delegate_pubkey, permissions, expiry
        )
        
        print(f"✓ Created delegation script with expiry:")
        print(f"  - Script length: {len(delegation_script_expiry)} bytes")
        print(f"  - Expiry block: {expiry}")
        
        # Verify expiry validation opcodes
        assert bytes([0xb1]) in delegation_script_expiry, "Should contain OP_CHECKLOCKTIMEVERIFY"
        assert bytes([0x75]) in delegation_script_expiry, "Should contain OP_DROP"
        
        # Verify both scripts are valid
        assert validate_taproot_script(delegation_script), "Delegation script should be valid"
        assert validate_taproot_script(delegation_script_expiry), "Delegation script with expiry should be valid"
        
        print("✓ Delegation script construction passed")
        
    except Exception as e:
        print(f"✗ Delegation script construction failed: {e}")
        return False
    
    return True


def test_taproot_integration_with_psbt():
    """Test Taproot integration with PSBT builders."""
    print("\nTesting Taproot Integration with PSBT...")
    
    try:
        # Import PSBT builders
        from psbt.builder import BasePSBTBuilder
        
        # Create Taproot output
        internal_pubkey = b'\x01' * 32
        asset_id = "fedcba0987654321" * 4
        minter_pubkey = b'\x02' * 32
        
        # Create asset mint script and P2TR output
        mint_script = create_asset_mint_script(asset_id, minter_pubkey, 5000)
        p2tr_script, tweaked_pubkey = create_taproot_output(
            internal_pubkey, TapLeaf(mint_script)
        )
        
        # Create PSBT with Taproot output
        psbt_builder = BasePSBTBuilder()
        psbt_builder.add_output(script=p2tr_script, amount=100000000)
        
        # Add Taproot-specific data to PSBT output
        psbt_builder.psbt_outputs[0].tap_internal_key = internal_pubkey
        psbt_builder.psbt_outputs[0].tap_tree = {
            'leaves': [{'script': mint_script, 'leaf_version': 0xc0}]
        }
        
        # Verify PSBT structure
        assert len(psbt_builder.outputs) == 1, "Should have one output"
        assert psbt_builder.outputs[0].script == p2tr_script, "Should have P2TR script"
        assert psbt_builder.psbt_outputs[0].tap_internal_key == internal_pubkey, "Should have internal key"
        
        # Test serialization
        psbt_bytes = psbt_builder.serialize()
        assert psbt_bytes.startswith(b'psbt\xff'), "Should be valid PSBT"
        
        print("✓ Taproot integration with PSBT passed")
        print(f"  - PSBT size: {len(psbt_bytes)} bytes")
        print(f"  - P2TR script in output: {len(p2tr_script)} bytes")
        print(f"  - Internal key: {internal_pubkey.hex()[:16]}...")
        print(f"  - Tweaked key: {tweaked_pubkey.hex()[:16]}...")
        
    except Exception as e:
        print(f"✗ Taproot PSBT integration failed: {e}")
        return False
    
    return True


def test_script_validation_edge_cases():
    """Test Taproot script validation edge cases."""
    print("\nTesting Script Validation Edge Cases...")
    
    try:
        # Test empty script
        assert validate_taproot_script(b'') == False, "Empty script should be invalid"
        
        # Test very large script
        large_script = b'\x01' * 10001
        assert validate_taproot_script(large_script) == False, "Script too large should be invalid"
        
        # Test valid script
        valid_script = create_asset_transfer_script(
            "deadbeefcafebabe" * 4, b'\x01' * 32, b'\x02' * 32, 100
        )
        assert validate_taproot_script(valid_script) == True, "Valid script should pass validation"
        
        # Test leaf hash consistency
        script = b'\x20' + b'\x01' * 32 + b'\xac'
        hash1 = calculate_tap_leaf_hash(script, 0xc0)
        hash2 = calculate_tap_leaf_hash(script, 0xc0)
        assert hash1 == hash2, "Leaf hash should be deterministic"
        
        # Test different leaf versions produce different hashes
        hash_c0 = calculate_tap_leaf_hash(script, 0xc0)
        hash_c1 = calculate_tap_leaf_hash(script, 0xc1)
        assert hash_c0 != hash_c1, "Different leaf versions should produce different hashes"
        
        print("✓ Script validation edge cases passed")
        print(f"  - Valid script hash: {hash1.hex()[:16]}...")
        print(f"  - Different version hash: {hash_c1.hex()[:16]}...")
        
    except Exception as e:
        print(f"✗ Script validation edge cases failed: {e}")
        return False
    
    return True


def main():
    """Run integration tests."""
    print("Running Taproot Output Construction Integration Tests...\n")
    
    tests = [
        test_basic_taproot_construction,
        test_asset_transfer_taproot,
        test_asset_mint_taproot,
        test_multi_script_taproot_tree,
        test_taproot_tree_builder_advanced,
        test_delegation_script_construction,
        test_taproot_integration_with_psbt,
        test_script_validation_edge_cases
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