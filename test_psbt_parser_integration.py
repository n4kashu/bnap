#!/usr/bin/env python3
"""
Integration test for PSBT Parser with Metadata Extraction
"""

import sys
import os
import base64
import hashlib

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from psbt.parser import (
    PSBTParser,
    parse_psbt_from_base64,
    parse_psbt_from_bytes,
    extract_asset_operations,
    validate_psbt_structure
)
from psbt.builder import BasePSBTBuilder
from psbt.outputs.op_return import create_asset_issuance_op_return, create_nft_metadata_op_return
from psbt.fungible_mint import FungibleMintPSBTBuilder, FungibleMintParameters
from psbt.nft_mint import NFTMintPSBTBuilder, NFTMintParameters, NFTMetadata


def test_basic_psbt_parsing():
    """Test basic PSBT parsing functionality."""
    print("Testing Basic PSBT Parsing...")
    
    try:
        # Create a basic PSBT
        builder = BasePSBTBuilder()
        
        # Add input (using dummy transaction ID)
        dummy_txid = "a" * 64
        builder.add_input(dummy_txid, 0)
        
        # Add outputs
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)  # P2WPKH
        builder.add_output(script=b'\x00\x20' + b'\x02' * 32, amount=50000)   # P2WSH
        
        # Serialize PSBT
        psbt_bytes = builder.serialize()
        
        print(f"✓ Created basic PSBT:")
        print(f"  - Size: {len(psbt_bytes)} bytes")
        print(f"  - Inputs: 1")
        print(f"  - Outputs: 2")
        
        # Parse PSBT
        parser = PSBTParser()
        parsed = parser.parse(psbt_bytes)
        
        # Verify structure
        assert parsed.is_valid, f"PSBT should be valid: {parsed.validation_errors}"
        assert len(parsed.inputs) == 1, "Should have 1 input"
        assert len(parsed.outputs) == 2, "Should have 2 outputs"
        assert parsed.psbt_global.unsigned_tx is not None, "Should have unsigned transaction"
        
        print("✓ Basic PSBT parsing validation passed")
        
    except Exception as e:
        print(f"✗ Basic PSBT parsing failed: {e}")
        return False
    
    return True


def test_psbt_with_op_return_metadata():
    """Test PSBT parsing with OP_RETURN metadata."""
    print("\nTesting PSBT with OP_RETURN Metadata...")
    
    try:
        # Test data
        asset_id = "1234567890abcdef" * 4
        supply = 21000000
        decimals = 8
        symbol = "BTC"
        
        # Create PSBT with OP_RETURN
        builder = BasePSBTBuilder()
        
        # Add input
        builder.add_input("b" * 64, 0)
        
        # Add OP_RETURN output with BNAP metadata
        op_return_script = create_asset_issuance_op_return(
            asset_id, supply, decimals, symbol
        )
        builder.add_output(script=op_return_script, amount=0)
        
        # Add regular output
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        print(f"✓ Created PSBT with OP_RETURN:")
        print(f"  - Asset ID: {asset_id[:16]}...")
        print(f"  - Supply: {supply:,}")
        print(f"  - Symbol: {symbol}")
        print(f"  - OP_RETURN size: {len(op_return_script)} bytes")
        
        # Serialize and parse
        psbt_bytes = builder.serialize()
        parsed = parse_psbt_from_bytes(psbt_bytes)
        
        # Verify parsing
        assert parsed.is_valid, "PSBT should be valid"
        assert len(parsed.asset_metadata) > 0, "Should have extracted metadata"
        
        # Check OP_RETURN metadata
        op_return_metadata = None
        for metadata in parsed.asset_metadata:
            if metadata.op_return_data:
                op_return_metadata = metadata
                break
        
        assert op_return_metadata is not None, "Should have OP_RETURN metadata"
        assert op_return_metadata.op_return_data['type'] == 'ASSET_ISSUANCE'
        assert op_return_metadata.op_return_data['supply'] == supply
        assert op_return_metadata.op_return_data['decimals'] == decimals
        assert op_return_metadata.op_return_data['symbol'] == symbol
        
        print("✓ OP_RETURN metadata extraction passed")
        
    except Exception as e:
        print(f"✗ OP_RETURN metadata parsing failed: {e}")
        return False
    
    return True


def test_nft_psbt_parsing():
    """Test parsing PSBT with NFT metadata."""
    print("\nTesting NFT PSBT Parsing...")
    
    try:
        # Test data
        collection_id = 1
        token_id = 42
        metadata_json = {
            "name": "Test NFT #42",
            "description": "A test NFT",
            "image": "ipfs://QmTest123"
        }
        metadata_hash = hashlib.sha256(str(metadata_json).encode()).digest()
        
        # Create PSBT with NFT metadata
        builder = BasePSBTBuilder()
        
        # Add input
        builder.add_input("c" * 64, 0)
        
        # Add NFT OP_RETURN
        nft_script = create_nft_metadata_op_return(
            collection_id, token_id, metadata_hash, "ipfs"
        )
        builder.add_output(script=nft_script, amount=0)
        
        # Add regular output
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=50000)
        
        print(f"✓ Created NFT PSBT:")
        print(f"  - Collection ID: {collection_id}")
        print(f"  - Token ID: {token_id}")
        print(f"  - Metadata hash: {metadata_hash.hex()[:16]}...")
        
        # Parse PSBT
        psbt_bytes = builder.serialize()
        parsed = parse_psbt_from_bytes(psbt_bytes)
        
        # Verify NFT metadata extraction
        assert parsed.is_valid, "NFT PSBT should be valid"
        assert len(parsed.asset_metadata) > 0, "Should have NFT metadata"
        
        # Check NFT-specific fields
        nft_metadata = None
        for metadata in parsed.asset_metadata:
            if metadata.op_return_data and metadata.op_return_data.get('type') == 'NFT_METADATA':
                nft_metadata = metadata
                break
        
        assert nft_metadata is not None, "Should have NFT metadata"
        assert nft_metadata.op_return_data['collection_id'] == collection_id
        assert nft_metadata.op_return_data['token_id'] == token_id
        assert nft_metadata.op_return_data['uri_scheme'] == 'ipfs'
        
        print("✓ NFT metadata extraction passed")
        
    except Exception as e:
        print(f"✗ NFT PSBT parsing failed: {e}")
        return False
    
    return True


def test_asset_operations_extraction():
    """Test extracting asset operations from complex PSBT."""
    print("\nTesting Asset Operations Extraction...")
    
    try:
        # Create complex PSBT with multiple operations
        builder = BasePSBTBuilder()
        
        # Add multiple inputs
        builder.add_input("d" * 64, 0)
        builder.add_input("e" * 64, 1)
        
        # Add asset issuance OP_RETURN
        asset_id = "deadbeefcafebabe" * 4
        issuance_script = create_asset_issuance_op_return(
            asset_id, 1000000, 8, "TEST"
        )
        builder.add_output(script=issuance_script, amount=0)
        
        # Add NFT OP_RETURN
        collection_id = 5
        token_id = 100
        nft_hash = hashlib.sha256(b'nft metadata').digest()
        nft_script = create_nft_metadata_op_return(
            collection_id, token_id, nft_hash, "arweave"
        )
        builder.add_output(script=nft_script, amount=0)
        
        # Add regular outputs
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=75000)
        builder.add_output(script=b'\x00\x14' + b'\x02' * 20, amount=25000)
        
        print(f"✓ Created complex PSBT:")
        print(f"  - Inputs: 2")
        print(f"  - OP_RETURN outputs: 2")
        print(f"  - Regular outputs: 2")
        
        # Parse and extract operations
        psbt_bytes = builder.serialize()
        parsed = parse_psbt_from_bytes(psbt_bytes)
        operations = extract_asset_operations(parsed)
        
        # Verify operations extraction
        assert len(operations) >= 2, "Should extract at least 2 operations"
        
        # Check for asset issuance operation
        issuance_op = None
        for op in operations:
            if op.get('op_return', {}).get('type') == 'ASSET_ISSUANCE':
                issuance_op = op
                break
        
        assert issuance_op is not None, "Should have issuance operation"
        assert issuance_op['op_return']['supply'] == 1000000
        assert issuance_op['op_return']['symbol'] == 'TEST'
        
        # Check for NFT operation
        nft_op = None
        for op in operations:
            if op.get('op_return', {}).get('type') == 'NFT_METADATA':
                nft_op = op
                break
        
        assert nft_op is not None, "Should have NFT operation"
        assert nft_op['collection_id'] == collection_id
        assert nft_op['token_id'] == token_id
        
        print("✓ Asset operations extraction passed")
        print(f"  - Extracted {len(operations)} operations")
        print(f"  - Asset issuance: {issuance_op['op_return']['symbol']}")
        print(f"  - NFT: Collection {nft_op['collection_id']}, Token {nft_op['token_id']}")
        
    except Exception as e:
        print(f"✗ Asset operations extraction failed: {e}")
        return False
    
    return True


def test_base64_psbt_parsing():
    """Test parsing PSBT from base64 encoding."""
    print("\nTesting Base64 PSBT Parsing...")
    
    try:
        # Create PSBT
        builder = BasePSBTBuilder()
        builder.add_input("f" * 64, 0)
        
        # Add OP_RETURN
        asset_id = "abcdef1234567890" * 4
        op_return_script = create_asset_issuance_op_return(
            asset_id, 500000, 6, "XYZ"
        )
        builder.add_output(script=op_return_script, amount=0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=200000)
        
        # Serialize to base64
        psbt_bytes = builder.serialize()
        base64_str = base64.b64encode(psbt_bytes).decode()
        
        print(f"✓ Created base64 PSBT:")
        print(f"  - Base64 length: {len(base64_str)} characters")
        print(f"  - Sample: {base64_str[:50]}...")
        
        # Parse from base64
        parsed = parse_psbt_from_base64(base64_str)
        
        # Verify parsing
        assert parsed.is_valid, "Base64 PSBT should be valid"
        assert len(parsed.inputs) == 1, "Should have 1 input"
        assert len(parsed.outputs) == 2, "Should have 2 outputs"
        
        # Check metadata
        assert len(parsed.asset_metadata) > 0, "Should have metadata"
        
        # Extract operations
        operations = extract_asset_operations(parsed)
        assert len(operations) > 0, "Should have operations"
        
        # Check issuance data
        issuance_found = False
        for op in operations:
            if op.get('op_return', {}).get('symbol') == 'XYZ':
                issuance_found = True
                assert op['op_return']['supply'] == 500000
                assert op['op_return']['decimals'] == 6
                break
        
        assert issuance_found, "Should find XYZ issuance"
        
        print("✓ Base64 PSBT parsing passed")
        
    except Exception as e:
        print(f"✗ Base64 PSBT parsing failed: {e}")
        return False
    
    return True


def test_psbt_validation():
    """Test PSBT structure validation."""
    print("\nTesting PSBT Validation...")
    
    try:
        # Test valid PSBT
        builder = BasePSBTBuilder()
        builder.add_input("1" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        psbt_bytes = builder.serialize()
        is_valid, errors = validate_psbt_structure(psbt_bytes)
        
        assert is_valid, f"Valid PSBT should pass validation: {errors}"
        assert len(errors) == 0, "Valid PSBT should have no errors"
        
        print("✓ Valid PSBT validation passed")
        
        # Test invalid PSBT
        invalid_data = b'not a valid psbt'
        is_valid, errors = validate_psbt_structure(invalid_data)
        
        assert not is_valid, "Invalid data should fail validation"
        assert len(errors) > 0, "Invalid data should have errors"
        
        print("✓ Invalid PSBT rejection passed")
        print(f"  - Validation errors: {len(errors)}")
        
        # Test invalid base64
        is_valid, errors = validate_psbt_structure("invalid_base64!")
        
        assert not is_valid, "Invalid base64 should fail"
        assert len(errors) > 0, "Invalid base64 should have errors"
        
        print("✓ Invalid base64 rejection passed")
        
    except Exception as e:
        print(f"✗ PSBT validation testing failed: {e}")
        return False
    
    return True


def test_integration_with_builders():
    """Test integration with PSBT builders."""
    print("\nTesting Integration with PSBT Builders...")
    
    try:
        # Test with FungibleMintPSBTBuilder
        fungible_params = FungibleMintParameters(
            asset_id="5678901234abcdef" * 4,
            mint_amount=1000000,
            recipient_script=b'\x00\x14' + b'\x03' * 20,
            fee_rate=10.0
        )
        
        fungible_builder = FungibleMintPSBTBuilder()
        fungible_builder.set_mint_parameters(fungible_params)
        
        # Add funding input
        fungible_builder.add_input("funding_tx", 0, 200000)
        
        # Build PSBT
        fungible_builder.build_psbt()
        fungible_bytes = fungible_builder.serialize()
        
        print(f"✓ Created fungible mint PSBT:")
        print(f"  - Size: {len(fungible_bytes)} bytes")
        print(f"  - Asset ID: {fungible_params.asset_id[:16]}...")
        print(f"  - Mint amount: {fungible_params.mint_amount:,}")
        
        # Parse fungible PSBT
        fungible_parsed = parse_psbt_from_bytes(fungible_bytes)
        
        assert fungible_parsed.is_valid, "Fungible PSBT should be valid"
        assert len(fungible_parsed.inputs) >= 1, "Should have funding input"
        assert len(fungible_parsed.outputs) >= 1, "Should have recipient output"
        
        print("✓ Fungible PSBT integration passed")
        
        # Test with NFTMintPSBTBuilder
        nft_metadata = NFTMetadata(
            name="Test NFT",
            description="Integration test NFT",
            image="ipfs://QmTest456"
        )
        
        nft_params = NFTMintParameters(
            collection_id=10,
            token_id=200,
            metadata=nft_metadata,
            recipient_script=b'\x00\x14' + b'\x04' * 20,
            fee_rate=15.0
        )
        
        nft_builder = NFTMintPSBTBuilder()
        nft_builder.set_mint_parameters(nft_params)
        
        # Add funding input
        nft_builder.add_input("nft_funding_tx", 0, 100000)
        
        # Build PSBT
        nft_builder.build_psbt()
        nft_bytes = nft_builder.serialize()
        
        print(f"✓ Created NFT mint PSBT:")
        print(f"  - Size: {len(nft_bytes)} bytes")
        print(f"  - Collection: {nft_params.collection_id}")
        print(f"  - Token: {nft_params.token_id}")
        print(f"  - NFT name: {nft_metadata.name}")
        
        # Parse NFT PSBT
        nft_parsed = parse_psbt_from_bytes(nft_bytes)
        
        assert nft_parsed.is_valid, "NFT PSBT should be valid"
        assert len(nft_parsed.asset_metadata) > 0, "Should have NFT metadata"
        
        # Extract NFT operations
        nft_operations = extract_asset_operations(nft_parsed)
        
        nft_op_found = False
        for op in nft_operations:
            if op.get('collection_id') == 10 and op.get('token_id') == 200:
                nft_op_found = True
                break
        
        assert nft_op_found, "Should find NFT operation"
        
        print("✓ NFT PSBT integration passed")
        
    except Exception as e:
        print(f"✗ PSBT builders integration failed: {e}")
        return False
    
    return True


def main():
    """Run integration tests."""
    print("Running PSBT Parser Integration Tests...\n")
    
    tests = [
        test_basic_psbt_parsing,
        test_psbt_with_op_return_metadata,
        test_nft_psbt_parsing,
        test_asset_operations_extraction,
        test_base64_psbt_parsing,
        test_psbt_validation,
        test_integration_with_builders
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