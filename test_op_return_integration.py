#!/usr/bin/env python3
"""
Integration test for OP_RETURN Metadata Encoder Module
"""

import sys
import os
import hashlib
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from psbt.outputs.op_return import (
    OpReturnEncoder,
    OpReturnDecoder,
    MetadataPayload,
    MetadataType,
    CompressionType,
    create_asset_issuance_op_return,
    create_asset_transfer_op_return,
    create_nft_metadata_op_return,
    parse_op_return_metadata,
    validate_op_return_size,
    BNAP_PREFIX,
    MAX_OP_RETURN_SIZE
)


def test_basic_op_return_encoding():
    """Test basic OP_RETURN encoding workflow."""
    print("Testing Basic OP_RETURN Encoding...")
    
    encoder = OpReturnEncoder()
    
    try:
        # Create simple message
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=b'Hello Bitcoin Native Asset Protocol!'
        )
        
        # Encode to OP_RETURN
        script = encoder.create_op_return_output(payload)
        
        print(f"✓ Created OP_RETURN script:")
        print(f"  - Script length: {len(script)} bytes")
        print(f"  - OP_RETURN opcode: 0x{script[0]:02x}")
        print(f"  - Protocol prefix: {BNAP_PREFIX.decode()}")
        print(f"  - Message type: {payload.metadata_type.name}")
        
        # Verify script structure
        assert script[0] == 0x6a, "Should start with OP_RETURN"
        assert len(script) <= MAX_OP_RETURN_SIZE + 2, "Should fit within size limit"
        assert BNAP_PREFIX in script, "Should contain protocol prefix"
        
        print("✓ Basic OP_RETURN encoding validation passed")
        
    except Exception as e:
        print(f"✗ Basic OP_RETURN encoding failed: {e}")
        return False
    
    return True


def test_asset_issuance_encoding():
    """Test asset issuance metadata encoding."""
    print("\nTesting Asset Issuance Encoding...")
    
    # Test data
    asset_id = "1234567890abcdef" * 4  # 64-character hex string
    supply = 21000000
    decimals = 8
    symbol = "BTC"
    
    try:
        # Create issuance OP_RETURN
        script = create_asset_issuance_op_return(
            asset_id, supply, decimals, symbol
        )
        
        print(f"✓ Created asset issuance OP_RETURN:")
        print(f"  - Asset ID: {asset_id[:16]}...")
        print(f"  - Supply: {supply:,}")
        print(f"  - Decimals: {decimals}")
        print(f"  - Symbol: {symbol}")
        print(f"  - Script size: {len(script)} bytes")
        
        # Parse back
        metadata = parse_op_return_metadata(script)
        
        assert metadata is not None, "Should parse successfully"
        assert metadata['type'] == 'ASSET_ISSUANCE', "Should be issuance type"
        assert metadata['supply'] == supply, "Supply should match"
        assert metadata['decimals'] == decimals, "Decimals should match"
        assert metadata['symbol'] == symbol, "Symbol should match"
        
        print("✓ Asset issuance round-trip validation passed")
        
    except Exception as e:
        print(f"✗ Asset issuance encoding failed: {e}")
        return False
    
    return True


def test_asset_transfer_encoding():
    """Test asset transfer metadata encoding."""
    print("\nTesting Asset Transfer Encoding...")
    
    # Test data
    asset_id = "fedcba0987654321" * 4
    amount = 100000
    recipient_hash = hashlib.sha256(b'recipient_address').digest()
    
    try:
        # Create transfer OP_RETURN
        script = create_asset_transfer_op_return(
            asset_id, amount, recipient_hash
        )
        
        print(f"✓ Created asset transfer OP_RETURN:")
        print(f"  - Asset ID: {asset_id[:16]}...")
        print(f"  - Amount: {amount:,}")
        print(f"  - Recipient hash: {recipient_hash.hex()[:16]}...")
        print(f"  - Script size: {len(script)} bytes")
        
        # Parse back
        metadata = parse_op_return_metadata(script)
        
        assert metadata is not None, "Should parse successfully"
        assert metadata['type'] == 'ASSET_TRANSFER', "Should be transfer type"
        assert metadata['amount'] == amount, "Amount should match"
        assert metadata['recipient_hash'] is not None, "Should have recipient hash"
        
        print("✓ Asset transfer round-trip validation passed")
        
    except Exception as e:
        print(f"✗ Asset transfer encoding failed: {e}")
        return False
    
    return True


def test_nft_metadata_encoding():
    """Test NFT metadata reference encoding."""
    print("\nTesting NFT Metadata Encoding...")
    
    # Test data
    collection_id = 1
    token_id = 42
    metadata_json = {
        "name": "Test NFT #42",
        "description": "A test NFT for BNAP",
        "image": "ipfs://QmTest123",
        "attributes": [
            {"trait_type": "Color", "value": "Blue"},
            {"trait_type": "Rarity", "value": "Common"}
        ]
    }
    metadata_hash = hashlib.sha256(json.dumps(metadata_json).encode()).digest()
    uri_scheme = "ipfs"
    
    try:
        # Create NFT metadata OP_RETURN
        script = create_nft_metadata_op_return(
            collection_id, token_id, metadata_hash, uri_scheme
        )
        
        print(f"✓ Created NFT metadata OP_RETURN:")
        print(f"  - Collection ID: {collection_id}")
        print(f"  - Token ID: {token_id}")
        print(f"  - Metadata hash: {metadata_hash.hex()[:16]}...")
        print(f"  - URI scheme: {uri_scheme}")
        print(f"  - Script size: {len(script)} bytes")
        
        # Parse back
        metadata = parse_op_return_metadata(script)
        
        assert metadata is not None, "Should parse successfully"
        assert metadata['type'] == 'NFT_METADATA', "Should be NFT metadata type"
        assert metadata['collection_id'] == collection_id, "Collection ID should match"
        assert metadata['token_id'] == token_id, "Token ID should match"
        assert metadata['uri_scheme'] == uri_scheme, "URI scheme should match"
        
        print("✓ NFT metadata round-trip validation passed")
        
    except Exception as e:
        print(f"✗ NFT metadata encoding failed: {e}")
        return False
    
    return True


def test_uri_reference_encoding():
    """Test URI reference encoding."""
    print("\nTesting URI Reference Encoding...")
    
    encoder = OpReturnEncoder()
    
    # Test data
    uri = "https://api.example.com/assets/metadata.json"
    content_hash = hashlib.sha256(b'{"test": "data"}').digest()
    
    try:
        # Create URI reference OP_RETURN
        script = encoder.encode_uri_reference(uri, content_hash)
        
        print(f"✓ Created URI reference OP_RETURN:")
        print(f"  - URI: {uri}")
        print(f"  - Content hash: {content_hash.hex()[:16]}...")
        print(f"  - Script size: {len(script)} bytes")
        
        # Verify size constraint
        assert len(script) <= MAX_OP_RETURN_SIZE + 2, "Should fit within size limit"
        assert b'example.com' in script, "Should contain URI"
        
        print("✓ URI reference validation passed")
        
    except Exception as e:
        print(f"✗ URI reference encoding failed: {e}")
        return False
    
    return True


def test_commitment_encoding():
    """Test commitment data encoding."""
    print("\nTesting Commitment Encoding...")
    
    encoder = OpReturnEncoder()
    
    # Test data
    commitment_data = b'Important data to commit to blockchain'
    commitment_type = 1  # Custom type
    
    try:
        # Create commitment OP_RETURN
        script = encoder.encode_commitment(commitment_data, commitment_type)
        
        print(f"✓ Created commitment OP_RETURN:")
        print(f"  - Data length: {len(commitment_data)} bytes")
        print(f"  - Commitment type: {commitment_type}")
        print(f"  - Script size: {len(script)} bytes")
        
        # Test with large data (should hash)
        large_data = b'x' * 200
        large_script = encoder.encode_commitment(large_data)
        
        print(f"✓ Created large commitment OP_RETURN:")
        print(f"  - Original data: {len(large_data)} bytes")
        print(f"  - Script size: {len(large_script)} bytes (hashed)")
        
        # Verify both fit within limits
        assert len(script) <= MAX_OP_RETURN_SIZE + 2, "Small commitment should fit"
        assert len(large_script) <= MAX_OP_RETURN_SIZE + 2, "Large commitment should fit"
        
        print("✓ Commitment encoding validation passed")
        
    except Exception as e:
        print(f"✗ Commitment encoding failed: {e}")
        return False
    
    return True


def test_size_constraints():
    """Test OP_RETURN size constraints."""
    print("\nTesting Size Constraints...")
    
    encoder = OpReturnEncoder()
    
    try:
        # Test at exact limit
        overhead = len(BNAP_PREFIX) + 3  # prefix + version + type + compression
        max_content = b'x' * (MAX_OP_RETURN_SIZE - overhead)
        
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=max_content
        )
        
        script = encoder.create_op_return_output(payload)
        
        print(f"✓ Created maximum size OP_RETURN:")
        print(f"  - Content size: {len(max_content)} bytes")
        print(f"  - Total script size: {len(script)} bytes")
        print(f"  - OP_RETURN limit: {MAX_OP_RETURN_SIZE} bytes")
        
        # Verify size validation
        # The script includes OP_RETURN and length byte, so check the data portion
        data_portion = script[2:] if script[1] <= 75 else script[3:]
        assert validate_op_return_size(data_portion), "Should be valid size"
        
        # Test oversized data
        oversized = b'x' * (MAX_OP_RETURN_SIZE + 1)
        assert not validate_op_return_size(oversized), "Should reject oversized data"
        
        print("✓ Size constraint validation passed")
        
    except Exception as e:
        print(f"✗ Size constraint testing failed: {e}")
        return False
    
    return True


def test_decoder_validation():
    """Test decoder validation and error handling."""
    print("\nTesting Decoder Validation...")
    
    decoder = OpReturnDecoder()
    
    try:
        # Test invalid prefix
        invalid_data = b'INVALID' + bytes([0x01, 0x01, 0x00]) + b'content'
        result = decoder.decode_metadata(invalid_data)
        assert result is None, "Should reject invalid prefix"
        print("✓ Rejected invalid prefix")
        
        # Test too short data
        short_data = b'BN'
        result = decoder.decode_metadata(short_data)
        assert result is None, "Should reject short data"
        print("✓ Rejected short data")
        
        # Test non-OP_RETURN script
        non_op_return = b'\x51\x20' + b'\x01' * 32  # P2TR script
        result = decoder.decode_op_return(non_op_return)
        assert result is None, "Should reject non-OP_RETURN"
        print("✓ Rejected non-OP_RETURN script")
        
        print("✓ Decoder validation passed")
        
    except Exception as e:
        print(f"✗ Decoder validation failed: {e}")
        return False
    
    return True


def test_psbt_integration():
    """Test OP_RETURN integration with PSBT."""
    print("\nTesting PSBT Integration...")
    
    try:
        # Import PSBT builder
        from psbt.builder import BasePSBTBuilder
        
        # Create PSBT with OP_RETURN output
        psbt_builder = BasePSBTBuilder()
        
        # Add OP_RETURN for asset issuance
        asset_id = "abcdef1234567890" * 4
        op_return_script = create_asset_issuance_op_return(
            asset_id, 1000000, 8, "TEST"
        )
        
        # Add as output with 0 value (standard for OP_RETURN)
        psbt_builder.add_output(script=op_return_script, amount=0)
        
        # Add a regular output
        psbt_builder.add_output(
            script=b'\x00\x14' + b'\x01' * 20,  # P2WPKH
            amount=100000
        )
        
        # Verify PSBT structure
        assert len(psbt_builder.outputs) == 2, "Should have two outputs"
        assert psbt_builder.outputs[0].script == op_return_script, "First output should be OP_RETURN"
        assert psbt_builder.outputs[0].value == 0, "OP_RETURN should have 0 value"
        assert psbt_builder.outputs[1].value == 100000, "Second output should have value"
        
        # Serialize PSBT
        psbt_bytes = psbt_builder.serialize()
        assert psbt_bytes.startswith(b'psbt\xff'), "Should be valid PSBT"
        
        print("✓ PSBT integration passed")
        print(f"  - PSBT size: {len(psbt_bytes)} bytes")
        print(f"  - OP_RETURN output: 0 satoshis")
        print(f"  - Regular output: 100,000 satoshis")
        
    except Exception as e:
        print(f"✗ PSBT integration failed: {e}")
        return False
    
    return True


def main():
    """Run integration tests."""
    print("Running OP_RETURN Metadata Encoder Integration Tests...\n")
    
    tests = [
        test_basic_op_return_encoding,
        test_asset_issuance_encoding,
        test_asset_transfer_encoding,
        test_nft_metadata_encoding,
        test_uri_reference_encoding,
        test_commitment_encoding,
        test_size_constraints,
        test_decoder_validation,
        test_psbt_integration
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