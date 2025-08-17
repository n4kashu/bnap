#!/usr/bin/env python3
"""
Integration test for NFT Mint PSBT Construction
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from psbt.nft_mint import NFTMintPSBTBuilder, NFTMintParameters, NFTMetadata, MetadataScheme


def test_nft_mint_integration():
    """Test complete NFT mint PSBT construction workflow."""
    print("Testing NFT Mint PSBT Integration...")
    
    # Create builder
    builder = NFTMintPSBTBuilder(version=2, locktime=0)
    
    # NFT parameters
    collection_id = "deadbeefcafebabe" * 4  # 64-character hex string
    token_id = 1337
    recipient_script = bytes([0x00, 0x14]) + bytes(20)  # P2WPKH
    
    # Create rich metadata
    metadata = NFTMetadata(
        name="Epic Dragon #1337",
        description="A legendary dragon from the mystical realm of testing",
        image_uri="ipfs://QmDragonImage123456789abcdef",
        attributes={
            "species": "fire dragon",
            "rarity": "legendary",
            "power_level": 9001,
            "element": "fire",
            "generation": 1
        },
        external_url="https://epicnfts.example.com/dragon/1337",
        animation_url="ipfs://QmDragonAnimation987654321",
        content_hash="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
    )
    
    # Set mint parameters
    params = NFTMintParameters(
        collection_id=collection_id,
        token_id=token_id,
        metadata=metadata,
        metadata_uri="ipfs://QmDragonMetadata555666777",
        content_uri="ipfs://QmDragonContent888999000",
        recipient_script=recipient_script,
        fee_rate=3
    )
    
    try:
        builder.set_mint_parameters(params)
        print(f"✓ Set NFT parameters: Token #{token_id} from collection {collection_id[:16]}...")
        print(f"  - Name: {metadata.name}")
        print(f"  - Attributes: {len(metadata.attributes)} traits")
    except Exception as e:
        print(f"✗ Failed to set parameters: {e}")
        return False
    
    # Build transaction
    validator_script = b'nft_collection_covenant_script_with_minter_auth_and_royalty_enforcement'
    validator_amount = 50000000  # 0.5 BTC
    fee_amount = 8000  # 0.00008 BTC
    
    try:
        builder.build_mint_transaction(
            validator_txid="f" * 64,
            validator_vout=2,
            validator_script=validator_script,
            validator_amount=validator_amount,
            fee_amount=fee_amount
        )
        print(f"✓ Built complete NFT mint transaction")
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
    print(f"  - Collection ID: {summary['collection_id'][:16]}...")
    print(f"  - Token ID: #{summary['token_id']}")
    print(f"  - NFT Name: {summary['metadata_name']}")
    print(f"  - Transaction ID: {summary['transaction_id'][:16]}...")
    print(f"  - Inputs: {summary['num_inputs']}")
    print(f"  - Outputs: {summary['num_outputs']}")
    print(f"  - Fee: {summary.get('fee', 'N/A')} satoshis")
    print(f"  - Metadata URI: {summary.get('metadata_uri', 'N/A')}")
    print(f"  - Content Hash: {summary.get('content_hash', 'N/A')[:16]}...")
    
    # Test serialization
    try:
        psbt_bytes = builder.serialize()
        psbt_b64 = builder.to_base64()
        print(f"✓ PSBT serialized: {len(psbt_bytes)} bytes, {len(psbt_b64)} chars base64")
        print(f"  - PSBT (first 50 chars): {psbt_b64[:50]}...")
    except Exception as e:
        print(f"✗ Serialization failed: {e}")
        return False
    
    # Test collection covenant script creation
    try:
        authorized_minter = b'x' * 33  # Mock public key
        max_supply = 10000
        royalty_address = b'y' * 20  # Mock royalty address
        royalty_basis_points = 750  # 7.5% royalty
        
        covenant = builder.create_collection_covenant_script(
            collection_id,
            authorized_minter,
            max_supply,
            royalty_address,
            royalty_basis_points
        )
        print(f"✓ Created collection covenant script: {len(covenant)} bytes")
        print(f"  - Max supply: {max_supply:,} NFTs")
        print(f"  - Royalty: {royalty_basis_points/100}%")
    except Exception as e:
        print(f"✗ Covenant creation failed: {e}")
        return False
    
    # Test metadata encoding
    try:
        metadata_json = builder._encode_metadata_json()
        print(f"✓ Encoded metadata JSON: {len(metadata_json)} characters")
        
        import json
        parsed = json.loads(metadata_json)
        print(f"  - Attributes: {len(parsed.get('attributes', []))}")
        print(f"  - Has image: {'image' in parsed}")
        print(f"  - Has content hash: {'content_hash' in parsed}")
    except Exception as e:
        print(f"✗ Metadata encoding failed: {e}")
        return False
    
    # Test content hash calculation
    try:
        test_content = b"This is test NFT content for hashing"
        content_hash = builder.calculate_content_hash(test_content)
        print(f"✓ Calculated content hash: {content_hash[:16]}...")
    except Exception as e:
        print(f"✗ Content hash calculation failed: {e}")
        return False
    
    return True


def test_uri_validation():
    """Test URI validation for different schemes."""
    print("\nTesting URI Validation...")
    
    builder = NFTMintPSBTBuilder()
    
    test_cases = [
        ("ipfs://QmTest123456789abcdefghijklmnopqrstuvwxyz", True, "Valid IPFS URI"),
        ("https://example.com/metadata.json", True, "Valid HTTPS URI"),
        ("http://api.example.com/nft/metadata", True, "Valid HTTP URI"),
        ("onchain://abc123def456:0", True, "Valid on-chain reference"),
        ("ipfs://short", False, "Too short IPFS hash"),
        ("https://invalid", False, "Invalid HTTPS URI"),
        ("ftp://example.com/file", False, "Unsupported scheme"),
        ("", False, "Empty URI"),
    ]
    
    passed = 0
    failed = 0
    
    for uri, expected, description in test_cases:
        result = builder.validate_metadata_uri(uri)
        if result == expected:
            print(f"✓ {description}: {uri[:30]}...")
            passed += 1
        else:
            print(f"✗ {description}: {uri[:30]}... (expected {expected}, got {result})")
            failed += 1
    
    print(f"URI validation: {passed} passed, {failed} failed")
    return failed == 0


def test_error_handling():
    """Test error handling scenarios."""
    print("\nTesting Error Handling...")
    
    builder = NFTMintPSBTBuilder()
    
    # Test invalid collection ID
    try:
        metadata = NFTMetadata(name="Test NFT")
        invalid_params = NFTMintParameters(
            collection_id="invalid_collection_id",
            token_id=1,
            metadata=metadata,
            recipient_script=bytes(22)
        )
        print("✗ Should have failed with invalid collection ID")
        return False
    except Exception:
        print("✓ Correctly rejected invalid collection ID")
    
    # Test invalid token ID
    try:
        metadata = NFTMetadata(name="Test NFT")
        invalid_params = NFTMintParameters(
            collection_id="a" * 64,
            token_id=-1,
            metadata=metadata,
            recipient_script=bytes(22)
        )
        print("✗ Should have failed with invalid token ID")
        return False
    except Exception:
        print("✓ Correctly rejected invalid token ID")
    
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
        metadata = NFTMetadata(name="Test NFT")
        valid_params = NFTMintParameters(
            collection_id="a" * 64,
            token_id=1,
            metadata=metadata,
            recipient_script=bytes(22)
        )
        builder.set_mint_parameters(valid_params)
        
        builder.build_mint_transaction(
            validator_txid="c" * 64,
            validator_vout=0,
            validator_script=b'script',
            validator_amount=500,  # Too small
            fee_amount=10000
        )
        print("✗ Should have failed with insufficient funds")
        return False
    except Exception:
        print("✓ Correctly detected insufficient funds")
    
    return True


def main():
    """Run integration tests."""
    print("Running NFT Mint PSBT Integration Tests...\n")
    
    tests = [
        test_nft_mint_integration,
        test_uri_validation,
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