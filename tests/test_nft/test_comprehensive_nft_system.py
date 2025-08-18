"""
Comprehensive Test Suite for BNAP NFT System

Tests all NFT components including metadata validation, content management,
storage systems, immutability enforcement, and complete integration workflows.
"""

import json
import pytest
import tempfile
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

# Import all NFT system components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from nft import (
    # Core metadata
    NFTMetadata, NFTAttribute, MetadataValidator, CollectionMetadata,
    
    # Content management
    ContentHasher, ContentManager, MerkleTree, StorageType,
    LocalStorage, HTTPStorage, TaprootStorage,
    
    # Collections
    CollectionManifest, TokenTracker, CollectionManager, MintingRule,
    
    # Enhanced features
    URIResolver, EnhancedTaprootStorage, TaprootVersion, CompressionType,
    ImmutableMetadata, MetadataState, ImmutabilityLevel,
    create_immutable_nft, verify_metadata_immutability
)


class TestNFTMetadata:
    """Test NFT metadata validation and management."""
    
    def test_basic_nft_creation(self):
        """Test basic NFT metadata creation."""
        nft = NFTMetadata(
            name="Test NFT",
            description="A test NFT for validation",
            image="ipfs://QmTestHash123"
        )
        
        assert nft.name == "Test NFT"
        assert nft.description == "A test NFT for validation"
        assert nft.image == "ipfs://QmTestHash123"
        assert nft.schema_version == "2.0"
        assert len(nft.attributes) == 0
    
    def test_nft_with_attributes(self):
        """Test NFT with various attribute types."""
        attributes = [
            NFTAttribute("Color", "Blue"),
            NFTAttribute("Rarity", 95, max_value=100),
            NFTAttribute("Animated", False),
            NFTAttribute("Powers", ["Fire", "Ice"])
        ]
        
        nft = NFTMetadata(
            name="Attribute Test NFT",
            description="Testing attribute validation",
            image="https://example.com/image.png",
            attributes=attributes
        )
        
        assert len(nft.attributes) == 4
        assert nft.attributes[0].trait_type == "Color"
        assert nft.attributes[1].value == 95
        assert nft.attributes[2].value is False
        assert nft.attributes[3].value == ["Fire", "Ice"]
    
    def test_invalid_url_validation(self):
        """Test URL validation catches invalid formats."""
        with pytest.raises(ValueError, match="Invalid URL format"):
            NFTMetadata(
                name="Invalid NFT",
                description="Testing invalid URL",
                image="not-a-valid-url"
            )
    
    def test_background_color_validation(self):
        """Test background color validation."""
        # Valid color
        nft = NFTMetadata(
            name="Color Test",
            description="Testing color validation",
            image="ipfs://QmTest",
            background_color="FF0000"
        )
        assert nft.background_color == "FF0000"
        
        # Invalid color
        with pytest.raises(ValueError, match="Background color must be 6-digit hex"):
            NFTMetadata(
                name="Invalid Color",
                description="Testing invalid color",
                image="ipfs://QmTest",
                background_color="red"
            )
    
    def test_metadata_serialization(self):
        """Test metadata serialization and deserialization."""
        nft = NFTMetadata(
            name="Serialization Test",
            description="Testing JSON serialization",
            image="ipfs://QmSerializationTest",
            attributes=[NFTAttribute("Test", "Value")]
        )
        
        # Test to_dict
        metadata_dict = nft.to_dict()
        assert metadata_dict["name"] == "Serialization Test"
        assert len(metadata_dict["attributes"]) == 1
        
        # Test JSON serialization
        json_str = nft.to_json()
        parsed = json.loads(json_str)
        assert parsed["name"] == "Serialization Test"
    
    def test_metadata_validation(self):
        """Test metadata validator functionality."""
        validator = MetadataValidator()
        
        # Valid metadata
        valid_metadata = {
            "name": "Valid NFT",
            "description": "A valid NFT",
            "image": "ipfs://QmValidHash",
            "attributes": []
        }
        
        errors = validator.validate(valid_metadata)
        assert len(errors) == 0
        
        # Invalid metadata
        invalid_metadata = {
            "name": "",  # Empty name
            "image": "invalid-url",  # Invalid URL
            "attributes": "not-a-list"  # Wrong type
        }
        
        errors = validator.validate(invalid_metadata)
        assert len(errors) > 0


class TestContentManagement:
    """Test content hashing and storage systems."""
    
    def test_content_hashing(self):
        """Test content hashing with different algorithms."""
        hasher = ContentHasher()
        test_content = b"Test content for hashing"
        
        # Test default SHA256
        content_hash = hasher.hash_content(test_content, "text/plain")
        assert len(content_hash.hash_value) == 64  # SHA256 hex length
        assert content_hash.algorithm.value == "sha256"
        assert content_hash.content_size == len(test_content)
        assert content_hash.content_type == "text/plain"
        
        # Test content verification
        assert hasher.verify_content(test_content, content_hash)
        
        # Test tampered content detection
        tampered_content = b"Tampered content"
        assert not hasher.verify_content(tampered_content, content_hash)
    
    def test_merkle_tree(self):
        """Test Merkle tree for multi-file integrity."""
        tree = MerkleTree()
        
        # Add multiple content items
        contents = [
            b"Content 1",
            b"Content 2", 
            b"Content 3"
        ]
        
        hashes = []
        for content in contents:
            content_hash = tree.add_content(content, "text/plain")
            hashes.append(content_hash)
        
        # Calculate root
        root = tree.calculate_root()
        assert len(root) == 64  # SHA256 hex length
        
        # Test proof generation and verification
        proof = tree.generate_proof(0)
        valid = tree.verify_proof(hashes[0].hash_value, 0, proof, root)
        assert valid
    
    def test_local_storage(self):
        """Test local filesystem storage."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = LocalStorage(temp_dir)
            test_content = b"Local storage test content"
            
            # Store content
            content_info = storage.store(test_content, "test.txt", "text/plain")
            
            assert content_info.uri.startswith("file://")
            assert content_info.storage_type == StorageType.LOCAL
            assert content_info.content_size == len(test_content)
            assert content_info.filename == "test.txt"
            
            # Retrieve content
            retrieved = storage.retrieve(content_info.uri)
            assert retrieved == test_content
            
            # Test existence check
            assert storage.exists(content_info.uri)
    
    def test_content_manager(self):
        """Test content manager with multiple storage backends."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ContentManager()
            
            # Add storage backends
            local_storage = LocalStorage(temp_dir)
            manager.add_storage_backend(local_storage)
            
            # Store content
            test_content = b"Content manager test"
            content_info = manager.store_content(
                test_content,
                StorageType.LOCAL,
                "manager_test.txt",
                "text/plain"
            )
            
            # Retrieve and verify
            retrieved = manager.retrieve_content(content_info.uri)
            assert retrieved == test_content
            
            # Test integrity verification
            integrity_valid = manager.verify_content_integrity(
                content_info.uri, 
                content_info.content_hash
            )
            assert integrity_valid


class TestCollectionManagement:
    """Test NFT collection management and minting."""
    
    def test_collection_manifest(self):
        """Test collection manifest creation and management."""
        manifest = CollectionManifest(
            name="Test Collection",
            description="A test NFT collection",
            symbol="TEST",
            total_supply=1000
        )
        
        assert manifest.name == "Test Collection"
        assert manifest.total_supply == 1000
        assert manifest.minted_count == 0
        assert len(manifest.minting_rules) == 0
        
        # Test token ID assignment
        next_id = manifest.get_next_token_id()
        assert next_id == 1
        
        # Test minting
        success = manifest.mint_token(next_id, {"name": "Test Token"})
        assert success
        assert manifest.minted_count == 1
        assert next_id in manifest.minted_tokens
    
    def test_minting_rules(self):
        """Test collection minting rules and validation."""
        from nft.collections import MintingPhase
        from datetime import timedelta
        
        # Create minting rule
        rule = MintingRule(
            name="Early Access",
            phase=MintingPhase.ALLOWLIST,
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc) + timedelta(days=7),
            max_per_wallet=3,
            price_btc=0.001
        )
        
        manifest = CollectionManifest(
            name="Rule Test Collection",
            description="Testing minting rules",
            symbol="RULE",
            total_supply=100,
            minting_rules=[rule]
        )
        
        assert len(manifest.minting_rules) == 1
        
        # Test rule validation
        current_rule = manifest.get_current_minting_rule()
        assert current_rule is not None
        assert current_rule.name == "Early Access"
    
    def test_collection_manager(self):
        """Test collection manager functionality."""
        manager = CollectionManager()
        
        # Create test collection
        manifest = CollectionManifest(
            name="Manager Test Collection",
            description="Testing collection manager",
            symbol="MGR",
            total_supply=50
        )
        
        collection_id = manager.create_collection(manifest)
        assert collection_id is not None
        
        # Get collection
        retrieved = manager.get_collection(collection_id)
        assert retrieved is not None
        assert retrieved.name == "Manager Test Collection"
        
        # Test minting through manager
        nft_metadata = NFTMetadata(
            name="Manager Test NFT",
            description="NFT created through manager",
            image="ipfs://QmManagerTest"
        )
        
        success = manager.mint_nft(collection_id, nft_metadata)
        assert success
        
        # Verify minting
        updated_collection = manager.get_collection(collection_id)
        assert updated_collection.minted_count == 1


class TestURIResolution:
    """Test URI resolution and HTTP gateway functionality."""
    
    def test_uri_resolver_creation(self):
        """Test URI resolver initialization."""
        resolver = URIResolver()
        
        # Check default gateways are loaded
        stats = resolver.get_statistics()
        assert stats["gateways"]["ipfs_gateway"] > 0
        assert stats["gateways"]["arweave_gateway"] > 0
        
        resolver.close()
    
    def test_data_uri_resolution(self):
        """Test data URI resolution."""
        resolver = URIResolver()
        
        # Test base64 data URI
        test_data = "Hello BNAP"
        import base64
        encoded = base64.b64encode(test_data.encode()).decode()
        uri = f"data:text/plain;base64,{encoded}"
        
        content, content_type, metadata = resolver.resolve_uri(uri)
        
        assert content.decode() == test_data
        assert content_type == "text/plain"
        assert metadata["source"] == "data_uri"
        
        resolver.close()
    
    def test_file_uri_resolution(self):
        """Test file URI resolution."""
        resolver = URIResolver()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            test_content = "File URI test content"
            temp_file.write(test_content)
            temp_file_path = temp_file.name
        
        try:
            uri = f"file://{temp_file_path}"
            content, content_type, metadata = resolver.resolve_uri(uri)
            
            assert content.decode() == test_content
            assert metadata["source"] == "local_file"
        finally:
            Path(temp_file_path).unlink()
            resolver.close()
    
    def test_caching_functionality(self):
        """Test content caching."""
        from nft.gateway import ContentCache, CacheStrategy
        
        cache = ContentCache(CacheStrategy.MEMORY)
        
        # Test cache put/get
        test_uri = "test://cache"
        test_content = b"Cached content"
        test_hash = "test_hash_123"
        
        cache.put(test_uri, test_content, "text/plain", test_hash)
        
        cached_entry = cache.get(test_uri)
        assert cached_entry is not None
        assert cached_entry.content == test_content
        assert cached_entry.content_type == "text/plain"


class TestTaprootStorage:
    """Test Taproot envelope content storage."""
    
    def test_taproot_envelope_creation(self):
        """Test Taproot envelope creation and serialization."""
        from nft.taproot import TaprootEnvelope
        
        envelope = TaprootEnvelope(
            version=TaprootVersion.V3,
            content_type="application/json",
            content=b'{"test": "content"}',
            compression=CompressionType.ZLIB
        )
        
        # Test serialization
        envelope_bytes = envelope.to_bytes()
        assert len(envelope_bytes) > 0
        
        # Test deserialization
        reconstructed = TaprootEnvelope.from_bytes(envelope_bytes)
        assert reconstructed.version == envelope.version
        assert reconstructed.content_type == envelope.content_type
        assert reconstructed.compression == envelope.compression
    
    def test_taproot_compression(self):
        """Test Taproot content compression."""
        from nft.taproot import TaprootCompressor
        
        test_content = b"A" * 100 + b"B" * 100  # Repetitive for compression
        
        # Test compression
        compressed = TaprootCompressor.compress(test_content, CompressionType.ZLIB)
        assert len(compressed) < len(test_content)
        
        # Test decompression
        decompressed = TaprootCompressor.decompress(compressed, CompressionType.ZLIB)
        assert decompressed == test_content
        
        # Test best compression selection
        best_type, best_compressed = TaprootCompressor.find_best_compression(test_content)
        assert best_type in [CompressionType.ZLIB, CompressionType.GZIP, CompressionType.BROTLI]
    
    def test_enhanced_taproot_storage(self):
        """Test enhanced Taproot storage functionality."""
        storage = EnhancedTaprootStorage(max_chunk_size=50, auto_compress=True)
        
        test_content = b"Enhanced Taproot storage test content"
        
        # Store content
        content_info = storage.store(test_content, "test.txt", "text/plain")
        
        assert content_info.storage_type == StorageType.TAPROOT
        assert content_info.uri.startswith("taproot://")
        assert "chunks" in content_info.metadata
        assert "compression" in content_info.metadata
        
        # Test statistics
        stats = storage.get_statistics()
        assert stats["storage"]["content_stored"] == 1
        assert stats["blockchain"]["transactions"] >= 1


class TestImmutabilityEnforcement:
    """Test metadata immutability and version control."""
    
    def test_immutable_metadata_creation(self):
        """Test immutable metadata container creation."""
        nft = NFTMetadata(
            name="Immutable Test",
            description="Testing immutability",
            image="ipfs://QmImmutableTest"
        )
        
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        assert immutable_nft.get_current_state() == MetadataState.DRAFT
        assert immutable_nft.get_immutability_level() == ImmutabilityLevel.PARTIAL
        assert immutable_nft._current_version == 1
    
    def test_field_modification_rules(self):
        """Test field modification rules based on immutability level."""
        nft = NFTMetadata(
            name="Modification Test",
            description="Testing modification rules",
            image="ipfs://QmModTest"
        )
        
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        # Test modifications in draft state
        assert immutable_nft.can_modify("name")
        assert immutable_nft.can_modify("description")
        assert immutable_nft.can_modify("image")
        
        # Test successful field update
        success = immutable_nft.update_field("description", "Updated description")
        assert success
    
    def test_version_control(self):
        """Test metadata version control."""
        nft = NFTMetadata(
            name="Version Test",
            description="Testing versions",
            image="ipfs://QmVersionTest"
        )
        
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        # Create new version
        changes = {"description": "New version description"}
        new_version = immutable_nft.create_new_version(
            changes, 
            "Updated description",
            "test_user"
        )
        
        assert new_version == 2
        assert immutable_nft._current_version == 2
        
        # Test version history
        versions = immutable_nft.get_all_versions()
        assert len(versions) == 2
        assert versions[0].version == 1
        assert versions[1].version == 2
    
    def test_state_transitions(self):
        """Test metadata state transitions."""
        nft = NFTMetadata(
            name="State Test",
            description="Testing state transitions",
            image="ipfs://QmStateTest"
        )
        
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        # Test draft -> pending_mint
        success = immutable_nft.change_state(MetadataState.PENDING_MINT)
        assert success
        assert immutable_nft.get_current_state() == MetadataState.PENDING_MINT
        
        # Test pending_mint -> minted
        success = immutable_nft.mint_metadata("test_tx_123")
        assert success
        assert immutable_nft.get_current_state() == MetadataState.MINTED
        
        # Test minted -> frozen
        success = immutable_nft.freeze_metadata("freeze_tx_456")
        assert success
        assert immutable_nft.get_current_state() == MetadataState.FROZEN
    
    def test_immutability_after_minting(self):
        """Test that metadata becomes immutable after minting."""
        nft = NFTMetadata(
            name="Mint Protection Test",
            description="Testing post-mint protection",
            image="ipfs://QmMintTest"
        )
        
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        # Mint the NFT
        immutable_nft.change_state(MetadataState.PENDING_MINT)
        immutable_nft.mint_metadata("mint_tx_789")
        
        # Test that modifications are blocked
        success = immutable_nft.update_field("name", "Should not work")
        assert not success
        
        # Test immutability proof creation
        proof = immutable_nft.get_immutability_proof()
        assert proof is not None
        assert proof.transaction_id == "mint_tx_789"
        assert len(proof.signature) > 0
    
    def test_audit_trail(self):
        """Test comprehensive audit trail functionality."""
        nft = NFTMetadata(
            name="Audit Test",
            description="Testing audit trails",
            image="ipfs://QmAuditTest"
        )
        
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        # Perform various operations
        immutable_nft.update_field("description", "Updated for audit test", "user1")
        immutable_nft.change_state(MetadataState.PENDING_MINT, user_id="minter")
        immutable_nft.mint_metadata("audit_tx_123", "minter")
        
        # Check audit trail
        audit_trail = immutable_nft.get_audit_trail()
        assert len(audit_trail) >= 4  # created, updated, state_changed, minted
        
        # Check specific audit entries
        actions = [entry.action.value for entry in audit_trail]
        assert "created" in actions
        assert "updated" in actions
        assert "state_changed" in actions
        assert "minted" in actions
    
    def test_integrity_verification(self):
        """Test complete integrity verification."""
        nft = NFTMetadata(
            name="Integrity Test",
            description="Testing integrity verification",
            image="ipfs://QmIntegrityTest"
        )
        
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        # Complete minting process
        immutable_nft.change_state(MetadataState.PENDING_MINT)
        immutable_nft.mint_metadata("integrity_tx_456")
        
        # Verify integrity
        integrity = immutable_nft.verify_integrity()
        
        assert integrity["current_version_valid"]
        assert integrity["audit_trail_complete"]
        assert integrity["immutability_proof_valid"]
        assert integrity["version_chain_valid"]


class TestIntegrationWorkflows:
    """Test complete end-to-end NFT workflows."""
    
    def test_complete_nft_lifecycle(self):
        """Test complete NFT lifecycle from creation to immutable state."""
        # 1. Create NFT metadata
        nft = NFTMetadata(
            name="Lifecycle Test NFT",
            description="Testing complete NFT lifecycle",
            image="ipfs://QmLifecycleTest",
            attributes=[
                NFTAttribute("Test", "Value"),
                NFTAttribute("Lifecycle", True)
            ]
        )
        
        # 2. Create immutable container
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.PARTIAL)
        
        # 3. Store content in multiple storage systems
        with tempfile.TemporaryDirectory() as temp_dir:
            # Local storage
            local_storage = LocalStorage(temp_dir)
            metadata_json = nft.to_json().encode('utf-8')
            local_info = local_storage.store(metadata_json, "metadata.json", "application/json")
            
            # Taproot storage
            taproot_storage = EnhancedTaprootStorage(max_chunk_size=100)
            taproot_info = taproot_storage.store(metadata_json, "metadata.json", "application/json")
            
            # 4. Test content integrity
            hasher = ContentHasher()
            original_hash = hasher.hash_content(metadata_json, "application/json")
            
            # Verify local storage
            local_retrieved = local_storage.retrieve(local_info.uri)
            local_hash = hasher.hash_content(local_retrieved, "application/json")
            assert original_hash.hash_value == local_hash.hash_value
            
            # 5. Complete minting workflow
            immutable_nft.change_state(MetadataState.PENDING_MINT, user_id="system")
            immutable_nft.mint_metadata("lifecycle_tx_789", "system")
            immutable_nft.freeze_metadata("freeze_tx_abc", "admin")
            
            # 6. Verify final state
            assert immutable_nft.get_current_state() == MetadataState.FROZEN
            
            # 7. Verify integrity
            integrity = immutable_nft.verify_integrity()
            assert all(integrity.values())
            
            # 8. Test serialization round-trip
            metadata_dict = immutable_nft.to_dict()
            verification = verify_metadata_immutability(metadata_dict)
            assert not verification.get("error")
    
    def test_collection_with_multiple_nfts(self):
        """Test collection management with multiple NFTs."""
        # Create collection
        manifest = CollectionManifest(
            name="Integration Test Collection",
            description="Testing collection with multiple NFTs",
            symbol="INTEG",
            total_supply=5
        )
        
        manager = CollectionManager()
        collection_id = manager.create_collection(manifest)
        
        # Create and mint multiple NFTs
        nfts_minted = []
        for i in range(3):
            nft = NFTMetadata(
                name=f"Integration NFT #{i+1}",
                description=f"NFT number {i+1} in integration test",
                image=f"ipfs://QmIntegrationTest{i+1}",
                attributes=[NFTAttribute("Number", i+1)]
            )
            
            success = manager.mint_nft(collection_id, nft)
            assert success
            nfts_minted.append(nft)
        
        # Verify collection state
        updated_collection = manager.get_collection(collection_id)
        assert updated_collection.minted_count == 3
        assert len(updated_collection.minted_tokens) == 3
        
        # Test uniqueness enforcement
        duplicate_nft = NFTMetadata(
            name="Integration NFT #1",  # Same name as first NFT
            description="Duplicate test",
            image="ipfs://QmDuplicateTest"
        )
        
        # This should fail due to uniqueness constraints
        success = manager.mint_nft(collection_id, duplicate_nft)
        assert not success  # Should fail due to duplicate name
    
    def test_uri_resolution_with_storage_integration(self):
        """Test URI resolution integrated with various storage systems."""
        resolver = URIResolver()
        
        # Test multiple URI schemes
        test_cases = [
            # Data URI
            ("data:text/plain;base64,VGVzdCBjb250ZW50", "Test content"),
        ]
        
        # Create temporary file for file URI test
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            file_content = "File URI integration test"
            temp_file.write(file_content)
            temp_file_path = temp_file.name
            
            test_cases.append((f"file://{temp_file_path}", file_content))
        
        try:
            for uri, expected_content in test_cases:
                content, content_type, metadata = resolver.resolve_uri(uri)
                assert content.decode() == expected_content
                assert "source" in metadata
        finally:
            Path(temp_file_path).unlink()
            resolver.close()
    
    def test_comprehensive_error_handling(self):
        """Test error handling across all components."""
        # Test invalid metadata
        with pytest.raises(ValueError):
            NFTMetadata(
                name="",  # Invalid empty name
                description="Error test",
                image="ipfs://QmErrorTest"
            )
        
        # Test invalid URI resolution
        resolver = URIResolver()
        with pytest.raises(ValueError):
            resolver.resolve_uri("invalid://not-a-real-scheme")
        resolver.close()
        
        # Test invalid state transitions
        nft = NFTMetadata(
            name="Error Test NFT",
            description="Testing error conditions",
            image="ipfs://QmErrorTest"
        )
        
        immutable_nft = create_immutable_nft(nft, ImmutabilityLevel.FULL)
        immutable_nft.mint_metadata("error_tx_123")
        
        # Try invalid state transition
        success = immutable_nft.change_state(MetadataState.DRAFT)  # Can't go back to draft
        assert not success
        
        # Test modification of immutable fields
        success = immutable_nft.update_field("name", "Should not work")
        assert not success


def run_comprehensive_test_suite():
    """Run the complete NFT system test suite."""
    print("Running Comprehensive BNAP NFT System Test Suite...")
    print("=" * 60)
    
    test_classes = [
        TestNFTMetadata,
        TestContentManagement,
        TestCollectionManagement,
        TestURIResolution,
        TestTaprootStorage,
        TestImmutabilityEnforcement,
        TestIntegrationWorkflows
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for test_class in test_classes:
        print(f"\n🔬 Running {test_class.__name__}...")
        
        test_instance = test_class()
        test_methods = [method for method in dir(test_instance) if method.startswith('test_')]
        
        for test_method in test_methods:
            total_tests += 1
            try:
                method = getattr(test_instance, test_method)
                method()
                passed_tests += 1
                print(f"  ✓ {test_method}")
            except Exception as e:
                failed_tests.append(f"{test_class.__name__}.{test_method}: {str(e)}")
                print(f"  ✗ {test_method}: {str(e)}")
    
    print(f"\n📊 Test Results Summary:")
    print(f"  Total tests: {total_tests}")
    print(f"  Passed: {passed_tests}")
    print(f"  Failed: {len(failed_tests)}")
    
    if failed_tests:
        print(f"\n❌ Failed Tests:")
        for failure in failed_tests:
            print(f"  • {failure}")
    
    success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
    print(f"\n🎯 Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 95:
        print("🎉 Excellent! NFT system is highly reliable.")
    elif success_rate >= 90:
        print("✅ Good! NFT system is reliable with minor issues.")
    elif success_rate >= 80:
        print("⚠️  Fair! NFT system needs improvement.")
    else:
        print("🚨 Poor! NFT system requires significant fixes.")
    
    return success_rate >= 95


if __name__ == "__main__":
    success = run_comprehensive_test_suite()
    exit(0 if success else 1)