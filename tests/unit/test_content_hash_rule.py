"""
Tests for Content Hash Rule

Tests the ContentHashRule validation logic including NFT metadata parsing,
content reference validation, and hash verification.
"""

import pytest
import json
import time
import hashlib
import base64
from unittest.mock import Mock, patch

from validator.core import ValidationContext
from validator.rules.content_hash import (
    ContentHashRule,
    ContentReference,
    NFTMetadata,
    ValidationResult,
    ContentType,
    HashMethod,
    ContentLocation,
    create_content_hash_rule,
    validate_nft_metadata_quick,
    extract_content_hashes
)
from registry.schema import AssetType
from crypto.commitments import OperationType


class TestContentReference:
    """Test ContentReference data class."""
    
    def test_content_reference_creation(self):
        """Test basic content reference creation."""
        ref = ContentReference(
            uri="https://example.com/image.png",
            hash="a" * 64,  # 64 character hex string
            hash_method=HashMethod.SHA256,
            content_type=ContentType.IMAGE
        )
        
        assert ref.uri == "https://example.com/image.png"
        assert len(ref.hash) == 64
        assert ref.hash_method == HashMethod.SHA256
        assert ref.content_type == ContentType.IMAGE
    
    def test_content_reference_validation(self):
        """Test content reference validation on creation."""
        # Valid reference
        ref = ContentReference(
            uri="ipfs://QmHash123",
            hash="QmHash123",
            hash_method=HashMethod.IPFS,
            content_type=ContentType.IMAGE
        )
        assert ref.uri == "ipfs://QmHash123"
        
        # Invalid - empty URI
        with pytest.raises(ValueError, match="URI and hash are required"):
            ContentReference(
                uri="",
                hash="validhash",
                hash_method=HashMethod.SHA256,
                content_type=ContentType.IMAGE
            )
        
        # Invalid - empty hash
        with pytest.raises(ValueError, match="URI and hash are required"):
            ContentReference(
                uri="https://example.com/test.png",
                hash="",
                hash_method=HashMethod.SHA256,
                content_type=ContentType.IMAGE
            )
    
    def test_hash_format_validation(self):
        """Test hash format validation."""
        # Valid SHA256
        ref = ContentReference(
            uri="https://example.com/test.png",
            hash="a" * 64,
            hash_method=HashMethod.SHA256,
            content_type=ContentType.IMAGE
        )
        assert len(ref.hash) == 64
        
        # Invalid SHA256 - wrong length
        with pytest.raises(ValueError, match="SHA256 hash must be 64 hex characters"):
            ContentReference(
                uri="https://example.com/test.png",
                hash="a" * 32,  # Too short
                hash_method=HashMethod.SHA256,
                content_type=ContentType.IMAGE
            )
        
        # Valid IPFS CID
        ref = ContentReference(
            uri="ipfs://QmTest",
            hash="QmTest123456789012345678901234567890123456",
            hash_method=HashMethod.IPFS,
            content_type=ContentType.IMAGE
        )
        assert ref.hash.startswith("Qm")
        
        # Invalid IPFS CID
        with pytest.raises(ValueError, match="Invalid IPFS CID format"):
            ContentReference(
                uri="ipfs://invalid",
                hash="invalid",
                hash_method=HashMethod.IPFS,
                content_type=ContentType.IMAGE
            )


class TestNFTMetadata:
    """Test NFTMetadata data class."""
    
    def test_metadata_creation(self):
        """Test basic metadata creation."""
        image_ref = ContentReference(
            uri="https://example.com/image.png",
            hash="a" * 64,
            hash_method=HashMethod.SHA256,
            content_type=ContentType.IMAGE
        )
        
        metadata = NFTMetadata(
            name="Test NFT",
            description="A test NFT",
            image=image_ref
        )
        
        assert metadata.name == "Test NFT"
        assert metadata.description == "A test NFT"
        assert metadata.image == image_ref
    
    def test_get_all_content_references(self):
        """Test getting all content references from metadata."""
        image_ref = ContentReference(
            uri="https://example.com/image.png",
            hash="a" * 64,
            hash_method=HashMethod.SHA256,
            content_type=ContentType.IMAGE
        )
        
        animation_ref = ContentReference(
            uri="https://example.com/animation.mp4",
            hash="b" * 64,
            hash_method=HashMethod.SHA256,
            content_type=ContentType.VIDEO
        )
        
        additional_ref = ContentReference(
            uri="https://example.com/metadata.json",
            hash="c" * 64,
            hash_method=HashMethod.SHA256,
            content_type=ContentType.JSON
        )
        
        metadata = NFTMetadata(
            name="Test NFT",
            image=image_ref,
            animation_url=animation_ref,
            additional_content=[additional_ref]
        )
        
        refs = metadata.get_all_content_references()
        
        assert len(refs) == 3
        assert image_ref in refs
        assert animation_ref in refs
        assert additional_ref in refs


class TestContentHashRule:
    """Test ContentHashRule functionality."""
    
    def test_rule_creation(self):
        """Test basic rule creation."""
        rule = ContentHashRule()
        
        assert rule.name == "content_hash"
        assert "content hash" in rule.description.lower()
        assert rule.enabled is True
        assert rule.enable_content_fetching is False
        assert rule.strict_validation is True
        assert rule.max_content_size == 100 * 1024 * 1024  # 100MB
        assert rule.timeout_seconds == 30
    
    def test_rule_creation_with_config(self):
        """Test rule creation with custom configuration."""
        rule = ContentHashRule(
            enable_content_fetching=True,
            max_content_size=50 * 1024 * 1024,
            timeout_seconds=60,
            strict_validation=False
        )
        
        assert rule.enable_content_fetching is True
        assert rule.max_content_size == 50 * 1024 * 1024
        assert rule.timeout_seconds == 60
        assert rule.strict_validation is False
    
    def test_applicability_nft_mint_operation(self):
        """Test rule applicability for NFT mint operations."""
        rule = ContentHashRule()
        
        # Valid NFT mint operation with metadata
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            metadata={"name": "Test NFT", "image": "https://example.com/test.png"}
        )
        
        assert rule.is_applicable(context) is True
    
    def test_applicability_non_nft_operation(self):
        """Test rule applicability for non-NFT operations."""
        rule = ContentHashRule()
        
        # Transfer operation should not be applicable
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            asset_type=AssetType.NFT,
            operation=OperationType.TRANSFER,
            metadata={"name": "Test NFT"}
        )
        
        assert rule.is_applicable(context) is False
    
    def test_applicability_missing_data(self):
        """Test rule applicability with missing required data."""
        rule = ContentHashRule()
        
        # Missing asset_id
        context = ValidationContext(
            psbt_data={},
            asset_id=None,
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            metadata={"name": "Test NFT"}
        )
        assert rule.is_applicable(context) is False
        
        # Missing metadata
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            metadata=None
        )
        assert rule.is_applicable(context) is False
    
    def test_metadata_parsing_json_string(self):
        """Test parsing metadata from JSON string."""
        rule = ContentHashRule()
        
        metadata_json = json.dumps({
            "name": "Test NFT",
            "description": "A test NFT",
            "image": "https://example.com/image.png"
        })
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            metadata=metadata_json
        )
        
        metadata = rule._parse_metadata(context)
        
        assert metadata is not None
        assert metadata.name == "Test NFT"
        assert metadata.description == "A test NFT"
        # Note: image parsing requires content hash, so it might be None without structured data
    
    def test_metadata_parsing_dict(self):
        """Test parsing metadata from dictionary."""
        rule = ContentHashRule()
        
        metadata_dict = {
            "name": "Test NFT",
            "description": "A test NFT",
            "image": {
                "uri": "https://example.com/image.png",
                "hash": "a" * 64,
                "hash_method": "sha256"
            }
        }
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            metadata=metadata_dict
        )
        
        metadata = rule._parse_metadata(context)
        
        assert metadata is not None
        assert metadata.name == "Test NFT"
        assert metadata.image is not None
        assert metadata.image.uri == "https://example.com/image.png"
        assert metadata.image.hash == "a" * 64
    
    def test_metadata_parsing_missing_name(self):
        """Test metadata parsing with missing required name field."""
        rule = ContentHashRule()
        
        metadata_dict = {
            "description": "Missing name",
            "image": "https://example.com/image.png"
        }
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            metadata=metadata_dict
        )
        
        metadata = rule._parse_metadata(context)
        
        assert metadata is None  # Should fail without name
    
    def test_content_reference_parsing(self):
        """Test parsing of content references."""
        rule = ContentHashRule()
        
        # String URI - IPFS
        ref = rule._parse_content_reference("ipfs://QmTest123456789012345678901234567890123456", ContentType.IMAGE)
        assert ref is not None
        assert ref.uri == "ipfs://QmTest123456789012345678901234567890123456"
        assert ref.hash_method == HashMethod.IPFS
        
        # Structured content reference
        content_data = {
            "uri": "https://example.com/image.png",
            "hash": "a" * 64,
            "hash_method": "sha256",
            "type": "image",
            "size": 1024
        }
        
        ref = rule._parse_content_reference(content_data, ContentType.UNKNOWN)
        assert ref is not None
        assert ref.uri == "https://example.com/image.png"
        assert ref.hash == "a" * 64
        assert ref.hash_method == HashMethod.SHA256
        assert ref.content_type == ContentType.IMAGE
        assert ref.size == 1024
    
    def test_uri_format_validation(self):
        """Test URI format validation."""
        rule = ContentHashRule()
        
        # Valid URIs
        assert rule._validate_uri_format("https://example.com/image.png") is True
        assert rule._validate_uri_format("ipfs://QmTest123") is True
        assert rule._validate_uri_format("ar://abcdefghijklmnopqrstuvwxyz1234567890123") is True
        assert rule._validate_uri_format("data:image/png;base64,iVBORw0KGgo=") is True
        
        # Invalid URIs
        assert rule._validate_uri_format("ftp://example.com/file") is False
        assert rule._validate_uri_format("invalid_scheme://test") is False
        assert rule._validate_uri_format("") is False
    
    def test_hash_format_validation(self):
        """Test hash format validation."""
        rule = ContentHashRule()
        
        # Valid SHA256
        assert rule._validate_hash_format("a" * 64, HashMethod.SHA256) is True
        assert rule._validate_hash_format("A" * 64, HashMethod.SHA256) is True
        assert rule._validate_hash_format("123abc" * 10 + "1234", HashMethod.SHA256) is True
        
        # Invalid SHA256
        assert rule._validate_hash_format("a" * 63, HashMethod.SHA256) is False  # Too short
        assert rule._validate_hash_format("a" * 65, HashMethod.SHA256) is False  # Too long
        assert rule._validate_hash_format("gggg" * 16, HashMethod.SHA256) is False  # Invalid hex
        
        # Valid IPFS CID
        assert rule._validate_hash_format("Qm" + "T" * 44, HashMethod.IPFS) is True  # 46 chars total
        assert rule._validate_hash_format("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", HashMethod.IPFS) is True
        
        # Invalid IPFS CID
        assert rule._validate_hash_format("invalidcid", HashMethod.IPFS) is False
        assert rule._validate_hash_format("", HashMethod.IPFS) is False
    
    def test_content_type_inference(self):
        """Test content type inference from URI."""
        rule = ContentHashRule()
        
        # Image types
        assert rule._infer_content_type("https://example.com/image.png", ContentType.UNKNOWN) == ContentType.IMAGE
        assert rule._infer_content_type("https://example.com/photo.JPG", ContentType.UNKNOWN) == ContentType.IMAGE
        assert rule._infer_content_type("https://example.com/icon.svg", ContentType.UNKNOWN) == ContentType.IMAGE
        
        # Video types
        assert rule._infer_content_type("https://example.com/video.mp4", ContentType.UNKNOWN) == ContentType.VIDEO
        assert rule._infer_content_type("https://example.com/movie.webm", ContentType.UNKNOWN) == ContentType.VIDEO
        
        # Audio types
        assert rule._infer_content_type("https://example.com/song.mp3", ContentType.UNKNOWN) == ContentType.AUDIO
        assert rule._infer_content_type("https://example.com/sound.wav", ContentType.UNKNOWN) == ContentType.AUDIO
        
        # Documents
        assert rule._infer_content_type("https://example.com/doc.pdf", ContentType.UNKNOWN) == ContentType.DOCUMENT
        assert rule._infer_content_type("https://example.com/text.txt", ContentType.UNKNOWN) == ContentType.DOCUMENT
        
        # JSON
        assert rule._infer_content_type("https://example.com/metadata.json", ContentType.UNKNOWN) == ContentType.JSON
        
        # Unknown - return default
        assert rule._infer_content_type("https://example.com/unknown.xyz", ContentType.IMAGE) == ContentType.IMAGE
    
    def test_validation_success_with_valid_metadata(self):
        """Test successful validation with valid NFT metadata."""
        rule = ContentHashRule(strict_validation=False)
        
        metadata_dict = {
            "name": "Test NFT",
            "description": "A valid test NFT",
            "image": {
                "uri": "https://example.com/image.png",
                "hash": "a" * 64,
                "hash_method": "sha256"
            },
            "attributes": [
                {"trait_type": "Color", "value": "Blue"},
                {"trait_type": "Rarity", "value": "Common"}
            ]
        }
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            metadata=metadata_dict
        )
        
        result = rule.validate(context)
        
        assert result is True
        assert not context.has_errors()
        assert rule.stats["validations_performed"] == 1
        assert rule.stats["metadata_parsed"] == 1
    
    def test_validation_failure_with_invalid_metadata(self):
        """Test validation failure with invalid NFT metadata."""
        rule = ContentHashRule()
        
        # Missing name field
        metadata_dict = {
            "description": "Invalid metadata without name"
        }
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            metadata=metadata_dict
        )
        
        result = rule.validate(context)
        
        assert result is False
        assert context.has_errors()
        assert rule.stats["invalid_metadata"] == 1
    
    def test_validation_no_content_references_strict(self):
        """Test validation with no content references in strict mode."""
        rule = ContentHashRule(strict_validation=True)
        
        metadata_dict = {
            "name": "NFT without content",
            "description": "This NFT has no content references"
        }
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            metadata=metadata_dict
        )
        
        result = rule.validate(context)
        
        assert result is False
        assert context.has_errors()
        assert "No content references found" in context.validation_errors[0]
    
    def test_validation_no_content_references_non_strict(self):
        """Test validation with no content references in non-strict mode."""
        rule = ContentHashRule(strict_validation=False)
        
        metadata_dict = {
            "name": "NFT without content",
            "description": "This NFT has no content references"
        }
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            metadata=metadata_dict
        )
        
        result = rule.validate(context)
        
        assert result is True
        assert not context.has_errors()
    
    def test_data_uri_content_validation(self):
        """Test validation of content embedded in data URIs."""
        rule = ContentHashRule(enable_content_fetching=True)
        
        # Create test content and its hash
        test_content = "Hello, World!"
        content_bytes = test_content.encode('utf-8')
        expected_hash = hashlib.sha256(content_bytes).hexdigest()
        
        # Create data URI with base64 encoding
        encoded_content = base64.b64encode(content_bytes).decode('ascii')
        data_uri = f"data:text/plain;base64,{encoded_content}"
        
        content_ref = ContentReference(
            uri=data_uri,
            hash=expected_hash,
            hash_method=HashMethod.SHA256,
            content_type=ContentType.DOCUMENT
        )
        
        # Test validation
        result = rule._validate_data_uri_content(content_ref)
        assert result is True
        
        # Test with wrong hash
        wrong_ref = ContentReference(
            uri=data_uri,
            hash="f" * 64,  # Wrong but valid length hash
            hash_method=HashMethod.SHA256,
            content_type=ContentType.DOCUMENT
        )
        
        result = rule._validate_data_uri_content(wrong_ref)
        assert result is False
    
    def test_caching_functionality(self):
        """Test content validation caching."""
        rule = ContentHashRule()
        
        content_ref = ContentReference(
            uri="https://example.com/image.png",
            hash="a" * 64,
            hash_method=HashMethod.SHA256,
            content_type=ContentType.IMAGE
        )
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            metadata={}
        )
        
        # First validation - cache miss
        with patch.object(rule, '_validate_uri_format', return_value=True):
            with patch.object(rule, '_validate_hash_format', return_value=True):
                result1 = rule._validate_content_reference(content_ref, context)
                assert result1 is True
                assert rule.stats["cache_misses"] == 1
                assert rule.stats["cache_hits"] == 0
        
        # Second validation - cache hit
        with patch.object(rule, '_validate_uri_format', return_value=True):
            with patch.object(rule, '_validate_hash_format', return_value=True):
                result2 = rule._validate_content_reference(content_ref, context)
                assert result2 is True
                assert rule.stats["cache_misses"] == 1
                assert rule.stats["cache_hits"] == 1
    
    def test_cache_clearing(self):
        """Test cache clearing functionality."""
        rule = ContentHashRule()
        
        # Populate cache
        rule.content_cache["test_key"] = ValidationResult(
            is_valid=True,
            content_ref=ContentReference("https://test.com", "a" * 64, HashMethod.SHA256, ContentType.IMAGE)
        )
        
        assert len(rule.content_cache) == 1
        
        # Clear entire cache
        rule.clear_cache()
        assert len(rule.content_cache) == 0
        
        # Populate cache again
        rule.content_cache["https://example.com/image.png:hash1"] = ValidationResult(
            is_valid=True,
            content_ref=ContentReference("https://example.com/image.png", "a" * 64, HashMethod.SHA256, ContentType.IMAGE)
        )
        rule.content_cache["https://other.com/video.mp4:hash2"] = ValidationResult(
            is_valid=True,
            content_ref=ContentReference("https://other.com/video.mp4", "b" * 64, HashMethod.SHA256, ContentType.VIDEO)
        )
        
        # Selective clearing
        rule.clear_cache("example.com")
        assert len(rule.content_cache) == 1
        assert "https://other.com/video.mp4:hash2" in rule.content_cache
    
    def test_statistics(self):
        """Test statistics tracking."""
        rule = ContentHashRule()
        
        stats = rule.get_statistics()
        
        expected_keys = [
            "validations_performed",
            "metadata_parsed",
            "content_validated",
            "content_fetch_errors",
            "cache_hits",
            "cache_misses",
            "hash_mismatches",
            "invalid_metadata",
            "cache_hit_rate_percent",
            "success_rate_percent",
            "cached_entries"
        ]
        
        for key in expected_keys:
            assert key in stats
        
        # Initial state
        assert stats["cache_hit_rate_percent"] == 0.0
        assert stats["success_rate_percent"] == 0.0
        assert stats["enable_content_fetching"] is False
        assert stats["strict_validation"] is True
    
    def test_metadata_structure_validation(self):
        """Test metadata structure validation."""
        rule = ContentHashRule()
        
        # Valid metadata structure
        valid_metadata = NFTMetadata(
            name="Valid NFT",
            description="Valid description",
            attributes=[
                {"trait_type": "Color", "value": "Red"},
                {"trait_type": "Size", "value": "Large"}
            ],
            external_url="https://example.com/nft"
        )
        
        context = ValidationContext(psbt_data={}, asset_id=b'\\x01' * 32)
        
        result = rule._validate_metadata_structure(valid_metadata, context)
        assert result is True
        assert not context.has_errors()
        
        # Invalid metadata - missing trait_type
        invalid_metadata = NFTMetadata(
            name="Invalid NFT",
            attributes=[
                {"value": "Red"}  # Missing trait_type
            ]
        )
        
        context2 = ValidationContext(psbt_data={}, asset_id=b'\\x01' * 32)
        result = rule._validate_metadata_structure(invalid_metadata, context2)
        assert result is False
        assert context2.has_errors()
        assert "missing 'trait_type'" in context2.validation_errors[0]
    
    def test_extract_hash_from_uri(self):
        """Test hash extraction from various URI formats."""
        rule = ContentHashRule()
        
        # IPFS URI
        method, hash_val = rule._extract_hash_from_uri("ipfs://QmTest123456789012345678901234567890123456")
        assert method == HashMethod.IPFS
        assert hash_val == "QmTest123456789012345678901234567890123456"
        
        # Arweave URI (example)
        method, hash_val = rule._extract_hash_from_uri("ar://abcdefghijklmnopqrstuvwxyz1234567890123")
        assert method == HashMethod.SHA256
        assert hash_val == "abcdefghijklmnopqrstuvwxyz1234567890123"
        
        # HTTP URI - no extractable hash
        method, hash_val = rule._extract_hash_from_uri("https://example.com/image.png")
        assert method == HashMethod.SHA256
        assert hash_val is None
        
        # Data URI - no extractable hash (content is embedded)
        method, hash_val = rule._extract_hash_from_uri("data:image/png;base64,iVBORw0KGgo=")
        assert method == HashMethod.SHA256
        assert hash_val is None


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_create_content_hash_rule(self):
        """Test content hash rule creation utility."""
        rule = create_content_hash_rule()
        assert isinstance(rule, ContentHashRule)
        assert rule.enable_content_fetching is False
        assert rule.strict_validation is True
        
        # With custom config
        config = {
            "enable_content_fetching": True,
            "max_content_size": 50 * 1024 * 1024,
            "timeout_seconds": 60,
            "strict_validation": False
        }
        rule = create_content_hash_rule(config)
        assert rule.enable_content_fetching is True
        assert rule.max_content_size == 50 * 1024 * 1024
        assert rule.timeout_seconds == 60
        assert rule.strict_validation is False
    
    def test_validate_nft_metadata_quick(self):
        """Test quick NFT metadata validation utility."""
        # Valid metadata
        valid_metadata = {
            "name": "Test NFT",
            "description": "A test NFT",
            "image": "https://example.com/image.png",
            "attributes": [
                {"trait_type": "Color", "value": "Blue"}
            ]
        }
        
        is_valid, error = validate_nft_metadata_quick(valid_metadata)
        assert is_valid is True
        assert error == ""
        
        # Missing name
        invalid_metadata = {
            "description": "Missing name"
        }
        
        is_valid, error = validate_nft_metadata_quick(invalid_metadata)
        assert is_valid is False
        assert "Missing required field: name" in error
        
        # Invalid image URI
        invalid_uri_metadata = {
            "name": "Test NFT",
            "image": "invalid_uri"
        }
        
        is_valid, error = validate_nft_metadata_quick(invalid_uri_metadata)
        assert is_valid is False
        assert "Invalid URI format" in error
        
        # Invalid attributes structure
        invalid_attrs_metadata = {
            "name": "Test NFT",
            "attributes": [
                {"value": "Missing trait_type"}
            ]
        }
        
        is_valid, error = validate_nft_metadata_quick(invalid_attrs_metadata)
        assert is_valid is False
        assert "Invalid attribute" in error
    
    def test_extract_content_hashes(self):
        """Test content hash extraction utility."""
        metadata = {
            "name": "Test NFT",
            "image": {
                "uri": "https://example.com/image.png",
                "hash": "a" * 64,
                "hash_method": "sha256"
            },
            "animation_url": "ipfs://QmTest123456789012345678901234567890123456",
            "content": [
                {
                    "uri": "https://example.com/metadata.json",
                    "hash": "b" * 64,
                    "hash_method": "sha256"
                }
            ]
        }
        
        hashes = extract_content_hashes(metadata)
        
        assert len(hashes) == 3
        
        # Check image hash
        image_hash = next((h for h in hashes if h["field"] == "image"), None)
        assert image_hash is not None
        assert image_hash["hash"] == "a" * 64
        assert image_hash["method"] == "sha256"
        
        # Check animation_url hash (extracted from IPFS URI)
        animation_hash = next((h for h in hashes if h["field"] == "animation_url"), None)
        assert animation_hash is not None
        assert animation_hash["hash"] == "QmTest123456789012345678901234567890123456"
        assert animation_hash["method"] == "ipfs"
        
        # Check content hash
        content_hash = next((h for h in hashes if h["field"] == "content[0]"), None)
        assert content_hash is not None
        assert content_hash["hash"] == "b" * 64


class TestIntegration:
    """Integration tests with ValidationEngine."""
    
    def test_rule_integration(self):
        """Test content hash rule integration with ValidationEngine."""
        from validator.core import ValidationEngine
        
        engine = ValidationEngine()
        
        # Check that ContentHashRule is registered by default
        rule_names = [rule.name for rule in engine.rules]
        assert "content_hash" in rule_names
        
        # Get the content hash rule
        content_rule = engine.rule_registry["content_hash"]
        assert isinstance(content_rule, ContentHashRule)
        
        # Test statistics access
        stats = content_rule.get_statistics()
        assert isinstance(stats, dict)
        assert "validations_performed" in stats


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_invalid_json_metadata(self):
        """Test handling of invalid JSON metadata."""
        rule = ContentHashRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            metadata="{ invalid json }"
        )
        
        metadata = rule._parse_metadata(context)
        assert metadata is None
    
    def test_unsupported_metadata_format(self):
        """Test handling of unsupported metadata formats."""
        rule = ContentHashRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            metadata=12345  # Number instead of string or dict
        )
        
        metadata = rule._parse_metadata(context)
        assert metadata is None
    
    def test_validation_exception_handling(self):
        """Test handling of exceptions during validation."""
        rule = ContentHashRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            metadata={"name": "Test NFT"}
        )
        
        # Mock _parse_metadata to raise exception
        with patch.object(rule, '_parse_metadata', side_effect=Exception("Parse error")):
            result = rule.validate(context)
            
            assert result is False
            assert context.has_errors()
            assert "Parse error" in context.validation_errors[0]
    
    def test_cache_expiration(self):
        """Test cache entry expiration."""
        rule = ContentHashRule()
        rule.cache_ttl = 1  # 1 second TTL
        
        content_ref = ContentReference(
            uri="https://example.com/image.png",
            hash="a" * 64,
            hash_method=HashMethod.SHA256,
            content_type=ContentType.IMAGE
        )
        
        # Cache a result
        cache_key = f"{content_ref.uri}:{content_ref.hash}"
        rule._cache_validation_result(cache_key, True, content_ref)
        
        # Should be cached initially
        assert cache_key in rule.content_cache
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Create context for validation
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            metadata={}
        )
        
        # Next validation should be cache miss due to expiration
        with patch.object(rule, '_validate_uri_format', return_value=True):
            with patch.object(rule, '_validate_hash_format', return_value=True):
                rule._validate_content_reference(content_ref, context)
                # Should have incremented cache misses due to expiration
                assert rule.stats["cache_misses"] >= 1