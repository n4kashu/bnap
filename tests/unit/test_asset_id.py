"""
Unit tests for asset ID generation and validation.
"""

import pytest
from unittest.mock import patch
from datetime import datetime

from registry.asset_id import (
    AssetIDGenerator, AssetIDValidator, AssetIDCollisionError,
    generate_deterministic_id, validate_asset_id_format,
    derive_child_asset_id
)
from registry.schema import AssetType


class TestAssetIDGenerator:
    """Test asset ID generation functionality."""
    
    @pytest.fixture
    def generator(self):
        """Create asset ID generator."""
        return AssetIDGenerator()
    
    def test_generator_initialization(self, generator):
        """Test generator initialization."""
        assert generator.collision_detector is not None
        assert generator.entropy_sources == ['urandom', 'time', 'counter']
        assert len(generator.used_ids) == 0
    
    def test_basic_id_generation(self, generator):
        """Test basic asset ID generation."""
        asset_id = generator.generate_id(
            issuer_pubkey="a" * 64,
            name="Test Asset",
            asset_type=AssetType.FUNGIBLE
        )
        
        assert len(asset_id) == 64
        assert all(c in "0123456789abcdef" for c in asset_id)
        assert asset_id in generator.used_ids
    
    def test_deterministic_generation(self, generator):
        """Test deterministic asset ID generation."""
        # Same inputs should produce same ID when using nonce
        nonce = "test_nonce_123"
        
        asset_id_1 = generator.generate_deterministic_id(
            issuer_pubkey="b" * 64,
            name="Deterministic Asset",
            asset_type=AssetType.FUNGIBLE,
            nonce=nonce
        )
        
        asset_id_2 = generator.generate_deterministic_id(
            issuer_pubkey="b" * 64,
            name="Deterministic Asset",
            asset_type=AssetType.FUNGIBLE,
            nonce=nonce
        )
        
        assert asset_id_1 == asset_id_2
        assert len(asset_id_1) == 64
    
    def test_unique_generation(self, generator):
        """Test that generated IDs are unique."""
        ids = set()
        
        for i in range(100):
            asset_id = generator.generate_id(
                issuer_pubkey=f"{i:064d}",
                name=f"Asset {i}",
                asset_type=AssetType.FUNGIBLE
            )
            assert asset_id not in ids
            ids.add(asset_id)
        
        assert len(ids) == 100
    
    def test_collision_detection(self, generator):
        """Test collision detection and handling."""
        # Generate first ID
        asset_id_1 = generator.generate_id(
            issuer_pubkey="c" * 64,
            name="Collision Test",
            asset_type=AssetType.FUNGIBLE
        )
        
        # Mock hash function to force collision
        with patch('hashlib.sha256') as mock_sha256:
            # First call returns existing ID (collision)
            # Second call returns new ID
            mock_hash = mock_sha256.return_value
            mock_hash.hexdigest.side_effect = [asset_id_1, "d" * 64]
            
            # Should detect collision and generate new ID
            asset_id_2 = generator.generate_id(
                issuer_pubkey="e" * 64,
                name="Different Asset",
                asset_type=AssetType.NFT
            )
            
            assert asset_id_2 != asset_id_1
            assert asset_id_2 == "d" * 64
    
    def test_entropy_mixing(self, generator):
        """Test entropy mixing from multiple sources."""
        with patch('os.urandom') as mock_urandom, \
             patch('time.time') as mock_time:
            
            mock_urandom.return_value = b'\x01' * 32
            mock_time.return_value = 1234567890.123
            
            asset_id = generator.generate_id(
                issuer_pubkey="f" * 64,
                name="Entropy Test",
                asset_type=AssetType.FUNGIBLE
            )
            
            # Verify entropy sources were called
            mock_urandom.assert_called_once_with(32)
            mock_time.assert_called()
            
            assert len(asset_id) == 64
    
    def test_custom_entropy(self, generator):
        """Test generation with custom entropy."""
        custom_entropy = "custom_entropy_data_123"
        
        asset_id = generator.generate_id(
            issuer_pubkey="g" * 64,
            name="Custom Entropy Test",
            asset_type=AssetType.FUNGIBLE,
            custom_entropy=custom_entropy
        )
        
        assert len(asset_id) == 64
        assert asset_id in generator.used_ids
    
    def test_batch_generation(self, generator):
        """Test batch asset ID generation."""
        count = 50
        asset_ids = generator.generate_batch(
            base_issuer="h" * 64,
            base_name="Batch Asset",
            asset_type=AssetType.FUNGIBLE,
            count=count
        )
        
        assert len(asset_ids) == count
        assert len(set(asset_ids)) == count  # All unique
        
        for asset_id in asset_ids:
            assert len(asset_id) == 64
            assert asset_id in generator.used_ids
    
    def test_collision_rate_monitoring(self, generator):
        """Test collision rate monitoring."""
        # Generate many IDs to potentially trigger collisions
        for i in range(10):
            generator.generate_id(
                issuer_pubkey=f"{i:064d}",
                name=f"Rate Test {i}",
                asset_type=AssetType.FUNGIBLE
            )
        
        collision_rate = generator.get_collision_rate()
        assert isinstance(collision_rate, float)
        assert 0.0 <= collision_rate <= 1.0
        
        stats = generator.get_generation_stats()
        assert 'total_generated' in stats
        assert 'collision_count' in stats
        assert 'collision_rate' in stats
        assert stats['total_generated'] >= 10


class TestAssetIDValidator:
    """Test asset ID validation functionality."""
    
    @pytest.fixture
    def validator(self):
        """Create asset ID validator."""
        return AssetIDValidator()
    
    def test_validator_initialization(self, validator):
        """Test validator initialization."""
        assert validator.format_rules is not None
        assert validator.security_requirements is not None
    
    def test_format_validation(self, validator):
        """Test asset ID format validation."""
        # Valid format
        valid_id = "a" * 64
        assert validator.validate_format(valid_id)
        
        # Invalid length
        assert not validator.validate_format("abc123")
        assert not validator.validate_format("a" * 63)
        assert not validator.validate_format("a" * 65)
        
        # Invalid characters
        assert not validator.validate_format("g" * 64)  # 'g' not in hex
        assert not validator.validate_format("Z" * 64)  # uppercase
    
    def test_security_validation(self, validator):
        """Test security requirements validation."""
        # Test weak IDs (all same character)
        weak_id = "0" * 64
        security_result = validator.validate_security(weak_id)
        assert not security_result['valid']
        assert 'entropy' in security_result['issues']
        
        # Test strong ID
        strong_id = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        security_result = validator.validate_security(strong_id)
        assert security_result['valid']
        assert len(security_result['issues']) == 0
    
    def test_entropy_analysis(self, validator):
        """Test entropy analysis."""
        # Low entropy ID
        low_entropy_id = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
        entropy = validator.analyze_entropy(low_entropy_id)
        assert entropy < 0.8  # Should be low entropy
        
        # High entropy ID
        high_entropy_id = "a7f3c9e2d8b5f1049c6e8a2d7f3b9c5e8a1d6f4b9e2c7a5d8f3b6c9e4a7d2f8"
        entropy = validator.analyze_entropy(high_entropy_id)
        assert entropy > 0.8  # Should be high entropy
    
    def test_pattern_detection(self, validator):
        """Test pattern detection in asset IDs."""
        # Sequential pattern
        sequential_id = "0123456789abcdef" * 4
        patterns = validator.detect_patterns(sequential_id)
        assert len(patterns) > 0
        assert any(p['type'] == 'sequential' for p in patterns)
        
        # Repetitive pattern
        repetitive_id = "abcd" * 16
        patterns = validator.detect_patterns(repetitive_id)
        assert len(patterns) > 0
        assert any(p['type'] == 'repetitive' for p in patterns)
        
        # No obvious patterns
        random_id = "a7f3c9e2d8b5f1049c6e8a2d7f3b9c5e8a1d6f4b9e2c7a5d8f3b6c9e4a7d2f8"
        patterns = validator.detect_patterns(random_id)
        assert len(patterns) == 0 or all(p['severity'] == 'low' for p in patterns)
    
    def test_uniqueness_checking(self, validator):
        """Test uniqueness checking against existing IDs."""
        existing_ids = {
            "existing1" + "0" * 56,
            "existing2" + "0" * 56,
            "existing3" + "0" * 56
        }
        
        validator.add_existing_ids(existing_ids)
        
        # Test duplicate
        assert not validator.check_uniqueness("existing1" + "0" * 56)
        
        # Test unique
        assert validator.check_uniqueness("unique123" + "0" * 55)
    
    def test_comprehensive_validation(self, validator):
        """Test comprehensive validation combining all checks."""
        # Add some existing IDs
        validator.add_existing_ids({"taken123" + "0" * 55})
        
        # Test valid ID
        valid_id = "a7f3c9e2d8b5f1049c6e8a2d7f3b9c5e8a1d6f4b9e2c7a5d8f3b6c9e4a7d2f8"
        result = validator.validate(valid_id)
        
        assert result['valid']
        assert result['format_valid']
        assert result['security_valid']
        assert result['unique']
        assert len(result['issues']) == 0
        
        # Test invalid ID
        invalid_id = "taken123" + "0" * 55  # Duplicate
        result = validator.validate(invalid_id)
        
        assert not result['valid']
        assert not result['unique']
        assert len(result['issues']) > 0
    
    def test_validation_with_context(self, validator):
        """Test validation with additional context."""
        context = {
            'issuer_pubkey': 'a' * 64,
            'asset_name': 'Test Asset',
            'asset_type': 'fungible'
        }
        
        asset_id = "b" * 64
        result = validator.validate(asset_id, context=context)
        
        assert 'context' in result
        assert result['context'] == context


class TestUtilityFunctions:
    """Test utility functions for asset ID operations."""
    
    def test_generate_deterministic_id(self):
        """Test standalone deterministic ID generation."""
        # Same inputs should produce same output
        id1 = generate_deterministic_id(
            issuer_pubkey="a" * 64,
            name="Test Asset",
            nonce="test_nonce"
        )
        
        id2 = generate_deterministic_id(
            issuer_pubkey="a" * 64,
            name="Test Asset",
            nonce="test_nonce"
        )
        
        assert id1 == id2
        assert len(id1) == 64
        
        # Different inputs should produce different output
        id3 = generate_deterministic_id(
            issuer_pubkey="a" * 64,
            name="Different Asset",
            nonce="test_nonce"
        )
        
        assert id3 != id1
    
    def test_validate_asset_id_format(self):
        """Test standalone format validation."""
        # Valid formats
        assert validate_asset_id_format("a" * 64)
        assert validate_asset_id_format("0123456789abcdef" * 4)
        
        # Invalid formats
        assert not validate_asset_id_format("g" * 64)  # Invalid hex
        assert not validate_asset_id_format("a" * 63)  # Too short
        assert not validate_asset_id_format("a" * 65)  # Too long
        assert not validate_asset_id_format("")         # Empty
        assert not validate_asset_id_format("ABC" * 21 + "D")  # Uppercase
    
    def test_derive_child_asset_id(self):
        """Test child asset ID derivation."""
        parent_id = "parent123" + "0" * 55
        
        # Derive child IDs
        child1 = derive_child_asset_id(parent_id, "child_1")
        child2 = derive_child_asset_id(parent_id, "child_2")
        
        assert len(child1) == 64
        assert len(child2) == 64
        assert child1 != child2
        assert child1 != parent_id
        assert child2 != parent_id
        
        # Same derivation should be deterministic
        child1_repeat = derive_child_asset_id(parent_id, "child_1")
        assert child1 == child1_repeat
    
    def test_asset_id_collision_error(self):
        """Test asset ID collision error."""
        collision_id = "collision" + "0" * 55
        
        error = AssetIDCollisionError(collision_id)
        assert str(error) == f"Asset ID collision detected: {collision_id}"
        assert error.asset_id == collision_id
        
        # Test with additional context
        error_with_context = AssetIDCollisionError(
            collision_id,
            attempts=5,
            context="batch generation"
        )
        assert error_with_context.attempts == 5
        assert error_with_context.context == "batch generation"


class TestAssetIDPerformance:
    """Test asset ID generation performance characteristics."""
    
    def test_generation_performance(self):
        """Test ID generation performance."""
        generator = AssetIDGenerator()
        
        import time
        start_time = time.time()
        
        # Generate many IDs
        for i in range(1000):
            generator.generate_id(
                issuer_pubkey=f"{i:064d}",
                name=f"Performance Test {i}",
                asset_type=AssetType.FUNGIBLE
            )
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Should generate 1000 IDs in reasonable time
        assert elapsed < 5.0  # Less than 5 seconds
        
        # Check generation rate
        rate = 1000 / elapsed
        assert rate > 100  # At least 100 IDs per second
    
    def test_validation_performance(self):
        """Test ID validation performance."""
        validator = AssetIDValidator()
        
        # Add many existing IDs
        existing_ids = {f"{i:064d}" for i in range(10000)}
        validator.add_existing_ids(existing_ids)
        
        import time
        start_time = time.time()
        
        # Validate many IDs
        for i in range(1000):
            test_id = f"test{i:060d}"
            validator.validate(test_id)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Should validate 1000 IDs in reasonable time
        assert elapsed < 2.0  # Less than 2 seconds
        
        # Check validation rate
        rate = 1000 / elapsed
        assert rate > 200  # At least 200 validations per second
    
    def test_memory_usage(self):
        """Test memory usage during large-scale operations."""
        generator = AssetIDGenerator()
        
        # Generate many IDs and check memory doesn't grow excessively
        initial_id_count = len(generator.used_ids)
        
        for i in range(10000):
            generator.generate_id(
                issuer_pubkey=f"{i:064d}",
                name=f"Memory Test {i}",
                asset_type=AssetType.FUNGIBLE
            )
        
        final_id_count = len(generator.used_ids)
        
        # Should track all generated IDs
        assert final_id_count == initial_id_count + 10000
        
        # Clear old IDs to test memory management
        cleared_count = generator.clear_old_ids(keep_recent=1000)
        assert cleared_count == 9000
        assert len(generator.used_ids) == 1000