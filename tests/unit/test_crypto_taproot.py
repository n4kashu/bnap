"""
Tests for Crypto Taproot Module

Tests BIP341 Taproot key tweaking, tagged hashes, and x-only key operations.
"""

import pytest
import hashlib
import secrets
from crypto.keys import (
    PrivateKey,
    PublicKey,
    tagged_hash,
    lift_x,
    has_even_y,
    compute_taproot_tweak,
    taproot_output_script,
    verify_taproot_tweak,
)
from crypto.exceptions import InvalidKeyError


class TestTaggedHash:
    """Test BIP340/341 tagged hash functionality."""
    
    def test_tagged_hash_basic(self):
        """Test basic tagged hash computation."""
        data = b"hello world"
        tag = "BIP0340/challenge"
        
        result = tagged_hash(tag, data)
        
        # Should be 32 bytes
        assert len(result) == 32
        assert isinstance(result, bytes)
        
        # Should be deterministic
        result2 = tagged_hash(tag, data)
        assert result == result2
        
    def test_tagged_hash_different_tags(self):
        """Test that different tags produce different results."""
        data = b"test data"
        
        hash1 = tagged_hash("tag1", data)
        hash2 = tagged_hash("tag2", data)
        
        assert hash1 != hash2
        
    def test_tagged_hash_different_data(self):
        """Test that different data produces different results."""
        tag = "test_tag"
        
        hash1 = tagged_hash(tag, b"data1")
        hash2 = tagged_hash(tag, b"data2")
        
        assert hash1 != hash2
        
    def test_taptweak_tag(self):
        """Test TapTweak tag specifically."""
        internal_key = b'\x01' * 32
        merkle_root = b'\x02' * 32
        
        # Key-path only (no merkle root)
        tweak1 = tagged_hash("TapTweak", internal_key)
        assert len(tweak1) == 32
        
        # With script tree (merkle root)
        tweak2 = tagged_hash("TapTweak", internal_key + merkle_root)
        assert len(tweak2) == 32
        assert tweak1 != tweak2


class TestPointOperations:
    """Test elliptic curve point operations for Taproot."""
    
    def test_has_even_y_compressed(self):
        """Test has_even_y with compressed keys."""
        # Generate keys and test parity
        for _ in range(10):
            private_key = PrivateKey()
            public_key = private_key.public_key()
            
            result = has_even_y(public_key.bytes)
            assert isinstance(result, bool)
            
            # Check consistency with prefix
            compressed = public_key.bytes
            if compressed[0] == 0x02:
                assert result is True
            elif compressed[0] == 0x03:
                assert result is False
                
    def test_lift_x_basic(self):
        """Test x-coordinate lifting."""
        # Generate a key and extract x-coordinate
        private_key = PrivateKey(b'\x01' * 32)
        public_key = private_key.public_key()
        x_only = public_key.x_only
        
        # Lift the x-coordinate
        lifted = lift_x(x_only)
        
        if lifted is not None:
            assert len(lifted) == 33
            assert lifted[0] in [0x02, 0x03]
            assert lifted[1:] == x_only
            assert has_even_y(lifted)  # Should have even y
            
    def test_lift_x_invalid(self):
        """Test lift_x with invalid input."""
        # Wrong length
        result = lift_x(b'\x00' * 31)
        assert result is None
        
        result = lift_x(b'\x00' * 33)
        assert result is None
        
        # Invalid x-coordinate (all zeros is invalid)
        result = lift_x(b'\x00' * 32)
        assert result is None
        
    def test_x_only_property(self):
        """Test x_only property of PublicKey."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        
        x_only = public_key.x_only
        assert len(x_only) == 32
        assert x_only == public_key.bytes[1:]  # Compressed key without prefix


class TestTaprootKeyTweaking:
    """Test Taproot key tweaking operations."""
    
    def test_private_key_tweak_add(self):
        """Test private key tweak addition."""
        private_key = PrivateKey(b'\x01' * 32)
        tweak = b'\x02' * 32
        
        tweaked_key = private_key.tweak_add(tweak)
        
        assert isinstance(tweaked_key, PrivateKey)
        assert tweaked_key.bytes != private_key.bytes
        
    def test_private_key_tweak_invalid(self):
        """Test private key tweaking with invalid tweak."""
        private_key = PrivateKey()
        
        # Wrong tweak length
        with pytest.raises(InvalidKeyError):
            private_key.tweak_add(b'\x01' * 31)
            
        with pytest.raises(InvalidKeyError):
            private_key.tweak_add(b'\x01' * 33)
            
    def test_public_key_tweak_add(self):
        """Test public key tweak addition."""
        private_key = PrivateKey(b'\x01' * 32)
        public_key = private_key.public_key()
        tweak = b'\x02' * 32
        
        tweaked_pubkey = public_key.tweak_add(tweak)
        
        assert isinstance(tweaked_pubkey, PublicKey)
        assert tweaked_pubkey.bytes != public_key.bytes
        
        # Verify tweaking consistency between private and public
        tweaked_private = private_key.tweak_add(tweak)
        expected_pubkey = tweaked_private.public_key()
        
        # X-coordinates should match (y-coordinate parity might differ)
        assert tweaked_pubkey.x_only == expected_pubkey.x_only
        
    def test_taproot_tweak_private_key_path_only(self):
        """Test Taproot private key tweaking for key-path only."""
        private_key = PrivateKey(b'\x01' * 32)
        
        tweaked_private, negated = private_key.taproot_tweak_private_key()
        
        assert isinstance(tweaked_private, PrivateKey)
        assert isinstance(negated, bool)
        assert tweaked_private.bytes != private_key.bytes
        
    def test_taproot_tweak_private_key_with_script(self):
        """Test Taproot private key tweaking with script tree."""
        private_key = PrivateKey(b'\x01' * 32)
        merkle_root = b'\xaa' * 32
        
        tweaked_private, negated = private_key.taproot_tweak_private_key(merkle_root)
        
        assert isinstance(tweaked_private, PrivateKey)
        assert isinstance(negated, bool)
        
        # Should be different from key-path only
        tweaked_private_key_only, _ = private_key.taproot_tweak_private_key()
        assert tweaked_private.bytes != tweaked_private_key_only.bytes
        
    def test_taproot_tweak_public_key_path_only(self):
        """Test Taproot public key tweaking for key-path only.""" 
        private_key = PrivateKey(b'\x01' * 32)
        public_key = private_key.public_key()
        
        tweaked_x = public_key.taproot_tweak_public_key()
        
        assert isinstance(tweaked_x, bytes)
        assert len(tweaked_x) == 32
        
    def test_taproot_tweak_public_key_with_script(self):
        """Test Taproot public key tweaking with script tree."""
        private_key = PrivateKey(b'\x01' * 32)
        public_key = private_key.public_key()
        merkle_root = b'\xbb' * 32
        
        tweaked_x = public_key.taproot_tweak_public_key(merkle_root)
        
        assert isinstance(tweaked_x, bytes)
        assert len(tweaked_x) == 32
        
        # Should be different from key-path only
        tweaked_x_key_only = public_key.taproot_tweak_public_key()
        assert tweaked_x != tweaked_x_key_only
        
    def test_taproot_tweak_consistency(self):
        """Test consistency between private and public key tweaking."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        
        # Test with and without merkle root
        test_cases = [None, b'\xcc' * 32]
        
        for merkle_root in test_cases:
            # Tweak private key
            tweaked_private, negated = private_key.taproot_tweak_private_key(merkle_root)
            
            # Tweak public key
            tweaked_x = public_key.taproot_tweak_public_key(merkle_root)
            
            # Get public key from tweaked private key
            tweaked_pubkey_from_private = tweaked_private.public_key()
            
            # X-coordinates should match
            assert tweaked_pubkey_from_private.x_only == tweaked_x
            
    def test_taproot_tweak_invalid_merkle_root(self):
        """Test Taproot tweaking with invalid merkle root."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        
        # Wrong merkle root length
        with pytest.raises(InvalidKeyError):
            private_key.taproot_tweak_private_key(b'\x01' * 31)
            
        with pytest.raises(InvalidKeyError):
            public_key.taproot_tweak_public_key(b'\x01' * 33)


class TestTaprootUtilities:
    """Test Taproot utility functions."""
    
    def test_compute_taproot_tweak(self):
        """Test Taproot tweak computation."""
        internal_x = b'\x01' * 32
        
        # Key-path only
        tweak1 = compute_taproot_tweak(internal_x)
        assert len(tweak1) == 32
        
        # With merkle root
        merkle_root = b'\x02' * 32
        tweak2 = compute_taproot_tweak(internal_x, merkle_root)
        assert len(tweak2) == 32
        
        assert tweak1 != tweak2
        
    def test_compute_taproot_tweak_invalid(self):
        """Test Taproot tweak computation with invalid inputs."""
        # Invalid internal key length
        with pytest.raises(InvalidKeyError):
            compute_taproot_tweak(b'\x01' * 31)
            
        # Invalid merkle root length
        with pytest.raises(InvalidKeyError):
            compute_taproot_tweak(b'\x01' * 32, b'\x02' * 31)
            
    def test_taproot_output_script(self):
        """Test Taproot output script creation."""
        tweaked_x = b'\xaa' * 32
        
        script = taproot_output_script(tweaked_x)
        
        # Should be OP_1 + 32-byte key
        assert len(script) == 34
        assert script[:2] == b'\x51\x20'  # OP_1 + PUSH32
        assert script[2:] == tweaked_x
        
    def test_taproot_output_script_invalid(self):
        """Test Taproot output script with invalid key."""
        with pytest.raises(InvalidKeyError):
            taproot_output_script(b'\x01' * 31)  # Wrong length
            
    def test_verify_taproot_tweak(self):
        """Test Taproot tweak verification."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        
        # Generate tweaked key
        tweaked_x = public_key.taproot_tweak_public_key()
        
        # Verify the tweak
        assert verify_taproot_tweak(public_key, tweaked_x)
        
        # Verify with wrong tweaked key should fail
        wrong_tweaked_x = b'\xff' * 32
        assert not verify_taproot_tweak(public_key, wrong_tweaked_x)
        
    def test_verify_taproot_tweak_with_merkle_root(self):
        """Test Taproot tweak verification with merkle root."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        merkle_root = b'\xdd' * 32
        
        # Generate tweaked key with merkle root
        tweaked_x = public_key.taproot_tweak_public_key(merkle_root)
        
        # Verify with correct merkle root
        assert verify_taproot_tweak(public_key, tweaked_x, merkle_root)
        
        # Verify with wrong merkle root should fail
        wrong_merkle = b'\xee' * 32
        assert not verify_taproot_tweak(public_key, tweaked_x, wrong_merkle)
        
        # Verify without merkle root should fail
        assert not verify_taproot_tweak(public_key, tweaked_x)


class TestBIP341TestVectors:
    """Test against BIP341 test vectors and known values."""
    
    def test_taptweak_tag_vector(self):
        """Test TapTweak tagged hash with known vector."""
        # This is a basic test - in production you'd use official BIP341 test vectors
        internal_key = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        
        tweak = tagged_hash("TapTweak", internal_key)
        
        # Should be deterministic
        tweak2 = tagged_hash("TapTweak", internal_key)
        assert tweak == tweak2
        
        # Should be 32 bytes
        assert len(tweak) == 32
        
    def test_deterministic_tweaking(self):
        """Test that tweaking is deterministic."""
        # Fixed private key for deterministic testing
        fixed_bytes = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
        private_key = PrivateKey(fixed_bytes)
        public_key = private_key.public_key()
        
        # Should always produce same result
        tweaked_x1 = public_key.taproot_tweak_public_key()
        tweaked_x2 = public_key.taproot_tweak_public_key()
        
        assert tweaked_x1 == tweaked_x2
        
        # Private key tweaking should also be deterministic
        tweaked_priv1, neg1 = private_key.taproot_tweak_private_key()
        tweaked_priv2, neg2 = private_key.taproot_tweak_private_key()
        
        assert tweaked_priv1.bytes == tweaked_priv2.bytes
        assert neg1 == neg2
        
    def test_multiple_keys_tweaking(self):
        """Test tweaking with multiple different keys."""
        for i in range(5):
            # Create different keys
            key_bytes = (i + 1).to_bytes(32, 'big')
            private_key = PrivateKey(key_bytes)
            public_key = private_key.public_key()
            
            # Test key-path only tweaking
            tweaked_x = public_key.taproot_tweak_public_key()
            assert len(tweaked_x) == 32
            
            # Verify the tweak
            assert verify_taproot_tweak(public_key, tweaked_x)
            
            # Test with merkle root
            merkle_root = hashlib.sha256(key_bytes).digest()
            tweaked_x_script = public_key.taproot_tweak_public_key(merkle_root)
            assert len(tweaked_x_script) == 32
            assert tweaked_x != tweaked_x_script  # Should be different
            
            # Verify the script tweak
            assert verify_taproot_tweak(public_key, tweaked_x_script, merkle_root)