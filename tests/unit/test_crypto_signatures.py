"""
Tests for Crypto Signatures Module

Tests ECDSA and Schnorr signature operations including signing, verification,
DER encoding/decoding, and Bitcoin message signing.
"""

import pytest
import hashlib
import secrets
from crypto.signatures import (
    ECDSASignature,
    SchnorrSignature,
    sign_ecdsa,
    verify_ecdsa,
    sign_ecdsa_recoverable,
    recover_ecdsa_public_key,
    sign_schnorr,
    verify_schnorr,
    normalize_signature,
    is_low_s,
    double_sha256,
    sign_message_hash,
    verify_message_hash,
    sign_bitcoin_message,
    verify_bitcoin_message,
)
from crypto.keys import PrivateKey, PublicKey
from crypto.exceptions import InvalidSignatureError


class TestECDSASignature:
    """Test ECDSA signature data structure."""
    
    def test_ecdsa_signature_creation(self):
        """Test basic ECDSA signature creation."""
        r = 12345
        s = 67890
        signature = ECDSASignature(r=r, s=s)
        
        assert signature.r == r
        assert signature.s == s
    
    def test_ecdsa_signature_validation(self):
        """Test ECDSA signature validation."""
        # Valid signature
        signature = ECDSASignature(r=1, s=1)
        assert signature.r == 1
        assert signature.s == 1
        
        # Invalid r value (zero)
        with pytest.raises(InvalidSignatureError, match="Invalid r value"):
            ECDSASignature(r=0, s=1)
        
        # Invalid s value (too large)
        with pytest.raises(InvalidSignatureError, match="Invalid s value"):
            ECDSASignature(r=1, s=2**256)
    
    def test_ecdsa_compact_encoding(self):
        """Test ECDSA compact format encoding/decoding."""
        r = 0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0
        s = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321
        
        signature = ECDSASignature(r=r, s=s)
        compact = signature.to_compact()
        
        assert len(compact) == 64
        assert compact[:32] == r.to_bytes(32, 'big')
        assert compact[32:] == s.to_bytes(32, 'big')
        
        # Test round-trip
        parsed = ECDSASignature.from_compact(compact)
        assert parsed.r == r
        assert parsed.s == s
    
    def test_ecdsa_compact_invalid_length(self):
        """Test ECDSA compact parsing with invalid length."""
        with pytest.raises(InvalidSignatureError, match="Compact signature must be 64 bytes"):
            ECDSASignature.from_compact(b'\x00' * 63)
    
    def test_ecdsa_der_encoding(self):
        """Test ECDSA DER format encoding/decoding."""
        # Use specific values that create valid DER
        r = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        s = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321
        
        signature = ECDSASignature(r=r, s=s)
        der_bytes = signature.to_der()
        
        # Basic DER structure validation
        assert der_bytes[0] == 0x30  # SEQUENCE tag
        assert len(der_bytes) >= 8
        
        # Test round-trip
        parsed = ECDSASignature.from_der(der_bytes)
        assert parsed.r == r
        assert parsed.s == s
    
    def test_ecdsa_der_invalid(self):
        """Test ECDSA DER parsing with invalid data."""
        # Too short
        with pytest.raises(InvalidSignatureError, match="DER signature too short"):
            ECDSASignature.from_der(b'\x30\x06')
        
        # Invalid header
        with pytest.raises(InvalidSignatureError, match="Invalid DER signature header"):
            ECDSASignature.from_der(b'\x31\x06\x02\x01\x01\x02\x01\x01')


class TestSchnorrSignature:
    """Test Schnorr signature data structure."""
    
    def test_schnorr_signature_creation(self):
        """Test basic Schnorr signature creation."""
        r = b'\x01' * 32
        s = b'\x02' * 32
        signature = SchnorrSignature(r=r, s=s)
        
        assert signature.r == r
        assert signature.s == s
    
    def test_schnorr_signature_validation(self):
        """Test Schnorr signature validation."""
        # Valid signature
        r = b'\x01' * 32
        s = b'\x02' * 32
        signature = SchnorrSignature(r=r, s=s)
        assert len(signature.r) == 32
        assert len(signature.s) == 32
        
        # Invalid r length
        with pytest.raises(InvalidSignatureError, match="Schnorr r must be 32 bytes"):
            SchnorrSignature(r=b'\x01' * 31, s=b'\x02' * 32)
        
        # Invalid s length
        with pytest.raises(InvalidSignatureError, match="Schnorr s must be 32 bytes"):
            SchnorrSignature(r=b'\x01' * 32, s=b'\x02' * 31)
    
    def test_schnorr_bytes_encoding(self):
        """Test Schnorr bytes format encoding/decoding."""
        r = secrets.token_bytes(32)
        s = secrets.token_bytes(32)
        
        signature = SchnorrSignature(r=r, s=s)
        sig_bytes = signature.to_bytes()
        
        assert len(sig_bytes) == 64
        assert sig_bytes[:32] == r
        assert sig_bytes[32:] == s
        
        # Test round-trip
        parsed = SchnorrSignature.from_bytes(sig_bytes)
        assert parsed.r == r
        assert parsed.s == s
    
    def test_schnorr_bytes_invalid_length(self):
        """Test Schnorr bytes parsing with invalid length."""
        with pytest.raises(InvalidSignatureError, match="Schnorr signature must be 64 bytes"):
            SchnorrSignature.from_bytes(b'\x00' * 63)


class TestECDSAOperations:
    """Test ECDSA signing and verification operations."""
    
    def test_ecdsa_sign_and_verify(self):
        """Test basic ECDSA signing and verification."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message_hash = hashlib.sha256(b"test message").digest()
        
        # Sign the message
        signature = sign_ecdsa(private_key, message_hash)
        
        assert isinstance(signature, ECDSASignature)
        assert signature.r > 0
        assert signature.s > 0
        
        # Verify the signature
        assert verify_ecdsa(public_key, signature, message_hash) is True
        
        # Verify with wrong message should fail
        wrong_hash = hashlib.sha256(b"wrong message").digest()
        assert verify_ecdsa(public_key, signature, wrong_hash) is False
    
    def test_ecdsa_deterministic_signing(self):
        """Test that ECDSA signing is deterministic with RFC6979."""
        private_key = PrivateKey(b'\x01' * 32)
        message_hash = hashlib.sha256(b"deterministic test").digest()
        
        # Sign twice with same key and message
        signature1 = sign_ecdsa(private_key, message_hash, deterministic=True)
        signature2 = sign_ecdsa(private_key, message_hash, deterministic=True)
        
        # Should be identical
        assert signature1.r == signature2.r
        assert signature1.s == signature2.s
    
    def test_ecdsa_invalid_message_hash(self):
        """Test ECDSA with invalid message hash length."""
        private_key = PrivateKey()
        
        # Wrong length
        with pytest.raises(InvalidSignatureError, match="Message hash must be 32 bytes"):
            sign_ecdsa(private_key, b"short")
        
        # Verification with wrong length
        signature = ECDSASignature(r=1, s=1)
        public_key = private_key.public_key()
        assert verify_ecdsa(public_key, signature, b"short") is False
    
    def test_ecdsa_sign_recoverable(self):
        """Test ECDSA signing with recovery information."""
        private_key = PrivateKey()
        message_hash = hashlib.sha256(b"recoverable test").digest()
        
        signature, recovery_id = sign_ecdsa_recoverable(private_key, message_hash)
        
        assert isinstance(signature, ECDSASignature)
        assert isinstance(recovery_id, int)
        assert 0 <= recovery_id <= 3
    
    def test_ecdsa_public_key_recovery(self):
        """Test ECDSA public key recovery."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message_hash = hashlib.sha256(b"recovery test").digest()
        
        # Sign with recovery
        signature, recovery_id = sign_ecdsa_recoverable(private_key, message_hash)
        
        # Recover public key
        recovered_pubkey = recover_ecdsa_public_key(signature, recovery_id, message_hash)
        
        assert recovered_pubkey is not None
        # Note: recovered key might have different y-coordinate parity
        # but should have same x-coordinate for verification purposes
        assert verify_ecdsa(recovered_pubkey, signature, message_hash) is True
    
    def test_ecdsa_recovery_invalid_inputs(self):
        """Test ECDSA recovery with invalid inputs."""
        signature = ECDSASignature(r=1, s=1)
        
        # Invalid message hash length
        assert recover_ecdsa_public_key(signature, 0, b"short") is None
        
        # Invalid recovery ID
        message_hash = hashlib.sha256(b"test").digest()
        assert recover_ecdsa_public_key(signature, 5, message_hash) is None
    
    def test_ecdsa_multiple_keys(self):
        """Test ECDSA with multiple different keys."""
        for i in range(5):
            private_key = PrivateKey((i + 1).to_bytes(32, 'big'))
            public_key = private_key.public_key()
            message_hash = hashlib.sha256(f"test message {i}".encode()).digest()
            
            # Sign and verify
            signature = sign_ecdsa(private_key, message_hash)
            assert verify_ecdsa(public_key, signature, message_hash) is True
            
            # Verify with wrong key should fail
            other_key = PrivateKey((i + 2).to_bytes(32, 'big')).public_key()
            assert verify_ecdsa(other_key, signature, message_hash) is False


class TestSchnorrOperations:
    """Test Schnorr signing and verification operations."""
    
    def test_schnorr_sign_and_verify(self):
        """Test basic Schnorr signing and verification."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message = b"schnorr test message"
        
        # Sign the message
        signature = sign_schnorr(private_key, message)
        
        assert isinstance(signature, SchnorrSignature)
        assert len(signature.r) == 32
        assert len(signature.s) == 32
        
        # Verify the signature
        assert verify_schnorr(public_key, signature, message) is True
        
        # Verify with wrong message should fail
        wrong_message = b"wrong schnorr message"
        assert verify_schnorr(public_key, signature, wrong_message) is False
    
    def test_schnorr_with_aux_randomness(self):
        """Test Schnorr signing with auxiliary randomness."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message = b"schnorr aux test"
        aux_rand = secrets.token_bytes(32)
        
        # Sign with auxiliary randomness
        signature = sign_schnorr(private_key, message, aux_rand)
        
        assert isinstance(signature, SchnorrSignature)
        assert verify_schnorr(public_key, signature, message) is True
    
    def test_schnorr_invalid_aux_randomness(self):
        """Test Schnorr signing with invalid auxiliary randomness."""
        private_key = PrivateKey()
        message = b"test"
        
        # Wrong length
        with pytest.raises(InvalidSignatureError, match="Auxiliary randomness must be 32 bytes"):
            sign_schnorr(private_key, message, aux_rand=b"short")
    
    def test_schnorr_deterministic_with_aux(self):
        """Test that Schnorr is deterministic with same auxiliary randomness."""
        private_key = PrivateKey(b'\x02' * 32)
        message = b"deterministic schnorr"
        aux_rand = b'\x03' * 32
        
        # Sign twice with same parameters
        signature1 = sign_schnorr(private_key, message, aux_rand)
        signature2 = sign_schnorr(private_key, message, aux_rand)
        
        # Should be identical
        assert signature1.r == signature2.r
        assert signature1.s == signature2.s
    
    def test_schnorr_different_messages(self):
        """Test Schnorr signatures for different messages."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        
        messages = [b"message1", b"message2", b"message3"]
        signatures = []
        
        for message in messages:
            signature = sign_schnorr(private_key, message)
            signatures.append(signature)
            assert verify_schnorr(public_key, signature, message) is True
        
        # All signatures should be different
        for i in range(len(signatures)):
            for j in range(i + 1, len(signatures)):
                assert signatures[i].r != signatures[j].r or signatures[i].s != signatures[j].s
    
    def test_schnorr_hash_32_byte_message(self):
        """Test Schnorr with 32-byte message (no hashing)."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message_hash = hashlib.sha256(b"pre-hashed message").digest()
        
        # Sign the hash directly
        signature = sign_schnorr(private_key, message_hash)
        
        assert verify_schnorr(public_key, signature, message_hash) is True


class TestSignatureUtilities:
    """Test signature utility functions."""
    
    def test_normalize_signature(self):
        """Test ECDSA signature normalization."""
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        half_order = curve_order // 2
        
        # Low-s signature (should remain unchanged)
        low_s_sig = ECDSASignature(r=123, s=half_order - 1)
        normalized = normalize_signature(low_s_sig)
        assert normalized.r == low_s_sig.r
        assert normalized.s == low_s_sig.s
        
        # High-s signature (should be normalized)
        high_s_sig = ECDSASignature(r=123, s=half_order + 100)
        normalized = normalize_signature(high_s_sig)
        assert normalized.r == high_s_sig.r
        assert normalized.s == curve_order - high_s_sig.s
        assert normalized.s < half_order
    
    def test_is_low_s(self):
        """Test low-s signature check."""
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        half_order = curve_order // 2
        
        # Low-s signature
        low_s_sig = ECDSASignature(r=123, s=half_order)
        assert is_low_s(low_s_sig) is True
        
        # High-s signature
        high_s_sig = ECDSASignature(r=123, s=half_order + 1)
        assert is_low_s(high_s_sig) is False
    
    def test_double_sha256(self):
        """Test double SHA256 hash function."""
        data = b"test data"
        result = double_sha256(data)
        
        # Should be 32 bytes
        assert len(result) == 32
        
        # Should equal SHA256(SHA256(data))
        expected = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        assert result == expected
        
        # Should be deterministic
        result2 = double_sha256(data)
        assert result == result2


class TestUnifiedSigningAPI:
    """Test unified signing API."""
    
    def test_sign_message_hash_ecdsa(self):
        """Test unified API for ECDSA signing."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message_hash = hashlib.sha256(b"unified test").digest()
        
        # Sign with ECDSA
        signature = sign_message_hash(private_key, message_hash, "ecdsa")
        
        assert isinstance(signature, ECDSASignature)
        assert verify_message_hash(public_key, signature, message_hash) is True
    
    def test_sign_message_hash_schnorr(self):
        """Test unified API for Schnorr signing."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message_hash = hashlib.sha256(b"unified schnorr test").digest()
        
        # Sign with Schnorr
        signature = sign_message_hash(private_key, message_hash, "schnorr")
        
        assert isinstance(signature, SchnorrSignature)
        assert verify_message_hash(public_key, signature, message_hash) is True
    
    def test_sign_message_hash_invalid_type(self):
        """Test unified API with invalid signature type."""
        private_key = PrivateKey()
        message_hash = hashlib.sha256(b"test").digest()
        
        with pytest.raises(InvalidSignatureError, match="Unknown signature type"):
            sign_message_hash(private_key, message_hash, "invalid")
    
    def test_verify_message_hash_invalid_type(self):
        """Test unified verification with invalid signature type."""
        public_key = PrivateKey().public_key()
        message_hash = hashlib.sha256(b"test").digest()
        
        # Create mock signature object
        class InvalidSignature:
            pass
        
        invalid_sig = InvalidSignature()
        
        with pytest.raises(InvalidSignatureError, match="Unknown signature type"):
            verify_message_hash(public_key, invalid_sig, message_hash)


class TestBitcoinMessageSigning:
    """Test Bitcoin message signing compatibility."""
    
    def test_bitcoin_message_sign_and_verify(self):
        """Test Bitcoin message signing and verification."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message = "Hello Bitcoin!"
        
        # Sign Bitcoin message
        signature = sign_bitcoin_message(private_key, message)
        
        assert len(signature) == 65  # 64-byte signature + 1-byte recovery
        
        # Verify Bitcoin message
        assert verify_bitcoin_message(public_key, signature, message) is True
        
        # Verify with wrong message should fail
        assert verify_bitcoin_message(public_key, signature, "Wrong message") is False
    
    def test_bitcoin_message_different_messages(self):
        """Test Bitcoin message signing with different messages."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        
        messages = ["Short", "A longer message with more content", "🚀 Unicode message! 🌟"]
        
        for message in messages:
            signature = sign_bitcoin_message(private_key, message)
            assert len(signature) == 65
            assert verify_bitcoin_message(public_key, signature, message) is True
    
    def test_bitcoin_message_verify_invalid_signature(self):
        """Test Bitcoin message verification with invalid signature."""
        public_key = PrivateKey().public_key()
        message = "test message"
        
        # Wrong signature length
        assert verify_bitcoin_message(public_key, b'\x00' * 64, message) is False
        
        # Invalid recovery ID
        invalid_sig = b'\x00' * 64 + b'\x00'  # Recovery ID would be -31
        assert verify_bitcoin_message(public_key, invalid_sig, message) is False
    
    def test_bitcoin_message_deterministic(self):
        """Test that Bitcoin message signing is deterministic."""
        private_key = PrivateKey(b'\x04' * 32)
        message = "Deterministic Bitcoin message"
        
        # Sign twice
        signature1 = sign_bitcoin_message(private_key, message)
        signature2 = sign_bitcoin_message(private_key, message)
        
        # Should be identical (RFC6979 deterministic)
        assert signature1 == signature2


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_signature_with_extreme_values(self):
        """Test signatures with boundary values."""
        # Test with maximum valid private key
        max_private_bytes = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140).to_bytes(32, 'big')
        private_key = PrivateKey(max_private_bytes)
        public_key = private_key.public_key()
        message_hash = hashlib.sha256(b"extreme test").digest()
        
        # Should work with both algorithms
        ecdsa_sig = sign_ecdsa(private_key, message_hash)
        assert verify_ecdsa(public_key, ecdsa_sig, message_hash) is True
        
        schnorr_sig = sign_schnorr(private_key, b"extreme test")
        assert verify_schnorr(public_key, schnorr_sig, b"extreme test") is True
    
    def test_signature_verification_edge_cases(self):
        """Test signature verification with edge cases."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        other_public_key = PrivateKey().public_key()
        
        message_hash = hashlib.sha256(b"edge case test").digest()
        signature = sign_ecdsa(private_key, message_hash)
        
        # Correct verification
        assert verify_ecdsa(public_key, signature, message_hash) is True
        
        # Wrong public key
        assert verify_ecdsa(other_public_key, signature, message_hash) is False
        
        # Wrong message hash
        wrong_hash = hashlib.sha256(b"wrong message").digest()
        assert verify_ecdsa(public_key, signature, wrong_hash) is False
    
    def test_corrupted_signatures(self):
        """Test verification with corrupted signatures."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        message_hash = hashlib.sha256(b"corruption test").digest()
        
        # Valid signature
        signature = sign_ecdsa(private_key, message_hash)
        assert verify_ecdsa(public_key, signature, message_hash) is True
        
        # Corrupt r value
        corrupted_sig = ECDSASignature(r=signature.r + 1, s=signature.s)
        assert verify_ecdsa(public_key, corrupted_sig, message_hash) is False
        
        # Corrupt s value
        corrupted_sig = ECDSASignature(r=signature.r, s=signature.s + 1)
        assert verify_ecdsa(public_key, corrupted_sig, message_hash) is False


class TestRandomizedTesting:
    """Test with randomized inputs for robustness."""
    
    def test_random_ecdsa_signatures(self):
        """Test ECDSA with random inputs."""
        for _ in range(10):
            # Generate random key and message
            private_key = PrivateKey()
            public_key = private_key.public_key()
            message = secrets.token_bytes(secrets.randbelow(100) + 1)
            message_hash = hashlib.sha256(message).digest()
            
            # Sign and verify
            signature = sign_ecdsa(private_key, message_hash)
            assert verify_ecdsa(public_key, signature, message_hash) is True
            
            # Test serialization round-trip
            compact = signature.to_compact()
            parsed = ECDSASignature.from_compact(compact)
            assert verify_ecdsa(public_key, parsed, message_hash) is True
    
    def test_random_schnorr_signatures(self):
        """Test Schnorr with random inputs."""
        for _ in range(10):
            # Generate random key and message
            private_key = PrivateKey()
            public_key = private_key.public_key()
            message = secrets.token_bytes(secrets.randbelow(100) + 1)
            
            # Sign and verify
            signature = sign_schnorr(private_key, message)
            assert verify_schnorr(public_key, signature, message) is True
            
            # Test serialization round-trip
            sig_bytes = signature.to_bytes()
            parsed = SchnorrSignature.from_bytes(sig_bytes)
            assert verify_schnorr(public_key, parsed, message) is True
    
    def test_random_bitcoin_messages(self):
        """Test Bitcoin message signing with random strings."""
        for _ in range(5):
            private_key = PrivateKey()
            public_key = private_key.public_key()
            
            # Generate random message
            message_bytes = secrets.token_bytes(secrets.randbelow(200) + 1)
            try:
                message = message_bytes.decode('utf-8', errors='ignore')
            except:
                message = "fallback message"
            
            # Sign and verify
            signature = sign_bitcoin_message(private_key, message)
            assert len(signature) == 65
            assert verify_bitcoin_message(public_key, signature, message) is True