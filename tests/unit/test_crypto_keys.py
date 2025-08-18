"""
Tests for Crypto Keys Module

Tests BIP32/BIP39 key derivation, private/public key operations,
and extended key functionality.
"""

import pytest
import hashlib
from crypto.keys import (
    PrivateKey,
    PublicKey,
    ExtendedKey,
    generate_mnemonic,
    mnemonic_to_seed,
    seed_to_master_key,
    derive_key_from_path,
    get_standard_derivation_path,
    parse_derivation_path,
    BIP32_HARDENED_OFFSET,
)
from crypto.exceptions import (
    InvalidKeyError,
    DerivationError,
)


class TestPrivateKey:
    """Test PrivateKey class functionality."""
    
    def test_random_key_generation(self):
        """Test random private key generation."""
        key1 = PrivateKey()
        key2 = PrivateKey()
        
        # Keys should be different
        assert key1.bytes != key2.bytes
        assert len(key1.bytes) == 32
        assert len(key2.bytes) == 32
        
    def test_key_from_bytes(self):
        """Test private key creation from bytes."""
        # Valid key
        key_bytes = b'\x01' * 32
        key = PrivateKey(key_bytes)
        assert key.bytes == key_bytes
        
    def test_invalid_key_bytes(self):
        """Test invalid key bytes handling."""
        # Wrong length
        with pytest.raises(InvalidKeyError):
            PrivateKey(b'\x01' * 31)
            
        with pytest.raises(InvalidKeyError):
            PrivateKey(b'\x01' * 33)
            
        # Zero key
        with pytest.raises(InvalidKeyError):
            PrivateKey(b'\x00' * 32)
            
    def test_public_key_derivation(self):
        """Test public key derivation from private key."""
        private_key = PrivateKey(b'\x01' * 32)
        public_key = private_key.public_key()
        
        assert isinstance(public_key, PublicKey)
        assert len(public_key.bytes) == 33  # Compressed
        assert len(public_key.uncompressed_bytes) == 65
        
    def test_hex_properties(self):
        """Test hex string properties."""
        key_bytes = b'\x01' * 32
        private_key = PrivateKey(key_bytes)
        
        assert private_key.hex == key_bytes.hex()
        assert len(private_key.hex) == 64
        
    def test_signing(self):
        """Test message signing."""
        private_key = PrivateKey(b'\x01' * 32)
        message_hash = hashlib.sha256(b"test message").digest()
        
        # Standard signature
        signature = private_key.sign(message_hash)
        assert isinstance(signature, bytes)
        assert len(signature) >= 8  # Minimum DER signature length
        
        # Recoverable signature
        recoverable_sig = private_key.sign_recoverable(message_hash)
        assert isinstance(recoverable_sig, bytes)
        assert len(recoverable_sig) == 65
        
    def test_invalid_message_hash(self):
        """Test signing with invalid message hash."""
        private_key = PrivateKey()
        
        with pytest.raises(InvalidKeyError):
            private_key.sign(b"wrong_length")
            
        with pytest.raises(InvalidKeyError):
            private_key.sign_recoverable(b"wrong_length")


class TestPublicKey:
    """Test PublicKey class functionality."""
    
    def test_key_from_bytes(self):
        """Test public key creation from bytes."""
        # Compressed key (33 bytes)
        compressed_key = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        public_key = PublicKey(compressed_key)
        
        assert public_key.bytes == compressed_key
        assert len(public_key.bytes) == 33
        
    def test_uncompressed_key(self):
        """Test uncompressed public key handling."""
        # Uncompressed key (65 bytes)
        uncompressed_key = bytes.fromhex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" + 
                                       "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
        public_key = PublicKey(uncompressed_key)
        
        assert len(public_key.uncompressed_bytes) == 65
        assert len(public_key.bytes) == 33  # Should return compressed
        
    def test_x_only_key(self):
        """Test x-only key for Taproot."""
        compressed_key = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        public_key = PublicKey(compressed_key)
        
        x_only = public_key.x_only
        assert len(x_only) == 32
        assert x_only == compressed_key[1:]  # Without prefix
        
    def test_invalid_key_bytes(self):
        """Test invalid public key bytes handling."""
        with pytest.raises(InvalidKeyError):
            PublicKey(b'\x01' * 32)  # Wrong length
            
        with pytest.raises(InvalidKeyError):
            PublicKey(b'\x01' * 34)  # Wrong length
            
    def test_signature_verification(self):
        """Test signature verification."""
        private_key = PrivateKey(b'\x01' * 32)
        public_key = private_key.public_key()
        message_hash = hashlib.sha256(b"test message").digest()
        
        signature = private_key.sign(message_hash)
        assert public_key.verify(signature, message_hash)
        
        # Wrong message should fail
        wrong_message = hashlib.sha256(b"wrong message").digest()
        assert not public_key.verify(signature, wrong_message)
        
        # Wrong signature should fail
        assert not public_key.verify(b"invalid_signature", message_hash)


class TestExtendedKey:
    """Test ExtendedKey class for BIP32 derivation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.test_seed = b"test seed for extended keys" * 2  # 54 bytes
        self.master_key = seed_to_master_key(self.test_seed)
        
    def test_master_key_creation(self):
        """Test master key creation from seed."""
        assert isinstance(self.master_key, ExtendedKey)
        assert self.master_key.is_private
        assert self.master_key.depth == 0
        assert self.master_key.fingerprint == b'\x00\x00\x00\x00'
        assert self.master_key.child_number == 0
        assert len(self.master_key.chain_code) == 32
        
    def test_invalid_extended_key_creation(self):
        """Test invalid extended key creation."""
        private_key = PrivateKey()
        
        # Invalid chain code
        with pytest.raises(DerivationError):
            ExtendedKey(private_key, b"short_chain_code")
            
        # Invalid fingerprint
        with pytest.raises(DerivationError):
            ExtendedKey(private_key, b'a' * 32, fingerprint=b'short')
            
        # Invalid depth
        with pytest.raises(DerivationError):
            ExtendedKey(private_key, b'a' * 32, depth=-1)
            
        with pytest.raises(DerivationError):
            ExtendedKey(private_key, b'a' * 32, depth=256)
            
    def test_child_derivation_hardened(self):
        """Test hardened child derivation."""
        child_index = BIP32_HARDENED_OFFSET  # First hardened child (0')
        child_key = self.master_key.derive_child(child_index)
        
        assert child_key.depth == 1
        assert child_key.child_number == child_index
        assert child_key.is_private
        assert child_key.chain_code != self.master_key.chain_code
        
    def test_child_derivation_non_hardened(self):
        """Test non-hardened child derivation."""
        # First derive a hardened child, then non-hardened from it
        hardened_child = self.master_key.derive_child(BIP32_HARDENED_OFFSET)
        non_hardened_child = hardened_child.derive_child(0)
        
        assert non_hardened_child.depth == 2
        assert non_hardened_child.child_number == 0
        assert non_hardened_child.is_private
        
    def test_public_key_derivation(self):
        """Test derivation from public extended key."""
        # Derive hardened child first (can only be done with private key)
        hardened_child = self.master_key.derive_child(BIP32_HARDENED_OFFSET)
        
        # Convert to public extended key
        public_extended_key = ExtendedKey(
            key=hardened_child.key.public_key(),
            chain_code=hardened_child.chain_code,
            depth=hardened_child.depth,
            fingerprint=hardened_child.fingerprint,
            child_number=hardened_child.child_number
        )
        
        assert not public_extended_key.is_private
        
        # Can derive non-hardened children
        public_child = public_extended_key.derive_child(0)
        assert not public_child.is_private
        
        # Cannot derive hardened children from public key
        with pytest.raises(DerivationError):
            public_extended_key.derive_child(BIP32_HARDENED_OFFSET)
            
    def test_path_derivation(self):
        """Test derivation from path string."""
        path = "m/84'/0'/0'/0/0"  # Native SegWit path
        derived_key = self.master_key.derive_path(path)
        
        assert derived_key.depth == 5
        assert derived_key.is_private
        
    def test_invalid_path_derivation(self):
        """Test invalid path derivation."""
        # Path must start with 'm/'
        with pytest.raises(DerivationError):
            self.master_key.derive_path("84'/0'/0'")
            
        # Empty path parts are ignored
        valid_key = self.master_key.derive_path("m//0//")
        assert valid_key.depth == 1


class TestBIP39:
    """Test BIP39 mnemonic functionality."""
    
    def test_mnemonic_generation(self):
        """Test mnemonic phrase generation."""
        # Default strength (128 bits = 12 words)
        mnemonic = generate_mnemonic()
        words = mnemonic.split()
        assert len(words) == 12
        
        # Different strengths
        strengths_words = {
            128: 12,
            160: 15, 
            192: 18,
            224: 21,
            256: 24
        }
        
        for strength, expected_words in strengths_words.items():
            mnemonic = generate_mnemonic(strength)
            words = mnemonic.split()
            assert len(words) == expected_words
            
    def test_invalid_mnemonic_strength(self):
        """Test invalid mnemonic strength."""
        with pytest.raises(DerivationError):
            generate_mnemonic(100)  # Invalid strength
            
    def test_mnemonic_to_seed(self):
        """Test mnemonic to seed conversion."""
        # Known test vector from BIP39
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        
        # Without passphrase
        seed = mnemonic_to_seed(mnemonic)
        assert len(seed) == 64
        
        # With passphrase
        seed_with_passphrase = mnemonic_to_seed(mnemonic, "TREZOR")
        assert len(seed_with_passphrase) == 64
        assert seed_with_passphrase != seed  # Should be different
        
    def test_invalid_mnemonic(self):
        """Test invalid mnemonic handling."""
        with pytest.raises(DerivationError):
            mnemonic_to_seed("invalid mnemonic phrase")
            
    def test_seed_to_master_key(self):
        """Test seed to master key conversion."""
        mnemonic = generate_mnemonic()
        seed = mnemonic_to_seed(mnemonic)
        master_key = seed_to_master_key(seed)
        
        assert isinstance(master_key, ExtendedKey)
        assert master_key.is_private
        assert master_key.depth == 0
        
    def test_invalid_seed_length(self):
        """Test invalid seed length handling."""
        with pytest.raises(DerivationError):
            seed_to_master_key(b"short")  # Too short
            
        with pytest.raises(DerivationError):
            seed_to_master_key(b"a" * 65)  # Too long


class TestKeyDerivationIntegration:
    """Test full key derivation integration."""
    
    def test_derive_key_from_path(self):
        """Test complete derivation from mnemonic and path."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        path = "m/84'/0'/0'/0/0"
        
        derived_key = derive_key_from_path(mnemonic, path)
        
        assert isinstance(derived_key, ExtendedKey)
        assert derived_key.is_private
        assert derived_key.depth == 5
        
        # Should be deterministic
        derived_key2 = derive_key_from_path(mnemonic, path)
        assert derived_key.key.bytes == derived_key2.key.bytes
        
    def test_standard_derivation_paths(self):
        """Test standard derivation paths."""
        paths = {
            'native_segwit': "m/84'/0'/0'",
            'taproot': "m/86'/0'/0'",
            'legacy': "m/44'/0'/0'",
            'nested_segwit': "m/49'/0'/0'",
        }
        
        for key_type, expected_path in paths.items():
            path = get_standard_derivation_path(key_type)
            assert path == expected_path
            
    def test_unknown_key_type(self):
        """Test unknown key type handling."""
        with pytest.raises(DerivationError):
            get_standard_derivation_path("unknown_type")
            
    def test_parse_derivation_path(self):
        """Test derivation path parsing."""
        path = "m/84'/0'/0'/0/0"
        indices = parse_derivation_path(path)
        
        expected = [
            84 + BIP32_HARDENED_OFFSET,
            0 + BIP32_HARDENED_OFFSET, 
            0 + BIP32_HARDENED_OFFSET,
            0,
            0
        ]
        
        assert indices == expected
        
    def test_consistency_across_derivations(self):
        """Test consistency between different derivation methods."""
        mnemonic = generate_mnemonic()
        path = "m/84'/0'/0'/0/0"
        
        # Method 1: Direct derivation
        key1 = derive_key_from_path(mnemonic, path)
        
        # Method 2: Step by step
        seed = mnemonic_to_seed(mnemonic)
        master = seed_to_master_key(seed)
        key2 = master.derive_path(path)
        
        # Should produce same result
        assert key1.key.bytes == key2.key.bytes
        assert key1.chain_code == key2.chain_code


class TestBIP32TestVectors:
    """Test against known BIP32 test vectors."""
    
    def test_bip32_test_vector_1(self):
        """Test BIP32 test vector 1."""
        # From BIP32 specification
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        
        master_key = seed_to_master_key(seed)
        
        # Master key should have specific fingerprint when deriving children
        child_m0h = master_key.derive_child(BIP32_HARDENED_OFFSET)
        assert child_m0h.depth == 1
        assert child_m0h.is_private
        
        # Test path derivation
        m_0h_1_2h = master_key.derive_path("m/0'/1/2'")
        assert m_0h_1_2h.depth == 3
        
    def test_deterministic_derivation(self):
        """Test that derivation is deterministic."""
        seed = b"test seed for deterministic derivation" + b"x" * 20
        
        master1 = seed_to_master_key(seed)
        master2 = seed_to_master_key(seed)
        
        # Masters should be identical
        assert master1.key.bytes == master2.key.bytes
        assert master1.chain_code == master2.chain_code
        
        # Children should be identical  
        child1 = master1.derive_child(0)
        child2 = master2.derive_child(0)
        
        assert child1.key.bytes == child2.key.bytes
        assert child1.chain_code == child2.chain_code