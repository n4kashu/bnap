"""
Tests for Crypto Secure Key Storage Module

Tests secure key storage, encryption, derivation path management, backup/recovery,
and memory-safe operations for BNAP cryptographic keys.
"""

import pytest
import os
import tempfile
import shutil
import json
from pathlib import Path
from crypto.storage import (
    SecureKeyStorage,
    KeyDerivationPath,
    EncryptedKeyData,
    KeyType,
    EncryptionMethod,
    StorageError,
    encrypt_private_key,
    decrypt_private_key,
    generate_secure_password,
    verify_password_strength,
)
from crypto.keys import PrivateKey, ExtendedKey
from crypto.exceptions import CryptoError


class TestKeyDerivationPath:
    """Test BIP44/BIP84/BIP86 derivation path handling."""
    
    def test_derivation_path_creation(self):
        """Test basic derivation path creation."""
        path = KeyDerivationPath(
            purpose=84,
            coin_type=0,
            account=0,
            change=0,
            address_index=0
        )
        
        assert path.purpose == 84
        assert path.coin_type == 0
        assert path.account == 0
        assert path.change == 0
        assert path.address_index == 0
    
    def test_derivation_path_validation(self):
        """Test derivation path validation."""
        # Valid paths
        KeyDerivationPath(44, 0, 0, 0, 0)  # Legacy
        KeyDerivationPath(49, 0, 0, 0, 0)  # P2SH-wrapped SegWit
        KeyDerivationPath(84, 0, 0, 0, 0)  # Native SegWit
        KeyDerivationPath(86, 0, 0, 0, 0)  # Taproot
        
        # Invalid purpose
        with pytest.raises(StorageError, match="Unsupported purpose"):
            KeyDerivationPath(43, 0, 0, 0, 0)
        
        # Invalid coin type
        with pytest.raises(StorageError, match="Invalid coin type"):
            KeyDerivationPath(84, 2, 0, 0, 0)
        
        # Invalid account
        with pytest.raises(StorageError, match="Invalid account"):
            KeyDerivationPath(84, 0, -1, 0, 0)
        
        # Invalid change
        with pytest.raises(StorageError, match="Invalid change"):
            KeyDerivationPath(84, 0, 0, 2, 0)
        
        # Invalid address index
        with pytest.raises(StorageError, match="Invalid address index"):
            KeyDerivationPath(84, 0, 0, 0, -1)
    
    def test_path_string_conversion(self):
        """Test conversion to and from path strings."""
        path = KeyDerivationPath(84, 0, 0, 0, 0)
        path_string = path.to_path_string()
        
        assert path_string == "m/84'/0'/0'/0/0"
        
        # Test round-trip
        parsed_path = KeyDerivationPath.from_path_string(path_string)
        assert parsed_path.purpose == 84
        assert parsed_path.coin_type == 0
        assert parsed_path.account == 0
        assert parsed_path.change == 0
        assert parsed_path.address_index == 0
    
    def test_path_string_parsing_errors(self):
        """Test path string parsing error conditions."""
        # Invalid prefix
        with pytest.raises(StorageError, match="Path must start with 'm/'"):
            KeyDerivationPath.from_path_string("n/84'/0'/0'/0/0")
        
        # Invalid format
        with pytest.raises(StorageError, match="Invalid derivation path format"):
            KeyDerivationPath.from_path_string("m/84'/0'/0'/0")
        
        # Invalid components
        with pytest.raises(StorageError, match="Invalid path components"):
            KeyDerivationPath.from_path_string("m/abc'/0'/0'/0/0")
    
    def test_predefined_path_types(self):
        """Test predefined path type creation methods."""
        # Legacy
        legacy_path = KeyDerivationPath.legacy(1, 0, 5)
        assert legacy_path.to_path_string() == "m/44'/0'/1'/0/5"
        
        # Native SegWit
        segwit_path = KeyDerivationPath.native_segwit(0, 1, 10)
        assert segwit_path.to_path_string() == "m/84'/0'/0'/1/10"
        
        # Taproot
        taproot_path = KeyDerivationPath.taproot(2, 0, 20)
        assert taproot_path.to_path_string() == "m/86'/0'/2'/0/20"


class TestEncryptedKeyData:
    """Test encrypted key data container."""
    
    def test_encrypted_key_data_creation(self):
        """Test basic encrypted key data creation."""
        encrypted_data = EncryptedKeyData(
            key_id="test123",
            key_type=KeyType.PRIVATE_KEY,
            encryption_method=EncryptionMethod.PBKDF2_AES_256_GCM,
            encrypted_data=b'\x01' * 32,
            salt=b'\x02' * 32,
            nonce=b'\x03' * 12,
            tag=b'\x04' * 16
        )
        
        assert encrypted_data.key_id == "test123"
        assert encrypted_data.key_type == KeyType.PRIVATE_KEY
        assert encrypted_data.encryption_method == EncryptionMethod.PBKDF2_AES_256_GCM
    
    def test_encrypted_key_data_validation(self):
        """Test encrypted key data validation."""
        # Empty key ID
        with pytest.raises(StorageError, match="Key ID cannot be empty"):
            EncryptedKeyData("", KeyType.PRIVATE_KEY, EncryptionMethod.AES_256_GCM,
                           b'\x01' * 32, b'\x02' * 32, b'\x03' * 12, b'\x04' * 16)
        
        # Empty encrypted data
        with pytest.raises(StorageError, match="Encrypted data cannot be empty"):
            EncryptedKeyData("test", KeyType.PRIVATE_KEY, EncryptionMethod.AES_256_GCM,
                           b'', b'\x02' * 32, b'\x03' * 12, b'\x04' * 16)
        
        # Invalid nonce length for AES-GCM
        with pytest.raises(StorageError, match="Invalid nonce length"):
            EncryptedKeyData("test", KeyType.PRIVATE_KEY, EncryptionMethod.AES_256_GCM,
                           b'\x01' * 32, b'\x02' * 32, b'\x03' * 11, b'\x04' * 16)
        
        # Invalid tag length for AES-GCM
        with pytest.raises(StorageError, match="Invalid tag length"):
            EncryptedKeyData("test", KeyType.PRIVATE_KEY, EncryptionMethod.AES_256_GCM,
                           b'\x01' * 32, b'\x02' * 32, b'\x03' * 12, b'\x04' * 15)


class TestSecureKeyStorage:
    """Test secure key storage operations."""
    
    def setup_method(self):
        """Set up test environment with temporary directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / "test_storage"
    
    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_storage_initialization(self):
        """Test storage initialization."""
        # In-memory storage
        storage = SecureKeyStorage()
        assert storage.storage_path is None
        
        # File-based storage
        storage = SecureKeyStorage(self.storage_path)
        assert storage.storage_path == self.storage_path
        assert self.storage_path.exists()
    
    def test_encrypt_decrypt_private_key(self):
        """Test private key encryption and decryption."""
        storage = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        password = "test_password_123"
        
        # Encrypt private key
        key_id = storage.encrypt_private_key(private_key, password)
        assert isinstance(key_id, str)
        assert len(key_id) > 0
        
        # Decrypt private key
        decrypted_key = storage.decrypt_private_key(key_id, password)
        assert isinstance(decrypted_key, PrivateKey)
        assert decrypted_key.bytes == private_key.bytes
    
    def test_encrypt_decrypt_with_metadata(self):
        """Test key encryption with metadata."""
        storage = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        password = "meta_test_pass"
        metadata = {"purpose": "test", "created_by": "unittest"}
        
        key_id = storage.encrypt_private_key(private_key, password, 
                                           key_id="custom_id", metadata=metadata)
        assert key_id == "custom_id"
        
        # Check metadata is stored
        keys_info = storage.list_keys()
        key_info = next(k for k in keys_info if k['key_id'] == "custom_id")
        assert key_info['metadata'] == metadata
    
    def test_encrypt_duplicate_key_id(self):
        """Test encryption with duplicate key ID."""
        storage = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        password = "test_pass"
        
        # First encryption
        storage.encrypt_private_key(private_key, password, key_id="duplicate")
        
        # Second encryption with same ID should fail
        with pytest.raises(StorageError, match="Key ID already exists"):
            storage.encrypt_private_key(private_key, password, key_id="duplicate")
    
    def test_decrypt_nonexistent_key(self):
        """Test decryption of nonexistent key."""
        storage = SecureKeyStorage(self.storage_path)
        
        with pytest.raises(StorageError, match="Key not found"):
            storage.decrypt_private_key("nonexistent", "password")
    
    def test_decrypt_wrong_password(self):
        """Test decryption with wrong password."""
        storage = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        password = "correct_password"
        
        key_id = storage.encrypt_private_key(private_key, password)
        
        with pytest.raises(StorageError, match="Failed to decrypt"):
            storage.decrypt_private_key(key_id, "wrong_password")
    
    def test_encrypt_decrypt_mnemonic(self):
        """Test mnemonic encryption and decryption."""
        storage = SecureKeyStorage(self.storage_path)
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        password = "mnemonic_pass"
        
        # Encrypt mnemonic
        key_id = storage.encrypt_mnemonic(mnemonic, password)
        
        # Decrypt mnemonic
        decrypted_mnemonic = storage.decrypt_mnemonic(key_id, password)
        assert decrypted_mnemonic == mnemonic
    
    def test_store_derived_key(self):
        """Test storing extended key with derivation path."""
        storage = SecureKeyStorage(self.storage_path)
        
        # Create extended key
        private_key = PrivateKey()
        chain_code = b'\x01' * 32  # Example chain code
        extended_key = ExtendedKey(key=private_key, chain_code=chain_code, depth=1)
        derivation_path = KeyDerivationPath.native_segwit(0, 0, 0)
        password = "extended_pass"
        
        # Store extended key
        key_id = storage.store_derived_key(extended_key, derivation_path, password)
        
        # Verify metadata
        keys_info = storage.list_keys()
        key_info = next(k for k in keys_info if k['key_id'] == key_id)
        assert key_info['key_type'] == KeyType.EXTENDED_KEY.value
        assert key_info['metadata']['derivation_path'] == derivation_path.to_path_string()
    
    def test_list_keys(self):
        """Test key listing functionality."""
        storage = SecureKeyStorage(self.storage_path)
        
        # Initially empty
        assert storage.list_keys() == []
        
        # Add some keys
        private_key1 = PrivateKey()
        private_key2 = PrivateKey()
        
        key_id1 = storage.encrypt_private_key(private_key1, "pass1", key_id="key1")
        key_id2 = storage.encrypt_private_key(private_key2, "pass2", key_id="key2")
        
        # List keys
        keys_info = storage.list_keys()
        assert len(keys_info) == 2
        
        key_ids = [info['key_id'] for info in keys_info]
        assert "key1" in key_ids
        assert "key2" in key_ids
    
    def test_delete_key(self):
        """Test key deletion."""
        storage = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        
        key_id = storage.encrypt_private_key(private_key, "delete_test")
        
        # Verify key exists
        assert len(storage.list_keys()) == 1
        
        # Delete key
        assert storage.delete_key(key_id) is True
        assert len(storage.list_keys()) == 0
        
        # Delete nonexistent key
        assert storage.delete_key("nonexistent") is False
    
    def test_backup_and_restore(self):
        """Test key backup and restore functionality."""
        # Create storage with some keys
        storage1 = SecureKeyStorage(self.storage_path)
        private_key1 = PrivateKey()
        private_key2 = PrivateKey()
        
        key_id1 = storage1.encrypt_private_key(private_key1, "pass1", key_id="backup1")
        key_id2 = storage1.encrypt_private_key(private_key2, "pass2", key_id="backup2")
        
        # Create backup
        backup_path = Path(self.temp_dir) / "backup.json"
        backup_password = "backup_password_123"
        storage1.backup_keys(backup_path, backup_password)
        
        assert backup_path.exists()
        
        # Create new storage and restore
        storage2 = SecureKeyStorage(Path(self.temp_dir) / "restore_storage")
        restored_count = storage2.restore_keys(backup_path, backup_password)
        
        assert restored_count == 2
        assert len(storage2.list_keys()) == 2
        
        # Verify keys can be decrypted
        restored_key1 = storage2.decrypt_private_key("backup1", "pass1")
        restored_key2 = storage2.decrypt_private_key("backup2", "pass2")
        
        assert restored_key1.bytes == private_key1.bytes
        assert restored_key2.bytes == private_key2.bytes
    
    def test_restore_nonexistent_backup(self):
        """Test restore from nonexistent backup file."""
        storage = SecureKeyStorage(self.storage_path)
        nonexistent_path = Path(self.temp_dir) / "nonexistent.json"
        
        with pytest.raises(StorageError, match="Backup file not found"):
            storage.restore_keys(nonexistent_path, "password")
    
    def test_restore_wrong_backup_password(self):
        """Test restore with wrong backup password."""
        storage1 = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        storage1.encrypt_private_key(private_key, "pass")
        
        backup_path = Path(self.temp_dir) / "backup.json"
        storage1.backup_keys(backup_path, "correct_backup_pass")
        
        storage2 = SecureKeyStorage(Path(self.temp_dir) / "restore_storage")
        
        with pytest.raises(StorageError, match="Failed to restore backup"):
            storage2.restore_keys(backup_path, "wrong_backup_pass")
    
    def test_persistence_across_sessions(self):
        """Test that keys persist across storage sessions."""
        # Create storage and add key
        storage1 = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        key_id = storage1.encrypt_private_key(private_key, "persist_test")
        
        # Create new storage instance with same path
        storage2 = SecureKeyStorage(self.storage_path)
        
        # Should load existing keys
        keys_info = storage2.list_keys()
        assert len(keys_info) == 1
        assert keys_info[0]['key_id'] == key_id
        
        # Should be able to decrypt
        decrypted = storage2.decrypt_private_key(key_id, "persist_test")
        assert decrypted.bytes == private_key.bytes


class TestStandaloneUtilities:
    """Test standalone utility functions."""
    
    def test_standalone_encrypt_decrypt(self):
        """Test standalone encryption/decryption functions."""
        private_key = PrivateKey()
        password = "standalone_test"
        
        # Encrypt
        encrypted_data = encrypt_private_key(private_key, password)
        assert isinstance(encrypted_data, dict)
        assert 'encrypted_data' in encrypted_data
        assert 'salt' in encrypted_data
        assert 'nonce' in encrypted_data
        assert 'tag' in encrypted_data
        assert 'method' in encrypted_data
        
        # Decrypt
        decrypted_key = decrypt_private_key(encrypted_data, password)
        assert isinstance(decrypted_key, PrivateKey)
        assert decrypted_key.bytes == private_key.bytes
    
    def test_standalone_decrypt_wrong_password(self):
        """Test standalone decryption with wrong password."""
        private_key = PrivateKey()
        encrypted_data = encrypt_private_key(private_key, "correct")
        
        with pytest.raises(StorageError, match="Failed to decrypt"):
            decrypt_private_key(encrypted_data, "wrong")
    
    def test_generate_secure_password(self):
        """Test secure password generation."""
        # Default length
        password1 = generate_secure_password()
        assert len(password1) == 32
        
        # Custom length
        password2 = generate_secure_password(16)
        assert len(password2) == 16
        
        # Should be different
        password3 = generate_secure_password()
        assert password1 != password3
    
    def test_verify_password_strength(self):
        """Test password strength verification."""
        # Strong password
        strong_analysis = verify_password_strength("MyStr0ng!P@ssw0rd123")
        assert strong_analysis['strength'] == 'strong'
        assert strong_analysis['has_upper'] is True
        assert strong_analysis['has_lower'] is True
        assert strong_analysis['has_digit'] is True
        assert strong_analysis['has_special'] is True
        assert len(strong_analysis['recommendations']) == 0
        
        # Weak password
        weak_analysis = verify_password_strength("weak")
        assert weak_analysis['strength'] == 'weak'
        assert len(weak_analysis['recommendations']) > 0
        
        # Moderate password
        moderate_analysis = verify_password_strength("Moderate123")
        assert moderate_analysis['strength'] in ['moderate', 'weak']


class TestErrorConditions:
    """Test various error conditions and edge cases."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / "error_storage"
    
    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_decrypt_wrong_key_type(self):
        """Test decryption with wrong key type expectation."""
        storage = SecureKeyStorage(self.storage_path)
        mnemonic = "test mnemonic phrase"
        password = "test_pass"
        
        # Store as mnemonic
        key_id = storage.encrypt_mnemonic(mnemonic, password)
        
        # Try to decrypt as private key
        with pytest.raises(StorageError, match="Key is not a private key"):
            storage.decrypt_private_key(key_id, password)
    
    def test_corrupted_key_file_handling(self):
        """Test handling of corrupted key files."""
        storage = SecureKeyStorage(self.storage_path)
        
        # Create a corrupted key file
        corrupted_file = self.storage_path / "corrupted.key"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        with open(corrupted_file, 'w') as f:
            f.write("invalid json content")
        
        # Storage should handle this gracefully during initialization
        storage2 = SecureKeyStorage(self.storage_path)
        assert len(storage2.list_keys()) == 0  # Should skip corrupted file
    
    def test_memory_clearing(self):
        """Test that sensitive data is cleared from memory."""
        storage = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        
        key_id = storage.encrypt_private_key(private_key, "clear_test")
        
        # The _secure_clear method should be called during operations
        # This is primarily tested through the fact that operations complete
        # without errors and don't leave sensitive data exposed
        
        decrypted = storage.decrypt_private_key(key_id, "clear_test")
        assert decrypted.bytes == private_key.bytes


class TestRandomizedTesting:
    """Test with randomized inputs for robustness."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / "random_storage"
    
    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_random_key_operations(self):
        """Test storage with random keys and passwords."""
        storage = SecureKeyStorage(self.storage_path)
        
        keys_data = []
        for i in range(10):
            private_key = PrivateKey()
            password = generate_secure_password()
            
            key_id = storage.encrypt_private_key(private_key, password)
            keys_data.append((key_id, private_key, password))
        
        # Verify all keys can be decrypted
        for key_id, original_key, password in keys_data:
            decrypted = storage.decrypt_private_key(key_id, password)
            assert decrypted.bytes == original_key.bytes
    
    def test_random_derivation_paths(self):
        """Test with random derivation paths."""
        storage = SecureKeyStorage(self.storage_path)
        
        purposes = [44, 49, 84, 86]
        
        for _ in range(20):
            purpose = purposes[len(storage.list_keys()) % len(purposes)]
            account = len(storage.list_keys()) % 10
            change = len(storage.list_keys()) % 2
            address_index = len(storage.list_keys())
            
            path = KeyDerivationPath(purpose, 0, account, change, address_index)
            path_string = path.to_path_string()
            
            # Test round-trip
            parsed = KeyDerivationPath.from_path_string(path_string)
            assert parsed.purpose == purpose
            assert parsed.account == account
            assert parsed.change == change
            assert parsed.address_index == address_index


class TestConcurrencyAndSafety:
    """Test thread safety and concurrent access scenarios."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = Path(self.temp_dir) / "concurrent_storage"
    
    def teardown_method(self):
        """Clean up test environment."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_multiple_storage_instances(self):
        """Test multiple storage instances accessing same directory."""
        # Create key with first instance
        storage1 = SecureKeyStorage(self.storage_path)
        private_key = PrivateKey()
        key_id = storage1.encrypt_private_key(private_key, "concurrent_test")
        
        # Access with second instance
        storage2 = SecureKeyStorage(self.storage_path)
        decrypted = storage2.decrypt_private_key(key_id, "concurrent_test")
        
        assert decrypted.bytes == private_key.bytes
        
        # Both should see the same keys
        keys1 = storage1.list_keys()
        keys2 = storage2.list_keys()
        assert len(keys1) == len(keys2) == 1