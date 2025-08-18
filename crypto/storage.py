"""
Secure Key Storage and Management for BNAP

This module provides secure storage, encryption, and management
of private keys and derivation paths for Bitcoin Native Asset Protocol.

Features:
- AES-256-GCM encryption for private key storage
- PBKDF2 key derivation for password-based encryption
- Secure key derivation path management
- Memory-safe operations with automatic cleanup
- Encrypted storage with authentication
- Backup and recovery functionality
"""

import os
import json
import secrets
import hashlib
import hmac
from typing import Optional, Dict, List, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import time

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from .exceptions import CryptoError, InvalidKeyError
from .keys import PrivateKey, PublicKey, ExtendedKey


class StorageError(CryptoError):
    """Secure storage specific error."""
    pass


class KeyType(Enum):
    """Key type enumeration for storage."""
    PRIVATE_KEY = "private_key"
    EXTENDED_KEY = "extended_key"
    MNEMONIC = "mnemonic"
    SEED = "seed"


class EncryptionMethod(Enum):
    """Encryption method enumeration."""
    AES_256_GCM = "aes_256_gcm"
    PBKDF2_AES_256_GCM = "pbkdf2_aes_256_gcm"


@dataclass
class KeyDerivationPath:
    """
    BIP44/BIP84/BIP86 key derivation path representation.
    """
    purpose: int  # 44, 84, 86, etc.
    coin_type: int  # 0 for Bitcoin, 1 for testnet
    account: int
    change: int  # 0 for external, 1 for internal
    address_index: int
    
    def __post_init__(self):
        """Validate derivation path components."""
        if self.purpose not in [44, 49, 84, 86]:
            raise StorageError(f"Unsupported purpose: {self.purpose}")
        if self.coin_type not in [0, 1]:
            raise StorageError(f"Invalid coin type: {self.coin_type}")
        if self.account < 0 or self.account >= 2**31:
            raise StorageError(f"Invalid account: {self.account}")
        if self.change not in [0, 1]:
            raise StorageError(f"Invalid change: {self.change}")
        if self.address_index < 0 or self.address_index >= 2**31:
            raise StorageError(f"Invalid address index: {self.address_index}")
    
    def to_path_string(self) -> str:
        """Convert to BIP44 path string."""
        return f"m/{self.purpose}'/{self.coin_type}'/{self.account}'/{self.change}/{self.address_index}"
    
    @classmethod
    def from_path_string(cls, path: str) -> 'KeyDerivationPath':
        """Parse BIP44 path string."""
        if not path.startswith('m/'):
            raise StorageError("Path must start with 'm/'")
        
        parts = path[2:].split('/')
        if len(parts) != 5:
            raise StorageError("Invalid derivation path format")
        
        try:
            purpose = int(parts[0].rstrip("'"))
            coin_type = int(parts[1].rstrip("'"))
            account = int(parts[2].rstrip("'"))
            change = int(parts[3])
            address_index = int(parts[4])
            
            return cls(
                purpose=purpose,
                coin_type=coin_type,
                account=account,
                change=change,
                address_index=address_index
            )
        except ValueError as e:
            raise StorageError(f"Invalid path components: {e}")
    
    @classmethod
    def native_segwit(cls, account: int = 0, change: int = 0, address_index: int = 0) -> 'KeyDerivationPath':
        """Create native SegWit (P2WPKH) path."""
        return cls(purpose=84, coin_type=0, account=account, change=change, address_index=address_index)
    
    @classmethod
    def taproot(cls, account: int = 0, change: int = 0, address_index: int = 0) -> 'KeyDerivationPath':
        """Create Taproot (P2TR) path."""
        return cls(purpose=86, coin_type=0, account=account, change=change, address_index=address_index)
    
    @classmethod
    def legacy(cls, account: int = 0, change: int = 0, address_index: int = 0) -> 'KeyDerivationPath':
        """Create legacy (P2PKH) path."""
        return cls(purpose=44, coin_type=0, account=account, change=change, address_index=address_index)


@dataclass
class EncryptedKeyData:
    """
    Encrypted key storage container.
    """
    key_id: str
    key_type: KeyType
    encryption_method: EncryptionMethod
    encrypted_data: bytes
    salt: bytes
    nonce: bytes  # IV for AES-GCM
    tag: bytes  # Authentication tag for AES-GCM
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    
    def __post_init__(self):
        """Validate encrypted data structure."""
        if not self.key_id:
            raise StorageError("Key ID cannot be empty")
        if len(self.encrypted_data) == 0:
            raise StorageError("Encrypted data cannot be empty")
        if self.encryption_method == EncryptionMethod.AES_256_GCM:
            if len(self.nonce) != 12:  # AES-GCM standard nonce length
                raise StorageError("Invalid nonce length for AES-GCM")
            if len(self.tag) != 16:  # AES-GCM authentication tag length
                raise StorageError("Invalid tag length for AES-GCM")


class SecureKeyStorage:
    """
    Secure key storage and management system.
    """
    
    def __init__(self, storage_path: Optional[Union[str, Path]] = None):
        """
        Initialize secure key storage.
        
        Args:
            storage_path: Path to storage directory (None for in-memory only)
        """
        if not HAS_CRYPTO:
            raise StorageError("pycryptodome is required for secure key storage")
        
        self.storage_path = Path(storage_path) if storage_path else None
        self._keys: Dict[str, EncryptedKeyData] = {}
        self._memory_keys: Dict[str, bytes] = {}  # Temporary in-memory storage
        
        if self.storage_path:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            self._load_existing_keys()
    
    def _load_existing_keys(self) -> None:
        """Load existing keys from storage."""
        if not self.storage_path or not self.storage_path.exists():
            return
        
        for key_file in self.storage_path.glob("*.key"):
            try:
                with open(key_file, 'r') as f:
                    data = json.load(f)
                
                encrypted_key = EncryptedKeyData(
                    key_id=data['key_id'],
                    key_type=KeyType(data['key_type']),
                    encryption_method=EncryptionMethod(data['encryption_method']),
                    encrypted_data=bytes.fromhex(data['encrypted_data']),
                    salt=bytes.fromhex(data['salt']),
                    nonce=bytes.fromhex(data['nonce']),
                    tag=bytes.fromhex(data['tag']),
                    metadata=data.get('metadata', {}),
                    created_at=data.get('created_at', time.time())
                )
                
                self._keys[encrypted_key.key_id] = encrypted_key
                
            except Exception as e:
                # Log warning but continue loading other keys
                print(f"Warning: Failed to load key file {key_file}: {e}")
    
    def _save_key_to_file(self, encrypted_key: EncryptedKeyData) -> None:
        """Save encrypted key to file."""
        if not self.storage_path:
            return
        
        key_file = self.storage_path / f"{encrypted_key.key_id}.key"
        
        data = {
            'key_id': encrypted_key.key_id,
            'key_type': encrypted_key.key_type.value,
            'encryption_method': encrypted_key.encryption_method.value,
            'encrypted_data': encrypted_key.encrypted_data.hex(),
            'salt': encrypted_key.salt.hex(),
            'nonce': encrypted_key.nonce.hex(),
            'tag': encrypted_key.tag.hex(),
            'metadata': encrypted_key.metadata,
            'created_at': encrypted_key.created_at
        }
        
        # Write atomically
        temp_file = key_file.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(data, f, indent=2)
        temp_file.rename(key_file)
    
    def _derive_key(self, password: str, salt: bytes, key_length: int = 32) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        return PBKDF2(
            password=password,
            salt=salt,
            dkLen=key_length,
            count=100000,  # 100k iterations for security
            hmac_hash_module=SHA256
        )
    
    def encrypt_private_key(self, private_key: PrivateKey, password: str, 
                          key_id: Optional[str] = None, metadata: Optional[Dict] = None) -> str:
        """
        Encrypt and store a private key.
        
        Args:
            private_key: Private key to encrypt
            password: Password for encryption
            key_id: Optional key identifier (generated if None)
            metadata: Optional metadata to store with key
            
        Returns:
            Key ID for retrieval
        """
        if key_id is None:
            key_id = self._generate_key_id()
        
        if key_id in self._keys:
            raise StorageError(f"Key ID already exists: {key_id}")
        
        # Generate salt and nonce
        salt = get_random_bytes(32)
        nonce = get_random_bytes(12)
        
        # Derive encryption key
        encryption_key = self._derive_key(password, salt)
        
        # Encrypt private key
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        encrypted_data, tag = cipher.encrypt_and_digest(private_key.bytes)
        
        # Create encrypted key data
        encrypted_key = EncryptedKeyData(
            key_id=key_id,
            key_type=KeyType.PRIVATE_KEY,
            encryption_method=EncryptionMethod.PBKDF2_AES_256_GCM,
            encrypted_data=encrypted_data,
            salt=salt,
            nonce=nonce,
            tag=tag,
            metadata=metadata or {}
        )
        
        # Store encrypted key
        self._keys[key_id] = encrypted_key
        self._save_key_to_file(encrypted_key)
        
        # Clear sensitive data
        self._secure_clear(encryption_key)
        
        return key_id
    
    def decrypt_private_key(self, key_id: str, password: str) -> PrivateKey:
        """
        Decrypt and retrieve a private key.
        
        Args:
            key_id: Key identifier
            password: Password for decryption
            
        Returns:
            Decrypted private key
        """
        if key_id not in self._keys:
            raise StorageError(f"Key not found: {key_id}")
        
        encrypted_key = self._keys[key_id]
        
        if encrypted_key.key_type != KeyType.PRIVATE_KEY:
            raise StorageError(f"Key is not a private key: {key_id}")
        
        # Derive decryption key
        decryption_key = self._derive_key(password, encrypted_key.salt)
        
        try:
            # Decrypt private key
            cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=encrypted_key.nonce)
            private_key_bytes = cipher.decrypt_and_verify(encrypted_key.encrypted_data, encrypted_key.tag)
            
            # Create private key object
            private_key = PrivateKey(private_key_bytes)
            
            # Clear sensitive data
            self._secure_clear(decryption_key)
            self._secure_clear(private_key_bytes)
            
            return private_key
            
        except Exception as e:
            # Clear sensitive data on error
            self._secure_clear(decryption_key)
            raise StorageError(f"Failed to decrypt private key: {e}")
    
    def encrypt_mnemonic(self, mnemonic: str, password: str, 
                        key_id: Optional[str] = None, metadata: Optional[Dict] = None) -> str:
        """
        Encrypt and store a mnemonic phrase.
        
        Args:
            mnemonic: Mnemonic phrase to encrypt
            password: Password for encryption
            key_id: Optional key identifier
            metadata: Optional metadata
            
        Returns:
            Key ID for retrieval
        """
        if key_id is None:
            key_id = self._generate_key_id()
        
        if key_id in self._keys:
            raise StorageError(f"Key ID already exists: {key_id}")
        
        # Generate salt and nonce
        salt = get_random_bytes(32)
        nonce = get_random_bytes(12)
        
        # Derive encryption key
        encryption_key = self._derive_key(password, salt)
        
        # Encrypt mnemonic
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        mnemonic_bytes = mnemonic.encode('utf-8')
        encrypted_data, tag = cipher.encrypt_and_digest(mnemonic_bytes)
        
        # Create encrypted key data
        encrypted_key = EncryptedKeyData(
            key_id=key_id,
            key_type=KeyType.MNEMONIC,
            encryption_method=EncryptionMethod.PBKDF2_AES_256_GCM,
            encrypted_data=encrypted_data,
            salt=salt,
            nonce=nonce,
            tag=tag,
            metadata=metadata or {}
        )
        
        # Store encrypted key
        self._keys[key_id] = encrypted_key
        self._save_key_to_file(encrypted_key)
        
        # Clear sensitive data
        self._secure_clear(encryption_key)
        self._secure_clear(mnemonic_bytes)
        
        return key_id
    
    def decrypt_mnemonic(self, key_id: str, password: str) -> str:
        """
        Decrypt and retrieve a mnemonic phrase.
        
        Args:
            key_id: Key identifier
            password: Password for decryption
            
        Returns:
            Decrypted mnemonic phrase
        """
        if key_id not in self._keys:
            raise StorageError(f"Key not found: {key_id}")
        
        encrypted_key = self._keys[key_id]
        
        if encrypted_key.key_type != KeyType.MNEMONIC:
            raise StorageError(f"Key is not a mnemonic: {key_id}")
        
        # Derive decryption key
        decryption_key = self._derive_key(password, encrypted_key.salt)
        
        try:
            # Decrypt mnemonic
            cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=encrypted_key.nonce)
            mnemonic_bytes = cipher.decrypt_and_verify(encrypted_key.encrypted_data, encrypted_key.tag)
            mnemonic = mnemonic_bytes.decode('utf-8')
            
            # Clear sensitive data
            self._secure_clear(decryption_key)
            self._secure_clear(mnemonic_bytes)
            
            return mnemonic
            
        except Exception as e:
            # Clear sensitive data on error
            self._secure_clear(decryption_key)
            raise StorageError(f"Failed to decrypt mnemonic: {e}")
    
    def store_derived_key(self, extended_key: ExtendedKey, derivation_path: KeyDerivationPath,
                         password: str, key_id: Optional[str] = None) -> str:
        """
        Store an extended key with its derivation path.
        
        Args:
            extended_key: Extended key to store
            derivation_path: Key derivation path
            password: Password for encryption
            key_id: Optional key identifier
            
        Returns:
            Key ID for retrieval
        """
        if key_id is None:
            key_id = self._generate_key_id()
        
        metadata = {
            'derivation_path': derivation_path.to_path_string(),
            'is_private': extended_key.is_private,
            'depth': extended_key.depth,
            'child_number': extended_key.child_number
        }
        
        # Serialize extended key data
        if extended_key.is_private:
            key_data = extended_key.key.bytes + extended_key.chain_code
        else:
            key_data = extended_key.key.bytes + extended_key.chain_code
        
        # Generate salt and nonce
        salt = get_random_bytes(32)
        nonce = get_random_bytes(12)
        
        # Derive encryption key
        encryption_key = self._derive_key(password, salt)
        
        # Encrypt key data
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        encrypted_data, tag = cipher.encrypt_and_digest(key_data)
        
        # Create encrypted key data
        encrypted_key = EncryptedKeyData(
            key_id=key_id,
            key_type=KeyType.EXTENDED_KEY,
            encryption_method=EncryptionMethod.PBKDF2_AES_256_GCM,
            encrypted_data=encrypted_data,
            salt=salt,
            nonce=nonce,
            tag=tag,
            metadata=metadata
        )
        
        # Store encrypted key
        self._keys[key_id] = encrypted_key
        self._save_key_to_file(encrypted_key)
        
        # Clear sensitive data
        self._secure_clear(encryption_key)
        self._secure_clear(key_data)
        
        return key_id
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List all stored keys with their metadata.
        
        Returns:
            List of key information dictionaries
        """
        keys_info = []
        for key_id, encrypted_key in self._keys.items():
            info = {
                'key_id': key_id,
                'key_type': encrypted_key.key_type.value,
                'created_at': encrypted_key.created_at,
                'metadata': encrypted_key.metadata.copy()
            }
            keys_info.append(info)
        
        return sorted(keys_info, key=lambda x: x['created_at'])
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a stored key.
        
        Args:
            key_id: Key identifier to delete
            
        Returns:
            True if key was deleted
        """
        if key_id not in self._keys:
            return False
        
        # Remove from memory
        del self._keys[key_id]
        
        # Remove from disk if applicable
        if self.storage_path:
            key_file = self.storage_path / f"{key_id}.key"
            if key_file.exists():
                key_file.unlink()
        
        # Clear from memory keys if present
        if key_id in self._memory_keys:
            self._secure_clear(self._memory_keys[key_id])
            del self._memory_keys[key_id]
        
        return True
    
    def backup_keys(self, backup_path: Union[str, Path], password: str) -> None:
        """
        Create encrypted backup of all keys.
        
        Args:
            backup_path: Path for backup file
            password: Password for backup encryption
        """
        backup_data = {
            'version': '1.0',
            'created_at': time.time(),
            'keys': {}
        }
        
        # Include all encrypted keys
        for key_id, encrypted_key in self._keys.items():
            backup_data['keys'][key_id] = {
                'key_id': encrypted_key.key_id,
                'key_type': encrypted_key.key_type.value,
                'encryption_method': encrypted_key.encryption_method.value,
                'encrypted_data': encrypted_key.encrypted_data.hex(),
                'salt': encrypted_key.salt.hex(),
                'nonce': encrypted_key.nonce.hex(),
                'tag': encrypted_key.tag.hex(),
                'metadata': encrypted_key.metadata,
                'created_at': encrypted_key.created_at
            }
        
        # Encrypt backup data
        backup_json = json.dumps(backup_data).encode('utf-8')
        
        # Generate backup encryption parameters
        salt = get_random_bytes(32)
        nonce = get_random_bytes(12)
        backup_key = self._derive_key(password, salt)
        
        # Encrypt backup
        cipher = AES.new(backup_key, AES.MODE_GCM, nonce=nonce)
        encrypted_backup, tag = cipher.encrypt_and_digest(backup_json)
        
        # Create backup file
        backup_file_data = {
            'version': '1.0',
            'salt': salt.hex(),
            'nonce': nonce.hex(),
            'tag': tag.hex(),
            'encrypted_data': encrypted_backup.hex()
        }
        
        # Write backup file
        backup_path = Path(backup_path)
        with open(backup_path, 'w') as f:
            json.dump(backup_file_data, f, indent=2)
        
        # Clear sensitive data
        self._secure_clear(backup_key)
        self._secure_clear(backup_json)
    
    def restore_keys(self, backup_path: Union[str, Path], password: str) -> int:
        """
        Restore keys from encrypted backup.
        
        Args:
            backup_path: Path to backup file
            password: Password for backup decryption
            
        Returns:
            Number of keys restored
        """
        backup_path = Path(backup_path)
        
        if not backup_path.exists():
            raise StorageError(f"Backup file not found: {backup_path}")
        
        # Load backup file
        with open(backup_path, 'r') as f:
            backup_file_data = json.load(f)
        
        # Extract backup parameters
        salt = bytes.fromhex(backup_file_data['salt'])
        nonce = bytes.fromhex(backup_file_data['nonce'])
        tag = bytes.fromhex(backup_file_data['tag'])
        encrypted_backup = bytes.fromhex(backup_file_data['encrypted_data'])
        
        # Derive backup decryption key
        backup_key = self._derive_key(password, salt)
        
        try:
            # Decrypt backup
            cipher = AES.new(backup_key, AES.MODE_GCM, nonce=nonce)
            backup_json = cipher.decrypt_and_verify(encrypted_backup, tag)
            backup_data = json.loads(backup_json.decode('utf-8'))
            
            # Restore keys
            restored_count = 0
            for key_id, key_data in backup_data['keys'].items():
                if key_id not in self._keys:  # Don't overwrite existing keys
                    encrypted_key = EncryptedKeyData(
                        key_id=key_data['key_id'],
                        key_type=KeyType(key_data['key_type']),
                        encryption_method=EncryptionMethod(key_data['encryption_method']),
                        encrypted_data=bytes.fromhex(key_data['encrypted_data']),
                        salt=bytes.fromhex(key_data['salt']),
                        nonce=bytes.fromhex(key_data['nonce']),
                        tag=bytes.fromhex(key_data['tag']),
                        metadata=key_data['metadata'],
                        created_at=key_data['created_at']
                    )
                    
                    self._keys[key_id] = encrypted_key
                    self._save_key_to_file(encrypted_key)
                    restored_count += 1
            
            # Clear sensitive data
            self._secure_clear(backup_key)
            self._secure_clear(backup_json)
            
            return restored_count
            
        except Exception as e:
            # Clear sensitive data on error
            self._secure_clear(backup_key)
            raise StorageError(f"Failed to restore backup: {e}")
    
    def _generate_key_id(self) -> str:
        """Generate a unique key ID."""
        while True:
            key_id = secrets.token_hex(16)
            if key_id not in self._keys:
                return key_id
    
    def _secure_clear(self, data: Union[bytes, bytearray]) -> None:
        """Securely clear sensitive data from memory."""
        if isinstance(data, bytes):
            # Convert to bytearray for clearing
            data_array = bytearray(data)
            self._secure_clear(data_array)
        elif isinstance(data, bytearray):
            # Overwrite with random data, then zeros
            for i in range(len(data)):
                data[i] = secrets.randbelow(256)
            for i in range(len(data)):
                data[i] = 0
    
    def __del__(self):
        """Cleanup on object destruction."""
        # Clear any memory keys
        for key_data in self._memory_keys.values():
            self._secure_clear(key_data)
        self._memory_keys.clear()


# Utility functions

def encrypt_private_key(private_key: PrivateKey, password: str) -> Dict[str, str]:
    """
    Encrypt a private key with a password (standalone function).
    
    Args:
        private_key: Private key to encrypt
        password: Password for encryption
        
    Returns:
        Dictionary with encrypted data components
    """
    if not HAS_CRYPTO:
        raise StorageError("pycryptodome is required for encryption")
    
    # Generate salt and nonce
    salt = get_random_bytes(32)
    nonce = get_random_bytes(12)
    
    # Derive encryption key
    encryption_key = PBKDF2(
        password=password,
        salt=salt,
        dkLen=32,
        count=100000,
        hmac_hash_module=SHA256
    )
    
    # Encrypt private key
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
    encrypted_data, tag = cipher.encrypt_and_digest(private_key.bytes)
    
    return {
        'encrypted_data': encrypted_data.hex(),
        'salt': salt.hex(),
        'nonce': nonce.hex(),
        'tag': tag.hex(),
        'method': 'pbkdf2_aes_256_gcm'
    }


def decrypt_private_key(encrypted_data: Dict[str, str], password: str) -> PrivateKey:
    """
    Decrypt a private key with a password (standalone function).
    
    Args:
        encrypted_data: Dictionary with encrypted data components
        password: Password for decryption
        
    Returns:
        Decrypted private key
    """
    if not HAS_CRYPTO:
        raise StorageError("pycryptodome is required for decryption")
    
    # Extract components
    salt = bytes.fromhex(encrypted_data['salt'])
    nonce = bytes.fromhex(encrypted_data['nonce'])
    tag = bytes.fromhex(encrypted_data['tag'])
    ciphertext = bytes.fromhex(encrypted_data['encrypted_data'])
    
    # Derive decryption key
    decryption_key = PBKDF2(
        password=password,
        salt=salt,
        dkLen=32,
        count=100000,
        hmac_hash_module=SHA256
    )
    
    try:
        # Decrypt private key
        cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=nonce)
        private_key_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        
        return PrivateKey(private_key_bytes)
        
    except Exception as e:
        raise StorageError(f"Failed to decrypt private key: {e}")


def generate_secure_password(length: int = 32) -> str:
    """
    Generate a cryptographically secure password.
    
    Args:
        length: Password length
        
    Returns:
        Secure random password
    """
    # Use base64 encoding of random bytes for readable password
    import base64
    random_bytes = secrets.token_bytes(length * 3 // 4)  # Adjust for base64 expansion
    return base64.b64encode(random_bytes).decode('ascii')[:length]


def verify_password_strength(password: str) -> Dict[str, Any]:
    """
    Verify password strength and provide recommendations.
    
    Args:
        password: Password to analyze
        
    Returns:
        Dictionary with strength analysis
    """
    analysis = {
        'length': len(password),
        'has_upper': any(c.isupper() for c in password),
        'has_lower': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
        'entropy_estimate': 0,
        'strength': 'weak',
        'recommendations': []
    }
    
    # Estimate entropy (simplified)
    char_space = 0
    if analysis['has_lower']:
        char_space += 26
    if analysis['has_upper']:
        char_space += 26
    if analysis['has_digit']:
        char_space += 10
    if analysis['has_special']:
        char_space += 32
    
    if char_space > 0:
        import math
        analysis['entropy_estimate'] = math.log2(char_space) * len(password)
    
    # Determine strength
    if analysis['entropy_estimate'] >= 60 and analysis['length'] >= 12:
        analysis['strength'] = 'strong'
    elif analysis['entropy_estimate'] >= 40 and analysis['length'] >= 8:
        analysis['strength'] = 'moderate'
    else:
        analysis['strength'] = 'weak'
    
    # Generate recommendations
    if analysis['length'] < 12:
        analysis['recommendations'].append("Use at least 12 characters")
    if not analysis['has_upper']:
        analysis['recommendations'].append("Include uppercase letters")
    if not analysis['has_lower']:
        analysis['recommendations'].append("Include lowercase letters")
    if not analysis['has_digit']:
        analysis['recommendations'].append("Include numbers")
    if not analysis['has_special']:
        analysis['recommendations'].append("Include special characters")
    
    return analysis