"""
Bitcoin Native Asset Protocol - Asset ID Generation and Validation

This module provides utilities for generating and validating 32-byte SHA-256
asset identifiers with collision detection and deterministic derivation.
"""

import hashlib
import re
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Union
from uuid import uuid4

from .schema import AssetType


class AssetIDError(Exception):
    """Base asset ID exception."""
    pass


class InvalidAssetIDError(AssetIDError):
    """Invalid asset ID format exception."""
    pass


class AssetIDCollisionError(AssetIDError):
    """Asset ID collision detected exception."""
    pass


class AssetIDGenerator:
    """Deterministic asset ID generator with collision detection."""
    
    def __init__(self, collision_checker: Optional[Callable[[str], bool]] = None):
        """
        Initialize asset ID generator.
        
        Args:
            collision_checker: Function that returns True if asset ID already exists
        """
        self.collision_checker = collision_checker or (lambda x: False)
        self._used_nonces: Set[str] = set()
    
    def generate_id(
        self,
        name: str,
        issuer_pubkey: str,
        asset_type: AssetType,
        timestamp: Optional[datetime] = None,
        nonce: Optional[str] = None,
        max_attempts: int = 100
    ) -> str:
        """
        Generate a deterministic asset ID.
        
        Args:
            name: Asset name
            issuer_pubkey: Issuer public key (hex)
            asset_type: Asset type (fungible/nft)
            timestamp: Creation timestamp (defaults to current time)
            nonce: Optional nonce for uniqueness
            max_attempts: Maximum collision resolution attempts
            
        Returns:
            32-byte SHA-256 asset ID (hex string)
            
        Raises:
            AssetIDCollisionError: If unable to resolve collision after max_attempts
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        # Normalize inputs
        name = name.strip()
        issuer_pubkey = self._normalize_pubkey(issuer_pubkey)
        timestamp_str = timestamp.isoformat()
        
        for attempt in range(max_attempts):
            # Generate nonce if not provided or if collision detected
            if nonce is None or attempt > 0:
                nonce = self._generate_nonce()
            
            # Create deterministic string for hashing
            data_string = f"{name}|{issuer_pubkey}|{asset_type.value}|{timestamp_str}|{nonce}"
            
            # Generate SHA-256 hash
            asset_id = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
            
            # Check for collision
            if not self.collision_checker(asset_id):
                self._used_nonces.add(nonce)
                return asset_id
        
        raise AssetIDCollisionError(
            f"Unable to generate unique asset ID after {max_attempts} attempts"
        )
    
    def generate_collection_id(
        self,
        collection_name: str,
        issuer_pubkey: str,
        base_nonce: Optional[str] = None
    ) -> str:
        """
        Generate a collection ID for NFT collections.
        
        Args:
            collection_name: Name of the NFT collection
            issuer_pubkey: Issuer public key
            base_nonce: Optional base nonce for deterministic generation
            
        Returns:
            Collection ID (hex string)
        """
        return self.generate_id(
            name=f"collection:{collection_name}",
            issuer_pubkey=issuer_pubkey,
            asset_type=AssetType.NFT,
            nonce=base_nonce
        )
    
    def derive_sub_asset_id(
        self,
        parent_asset_id: str,
        sub_asset_name: str,
        sub_index: int = 0
    ) -> str:
        """
        Derive a sub-asset ID from a parent asset.
        
        Args:
            parent_asset_id: Parent asset ID
            sub_asset_name: Sub-asset name/identifier
            sub_index: Sub-asset index
            
        Returns:
            Derived sub-asset ID (hex string)
        """
        if not self.validate_asset_id(parent_asset_id):
            raise InvalidAssetIDError(f"Invalid parent asset ID: {parent_asset_id}")
        
        # Create derivation string
        derivation_data = f"{parent_asset_id}|sub:{sub_asset_name}|{sub_index}"
        
        # Generate derived ID
        derived_id = hashlib.sha256(derivation_data.encode('utf-8')).hexdigest()
        
        return derived_id
    
    def generate_nft_token_id(
        self,
        collection_id: str,
        token_index: int,
        token_metadata_hash: Optional[str] = None
    ) -> str:
        """
        Generate a unique NFT token ID within a collection.
        
        Args:
            collection_id: Collection asset ID
            token_index: Token index within collection
            token_metadata_hash: Optional metadata hash for uniqueness
            
        Returns:
            NFT token ID (hex string)
        """
        if not self.validate_asset_id(collection_id):
            raise InvalidAssetIDError(f"Invalid collection ID: {collection_id}")
        
        # Create token ID string
        token_data = f"{collection_id}|token:{token_index}"
        
        if token_metadata_hash:
            token_data += f"|{token_metadata_hash}"
        
        # Generate token ID
        token_id = hashlib.sha256(token_data.encode('utf-8')).hexdigest()
        
        return token_id
    
    def _normalize_pubkey(self, pubkey: str) -> str:
        """Normalize public key format."""
        # Remove 0x prefix if present
        if pubkey.startswith('0x'):
            pubkey = pubkey[2:]
        
        # Convert to lowercase
        return pubkey.lower()
    
    def _generate_nonce(self) -> str:
        """Generate a unique nonce."""
        # Combine timestamp and UUID for uniqueness
        timestamp = str(int(time.time() * 1000000))  # microseconds
        uuid_hex = uuid4().hex
        return f"{timestamp}:{uuid_hex}"
    
    @staticmethod
    def validate_asset_id(asset_id: str) -> bool:
        """
        Validate asset ID format.
        
        Args:
            asset_id: Asset ID to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(asset_id, str):
            return False
        
        # Remove 0x prefix if present
        if asset_id.startswith('0x'):
            asset_id = asset_id[2:]
        
        # Check length (64 hex characters = 32 bytes)
        if len(asset_id) != 64:
            return False
        
        # Check hex format
        if not re.match(r'^[a-fA-F0-9]{64}$', asset_id):
            return False
        
        return True
    
    @staticmethod
    def asset_id_to_bytes(asset_id: str) -> bytes:
        """
        Convert asset ID from hex string to bytes.
        
        Args:
            asset_id: Asset ID hex string
            
        Returns:
            32-byte array
            
        Raises:
            InvalidAssetIDError: If asset ID format is invalid
        """
        if not AssetIDGenerator.validate_asset_id(asset_id):
            raise InvalidAssetIDError(f"Invalid asset ID format: {asset_id}")
        
        # Remove 0x prefix if present
        if asset_id.startswith('0x'):
            asset_id = asset_id[2:]
        
        return bytes.fromhex(asset_id)
    
    @staticmethod
    def bytes_to_asset_id(asset_bytes: bytes) -> str:
        """
        Convert bytes to asset ID hex string.
        
        Args:
            asset_bytes: 32-byte array
            
        Returns:
            Asset ID hex string
            
        Raises:
            InvalidAssetIDError: If byte length is not 32
        """
        if len(asset_bytes) != 32:
            raise InvalidAssetIDError(f"Asset ID must be 32 bytes, got {len(asset_bytes)}")
        
        return asset_bytes.hex()
    
    @staticmethod
    def truncate_asset_id(asset_id: str, length: int = 8) -> str:
        """
        Truncate asset ID for display purposes.
        
        Args:
            asset_id: Full asset ID
            length: Number of characters to show from start and end
            
        Returns:
            Truncated asset ID with ellipsis
        """
        if not AssetIDGenerator.validate_asset_id(asset_id):
            return "invalid"
        
        if len(asset_id) <= length * 2:
            return asset_id
        
        return f"{asset_id[:length]}...{asset_id[-length:]}"


class AssetIDValidator:
    """Advanced asset ID validation with test vectors and security checks."""
    
    # Test vectors for validation
    VALID_TEST_VECTORS = [
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
    ]
    
    INVALID_TEST_VECTORS = [
        "",  # Empty
        "123",  # Too short
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefg",  # Invalid hex
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",  # Too long
        "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcde",  # 63 chars
        None,  # None type
        123,  # Integer type
    ]
    
    @classmethod
    def run_test_vectors(cls) -> Dict[str, bool]:
        """
        Run validation test vectors.
        
        Returns:
            Dict with test results
        """
        results = {
            'valid_tests_passed': 0,
            'valid_tests_failed': 0,
            'invalid_tests_passed': 0,
            'invalid_tests_failed': 0,
            'all_passed': True
        }
        
        # Test valid vectors
        for test_id in cls.VALID_TEST_VECTORS:
            if AssetIDGenerator.validate_asset_id(test_id):
                results['valid_tests_passed'] += 1
            else:
                results['valid_tests_failed'] += 1
                results['all_passed'] = False
        
        # Test invalid vectors
        for test_id in cls.INVALID_TEST_VECTORS:
            if not AssetIDGenerator.validate_asset_id(test_id):
                results['invalid_tests_passed'] += 1
            else:
                results['invalid_tests_failed'] += 1
                results['all_passed'] = False
        
        return results
    
    @staticmethod
    def check_entropy(asset_id: str) -> Dict[str, Union[bool, float]]:
        """
        Check entropy and randomness of asset ID.
        
        Args:
            asset_id: Asset ID to check
            
        Returns:
            Dict with entropy analysis results
        """
        if not AssetIDGenerator.validate_asset_id(asset_id):
            raise InvalidAssetIDError(f"Invalid asset ID: {asset_id}")
        
        # Remove 0x prefix if present
        if asset_id.startswith('0x'):
            asset_id = asset_id[2:]
        
        # Convert to bytes for analysis
        asset_bytes = bytes.fromhex(asset_id)
        
        # Count unique bytes
        unique_bytes = len(set(asset_bytes))
        
        # Calculate byte frequency
        byte_counts = {}
        for byte in asset_bytes:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy (simplified)
        entropy = 0.0
        for count in byte_counts.values():
            p = count / len(asset_bytes)
            if p > 0:
                entropy -= p * (p.bit_length() - 1)  # Approximate log2
        
        # Check for patterns
        has_repeating_bytes = any(count > 4 for count in byte_counts.values())
        has_sequential = False
        for i in range(len(asset_bytes) - 3):
            if (asset_bytes[i] + 1 == asset_bytes[i + 1] and
                asset_bytes[i + 1] + 1 == asset_bytes[i + 2] and
                asset_bytes[i + 2] + 1 == asset_bytes[i + 3]):
                has_sequential = True
                break
        
        return {
            'unique_bytes': unique_bytes,
            'max_unique_bytes': 256,
            'entropy_score': entropy,
            'has_repeating_pattern': has_repeating_bytes,
            'has_sequential_pattern': has_sequential,
            'appears_random': (
                unique_bytes > 16 and
                not has_repeating_bytes and
                not has_sequential and
                entropy > 4.0
            )
        }
    
    @staticmethod
    def validate_security_requirements(asset_id: str) -> Dict[str, bool]:
        """
        Validate asset ID meets security requirements.
        
        Args:
            asset_id: Asset ID to validate
            
        Returns:
            Dict with security validation results
        """
        results = {
            'format_valid': False,
            'not_zero': False,
            'not_max': False,
            'sufficient_entropy': False,
            'no_obvious_patterns': False,
            'all_checks_passed': False
        }
        
        try:
            # Basic format validation
            results['format_valid'] = AssetIDGenerator.validate_asset_id(asset_id)
            
            if not results['format_valid']:
                return results
            
            # Convert to bytes for analysis
            asset_bytes = AssetIDGenerator.asset_id_to_bytes(asset_id)
            
            # Check not all zeros
            results['not_zero'] = not all(b == 0 for b in asset_bytes)
            
            # Check not all ones (max value)
            results['not_max'] = not all(b == 255 for b in asset_bytes)
            
            # Check entropy
            entropy_info = AssetIDValidator.check_entropy(asset_id)
            results['sufficient_entropy'] = entropy_info['appears_random']
            results['no_obvious_patterns'] = (
                not entropy_info['has_repeating_pattern'] and
                not entropy_info['has_sequential_pattern']
            )
            
            # All checks must pass
            results['all_checks_passed'] = all([
                results['format_valid'],
                results['not_zero'],
                results['not_max'],
                results['sufficient_entropy'],
                results['no_obvious_patterns']
            ])
            
        except Exception:
            # Any exception means validation failed
            pass
        
        return results