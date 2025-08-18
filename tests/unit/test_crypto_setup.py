"""
Tests for Crypto Module Setup

Tests the basic structure and imports for the crypto module.
"""

import pytest
import crypto
from crypto.exceptions import (
    CryptoError,
    InvalidKeyError,
    InvalidSignatureError,
    DerivationError,
    CommitmentError,
)


class TestCryptoModuleSetup:
    """Test crypto module basic setup and structure."""
    
    def test_crypto_module_imports(self):
        """Test that crypto module can be imported."""
        assert crypto.__version__ == "0.1.0"
        
    def test_exception_hierarchy(self):
        """Test exception class hierarchy."""
        # Test base exception
        assert issubclass(CryptoError, Exception)
        
        # Test specific exceptions inherit from CryptoError
        assert issubclass(InvalidKeyError, CryptoError)
        assert issubclass(InvalidSignatureError, CryptoError)
        assert issubclass(DerivationError, CryptoError)
        assert issubclass(CommitmentError, CryptoError)
        
    def test_exception_instantiation(self):
        """Test that exceptions can be instantiated with messages."""
        error = CryptoError("Test error message")
        assert str(error) == "Test error message"
        
        key_error = InvalidKeyError("Invalid key format")
        assert str(key_error) == "Invalid key format"
        
    def test_module_structure_files_exist(self):
        """Test that all expected module files exist."""
        import os
        crypto_dir = os.path.dirname(crypto.__file__)
        
        expected_files = [
            '__init__.py',
            'exceptions.py',
            'keys.py',
            'commitments.py',
            'signatures.py',
            'musig2.py',
            'storage.py'
        ]
        
        for filename in expected_files:
            file_path = os.path.join(crypto_dir, filename)
            assert os.path.exists(file_path), f"Expected file {filename} not found"
            
    def test_dependencies_available(self):
        """Test that required dependencies are available."""
        import coincurve
        import mnemonic
        import hashlib
        import hmac
        import secrets
        
        # Test coincurve basic functionality
        from coincurve import PrivateKey as CoinCurvePrivateKey
        private_key = CoinCurvePrivateKey()
        assert private_key is not None
        
        # Test mnemonic basic functionality  
        from mnemonic import Mnemonic
        mnemo = Mnemonic("english")
        assert mnemo is not None