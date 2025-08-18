"""
Tests for PSBT Signer Module

Tests the PSBTSigner functionality including signing strategies, key management,
validation integration, and various signing modes.
"""

import pytest
import json
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from validator.signer import (
    PSBTSigner,
    SigningRequest,
    SigningResult,
    KeyInfo,
    SigningStrategy,
    SigningMode,
    SigningError,
    KeyManagementError,
    SignatureError,
    create_signing_request,
    create_psbt_signer,
    sign_psbt_quick
)
from crypto.keys import PrivateKey, PublicKey
from psbt.parser import PSBTParser, ParsedPSBT
from validator.core import ValidationEngine


class TestSigningRequest:
    """Test SigningRequest data class."""
    
    def test_signing_request_creation(self):
        """Test basic signing request creation."""
        psbt_data = b"mock_psbt_data"
        request = SigningRequest(
            psbt_data=psbt_data,
            signing_strategy=SigningStrategy.SINGLE_KEY,
            signing_mode=SigningMode.AUTOMATIC
        )
        
        assert request.psbt_data == psbt_data
        assert request.signing_strategy == SigningStrategy.SINGLE_KEY
        assert request.signing_mode == SigningMode.AUTOMATIC
        assert request.key_identifiers == []
        assert request.validation_required is True
        assert request.auto_finalize is False
    
    def test_signing_request_with_keys(self):
        """Test signing request with key identifiers."""
        request = SigningRequest(
            psbt_data=b"test",
            signing_strategy=SigningStrategy.MULTI_SIG,
            signing_mode=SigningMode.INTERACTIVE,
            key_identifiers=["key1", "key2", "key3"],
            validation_required=False,
            auto_finalize=True
        )
        
        assert request.key_identifiers == ["key1", "key2", "key3"]
        assert request.validation_required is False
        assert request.auto_finalize is True


class TestKeyInfo:
    """Test KeyInfo data class."""
    
    def test_key_info_creation(self):
        """Test basic key info creation."""
        private_key = PrivateKey()
        public_key = private_key.public_key
        
        key_info = KeyInfo(
            key_id="test_key",
            public_key=public_key,
            private_key=private_key,
            derivation_path="m/84'/0'/0'/0/0"
        )
        
        assert key_info.key_id == "test_key"
        assert key_info.public_key == public_key
        assert key_info.private_key == private_key
        assert key_info.derivation_path == "m/84'/0'/0'/0/0"
        assert key_info.usage_count == 0
        assert key_info.last_used is None
    
    def test_key_info_mark_used(self):
        """Test key usage tracking."""
        key_info = KeyInfo(
            key_id="test",
            public_key=PrivateKey().public_key
        )
        
        assert key_info.usage_count == 0
        assert key_info.last_used is None
        
        # Manually update usage (normally done by PSBTSigner)
        key_info.last_used = time.time()
        key_info.usage_count += 1
        
        assert key_info.usage_count == 1
        assert isinstance(key_info.last_used, float)


class TestPSBTSigner:
    """Test PSBTSigner functionality."""
    
    def test_signer_creation(self):
        """Test basic signer creation."""
        signer = PSBTSigner()
        
        assert signer.config == {}
        assert isinstance(signer.validator, ValidationEngine)
        assert signer.keys == {}
        assert signer.require_validation is True
        assert signer.auto_finalize is False
    
    def test_signer_with_config(self):
        """Test signer creation with custom configuration."""
        config = {
            "require_validation": False,
            "auto_finalize": True,
            "default_sighash": 0x02,
            "max_signature_attempts": 5,
            "allowed_strategies": [SigningStrategy.SINGLE_KEY]
        }
        
        signer = PSBTSigner(config=config)
        
        assert signer.require_validation is False
        assert signer.auto_finalize is True
        assert signer.default_sighash == 0x02
        assert signer.max_signature_attempts == 5
        assert SigningStrategy.SINGLE_KEY in signer.allowed_strategies
    
    def test_signer_with_validator(self):
        """Test signer creation with custom validator."""
        mock_validator = Mock(spec=ValidationEngine)
        signer = PSBTSigner(validator=mock_validator)
        
        assert signer.validator == mock_validator
    
    def test_add_key(self):
        """Test adding keys to the key store."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        
        success = signer.add_key("test_key", private_key, "m/84'/0'/0'/0/0")
        
        assert success is True
        assert "test_key" in signer.keys
        assert signer.keys["test_key"].private_key == private_key
        assert signer.keys["test_key"].derivation_path == "m/84'/0'/0'/0/0"
        assert signer.stats["keys_managed"] == 1
    
    def test_add_duplicate_key(self):
        """Test adding duplicate key overwrites existing."""
        signer = PSBTSigner()
        private_key1 = PrivateKey()
        private_key2 = PrivateKey()
        
        signer.add_key("test_key", private_key1)
        signer.add_key("test_key", private_key2)  # Should overwrite
        
        assert signer.keys["test_key"].private_key == private_key2
        assert signer.stats["keys_managed"] == 2  # Both additions counted
    
    def test_remove_key(self):
        """Test removing keys from the key store."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        
        signer.add_key("test_key", private_key)
        assert "test_key" in signer.keys
        
        success = signer.remove_key("test_key")
        
        assert success is True
        assert "test_key" not in signer.keys
    
    def test_remove_nonexistent_key(self):
        """Test removing non-existent key."""
        signer = PSBTSigner()
        
        success = signer.remove_key("nonexistent")
        
        assert success is False
    
    def test_list_keys(self):
        """Test listing keys in the key store."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        
        signer.add_key("test_key", private_key, "m/84'/0'/0'/0/0", {"purpose": "testing"})
        
        keys_list = signer.list_keys()
        
        assert len(keys_list) == 1
        key_info = keys_list[0]
        assert key_info["key_id"] == "test_key"
        assert key_info["derivation_path"] == "m/84'/0'/0'/0/0"
        assert key_info["metadata"] == {"purpose": "testing"}
        assert "has_private_key" not in key_info  # Not included by default
    
    def test_list_keys_with_private(self):
        """Test listing keys including private key flag."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        
        signer.add_key("test_key", private_key)
        
        keys_list = signer.list_keys(include_private=True)
        
        assert len(keys_list) == 1
        assert keys_list[0]["has_private_key"] is True
    
    def test_statistics(self):
        """Test signer statistics."""
        signer = PSBTSigner()
        
        stats = signer.get_statistics()
        
        expected_keys = [
            "signatures_created",
            "psbts_signed", 
            "validation_failures",
            "signing_errors",
            "keys_managed",
            "successful_finalizations",
            "total_keys",
            "keys_with_private",
            "allowed_strategies",
            "require_validation",
            "auto_finalize"
        ]
        
        for key in expected_keys:
            assert key in stats
        
        assert stats["total_keys"] == 0
        assert stats["keys_with_private"] == 0
    
    def test_health_check(self):
        """Test signer health check."""
        signer = PSBTSigner()
        
        health = signer.health_check()
        
        assert "status" in health
        assert "issues" in health
        assert "validator_available" in health
        assert "keys_loaded" in health
        assert "timestamp" in health
        
        assert health["validator_available"] is True
        assert health["keys_loaded"] == 0
        assert isinstance(health["timestamp"], float)
    
    @patch('validator.signer.PSBTParser')
    def test_sign_psbt_validation_failure(self, mock_parser):
        """Test signing with validation failure."""
        signer = PSBTSigner()
        
        # Mock validator to return invalid result
        mock_validation_result = Mock()
        mock_validation_result.is_valid = False
        signer.validator.validate_psbt_data = Mock(return_value=mock_validation_result)
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.SINGLE_KEY,
            signing_mode=SigningMode.AUTOMATIC,
            validation_required=True
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is False
        assert "PSBT validation failed" in result.errors[0]
        assert signer.stats["validation_failures"] == 1
    
    @patch('validator.signer.PSBTParser')
    def test_sign_psbt_single_key_success(self, mock_parser):
        """Test successful single key signing."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        signer.add_key("test_key", private_key)
        
        # Mock PSBT parsing
        mock_parsed_psbt = Mock(spec=ParsedPSBT)
        mock_parsed_psbt.inputs = [Mock()]  # One input
        mock_parser.return_value.parse.return_value = mock_parsed_psbt
        
        # Mock validation success
        mock_validation_result = Mock()
        mock_validation_result.is_valid = True
        signer.validator.validate_psbt_data = Mock(return_value=mock_validation_result)
        
        # Mock signing methods
        signer._sign_psbt_with_key = Mock(return_value=(b"signed_psbt", 1))
        signer._try_finalize_psbt = Mock(return_value=(False, None))
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.SINGLE_KEY,
            signing_mode=SigningMode.AUTOMATIC,
            key_identifiers=["test_key"],
            validation_required=True
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is True
        assert result.signatures_added == 1
        assert result.signed_psbt == b"signed_psbt"
        assert signer.stats["psbts_signed"] == 1
        assert signer.stats["signatures_created"] == 1
    
    def test_sign_psbt_single_key_no_key(self):
        """Test single key signing without providing key ID."""
        signer = PSBTSigner()
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.SINGLE_KEY,
            signing_mode=SigningMode.AUTOMATIC,
            validation_required=False
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is False
        assert "No key identifier provided" in result.errors[0]
    
    def test_sign_psbt_single_key_key_not_found(self):
        """Test single key signing with non-existent key."""
        signer = PSBTSigner()
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.SINGLE_KEY,
            signing_mode=SigningMode.AUTOMATIC,
            key_identifiers=["nonexistent"],
            validation_required=False
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is False
        assert "Private key not found for key ID: nonexistent" in result.errors[0]
    
    def test_sign_psbt_disallowed_strategy(self):
        """Test signing with disallowed strategy."""
        config = {"allowed_strategies": [SigningStrategy.SINGLE_KEY]}
        signer = PSBTSigner(config=config)
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.MULTI_SIG,
            signing_mode=SigningMode.AUTOMATIC,
            validation_required=False
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is False
        assert "not allowed" in result.errors[0]
    
    @patch('validator.signer.PSBTParser')
    def test_sign_psbt_multi_sig(self, mock_parser):
        """Test multi-signature signing."""
        signer = PSBTSigner()
        private_key1 = PrivateKey()
        private_key2 = PrivateKey()
        signer.add_key("key1", private_key1)
        signer.add_key("key2", private_key2)
        
        # Mock PSBT parsing
        mock_parsed_psbt = Mock(spec=ParsedPSBT)
        mock_parsed_psbt.inputs = [Mock()]
        mock_parser.return_value.parse.return_value = mock_parsed_psbt
        
        # Mock signing methods
        signer._sign_psbt_with_key = Mock(return_value=(b"signed_psbt", 1))
        signer._try_finalize_psbt = Mock(return_value=(False, None))
        signer._serialize_psbt = Mock(return_value=b"final_psbt")
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.MULTI_SIG,
            signing_mode=SigningMode.AUTOMATIC,
            key_identifiers=["key1", "key2"],
            validation_required=False
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is True
        assert signer._sign_psbt_with_key.call_count == 2  # Called for each key
        assert signer.stats["signatures_created"] == 2
    
    @patch('validator.signer.PSBTParser')
    def test_sign_psbt_hierarchical(self, mock_parser):
        """Test hierarchical deterministic signing."""
        signer = PSBTSigner()
        master_key = PrivateKey()
        signer.add_key("master", master_key)
        
        # Mock PSBT parsing
        mock_parsed_psbt = Mock(spec=ParsedPSBT)
        mock_input = Mock()
        mock_input.bip32_derivs = {}  # No derivation info
        mock_parsed_psbt.inputs = [mock_input]
        mock_parser.return_value.parse.return_value = mock_parsed_psbt
        
        # Mock derivation and signing
        with patch('validator.signer.derive_key_from_path') as mock_derive:
            derived_key = PrivateKey()
            mock_derive.return_value = derived_key
            
            signer._sign_psbt_with_key = Mock(return_value=(b"signed_psbt", 1))
            signer._serialize_psbt = Mock(return_value=b"final_psbt")
            signer._try_finalize_psbt = Mock(return_value=(False, None))
            
            request = SigningRequest(
                psbt_data=b"test_psbt",
                signing_strategy=SigningStrategy.HIERARCHICAL,
                signing_mode=SigningMode.AUTOMATIC,
                key_identifiers=["master"],
                validation_required=False
            )
            
            result = signer.sign_psbt(request)
            
            assert result.success is True
            mock_derive.assert_called_once()
    
    @patch('validator.signer.PSBTParser') 
    def test_sign_psbt_validator_controlled(self, mock_parser):
        """Test validator-controlled signing."""
        signer = PSBTSigner()
        
        # Mock validator with signing keys
        mock_validator = Mock()
        mock_validator.signing_keys = {"validator_key": PrivateKey()}
        signer.validator = mock_validator
        
        # Mock PSBT parsing
        mock_parsed_psbt = Mock(spec=ParsedPSBT)
        mock_parsed_psbt.inputs = [Mock()]
        mock_parser.return_value.parse.return_value = mock_parsed_psbt
        
        # Mock signing methods
        signer._sign_psbt_with_key = Mock(return_value=(b"signed_psbt", 1))
        signer._serialize_psbt = Mock(return_value=b"final_psbt")
        signer._try_finalize_psbt = Mock(return_value=(False, None))
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.VALIDATOR_CONTROLLED,
            signing_mode=SigningMode.AUTOMATIC,
            validation_required=False
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is True
        assert signer._sign_psbt_with_key.call_count == 1
    
    def test_sign_psbt_validator_controlled_no_keys(self):
        """Test validator-controlled signing with no available keys."""
        signer = PSBTSigner()
        
        # Mock validator without signing keys
        mock_validator = Mock()
        mock_validator.signing_keys = {}
        signer.validator = mock_validator
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.VALIDATOR_CONTROLLED,
            signing_mode=SigningMode.AUTOMATIC,
            validation_required=False
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is False
        assert "No signing keys available in validator" in result.errors[0]
    
    def test_create_signature_hash(self):
        """Test signature hash creation."""
        signer = PSBTSigner()
        
        # Mock parsed PSBT
        mock_psbt = Mock(spec=ParsedPSBT)
        mock_global = Mock()
        mock_global.unsigned_tx = Mock()
        mock_global.unsigned_tx.version = 2
        mock_psbt.psbt_global = mock_global
        
        mock_input = Mock()
        mock_input.witness_utxo = b"witness_utxo_data"
        mock_psbt.inputs = [mock_input]
        
        sighash = signer._create_signature_hash(mock_psbt, 0, 0x01)
        
        assert isinstance(sighash, bytes)
        assert len(sighash) == 32  # SHA256 hash length
    
    def test_is_taproot_input(self):
        """Test Taproot input detection."""
        signer = PSBTSigner()
        
        # Mock Taproot input
        taproot_input = Mock()
        taproot_input.tap_key_sig = b"signature"
        
        # Mock non-Taproot input
        regular_input = Mock()
        regular_input.tap_key_sig = None
        regular_input.tap_script_sig = None
        
        assert signer._is_taproot_input(taproot_input) is True
        assert signer._is_taproot_input(regular_input) is False
    
    def test_determine_derivation_path(self):
        """Test derivation path determination."""
        signer = PSBTSigner()
        
        # Mock input with BIP32 derivation info
        input_with_deriv = Mock()
        input_with_deriv.bip32_derivs = {
            b"pubkey": Mock(fingerprint=b"fing", path=[0x80000054, 0x80000000, 0x80000000, 0, 5])
        }
        
        # Mock input without derivation info
        input_without_deriv = Mock()
        input_without_deriv.bip32_derivs = {}
        
        # Test with derivation info
        path1 = signer._determine_derivation_path(input_with_deriv, 0)
        assert path1 is not None
        
        # Test without derivation info (should use default)
        path2 = signer._determine_derivation_path(input_without_deriv, 5)
        assert path2 == "m/84'/0'/0'/0/5"
    
    @patch('validator.signer.Path')
    def test_key_storage_loading(self, mock_path):
        """Test key storage loading."""
        # Mock file existence and content
        mock_path.return_value.exists.return_value = True
        
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = '[]'
            
            signer = PSBTSigner(config={"key_storage_path": "/test/keys.json"})
            
            # Should attempt to load keys
            assert signer.key_storage_path == "/test/keys.json"
    
    def test_key_storage_saving(self):
        """Test key storage saving."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
            storage_path = tmp_file.name
        
        signer = PSBTSigner(config={"key_storage_path": storage_path})
        private_key = PrivateKey()
        
        # Add a key and save
        signer.add_key("test_key", private_key, metadata={"test": True})
        
        # Verify file was created and contains key data
        assert Path(storage_path).exists()
        
        with open(storage_path, 'r') as f:
            saved_data = json.load(f)
        
        assert len(saved_data) == 1
        assert saved_data[0]["key_id"] == "test_key"
        assert saved_data[0]["metadata"] == {"test": True}
        
        # Clean up
        Path(storage_path).unlink()


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_create_signing_request(self):
        """Test signing request creation utility."""
        psbt_data = b"test_psbt"
        request = create_signing_request(
            psbt_data=psbt_data,
            strategy=SigningStrategy.MULTI_SIG,
            key_ids=["key1", "key2"],
            validation_required=False,
            auto_finalize=True
        )
        
        assert isinstance(request, SigningRequest)
        assert request.psbt_data == psbt_data
        assert request.signing_strategy == SigningStrategy.MULTI_SIG
        assert request.key_identifiers == ["key1", "key2"]
        assert request.validation_required is False
        assert request.auto_finalize is True
    
    def test_create_psbt_signer(self):
        """Test PSBT signer creation utility."""
        config = {"require_validation": False}
        signer = create_psbt_signer(config)
        
        assert isinstance(signer, PSBTSigner)
        assert signer.require_validation is False
    
    @patch('validator.signer.PSBTSigner')
    def test_sign_psbt_quick(self, mock_signer_class):
        """Test quick PSBT signing utility."""
        mock_signer = Mock()
        mock_signer.add_key.return_value = True
        
        mock_result = Mock()
        mock_result.success = True
        mock_result.signed_psbt = b"signed_psbt"
        mock_result.errors = []
        mock_signer.sign_psbt.return_value = mock_result
        
        mock_signer_class.return_value = mock_signer
        
        private_key = PrivateKey()
        success, signed_psbt, errors = sign_psbt_quick(
            b"test_psbt", 
            private_key,
            auto_finalize=True
        )
        
        assert success is True
        assert signed_psbt == b"signed_psbt"
        assert errors == []
        
        # Verify signer was configured correctly
        mock_signer.add_key.assert_called_once_with("temp_key", private_key)
        mock_signer.sign_psbt.assert_called_once()


class TestSigningStrategies:
    """Test different signing strategies in detail."""
    
    @patch('validator.signer.PSBTParser')
    def test_single_key_strategy_complete_flow(self, mock_parser):
        """Test complete single key signing flow."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        signer.add_key("test_key", private_key)
        
        # Mock PSBT structure
        mock_input = Mock()
        mock_input.witness_utxo = b"utxo_data"
        mock_input.partial_sigs = {}
        mock_input.tap_key_sig = None
        mock_input.tap_script_sig = None
        
        mock_parsed_psbt = Mock(spec=ParsedPSBT)
        mock_parsed_psbt.inputs = [mock_input]
        mock_parsed_psbt.psbt_global = Mock()
        mock_parsed_psbt.psbt_global.unsigned_tx = Mock(version=2)
        
        mock_parser.return_value.parse.return_value = mock_parsed_psbt
        
        # Mock signing components
        with patch('validator.signer.sign_ecdsa') as mock_sign:
            # Create a mock signature object with to_der method
            mock_signature = Mock()
            mock_signature.to_der.return_value = b"signature_data"
            mock_sign.return_value = mock_signature
            
            signer._serialize_psbt = Mock(return_value=b"signed_psbt")
            signer._try_finalize_psbt = Mock(return_value=(True, "tx_hex"))
            
            request = SigningRequest(
                psbt_data=b"test_psbt",
                signing_strategy=SigningStrategy.SINGLE_KEY,
                signing_mode=SigningMode.AUTOMATIC,
                key_identifiers=["test_key"],
                validation_required=False,
                auto_finalize=True
            )
            
            result = signer.sign_psbt(request)
            
            assert result.success is True
            assert result.finalized is True
            assert result.transaction_hex == "tx_hex"
            mock_sign.assert_called()
    
    def test_multi_sig_strategy_key_collection(self):
        """Test multi-sig strategy key collection."""
        signer = PSBTSigner()
        
        # Add multiple keys, some without private keys
        key1 = PrivateKey()
        key2 = PrivateKey() 
        signer.add_key("key1", key1)
        signer.add_key("key2", key2)
        
        # Add key without private key (public only)
        public_only_key = KeyInfo("key3", PrivateKey().public_key)
        signer.keys["key3"] = public_only_key
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.MULTI_SIG,
            signing_mode=SigningMode.AUTOMATIC,
            key_identifiers=["key1", "key2", "key3"],  # key3 has no private key
            validation_required=False
        )
        
        # Mock dependencies
        with patch('validator.signer.PSBTParser') as mock_parser:
            mock_parsed_psbt = Mock(spec=ParsedPSBT)
            mock_parsed_psbt.inputs = [Mock()]
            mock_parser.return_value.parse.return_value = mock_parsed_psbt
            
            signer._sign_psbt_with_key = Mock(return_value=(b"signed", 1))
            signer._serialize_psbt = Mock(return_value=b"final")
            signer._try_finalize_psbt = Mock(return_value=(False, None))
            
            result = signer.sign_psbt(request)
            
            # Should succeed with 2 keys (key1 and key2), ignore key3
            assert result.success is True
            assert signer._sign_psbt_with_key.call_count == 2
    
    @patch('validator.signer.derive_key_from_path')
    @patch('validator.signer.PSBTParser')
    def test_hierarchical_strategy_derivation(self, mock_parser, mock_derive):
        """Test hierarchical strategy key derivation."""
        signer = PSBTSigner()
        master_key = PrivateKey()
        signer.add_key("master", master_key)
        
        # Mock inputs with different derivation paths
        mock_input1 = Mock()
        mock_input1.bip32_derivs = {
            b"pubkey1": Mock(fingerprint=b"abcd", path=[0x80000054, 0, 0, 0, 1])
        }
        
        mock_input2 = Mock()
        mock_input2.bip32_derivs = {}  # No derivation info
        
        mock_parsed_psbt = Mock(spec=ParsedPSBT)
        mock_parsed_psbt.inputs = [mock_input1, mock_input2]
        mock_parser.return_value.parse.return_value = mock_parsed_psbt
        
        # Mock derived keys
        derived_key1 = PrivateKey()
        derived_key2 = PrivateKey()
        mock_derive.side_effect = [derived_key1, derived_key2]
        
        # Mock other methods
        signer._sign_psbt_with_key = Mock(return_value=(b"signed", 1))
        signer._serialize_psbt = Mock(return_value=b"final")
        signer._try_finalize_psbt = Mock(return_value=(False, None))
        
        request = SigningRequest(
            psbt_data=b"test_psbt",
            signing_strategy=SigningStrategy.HIERARCHICAL,
            signing_mode=SigningMode.AUTOMATIC,
            key_identifiers=["master"],
            validation_required=False
        )
        
        result = signer.sign_psbt(request)
        
        assert result.success is True
        assert mock_derive.call_count == 2  # Called for each input
        assert signer._sign_psbt_with_key.call_count == 2


class TestSigningModes:
    """Test different signing modes."""
    
    def test_automatic_mode(self):
        """Test automatic signing mode."""
        signer = PSBTSigner()
        
        request = SigningRequest(
            psbt_data=b"test",
            signing_strategy=SigningStrategy.SINGLE_KEY,
            signing_mode=SigningMode.AUTOMATIC,
            validation_required=False
        )
        
        # Automatic mode should proceed without user interaction
        # This is the default behavior tested in other tests
        assert request.signing_mode == SigningMode.AUTOMATIC
    
    def test_interactive_mode_placeholder(self):
        """Test interactive signing mode (placeholder)."""
        signer = PSBTSigner()
        
        request = SigningRequest(
            psbt_data=b"test",
            signing_strategy=SigningStrategy.SINGLE_KEY, 
            signing_mode=SigningMode.INTERACTIVE
        )
        
        # Interactive mode would require user confirmation
        # This is a placeholder test - full implementation would need UI integration
        assert request.signing_mode == SigningMode.INTERACTIVE


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_signing_with_parser_error(self):
        """Test signing with PSBT parser error."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        signer.add_key("test_key", private_key)
        
        with patch('validator.signer.PSBTParser') as mock_parser:
            mock_parser.return_value.parse.side_effect = Exception("Parse error")
            
            request = SigningRequest(
                psbt_data=b"invalid_psbt",
                signing_strategy=SigningStrategy.SINGLE_KEY,
                signing_mode=SigningMode.AUTOMATIC,
                key_identifiers=["test_key"],
                validation_required=False
            )
            
            result = signer.sign_psbt(request)
            
            assert result.success is False
            assert "Parse error" in result.errors[0]
            assert signer.stats["signing_errors"] == 1
    
    def test_signing_with_signature_error(self):
        """Test signing with signature creation error."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        signer.add_key("test_key", private_key)
        
        with patch('validator.signer.PSBTParser') as mock_parser:
            mock_parsed_psbt = Mock(spec=ParsedPSBT)
            mock_parsed_psbt.inputs = [Mock()]
            mock_parser.return_value.parse.return_value = mock_parsed_psbt
            
            # Mock signing method to raise error
            signer._sign_psbt_with_key = Mock(side_effect=Exception("Signing error"))
            
            request = SigningRequest(
                psbt_data=b"test_psbt",
                signing_strategy=SigningStrategy.SINGLE_KEY,
                signing_mode=SigningMode.AUTOMATIC,
                key_identifiers=["test_key"],
                validation_required=False
            )
            
            result = signer.sign_psbt(request)
            
            assert result.success is False
            assert "Signing error" in result.errors[0]
    
    def test_add_key_error(self):
        """Test add key with error."""
        signer = PSBTSigner()
        
        # Mock to raise error during key addition
        with patch.object(signer, '_save_keys', side_effect=Exception("Save error")):
            signer.key_storage_path = "/test/path"
            
            # Should still succeed since save error is logged but not fatal
            result = signer.add_key("test", PrivateKey())
            assert result is True  # Key added despite save error
    
    def test_health_check_with_validator_error(self):
        """Test health check when validator health check fails."""
        signer = PSBTSigner()
        
        # Mock validator health check to raise error
        signer.validator.health_check = Mock(side_effect=Exception("Validator error"))
        
        health = signer.health_check()
        
        assert "Validator health check error" in health["issues"][0]
        assert health["status"] in ["degraded", "unhealthy"]


class TestIntegration:
    """Integration tests with other components."""
    
    def test_signer_with_real_validator(self):
        """Test signer integration with real ValidationEngine."""
        from validator.core import ValidationEngine
        
        validator = ValidationEngine()
        signer = PSBTSigner(validator=validator)
        
        assert signer.validator == validator
        assert isinstance(signer.validator, ValidationEngine)
    
    def test_signer_statistics_tracking(self):
        """Test that statistics are properly tracked across operations."""
        signer = PSBTSigner()
        private_key = PrivateKey()
        
        # Add some keys
        signer.add_key("key1", private_key)
        signer.add_key("key2", private_key)
        
        stats = signer.get_statistics()
        
        assert stats["keys_managed"] == 2
        assert stats["total_keys"] == 2
        assert stats["keys_with_private"] == 2
        
        # Remove a key
        signer.remove_key("key1")
        
        updated_stats = signer.get_statistics()
        assert updated_stats["total_keys"] == 1