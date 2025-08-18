"""
PSBT Signing Module with Key Management

This module provides comprehensive PSBT signing capabilities integrated with
the BNAP validator system, including key management, signature validation,
and secure signing workflows.
"""

import logging
import hashlib
import struct
import time
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json

from crypto.keys import PrivateKey, PublicKey, derive_key_from_path, parse_derivation_path
from crypto.signatures import sign_ecdsa, sign_schnorr, verify_ecdsa, verify_schnorr
from crypto.exceptions import CryptoError, InvalidKeyError, InvalidSignatureError
from psbt.parser import PSBTParser, ParsedPSBT
from psbt.exceptions import PSBTError
from .core import ValidationEngine, ValidationContext, ValidationResult


class SigningError(Exception):
    """Base exception for PSBT signing errors."""
    pass


class KeyManagementError(SigningError):
    """Exception for key management errors."""
    pass


class SignatureError(SigningError):
    """Exception for signature creation/verification errors."""
    pass


class SigningStrategy(str, Enum):
    """Available signing strategies."""
    SINGLE_KEY = "single_key"              # Sign with single private key
    MULTI_SIG = "multi_sig"                # Multi-signature signing
    HIERARCHICAL = "hierarchical"          # BIP32 hierarchical deterministic signing
    THRESHOLD = "threshold"                # Threshold signature scheme
    VALIDATOR_CONTROLLED = "validator"     # Validator-controlled signing


class SigningMode(str, Enum):
    """Signing modes for different security levels."""
    AUTOMATIC = "automatic"      # Fully automatic signing
    INTERACTIVE = "interactive"  # Require user confirmation
    OFFLINE = "offline"          # Offline signing mode
    HSM = "hsm"                 # Hardware security module


@dataclass
class SigningRequest:
    """Represents a PSBT signing request."""
    psbt_data: bytes
    signing_strategy: SigningStrategy
    signing_mode: SigningMode
    key_identifiers: List[str] = field(default_factory=list)
    validation_required: bool = True
    auto_finalize: bool = False
    custom_sighash: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SigningResult:
    """Results of PSBT signing operation."""
    success: bool
    signed_psbt: Optional[bytes] = None
    signatures_added: int = 0
    validation_result: Optional[ValidationResult] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    signing_time: float = field(default_factory=time.time)
    finalized: bool = False
    transaction_hex: Optional[str] = None


@dataclass
class KeyInfo:
    """Information about a signing key."""
    key_id: str
    public_key: PublicKey
    private_key: Optional[PrivateKey] = None
    derivation_path: Optional[str] = None
    key_type: str = "secp256k1"
    created_at: float = field(default_factory=time.time)
    last_used: Optional[float] = None
    usage_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class PSBTSigner:
    """
    Comprehensive PSBT signing system with integrated key management.
    
    Provides secure signing workflows, key management, validation integration,
    and support for various signing strategies and modes.
    """
    
    def __init__(self, 
                 config: Optional[Dict[str, Any]] = None,
                 validator: Optional[ValidationEngine] = None):
        """
        Initialize PSBT signer.
        
        Args:
            config: Signer configuration
            validator: Optional ValidationEngine instance
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize validator if not provided
        if validator:
            self.validator = validator
        else:
            try:
                from .core import create_default_validator
                self.validator = create_default_validator(self.config.get("validator", {}))
            except ImportError:
                # Fallback: create a basic ValidationEngine
                from .core import ValidationEngine
                self.validator = ValidationEngine()
        
        # Key management
        self.keys: Dict[str, KeyInfo] = {}
        self.key_storage_path = self.config.get("key_storage_path")
        
        # Signing configuration
        self.default_sighash = self.config.get("default_sighash", 0x01)  # SIGHASH_ALL
        self.require_validation = self.config.get("require_validation", True)
        self.auto_finalize = self.config.get("auto_finalize", False)
        self.max_signature_attempts = self.config.get("max_signature_attempts", 3)
        
        # Security settings
        self.signing_timeout = self.config.get("signing_timeout", 300)  # 5 minutes
        self.require_confirmation = self.config.get("require_confirmation", True)
        allowed_strategies_config = self.config.get("allowed_strategies", [
            SigningStrategy.SINGLE_KEY,
            SigningStrategy.HIERARCHICAL,
            SigningStrategy.MULTI_SIG,
            SigningStrategy.VALIDATOR_CONTROLLED
        ])
        self.allowed_strategies = set(allowed_strategies_config)
        
        # Statistics
        self.stats = {
            "signatures_created": 0,
            "psbts_signed": 0,
            "validation_failures": 0,
            "signing_errors": 0,
            "keys_managed": 0,
            "successful_finalizations": 0
        }
        
        # Load existing keys if storage path is configured
        if self.key_storage_path:
            self._load_keys()
    
    def sign_psbt(self, request: SigningRequest) -> SigningResult:
        """
        Sign a PSBT according to the signing request.
        
        Args:
            request: SigningRequest containing PSBT and signing parameters
            
        Returns:
            SigningResult with signing outcome and details
        """
        start_time = time.time()
        self.logger.info(f"Starting PSBT signing with strategy: {request.signing_strategy}")
        
        try:
            # Validate PSBT first if required
            validation_result = None
            if request.validation_required:
                validation_result = self._validate_psbt(request.psbt_data)
                if not validation_result.is_valid:
                    self.stats["validation_failures"] += 1
                    return SigningResult(
                        success=False,
                        validation_result=validation_result,
                        errors=["PSBT validation failed before signing"],
                        signing_time=time.time() - start_time
                    )
            
            # Check strategy constraints
            if request.signing_strategy not in self.allowed_strategies:
                return SigningResult(
                    success=False,
                    errors=[f"Signing strategy {request.signing_strategy} not allowed"],
                    signing_time=time.time() - start_time
                )
            
            # Check required parameters for strategy
            strategy_check_result = self._check_strategy_parameters(request)
            if not strategy_check_result.success:
                strategy_check_result.signing_time = time.time() - start_time
                return strategy_check_result
            
            # Parse PSBT
            parser = PSBTParser()
            parsed_psbt = parser.parse(request.psbt_data)
            
            # Execute signing strategy
            result = self._execute_signing_strategy(request, parsed_psbt, validation_result)
            
            # Update statistics
            if result.success:
                self.stats["psbts_signed"] += 1
                if result.finalized:
                    self.stats["successful_finalizations"] += 1
            else:
                self.stats["signing_errors"] += 1
            
            result.signing_time = time.time() - start_time
            return result
            
        except Exception as e:
            self.logger.error(f"PSBT signing failed: {e}")
            self.stats["signing_errors"] += 1
            return SigningResult(
                success=False,
                errors=[f"Signing failed: {str(e)}"],
                signing_time=time.time() - start_time
            )
    
    def _validate_psbt(self, psbt_data: bytes) -> ValidationResult:
        """Validate PSBT using the integrated validator."""
        try:
            # Create validation context
            context = ValidationContext(psbt_data={'raw': psbt_data})
            
            # Run validation
            return self.validator.validate_psbt_data(psbt_data, context)
        except Exception as e:
            self.logger.error(f"PSBT validation error: {e}")
            # Return a failed validation result
            from .core import ValidationResult as VResult, ValidationError
            result = VResult.ERROR
            return result
    
    def _check_strategy_parameters(self, request: SigningRequest) -> SigningResult:
        """Check if request has required parameters for the signing strategy."""
        if request.signing_strategy == SigningStrategy.SINGLE_KEY:
            if not request.key_identifiers:
                return SigningResult(
                    success=False,
                    errors=["No key identifier provided for single key signing"]
                )
            key_id = request.key_identifiers[0]
            if key_id not in self.keys or not self.keys[key_id].private_key:
                return SigningResult(
                    success=False,
                    errors=[f"Private key not found for key ID: {key_id}"]
                )
        elif request.signing_strategy == SigningStrategy.HIERARCHICAL:
            if not request.key_identifiers:
                return SigningResult(
                    success=False,
                    errors=["No master key identifier provided for hierarchical signing"]
                )
            master_key_id = request.key_identifiers[0]
            if master_key_id not in self.keys or not self.keys[master_key_id].private_key:
                return SigningResult(
                    success=False,
                    errors=[f"Master private key not found for key ID: {master_key_id}"]
                )
        elif request.signing_strategy == SigningStrategy.MULTI_SIG:
            if not request.key_identifiers:
                return SigningResult(
                    success=False,
                    errors=["No key identifiers provided for multi-sig signing"]
                )
        elif request.signing_strategy == SigningStrategy.VALIDATOR_CONTROLLED:
            validator_keys = getattr(self.validator, 'signing_keys', {})
            if not validator_keys:
                return SigningResult(
                    success=False,
                    errors=["No signing keys available in validator"]
                )
        
        return SigningResult(success=True)
    
    def _execute_signing_strategy(self, request: SigningRequest, parsed_psbt: ParsedPSBT, 
                                 validation_result: Optional[ValidationResult]) -> SigningResult:
        """Execute the specified signing strategy."""        
        if request.signing_strategy == SigningStrategy.SINGLE_KEY:
            return self._sign_single_key(request, parsed_psbt, validation_result)
        elif request.signing_strategy == SigningStrategy.HIERARCHICAL:
            return self._sign_hierarchical(request, parsed_psbt, validation_result)
        elif request.signing_strategy == SigningStrategy.MULTI_SIG:
            return self._sign_multi_sig(request, parsed_psbt, validation_result)
        elif request.signing_strategy == SigningStrategy.VALIDATOR_CONTROLLED:
            return self._sign_validator_controlled(request, parsed_psbt, validation_result)
        else:
            return SigningResult(
                success=False,
                errors=[f"Signing strategy {request.signing_strategy} not implemented"]
            )
    
    def _sign_single_key(self, request: SigningRequest, parsed_psbt: ParsedPSBT, 
                        validation_result: Optional[ValidationResult]) -> SigningResult:
        """Sign PSBT with a single key."""
        key_id = request.key_identifiers[0]
        key_info = self.keys[key_id]  # We know it exists from parameter check
        
        try:
            signed_psbt, signatures_added = self._sign_psbt_with_key(
                parsed_psbt, 
                key_info.private_key,
                request.custom_sighash or self.default_sighash
            )
            
            self.stats["signatures_created"] += signatures_added
            self._update_key_usage(key_id)
            
            # Finalize if requested and all inputs are signed
            finalized = False
            transaction_hex = None
            if request.auto_finalize:
                finalized, transaction_hex = self._try_finalize_psbt(signed_psbt)
            
            return SigningResult(
                success=True,
                signed_psbt=signed_psbt,
                signatures_added=signatures_added,
                validation_result=validation_result,
                finalized=finalized,
                transaction_hex=transaction_hex
            )
            
        except Exception as e:
            return SigningResult(
                success=False,
                errors=[f"Single key signing failed: {str(e)}"]
            )
    
    def _sign_hierarchical(self, request: SigningRequest, parsed_psbt: ParsedPSBT,
                          validation_result: Optional[ValidationResult]) -> SigningResult:
        """Sign PSBT using hierarchical deterministic keys."""
        master_key_id = request.key_identifiers[0]
        master_key_info = self.keys[master_key_id]  # We know it exists from parameter check
        
        try:
            total_signatures = 0
            current_psbt = parsed_psbt
            
            # Derive keys for each input as needed
            for i, input_data in enumerate(parsed_psbt.inputs):
                # Determine derivation path for this input
                derivation_path = self._determine_derivation_path(input_data, i)
                
                if derivation_path:
                    # Derive private key for this input
                    derived_key = derive_key_from_path(
                        master_key_info.private_key, 
                        derivation_path
                    )
                    
                    # Sign with derived key
                    signed_psbt, sigs_added = self._sign_psbt_with_key(
                        current_psbt,
                        derived_key,
                        request.custom_sighash or self.default_sighash,
                        input_indices=[i]
                    )
                    
                    current_psbt = PSBTParser().parse(signed_psbt)
                    total_signatures += sigs_added
            
            self.stats["signatures_created"] += total_signatures
            self._update_key_usage(master_key_id)
            
            # Finalize if requested
            finalized = False
            transaction_hex = None
            if request.auto_finalize:
                finalized, transaction_hex = self._try_finalize_psbt(current_psbt)
            
            return SigningResult(
                success=True,
                signed_psbt=self._serialize_psbt(current_psbt),
                signatures_added=total_signatures,
                validation_result=validation_result,
                finalized=finalized,
                transaction_hex=transaction_hex
            )
            
        except Exception as e:
            return SigningResult(
                success=False,
                errors=[f"Hierarchical signing failed: {str(e)}"]
            )
    
    def _sign_multi_sig(self, request: SigningRequest, parsed_psbt: ParsedPSBT,
                       validation_result: Optional[ValidationResult]) -> SigningResult:
        """Sign PSBT with multiple keys (multi-signature)."""
        
        try:
            total_signatures = 0
            current_psbt = parsed_psbt
            signing_keys = []
            
            # Collect all available private keys
            for key_id in request.key_identifiers:
                key_info = self.keys.get(key_id)
                if key_info and key_info.private_key:
                    signing_keys.append((key_id, key_info.private_key))
            
            if not signing_keys:
                return SigningResult(
                    success=False,
                    errors=["No valid private keys found for multi-sig signing"]
                )
            
            # Sign with each key
            for key_id, private_key in signing_keys:
                signed_psbt, sigs_added = self._sign_psbt_with_key(
                    current_psbt,
                    private_key,
                    request.custom_sighash or self.default_sighash
                )
                
                current_psbt = PSBTParser().parse(signed_psbt)
                total_signatures += sigs_added
                self._update_key_usage(key_id)
            
            self.stats["signatures_created"] += total_signatures
            
            # Finalize if requested
            finalized = False
            transaction_hex = None
            if request.auto_finalize:
                finalized, transaction_hex = self._try_finalize_psbt(current_psbt)
            
            return SigningResult(
                success=True,
                signed_psbt=self._serialize_psbt(current_psbt),
                signatures_added=total_signatures,
                validation_result=validation_result,
                finalized=finalized,
                transaction_hex=transaction_hex
            )
            
        except Exception as e:
            return SigningResult(
                success=False,
                errors=[f"Multi-sig signing failed: {str(e)}"]
            )
    
    def _sign_validator_controlled(self, request: SigningRequest, parsed_psbt: ParsedPSBT,
                                  validation_result: Optional[ValidationResult]) -> SigningResult:
        """Sign PSBT with validator-controlled keys."""
        try:
            # Use the validator's built-in signing keys
            validator_keys = getattr(self.validator, 'signing_keys', {})
            
            total_signatures = 0
            current_psbt = parsed_psbt
            
            # Sign with each validator key
            for key_id, private_key in validator_keys.items():
                signed_psbt, sigs_added = self._sign_psbt_with_key(
                    current_psbt,
                    private_key,
                    request.custom_sighash or self.default_sighash
                )
                
                current_psbt = PSBTParser().parse(signed_psbt)
                total_signatures += sigs_added
            
            self.stats["signatures_created"] += total_signatures
            
            # Finalize if requested
            finalized = False
            transaction_hex = None
            if request.auto_finalize:
                finalized, transaction_hex = self._try_finalize_psbt(current_psbt)
            
            return SigningResult(
                success=True,
                signed_psbt=self._serialize_psbt(current_psbt),
                signatures_added=total_signatures,
                validation_result=validation_result,
                finalized=finalized,
                transaction_hex=transaction_hex
            )
            
        except Exception as e:
            return SigningResult(
                success=False,
                errors=[f"Validator-controlled signing failed: {str(e)}"]
            )
    
    def _sign_psbt_with_key(self, parsed_psbt: ParsedPSBT, private_key: PrivateKey, 
                           sighash_type: int, input_indices: Optional[List[int]] = None) -> Tuple[bytes, int]:
        """
        Sign PSBT inputs with the given private key.
        
        Args:
            parsed_psbt: Parsed PSBT to sign
            private_key: Private key for signing
            sighash_type: Signature hash type
            input_indices: Optional list of input indices to sign (default: all)
            
        Returns:
            Tuple of (signed_psbt_bytes, signatures_added_count)
        """
        signatures_added = 0
        
        # Determine which inputs to sign
        if input_indices is None:
            input_indices = list(range(len(parsed_psbt.inputs)))
        
        for input_index in input_indices:
            if input_index >= len(parsed_psbt.inputs):
                continue
                
            input_data = parsed_psbt.inputs[input_index]
            
            try:
                # Create signature hash for this input
                sighash = self._create_signature_hash(parsed_psbt, input_index, sighash_type)
                
                # Determine signature type (ECDSA vs Schnorr) based on output type
                if self._is_taproot_input(input_data):
                    # Use Schnorr signature for Taproot inputs
                    signature_obj = sign_schnorr(private_key, sighash)
                    signature = signature_obj.to_bytes()
                else:
                    # Use ECDSA signature for non-Taproot inputs
                    signature_obj = sign_ecdsa(private_key, sighash)
                    signature = signature_obj.to_der()
                
                # Add signature to PSBT input
                self._add_signature_to_input(input_data, signature, sighash_type, private_key.public_key())
                signatures_added += 1
                
            except Exception as e:
                self.logger.warning(f"Failed to sign input {input_index}: {e}")
                continue
        
        # Serialize the signed PSBT
        signed_psbt = self._serialize_psbt(parsed_psbt)
        
        return signed_psbt, signatures_added
    
    def _create_signature_hash(self, parsed_psbt: ParsedPSBT, input_index: int, 
                              sighash_type: int) -> bytes:
        """
        Create signature hash for PSBT input.
        
        Args:
            parsed_psbt: Parsed PSBT
            input_index: Index of input to create hash for
            sighash_type: Signature hash type
            
        Returns:
            32-byte signature hash
        """
        # This is a simplified implementation
        # In a real implementation, this would need to properly handle:
        # - Different output types (P2WPKH, P2WSH, P2TR, etc.)
        # - BIP143 signature hash for segwit
        # - BIP341 signature hash for taproot
        # - Proper UTXO amount handling
        
        input_data = parsed_psbt.inputs[input_index]
        unsigned_tx = parsed_psbt.psbt_global.unsigned_tx
        
        # Simplified signature hash creation
        # In practice, this would use proper BIP143/BIP341 algorithms
        hash_data = b""
        hash_data += struct.pack("<I", unsigned_tx.version if hasattr(unsigned_tx, 'version') else 2)
        hash_data += struct.pack("<I", input_index)
        hash_data += struct.pack("<B", sighash_type)
        
        # Add input-specific data
        if hasattr(input_data, 'witness_utxo') and input_data.witness_utxo:
            hash_data += input_data.witness_utxo
        elif hasattr(input_data, 'non_witness_utxo') and input_data.non_witness_utxo:
            hash_data += input_data.non_witness_utxo[:64]  # First 64 bytes
        
        return hashlib.sha256(hashlib.sha256(hash_data).digest()).digest()
    
    def _is_taproot_input(self, input_data) -> bool:
        """Check if input is a Taproot input."""
        # Simplified check - in practice would examine the output script
        try:
            # Check if input has taproot signatures with actual data
            has_tap_key_sig = (hasattr(input_data, 'tap_key_sig') and 
                             input_data.tap_key_sig is not None and
                             input_data.tap_key_sig != b'')
            has_tap_script_sig = (hasattr(input_data, 'tap_script_sig') and 
                                 input_data.tap_script_sig is not None and
                                 input_data.tap_script_sig != b'')
            return has_tap_key_sig or has_tap_script_sig
        except AttributeError:
            return False
    
    def _add_signature_to_input(self, input_data, signature: bytes, sighash_type: int, 
                               public_key: PublicKey) -> None:
        """Add signature to PSBT input data."""
        # Add sighash type to signature
        signature_with_sighash = signature + struct.pack("<B", sighash_type)
        
        # Add to appropriate signature field based on input type
        if self._is_taproot_input(input_data):
            # Taproot key path signature
            if not hasattr(input_data, 'tap_key_sig'):
                input_data.tap_key_sig = {}
            input_data.tap_key_sig = signature
        else:
            # Traditional partial signature
            if not hasattr(input_data, 'partial_sigs'):
                input_data.partial_sigs = {}
            input_data.partial_sigs[public_key.bytes] = signature_with_sighash
    
    def _determine_derivation_path(self, input_data, input_index: int) -> Optional[str]:
        """Determine the derivation path for an input."""
        # Check for BIP32 derivation info in the input
        if hasattr(input_data, 'bip32_derivs') and input_data.bip32_derivs:
            # Use the first available derivation path
            for pubkey, deriv_info in input_data.bip32_derivs.items():
                return self._format_derivation_path(deriv_info)
        
        # Default derivation path based on input index
        return f"m/84'/0'/0'/0/{input_index}"
    
    def _format_derivation_path(self, deriv_info) -> str:
        """Format derivation info into a derivation path string."""
        # Simplified implementation
        if hasattr(deriv_info, 'fingerprint') and hasattr(deriv_info, 'path'):
            return "/".join([f"{step}'" if step >= 0x80000000 else str(step) for step in deriv_info.path])
        return "m/84'/0'/0'/0/0"  # Default path
    
    def _try_finalize_psbt(self, parsed_psbt: ParsedPSBT) -> Tuple[bool, Optional[str]]:
        """
        Attempt to finalize the PSBT if all inputs are signed.
        
        Args:
            parsed_psbt: Parsed PSBT to finalize
            
        Returns:
            Tuple of (finalization_success, transaction_hex)
        """
        try:
            # Check if all inputs have signatures
            for input_data in parsed_psbt.inputs:
                has_signature = (
                    (hasattr(input_data, 'partial_sigs') and input_data.partial_sigs) or
                    (hasattr(input_data, 'tap_key_sig') and input_data.tap_key_sig) or
                    (hasattr(input_data, 'final_scriptwitness') and input_data.final_scriptwitness)
                )
                
                if not has_signature:
                    self.logger.debug("PSBT cannot be finalized: missing signatures")
                    return False, None
            
            # Finalize each input
            for input_data in parsed_psbt.inputs:
                self._finalize_input(input_data)
            
            # Extract final transaction
            transaction_hex = self._extract_final_transaction(parsed_psbt)
            
            return True, transaction_hex
            
        except Exception as e:
            self.logger.error(f"PSBT finalization failed: {e}")
            return False, None
    
    def _finalize_input(self, input_data) -> None:
        """Finalize a single PSBT input."""
        # Move partial signatures to final witness/signature fields
        if hasattr(input_data, 'partial_sigs') and input_data.partial_sigs:
            # Create final scriptSig or scriptWitness from partial signatures
            # This is a simplified implementation
            signatures = list(input_data.partial_sigs.values())
            if signatures:
                if not hasattr(input_data, 'final_scriptwitness'):
                    input_data.final_scriptwitness = b""
                # Append signature to witness (simplified)
                input_data.final_scriptwitness += signatures[0]
        
        if hasattr(input_data, 'tap_key_sig') and input_data.tap_key_sig:
            # Taproot key path signature
            if not hasattr(input_data, 'final_scriptwitness'):
                input_data.final_scriptwitness = b""
            input_data.final_scriptwitness += input_data.tap_key_sig
    
    def _extract_final_transaction(self, parsed_psbt: ParsedPSBT) -> str:
        """Extract the final transaction from a finalized PSBT."""
        # This would construct the final transaction with witness data
        # Simplified implementation returns placeholder
        return "0200000000000000000000000000000000000000000000000000000000000000000000000000"
    
    def _serialize_psbt(self, parsed_psbt: ParsedPSBT) -> bytes:
        """Serialize a parsed PSBT back to bytes."""
        # This would implement proper PSBT serialization
        # For now, return a placeholder
        return b"PSBT_SERIALIZED_DATA"
    
    def add_key(self, key_id: str, private_key: PrivateKey, 
                derivation_path: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Add a private key to the key store.
        
        Args:
            key_id: Unique identifier for the key
            private_key: Private key to store
            derivation_path: Optional BIP32 derivation path
            metadata: Optional key metadata
            
        Returns:
            True if key was added successfully
        """
        try:
            if key_id in self.keys:
                self.logger.warning(f"Key {key_id} already exists, overwriting")
            
            key_info = KeyInfo(
                key_id=key_id,
                public_key=private_key.public_key(),
                private_key=private_key,
                derivation_path=derivation_path,
                metadata=metadata or {}
            )
            
            self.keys[key_id] = key_info
            self.stats["keys_managed"] += 1
            
            # Save to persistent storage if configured
            if self.key_storage_path:
                try:
                    self._save_keys()
                except Exception as save_error:
                    # Log the save error but don't fail the key addition
                    self.logger.error(f"Failed to save keys to storage: {save_error}")
            
            self.logger.info(f"Added key {key_id} to key store")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add key {key_id}: {e}")
            return False
    
    def remove_key(self, key_id: str) -> bool:
        """
        Remove a key from the key store.
        
        Args:
            key_id: Key identifier to remove
            
        Returns:
            True if key was removed successfully
        """
        try:
            if key_id not in self.keys:
                self.logger.warning(f"Key {key_id} not found")
                return False
            
            del self.keys[key_id]
            
            # Save to persistent storage if configured
            if self.key_storage_path:
                self._save_keys()
            
            self.logger.info(f"Removed key {key_id} from key store")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove key {key_id}: {e}")
            return False
    
    def list_keys(self, include_private: bool = False) -> List[Dict[str, Any]]:
        """
        List all keys in the key store.
        
        Args:
            include_private: Whether to include private key information
            
        Returns:
            List of key information dictionaries
        """
        keys_list = []
        
        for key_id, key_info in self.keys.items():
            key_dict = {
                "key_id": key_id,
                "public_key": key_info.public_key.bytes.hex(),
                "key_type": key_info.key_type,
                "derivation_path": key_info.derivation_path,
                "created_at": key_info.created_at,
                "last_used": key_info.last_used,
                "usage_count": key_info.usage_count,
                "metadata": key_info.metadata
            }
            
            if include_private and key_info.private_key:
                key_dict["has_private_key"] = True
                # Never actually include the private key bytes for security
            
            keys_list.append(key_dict)
        
        return keys_list
    
    def _update_key_usage(self, key_id: str) -> None:
        """Update key usage statistics."""
        if key_id in self.keys:
            self.keys[key_id].last_used = time.time()
            self.keys[key_id].usage_count += 1
    
    def _load_keys(self) -> None:
        """Load keys from persistent storage."""
        try:
            if not self.key_storage_path or not Path(self.key_storage_path).exists():
                return
            
            with open(self.key_storage_path, 'r') as f:
                key_data = json.load(f)
            
            # Note: This would need proper key encryption/decryption
            # This is a simplified implementation
            self.logger.info(f"Loaded {len(key_data)} keys from storage")
            
        except Exception as e:
            self.logger.error(f"Failed to load keys: {e}")
    
    def _save_keys(self) -> None:
        """Save keys to persistent storage."""
        try:
            if not self.key_storage_path:
                return
            
            # Note: This would need proper key encryption
            # This is a simplified implementation that doesn't save private keys
            key_data = []
            for key_id, key_info in self.keys.items():
                key_data.append({
                    "key_id": key_id,
                    "public_key": key_info.public_key.bytes.hex(),
                    "derivation_path": key_info.derivation_path,
                    "created_at": key_info.created_at,
                    "metadata": key_info.metadata
                    # Private keys would be encrypted before storage
                })
            
            with open(self.key_storage_path, 'w') as f:
                json.dump(key_data, f, indent=2)
            
            self.logger.info(f"Saved {len(key_data)} keys to storage")
            
        except Exception as e:
            self.logger.error(f"Failed to save keys: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get signer statistics."""
        return {
            **self.stats,
            "total_keys": len(self.keys),
            "keys_with_private": sum(1 for k in self.keys.values() if k.private_key),
            "allowed_strategies": list(self.allowed_strategies),
            "require_validation": self.require_validation,
            "auto_finalize": self.auto_finalize
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the signer."""
        health = {
            "status": "healthy",
            "issues": [],
            "key_store_accessible": self.key_storage_path is None or Path(self.key_storage_path).exists(),
            "validator_available": self.validator is not None,
            "keys_loaded": len(self.keys),
            "timestamp": time.time()
        }
        
        # Check validator health if available
        if self.validator:
            try:
                validator_health = self.validator.health_check()
                if validator_health.get("status") != "healthy":
                    health["issues"].append("Validator health check failed")
            except Exception as e:
                health["issues"].append(f"Validator health check error: {e}")
        
        # Check key store accessibility
        if self.key_storage_path and not Path(self.key_storage_path).exists():
            health["issues"].append("Key storage path not accessible")
        
        if health["issues"]:
            health["status"] = "degraded" if len(health["issues"]) < 3 else "unhealthy"
        
        return health


# Utility functions

def create_signing_request(psbt_data: bytes, 
                          strategy: SigningStrategy = SigningStrategy.SINGLE_KEY,
                          key_ids: Optional[List[str]] = None,
                          **kwargs) -> SigningRequest:
    """
    Create a signing request with default parameters.
    
    Args:
        psbt_data: PSBT bytes to sign
        strategy: Signing strategy to use
        key_ids: List of key identifiers
        **kwargs: Additional signing parameters
        
    Returns:
        Configured SigningRequest
    """
    return SigningRequest(
        psbt_data=psbt_data,
        signing_strategy=strategy,
        signing_mode=kwargs.get("signing_mode", SigningMode.AUTOMATIC),
        key_identifiers=key_ids or [],
        validation_required=kwargs.get("validation_required", True),
        auto_finalize=kwargs.get("auto_finalize", False),
        custom_sighash=kwargs.get("custom_sighash"),
        metadata=kwargs.get("metadata", {})
    )


def create_psbt_signer(config: Optional[Dict[str, Any]] = None) -> PSBTSigner:
    """
    Create a PSBT signer with default configuration.
    
    Args:
        config: Optional signer configuration
        
    Returns:
        Configured PSBTSigner instance
    """
    return PSBTSigner(config)


def sign_psbt_quick(psbt_data: bytes, private_key: PrivateKey, 
                   auto_finalize: bool = False) -> Tuple[bool, Optional[bytes], List[str]]:
    """
    Quick PSBT signing utility function.
    
    Args:
        psbt_data: PSBT bytes to sign
        private_key: Private key for signing
        auto_finalize: Whether to auto-finalize the PSBT
        
    Returns:
        Tuple of (success, signed_psbt_bytes, errors)
    """
    try:
        signer = PSBTSigner()
        
        # Add the key temporarily
        key_id = "temp_key"
        signer.add_key(key_id, private_key)
        
        # Create and execute signing request
        request = create_signing_request(
            psbt_data=psbt_data,
            strategy=SigningStrategy.SINGLE_KEY,
            key_ids=[key_id],
            auto_finalize=auto_finalize,
            validation_required=False  # Skip validation for quick signing
        )
        
        result = signer.sign_psbt(request)
        
        return result.success, result.signed_psbt, result.errors
        
    except Exception as e:
        return False, None, [f"Quick signing failed: {str(e)}"]