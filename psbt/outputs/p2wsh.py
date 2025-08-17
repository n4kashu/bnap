"""
Bitcoin Native Asset Protocol - P2WSH Output Construction Module

This module provides specialized functions and classes for creating P2WSH outputs
with covenant scripts for asset validation and control within the Bitcoin Native
Asset Protocol.
"""

import hashlib
import struct
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

from ..utils import (
    calculate_witness_script_hash,
    create_p2wsh_script,
    serialize_compact_size,
    double_sha256
)
from ..exceptions import (
    PSBTConstructionError,
    InvalidScriptError,
    UnsupportedScriptTypeError
)


class ScriptType(Enum):
    """Types of witness scripts for P2WSH outputs."""
    VALIDATOR = "validator"
    MULTISIG = "multisig"
    TIMELOCK = "timelock"
    COVENANT = "covenant"
    HTLC = "htlc"


@dataclass
class ScriptTemplate:
    """Template for generating witness scripts."""
    script_type: ScriptType
    required_sigs: int = 1
    total_keys: int = 1
    timelock: Optional[int] = None
    hash_lock: Optional[bytes] = None
    covenant_rules: Optional[Dict[str, any]] = None


class WitnessScriptBuilder:
    """
    Builder for creating witness scripts used in P2WSH outputs.
    
    This class provides methods to construct various types of witness scripts
    including simple validators, multisig, timelock, and covenant scripts.
    """
    
    # Bitcoin script opcodes
    OP_0 = 0x00
    OP_1 = 0x51
    OP_2 = 0x52
    OP_3 = 0x53
    OP_DUP = 0x76
    OP_HASH160 = 0xa9
    OP_EQUALVERIFY = 0x88
    OP_EQUAL = 0x87
    OP_CHECKSIG = 0xac
    OP_CHECKMULTISIG = 0xae
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_DROP = 0x75
    OP_BOOLAND = 0x9a
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    
    def __init__(self):
        """Initialize witness script builder."""
        self.script_stack: List[bytes] = []
        
    def reset(self) -> None:
        """Reset the script builder to start a new script."""
        self.script_stack.clear()
        
    def push_data(self, data: bytes) -> 'WitnessScriptBuilder':
        """
        Push data onto the script stack with proper opcode.
        
        Args:
            data: Data to push
            
        Returns:
            Self for method chaining
        """
        if len(data) == 0:
            self.script_stack.append(bytes([self.OP_0]))
        elif len(data) == 1 and 1 <= data[0] <= 16:
            # Use OP_1 through OP_16 for small numbers
            self.script_stack.append(bytes([self.OP_1 + data[0] - 1]))
        elif len(data) <= 75:
            # Direct push
            self.script_stack.append(bytes([len(data)]) + data)
        elif len(data) <= 255:
            # OP_PUSHDATA1
            self.script_stack.append(bytes([self.OP_PUSHDATA1, len(data)]) + data)
        elif len(data) <= 65535:
            # OP_PUSHDATA2
            self.script_stack.append(bytes([self.OP_PUSHDATA2]) + struct.pack('<H', len(data)) + data)
        else:
            # OP_PUSHDATA4
            self.script_stack.append(bytes([self.OP_PUSHDATA4]) + struct.pack('<I', len(data)) + data)
        
        return self
        
    def push_opcode(self, opcode: int) -> 'WitnessScriptBuilder':
        """
        Push an opcode onto the script stack.
        
        Args:
            opcode: Bitcoin script opcode
            
        Returns:
            Self for method chaining
        """
        self.script_stack.append(bytes([opcode]))
        return self
        
    def push_number(self, number: int) -> 'WitnessScriptBuilder':
        """
        Push a number onto the script stack using minimal encoding.
        
        Args:
            number: Number to push
            
        Returns:
            Self for method chaining
        """
        if number == 0:
            return self.push_opcode(self.OP_0)
        elif 1 <= number <= 16:
            return self.push_opcode(self.OP_1 + number - 1)
        else:
            # Encode as little-endian bytes
            data = self._encode_number(number)
            return self.push_data(data)
    
    def _encode_number(self, number: int) -> bytes:
        """Encode number in Bitcoin script format."""
        if number == 0:
            return b''
        
        negative = number < 0
        if negative:
            number = -number
        
        # Convert to bytes
        result = []
        while number > 0:
            result.append(number & 0xff)
            number >>= 8
        
        # Add sign bit if needed
        if result[-1] & 0x80:
            result.append(0x80 if negative else 0x00)
        elif negative:
            result[-1] |= 0x80
        
        return bytes(result)
        
    def build(self) -> bytes:
        """
        Build the final witness script.
        
        Returns:
            Complete witness script bytes
        """
        return b''.join(self.script_stack)
        
    def create_validator_script(self, validator_pubkey: bytes) -> bytes:
        """
        Create simple validator script: <PubKey> OP_CHECKSIG
        
        Args:
            validator_pubkey: 33-byte compressed public key
            
        Returns:
            Witness script bytes
        """
        if len(validator_pubkey) != 33:
            raise InvalidScriptError(f"Invalid public key length: {len(validator_pubkey)}")
        
        self.reset()
        self.push_data(validator_pubkey)
        self.push_opcode(self.OP_CHECKSIG)
        return self.build()
        
    def create_multisig_script(
        self, 
        required_sigs: int, 
        public_keys: List[bytes]
    ) -> bytes:
        """
        Create multisig script: M <PubKey1> <PubKey2> ... <PubKeyN> N OP_CHECKMULTISIG
        
        Args:
            required_sigs: Number of required signatures (M)
            public_keys: List of public keys
            
        Returns:
            Witness script bytes
        """
        if required_sigs < 1 or required_sigs > len(public_keys):
            raise InvalidScriptError("Invalid required signatures count")
        
        if len(public_keys) > 15:
            raise InvalidScriptError("Too many public keys for multisig")
        
        for pubkey in public_keys:
            if len(pubkey) != 33:
                raise InvalidScriptError(f"Invalid public key length: {len(pubkey)}")
        
        self.reset()
        self.push_number(required_sigs)
        
        for pubkey in public_keys:
            self.push_data(pubkey)
        
        self.push_number(len(public_keys))
        self.push_opcode(self.OP_CHECKMULTISIG)
        return self.build()
        
    def create_timelock_script(
        self, 
        validator_pubkey: bytes, 
        locktime: int, 
        use_sequence: bool = False
    ) -> bytes:
        """
        Create timelock script with validator.
        
        Args:
            validator_pubkey: Validator public key
            locktime: Lock time value
            use_sequence: Use OP_CHECKSEQUENCEVERIFY instead of OP_CHECKLOCKTIMEVERIFY
            
        Returns:
            Witness script bytes
        """
        if len(validator_pubkey) != 33:
            raise InvalidScriptError(f"Invalid public key length: {len(validator_pubkey)}")
        
        self.reset()
        self.push_number(locktime)
        
        if use_sequence:
            self.push_opcode(self.OP_CHECKSEQUENCEVERIFY)
        else:
            self.push_opcode(self.OP_CHECKLOCKTIMEVERIFY)
        
        self.push_opcode(self.OP_DROP)
        self.push_data(validator_pubkey)
        self.push_opcode(self.OP_CHECKSIG)
        return self.build()
        
    def create_hash_timelock_script(
        self,
        hash_lock: bytes,
        validator_pubkey: bytes,
        timeout: int
    ) -> bytes:
        """
        Create Hash Time Locked Contract (HTLC) script.
        
        Args:
            hash_lock: SHA256 hash for the secret
            validator_pubkey: Validator public key
            timeout: Timeout block height
            
        Returns:
            Witness script bytes
        """
        if len(hash_lock) != 32:
            raise InvalidScriptError(f"Invalid hash length: {len(hash_lock)}")
        
        if len(validator_pubkey) != 33:
            raise InvalidScriptError(f"Invalid public key length: {len(validator_pubkey)}")
        
        self.reset()
        
        # Hash branch: OP_SHA256 <hash> OP_EQUAL OP_IF <pubkey> OP_CHECKSIG OP_ELSE <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG OP_ENDIF
        self.push_opcode(0xa8)  # OP_SHA256
        self.push_data(hash_lock)
        self.push_opcode(self.OP_EQUAL)
        self.push_opcode(0x63)  # OP_IF
        self.push_data(validator_pubkey)
        self.push_opcode(self.OP_CHECKSIG)
        self.push_opcode(0x67)  # OP_ELSE
        self.push_number(timeout)
        self.push_opcode(self.OP_CHECKLOCKTIMEVERIFY)
        self.push_opcode(self.OP_DROP)
        self.push_data(validator_pubkey)
        self.push_opcode(self.OP_CHECKSIG)
        self.push_opcode(0x68)  # OP_ENDIF
        
        return self.build()


class CovenantScriptBuilder:
    """
    Builder for creating covenant scripts with asset validation rules.
    
    Covenant scripts enforce specific spending conditions and can validate
    asset transfers, supply limits, and other protocol rules.
    """
    
    def __init__(self):
        """Initialize covenant script builder."""
        self.script_builder = WitnessScriptBuilder()
        
    def create_asset_commitment_script(
        self,
        asset_id: str,
        validator_pubkey: bytes,
        max_supply: Optional[int] = None,
        transfer_rules: Optional[Dict[str, any]] = None
    ) -> bytes:
        """
        Create covenant script for asset commitment validation.
        
        Args:
            asset_id: Asset identifier as hex string
            validator_pubkey: Validator public key
            max_supply: Maximum supply limit (optional)
            transfer_rules: Additional transfer validation rules
            
        Returns:
            Covenant witness script bytes
        """
        if len(validator_pubkey) != 33:
            raise InvalidScriptError(f"Invalid public key length: {len(validator_pubkey)}")
        
        try:
            asset_id_bytes = bytes.fromhex(asset_id)
            if len(asset_id_bytes) != 32:
                raise InvalidScriptError(f"Invalid asset ID length: {len(asset_id_bytes)}")
        except ValueError:
            raise InvalidScriptError(f"Invalid asset ID format: {asset_id}")
        
        self.script_builder.reset()
        
        # Validator signature check
        self.script_builder.push_data(validator_pubkey)
        self.script_builder.push_opcode(self.script_builder.OP_CHECKSIG)
        
        # Asset ID verification
        self.script_builder.push_data(asset_id_bytes)
        self.script_builder.push_opcode(self.script_builder.OP_EQUAL)
        
        # Combine conditions with OP_BOOLAND
        self.script_builder.push_opcode(self.script_builder.OP_BOOLAND)
        
        # Add supply limit check if specified
        if max_supply is not None:
            self.script_builder.push_number(max_supply)
            self.script_builder.push_opcode(0xa4)  # OP_LESSTHANOREQUAL
            self.script_builder.push_opcode(self.script_builder.OP_BOOLAND)
        
        return self.script_builder.build()
        
    def create_multisig_covenant_script(
        self,
        required_sigs: int,
        public_keys: List[bytes],
        asset_id: str,
        validation_rules: Optional[Dict[str, any]] = None
    ) -> bytes:
        """
        Create multisig covenant script with asset validation.
        
        Args:
            required_sigs: Number of required signatures
            public_keys: List of validator public keys
            asset_id: Asset identifier
            validation_rules: Additional validation rules
            
        Returns:
            Covenant witness script bytes
        """
        if required_sigs < 1 or required_sigs > len(public_keys):
            raise InvalidScriptError("Invalid required signatures count")
        
        try:
            asset_id_bytes = bytes.fromhex(asset_id)
            if len(asset_id_bytes) != 32:
                raise InvalidScriptError(f"Invalid asset ID length: {len(asset_id_bytes)}")
        except ValueError:
            raise InvalidScriptError(f"Invalid asset ID format: {asset_id}")
        
        self.script_builder.reset()
        
        # Create multisig portion
        self.script_builder.push_number(required_sigs)
        for pubkey in public_keys:
            if len(pubkey) != 33:
                raise InvalidScriptError(f"Invalid public key length: {len(pubkey)}")
            self.script_builder.push_data(pubkey)
        
        self.script_builder.push_number(len(public_keys))
        self.script_builder.push_opcode(self.script_builder.OP_CHECKMULTISIG)
        
        # Asset ID verification
        self.script_builder.push_data(asset_id_bytes)
        self.script_builder.push_opcode(self.script_builder.OP_EQUAL)
        
        # Combine conditions
        self.script_builder.push_opcode(self.script_builder.OP_BOOLAND)
        
        return self.script_builder.build()


class P2WSHBuilder:
    """
    Builder for creating P2WSH outputs and managing witness scripts in PSBTs.
    
    This class provides high-level functionality for creating P2WSH outputs
    with proper witness script handling and PSBT integration.
    """
    
    def __init__(self):
        """Initialize P2WSH builder."""
        self.witness_script_builder = WitnessScriptBuilder()
        self.covenant_script_builder = CovenantScriptBuilder()
        
    def create_p2wsh_output(
        self, 
        witness_script: bytes, 
        amount: int = 0
    ) -> Tuple[bytes, bytes]:
        """
        Create P2WSH output script and witness script hash.
        
        Args:
            witness_script: Witness script bytes
            amount: Output amount in satoshis
            
        Returns:
            Tuple of (p2wsh_script, script_hash)
        """
        if not witness_script:
            raise InvalidScriptError("Witness script cannot be empty")
        
        script_hash = calculate_witness_script_hash(witness_script)
        p2wsh_script = create_p2wsh_script(witness_script)
        
        return p2wsh_script, script_hash
        
    def create_validator_output(
        self,
        validator_pubkey: bytes,
        amount: int = 0
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Create P2WSH output with simple validator script.
        
        Args:
            validator_pubkey: 33-byte compressed public key
            amount: Output amount in satoshis
            
        Returns:
            Tuple of (p2wsh_script, witness_script, script_hash)
        """
        witness_script = self.witness_script_builder.create_validator_script(validator_pubkey)
        p2wsh_script, script_hash = self.create_p2wsh_output(witness_script, amount)
        
        return p2wsh_script, witness_script, script_hash
        
    def create_multisig_output(
        self,
        required_sigs: int,
        public_keys: List[bytes],
        amount: int = 0
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Create P2WSH output with multisig script.
        
        Args:
            required_sigs: Number of required signatures
            public_keys: List of public keys
            amount: Output amount in satoshis
            
        Returns:
            Tuple of (p2wsh_script, witness_script, script_hash)
        """
        witness_script = self.witness_script_builder.create_multisig_script(
            required_sigs, public_keys
        )
        p2wsh_script, script_hash = self.create_p2wsh_output(witness_script, amount)
        
        return p2wsh_script, witness_script, script_hash
        
    def create_covenant_output(
        self,
        asset_id: str,
        validator_pubkey: bytes,
        amount: int = 0,
        max_supply: Optional[int] = None,
        validation_rules: Optional[Dict[str, any]] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Create P2WSH output with covenant script for asset validation.
        
        Args:
            asset_id: Asset identifier
            validator_pubkey: Validator public key
            amount: Output amount in satoshis
            max_supply: Maximum supply limit
            validation_rules: Additional validation rules
            
        Returns:
            Tuple of (p2wsh_script, witness_script, script_hash)
        """
        witness_script = self.covenant_script_builder.create_asset_commitment_script(
            asset_id, validator_pubkey, max_supply, validation_rules
        )
        p2wsh_script, script_hash = self.create_p2wsh_output(witness_script, amount)
        
        return p2wsh_script, witness_script, script_hash
        
    def create_htlc_output(
        self,
        hash_lock: bytes,
        validator_pubkey: bytes,
        timeout: int,
        amount: int = 0
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Create P2WSH output with Hash Time Locked Contract.
        
        Args:
            hash_lock: SHA256 hash for the secret
            validator_pubkey: Validator public key
            timeout: Timeout block height
            amount: Output amount in satoshis
            
        Returns:
            Tuple of (p2wsh_script, witness_script, script_hash)
        """
        witness_script = self.witness_script_builder.create_hash_timelock_script(
            hash_lock, validator_pubkey, timeout
        )
        p2wsh_script, script_hash = self.create_p2wsh_output(witness_script, amount)
        
        return p2wsh_script, witness_script, script_hash


# Utility functions for easy access
def create_p2wsh_output(witness_script: bytes, amount: int = 0) -> Tuple[bytes, bytes]:
    """
    Create P2WSH output script from witness script.
    
    Args:
        witness_script: Witness script bytes
        amount: Output amount in satoshis
        
    Returns:
        Tuple of (p2wsh_script, script_hash)
    """
    builder = P2WSHBuilder()
    return builder.create_p2wsh_output(witness_script, amount)


def create_validator_script(validator_pubkey: bytes) -> bytes:
    """
    Create simple validator witness script.
    
    Args:
        validator_pubkey: 33-byte compressed public key
        
    Returns:
        Witness script bytes
    """
    builder = WitnessScriptBuilder()
    return builder.create_validator_script(validator_pubkey)


def create_multisig_script(required_sigs: int, public_keys: List[bytes]) -> bytes:
    """
    Create multisig witness script.
    
    Args:
        required_sigs: Number of required signatures
        public_keys: List of public keys
        
    Returns:
        Witness script bytes
    """
    builder = WitnessScriptBuilder()
    return builder.create_multisig_script(required_sigs, public_keys)


def create_asset_commitment_script(
    asset_id: str,
    validator_pubkey: bytes,
    max_supply: Optional[int] = None
) -> bytes:
    """
    Create covenant script for asset commitment validation.
    
    Args:
        asset_id: Asset identifier as hex string
        validator_pubkey: Validator public key
        max_supply: Maximum supply limit
        
    Returns:
        Covenant witness script bytes
    """
    builder = CovenantScriptBuilder()
    return builder.create_asset_commitment_script(asset_id, validator_pubkey, max_supply)


def validate_witness_script(script: bytes) -> bool:
    """
    Validate witness script format and structure.
    
    Args:
        script: Witness script to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not script:
        return False
    
    # Basic validation - check for valid opcodes and structure
    try:
        # Must be non-empty and reasonable size
        if len(script) > 10000:  # Max script size
            return False
        
        # Check for common invalid patterns
        if script.startswith(bytes([0xff])):  # Invalid opcode
            return False
        
        return True
    except Exception:
        return False


def calculate_script_hash(script: bytes) -> bytes:
    """
    Calculate SHA256 hash of script for P2WSH.
    
    Args:
        script: Script bytes to hash
        
    Returns:
        SHA256 hash of script
    """
    return hashlib.sha256(script).digest()