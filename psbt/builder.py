"""
Bitcoin Native Asset Protocol - PSBT Builder

This module provides classes for constructing Partially Signed Bitcoin Transactions (PSBTs)
for Bitcoin Native Asset Protocol operations. It implements BIP-174 PSBT format with
protocol-specific extensions for asset metadata.
"""

import base64
import hashlib
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union, Tuple, Any
from io import BytesIO

from bitcoinlib.encoding import to_bytes, varstr

from .utils import serialize_compact_size, double_sha256


@dataclass
class TransactionInput:
    """Simple input structure for PSBT transactions."""
    prev_txid: str
    output_n: int
    sequence: int = 0xfffffffe


@dataclass  
class TransactionOutput:
    """Simple output structure for PSBT transactions."""
    value: int
    script: bytes


class PSBTKeyType(Enum):
    """PSBT key types as defined in BIP-174."""
    
    # Global types
    PSBT_GLOBAL_UNSIGNED_TX = 0x00
    PSBT_GLOBAL_XPUB = 0x01
    PSBT_GLOBAL_VERSION = 0xfb
    PSBT_GLOBAL_PROPRIETARY = 0xfc
    
    # Input types
    PSBT_IN_NON_WITNESS_UTXO = 0x00
    PSBT_IN_WITNESS_UTXO = 0x01
    PSBT_IN_PARTIAL_SIG = 0x02
    PSBT_IN_SIGHASH_TYPE = 0x03
    PSBT_IN_REDEEM_SCRIPT = 0x04
    PSBT_IN_WITNESS_SCRIPT = 0x05
    PSBT_IN_BIP32_DERIVATION = 0x06
    PSBT_IN_FINAL_SCRIPTSIG = 0x07
    PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
    PSBT_IN_POR_COMMITMENT = 0x09
    PSBT_IN_PROPRIETARY = 0xfc
    
    # Output types
    PSBT_OUT_REDEEM_SCRIPT = 0x00
    PSBT_OUT_WITNESS_SCRIPT = 0x01
    PSBT_OUT_BIP32_DERIVATION = 0x02
    PSBT_OUT_PROPRIETARY = 0xfc


@dataclass
class PSBTKeyValue:
    """Represents a key-value pair in PSBT format."""
    key_type: int
    key_data: bytes = field(default_factory=bytes)
    value: bytes = field(default_factory=bytes)
    
    def serialize(self) -> bytes:
        """Serialize key-value pair to PSBT format."""
        key = bytes([self.key_type]) + self.key_data
        return varstr(key) + varstr(self.value)


@dataclass
class PSBTInput:
    """Represents a PSBT input with associated metadata."""
    non_witness_utxo: Optional[bytes] = None
    witness_utxo: Optional[bytes] = None
    partial_sigs: Dict[bytes, bytes] = field(default_factory=dict)
    sighash_type: Optional[int] = None
    redeem_script: Optional[bytes] = None
    witness_script: Optional[bytes] = None
    bip32_derivations: Dict[bytes, Tuple[bytes, List[int]]] = field(default_factory=dict)
    final_scriptsig: Optional[bytes] = None
    final_scriptwitness: Optional[List[bytes]] = None
    proprietary: Dict[bytes, bytes] = field(default_factory=dict)
    
    def serialize(self) -> bytes:
        """Serialize input to PSBT format."""
        result = BytesIO()
        
        if self.non_witness_utxo:
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_NON_WITNESS_UTXO.value, b'', self.non_witness_utxo)
            result.write(kv.serialize())
        
        if self.witness_utxo:
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_WITNESS_UTXO.value, b'', self.witness_utxo)
            result.write(kv.serialize())
        
        for pubkey, sig in self.partial_sigs.items():
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_PARTIAL_SIG.value, pubkey, sig)
            result.write(kv.serialize())
        
        if self.sighash_type is not None:
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_SIGHASH_TYPE.value, b'', 
                            struct.pack('<I', self.sighash_type))
            result.write(kv.serialize())
        
        if self.redeem_script:
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_REDEEM_SCRIPT.value, b'', self.redeem_script)
            result.write(kv.serialize())
        
        if self.witness_script:
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_WITNESS_SCRIPT.value, b'', self.witness_script)
            result.write(kv.serialize())
        
        for pubkey, (fingerprint, path) in self.bip32_derivations.items():
            path_bytes = b''.join(struct.pack('<I', p) for p in path)
            value = fingerprint + path_bytes
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_BIP32_DERIVATION.value, pubkey, value)
            result.write(kv.serialize())
        
        if self.final_scriptsig:
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_FINAL_SCRIPTSIG.value, b'', self.final_scriptsig)
            result.write(kv.serialize())
        
        if self.final_scriptwitness:
            witness_data = varstr(len(self.final_scriptwitness))
            for witness_elem in self.final_scriptwitness:
                witness_data += varstr(witness_elem)
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_FINAL_SCRIPTWITNESS.value, b'', witness_data)
            result.write(kv.serialize())
        
        for prop_key, prop_value in self.proprietary.items():
            kv = PSBTKeyValue(PSBTKeyType.PSBT_IN_PROPRIETARY.value, prop_key, prop_value)
            result.write(kv.serialize())
        
        # End marker
        result.write(b'\x00')
        return result.getvalue()


@dataclass
class PSBTOutput:
    """Represents a PSBT output with associated metadata."""
    redeem_script: Optional[bytes] = None
    witness_script: Optional[bytes] = None
    bip32_derivations: Dict[bytes, Tuple[bytes, List[int]]] = field(default_factory=dict)
    proprietary: Dict[bytes, bytes] = field(default_factory=dict)
    
    def serialize(self) -> bytes:
        """Serialize output to PSBT format."""
        result = BytesIO()
        
        if self.redeem_script:
            kv = PSBTKeyValue(PSBTKeyType.PSBT_OUT_REDEEM_SCRIPT.value, b'', self.redeem_script)
            result.write(kv.serialize())
        
        if self.witness_script:
            kv = PSBTKeyValue(PSBTKeyType.PSBT_OUT_WITNESS_SCRIPT.value, b'', self.witness_script)
            result.write(kv.serialize())
        
        for pubkey, (fingerprint, path) in self.bip32_derivations.items():
            path_bytes = b''.join(struct.pack('<I', p) for p in path)
            value = fingerprint + path_bytes
            kv = PSBTKeyValue(PSBTKeyType.PSBT_OUT_BIP32_DERIVATION.value, pubkey, value)
            result.write(kv.serialize())
        
        for prop_key, prop_value in self.proprietary.items():
            kv = PSBTKeyValue(PSBTKeyType.PSBT_OUT_PROPRIETARY.value, prop_key, prop_value)
            result.write(kv.serialize())
        
        # End marker
        result.write(b'\x00')
        return result.getvalue()


class BasePSBTBuilder:
    """
    Base class for constructing PSBTs according to BIP-174 specification.
    
    This class provides the foundational functionality for creating Partially Signed
    Bitcoin Transactions with proper structure, input/output management, and 
    serialization capabilities.
    """
    
    # Protocol-specific proprietary key prefixes
    BNAP_PROPRIETARY_PREFIX = b'BNAP'
    ASSET_ID_KEY = BNAP_PROPRIETARY_PREFIX + b'AID'
    ASSET_TYPE_KEY = BNAP_PROPRIETARY_PREFIX + b'ATY'
    MINT_AMOUNT_KEY = BNAP_PROPRIETARY_PREFIX + b'AMT'
    NFT_TOKEN_ID_KEY = BNAP_PROPRIETARY_PREFIX + b'TID'
    METADATA_HASH_KEY = BNAP_PROPRIETARY_PREFIX + b'MDH'
    
    def __init__(self, version: int = 2, locktime: int = 0):
        """
        Initialize PSBT builder.
        
        Args:
            version: Transaction version (default: 2)
            locktime: Transaction locktime (default: 0)
        """
        self.version = version
        self.locktime = locktime
        self.inputs: List[TransactionInput] = []
        self.outputs: List[TransactionOutput] = []
        self.psbt_inputs: List[PSBTInput] = []
        self.psbt_outputs: List[PSBTOutput] = []
        self.global_xpubs: Dict[bytes, Tuple[bytes, List[int]]] = {}
        self.global_proprietary: Dict[bytes, bytes] = {}
        
    def add_input(
        self,
        txid: str,
        vout: int,
        sequence: int = 0xfffffffe,
        witness_utxo: Optional[bytes] = None,
        non_witness_utxo: Optional[bytes] = None,
        redeem_script: Optional[bytes] = None,
        witness_script: Optional[bytes] = None
    ) -> None:
        """
        Add an input to the PSBT.
        
        Args:
            txid: Transaction ID of the UTXO to spend
            vout: Output index of the UTXO to spend
            sequence: Sequence number (default: 0xfffffffe for RBF)
            witness_utxo: Witness UTXO data for segwit inputs
            non_witness_utxo: Full previous transaction for non-segwit inputs
            redeem_script: Redeem script for P2SH inputs
            witness_script: Witness script for P2WSH inputs
        """
        # Add to transaction inputs
        input_obj = TransactionInput(prev_txid=txid, output_n=vout, sequence=sequence)
        self.inputs.append(input_obj)
        
        # Add PSBT input metadata
        psbt_input = PSBTInput(
            witness_utxo=witness_utxo,
            non_witness_utxo=non_witness_utxo,
            redeem_script=redeem_script,
            witness_script=witness_script
        )
        self.psbt_inputs.append(psbt_input)
    
    def add_output(
        self,
        address: Optional[str] = None,
        script: Optional[bytes] = None,
        amount: int = 0,
        redeem_script: Optional[bytes] = None,
        witness_script: Optional[bytes] = None
    ) -> None:
        """
        Add an output to the PSBT.
        
        Args:
            address: Destination address (mutually exclusive with script)
            script: Output script (mutually exclusive with address)
            amount: Amount in satoshis
            redeem_script: Redeem script for P2SH outputs
            witness_script: Witness script for P2WSH outputs
        """
        if address and script:
            raise ValueError("Cannot specify both address and script")
        if not address and not script:
            raise ValueError("Must specify either address or script")
        
        # Create output (simplified for now - just use script)
        if address:
            # For now, just create empty script - would need address-to-script conversion
            script = b''
        
        output_obj = TransactionOutput(value=amount, script=script)
        self.outputs.append(output_obj)
        
        # Add PSBT output metadata
        psbt_output = PSBTOutput(
            redeem_script=redeem_script,
            witness_script=witness_script
        )
        self.psbt_outputs.append(psbt_output)
    
    def add_global_xpub(
        self,
        xpub: bytes,
        fingerprint: bytes,
        derivation_path: List[int]
    ) -> None:
        """
        Add global extended public key to PSBT.
        
        Args:
            xpub: Extended public key
            fingerprint: Master key fingerprint
            derivation_path: BIP32 derivation path
        """
        self.global_xpubs[xpub] = (fingerprint, derivation_path)
    
    def add_global_proprietary(self, key: bytes, value: bytes) -> None:
        """
        Add global proprietary field to PSBT.
        
        Args:
            key: Proprietary key
            value: Proprietary value
        """
        self.global_proprietary[key] = value
    
    def add_input_proprietary(self, input_index: int, key: bytes, value: bytes) -> None:
        """
        Add proprietary field to specific input.
        
        Args:
            input_index: Index of the input
            key: Proprietary key
            value: Proprietary value
        """
        if input_index >= len(self.psbt_inputs):
            raise ValueError(f"Input index {input_index} out of range")
        
        self.psbt_inputs[input_index].proprietary[key] = value
    
    def add_output_proprietary(self, output_index: int, key: bytes, value: bytes) -> None:
        """
        Add proprietary field to specific output.
        
        Args:
            output_index: Index of the output
            key: Proprietary key
            value: Proprietary value
        """
        if output_index >= len(self.psbt_outputs):
            raise ValueError(f"Output index {output_index} out of range")
        
        self.psbt_outputs[output_index].proprietary[key] = value
    
    def set_sighash_type(self, input_index: int, sighash_type: int) -> None:
        """
        Set sighash type for specific input.
        
        Args:
            input_index: Index of the input
            sighash_type: Sighash type value
        """
        if input_index >= len(self.psbt_inputs):
            raise ValueError(f"Input index {input_index} out of range")
        
        self.psbt_inputs[input_index].sighash_type = sighash_type
    
    def _create_unsigned_transaction(self) -> bytes:
        """Create unsigned transaction data manually."""
        result = BytesIO()
        
        # Version (4 bytes, little endian)
        result.write(struct.pack('<I', self.version))
        
        # Input count (varint)
        result.write(serialize_compact_size(len(self.inputs)))
        
        # Inputs
        for input_obj in self.inputs:
            # Previous outpoint (32 + 4 bytes)
            txid_bytes = bytes.fromhex(input_obj.prev_txid)[::-1]  # Reverse for little endian
            result.write(txid_bytes)
            result.write(struct.pack('<I', input_obj.output_n))
            
            # Empty script (for unsigned transaction)
            result.write(b'\x00')
            
            # Sequence (4 bytes)
            result.write(struct.pack('<I', input_obj.sequence))
        
        # Output count (varint)
        result.write(serialize_compact_size(len(self.outputs)))
        
        # Outputs
        for output_obj in self.outputs:
            # Value (8 bytes, little endian)
            result.write(struct.pack('<Q', output_obj.value))
            
            # Script
            script_bytes = output_obj.script
            result.write(serialize_compact_size(len(script_bytes)))
            result.write(script_bytes)
        
        # Locktime (4 bytes)
        result.write(struct.pack('<I', self.locktime))
        
        return result.getvalue()
    
    def _serialize_global_data(self) -> bytes:
        """Serialize global PSBT data."""
        result = BytesIO()
        
        # Create unsigned transaction data manually
        unsigned_tx_data = self._create_unsigned_transaction()
        kv = PSBTKeyValue(PSBTKeyType.PSBT_GLOBAL_UNSIGNED_TX.value, b'', unsigned_tx_data)
        result.write(kv.serialize())
        
        # Global XPUBs
        for xpub, (fingerprint, path) in self.global_xpubs.items():
            path_bytes = b''.join(struct.pack('<I', p) for p in path)
            value = fingerprint + path_bytes
            kv = PSBTKeyValue(PSBTKeyType.PSBT_GLOBAL_XPUB.value, xpub, value)
            result.write(kv.serialize())
        
        # PSBT version
        kv = PSBTKeyValue(PSBTKeyType.PSBT_GLOBAL_VERSION.value, b'', struct.pack('<I', 0))
        result.write(kv.serialize())
        
        # Global proprietary fields
        for prop_key, prop_value in self.global_proprietary.items():
            kv = PSBTKeyValue(PSBTKeyType.PSBT_GLOBAL_PROPRIETARY.value, prop_key, prop_value)
            result.write(kv.serialize())
        
        # End marker
        result.write(b'\x00')
        return result.getvalue()
    
    def serialize(self) -> bytes:
        """
        Serialize PSBT to binary format.
        
        Returns:
            Serialized PSBT data
        """
        result = BytesIO()
        
        # PSBT magic bytes
        result.write(b'psbt\xff')
        
        # Global data
        result.write(self._serialize_global_data())
        
        # Input data
        for psbt_input in self.psbt_inputs:
            result.write(psbt_input.serialize())
        
        # Output data
        for psbt_output in self.psbt_outputs:
            result.write(psbt_output.serialize())
        
        return result.getvalue()
    
    def to_base64(self) -> str:
        """
        Serialize PSBT to base64 format.
        
        Returns:
            Base64-encoded PSBT string
        """
        return base64.b64encode(self.serialize()).decode('ascii')
    
    def get_transaction_id(self) -> str:
        """
        Get the transaction ID of the unsigned transaction.
        
        Returns:
            Transaction ID as hex string
        """
        unsigned_tx_data = self._create_unsigned_transaction()
        tx_hash = double_sha256(unsigned_tx_data)
        # Reverse bytes for display (big endian)
        return tx_hash[::-1].hex()
    
    def get_fee_info(self, input_amounts: List[int]) -> Dict[str, int]:
        """
        Calculate fee information for the transaction.
        
        Args:
            input_amounts: List of input amounts in satoshis
            
        Returns:
            Dictionary with fee information
        """
        total_input = sum(input_amounts)
        total_output = sum(output.value for output in self.outputs)
        fee = total_input - total_output
        
        return {
            'total_input': total_input,
            'total_output': total_output,
            'fee': fee,
            'fee_rate': fee / len(self.serialize()) if len(self.serialize()) > 0 else 0
        }
    
    def validate_structure(self) -> List[str]:
        """
        Validate PSBT structure and return list of issues.
        
        Returns:
            List of validation issues (empty if valid)
        """
        issues = []
        
        if not self.inputs:
            issues.append("PSBT must have at least one input")
        
        if not self.outputs:
            issues.append("PSBT must have at least one output")
        
        if len(self.inputs) != len(self.psbt_inputs):
            issues.append("Number of inputs must match number of PSBT input records")
        
        if len(self.outputs) != len(self.psbt_outputs):
            issues.append("Number of outputs must match number of PSBT output records")
        
        # Validate input UTXOs
        for i, psbt_input in enumerate(self.psbt_inputs):
            if not psbt_input.witness_utxo and not psbt_input.non_witness_utxo:
                issues.append(f"Input {i} must have either witness_utxo or non_witness_utxo")
        
        return issues


class FungibleMintBuilder(BasePSBTBuilder):
    """Builder for fungible token mint transactions."""
    
    def __init__(self, version: int = 2, locktime: int = 0):
        """Initialize fungible mint builder (legacy compatibility)."""
        super().__init__(version, locktime)
        
    def create_mint_psbt(self, asset_id: str, mint_amount: int, **kwargs):
        """Create mint PSBT (legacy method - use FungibleMintPSBTBuilder instead)."""
        from .fungible_mint import FungibleMintPSBTBuilder
        builder = FungibleMintPSBTBuilder(self.version, self.locktime)
        return builder


class NFTMintBuilder(BasePSBTBuilder):
    """Builder for NFT mint transactions."""
    
    def __init__(self, version: int = 2, locktime: int = 0):
        """Initialize NFT mint builder (legacy compatibility)."""
        super().__init__(version, locktime)
        
    def create_mint_psbt(self, collection_id: str, token_id: int, **kwargs):
        """Create mint PSBT (legacy method - use NFTMintPSBTBuilder instead)."""
        from .nft_mint import NFTMintPSBTBuilder
        builder = NFTMintPSBTBuilder(self.version, self.locktime)
        return builder


class TransferBuilder(BasePSBTBuilder):
    """Builder for asset transfer transactions."""
    pass