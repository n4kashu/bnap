"""
Bitcoin Native Asset Protocol - PSBT Parser with Metadata Extraction

This module provides functionality to parse PSBT files, extract BNAP metadata,
validate structure against BIP-174, and reconstruct asset operation details.
"""

import base64
import struct
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from io import BytesIO

from bitcoinlib.transactions import Transaction, Input, Output
from bitcoinlib.encoding import varstr

from .utils import (
    parse_compact_size,
    parse_key_value,
    parse_outpoint,
    extract_op_return_data,
    double_sha256,
    decode_bip32_path
)
from .outputs.op_return import (
    OpReturnDecoder,
    MetadataType,
    parse_op_return_metadata
)
from .exceptions import (
    PSBTParsingError,
    PSBTValidationError,
    MetadataError
)


# PSBT Magic Bytes
PSBT_MAGIC = b'psbt'
PSBT_SEPARATOR = b'\xff'

# PSBT Global Types (BIP-174)
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_XPUB = 0x01
PSBT_GLOBAL_VERSION = 0xfb
PSBT_GLOBAL_PROPRIETARY = 0xfc

# PSBT Input Types
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
PSBT_IN_RIPEMD160 = 0x0a
PSBT_IN_SHA256 = 0x0b
PSBT_IN_HASH160 = 0x0c
PSBT_IN_HASH256 = 0x0d
PSBT_IN_PREVIOUS_TXID = 0x0e
PSBT_IN_OUTPUT_INDEX = 0x0f
PSBT_IN_SEQUENCE = 0x10
PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11
PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
PSBT_IN_TAP_KEY_SIG = 0x13
PSBT_IN_TAP_SCRIPT_SIG = 0x14
PSBT_IN_TAP_LEAF_SCRIPT = 0x15
PSBT_IN_TAP_BIP32_DERIVATION = 0x16
PSBT_IN_TAP_INTERNAL_KEY = 0x17
PSBT_IN_TAP_MERKLE_ROOT = 0x18
PSBT_IN_PROPRIETARY = 0xfc

# PSBT Output Types
PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02
PSBT_OUT_AMOUNT = 0x03
PSBT_OUT_SCRIPT = 0x04
PSBT_OUT_TAP_INTERNAL_KEY = 0x05
PSBT_OUT_TAP_TREE = 0x06
PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
PSBT_OUT_PROPRIETARY = 0xfc

# BNAP Proprietary Prefixes
BNAP_PREFIX = b'BNAP'
BNAP_ASSET_ID = 0x01
BNAP_ASSET_AMOUNT = 0x02
BNAP_ASSET_TYPE = 0x03
BNAP_METADATA_HASH = 0x04
BNAP_COLLECTION_ID = 0x05
BNAP_TOKEN_ID = 0x06


@dataclass
class PSBTGlobal:
    """Represents global fields in a PSBT."""
    unsigned_tx: Optional[Transaction] = None
    version: int = 0
    xpubs: Dict[bytes, bytes] = field(default_factory=dict)
    proprietary: Dict[bytes, bytes] = field(default_factory=dict)
    unknown: Dict[bytes, bytes] = field(default_factory=dict)


@dataclass
class PSBTInput:
    """Represents input fields in a PSBT."""
    non_witness_utxo: Optional[Transaction] = None
    witness_utxo: Optional[Output] = None
    partial_sigs: Dict[bytes, bytes] = field(default_factory=dict)
    sighash_type: Optional[int] = None
    redeem_script: Optional[bytes] = None
    witness_script: Optional[bytes] = None
    bip32_derivations: Dict[bytes, Tuple[bytes, List[int]]] = field(default_factory=dict)
    final_scriptsig: Optional[bytes] = None
    final_scriptwitness: Optional[bytes] = None
    tap_key_sig: Optional[bytes] = None
    tap_internal_key: Optional[bytes] = None
    tap_merkle_root: Optional[bytes] = None
    proprietary: Dict[bytes, bytes] = field(default_factory=dict)
    unknown: Dict[bytes, bytes] = field(default_factory=dict)


@dataclass
class PSBTOutput:
    """Represents output fields in a PSBT."""
    redeem_script: Optional[bytes] = None
    witness_script: Optional[bytes] = None
    bip32_derivations: Dict[bytes, Tuple[bytes, List[int]]] = field(default_factory=dict)
    amount: Optional[int] = None
    script: Optional[bytes] = None
    tap_internal_key: Optional[bytes] = None
    tap_tree: Optional[Dict] = None
    proprietary: Dict[bytes, bytes] = field(default_factory=dict)
    unknown: Dict[bytes, bytes] = field(default_factory=dict)


@dataclass
class AssetMetadata:
    """Represents extracted BNAP asset metadata."""
    asset_id: Optional[str] = None
    asset_type: Optional[str] = None
    amount: Optional[int] = None
    metadata_hash: Optional[bytes] = None
    collection_id: Optional[int] = None
    token_id: Optional[int] = None
    op_return_data: Optional[Dict[str, Any]] = None


@dataclass
class ParsedPSBT:
    """Represents a fully parsed PSBT with metadata."""
    psbt_global: PSBTGlobal
    inputs: List[PSBTInput]
    outputs: List[PSBTOutput]
    asset_metadata: List[AssetMetadata]
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)


class PSBTParser:
    """
    Parser for PSBT files with BNAP metadata extraction.
    
    This class provides methods to deserialize PSBT data, validate structure
    against BIP-174, extract proprietary BNAP fields, and parse OP_RETURN metadata.
    """
    
    def __init__(self):
        """Initialize PSBT parser."""
        self.op_return_decoder = OpReturnDecoder()
    
    def parse(self, psbt_data: Union[bytes, str]) -> ParsedPSBT:
        """
        Parse PSBT data and extract metadata.
        
        Args:
            psbt_data: PSBT data as bytes or base64 string
            
        Returns:
            ParsedPSBT object with all extracted information
        """
        # Convert base64 to bytes if needed
        if isinstance(psbt_data, str):
            try:
                psbt_data = base64.b64decode(psbt_data)
            except Exception as e:
                raise PSBTParsingError(f"Invalid base64 encoding: {e}")
        
        # Parse PSBT structure
        try:
            psbt_global, inputs, outputs = self._parse_psbt_structure(psbt_data)
        except Exception as e:
            raise PSBTParsingError(f"Failed to parse PSBT structure: {e}")
        
        # Extract asset metadata
        asset_metadata = self._extract_asset_metadata(psbt_global, inputs, outputs)
        
        # Validate PSBT
        is_valid, errors = self._validate_psbt(psbt_global, inputs, outputs)
        
        return ParsedPSBT(
            psbt_global=psbt_global,
            inputs=inputs,
            outputs=outputs,
            asset_metadata=asset_metadata,
            is_valid=is_valid,
            validation_errors=errors
        )
    
    def _parse_psbt_structure(self, data: bytes) -> Tuple[PSBTGlobal, List[PSBTInput], List[PSBTOutput]]:
        """
        Parse the core PSBT structure.
        
        Args:
            data: Raw PSBT bytes
            
        Returns:
            Tuple of (global fields, inputs, outputs)
        """
        # Check magic bytes
        if not data.startswith(PSBT_MAGIC + PSBT_SEPARATOR):
            raise PSBTParsingError("Invalid PSBT magic bytes")
        
        stream = BytesIO(data[5:])  # Skip magic and separator
        
        # Parse global fields
        psbt_global = self._parse_global_fields(stream)
        
        # Get transaction to determine input/output count
        if not psbt_global.unsigned_tx:
            raise PSBTParsingError("Missing unsigned transaction in global fields")
        
        tx = psbt_global.unsigned_tx
        
        # Parse inputs
        inputs = []
        for _ in range(len(tx.inputs)):
            inputs.append(self._parse_input_fields(stream))
        
        # Parse outputs
        outputs = []
        for _ in range(len(tx.outputs)):
            outputs.append(self._parse_output_fields(stream))
        
        return psbt_global, inputs, outputs
    
    def _parse_global_fields(self, stream: BytesIO) -> PSBTGlobal:
        """Parse PSBT global fields."""
        psbt_global = PSBTGlobal()
        
        while True:
            # Read key-value pair
            key_len_bytes = stream.read(1)
            if not key_len_bytes:
                break
            
            key_len = key_len_bytes[0]
            if key_len == 0:  # Separator
                break
            
            key = stream.read(key_len)
            if len(key) < key_len:
                raise PSBTParsingError("Unexpected end of global fields")
            
            # Read value length as compact size
            value_len_data = stream.read(1)
            if not value_len_data:
                raise PSBTParsingError("Unexpected end while reading value length")
            
            first_byte = value_len_data[0]
            if first_byte < 0xfd:
                value_len = first_byte
            elif first_byte == 0xfd:
                value_len_data += stream.read(2)
                value_len = struct.unpack('<H', value_len_data[1:])[0]
            elif first_byte == 0xfe:
                value_len_data += stream.read(4)
                value_len = struct.unpack('<I', value_len_data[1:])[0]
            else:
                value_len_data += stream.read(8)
                value_len = struct.unpack('<Q', value_len_data[1:])[0]
            
            value = stream.read(value_len)
            
            # Parse based on key type
            if len(key) == 1:
                key_type = key[0]
                
                if key_type == PSBT_GLOBAL_UNSIGNED_TX:
                    # Parse unsigned transaction
                    psbt_global.unsigned_tx = self._parse_transaction(value)
                elif key_type == PSBT_GLOBAL_VERSION:
                    psbt_global.version = struct.unpack('<I', value)[0]
                elif key_type == PSBT_GLOBAL_XPUB:
                    # Extended public key
                    psbt_global.xpubs[key[1:]] = value
                else:
                    psbt_global.unknown[key] = value
            elif key[0] == PSBT_GLOBAL_PROPRIETARY:
                # Proprietary field
                psbt_global.proprietary[key[1:]] = value
            else:
                psbt_global.unknown[key] = value
        
        return psbt_global
    
    def _parse_input_fields(self, stream: BytesIO) -> PSBTInput:
        """Parse PSBT input fields."""
        psbt_input = PSBTInput()
        
        while True:
            # Read key-value pair
            key_len_bytes = stream.read(1)
            if not key_len_bytes:
                break
            
            key_len = key_len_bytes[0]
            if key_len == 0:  # Separator
                break
            
            key = stream.read(key_len)
            if len(key) < key_len:
                raise PSBTParsingError("Unexpected end of input fields")
            
            # Read value length as compact size
            value_len_data = stream.read(1)
            if not value_len_data:
                raise PSBTParsingError("Unexpected end while reading value length")
            
            first_byte = value_len_data[0]
            if first_byte < 0xfd:
                value_len = first_byte
            elif first_byte == 0xfd:
                value_len_data += stream.read(2)
                value_len = struct.unpack('<H', value_len_data[1:])[0]
            elif first_byte == 0xfe:
                value_len_data += stream.read(4)
                value_len = struct.unpack('<I', value_len_data[1:])[0]
            else:
                value_len_data += stream.read(8)
                value_len = struct.unpack('<Q', value_len_data[1:])[0]
            
            value = stream.read(value_len)
            
            # Parse based on key type
            if len(key) >= 1:
                key_type = key[0]
                
                if key_type == PSBT_IN_NON_WITNESS_UTXO:
                    psbt_input.non_witness_utxo = self._parse_transaction(value)
                elif key_type == PSBT_IN_WITNESS_UTXO:
                    psbt_input.witness_utxo = self._parse_transaction_output(value)
                elif key_type == PSBT_IN_PARTIAL_SIG:
                    psbt_input.partial_sigs[key[1:]] = value
                elif key_type == PSBT_IN_SIGHASH_TYPE:
                    psbt_input.sighash_type = struct.unpack('<I', value)[0]
                elif key_type == PSBT_IN_REDEEM_SCRIPT:
                    psbt_input.redeem_script = value
                elif key_type == PSBT_IN_WITNESS_SCRIPT:
                    psbt_input.witness_script = value
                elif key_type == PSBT_IN_BIP32_DERIVATION:
                    pubkey = key[1:]
                    fingerprint = value[:4]
                    path = decode_bip32_path(value[4:])
                    psbt_input.bip32_derivations[pubkey] = (fingerprint, path)
                elif key_type == PSBT_IN_FINAL_SCRIPTSIG:
                    psbt_input.final_scriptsig = value
                elif key_type == PSBT_IN_FINAL_SCRIPTWITNESS:
                    psbt_input.final_scriptwitness = value
                elif key_type == PSBT_IN_TAP_KEY_SIG:
                    psbt_input.tap_key_sig = value
                elif key_type == PSBT_IN_TAP_INTERNAL_KEY:
                    psbt_input.tap_internal_key = value
                elif key_type == PSBT_IN_TAP_MERKLE_ROOT:
                    psbt_input.tap_merkle_root = value
                elif key_type == PSBT_IN_PROPRIETARY:
                    psbt_input.proprietary[key[1:]] = value
                else:
                    psbt_input.unknown[key] = value
            else:
                psbt_input.unknown[key] = value
        
        return psbt_input
    
    def _parse_output_fields(self, stream: BytesIO) -> PSBTOutput:
        """Parse PSBT output fields."""
        psbt_output = PSBTOutput()
        
        while True:
            # Read key-value pair
            key_len_bytes = stream.read(1)
            if not key_len_bytes:
                break
            
            key_len = key_len_bytes[0]
            if key_len == 0:  # Separator
                break
            
            key = stream.read(key_len)
            if len(key) < key_len:
                raise PSBTParsingError("Unexpected end of output fields")
            
            # Read value length as compact size
            value_len_data = stream.read(1)
            if not value_len_data:
                raise PSBTParsingError("Unexpected end while reading value length")
            
            first_byte = value_len_data[0]
            if first_byte < 0xfd:
                value_len = first_byte
            elif first_byte == 0xfd:
                value_len_data += stream.read(2)
                value_len = struct.unpack('<H', value_len_data[1:])[0]
            elif first_byte == 0xfe:
                value_len_data += stream.read(4)
                value_len = struct.unpack('<I', value_len_data[1:])[0]
            else:
                value_len_data += stream.read(8)
                value_len = struct.unpack('<Q', value_len_data[1:])[0]
            
            value = stream.read(value_len)
            
            # Parse based on key type
            if len(key) >= 1:
                key_type = key[0]
                
                if key_type == PSBT_OUT_REDEEM_SCRIPT:
                    psbt_output.redeem_script = value
                elif key_type == PSBT_OUT_WITNESS_SCRIPT:
                    psbt_output.witness_script = value
                elif key_type == PSBT_OUT_BIP32_DERIVATION:
                    pubkey = key[1:]
                    fingerprint = value[:4]
                    path = decode_bip32_path(value[4:])
                    psbt_output.bip32_derivations[pubkey] = (fingerprint, path)
                elif key_type == PSBT_OUT_AMOUNT:
                    psbt_output.amount = struct.unpack('<Q', value)[0]
                elif key_type == PSBT_OUT_SCRIPT:
                    psbt_output.script = value
                elif key_type == PSBT_OUT_TAP_INTERNAL_KEY:
                    psbt_output.tap_internal_key = value
                elif key_type == PSBT_OUT_TAP_TREE:
                    psbt_output.tap_tree = self._parse_tap_tree(value)
                elif key_type == PSBT_OUT_PROPRIETARY:
                    psbt_output.proprietary[key[1:]] = value
                else:
                    psbt_output.unknown[key] = value
            else:
                psbt_output.unknown[key] = value
        
        return psbt_output
    
    def _parse_transaction(self, data: bytes) -> Transaction:
        """Parse a Bitcoin transaction."""
        # Use bitcoinlib for transaction parsing
        try:
            tx = Transaction.parse_hex(data.hex())
            return tx
        except Exception as e:
            raise PSBTParsingError(f"Failed to parse transaction: {e}")
    
    def _parse_transaction_output(self, data: bytes) -> Output:
        """Parse a transaction output."""
        stream = BytesIO(data)
        
        # Read amount (8 bytes)
        amount = struct.unpack('<Q', stream.read(8))[0]
        
        # Read script length as compact size
        remaining_data = stream.read()
        script_len, offset = parse_compact_size(remaining_data, 0)
        script = remaining_data[offset:offset + script_len]
        
        # Create output object
        output = Output(value=amount, script=script)
        return output
    
    def _parse_tap_tree(self, data: bytes) -> Dict:
        """Parse Taproot tree structure."""
        # Simplified parsing - would need full implementation
        return {'raw': data.hex()}
    
    def _extract_asset_metadata(
        self,
        psbt_global: PSBTGlobal,
        inputs: List[PSBTInput],
        outputs: List[PSBTOutput]
    ) -> List[AssetMetadata]:
        """
        Extract BNAP asset metadata from PSBT.
        
        Args:
            psbt_global: Global PSBT fields
            inputs: List of PSBT inputs
            outputs: List of PSBT outputs
            
        Returns:
            List of extracted asset metadata
        """
        metadata_list = []
        
        # Extract from global proprietary fields
        global_metadata = self._extract_proprietary_metadata(psbt_global.proprietary)
        if global_metadata.asset_id:
            metadata_list.append(global_metadata)
        
        # Extract from input proprietary fields
        for psbt_input in inputs:
            input_metadata = self._extract_proprietary_metadata(psbt_input.proprietary)
            if input_metadata.asset_id:
                metadata_list.append(input_metadata)
        
        # Extract from output proprietary fields and OP_RETURN
        tx = psbt_global.unsigned_tx
        for i, (psbt_output, tx_output) in enumerate(zip(outputs, tx.outputs)):
            # Check proprietary fields
            output_metadata = self._extract_proprietary_metadata(psbt_output.proprietary)
            
            # Check for OP_RETURN metadata
            script_bytes = tx_output.script.as_bytes() if tx_output.script else b''
            if script_bytes and script_bytes[0:1] == b'\x6a':  # OP_RETURN
                op_return_data = parse_op_return_metadata(script_bytes)
                if op_return_data:
                    output_metadata.op_return_data = op_return_data
                    
                    # Extract specific fields from OP_RETURN
                    if 'asset_id_partial' in op_return_data:
                        if not output_metadata.asset_id:
                            output_metadata.asset_id = op_return_data['asset_id_partial']
                    if 'amount' in op_return_data:
                        output_metadata.amount = op_return_data['amount']
                    if 'collection_id' in op_return_data:
                        output_metadata.collection_id = op_return_data['collection_id']
                    if 'token_id' in op_return_data:
                        output_metadata.token_id = op_return_data['token_id']
            
            if output_metadata.asset_id or output_metadata.op_return_data:
                metadata_list.append(output_metadata)
        
        return metadata_list
    
    def _extract_proprietary_metadata(self, proprietary: Dict[bytes, bytes]) -> AssetMetadata:
        """Extract BNAP metadata from proprietary fields."""
        metadata = AssetMetadata()
        
        for key, value in proprietary.items():
            # Check for BNAP prefix
            if key.startswith(BNAP_PREFIX):
                if len(key) < 5:
                    continue
                
                field_type = key[4]
                
                if field_type == BNAP_ASSET_ID:
                    metadata.asset_id = value.hex()
                elif field_type == BNAP_ASSET_AMOUNT:
                    if len(value) == 8:
                        metadata.amount = struct.unpack('<Q', value)[0]
                elif field_type == BNAP_ASSET_TYPE:
                    metadata.asset_type = value.decode('utf-8', errors='ignore')
                elif field_type == BNAP_METADATA_HASH:
                    metadata.metadata_hash = value
                elif field_type == BNAP_COLLECTION_ID:
                    if len(value) == 8:
                        metadata.collection_id = struct.unpack('<Q', value)[0]
                elif field_type == BNAP_TOKEN_ID:
                    if len(value) == 8:
                        metadata.token_id = struct.unpack('<Q', value)[0]
        
        return metadata
    
    def _validate_psbt(
        self,
        psbt_global: PSBTGlobal,
        inputs: List[PSBTInput],
        outputs: List[PSBTOutput]
    ) -> Tuple[bool, List[str]]:
        """
        Validate PSBT structure against BIP-174.
        
        Args:
            psbt_global: Global PSBT fields
            inputs: List of PSBT inputs
            outputs: List of PSBT outputs
            
        Returns:
            Tuple of (is_valid, list of errors)
        """
        errors = []
        
        # Check for unsigned transaction
        if not psbt_global.unsigned_tx:
            errors.append("Missing unsigned transaction in global fields")
        else:
            tx = psbt_global.unsigned_tx
            
            # Check input count matches
            if len(inputs) != len(tx.inputs):
                errors.append(f"Input count mismatch: PSBT has {len(inputs)}, transaction has {len(tx.inputs)}")
            
            # Check output count matches
            if len(outputs) != len(tx.outputs):
                errors.append(f"Output count mismatch: PSBT has {len(outputs)}, transaction has {len(tx.outputs)}")
            
            # Validate each input
            for i, psbt_input in enumerate(inputs):
                if not psbt_input.non_witness_utxo and not psbt_input.witness_utxo:
                    errors.append(f"Input {i}: Missing UTXO information")
                
                # Check for conflicting fields
                if psbt_input.final_scriptsig and psbt_input.partial_sigs:
                    errors.append(f"Input {i}: Has both final scriptsig and partial signatures")
                
                if psbt_input.final_scriptwitness and psbt_input.partial_sigs:
                    errors.append(f"Input {i}: Has both final scriptwitness and partial signatures")
            
            # Validate each output
            for i, psbt_output in enumerate(outputs):
                # Check for script consistency
                if psbt_output.script and i < len(tx.outputs):
                    if psbt_output.script != tx.outputs[i].script:
                        errors.append(f"Output {i}: Script mismatch between PSBT and transaction")
        
        is_valid = len(errors) == 0
        return is_valid, errors


# Utility functions
def parse_psbt_from_base64(base64_str: str) -> ParsedPSBT:
    """
    Parse PSBT from base64 string.
    
    Args:
        base64_str: Base64-encoded PSBT
        
    Returns:
        ParsedPSBT object
    """
    parser = PSBTParser()
    return parser.parse(base64_str)


def parse_psbt_from_bytes(psbt_bytes: bytes) -> ParsedPSBT:
    """
    Parse PSBT from raw bytes.
    
    Args:
        psbt_bytes: Raw PSBT bytes
        
    Returns:
        ParsedPSBT object
    """
    parser = PSBTParser()
    return parser.parse(psbt_bytes)


def extract_asset_operations(parsed_psbt: ParsedPSBT) -> List[Dict[str, Any]]:
    """
    Extract asset operations from parsed PSBT.
    
    Args:
        parsed_psbt: Parsed PSBT object
        
    Returns:
        List of asset operations
    """
    operations = []
    
    for metadata in parsed_psbt.asset_metadata:
        operation = {
            'asset_id': metadata.asset_id,
            'type': metadata.asset_type or 'unknown',
            'amount': metadata.amount
        }
        
        # Add NFT-specific fields if present
        if metadata.collection_id is not None:
            operation['collection_id'] = metadata.collection_id
        if metadata.token_id is not None:
            operation['token_id'] = metadata.token_id
        
        # Add OP_RETURN data if present
        if metadata.op_return_data:
            operation['op_return'] = metadata.op_return_data
        
        operations.append(operation)
    
    return operations


def validate_psbt_structure(psbt_data: Union[bytes, str]) -> Tuple[bool, List[str]]:
    """
    Validate PSBT structure without full parsing.
    
    Args:
        psbt_data: PSBT data as bytes or base64 string
        
    Returns:
        Tuple of (is_valid, list of errors)
    """
    try:
        parser = PSBTParser()
        parsed = parser.parse(psbt_data)
        return parsed.is_valid, parsed.validation_errors
    except Exception as e:
        return False, [str(e)]