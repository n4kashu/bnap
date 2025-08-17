"""
Bitcoin Native Asset Protocol - PSBT Utilities

This module provides utility functions for PSBT construction and manipulation.
"""

import hashlib
import struct
from typing import List, Tuple, Union, Optional
from io import BytesIO

from bitcoinlib.encoding import varstr


def varstr_parse(data: bytes, offset: int = 0) -> Tuple[bytes, int]:
    """
    Parse variable-length string from bytes (missing from bitcoinlib).
    
    Args:
        data: Bytes to parse
        offset: Starting offset
        
    Returns:
        Tuple of (parsed_data, new_offset)
    """
    length, new_offset = parse_compact_size(data, offset)
    if new_offset + length > len(data):
        raise ValueError("Insufficient data for varstr")
    
    return data[new_offset:new_offset + length], new_offset + length


def serialize_compact_size(n: int) -> bytes:
    """
    Serialize integer as Bitcoin compact size.
    
    Args:
        n: Integer to serialize
        
    Returns:
        Compact size encoded bytes
    """
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def parse_compact_size(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Parse Bitcoin compact size from bytes.
    
    Args:
        data: Bytes to parse
        offset: Starting offset in bytes
        
    Returns:
        Tuple of (value, new_offset)
    """
    if offset >= len(data):
        raise ValueError("Insufficient data for compact size")
    
    first_byte = data[offset]
    
    if first_byte < 0xfd:
        return first_byte, offset + 1
    elif first_byte == 0xfd:
        if offset + 3 > len(data):
            raise ValueError("Insufficient data for 2-byte compact size")
        return struct.unpack('<H', data[offset + 1:offset + 3])[0], offset + 3
    elif first_byte == 0xfe:
        if offset + 5 > len(data):
            raise ValueError("Insufficient data for 4-byte compact size")
        return struct.unpack('<I', data[offset + 1:offset + 5])[0], offset + 5
    else:  # 0xff
        if offset + 9 > len(data):
            raise ValueError("Insufficient data for 8-byte compact size")
        return struct.unpack('<Q', data[offset + 1:offset + 9])[0], offset + 9


def serialize_key_value(key: bytes, value: bytes) -> bytes:
    """
    Serialize key-value pair in PSBT format.
    
    Args:
        key: Key bytes
        value: Value bytes
        
    Returns:
        Serialized key-value pair
    """
    return varstr(key) + varstr(value)


def parse_key_value(data: bytes, offset: int = 0) -> Tuple[bytes, bytes, int]:
    """
    Parse key-value pair from PSBT format.
    
    Args:
        data: Bytes to parse
        offset: Starting offset
        
    Returns:
        Tuple of (key, value, new_offset)
    """
    key, offset = varstr_parse(data, offset)
    if not key:  # Empty key indicates end of map
        return b'', b'', offset
    
    value, offset = varstr_parse(data, offset)
    return key, value, offset


def calculate_witness_script_hash(script: bytes) -> bytes:
    """
    Calculate SHA256 hash of witness script for P2WSH.
    
    Args:
        script: Witness script bytes
        
    Returns:
        SHA256 hash of script
    """
    return hashlib.sha256(script).digest()


def create_p2wsh_script(witness_script: bytes) -> bytes:
    """
    Create P2WSH output script from witness script.
    
    Args:
        witness_script: The witness script
        
    Returns:
        P2WSH output script (OP_0 + 32-byte script hash)
    """
    script_hash = calculate_witness_script_hash(witness_script)
    return bytes([0x00, 0x20]) + script_hash  # OP_0 OP_PUSHDATA(32) <hash>


def create_op_return_script(data: bytes) -> bytes:
    """
    Create OP_RETURN script with data.
    
    Args:
        data: Data to embed in OP_RETURN
        
    Returns:
        OP_RETURN script
    """
    if len(data) > 80:
        raise ValueError("OP_RETURN data cannot exceed 80 bytes")
    
    script = bytes([0x6a])  # OP_RETURN
    if len(data) <= 75:
        script += bytes([len(data)]) + data
    else:
        script += bytes([0x4c, len(data)]) + data  # OP_PUSHDATA1
    
    return script


def extract_op_return_data(script: bytes) -> Optional[bytes]:
    """
    Extract data from OP_RETURN script.
    
    Args:
        script: Script bytes
        
    Returns:
        Extracted data or None if not OP_RETURN
    """
    if not script or script[0] != 0x6a:  # Not OP_RETURN
        return None
    
    if len(script) < 2:
        return b''  # Empty OP_RETURN
    
    # Handle different push opcodes
    if script[1] <= 75:  # Direct push
        data_len = script[1]
        if len(script) >= 2 + data_len:
            return script[2:2 + data_len]
    elif script[1] == 0x4c:  # OP_PUSHDATA1
        if len(script) >= 3:
            data_len = script[2]
            if len(script) >= 3 + data_len:
                return script[3:3 + data_len]
    
    return None


def double_sha256(data: bytes) -> bytes:
    """
    Calculate double SHA256 hash (used for transaction IDs).
    
    Args:
        data: Data to hash
        
    Returns:
        Double SHA256 hash
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def serialize_outpoint(txid: str, vout: int) -> bytes:
    """
    Serialize transaction outpoint.
    
    Args:
        txid: Transaction ID as hex string
        vout: Output index
        
    Returns:
        Serialized outpoint (32 bytes txid + 4 bytes vout)
    """
    # Convert hex txid to bytes and reverse (little endian)
    txid_bytes = bytes.fromhex(txid)[::-1]
    vout_bytes = struct.pack('<I', vout)
    return txid_bytes + vout_bytes


def parse_outpoint(data: bytes, offset: int = 0) -> Tuple[str, int, int]:
    """
    Parse transaction outpoint.
    
    Args:
        data: Bytes to parse
        offset: Starting offset
        
    Returns:
        Tuple of (txid, vout, new_offset)
    """
    if offset + 36 > len(data):
        raise ValueError("Insufficient data for outpoint")
    
    # Parse txid (32 bytes, reverse to big endian for hex)
    txid_bytes = data[offset:offset + 32][::-1]
    txid = txid_bytes.hex()
    
    # Parse vout (4 bytes little endian)
    vout = struct.unpack('<I', data[offset + 32:offset + 36])[0]
    
    return txid, vout, offset + 36


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
    
    if len(asset_id) != 64:
        return False
    
    try:
        int(asset_id, 16)
        return True
    except ValueError:
        return False


def create_asset_commitment(asset_id: str, amount: int) -> bytes:
    """
    Create asset commitment for use in covenant scripts.
    
    Args:
        asset_id: Asset ID as hex string
        amount: Asset amount
        
    Returns:
        Asset commitment bytes
    """
    if not validate_asset_id(asset_id):
        raise ValueError("Invalid asset ID format")
    
    asset_id_bytes = bytes.fromhex(asset_id)
    amount_bytes = struct.pack('<Q', amount)
    
    # Create commitment: HASH256(asset_id || amount)
    commitment_data = asset_id_bytes + amount_bytes
    return double_sha256(commitment_data)


def encode_bip32_path(path: List[int]) -> bytes:
    """
    Encode BIP32 derivation path.
    
    Args:
        path: List of path components
        
    Returns:
        Encoded path bytes
    """
    return b''.join(struct.pack('<I', p) for p in path)


def decode_bip32_path(data: bytes) -> List[int]:
    """
    Decode BIP32 derivation path.
    
    Args:
        data: Encoded path bytes
        
    Returns:
        List of path components
    """
    if len(data) % 4 != 0:
        raise ValueError("Invalid BIP32 path length")
    
    path = []
    for i in range(0, len(data), 4):
        component = struct.unpack('<I', data[i:i + 4])[0]
        path.append(component)
    
    return path


def estimate_transaction_size(
    num_inputs: int,
    num_outputs: int,
    has_witness: bool = True
) -> int:
    """
    Estimate transaction size in bytes.
    
    Args:
        num_inputs: Number of inputs
        num_outputs: Number of outputs
        has_witness: Whether transaction uses witness data
        
    Returns:
        Estimated size in bytes
    """
    # Base transaction size
    base_size = 4 + 1 + 1 + 4  # version + input_count + output_count + locktime
    
    # Input sizes (vary by type, use P2WPKH estimate)
    input_size = 32 + 4 + 1 + 4  # outpoint + script_len + sequence
    if has_witness:
        input_size += 110  # Estimated witness data for P2WPKH
    else:
        input_size += 110  # Script sig for P2PKH
    
    # Output sizes (vary by type, use P2WPKH estimate)
    output_size = 8 + 1 + 22  # value + script_len + script
    
    total_size = base_size + (num_inputs * input_size) + (num_outputs * output_size)
    
    # Add witness overhead if present
    if has_witness:
        total_size += 2  # witness flag and marker
    
    return total_size


def calculate_fee_rate(fee: int, size: int) -> float:
    """
    Calculate fee rate in sat/vB.
    
    Args:
        fee: Fee in satoshis
        size: Transaction size in virtual bytes
        
    Returns:
        Fee rate in sat/vB
    """
    if size <= 0:
        return 0.0
    
    return fee / size


def tagged_hash(tag: str, data: bytes) -> bytes:
    """
    Calculate tagged hash as defined in BIP-340.
    
    Args:
        tag: Hash tag string
        data: Data to hash
        
    Returns:
        Tagged hash
    """
    tag_bytes = tag.encode('utf-8')
    tag_hash = hashlib.sha256(tag_bytes).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def create_taproot_script(tweaked_pubkey: bytes) -> bytes:
    """
    Create P2TR output script from tweaked public key.
    
    Args:
        tweaked_pubkey: 32-byte tweaked public key
        
    Returns:
        P2TR output script (OP_1 + 32-byte tweaked pubkey)
    """
    if len(tweaked_pubkey) != 32:
        raise ValueError(f"Invalid tweaked pubkey length: {len(tweaked_pubkey)}")
    
    return bytes([0x51, 0x20]) + tweaked_pubkey  # OP_1 OP_PUSHDATA(32) <tweaked_pubkey>


def calculate_taproot_tweak(internal_pubkey: bytes, merkle_root: bytes) -> bytes:
    """
    Calculate Taproot tweak value.
    
    Args:
        internal_pubkey: 32-byte internal public key
        merkle_root: 32-byte Merkle root (can be zeros for key-path only)
        
    Returns:
        32-byte tweak value
    """
    if len(internal_pubkey) != 32:
        raise ValueError(f"Invalid internal pubkey length: {len(internal_pubkey)}")
    if len(merkle_root) != 32:
        raise ValueError(f"Invalid merkle root length: {len(merkle_root)}")
    
    return tagged_hash("TapTweak", internal_pubkey + merkle_root)


def is_valid_x_only_pubkey(pubkey: bytes) -> bool:
    """
    Validate x-only public key format for Taproot.
    
    Args:
        pubkey: Public key bytes to validate
        
    Returns:
        True if valid x-only pubkey, False otherwise
    """
    if not isinstance(pubkey, bytes):
        return False
    
    if len(pubkey) != 32:
        return False
    
    # Additional validation could check if it's a valid curve point
    # For now, just check it's not all zeros
    return pubkey != b'\x00' * 32


def extract_taproot_pubkey(script: bytes) -> Optional[bytes]:
    """
    Extract tweaked public key from P2TR script.
    
    Args:
        script: P2TR script bytes
        
    Returns:
        32-byte tweaked pubkey or None if not P2TR
    """
    if len(script) != 34:
        return None
    
    if script[0] != 0x51 or script[1] != 0x20:  # OP_1 OP_PUSHDATA(32)
        return None
    
    return script[2:34]