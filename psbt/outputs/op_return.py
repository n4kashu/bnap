"""
Bitcoin Native Asset Protocol - OP_RETURN Metadata Encoder Module

This module provides specialized functions and classes for creating OP_RETURN
outputs that encode asset metadata, protocol messages, and other data within
the Bitcoin Native Asset Protocol.
"""

import hashlib
import json
import struct
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from enum import Enum

from ..utils import (
    create_op_return_script,
    extract_op_return_data,
    serialize_compact_size,
    double_sha256
)
from ..exceptions import (
    PSBTConstructionError,
    InvalidScriptError,
    MetadataError
)


# Protocol constants
BNAP_PREFIX = b'BNAP'  # Bitcoin Native Asset Protocol prefix
BNAP_VERSION = 0x01  # Protocol version
MAX_OP_RETURN_SIZE = 80  # Maximum OP_RETURN data size in bytes


class MetadataType(Enum):
    """Types of metadata that can be encoded in OP_RETURN."""
    ASSET_ISSUANCE = 0x01
    ASSET_TRANSFER = 0x02
    ASSET_BURN = 0x03
    NFT_METADATA = 0x04
    COLLECTION_INFO = 0x05
    URI_REFERENCE = 0x06
    COMMITMENT = 0x07
    MESSAGE = 0x08
    PROTOCOL_UPDATE = 0x09


class CompressionType(Enum):
    """Compression types for metadata."""
    NONE = 0x00
    GZIP = 0x01
    BROTLI = 0x02
    LZ4 = 0x03


@dataclass
class MetadataPayload:
    """Represents a metadata payload for OP_RETURN encoding."""
    metadata_type: MetadataType
    content: bytes
    compression: CompressionType = CompressionType.NONE
    version: int = BNAP_VERSION
    
    def __post_init__(self):
        """Validate payload parameters."""
        if not isinstance(self.metadata_type, MetadataType):
            raise MetadataError("Invalid metadata type")
        
        if not isinstance(self.content, bytes):
            raise MetadataError("Content must be bytes")
        
        if len(self.content) == 0:
            raise MetadataError("Content cannot be empty")
        
        # Check total size with protocol overhead
        overhead = len(BNAP_PREFIX) + 1 + 1 + 1  # prefix + version + type + compression
        if len(self.content) + overhead > MAX_OP_RETURN_SIZE:
            raise MetadataError(
                f"Content too large: {len(self.content) + overhead} bytes "
                f"(max: {MAX_OP_RETURN_SIZE})"
            )


class OpReturnEncoder:
    """
    Encoder for creating OP_RETURN outputs with BNAP metadata.
    
    This class provides methods to encode various types of metadata
    into OP_RETURN outputs following the BNAP protocol specification.
    """
    
    def __init__(self):
        """Initialize OP_RETURN encoder."""
        self.prefix = BNAP_PREFIX
        self.version = BNAP_VERSION
    
    def encode_metadata(self, payload: MetadataPayload) -> bytes:
        """
        Encode metadata payload into OP_RETURN data.
        
        Args:
            payload: Metadata payload to encode
            
        Returns:
            Encoded data for OP_RETURN output
        """
        # Build protocol header
        data = self.prefix  # 4 bytes
        data += bytes([payload.version])  # 1 byte
        data += bytes([payload.metadata_type.value])  # 1 byte
        data += bytes([payload.compression.value])  # 1 byte
        
        # Add content
        data += payload.content
        
        # Verify total size
        if len(data) > MAX_OP_RETURN_SIZE:
            raise MetadataError(f"Encoded data too large: {len(data)} bytes")
        
        return data
    
    def create_op_return_output(self, payload: MetadataPayload) -> bytes:
        """
        Create complete OP_RETURN output script.
        
        Args:
            payload: Metadata payload to encode
            
        Returns:
            OP_RETURN script bytes
        """
        data = self.encode_metadata(payload)
        return create_op_return_script(data)
    
    def encode_asset_issuance(
        self,
        asset_id: str,
        supply: int,
        decimals: int = 8,
        symbol: Optional[str] = None
    ) -> bytes:
        """
        Encode asset issuance metadata.
        
        Args:
            asset_id: Asset identifier (32-byte hex string)
            supply: Total supply amount
            decimals: Number of decimal places
            symbol: Optional asset symbol (max 8 chars)
            
        Returns:
            OP_RETURN script for asset issuance
        """
        # Validate asset ID
        try:
            asset_id_bytes = bytes.fromhex(asset_id)
            if len(asset_id_bytes) != 32:
                raise MetadataError(f"Invalid asset ID length: {len(asset_id_bytes)}")
        except ValueError:
            raise MetadataError(f"Invalid asset ID format: {asset_id}")
        
        # Build issuance data
        content = b''
        
        # Asset ID (first 8 bytes only to save space)
        content += asset_id_bytes[:8]
        
        # Supply (8 bytes)
        content += struct.pack('<Q', supply)
        
        # Decimals (1 byte)
        content += bytes([min(decimals, 255)])
        
        # Symbol (optional, max 8 bytes)
        if symbol:
            symbol_bytes = symbol.encode('utf-8')[:8]
            content += bytes([len(symbol_bytes)])
            content += symbol_bytes
        else:
            content += bytes([0])
        
        payload = MetadataPayload(
            metadata_type=MetadataType.ASSET_ISSUANCE,
            content=content
        )
        
        return self.create_op_return_output(payload)
    
    def encode_asset_transfer(
        self,
        asset_id: str,
        amount: int,
        recipient_hash: Optional[bytes] = None
    ) -> bytes:
        """
        Encode asset transfer metadata.
        
        Args:
            asset_id: Asset identifier
            amount: Transfer amount
            recipient_hash: Optional recipient identifier hash
            
        Returns:
            OP_RETURN script for asset transfer
        """
        # Validate asset ID
        try:
            asset_id_bytes = bytes.fromhex(asset_id)
            if len(asset_id_bytes) != 32:
                raise MetadataError(f"Invalid asset ID length: {len(asset_id_bytes)}")
        except ValueError:
            raise MetadataError(f"Invalid asset ID format: {asset_id}")
        
        # Build transfer data
        content = b''
        
        # Asset ID (first 8 bytes)
        content += asset_id_bytes[:8]
        
        # Amount (8 bytes)
        content += struct.pack('<Q', amount)
        
        # Recipient hash (optional, 8 bytes)
        if recipient_hash:
            if len(recipient_hash) < 8:
                raise MetadataError("Recipient hash must be at least 8 bytes")
            content += recipient_hash[:8]
        
        payload = MetadataPayload(
            metadata_type=MetadataType.ASSET_TRANSFER,
            content=content
        )
        
        return self.create_op_return_output(payload)
    
    def encode_nft_metadata(
        self,
        collection_id: int,
        token_id: int,
        metadata_hash: bytes,
        uri_scheme: str = "ipfs"
    ) -> bytes:
        """
        Encode NFT metadata reference.
        
        Args:
            collection_id: Collection identifier
            token_id: Token identifier within collection
            metadata_hash: Hash of metadata content
            uri_scheme: URI scheme (ipfs, http, arweave, etc.)
            
        Returns:
            OP_RETURN script for NFT metadata
        """
        if len(metadata_hash) != 32:
            raise MetadataError(f"Invalid metadata hash length: {len(metadata_hash)}")
        
        # Build NFT metadata
        content = b''
        
        # Collection ID (8 bytes)
        content += struct.pack('<Q', collection_id)
        
        # Token ID (8 bytes)
        content += struct.pack('<Q', token_id)
        
        # Metadata hash (first 16 bytes to save space)
        content += metadata_hash[:16]
        
        # URI scheme (max 8 bytes)
        scheme_bytes = uri_scheme.encode('utf-8')[:8]
        content += bytes([len(scheme_bytes)])
        content += scheme_bytes
        
        payload = MetadataPayload(
            metadata_type=MetadataType.NFT_METADATA,
            content=content
        )
        
        return self.create_op_return_output(payload)
    
    def encode_uri_reference(self, uri: str, content_hash: Optional[bytes] = None) -> bytes:
        """
        Encode URI reference for external data.
        
        Args:
            uri: URI string (will be truncated if too long)
            content_hash: Optional hash of content at URI
            
        Returns:
            OP_RETURN script for URI reference
        """
        # Build URI reference data
        content = b''
        
        # Content hash (optional, 16 bytes)
        if content_hash:
            if len(content_hash) < 16:
                raise MetadataError("Content hash must be at least 16 bytes")
            content += content_hash[:16]
        else:
            content += b'\x00' * 16
        
        # URI (remaining space)
        remaining_space = MAX_OP_RETURN_SIZE - len(BNAP_PREFIX) - 3 - len(content)
        uri_bytes = uri.encode('utf-8')[:remaining_space]
        content += uri_bytes
        
        payload = MetadataPayload(
            metadata_type=MetadataType.URI_REFERENCE,
            content=content
        )
        
        return self.create_op_return_output(payload)
    
    def encode_commitment(self, commitment_data: bytes, commitment_type: int = 0) -> bytes:
        """
        Encode arbitrary commitment data.
        
        Args:
            commitment_data: Data to commit (will be hashed if too long)
            commitment_type: Type identifier for commitment
            
        Returns:
            OP_RETURN script for commitment
        """
        content = b''
        
        # Commitment type (1 byte)
        content += bytes([commitment_type & 0xFF])
        
        # If data is too large, use hash
        remaining_space = MAX_OP_RETURN_SIZE - len(BNAP_PREFIX) - 3 - 1
        if len(commitment_data) > remaining_space:
            # Use SHA256 hash
            content += hashlib.sha256(commitment_data).digest()
        else:
            # Use raw data
            content += commitment_data
        
        payload = MetadataPayload(
            metadata_type=MetadataType.COMMITMENT,
            content=content
        )
        
        return self.create_op_return_output(payload)
    
    def encode_message(self, message: str, msg_type: str = "text") -> bytes:
        """
        Encode a text message.
        
        Args:
            message: Message text
            msg_type: Message type identifier
            
        Returns:
            OP_RETURN script for message
        """
        content = b''
        
        # Message type (max 4 bytes)
        type_bytes = msg_type.encode('utf-8')[:4]
        content += bytes([len(type_bytes)])
        content += type_bytes
        
        # Message content (remaining space)
        remaining_space = MAX_OP_RETURN_SIZE - len(BNAP_PREFIX) - 3 - len(content)
        message_bytes = message.encode('utf-8')[:remaining_space]
        content += message_bytes
        
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=content
        )
        
        return self.create_op_return_output(payload)


class OpReturnDecoder:
    """
    Decoder for parsing OP_RETURN outputs with BNAP metadata.
    
    This class provides methods to decode and interpret metadata
    from OP_RETURN outputs following the BNAP protocol specification.
    """
    
    def __init__(self):
        """Initialize OP_RETURN decoder."""
        self.prefix = BNAP_PREFIX
    
    def decode_op_return(self, script: bytes) -> Optional[MetadataPayload]:
        """
        Decode OP_RETURN script to metadata payload.
        
        Args:
            script: OP_RETURN script bytes
            
        Returns:
            Decoded metadata payload or None if not BNAP format
        """
        # Extract data from OP_RETURN script
        data = extract_op_return_data(script)
        if not data:
            return None
        
        return self.decode_metadata(data)
    
    def decode_metadata(self, data: bytes) -> Optional[MetadataPayload]:
        """
        Decode raw OP_RETURN data to metadata payload.
        
        Args:
            data: Raw OP_RETURN data
            
        Returns:
            Decoded metadata payload or None if not BNAP format
        """
        # Check minimum length
        if len(data) < len(self.prefix) + 3:
            return None
        
        # Check prefix
        if not data.startswith(self.prefix):
            return None
        
        offset = len(self.prefix)
        
        # Parse header
        version = data[offset]
        offset += 1
        
        try:
            metadata_type = MetadataType(data[offset])
        except ValueError:
            return None
        offset += 1
        
        try:
            compression = CompressionType(data[offset])
        except ValueError:
            compression = CompressionType.NONE
        offset += 1
        
        # Extract content
        content = data[offset:]
        
        return MetadataPayload(
            metadata_type=metadata_type,
            content=content,
            compression=compression,
            version=version
        )
    
    def parse_asset_issuance(self, payload: MetadataPayload) -> Optional[Dict[str, Any]]:
        """
        Parse asset issuance metadata.
        
        Args:
            payload: Metadata payload
            
        Returns:
            Parsed issuance data or None if wrong type
        """
        if payload.metadata_type != MetadataType.ASSET_ISSUANCE:
            return None
        
        content = payload.content
        if len(content) < 17:  # Minimum required bytes
            return None
        
        offset = 0
        
        # Asset ID (8 bytes)
        asset_id_partial = content[offset:offset + 8]
        offset += 8
        
        # Supply (8 bytes)
        supply = struct.unpack('<Q', content[offset:offset + 8])[0]
        offset += 8
        
        # Decimals (1 byte)
        decimals = content[offset]
        offset += 1
        
        # Symbol (optional)
        symbol = None
        if offset < len(content):
            symbol_len = content[offset]
            offset += 1
            if symbol_len > 0 and offset + symbol_len <= len(content):
                symbol = content[offset:offset + symbol_len].decode('utf-8', errors='ignore')
        
        return {
            'asset_id_partial': asset_id_partial.hex(),
            'supply': supply,
            'decimals': decimals,
            'symbol': symbol
        }
    
    def parse_asset_transfer(self, payload: MetadataPayload) -> Optional[Dict[str, Any]]:
        """
        Parse asset transfer metadata.
        
        Args:
            payload: Metadata payload
            
        Returns:
            Parsed transfer data or None if wrong type
        """
        if payload.metadata_type != MetadataType.ASSET_TRANSFER:
            return None
        
        content = payload.content
        if len(content) < 16:  # Minimum required bytes
            return None
        
        offset = 0
        
        # Asset ID (8 bytes)
        asset_id_partial = content[offset:offset + 8]
        offset += 8
        
        # Amount (8 bytes)
        amount = struct.unpack('<Q', content[offset:offset + 8])[0]
        offset += 8
        
        # Recipient hash (optional)
        recipient_hash = None
        if offset + 8 <= len(content):
            recipient_hash = content[offset:offset + 8]
        
        return {
            'asset_id_partial': asset_id_partial.hex(),
            'amount': amount,
            'recipient_hash': recipient_hash.hex() if recipient_hash else None
        }
    
    def parse_nft_metadata(self, payload: MetadataPayload) -> Optional[Dict[str, Any]]:
        """
        Parse NFT metadata reference.
        
        Args:
            payload: Metadata payload
            
        Returns:
            Parsed NFT metadata or None if wrong type
        """
        if payload.metadata_type != MetadataType.NFT_METADATA:
            return None
        
        content = payload.content
        if len(content) < 33:  # Minimum required bytes
            return None
        
        offset = 0
        
        # Collection ID (8 bytes)
        collection_id = struct.unpack('<Q', content[offset:offset + 8])[0]
        offset += 8
        
        # Token ID (8 bytes)
        token_id = struct.unpack('<Q', content[offset:offset + 8])[0]
        offset += 8
        
        # Metadata hash (16 bytes)
        metadata_hash = content[offset:offset + 16]
        offset += 16
        
        # URI scheme
        uri_scheme = None
        if offset < len(content):
            scheme_len = content[offset]
            offset += 1
            if scheme_len > 0 and offset + scheme_len <= len(content):
                uri_scheme = content[offset:offset + scheme_len].decode('utf-8', errors='ignore')
        
        return {
            'collection_id': collection_id,
            'token_id': token_id,
            'metadata_hash': metadata_hash.hex(),
            'uri_scheme': uri_scheme
        }


# Utility functions
def create_asset_issuance_op_return(
    asset_id: str,
    supply: int,
    decimals: int = 8,
    symbol: Optional[str] = None
) -> bytes:
    """
    Create OP_RETURN output for asset issuance.
    
    Args:
        asset_id: Asset identifier
        supply: Total supply
        decimals: Decimal places
        symbol: Asset symbol
        
    Returns:
        OP_RETURN script bytes
    """
    encoder = OpReturnEncoder()
    return encoder.encode_asset_issuance(asset_id, supply, decimals, symbol)


def create_asset_transfer_op_return(
    asset_id: str,
    amount: int,
    recipient_hash: Optional[bytes] = None
) -> bytes:
    """
    Create OP_RETURN output for asset transfer.
    
    Args:
        asset_id: Asset identifier
        amount: Transfer amount
        recipient_hash: Recipient identifier
        
    Returns:
        OP_RETURN script bytes
    """
    encoder = OpReturnEncoder()
    return encoder.encode_asset_transfer(asset_id, amount, recipient_hash)


def create_nft_metadata_op_return(
    collection_id: int,
    token_id: int,
    metadata_hash: bytes,
    uri_scheme: str = "ipfs"
) -> bytes:
    """
    Create OP_RETURN output for NFT metadata.
    
    Args:
        collection_id: Collection ID
        token_id: Token ID
        metadata_hash: Metadata content hash
        uri_scheme: URI scheme
        
    Returns:
        OP_RETURN script bytes
    """
    encoder = OpReturnEncoder()
    return encoder.encode_nft_metadata(collection_id, token_id, metadata_hash, uri_scheme)


def parse_op_return_metadata(script: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse OP_RETURN script to extract metadata.
    
    Args:
        script: OP_RETURN script bytes
        
    Returns:
        Parsed metadata dictionary or None
    """
    decoder = OpReturnDecoder()
    payload = decoder.decode_op_return(script)
    if not payload:
        return None
    
    # Parse based on type
    if payload.metadata_type == MetadataType.ASSET_ISSUANCE:
        data = decoder.parse_asset_issuance(payload)
    elif payload.metadata_type == MetadataType.ASSET_TRANSFER:
        data = decoder.parse_asset_transfer(payload)
    elif payload.metadata_type == MetadataType.NFT_METADATA:
        data = decoder.parse_nft_metadata(payload)
    else:
        # Return raw payload info for other types
        data = {
            'content': payload.content.hex()
        }
    
    if data:
        data['type'] = payload.metadata_type.name
        data['version'] = payload.version
        data['compression'] = payload.compression.name
    
    return data


def validate_op_return_size(data: bytes) -> bool:
    """
    Validate that data fits within OP_RETURN size limit.
    
    Args:
        data: Data to validate
        
    Returns:
        True if valid size, False otherwise
    """
    return len(data) <= MAX_OP_RETURN_SIZE


def parse_op_return_metadata(script_data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse BNAP metadata from OP_RETURN script data.
    
    Args:
        script_data: Raw OP_RETURN script bytes
        
    Returns:
        Dictionary with parsed metadata or None if not BNAP data
    """
    try:
        decoder = OpReturnDecoder()
        return decoder.decode(script_data)
    except Exception:
        return None


def create_asset_transfer_op_return(
    asset_id: str,
    amount: int,
    from_pubkey: Optional[bytes],
    to_pubkey: Optional[bytes],
    metadata_type: MetadataType = MetadataType.ASSET_TRANSFER
) -> bytes:
    """
    Create OP_RETURN script for asset transfer.
    
    Args:
        asset_id: Asset identifier
        amount: Transfer amount
        from_pubkey: Sender public key hash
        to_pubkey: Recipient public key hash
        metadata_type: Type of metadata
        
    Returns:
        OP_RETURN script bytes
    """
    payload = MetadataPayload(
        metadata_type=metadata_type,
        content=_encode_transfer_data(asset_id, amount, from_pubkey, to_pubkey)
    )
    
    encoder = OpReturnEncoder()
    return encoder.create_op_return_output(payload)


def create_nft_transfer_op_return(
    collection_id: int,
    token_id: int,
    from_address: Optional[bytes],
    to_address: Optional[bytes]
) -> bytes:
    """
    Create OP_RETURN script for NFT transfer.
    
    Args:
        collection_id: NFT collection ID
        token_id: NFT token ID
        from_address: Sender address
        to_address: Recipient address
        
    Returns:
        OP_RETURN script bytes
    """
    payload = MetadataPayload(
        metadata_type=MetadataType.NFT_METADATA,
        content=_encode_nft_transfer_data(collection_id, token_id, from_address, to_address)
    )
    
    encoder = OpReturnEncoder()
    return encoder.create_op_return_output(payload)


def _encode_transfer_data(
    asset_id: str, 
    amount: int, 
    from_pubkey: Optional[bytes], 
    to_pubkey: Optional[bytes]
) -> bytes:
    """Encode asset transfer data (compact format)."""
    # More compact encoding to fit in OP_RETURN
    data = struct.pack('<Q', amount)  # Amount as 8-byte little-endian
    
    # Add asset ID hash (first 16 bytes only for compactness)
    asset_hash = hashlib.sha256(asset_id.encode('utf-8')).digest()[:16]
    data += asset_hash
    
    # Add public key hashes if provided (first 10 bytes only for compactness)
    if from_pubkey:
        data += from_pubkey[:10]
    else:
        data += b'\x00' * 10
    
    if to_pubkey:
        data += to_pubkey[:10]
    else:
        data += b'\x00' * 10
    
    # Total: 8 + 16 + 10 + 10 = 44 bytes + overhead should fit in 80 bytes
    return data


def _encode_nft_transfer_data(
    collection_id: int,
    token_id: int,
    from_address: Optional[bytes],
    to_address: Optional[bytes]
) -> bytes:
    """Encode NFT transfer data."""
    data = struct.pack('<QQ', collection_id, token_id)
    
    # Add addresses if provided
    if from_address:
        data += from_address[:20].ljust(20, b'\x00')
    else:
        data += b'\x00' * 20
        
    if to_address:
        data += to_address[:20].ljust(20, b'\x00')
    else:
        data += b'\x00' * 20
    
    return data