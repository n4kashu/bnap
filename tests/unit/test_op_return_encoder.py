"""
Tests for OP_RETURN Metadata Encoder Module
"""

import pytest
import hashlib
from psbt.outputs.op_return import (
    OpReturnEncoder,
    OpReturnDecoder,
    MetadataPayload,
    MetadataType,
    CompressionType,
    BNAP_PREFIX,
    BNAP_VERSION,
    MAX_OP_RETURN_SIZE,
    create_asset_issuance_op_return,
    create_asset_transfer_op_return,
    create_nft_metadata_op_return,
    parse_op_return_metadata,
    validate_op_return_size
)
from psbt.exceptions import MetadataError


class TestMetadataPayload:
    """Test MetadataPayload dataclass."""
    
    def test_valid_payload(self):
        """Test creating valid metadata payload."""
        payload = MetadataPayload(
            metadata_type=MetadataType.ASSET_ISSUANCE,
            content=b'test content',
            compression=CompressionType.NONE,
            version=BNAP_VERSION
        )
        
        assert payload.metadata_type == MetadataType.ASSET_ISSUANCE
        assert payload.content == b'test content'
        assert payload.compression == CompressionType.NONE
        assert payload.version == BNAP_VERSION
    
    def test_payload_empty_content(self):
        """Test payload with empty content."""
        with pytest.raises(MetadataError, match="Content cannot be empty"):
            MetadataPayload(
                metadata_type=MetadataType.ASSET_ISSUANCE,
                content=b''
            )
    
    def test_payload_content_too_large(self):
        """Test payload with content exceeding size limit."""
        large_content = b'x' * (MAX_OP_RETURN_SIZE - 6)  # Subtract overhead
        
        with pytest.raises(MetadataError, match="Content too large"):
            MetadataPayload(
                metadata_type=MetadataType.ASSET_ISSUANCE,
                content=large_content
            )
    
    def test_payload_invalid_content_type(self):
        """Test payload with non-bytes content."""
        with pytest.raises(MetadataError, match="Content must be bytes"):
            MetadataPayload(
                metadata_type=MetadataType.ASSET_ISSUANCE,
                content="string content"  # Should be bytes
            )


class TestOpReturnEncoder:
    """Test OpReturnEncoder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encoder = OpReturnEncoder()
        self.asset_id = "deadbeefcafebabe" * 4  # 64-char hex string
    
    def test_encoder_initialization(self):
        """Test encoder initialization."""
        assert self.encoder.prefix == BNAP_PREFIX
        assert self.encoder.version == BNAP_VERSION
    
    def test_encode_metadata_basic(self):
        """Test basic metadata encoding."""
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=b'Hello BNAP'
        )
        
        data = self.encoder.encode_metadata(payload)
        
        # Check structure
        assert data.startswith(BNAP_PREFIX)
        assert data[4] == BNAP_VERSION
        assert data[5] == MetadataType.MESSAGE.value
        assert data[6] == CompressionType.NONE.value
        assert b'Hello BNAP' in data
    
    def test_encode_metadata_size_limit(self):
        """Test metadata encoding with size limit."""
        # Create content at exact limit
        overhead = len(BNAP_PREFIX) + 3  # prefix + version + type + compression
        content = b'x' * (MAX_OP_RETURN_SIZE - overhead)
        
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=content
        )
        
        data = self.encoder.encode_metadata(payload)
        assert len(data) == MAX_OP_RETURN_SIZE
    
    def test_create_op_return_output(self):
        """Test creating complete OP_RETURN output."""
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=b'Test'
        )
        
        script = self.encoder.create_op_return_output(payload)
        
        # Should start with OP_RETURN opcode
        assert script[0] == 0x6a  # OP_RETURN
        assert BNAP_PREFIX in script
    
    def test_encode_asset_issuance(self):
        """Test encoding asset issuance metadata."""
        script = self.encoder.encode_asset_issuance(
            self.asset_id,
            supply=1000000,
            decimals=8,
            symbol="TEST"
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        assert BNAP_PREFIX in script
        
        # Extract and verify encoded data
        data = script[2:]  # Skip OP_RETURN and length byte
        assert data[5] == MetadataType.ASSET_ISSUANCE.value
    
    def test_encode_asset_issuance_no_symbol(self):
        """Test asset issuance without symbol."""
        script = self.encoder.encode_asset_issuance(
            self.asset_id,
            supply=1000000,
            decimals=8
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        assert len(script) <= MAX_OP_RETURN_SIZE + 2  # +2 for opcode and length
    
    def test_encode_asset_issuance_invalid_asset_id(self):
        """Test asset issuance with invalid asset ID."""
        with pytest.raises(MetadataError, match="Invalid asset ID format"):
            self.encoder.encode_asset_issuance(
                "not_hex",
                supply=1000000
            )
    
    def test_encode_asset_issuance_wrong_length_asset_id(self):
        """Test asset issuance with wrong length asset ID."""
        with pytest.raises(MetadataError, match="Invalid asset ID length"):
            self.encoder.encode_asset_issuance(
                "deadbeef",  # Too short
                supply=1000000
            )
    
    def test_encode_asset_transfer(self):
        """Test encoding asset transfer metadata."""
        recipient_hash = hashlib.sha256(b'recipient').digest()
        
        script = self.encoder.encode_asset_transfer(
            self.asset_id,
            amount=500,
            recipient_hash=recipient_hash
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        data = script[2:]
        assert data[5] == MetadataType.ASSET_TRANSFER.value
    
    def test_encode_asset_transfer_no_recipient(self):
        """Test asset transfer without recipient hash."""
        script = self.encoder.encode_asset_transfer(
            self.asset_id,
            amount=500
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        assert len(script) <= MAX_OP_RETURN_SIZE + 2
    
    def test_encode_asset_transfer_short_recipient_hash(self):
        """Test asset transfer with short recipient hash."""
        with pytest.raises(MetadataError, match="Recipient hash must be at least 8 bytes"):
            self.encoder.encode_asset_transfer(
                self.asset_id,
                amount=500,
                recipient_hash=b'short'
            )
    
    def test_encode_nft_metadata(self):
        """Test encoding NFT metadata reference."""
        metadata_hash = hashlib.sha256(b'nft metadata').digest()
        
        script = self.encoder.encode_nft_metadata(
            collection_id=1,
            token_id=100,
            metadata_hash=metadata_hash,
            uri_scheme="ipfs"
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        data = script[2:]
        assert data[5] == MetadataType.NFT_METADATA.value
        assert b'ipfs' in data
    
    def test_encode_nft_metadata_invalid_hash_length(self):
        """Test NFT metadata with invalid hash length."""
        with pytest.raises(MetadataError, match="Invalid metadata hash length"):
            self.encoder.encode_nft_metadata(
                collection_id=1,
                token_id=100,
                metadata_hash=b'short_hash'
            )
    
    def test_encode_uri_reference(self):
        """Test encoding URI reference."""
        content_hash = hashlib.sha256(b'content').digest()
        
        script = self.encoder.encode_uri_reference(
            "https://example.com/data.json",
            content_hash=content_hash
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        data = script[2:]
        assert data[5] == MetadataType.URI_REFERENCE.value
        assert b'example.com' in data
    
    def test_encode_uri_reference_no_hash(self):
        """Test URI reference without content hash."""
        script = self.encoder.encode_uri_reference(
            "https://example.com/data.json"
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        assert b'example.com' in script
    
    def test_encode_uri_reference_long_uri(self):
        """Test URI reference with long URI (should truncate)."""
        long_uri = "https://example.com/" + "x" * 100
        
        script = self.encoder.encode_uri_reference(long_uri)
        
        assert script[0] == 0x6a  # OP_RETURN
        # Script should be truncated to fit within limit
        # The data portion (after OP_RETURN and length byte) should be <= 80 bytes
        data_portion = script[2:] if script[1] <= 75 else script[3:]
        assert len(data_portion) <= MAX_OP_RETURN_SIZE
    
    def test_encode_commitment(self):
        """Test encoding commitment data."""
        commitment_data = b'important data to commit'
        
        script = self.encoder.encode_commitment(
            commitment_data,
            commitment_type=1
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        data = script[2:]
        assert data[5] == MetadataType.COMMITMENT.value
        assert commitment_data in data
    
    def test_encode_commitment_large_data(self):
        """Test commitment with large data (should hash)."""
        large_data = b'x' * 100
        
        script = self.encoder.encode_commitment(large_data)
        
        assert script[0] == 0x6a  # OP_RETURN
        data = script[2:]
        
        # Should contain hash instead of raw data
        expected_hash = hashlib.sha256(large_data).digest()
        assert expected_hash in data
        assert large_data not in data
    
    def test_encode_message(self):
        """Test encoding text message."""
        script = self.encoder.encode_message(
            "Hello Bitcoin!",
            msg_type="text"
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        data = script[2:]
        assert data[5] == MetadataType.MESSAGE.value
        assert b'text' in data
        assert b'Hello Bitcoin!' in data
    
    def test_encode_message_long_text(self):
        """Test message with long text (should truncate)."""
        long_message = "x" * 100
        
        script = self.encoder.encode_message(long_message)
        
        assert script[0] == 0x6a  # OP_RETURN
        # Data portion should be <= 80 bytes
        data_portion = script[2:] if script[1] <= 75 else script[3:]
        assert len(data_portion) <= MAX_OP_RETURN_SIZE


class TestOpReturnDecoder:
    """Test OpReturnDecoder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encoder = OpReturnEncoder()
        self.decoder = OpReturnDecoder()
        self.asset_id = "deadbeefcafebabe" * 4
    
    def test_decoder_initialization(self):
        """Test decoder initialization."""
        assert self.decoder.prefix == BNAP_PREFIX
    
    def test_decode_metadata_valid(self):
        """Test decoding valid metadata."""
        # Encode first
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=b'Test message'
        )
        data = self.encoder.encode_metadata(payload)
        
        # Decode
        decoded = self.decoder.decode_metadata(data)
        
        assert decoded is not None
        assert decoded.metadata_type == MetadataType.MESSAGE
        assert decoded.content == b'Test message'
        assert decoded.compression == CompressionType.NONE
        assert decoded.version == BNAP_VERSION
    
    def test_decode_metadata_invalid_prefix(self):
        """Test decoding with invalid prefix."""
        data = b'INVALID' + bytes([BNAP_VERSION, 0x01, 0x00]) + b'content'
        
        decoded = self.decoder.decode_metadata(data)
        assert decoded is None
    
    def test_decode_metadata_too_short(self):
        """Test decoding data that's too short."""
        data = b'BN'  # Too short
        
        decoded = self.decoder.decode_metadata(data)
        assert decoded is None
    
    def test_decode_op_return_script(self):
        """Test decoding complete OP_RETURN script."""
        # Create OP_RETURN script
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=b'Test'
        )
        script = self.encoder.create_op_return_output(payload)
        
        # Decode
        decoded = self.decoder.decode_op_return(script)
        
        assert decoded is not None
        assert decoded.metadata_type == MetadataType.MESSAGE
        assert decoded.content == b'Test'
    
    def test_parse_asset_issuance(self):
        """Test parsing asset issuance metadata."""
        # Encode
        script = self.encoder.encode_asset_issuance(
            self.asset_id,
            supply=1000000,
            decimals=8,
            symbol="TEST"
        )
        
        # Decode and parse
        payload = self.decoder.decode_op_return(script)
        data = self.decoder.parse_asset_issuance(payload)
        
        assert data is not None
        assert 'asset_id_partial' in data
        assert data['supply'] == 1000000
        assert data['decimals'] == 8
        assert data['symbol'] == "TEST"
    
    def test_parse_asset_issuance_wrong_type(self):
        """Test parsing with wrong metadata type."""
        payload = MetadataPayload(
            metadata_type=MetadataType.MESSAGE,
            content=b'not issuance'
        )
        
        data = self.decoder.parse_asset_issuance(payload)
        assert data is None
    
    def test_parse_asset_transfer(self):
        """Test parsing asset transfer metadata."""
        recipient_hash = hashlib.sha256(b'recipient').digest()
        
        # Encode
        script = self.encoder.encode_asset_transfer(
            self.asset_id,
            amount=500,
            recipient_hash=recipient_hash
        )
        
        # Decode and parse
        payload = self.decoder.decode_op_return(script)
        data = self.decoder.parse_asset_transfer(payload)
        
        assert data is not None
        assert 'asset_id_partial' in data
        assert data['amount'] == 500
        assert data['recipient_hash'] is not None
    
    def test_parse_nft_metadata(self):
        """Test parsing NFT metadata reference."""
        metadata_hash = hashlib.sha256(b'nft metadata').digest()
        
        # Encode
        script = self.encoder.encode_nft_metadata(
            collection_id=1,
            token_id=100,
            metadata_hash=metadata_hash,
            uri_scheme="ipfs"
        )
        
        # Decode and parse
        payload = self.decoder.decode_op_return(script)
        data = self.decoder.parse_nft_metadata(payload)
        
        assert data is not None
        assert data['collection_id'] == 1
        assert data['token_id'] == 100
        assert 'metadata_hash' in data
        assert data['uri_scheme'] == "ipfs"


class TestUtilityFunctions:
    """Test utility functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.asset_id = "deadbeefcafebabe" * 4
    
    def test_create_asset_issuance_op_return(self):
        """Test standalone asset issuance function."""
        script = create_asset_issuance_op_return(
            self.asset_id,
            supply=1000000,
            decimals=8,
            symbol="TEST"
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        assert BNAP_PREFIX in script
    
    def test_create_asset_transfer_op_return(self):
        """Test standalone asset transfer function."""
        script = create_asset_transfer_op_return(
            self.asset_id,
            amount=500
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        assert len(script) <= MAX_OP_RETURN_SIZE + 2
    
    def test_create_nft_metadata_op_return(self):
        """Test standalone NFT metadata function."""
        metadata_hash = hashlib.sha256(b'metadata').digest()
        
        script = create_nft_metadata_op_return(
            collection_id=1,
            token_id=100,
            metadata_hash=metadata_hash
        )
        
        assert script[0] == 0x6a  # OP_RETURN
        assert len(script) <= MAX_OP_RETURN_SIZE + 2
    
    def test_parse_op_return_metadata(self):
        """Test parsing OP_RETURN metadata."""
        # Create issuance script
        script = create_asset_issuance_op_return(
            self.asset_id,
            supply=1000000,
            decimals=8,
            symbol="TEST"
        )
        
        # Parse
        data = parse_op_return_metadata(script)
        
        assert data is not None
        assert data['type'] == 'ASSET_ISSUANCE'
        assert data['version'] == BNAP_VERSION
        assert data['compression'] == 'NONE'
        assert data['supply'] == 1000000
        assert data['decimals'] == 8
        assert data['symbol'] == "TEST"
    
    def test_parse_op_return_metadata_invalid(self):
        """Test parsing invalid OP_RETURN."""
        # Invalid script
        script = b'\x6a\x04test'  # OP_RETURN with non-BNAP data
        
        data = parse_op_return_metadata(script)
        assert data is None
    
    def test_validate_op_return_size(self):
        """Test OP_RETURN size validation."""
        # Valid size
        assert validate_op_return_size(b'x' * 80) == True
        
        # Exactly at limit
        assert validate_op_return_size(b'x' * MAX_OP_RETURN_SIZE) == True
        
        # Too large
        assert validate_op_return_size(b'x' * (MAX_OP_RETURN_SIZE + 1)) == False


class TestRoundTrip:
    """Test encoding and decoding round trips."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encoder = OpReturnEncoder()
        self.decoder = OpReturnDecoder()
        self.asset_id = "deadbeefcafebabe" * 4
    
    def test_roundtrip_asset_issuance(self):
        """Test round trip for asset issuance."""
        # Encode
        script = self.encoder.encode_asset_issuance(
            self.asset_id,
            supply=1000000,
            decimals=8,
            symbol="TEST"
        )
        
        # Decode
        payload = self.decoder.decode_op_return(script)
        data = self.decoder.parse_asset_issuance(payload)
        
        # Verify
        assert data['supply'] == 1000000
        assert data['decimals'] == 8
        assert data['symbol'] == "TEST"
    
    def test_roundtrip_asset_transfer(self):
        """Test round trip for asset transfer."""
        recipient_hash = hashlib.sha256(b'recipient').digest()
        
        # Encode
        script = self.encoder.encode_asset_transfer(
            self.asset_id,
            amount=500,
            recipient_hash=recipient_hash
        )
        
        # Decode
        payload = self.decoder.decode_op_return(script)
        data = self.decoder.parse_asset_transfer(payload)
        
        # Verify
        assert data['amount'] == 500
        assert data['recipient_hash'] == recipient_hash[:8].hex()
    
    def test_roundtrip_nft_metadata(self):
        """Test round trip for NFT metadata."""
        metadata_hash = hashlib.sha256(b'nft metadata').digest()
        
        # Encode
        script = self.encoder.encode_nft_metadata(
            collection_id=1,
            token_id=100,
            metadata_hash=metadata_hash,
            uri_scheme="ipfs"
        )
        
        # Decode
        payload = self.decoder.decode_op_return(script)
        data = self.decoder.parse_nft_metadata(payload)
        
        # Verify
        assert data['collection_id'] == 1
        assert data['token_id'] == 100
        assert data['metadata_hash'] == metadata_hash[:16].hex()
        assert data['uri_scheme'] == "ipfs"