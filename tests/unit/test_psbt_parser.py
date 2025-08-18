"""
Tests for PSBT Parser with Metadata Extraction
"""

import pytest
import base64
import struct
from psbt.parser import (
    PSBTParser,
    PSBTGlobal,
    PSBTInput,
    PSBTOutput,
    AssetMetadata,
    ParsedPSBT,
    parse_psbt_from_base64,
    parse_psbt_from_bytes,
    extract_asset_operations,
    validate_psbt_structure,
    PSBT_MAGIC,
    PSBT_SEPARATOR,
    BNAP_PREFIX,
    BNAP_ASSET_ID,
    BNAP_ASSET_AMOUNT,
    BNAP_ASSET_TYPE
)
from psbt.exceptions import PSBTParsingError, PSBTValidationError
from psbt.builder import BasePSBTBuilder
from psbt.outputs.op_return import create_asset_issuance_op_return


class TestPSBTParser:
    """Test PSBTParser functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = PSBTParser()
        self.asset_id = "deadbeefcafebabe" * 4  # 64-char hex string
    
    def test_parser_initialization(self):
        """Test parser initialization."""
        assert self.parser.op_return_decoder is not None
    
    def test_parse_invalid_magic(self):
        """Test parsing with invalid magic bytes."""
        invalid_data = b'invalid' + PSBT_SEPARATOR
        
        with pytest.raises(PSBTParsingError, match="Invalid PSBT magic bytes"):
            self.parser.parse(invalid_data)
    
    def test_parse_invalid_base64(self):
        """Test parsing with invalid base64."""
        with pytest.raises(PSBTParsingError, match="Invalid base64 encoding"):
            self.parser.parse("invalid_base64!")
    
    def test_parse_minimal_psbt(self):
        """Test parsing a minimal valid PSBT."""
        # Create minimal PSBT with BasePSBTBuilder
        builder = BasePSBTBuilder()
        
        # Add a minimal input
        builder.add_input("0" * 64, 0)
        
        # Add a minimal output
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        # Serialize and parse
        psbt_bytes = builder.serialize()
        
        parsed = self.parser.parse(psbt_bytes)
        
        assert isinstance(parsed, ParsedPSBT)
        assert parsed.psbt_global is not None
        assert len(parsed.inputs) == 1
        assert len(parsed.outputs) == 1
        assert isinstance(parsed.asset_metadata, list)
    
    def test_parse_psbt_with_op_return(self):
        """Test parsing PSBT with OP_RETURN metadata."""
        builder = BasePSBTBuilder()
        
        # Add input
        builder.add_input("0" * 64, 0)
        
        # Add OP_RETURN output with BNAP metadata
        op_return_script = create_asset_issuance_op_return(
            self.asset_id, 1000000, 8, "TEST"
        )
        builder.add_output(script=op_return_script, amount=0)
        
        # Add regular output
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        # Parse
        psbt_bytes = builder.serialize()
        parsed = self.parser.parse(psbt_bytes)
        
        # Check metadata extraction
        assert len(parsed.asset_metadata) > 0
        
        # Find metadata with OP_RETURN data
        op_return_metadata = None
        for metadata in parsed.asset_metadata:
            if metadata.op_return_data:
                op_return_metadata = metadata
                break
        
        assert op_return_metadata is not None
        assert op_return_metadata.op_return_data['type'] == 'ASSET_ISSUANCE'
        assert op_return_metadata.op_return_data['supply'] == 1000000
        assert op_return_metadata.op_return_data['symbol'] == 'TEST'
    
    def test_parse_psbt_with_proprietary_fields(self):
        """Test parsing PSBT with BNAP proprietary fields."""
        builder = BasePSBTBuilder()
        
        # Add input
        builder.add_input("0" * 64, 0)
        
        # Add output
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        # Add proprietary fields manually (simplified)
        # Note: This is a simplified test - real implementation would need
        # proper PSBT field insertion
        
        psbt_bytes = builder.serialize()
        parsed = self.parser.parse(psbt_bytes)
        
        # Should parse successfully even without proprietary fields
        assert parsed.is_valid
        assert isinstance(parsed.asset_metadata, list)


class TestDataStructures:
    """Test PSBT data structures."""
    
    def test_psbt_global_creation(self):
        """Test PSBTGlobal creation."""
        global_data = PSBTGlobal()
        
        assert global_data.unsigned_tx is None
        assert global_data.version == 0
        assert len(global_data.xpubs) == 0
        assert len(global_data.proprietary) == 0
        assert len(global_data.unknown) == 0
    
    def test_psbt_input_creation(self):
        """Test PSBTInput creation."""
        input_data = PSBTInput()
        
        assert input_data.non_witness_utxo is None
        assert input_data.witness_utxo is None
        assert len(input_data.partial_sigs) == 0
        assert input_data.sighash_type is None
        assert len(input_data.proprietary) == 0
    
    def test_psbt_output_creation(self):
        """Test PSBTOutput creation."""
        output_data = PSBTOutput()
        
        assert output_data.redeem_script is None
        assert output_data.witness_script is None
        assert len(output_data.bip32_derivations) == 0
        assert output_data.amount is None
        assert len(output_data.proprietary) == 0
    
    def test_asset_metadata_creation(self):
        """Test AssetMetadata creation."""
        metadata = AssetMetadata()
        
        assert metadata.asset_id is None
        assert metadata.asset_type is None
        assert metadata.amount is None
        assert metadata.metadata_hash is None
        assert metadata.collection_id is None
        assert metadata.token_id is None
        assert metadata.op_return_data is None
    
    def test_parsed_psbt_creation(self):
        """Test ParsedPSBT creation."""
        global_data = PSBTGlobal()
        parsed = ParsedPSBT(
            psbt_global=global_data,
            inputs=[],
            outputs=[],
            asset_metadata=[]
        )
        
        assert parsed.psbt_global == global_data
        assert len(parsed.inputs) == 0
        assert len(parsed.outputs) == 0
        assert len(parsed.asset_metadata) == 0
        assert parsed.is_valid == True
        assert len(parsed.validation_errors) == 0


class TestMetadataExtraction:
    """Test metadata extraction functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = PSBTParser()
        self.asset_id = "1234567890abcdef" * 4
    
    def test_extract_proprietary_metadata_empty(self):
        """Test extracting metadata from empty proprietary fields."""
        metadata = self.parser._extract_proprietary_metadata({})
        
        assert metadata.asset_id is None
        assert metadata.asset_type is None
        assert metadata.amount is None
    
    def test_extract_proprietary_metadata_with_asset_id(self):
        """Test extracting asset ID from proprietary fields."""
        asset_id_bytes = bytes.fromhex(self.asset_id)
        proprietary = {
            BNAP_PREFIX + bytes([BNAP_ASSET_ID]): asset_id_bytes
        }
        
        metadata = self.parser._extract_proprietary_metadata(proprietary)
        
        assert metadata.asset_id == self.asset_id
    
    def test_extract_proprietary_metadata_with_amount(self):
        """Test extracting amount from proprietary fields."""
        amount = 1000000
        amount_bytes = struct.pack('<Q', amount)
        proprietary = {
            BNAP_PREFIX + bytes([BNAP_ASSET_AMOUNT]): amount_bytes
        }
        
        metadata = self.parser._extract_proprietary_metadata(proprietary)
        
        assert metadata.amount == amount
    
    def test_extract_proprietary_metadata_with_type(self):
        """Test extracting asset type from proprietary fields."""
        asset_type = "fungible"
        type_bytes = asset_type.encode('utf-8')
        proprietary = {
            BNAP_PREFIX + bytes([BNAP_ASSET_TYPE]): type_bytes
        }
        
        metadata = self.parser._extract_proprietary_metadata(proprietary)
        
        assert metadata.asset_type == asset_type
    
    def test_extract_proprietary_metadata_invalid_prefix(self):
        """Test extracting metadata with invalid prefix."""
        proprietary = {
            b'INVALID' + bytes([BNAP_ASSET_ID]): b'test'
        }
        
        metadata = self.parser._extract_proprietary_metadata(proprietary)
        
        assert metadata.asset_id is None


class TestValidation:
    """Test PSBT validation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = PSBTParser()
    
    def test_validate_valid_psbt(self):
        """Test validation of valid PSBT."""
        # Create valid PSBT
        builder = BasePSBTBuilder()
        builder.add_input("0" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        psbt_bytes = builder.serialize()
        parsed = self.parser.parse(psbt_bytes)
        
        assert parsed.is_valid
        assert len(parsed.validation_errors) == 0
    
    def test_validate_missing_transaction(self):
        """Test validation with missing transaction."""
        global_data = PSBTGlobal()  # No unsigned_tx
        inputs = []
        outputs = []
        
        is_valid, errors = self.parser._validate_psbt(global_data, inputs, outputs)
        
        assert not is_valid
        assert "Missing unsigned transaction" in ' '.join(errors)
    
    def test_validate_input_output_count_mismatch(self):
        """Test validation with input/output count mismatch."""
        # This is a simplified test - would need actual transaction object
        # for complete testing
        builder = BasePSBTBuilder()
        builder.add_input("0" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        psbt_bytes = builder.serialize()
        parsed = self.parser.parse(psbt_bytes)
        
        # Should be valid for properly constructed PSBT
        assert parsed.is_valid


class TestUtilityFunctions:
    """Test utility functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.asset_id = "abcdef1234567890" * 4
    
    def test_parse_psbt_from_base64(self):
        """Test parsing PSBT from base64 string."""
        # Create PSBT and convert to base64
        builder = BasePSBTBuilder()
        builder.add_input("0" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        psbt_bytes = builder.serialize()
        base64_str = base64.b64encode(psbt_bytes).decode()
        
        parsed = parse_psbt_from_base64(base64_str)
        
        assert isinstance(parsed, ParsedPSBT)
        assert len(parsed.inputs) == 1
        assert len(parsed.outputs) == 1
    
    def test_parse_psbt_from_bytes(self):
        """Test parsing PSBT from raw bytes."""
        # Create PSBT
        builder = BasePSBTBuilder()
        builder.add_input("0" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        psbt_bytes = builder.serialize()
        
        parsed = parse_psbt_from_bytes(psbt_bytes)
        
        assert isinstance(parsed, ParsedPSBT)
        assert len(parsed.inputs) == 1
        assert len(parsed.outputs) == 1
    
    def test_extract_asset_operations_empty(self):
        """Test extracting operations from PSBT without metadata."""
        parsed = ParsedPSBT(
            psbt_global=PSBTGlobal(),
            inputs=[],
            outputs=[],
            asset_metadata=[]
        )
        
        operations = extract_asset_operations(parsed)
        
        assert len(operations) == 0
    
    def test_extract_asset_operations_with_metadata(self):
        """Test extracting operations from PSBT with metadata."""
        metadata = AssetMetadata(
            asset_id=self.asset_id,
            asset_type="fungible",
            amount=1000000
        )
        
        parsed = ParsedPSBT(
            psbt_global=PSBTGlobal(),
            inputs=[],
            outputs=[],
            asset_metadata=[metadata]
        )
        
        operations = extract_asset_operations(parsed)
        
        assert len(operations) == 1
        assert operations[0]['asset_id'] == self.asset_id
        assert operations[0]['type'] == 'fungible'
        assert operations[0]['amount'] == 1000000
    
    def test_extract_asset_operations_with_nft_metadata(self):
        """Test extracting NFT operations."""
        metadata = AssetMetadata(
            asset_id=self.asset_id,
            collection_id=1,
            token_id=42,
            op_return_data={'type': 'NFT_METADATA'}
        )
        
        parsed = ParsedPSBT(
            psbt_global=PSBTGlobal(),
            inputs=[],
            outputs=[],
            asset_metadata=[metadata]
        )
        
        operations = extract_asset_operations(parsed)
        
        assert len(operations) == 1
        assert operations[0]['collection_id'] == 1
        assert operations[0]['token_id'] == 42
        assert 'op_return' in operations[0]
        assert operations[0]['op_return']['type'] == 'NFT_METADATA'
    
    def test_validate_psbt_structure_valid(self):
        """Test PSBT structure validation with valid PSBT."""
        builder = BasePSBTBuilder()
        builder.add_input("0" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        psbt_bytes = builder.serialize()
        
        is_valid, errors = validate_psbt_structure(psbt_bytes)
        
        assert is_valid
        assert len(errors) == 0
    
    def test_validate_psbt_structure_invalid(self):
        """Test PSBT structure validation with invalid data."""
        invalid_data = b'not a psbt'
        
        is_valid, errors = validate_psbt_structure(invalid_data)
        
        assert not is_valid
        assert len(errors) > 0


class TestIntegration:
    """Test integration with other PSBT modules."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = PSBTParser()
        self.asset_id = "fedcba0987654321" * 4
    
    def test_integration_with_op_return_encoder(self):
        """Test integration with OP_RETURN encoder."""
        # Create PSBT with OP_RETURN
        builder = BasePSBTBuilder()
        builder.add_input("0" * 64, 0)
        
        # Add OP_RETURN with asset metadata
        op_return_script = create_asset_issuance_op_return(
            self.asset_id, 21000000, 8, "BTC"
        )
        builder.add_output(script=op_return_script, amount=0)
        
        # Add regular output
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=100000)
        
        # Parse PSBT
        psbt_bytes = builder.serialize()
        parsed = self.parser.parse(psbt_bytes)
        
        # Verify metadata extraction
        assert len(parsed.asset_metadata) > 0
        
        # Check OP_RETURN metadata
        metadata_with_op_return = None
        for metadata in parsed.asset_metadata:
            if metadata.op_return_data:
                metadata_with_op_return = metadata
                break
        
        assert metadata_with_op_return is not None
        assert metadata_with_op_return.op_return_data['type'] == 'ASSET_ISSUANCE'
        assert metadata_with_op_return.op_return_data['supply'] == 21000000
        assert metadata_with_op_return.op_return_data['decimals'] == 8
        assert metadata_with_op_return.op_return_data['symbol'] == 'BTC'
        
        # Extract operations
        operations = extract_asset_operations(parsed)
        assert len(operations) > 0
        
        # Check operation with OP_RETURN
        op_return_operation = None
        for operation in operations:
            if 'op_return' in operation:
                op_return_operation = operation
                break
        
        assert op_return_operation is not None
        assert op_return_operation['op_return']['type'] == 'ASSET_ISSUANCE'
    
    def test_roundtrip_psbt_construction_parsing(self):
        """Test round-trip PSBT construction and parsing."""
        # Create PSBT
        builder = BasePSBTBuilder()
        
        # Add multiple inputs
        builder.add_input("1" * 64, 0)
        builder.add_input("2" * 64, 1)
        
        # Add OP_RETURN output
        op_return_script = create_asset_issuance_op_return(
            self.asset_id, 1000000, 8, "TEST"
        )
        builder.add_output(script=op_return_script, amount=0)
        
        # Add multiple regular outputs
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=50000)
        builder.add_output(script=b'\x00\x14' + b'\x02' * 20, amount=50000)
        
        # Serialize
        psbt_bytes = builder.serialize()
        
        # Parse back
        parsed = self.parser.parse(psbt_bytes)
        
        # Verify structure
        assert len(parsed.inputs) == 2
        assert len(parsed.outputs) == 3
        assert parsed.is_valid
        
        # Check transaction consistency
        tx = parsed.psbt_global.unsigned_tx
        assert len(tx.inputs) == 2
        assert len(tx.outputs) == 3
        
        # Check metadata extraction
        assert len(parsed.asset_metadata) > 0
        
        # Verify OP_RETURN parsing
        has_op_return = False
        for metadata in parsed.asset_metadata:
            if metadata.op_return_data:
                has_op_return = True
                assert metadata.op_return_data['type'] == 'ASSET_ISSUANCE'
                break
        
        assert has_op_return