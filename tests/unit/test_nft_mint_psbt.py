"""
Tests for NFT Mint PSBT Construction
"""

import pytest
import struct
import json
from psbt.nft_mint import (
    NFTMintPSBTBuilder, 
    NFTMintParameters, 
    NFTMetadata, 
    MetadataScheme
)
from psbt.exceptions import PSBTConstructionError, AssetMetadataError, InsufficientFundsError
from psbt.utils import validate_asset_id


class TestNFTMetadata:
    """Test NFTMetadata validation."""
    
    def test_valid_metadata(self):
        """Test valid NFT metadata."""
        metadata = NFTMetadata(
            name="Test NFT",
            description="A test NFT for unit testing",
            image_uri="ipfs://QmTest123456789",
            attributes={"rarity": "common", "level": 1},
            external_url="https://example.com/nft/1",
            content_hash="a" * 64
        )
        assert metadata.name == "Test NFT"
        assert metadata.description == "A test NFT for unit testing"
        assert metadata.attributes["rarity"] == "common"
        assert metadata.attributes["level"] == 1


class TestNFTMintParameters:
    """Test NFTMintParameters validation."""
    
    def test_valid_parameters(self):
        """Test valid mint parameters."""
        metadata = NFTMetadata(name="Test NFT")
        params = NFTMintParameters(
            collection_id="a" * 64,
            token_id=1,
            metadata=metadata,
            recipient_script=bytes([0x00, 0x14]) + bytes(20),
            fee_rate=2
        )
        assert params.collection_id == "a" * 64
        assert params.token_id == 1
        assert params.metadata.name == "Test NFT"
        assert params.fee_rate == 2
    
    def test_invalid_collection_id(self):
        """Test invalid collection ID."""
        metadata = NFTMetadata(name="Test NFT")
        
        with pytest.raises(AssetMetadataError, match="Invalid collection ID format"):
            NFTMintParameters(
                collection_id="invalid",
                token_id=1,
                metadata=metadata,
                recipient_script=bytes(22)
            )
    
    def test_invalid_token_id_negative(self):
        """Test negative token ID."""
        metadata = NFTMetadata(name="Test NFT")
        
        with pytest.raises(AssetMetadataError, match="Token ID must be"):
            NFTMintParameters(
                collection_id="a" * 64,
                token_id=-1,
                metadata=metadata,
                recipient_script=bytes(22)
            )
    
    def test_invalid_token_id_excessive(self):
        """Test excessive token ID."""
        metadata = NFTMetadata(name="Test NFT")
        
        with pytest.raises(AssetMetadataError, match="Token ID must be"):
            NFTMintParameters(
                collection_id="a" * 64,
                token_id=2**64,  # Exceeds maximum
                metadata=metadata,
                recipient_script=bytes(22)
            )
    
    def test_both_address_and_script(self):
        """Test both address and script specified."""
        metadata = NFTMetadata(name="Test NFT")
        
        with pytest.raises(AssetMetadataError, match="Cannot specify both"):
            NFTMintParameters(
                collection_id="a" * 64,
                token_id=1,
                metadata=metadata,
                recipient_address="bc1qaddress",
                recipient_script=bytes(22)
            )
    
    def test_neither_address_nor_script(self):
        """Test neither address nor script specified."""
        metadata = NFTMetadata(name="Test NFT")
        
        with pytest.raises(AssetMetadataError, match="Must specify either"):
            NFTMintParameters(
                collection_id="a" * 64,
                token_id=1,
                metadata=metadata
            )


class TestNFTMintPSBTBuilder:
    """Test NFTMintPSBTBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = NFTMintPSBTBuilder()
        self.collection_id = "1234567890abcdef" * 4
        self.token_id = 42
        self.recipient_script = bytes([0x00, 0x14]) + bytes(20)  # P2WPKH
        
        self.metadata = NFTMetadata(
            name="Awesome NFT #42",
            description="A truly awesome NFT from the test collection",
            image_uri="ipfs://QmTest123456789abcdef",
            attributes={"rarity": "legendary", "power": 9000},
            external_url="https://example.com/nft/42",
            content_hash="b" * 64
        )
        
        self.params = NFTMintParameters(
            collection_id=self.collection_id,
            token_id=self.token_id,
            metadata=self.metadata,
            metadata_uri="ipfs://QmMetadata123456789",
            content_uri="ipfs://QmContent123456789",
            recipient_script=self.recipient_script,
            fee_rate=1
        )
    
    def test_initialization(self):
        """Test builder initialization."""
        assert self.builder.version == 2
        assert self.builder.locktime == 0
        assert self.builder.mint_params is None
        assert self.builder.validator_input_index is None
        assert self.builder.nft_output_index is None
        assert self.builder.metadata_output_index is None
    
    def test_set_mint_parameters_valid(self):
        """Test setting valid mint parameters."""
        self.builder.set_mint_parameters(self.params)
        assert self.builder.mint_params == self.params
    
    def test_add_validator_input(self):
        """Test adding validator input."""
        self.builder.set_mint_parameters(self.params)
        
        validator_script = b'nft_validator_script_data'
        validator_amount = 100000000  # 1 BTC
        
        self.builder.add_validator_input(
            txid="b" * 64,
            vout=1,
            validator_script=validator_script,
            utxo_amount=validator_amount
        )
        
        assert self.builder.validator_input_index == 0
        assert len(self.builder.inputs) == 1
        assert len(self.builder.psbt_inputs) == 1
        
        # Check input details
        assert self.builder.inputs[0].prev_txid == "b" * 64
        assert self.builder.inputs[0].output_n == 1
        
        # Check proprietary fields
        psbt_input = self.builder.psbt_inputs[0]
        assert self.builder.COLLECTION_ID_KEY in psbt_input.proprietary
        assert self.builder.TOKEN_ID_KEY in psbt_input.proprietary
        assert self.builder.ASSET_TYPE_KEY in psbt_input.proprietary
        assert psbt_input.proprietary[self.builder.ASSET_TYPE_KEY] == b'NFT'
        
        # Verify token ID encoding
        token_id_bytes = psbt_input.proprietary[self.builder.TOKEN_ID_KEY]
        assert struct.unpack('<Q', token_id_bytes)[0] == self.token_id
    
    def test_add_validator_input_without_params_fails(self):
        """Test adding validator input without parameters fails."""
        with pytest.raises(PSBTConstructionError, match="Mint parameters must be set first"):
            self.builder.add_validator_input(
                txid="b" * 64,
                vout=1,
                validator_script=b'script',
                utxo_amount=100000000
            )
    
    def test_add_validator_input_twice_fails(self):
        """Test that adding validator input twice fails."""
        self.builder.set_mint_parameters(self.params)
        
        self.builder.add_validator_input(
            txid="b" * 64,
            vout=1,
            validator_script=b'script',
            utxo_amount=100000000
        )
        
        with pytest.raises(PSBTConstructionError, match="Validator input already added"):
            self.builder.add_validator_input(
                txid="c" * 64,
                vout=0,
                validator_script=b'script2',
                utxo_amount=50000000
            )
    
    def test_add_nft_output(self):
        """Test adding NFT output."""
        self.builder.set_mint_parameters(self.params)
        
        self.builder.add_nft_output()
        
        assert self.builder.nft_output_index == 0
        assert len(self.builder.outputs) == 1
        assert len(self.builder.psbt_outputs) == 1
        
        # Check output details
        output = self.builder.outputs[0]
        assert output.value == self.builder.NFT_OUTPUT_AMOUNT
        assert output.script == self.recipient_script
        
        # Check proprietary fields
        psbt_output = self.builder.psbt_outputs[0]
        assert self.builder.COLLECTION_ID_KEY in psbt_output.proprietary
        assert self.builder.TOKEN_ID_KEY in psbt_output.proprietary
        assert self.builder.ASSET_TYPE_KEY in psbt_output.proprietary
        assert self.builder.METADATA_URI_KEY in psbt_output.proprietary
        assert self.builder.CONTENT_URI_KEY in psbt_output.proprietary
        assert self.builder.CONTENT_HASH_KEY in psbt_output.proprietary
        assert self.builder.METADATA_JSON_KEY in psbt_output.proprietary
        
        # Verify URIs
        metadata_uri = psbt_output.proprietary[self.builder.METADATA_URI_KEY].decode('utf-8')
        assert metadata_uri == self.params.metadata_uri
        
        content_uri = psbt_output.proprietary[self.builder.CONTENT_URI_KEY].decode('utf-8')
        assert content_uri == self.params.content_uri
        
        # Verify content hash
        content_hash = psbt_output.proprietary[self.builder.CONTENT_HASH_KEY]
        assert content_hash == bytes.fromhex(self.metadata.content_hash)
        
        # Verify metadata JSON
        metadata_json = psbt_output.proprietary[self.builder.METADATA_JSON_KEY].decode('utf-8')
        parsed_metadata = json.loads(metadata_json)
        assert parsed_metadata["name"] == self.metadata.name
        assert parsed_metadata["token_id"] == self.token_id
        assert parsed_metadata["collection_id"] == self.collection_id
    
    def test_add_nft_output_without_params_fails(self):
        """Test that adding NFT output without parameters fails."""
        with pytest.raises(PSBTConstructionError, match="Mint parameters not set"):
            self.builder.add_nft_output()
    
    def test_add_nft_output_twice_fails(self):
        """Test that adding NFT output twice fails."""
        self.builder.set_mint_parameters(self.params)
        
        self.builder.add_nft_output()
        
        with pytest.raises(PSBTConstructionError, match="NFT output already added"):
            self.builder.add_nft_output()
    
    def test_add_metadata_output(self):
        """Test adding metadata output."""
        self.builder.set_mint_parameters(self.params)
        
        self.builder.add_metadata_output()
        
        assert self.builder.metadata_output_index == 0
        assert len(self.builder.outputs) == 1
        
        # Check output details
        output = self.builder.outputs[0]
        assert output.value == 0  # OP_RETURN has 0 value
        
        # Check script is OP_RETURN
        script = output.script
        assert script[0] == 0x6a  # OP_RETURN opcode
        
        # Verify metadata contains protocol identifier
        from psbt.utils import extract_op_return_data
        metadata = extract_op_return_data(script)
        assert metadata.startswith(b'BNAP')
        assert b'NFT' in metadata
        
        # Verify collection ID and token ID are in metadata
        collection_id_bytes = bytes.fromhex(self.collection_id)[:16]
        assert collection_id_bytes in metadata
        
        token_id_bytes = struct.pack('<Q', self.token_id)
        assert token_id_bytes in metadata
    
    def test_add_metadata_output_without_params_fails(self):
        """Test that adding metadata output without parameters fails."""
        with pytest.raises(PSBTConstructionError, match="Mint parameters not set"):
            self.builder.add_metadata_output()
    
    def test_add_metadata_output_twice_fails(self):
        """Test that adding metadata output twice fails."""
        self.builder.set_mint_parameters(self.params)
        
        self.builder.add_metadata_output()
        
        with pytest.raises(PSBTConstructionError, match="Metadata output already added"):
            self.builder.add_metadata_output()
    
    def test_add_change_output(self):
        """Test adding change output."""
        self.builder.set_mint_parameters(self.params)
        
        change_amount = 50000000  # 0.5 BTC
        self.builder.add_change_output(change_amount)
        
        assert len(self.builder.outputs) == 1
        
        # Check output details
        output = self.builder.outputs[0]
        assert output.value == change_amount
    
    def test_add_change_output_dust_ignored(self):
        """Test that dust change amounts are ignored."""
        self.builder.set_mint_parameters(self.params)
        
        dust_amount = 500  # Below minimum dust threshold
        self.builder.add_change_output(dust_amount)
        
        # Should not create output for dust amounts
        assert len(self.builder.outputs) == 0
    
    def test_build_mint_transaction_complete(self):
        """Test building complete NFT mint transaction."""
        self.builder.set_mint_parameters(self.params)
        
        validator_script = b'mock_nft_validator_script'
        validator_amount = 100000000  # 1 BTC
        
        self.builder.build_mint_transaction(
            validator_txid="c" * 64,
            validator_vout=0,
            validator_script=validator_script,
            validator_amount=validator_amount,
            fee_amount=10000  # 0.0001 BTC
        )
        
        # Check transaction structure
        assert len(self.builder.inputs) == 1
        assert len(self.builder.outputs) >= 2  # NFT + metadata, possibly change
        
        # Verify input/output indices are set
        assert self.builder.validator_input_index == 0
        assert self.builder.nft_output_index == 0
        assert self.builder.metadata_output_index == 1
        
        # Check global proprietary fields
        assert b'BNAP_TX_TYPE' in self.builder.global_proprietary
        assert b'BNAP_VERSION' in self.builder.global_proprietary
        assert b'BNAP_COLLECTION' in self.builder.global_proprietary
        assert self.builder.global_proprietary[b'BNAP_TX_TYPE'] == b'NFT_MINT'
    
    def test_build_mint_transaction_insufficient_funds(self):
        """Test building transaction with insufficient funds."""
        self.builder.set_mint_parameters(self.params)
        
        validator_script = b'mock_validator_script'
        validator_amount = 1000  # Very small amount
        
        with pytest.raises(InsufficientFundsError):
            self.builder.build_mint_transaction(
                validator_txid="c" * 64,
                validator_vout=0,
                validator_script=validator_script,
                validator_amount=validator_amount,
                fee_amount=10000
            )
    
    def test_build_mint_transaction_without_params_fails(self):
        """Test building transaction without parameters fails."""
        with pytest.raises(PSBTConstructionError, match="Mint parameters must be set first"):
            self.builder.build_mint_transaction(
                validator_txid="c" * 64,
                validator_vout=0,
                validator_script=b'script',
                validator_amount=100000000
            )
    
    def test_create_collection_covenant_script(self):
        """Test creating collection covenant script."""
        authorized_minter = b'x' * 33  # 33-byte public key
        max_supply = 10000
        royalty_address = b'y' * 20  # 20-byte address
        royalty_basis_points = 500  # 5%
        
        script = self.builder.create_collection_covenant_script(
            self.collection_id,
            authorized_minter,
            max_supply,
            royalty_address,
            royalty_basis_points
        )
        
        assert isinstance(script, bytes)
        assert len(script) > 0
        assert authorized_minter in script
        assert royalty_address in script
    
    def test_create_collection_covenant_script_no_royalty(self):
        """Test creating covenant script without royalty."""
        authorized_minter = b'x' * 33
        max_supply = 10000
        
        script = self.builder.create_collection_covenant_script(
            self.collection_id,
            authorized_minter,
            max_supply
        )
        
        assert isinstance(script, bytes)
        assert len(script) > 0
        assert authorized_minter in script
    
    def test_encode_metadata_json(self):
        """Test encoding metadata as JSON."""
        self.builder.set_mint_parameters(self.params)
        
        json_str = self.builder._encode_metadata_json()
        parsed = json.loads(json_str)
        
        assert parsed["name"] == self.metadata.name
        assert parsed["description"] == self.metadata.description
        assert parsed["image"] == self.metadata.image_uri
        assert parsed["external_url"] == self.metadata.external_url
        assert parsed["token_id"] == self.token_id
        assert parsed["collection_id"] == self.collection_id
        assert parsed["content_hash"] == self.metadata.content_hash
        
        # Check attributes
        assert len(parsed["attributes"]) == 2
        rarity_attr = next(attr for attr in parsed["attributes"] if attr["trait_type"] == "rarity")
        assert rarity_attr["value"] == "legendary"
    
    def test_calculate_content_hash(self):
        """Test content hash calculation."""
        content = b"Hello, NFT World!"
        hash_hex = self.builder.calculate_content_hash(content)
        
        assert len(hash_hex) == 64  # SHA256 produces 32 bytes = 64 hex chars
        assert isinstance(hash_hex, str)
        
        # Verify it's a valid hex string
        bytes.fromhex(hash_hex)
    
    def test_validate_metadata_uri_ipfs(self):
        """Test IPFS URI validation."""
        valid_ipfs = "ipfs://QmTest123456789abcdefghijklmnopqrstuvwxyz12345"
        assert self.builder.validate_metadata_uri(valid_ipfs)
        
        invalid_ipfs = "ipfs://short"
        assert not self.builder.validate_metadata_uri(invalid_ipfs)
    
    def test_validate_metadata_uri_http(self):
        """Test HTTP URI validation."""
        valid_http = "https://example.com/metadata.json"
        assert self.builder.validate_metadata_uri(valid_http)
        
        valid_http2 = "http://example.com/nft/1"
        assert self.builder.validate_metadata_uri(valid_http2)
        
        invalid_http = "https://short"
        assert not self.builder.validate_metadata_uri(invalid_http)
    
    def test_validate_metadata_uri_onchain(self):
        """Test on-chain URI validation."""
        valid_onchain = "onchain://txid123456:0"
        assert self.builder.validate_metadata_uri(valid_onchain)
        
        invalid_onchain = "onchain://short"
        assert not self.builder.validate_metadata_uri(invalid_onchain)
    
    def test_validate_metadata_uri_invalid_scheme(self):
        """Test invalid URI schemes."""
        invalid_scheme = "ftp://example.com/file"
        assert not self.builder.validate_metadata_uri(invalid_scheme)
        
        empty_uri = ""
        assert not self.builder.validate_metadata_uri(empty_uri)
    
    def test_validate_mint_transaction(self):
        """Test transaction validation."""
        # Build complete transaction first
        self.builder.set_mint_parameters(self.params)
        
        validator_script = b'validator_script'
        validator_amount = 100000000
        
        self.builder.build_mint_transaction(
            validator_txid="d" * 64,
            validator_vout=0,
            validator_script=validator_script,
            validator_amount=validator_amount
        )
        
        # Validation should pass
        issues = self.builder.validate_mint_transaction()
        assert len(issues) == 0
    
    def test_validate_mint_transaction_missing_components(self):
        """Test validation with missing components."""
        self.builder.set_mint_parameters(self.params)
        
        # Without building transaction
        issues = self.builder.validate_mint_transaction()
        
        expected_issues = [
            "Validator input not added",
            "NFT output not added",
            "Metadata output not added"
        ]
        
        for issue in expected_issues:
            assert any(issue in i for i in issues)
    
    def test_validate_mint_transaction_invalid_uris(self):
        """Test validation with invalid URIs."""
        # Create params with invalid URIs
        invalid_params = NFTMintParameters(
            collection_id=self.collection_id,
            token_id=self.token_id,
            metadata=self.metadata,
            metadata_uri="invalid://uri",
            content_uri="invalid://uri",
            recipient_script=self.recipient_script
        )
        
        self.builder.set_mint_parameters(invalid_params)
        
        issues = self.builder.validate_mint_transaction()
        
        uri_issues = [i for i in issues if "URI" in i]
        assert len(uri_issues) >= 2  # Should catch both invalid URIs
    
    def test_get_mint_summary(self):
        """Test getting mint transaction summary."""
        # Build complete transaction
        self.builder.set_mint_parameters(self.params)
        
        validator_script = b'validator_script'
        validator_amount = 100000000
        
        self.builder.build_mint_transaction(
            validator_txid="e" * 64,
            validator_vout=0,
            validator_script=validator_script,
            validator_amount=validator_amount
        )
        
        summary = self.builder.get_mint_summary()
        
        assert summary['collection_id'] == self.collection_id
        assert summary['token_id'] == self.token_id
        assert summary['metadata_name'] == self.metadata.name
        assert summary['transaction_id'] is not None
        assert summary['validator_input'] == 0
        assert summary['nft_output'] == 0
        assert summary['metadata_output'] == 1
        assert summary['num_inputs'] == 1
        assert summary['num_outputs'] >= 2
        assert len(summary['validation_issues']) == 0
        assert summary['metadata_uri'] == self.params.metadata_uri
        assert summary['content_uri'] == self.params.content_uri
        assert summary['content_hash'] == self.metadata.content_hash
        assert 'fee' in summary
    
    def test_get_mint_summary_no_params(self):
        """Test getting summary without parameters."""
        summary = self.builder.get_mint_summary()
        assert summary == {"error": "Mint parameters not set"}
    
    def test_psbt_serialization(self):
        """Test PSBT serialization."""
        # Build complete transaction
        self.builder.set_mint_parameters(self.params)
        
        validator_script = b'validator_script'
        validator_amount = 100000000
        
        self.builder.build_mint_transaction(
            validator_txid="f" * 64,
            validator_vout=0,
            validator_script=validator_script,
            validator_amount=validator_amount
        )
        
        # Test serialization
        psbt_bytes = self.builder.serialize()
        assert psbt_bytes.startswith(b'psbt\xff')
        
        # Test base64 encoding
        psbt_b64 = self.builder.to_base64()
        assert isinstance(psbt_b64, str)
        assert len(psbt_b64) > 0
        
        # Should be valid base64
        import base64
        decoded = base64.b64decode(psbt_b64)
        assert decoded == psbt_bytes