"""
Tests for Fungible Token Mint PSBT Construction
"""

import pytest
import struct
from psbt.fungible_mint import FungibleMintPSBTBuilder, FungibleMintParameters
from psbt.exceptions import PSBTConstructionError, AssetMetadataError, InsufficientFundsError
from psbt.utils import validate_asset_id


class TestFungibleMintParameters:
    """Test FungibleMintParameters validation."""
    
    def test_valid_parameters(self):
        """Test valid mint parameters."""
        params = FungibleMintParameters(
            asset_id="a" * 64,
            mint_amount=1000000,
            recipient_script=bytes([0x00, 0x14]) + bytes(20),
            fee_rate=2
        )
        assert params.asset_id == "a" * 64
        assert params.mint_amount == 1000000
        assert params.fee_rate == 2


class TestFungibleMintPSBTBuilder:
    """Test FungibleMintPSBTBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = FungibleMintPSBTBuilder()
        self.asset_id = "1234567890abcdef" * 4
        self.mint_amount = 5000000
        self.recipient_script = bytes([0x00, 0x14]) + bytes(20)  # P2WPKH
        
        self.params = FungibleMintParameters(
            asset_id=self.asset_id,
            mint_amount=self.mint_amount,
            recipient_script=self.recipient_script,
            fee_rate=1
        )
    
    def test_initialization(self):
        """Test builder initialization."""
        assert self.builder.version == 2
        assert self.builder.locktime == 0
        assert self.builder.mint_params is None
        assert self.builder.validator_input_index is None
        assert self.builder.colored_output_index is None
        assert self.builder.metadata_output_index is None
    
    def test_set_mint_parameters_valid(self):
        """Test setting valid mint parameters."""
        self.builder.set_mint_parameters(self.params)
        assert self.builder.mint_params == self.params
    
    def test_set_mint_parameters_invalid_asset_id(self):
        """Test setting parameters with invalid asset ID."""
        invalid_params = FungibleMintParameters(
            asset_id="invalid",
            mint_amount=1000,
            recipient_script=self.recipient_script
        )
        
        with pytest.raises(AssetMetadataError, match="Invalid asset ID format"):
            self.builder.set_mint_parameters(invalid_params)
    
    def test_set_mint_parameters_invalid_amount(self):
        """Test setting parameters with invalid mint amount."""
        invalid_params = FungibleMintParameters(
            asset_id=self.asset_id,
            mint_amount=0,
            recipient_script=self.recipient_script
        )
        
        with pytest.raises(AssetMetadataError, match="Mint amount must be positive"):
            self.builder.set_mint_parameters(invalid_params)
    
    def test_set_mint_parameters_excessive_amount(self):
        """Test setting parameters with excessive mint amount."""
        invalid_params = FungibleMintParameters(
            asset_id=self.asset_id,
            mint_amount=10**19,  # Exceeds maximum
            recipient_script=self.recipient_script
        )
        
        with pytest.raises(AssetMetadataError, match="Mint amount exceeds maximum"):
            self.builder.set_mint_parameters(invalid_params)
    
    def test_set_mint_parameters_both_address_and_script(self):
        """Test setting parameters with both address and script."""
        invalid_params = FungibleMintParameters(
            asset_id=self.asset_id,
            mint_amount=1000,
            recipient_address="bc1qaddress",
            recipient_script=self.recipient_script
        )
        
        with pytest.raises(AssetMetadataError, match="Cannot specify both"):
            self.builder.set_mint_parameters(invalid_params)
    
    def test_set_mint_parameters_neither_address_nor_script(self):
        """Test setting parameters without address or script."""
        invalid_params = FungibleMintParameters(
            asset_id=self.asset_id,
            mint_amount=1000
        )
        
        with pytest.raises(AssetMetadataError, match="Must specify either"):
            self.builder.set_mint_parameters(invalid_params)
    
    def test_add_validator_input(self):
        """Test adding validator input."""
        self.builder.set_mint_parameters(self.params)
        
        validator_script = b'validator_script_data'
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
        assert self.builder.ASSET_ID_KEY in psbt_input.proprietary
        assert self.builder.ASSET_TYPE_KEY in psbt_input.proprietary
        assert psbt_input.proprietary[self.builder.ASSET_TYPE_KEY] == b'FUNGIBLE'
    
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
    
    def test_add_colored_output(self):
        """Test adding colored output."""
        self.builder.set_mint_parameters(self.params)
        
        self.builder.add_colored_output()
        
        assert self.builder.colored_output_index == 0
        assert len(self.builder.outputs) == 1
        assert len(self.builder.psbt_outputs) == 1
        
        # Check output details
        output = self.builder.outputs[0]
        assert output.value == self.builder.COLORED_OUTPUT_AMOUNT
        assert output.script == self.recipient_script
        
        # Check proprietary fields
        psbt_output = self.builder.psbt_outputs[0]
        assert self.builder.ASSET_ID_KEY in psbt_output.proprietary
        assert self.builder.MINT_AMOUNT_KEY in psbt_output.proprietary
        assert self.builder.METADATA_HASH_KEY in psbt_output.proprietary
        
        # Verify mint amount encoding
        amount_bytes = psbt_output.proprietary[self.builder.MINT_AMOUNT_KEY]
        assert struct.unpack('<Q', amount_bytes)[0] == self.mint_amount
    
    def test_add_colored_output_without_params_fails(self):
        """Test that adding colored output without parameters fails."""
        with pytest.raises(PSBTConstructionError, match="Mint parameters not set"):
            self.builder.add_colored_output()
    
    def test_add_colored_output_twice_fails(self):
        """Test that adding colored output twice fails."""
        self.builder.set_mint_parameters(self.params)
        
        self.builder.add_colored_output()
        
        with pytest.raises(PSBTConstructionError, match="Colored output already added"):
            self.builder.add_colored_output()
    
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
        assert b'MINT' in metadata
    
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
        """Test building complete mint transaction."""
        self.builder.set_mint_parameters(self.params)
        
        validator_script = b'mock_validator_script'
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
        assert len(self.builder.outputs) >= 2  # Colored + metadata, possibly change
        
        # Verify input/output indices are set
        assert self.builder.validator_input_index == 0
        assert self.builder.colored_output_index == 0
        assert self.builder.metadata_output_index == 1
        
        # Check global proprietary fields
        assert b'BNAP_TX_TYPE' in self.builder.global_proprietary
        assert b'BNAP_VERSION' in self.builder.global_proprietary
        assert self.builder.global_proprietary[b'BNAP_TX_TYPE'] == b'FUNGIBLE_MINT'
    
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
    
    def test_create_covenant_script(self):
        """Test creating covenant script."""
        authorized_minter = b'x' * 33  # 33-byte public key
        max_supply = 21000000
        
        script = self.builder.create_covenant_script(
            self.asset_id,
            authorized_minter,
            max_supply
        )
        
        assert isinstance(script, bytes)
        assert len(script) > 0
        assert authorized_minter in script
    
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
        
        # Validate should pass
        issues = self.builder.validate_mint_transaction()
        assert len(issues) == 0
    
    def test_validate_mint_transaction_missing_components(self):
        """Test validation with missing components."""
        self.builder.set_mint_parameters(self.params)
        
        # Without building transaction
        issues = self.builder.validate_mint_transaction()
        
        expected_issues = [
            "Validator input not added",
            "Colored output not added", 
            "Metadata output not added"
        ]
        
        for issue in expected_issues:
            assert any(issue in i for i in issues)
    
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
        
        assert summary['asset_id'] == self.asset_id
        assert summary['mint_amount'] == self.mint_amount
        assert summary['transaction_id'] is not None
        assert summary['validator_input'] == 0
        assert summary['colored_output'] == 0
        assert summary['metadata_output'] == 1
        assert summary['num_inputs'] == 1
        assert summary['num_outputs'] >= 2
        assert len(summary['validation_issues']) == 0
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