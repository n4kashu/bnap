"""
Tests for PSBT Transfer Templates
"""

import pytest
import hashlib
from psbt.templates import (
    TransferPSBTBuilder,
    TransferParameters,
    TransferType,
    FeeStrategy,
    UTXO,
    AssetTransferInput,
    AssetTransferOutput,
    FeeCalculation,
    create_fungible_transfer_template,
    create_nft_transfer_template,
    create_multi_asset_transfer_template,
    estimate_transfer_fee,
    validate_transfer_parameters
)
from psbt.exceptions import PSBTBuildError, InsufficientFundsError


class TestTransferDataStructures:
    """Test transfer-related data structures."""
    
    def test_utxo_creation(self):
        """Test UTXO creation."""
        utxo = UTXO(
            txid="a" * 64,
            vout=0,
            value=100000,
            script=b'\x00\x14' + b'\x01' * 20
        )
        
        assert utxo.txid == "a" * 64
        assert utxo.vout == 0
        assert utxo.value == 100000
        assert len(utxo.script) == 22
    
    def test_asset_transfer_input(self):
        """Test AssetTransferInput creation."""
        utxo = UTXO("b" * 64, 0, 50000, b'\x00\x14' + b'\x02' * 20)
        
        asset_input = AssetTransferInput(
            utxo=utxo,
            asset_id="test_asset_123",
            asset_amount=1000,
            asset_type="fungible"
        )
        
        assert asset_input.utxo == utxo
        assert asset_input.asset_id == "test_asset_123"
        assert asset_input.asset_amount == 1000
        assert asset_input.asset_type == "fungible"
    
    def test_asset_transfer_output(self):
        """Test AssetTransferOutput creation."""
        script = b'\x00\x14' + b'\x03' * 20
        
        asset_output = AssetTransferOutput(
            recipient_script=script,
            asset_id="test_asset_456",
            asset_amount=500,
            btc_value=1000
        )
        
        assert asset_output.recipient_script == script
        assert asset_output.asset_id == "test_asset_456"
        assert asset_output.asset_amount == 500
        assert asset_output.btc_value == 1000
    
    def test_transfer_parameters(self):
        """Test TransferParameters creation."""
        utxo = UTXO("c" * 64, 0, 75000, b'\x00\x14' + b'\x04' * 20)
        asset_input = AssetTransferInput(utxo, "asset_789", 250, "fungible")
        asset_output = AssetTransferOutput(b'\x00\x14' + b'\x05' * 20, asset_id="asset_789", asset_amount=250)
        
        params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x06' * 20,
            fee_rate=2.5
        )
        
        assert params.transfer_type == TransferType.FUNGIBLE_TRANSFER
        assert len(params.inputs) == 1
        assert len(params.outputs) == 1
        assert params.fee_rate == 2.5


class TestFeeCalculation:
    """Test fee calculation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = TransferPSBTBuilder()
        
        # Create test UTXOs
        self.utxo1 = UTXO("d" * 64, 0, 100000, b'\x00\x14' + b'\x01' * 20)
        self.utxo2 = UTXO("e" * 64, 1, 50000, b'\x00\x14' + b'\x02' * 20)
        
        # Create test transfer parameters
        asset_input = AssetTransferInput(self.utxo1, "test_asset", 1000)
        asset_output = AssetTransferOutput(
            recipient_script=b'\x00\x14' + b'\x03' * 20,
            asset_id="test_asset",
            asset_amount=1000,
            btc_value=1000
        )
        
        self.params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x04' * 20,
            fee_rate=1.0
        )
    
    def test_fee_calculation_with_fee_rate(self):
        """Test fee calculation using fee rate."""
        self.builder.set_transfer_parameters(self.params)
        fee_calc = self.builder.calculate_fees()
        
        assert fee_calc.total_input_value == 100000
        assert fee_calc.total_output_value == 1000
        assert fee_calc.fee_rate == 1.0
        assert fee_calc.calculated_fee > 0
        assert fee_calc.change_amount == 100000 - 1000 - fee_calc.calculated_fee
        assert fee_calc.is_valid
    
    def test_fee_calculation_with_fixed_fee(self):
        """Test fee calculation with fixed fee."""
        self.params.fee_strategy = FeeStrategy.FIXED_FEE
        self.params.fixed_fee = 5000
        
        self.builder.set_transfer_parameters(self.params)
        fee_calc = self.builder.calculate_fees()
        
        assert fee_calc.calculated_fee == 5000
        assert fee_calc.change_amount == 100000 - 1000 - 5000
        assert fee_calc.is_valid
    
    def test_fee_calculation_insufficient_funds(self):
        """Test fee calculation with insufficient funds."""
        # Create high-value output that exceeds input
        self.params.outputs[0].btc_value = 150000
        
        self.builder.set_transfer_parameters(self.params)
        fee_calc = self.builder.calculate_fees()
        
        assert not fee_calc.is_valid
        assert "Insufficient funds" in fee_calc.errors[0]
        assert fee_calc.change_amount < 0
    
    def test_fee_calculation_dust_handling(self):
        """Test handling of dust change amounts."""
        # Set up scenario that creates dust change
        self.params.outputs[0].btc_value = 99500  # Leaves ~500 sat change (dust)
        self.params.fee_rate = 1.0
        
        self.builder.set_transfer_parameters(self.params)
        fee_calc = self.builder.calculate_fees()
        
        # Dust should be added to fee
        assert fee_calc.change_amount == 0
        assert fee_calc.calculated_fee > fee_calc.estimated_size * 1.0
    
    def test_fee_strategy_rates(self):
        """Test different fee strategy rates."""
        strategies = [
            (FeeStrategy.ECONOMY, 1.0),
            (FeeStrategy.FEE_RATE, self.params.fee_rate),
            (FeeStrategy.HIGH_PRIORITY, 10.0)
        ]
        
        for strategy, expected_rate in strategies:
            self.params.fee_strategy = strategy
            self.builder.set_transfer_parameters(self.params)
            
            rate = self.builder._get_fee_rate_for_strategy(strategy)
            assert rate == expected_rate


class TestTransferPSBTBuilder:
    """Test TransferPSBTBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = TransferPSBTBuilder()
        
        # Create test UTXOs and parameters
        self.utxo = UTXO("f" * 64, 0, 100000, b'\x00\x14' + b'\x01' * 20)
        self.change_script = b'\x00\x14' + b'\x02' * 20
        self.recipient_script = b'\x00\x14' + b'\x03' * 20
    
    def test_builder_initialization(self):
        """Test builder initialization."""
        assert self.builder.transfer_params is None
        assert self.builder.fee_calculation is None
        assert len(self.builder.asset_inputs) == 0
        assert len(self.builder.asset_outputs) == 0
    
    def test_set_transfer_parameters(self):
        """Test setting transfer parameters."""
        asset_input = AssetTransferInput(self.utxo, "asset1", 100)
        asset_output = AssetTransferOutput(self.recipient_script, asset_id="asset1", asset_amount=100)
        
        params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=self.change_script
        )
        
        self.builder.set_transfer_parameters(params)
        
        assert self.builder.transfer_params == params
        assert len(self.builder.asset_inputs) == 1
        assert len(self.builder.asset_outputs) == 1
    
    def test_build_fungible_transfer_psbt(self):
        """Test building fungible transfer PSBT."""
        asset_input = AssetTransferInput(self.utxo, "fungible_asset", 500)
        asset_output = AssetTransferOutput(
            self.recipient_script,
            asset_id="fungible_asset",
            asset_amount=500,
            btc_value=2000
        )
        
        params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=self.change_script,
            fee_rate=2.0
        )
        
        self.builder.set_transfer_parameters(params)
        self.builder.build_fungible_transfer_psbt()
        
        # Check that PSBT has correct structure
        assert len(self.builder.inputs) == 1
        assert len(self.builder.outputs) >= 2  # At least recipient + change
        assert len(self.builder.psbt_inputs) == 1
        assert len(self.builder.psbt_outputs) >= 2
    
    def test_build_nft_transfer_psbt(self):
        """Test building NFT transfer PSBT."""
        asset_input = AssetTransferInput(
            self.utxo,
            "1:42",
            1,
            asset_type="nft",
            collection_id=1,
            token_id=42
        )
        asset_output = AssetTransferOutput(
            self.recipient_script,
            asset_id="1:42",
            asset_amount=1,
            asset_type="nft",
            collection_id=1,
            token_id=42,
            btc_value=1000
        )
        
        params = TransferParameters(
            transfer_type=TransferType.NFT_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=self.change_script
        )
        
        self.builder.set_transfer_parameters(params)
        self.builder.build_nft_transfer_psbt()
        
        # Check that PSBT has correct structure
        assert len(self.builder.inputs) == 1
        assert len(self.builder.outputs) >= 2  # At least recipient + change
    
    def test_build_multi_asset_transfer_psbt(self):
        """Test building multi-asset transfer PSBT."""
        # Create inputs and outputs for two different assets
        utxo2 = UTXO("g" * 64, 0, 75000, b'\x00\x14' + b'\x05' * 20)
        
        asset_inputs = [
            AssetTransferInput(self.utxo, "asset_a", 100),
            AssetTransferInput(utxo2, "asset_b", 200)
        ]
        
        asset_outputs = [
            AssetTransferOutput(self.recipient_script, asset_id="asset_a", asset_amount=100, btc_value=1000),
            AssetTransferOutput(b'\x00\x14' + b'\x04' * 20, asset_id="asset_b", asset_amount=200, btc_value=1500)
        ]
        
        params = TransferParameters(
            transfer_type=TransferType.MULTI_ASSET_TRANSFER,
            inputs=asset_inputs,
            outputs=asset_outputs,
            change_script=self.change_script
        )
        
        self.builder.set_transfer_parameters(params)
        self.builder.build_multi_asset_transfer_psbt()
        
        # Check that PSBT has correct structure
        assert len(self.builder.inputs) == 2
        assert len(self.builder.outputs) >= 3  # 2 recipients + change
    
    def test_build_batch_transfer_psbt(self):
        """Test building batch transfer PSBT."""
        utxo2 = UTXO("h" * 64, 1, 60000, b'\x00\x14' + b'\x06' * 20)
        
        asset_inputs = [
            AssetTransferInput(self.utxo, "batch_asset", 300),
            AssetTransferInput(utxo2, "batch_asset", 200)
        ]
        
        asset_outputs = [
            AssetTransferOutput(self.recipient_script, asset_id="batch_asset", asset_amount=200, btc_value=1000),
            AssetTransferOutput(b'\x00\x14' + b'\x07' * 20, asset_id="batch_asset", asset_amount=150, btc_value=800),
            AssetTransferOutput(b'\x00\x14' + b'\x08' * 20, asset_id="batch_asset", asset_amount=150, btc_value=700)
        ]
        
        params = TransferParameters(
            transfer_type=TransferType.BATCH_TRANSFER,
            inputs=asset_inputs,
            outputs=asset_outputs,
            change_script=self.change_script
        )
        
        self.builder.set_transfer_parameters(params)
        self.builder.build_batch_transfer_psbt()
        
        # Check that PSBT has correct structure for batch transfer
        assert len(self.builder.inputs) == 2
        assert len(self.builder.outputs) >= 4  # 3 recipients + change
    
    def test_build_psbt_insufficient_funds(self):
        """Test building PSBT with insufficient funds."""
        asset_input = AssetTransferInput(self.utxo, "test_asset", 100)
        asset_output = AssetTransferOutput(
            self.recipient_script,
            asset_id="test_asset",
            asset_amount=100,
            btc_value=200000  # More than available in UTXO
        )
        
        params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=self.change_script
        )
        
        self.builder.set_transfer_parameters(params)
        
        with pytest.raises(InsufficientFundsError):
            self.builder.build_fungible_transfer_psbt()
    
    def test_get_transfer_summary(self):
        """Test getting transfer summary."""
        asset_input = AssetTransferInput(self.utxo, "summary_asset", 750)
        asset_output = AssetTransferOutput(
            self.recipient_script,
            asset_id="summary_asset",
            asset_amount=750,
            btc_value=3000
        )
        
        params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=self.change_script,
            fee_rate=1.5
        )
        
        self.builder.set_transfer_parameters(params)
        self.builder.calculate_fees()
        
        summary = self.builder.get_transfer_summary()
        
        assert summary['transfer_type'] == 'fungible_transfer'
        assert summary['total_inputs'] == 1
        assert summary['total_outputs'] == 1
        assert summary['total_btc_input'] == 100000
        assert summary['total_btc_output'] == 3000
        assert 'fee' in summary
        assert 'change' in summary
        assert 'estimated_size' in summary
        assert summary['assets_transferred'] == 1
        assert summary['includes_metadata'] is True


class TestTemplateCreationFunctions:
    """Test template creation helper functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.utxo = UTXO("template" + "a" * 56, 0, 50000, b'\x00\x14' + b'\x01' * 20)
        self.recipient_script = b'\x00\x14' + b'\x02' * 20
        self.change_script = b'\x00\x14' + b'\x03' * 20
    
    def test_create_fungible_transfer_template(self):
        """Test creating fungible transfer template."""
        builder = create_fungible_transfer_template(
            asset_id="fungible_123",
            amount=1000,
            sender_utxos=[self.utxo],
            recipient_script=self.recipient_script,
            change_script=self.change_script,
            fee_rate=2.0
        )
        
        assert isinstance(builder, TransferPSBTBuilder)
        assert builder.transfer_params.transfer_type == TransferType.FUNGIBLE_TRANSFER
        assert len(builder.asset_inputs) == 1
        assert len(builder.asset_outputs) == 1
        assert builder.transfer_params.fee_rate == 2.0
        
        # Check asset details
        assert builder.asset_inputs[0].asset_id == "fungible_123"
        assert builder.asset_outputs[0].asset_amount == 1000
    
    def test_create_nft_transfer_template(self):
        """Test creating NFT transfer template."""
        builder = create_nft_transfer_template(
            collection_id=5,
            token_id=99,
            sender_utxo=self.utxo,
            recipient_script=self.recipient_script,
            change_script=self.change_script,
            fee_rate=3.0
        )
        
        assert isinstance(builder, TransferPSBTBuilder)
        assert builder.transfer_params.transfer_type == TransferType.NFT_TRANSFER
        assert len(builder.asset_inputs) == 1
        assert len(builder.asset_outputs) == 1
        assert builder.transfer_params.fee_rate == 3.0
        
        # Check NFT details
        assert builder.asset_inputs[0].collection_id == 5
        assert builder.asset_inputs[0].token_id == 99
        assert builder.asset_outputs[0].asset_amount == 1
    
    def test_create_multi_asset_transfer_template(self):
        """Test creating multi-asset transfer template."""
        utxo2 = UTXO("template" + "b" * 56, 0, 40000, b'\x00\x14' + b'\x04' * 20)
        recipient2 = b'\x00\x14' + b'\x05' * 20
        
        asset_transfers = [
            ("asset_x", 500, self.utxo, self.recipient_script),
            ("asset_y", 300, utxo2, recipient2)
        ]
        
        builder = create_multi_asset_transfer_template(
            asset_transfers=asset_transfers,
            change_script=self.change_script,
            fee_rate=1.5
        )
        
        assert isinstance(builder, TransferPSBTBuilder)
        assert builder.transfer_params.transfer_type == TransferType.MULTI_ASSET_TRANSFER
        assert len(builder.asset_inputs) == 2
        assert len(builder.asset_outputs) == 2
        assert builder.transfer_params.fee_rate == 1.5
        
        # Check asset details
        asset_ids = {inp.asset_id for inp in builder.asset_inputs}
        assert "asset_x" in asset_ids
        assert "asset_y" in asset_ids


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_estimate_transfer_fee(self):
        """Test fee estimation."""
        fee = estimate_transfer_fee(
            num_inputs=2,
            num_outputs=3,
            fee_rate=1.5,
            include_metadata=True
        )
        
        assert fee > 0
        assert isinstance(fee, int)
        
        # Fee with metadata should be higher than without
        fee_no_metadata = estimate_transfer_fee(2, 3, 1.5, False)
        assert fee > fee_no_metadata
    
    def test_validate_transfer_parameters(self):
        """Test parameter validation."""
        utxo = UTXO("valid" + "a" * 59, 0, 25000, b'\x00\x14' + b'\x01' * 20)
        
        # Valid parameters
        asset_input = AssetTransferInput(utxo, "valid_asset", 100)
        asset_output = AssetTransferOutput(b'\x00\x14' + b'\x02' * 20, asset_id="valid_asset", asset_amount=100)
        
        valid_params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x03' * 20
        )
        
        is_valid, errors = validate_transfer_parameters(valid_params)
        assert is_valid
        assert len(errors) == 0
        
        # Invalid parameters - no inputs
        invalid_params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x03' * 20
        )
        
        is_valid, errors = validate_transfer_parameters(invalid_params)
        assert not is_valid
        assert "No inputs specified" in errors
    
    def test_validate_asset_amounts(self):
        """Test validation of asset amount matching."""
        utxo = UTXO("amounts" + "a" * 56, 0, 30000, b'\x00\x14' + b'\x01' * 20)
        
        # Mismatched amounts
        asset_input = AssetTransferInput(utxo, "test_asset", 100)  # Input: 100
        asset_output = AssetTransferOutput(b'\x00\x14' + b'\x02' * 20, asset_id="test_asset", asset_amount=150)  # Output: 150
        
        params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x03' * 20
        )
        
        is_valid, errors = validate_transfer_parameters(params)
        assert not is_valid
        assert any("amount mismatch" in error.lower() for error in errors)
    
    def test_validate_nft_parameters(self):
        """Test validation of NFT-specific parameters."""
        utxo = UTXO("nft" + "a" * 61, 0, 15000, b'\x00\x14' + b'\x01' * 20)
        
        # Valid NFT parameters
        asset_input = AssetTransferInput(utxo, "1:42", 1, asset_type="nft", collection_id=1, token_id=42)
        asset_output = AssetTransferOutput(b'\x00\x14' + b'\x02' * 20, asset_id="1:42", asset_amount=1)
        
        params = TransferParameters(
            transfer_type=TransferType.NFT_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x03' * 20
        )
        
        is_valid, errors = validate_transfer_parameters(params)
        assert is_valid
        
        # Invalid NFT - wrong amount
        asset_input.asset_amount = 2
        is_valid, errors = validate_transfer_parameters(params)
        assert not is_valid
        assert any("nft amounts should be 1" in error.lower() for error in errors)
    
    def test_validate_fee_parameters(self):
        """Test validation of fee parameters."""
        utxo = UTXO("fee" + "a" * 61, 0, 20000, b'\x00\x14' + b'\x01' * 20)
        asset_input = AssetTransferInput(utxo, "fee_asset", 50)
        asset_output = AssetTransferOutput(b'\x00\x14' + b'\x02' * 20, asset_id="fee_asset", asset_amount=50)
        
        # Fixed fee strategy without fixed_fee parameter
        params = TransferParameters(
            transfer_type=TransferType.FUNGIBLE_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x03' * 20,
            fee_strategy=FeeStrategy.FIXED_FEE
            # missing fixed_fee
        )
        
        is_valid, errors = validate_transfer_parameters(params)
        assert not is_valid
        assert any("fixed fee strategy requires" in error.lower() for error in errors)
        
        # Negative fee rate
        params.fee_strategy = FeeStrategy.FEE_RATE
        params.fee_rate = -1.0
        
        is_valid, errors = validate_transfer_parameters(params)
        assert not is_valid
        assert any("fee rate must be positive" in error.lower() for error in errors)


class TestErrorHandling:
    """Test error handling in transfer templates."""
    
    def test_build_without_parameters(self):
        """Test building PSBT without setting parameters."""
        builder = TransferPSBTBuilder()
        
        with pytest.raises(PSBTBuildError, match="Transfer parameters not set"):
            builder.calculate_fees()
        
        with pytest.raises(PSBTBuildError, match="Transfer parameters not set"):
            builder.build_fungible_transfer_psbt()
    
    def test_build_with_wrong_transfer_type(self):
        """Test building PSBT with wrong transfer type."""
        builder = TransferPSBTBuilder()
        utxo = UTXO("wrong" + "a" * 59, 0, 10000, b'\x00\x14' + b'\x01' * 20)
        
        asset_input = AssetTransferInput(utxo, "test_asset", 25)
        asset_output = AssetTransferOutput(b'\x00\x14' + b'\x02' * 20, asset_id="test_asset", asset_amount=25)
        
        # Set NFT parameters but try to build fungible transfer
        params = TransferParameters(
            transfer_type=TransferType.NFT_TRANSFER,  # Wrong type
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x03' * 20
        )
        
        builder.set_transfer_parameters(params)
        
        with pytest.raises(PSBTBuildError, match="Invalid parameters for fungible transfer"):
            builder.build_fungible_transfer_psbt()
    
    def test_nft_transfer_missing_ids(self):
        """Test NFT transfer with missing collection/token IDs."""
        builder = TransferPSBTBuilder()
        utxo = UTXO("nft_ids" + "a" * 56, 0, 8000, b'\x00\x14' + b'\x01' * 20)
        
        asset_input = AssetTransferInput(utxo, "nft_asset", 1, asset_type="nft")
        asset_output = AssetTransferOutput(
            b'\x00\x14' + b'\x02' * 20,
            asset_id="nft_asset",
            asset_amount=1,
            # Missing collection_id and token_id
        )
        
        params = TransferParameters(
            transfer_type=TransferType.NFT_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x03' * 20
        )
        
        builder.set_transfer_parameters(params)
        
        with pytest.raises(PSBTBuildError, match="NFT transfer requires collection_id and token_id"):
            builder.build_nft_transfer_psbt()
    
    def test_multi_asset_amount_mismatch(self):
        """Test multi-asset transfer with amount mismatches."""
        builder = TransferPSBTBuilder()
        utxo = UTXO("multi" + "a" * 59, 0, 12000, b'\x00\x14' + b'\x01' * 20)
        
        asset_input = AssetTransferInput(utxo, "mismatch_asset", 100)  # Input: 100
        asset_output = AssetTransferOutput(
            b'\x00\x14' + b'\x02' * 20,
            asset_id="mismatch_asset",
            asset_amount=75  # Output: 75 (mismatch!)
        )
        
        params = TransferParameters(
            transfer_type=TransferType.MULTI_ASSET_TRANSFER,
            inputs=[asset_input],
            outputs=[asset_output],
            change_script=b'\x00\x14' + b'\x03' * 20
        )
        
        builder.set_transfer_parameters(params)
        
        with pytest.raises(PSBTBuildError, match="input amount.*!= output amount"):
            builder.build_multi_asset_transfer_psbt()