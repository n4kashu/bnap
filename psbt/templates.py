"""
Bitcoin Native Asset Protocol - PSBT Transfer Templates

This module provides reusable PSBT templates for various asset transfer operations
including fungible token transfers, NFT transfers, multi-asset transfers, and 
proper fee calculation with change handling.
"""

import hashlib
from typing import List, Dict, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum

from bitcoinlib.transactions import Transaction, Input, Output
from bitcoinlib.keys import HDKey
from bitcoinlib.encoding import varstr

from .builder import BasePSBTBuilder, PSBTKeyValue, PSBTKeyType
from .utils import (
    serialize_compact_size,
    double_sha256,
    create_p2wpkh_script,
    create_p2wsh_script,
    estimate_tx_size
)
from .outputs.op_return import (
    create_asset_transfer_op_return,
    create_nft_transfer_op_return,
    MetadataType,
    CompressionType
)
from .outputs.taproot import TaprootBuilder
from .exceptions import (
    PSBTBuildError,
    PSBTValidationError,
    InsufficientFundsError
)


class TransferType(Enum):
    """Types of asset transfers."""
    FUNGIBLE_TRANSFER = "fungible_transfer"
    NFT_TRANSFER = "nft_transfer"
    MULTI_ASSET_TRANSFER = "multi_asset_transfer"
    BATCH_TRANSFER = "batch_transfer"


class FeeStrategy(Enum):
    """Fee calculation strategies."""
    FIXED_FEE = "fixed_fee"
    FEE_RATE = "fee_rate"
    HIGH_PRIORITY = "high_priority"
    ECONOMY = "economy"


@dataclass
class UTXO:
    """Represents an unspent transaction output."""
    txid: str
    vout: int
    value: int
    script: bytes
    address: Optional[str] = None
    witness_utxo: Optional[bytes] = None
    non_witness_utxo: Optional[bytes] = None


@dataclass
class AssetTransferInput:
    """Represents an asset transfer input with associated metadata."""
    utxo: UTXO
    asset_id: str
    asset_amount: int
    asset_type: str = "fungible"
    collection_id: Optional[int] = None
    token_id: Optional[int] = None
    previous_owner: Optional[bytes] = None
    witness_script: Optional[bytes] = None
    redeem_script: Optional[bytes] = None


@dataclass
class AssetTransferOutput:
    """Represents an asset transfer output."""
    recipient_script: bytes
    recipient_address: Optional[str] = None
    asset_id: str = ""
    asset_amount: int = 0
    asset_type: str = "fungible"
    collection_id: Optional[int] = None
    token_id: Optional[int] = None
    btc_value: int = 546  # Dust threshold


@dataclass
class TransferParameters:
    """Parameters for asset transfer operations."""
    transfer_type: TransferType
    inputs: List[AssetTransferInput]
    outputs: List[AssetTransferOutput]
    change_script: bytes
    fee_strategy: FeeStrategy = FeeStrategy.FEE_RATE
    fee_rate: float = 1.0  # sat/vbyte
    fixed_fee: Optional[int] = None
    include_metadata: bool = True
    metadata_compression: CompressionType = CompressionType.NONE


@dataclass
class FeeCalculation:
    """Results of fee calculation."""
    total_input_value: int
    total_output_value: int
    estimated_size: int
    fee_rate: float
    calculated_fee: int
    change_amount: int
    is_valid: bool
    errors: List[str] = field(default_factory=list)


class TransferPSBTBuilder(BasePSBTBuilder):
    """
    Specialized PSBT builder for asset transfers.
    
    Provides templates and utilities for creating transfer PSBTs with proper
    fee calculation, change handling, and asset metadata integration.
    """
    
    def __init__(self):
        """Initialize transfer PSBT builder."""
        super().__init__()
        self.transfer_params: Optional[TransferParameters] = None
        self.fee_calculation: Optional[FeeCalculation] = None
        self.asset_inputs: List[AssetTransferInput] = []
        self.asset_outputs: List[AssetTransferOutput] = []
    
    def set_transfer_parameters(self, params: TransferParameters) -> None:
        """
        Set transfer parameters for the PSBT.
        
        Args:
            params: Transfer parameters including inputs, outputs, and fees
        """
        self.transfer_params = params
        self.asset_inputs = params.inputs.copy()
        self.asset_outputs = params.outputs.copy()
    
    def calculate_fees(self) -> FeeCalculation:
        """
        Calculate fees for the transfer transaction.
        
        Returns:
            FeeCalculation object with fee details and validation
        """
        if not self.transfer_params:
            raise PSBTBuildError("Transfer parameters not set")
        
        # Calculate total input value
        total_input_value = sum(inp.utxo.value for inp in self.asset_inputs)
        
        # Calculate total output value (excluding change)
        total_output_value = sum(out.btc_value for out in self.asset_outputs)
        
        # Estimate transaction size
        num_inputs = len(self.asset_inputs)
        num_outputs = len(self.asset_outputs) + 1  # +1 for change
        
        # Add OP_RETURN output if metadata is included
        if self.transfer_params.include_metadata:
            num_outputs += 1
        
        estimated_size = estimate_tx_size(num_inputs, num_outputs)
        
        # Calculate fee based on strategy
        if self.transfer_params.fee_strategy == FeeStrategy.FIXED_FEE:
            if not self.transfer_params.fixed_fee:
                raise PSBTBuildError("Fixed fee not specified")
            calculated_fee = self.transfer_params.fixed_fee
            fee_rate = calculated_fee / estimated_size
        else:
            # Use fee rate
            fee_rate = self._get_fee_rate_for_strategy(self.transfer_params.fee_strategy)
            calculated_fee = int(estimated_size * fee_rate)
        
        # Calculate change amount
        change_amount = total_input_value - total_output_value - calculated_fee
        
        # Validate calculation
        errors = []
        is_valid = True
        
        if change_amount < 0:
            errors.append(f"Insufficient funds: need {total_output_value + calculated_fee}, have {total_input_value}")
            is_valid = False
        
        if change_amount > 0 and change_amount < 546:  # Dust threshold
            # Add dust to fee instead of creating dust change
            calculated_fee += change_amount
            change_amount = 0
        
        self.fee_calculation = FeeCalculation(
            total_input_value=total_input_value,
            total_output_value=total_output_value,
            estimated_size=estimated_size,
            fee_rate=fee_rate,
            calculated_fee=calculated_fee,
            change_amount=change_amount,
            is_valid=is_valid,
            errors=errors
        )
        
        return self.fee_calculation
    
    def _get_fee_rate_for_strategy(self, strategy: FeeStrategy) -> float:
        """Get fee rate for the given strategy."""
        fee_rates = {
            FeeStrategy.FEE_RATE: self.transfer_params.fee_rate,
            FeeStrategy.HIGH_PRIORITY: 10.0,
            FeeStrategy.ECONOMY: 1.0
        }
        return fee_rates.get(strategy, 1.0)
    
    def build_fungible_transfer_psbt(self) -> None:
        """Build a PSBT for fungible token transfer."""
        if not self.transfer_params:
            raise PSBTBuildError("Transfer parameters not set")
        if self.transfer_params.transfer_type != TransferType.FUNGIBLE_TRANSFER:
            raise PSBTBuildError("Invalid parameters for fungible transfer")
        
        # Calculate fees first
        fee_calc = self.calculate_fees()
        if not fee_calc.is_valid:
            raise InsufficientFundsError("; ".join(fee_calc.errors))
        
        # Add inputs
        for asset_input in self.asset_inputs:
            self.add_input(
                asset_input.utxo.txid,
                asset_input.utxo.vout,
                witness_utxo=asset_input.utxo.witness_utxo,
                non_witness_utxo=asset_input.utxo.non_witness_utxo,
                witness_script=asset_input.witness_script,
                redeem_script=asset_input.redeem_script
            )
        
        # Add asset transfer outputs
        for asset_output in self.asset_outputs:
            self.add_output(
                script=asset_output.recipient_script,
                amount=asset_output.btc_value
            )
        
        # Add OP_RETURN metadata if requested
        if self.transfer_params.include_metadata:
            # Create transfer metadata for the first asset (primary transfer)
            primary_output = self.asset_outputs[0]
            op_return_script = create_asset_transfer_op_return(
                asset_id=primary_output.asset_id,
                amount=primary_output.asset_amount,
                from_pubkey=self.asset_inputs[0].previous_owner,
                to_pubkey=self._extract_pubkey_from_script(primary_output.recipient_script),
                metadata_type=MetadataType.ASSET_TRANSFER
            )
            self.add_output(script=op_return_script, amount=0)
        
        # Add change output if needed
        if fee_calc.change_amount > 0:
            self.add_output(
                script=self.transfer_params.change_script,
                amount=fee_calc.change_amount
            )
    
    def build_nft_transfer_psbt(self) -> None:
        """Build a PSBT for NFT transfer."""
        if not self.transfer_params or self.transfer_params.transfer_type != TransferType.NFT_TRANSFER:
            raise PSBTBuildError("Invalid parameters for NFT transfer")
        
        # Calculate fees
        fee_calc = self.calculate_fees()
        if not fee_calc.is_valid:
            raise InsufficientFundsError("; ".join(fee_calc.errors))
        
        # Add inputs
        for asset_input in self.asset_inputs:
            self.add_input(
                asset_input.utxo.txid,
                asset_input.utxo.vout,
                witness_utxo=asset_input.utxo.witness_utxo,
                non_witness_utxo=asset_input.utxo.non_witness_utxo,
                witness_script=asset_input.witness_script,
                redeem_script=asset_input.redeem_script
            )
        
        # Add NFT transfer outputs
        for asset_output in self.asset_outputs:
            self.add_output(
                script=asset_output.recipient_script,
                amount=asset_output.btc_value
            )
        
        # Add OP_RETURN metadata for NFT transfer
        if self.transfer_params.include_metadata:
            primary_output = self.asset_outputs[0]
            if primary_output.collection_id is None or primary_output.token_id is None:
                raise PSBTBuildError("NFT transfer requires collection_id and token_id")
            
            op_return_script = create_nft_transfer_op_return(
                collection_id=primary_output.collection_id,
                token_id=primary_output.token_id,
                from_address=self.asset_inputs[0].previous_owner,
                to_address=self._extract_pubkey_from_script(primary_output.recipient_script)
            )
            self.add_output(script=op_return_script, amount=0)
        
        # Add change output if needed
        if fee_calc.change_amount > 0:
            self.add_output(
                script=self.transfer_params.change_script,
                amount=fee_calc.change_amount
            )
    
    def build_multi_asset_transfer_psbt(self) -> None:
        """Build a PSBT for multi-asset transfer (multiple assets in one transaction)."""
        if not self.transfer_params or self.transfer_params.transfer_type != TransferType.MULTI_ASSET_TRANSFER:
            raise PSBTBuildError("Invalid parameters for multi-asset transfer")
        
        # Calculate fees
        fee_calc = self.calculate_fees()
        if not fee_calc.is_valid:
            raise InsufficientFundsError("; ".join(fee_calc.errors))
        
        # Group inputs and outputs by asset
        asset_groups = {}
        for i, asset_input in enumerate(self.asset_inputs):
            key = asset_input.asset_id
            if key not in asset_groups:
                asset_groups[key] = {'inputs': [], 'outputs': []}
            asset_groups[key]['inputs'].append((i, asset_input))
        
        for i, asset_output in enumerate(self.asset_outputs):
            key = asset_output.asset_id
            if key not in asset_groups:
                asset_groups[key] = {'inputs': [], 'outputs': []}
            asset_groups[key]['outputs'].append((i, asset_output))
        
        # Validate that each asset has matching inputs and outputs
        for asset_id, group in asset_groups.items():
            total_input = sum(inp[1].asset_amount for inp in group['inputs'])
            total_output = sum(out[1].asset_amount for out in group['outputs'])
            if total_input != total_output:
                raise PSBTBuildError(
                    f"Asset {asset_id}: input amount ({total_input}) != output amount ({total_output})"
                )
        
        # Add all inputs
        for asset_input in self.asset_inputs:
            self.add_input(
                asset_input.utxo.txid,
                asset_input.utxo.vout,
                witness_utxo=asset_input.utxo.witness_utxo,
                non_witness_utxo=asset_input.utxo.non_witness_utxo,
                witness_script=asset_input.witness_script,
                redeem_script=asset_input.redeem_script
            )
        
        # Add all asset outputs
        for asset_output in self.asset_outputs:
            self.add_output(
                script=asset_output.recipient_script,
                amount=asset_output.btc_value
            )
        
        # Add OP_RETURN metadata for multi-asset transfer
        if self.transfer_params.include_metadata:
            # Create metadata listing all assets being transferred
            metadata_payload = self._create_multi_asset_metadata(asset_groups)
            op_return_script = self._create_multi_asset_op_return(metadata_payload)
            self.add_output(script=op_return_script, amount=0)
        
        # Add change output if needed
        if fee_calc.change_amount > 0:
            self.add_output(
                script=self.transfer_params.change_script,
                amount=fee_calc.change_amount
            )
    
    def build_batch_transfer_psbt(self) -> None:
        """Build a PSBT for batch transfer (same asset to multiple recipients)."""
        if not self.transfer_params or self.transfer_params.transfer_type != TransferType.BATCH_TRANSFER:
            raise PSBTBuildError("Invalid parameters for batch transfer")
        
        # Validate that all outputs are for the same asset
        if not self.asset_outputs:
            raise PSBTBuildError("No outputs specified for batch transfer")
        
        primary_asset = self.asset_outputs[0].asset_id
        for output in self.asset_outputs:
            if output.asset_id != primary_asset:
                raise PSBTBuildError("Batch transfer requires all outputs to be for the same asset")
        
        # Calculate total amounts
        total_input_amount = sum(inp.asset_amount for inp in self.asset_inputs if inp.asset_id == primary_asset)
        total_output_amount = sum(out.asset_amount for out in self.asset_outputs)
        
        if total_input_amount != total_output_amount:
            raise PSBTBuildError(
                f"Asset amount mismatch: input {total_input_amount} != output {total_output_amount}"
            )
        
        # Use multi-asset builder for implementation
        self.transfer_params.transfer_type = TransferType.MULTI_ASSET_TRANSFER
        self.build_multi_asset_transfer_psbt()
    
    def _extract_pubkey_from_script(self, script: bytes) -> Optional[bytes]:
        """Extract public key from output script (simplified)."""
        # This is a simplified implementation - real implementation would
        # need to handle different script types properly
        if len(script) >= 22 and script[0:2] == b'\x00\x14':  # P2WPKH
            return script[2:22]  # 20-byte hash
        return None
    
    def _create_multi_asset_metadata(self, asset_groups: Dict) -> bytes:
        """Create metadata payload for multi-asset transfer."""
        # Simplified implementation - would create proper TLV encoding
        metadata = b'MULTI_ASSET\x00'
        for asset_id in asset_groups:
            metadata += asset_id.encode('utf-8')[:32].ljust(32, b'\x00')
        return metadata
    
    def _create_multi_asset_op_return(self, payload: bytes) -> bytes:
        """Create OP_RETURN script for multi-asset metadata."""
        if len(payload) > 75:  # Limit for OP_RETURN
            # Compress or truncate payload
            payload = payload[:75]
        
        return b'\x6a' + bytes([len(payload)]) + payload
    
    def get_transfer_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the transfer transaction.
        
        Returns:
            Dictionary with transfer details
        """
        if not self.transfer_params or not self.fee_calculation:
            return {}
        
        return {
            'transfer_type': self.transfer_params.transfer_type.value,
            'total_inputs': len(self.asset_inputs),
            'total_outputs': len(self.asset_outputs),
            'total_btc_input': self.fee_calculation.total_input_value,
            'total_btc_output': self.fee_calculation.total_output_value,
            'fee': self.fee_calculation.calculated_fee,
            'change': self.fee_calculation.change_amount,
            'estimated_size': self.fee_calculation.estimated_size,
            'fee_rate': f"{self.fee_calculation.fee_rate:.2f} sat/vbyte",
            'assets_transferred': len(set(out.asset_id for out in self.asset_outputs)),
            'includes_metadata': self.transfer_params.include_metadata
        }


# Template Creation Functions

def create_fungible_transfer_template(
    asset_id: str,
    amount: int,
    sender_utxos: List[UTXO],
    recipient_script: bytes,
    change_script: bytes,
    fee_rate: float = 1.0
) -> TransferPSBTBuilder:
    """
    Create a template for fungible token transfer.
    
    Args:
        asset_id: ID of the asset to transfer
        amount: Amount to transfer
        sender_utxos: UTXOs owned by sender
        recipient_script: Recipient's script
        change_script: Change script
        fee_rate: Fee rate in sat/vbyte
        
    Returns:
        Configured TransferPSBTBuilder
    """
    # Create asset inputs
    asset_inputs = []
    for utxo in sender_utxos:
        asset_inputs.append(AssetTransferInput(
            utxo=utxo,
            asset_id=asset_id,
            asset_amount=amount,  # This would be determined by UTXO analysis
            asset_type="fungible"
        ))
    
    # Create asset output
    asset_outputs = [AssetTransferOutput(
        recipient_script=recipient_script,
        asset_id=asset_id,
        asset_amount=amount,
        asset_type="fungible"
    )]
    
    # Create transfer parameters
    params = TransferParameters(
        transfer_type=TransferType.FUNGIBLE_TRANSFER,
        inputs=asset_inputs,
        outputs=asset_outputs,
        change_script=change_script,
        fee_rate=fee_rate
    )
    
    # Create and configure builder
    builder = TransferPSBTBuilder()
    builder.set_transfer_parameters(params)
    
    return builder


def create_nft_transfer_template(
    collection_id: int,
    token_id: int,
    sender_utxo: UTXO,
    recipient_script: bytes,
    change_script: bytes,
    fee_rate: float = 1.0
) -> TransferPSBTBuilder:
    """
    Create a template for NFT transfer.
    
    Args:
        collection_id: NFT collection ID
        token_id: NFT token ID
        sender_utxo: UTXO containing the NFT
        recipient_script: Recipient's script
        change_script: Change script
        fee_rate: Fee rate in sat/vbyte
        
    Returns:
        Configured TransferPSBTBuilder
    """
    # Create asset input
    asset_input = AssetTransferInput(
        utxo=sender_utxo,
        asset_id=f"{collection_id}:{token_id}",
        asset_amount=1,  # NFTs have amount 1
        asset_type="nft",
        collection_id=collection_id,
        token_id=token_id
    )
    
    # Create asset output
    asset_output = AssetTransferOutput(
        recipient_script=recipient_script,
        asset_id=f"{collection_id}:{token_id}",
        asset_amount=1,
        asset_type="nft",
        collection_id=collection_id,
        token_id=token_id
    )
    
    # Create transfer parameters
    params = TransferParameters(
        transfer_type=TransferType.NFT_TRANSFER,
        inputs=[asset_input],
        outputs=[asset_output],
        change_script=change_script,
        fee_rate=fee_rate
    )
    
    # Create and configure builder
    builder = TransferPSBTBuilder()
    builder.set_transfer_parameters(params)
    
    return builder


def create_multi_asset_transfer_template(
    asset_transfers: List[Tuple[str, int, UTXO, bytes]],  # (asset_id, amount, utxo, recipient_script)
    change_script: bytes,
    fee_rate: float = 1.0
) -> TransferPSBTBuilder:
    """
    Create a template for multi-asset transfer.
    
    Args:
        asset_transfers: List of (asset_id, amount, sender_utxo, recipient_script)
        change_script: Change script
        fee_rate: Fee rate in sat/vbyte
        
    Returns:
        Configured TransferPSBTBuilder
    """
    asset_inputs = []
    asset_outputs = []
    
    for asset_id, amount, utxo, recipient_script in asset_transfers:
        # Create input
        asset_inputs.append(AssetTransferInput(
            utxo=utxo,
            asset_id=asset_id,
            asset_amount=amount,
            asset_type="fungible"  # Assume fungible unless specified
        ))
        
        # Create output
        asset_outputs.append(AssetTransferOutput(
            recipient_script=recipient_script,
            asset_id=asset_id,
            asset_amount=amount,
            asset_type="fungible"
        ))
    
    # Create transfer parameters
    params = TransferParameters(
        transfer_type=TransferType.MULTI_ASSET_TRANSFER,
        inputs=asset_inputs,
        outputs=asset_outputs,
        change_script=change_script,
        fee_rate=fee_rate
    )
    
    # Create and configure builder
    builder = TransferPSBTBuilder()
    builder.set_transfer_parameters(params)
    
    return builder


def estimate_transfer_fee(
    num_inputs: int,
    num_outputs: int,
    fee_rate: float,
    include_metadata: bool = True
) -> int:
    """
    Estimate fee for a transfer transaction.
    
    Args:
        num_inputs: Number of inputs
        num_outputs: Number of outputs
        fee_rate: Fee rate in sat/vbyte
        include_metadata: Whether to include OP_RETURN output
        
    Returns:
        Estimated fee in satoshis
    """
    # Add OP_RETURN output if metadata included
    if include_metadata:
        num_outputs += 1
    
    estimated_size = estimate_tx_size(num_inputs, num_outputs)
    return int(estimated_size * fee_rate)


def validate_transfer_parameters(params: TransferParameters) -> Tuple[bool, List[str]]:
    """
    Validate transfer parameters.
    
    Args:
        params: Transfer parameters to validate
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Check basic requirements
    if not params.inputs:
        errors.append("No inputs specified")
    
    if not params.outputs:
        errors.append("No outputs specified")
    
    if not params.change_script:
        errors.append("Change script not specified")
    
    # Check asset consistency
    if params.transfer_type == TransferType.FUNGIBLE_TRANSFER:
        if len(params.outputs) != 1:
            errors.append("Fungible transfer should have exactly one output")
        
        # Check asset amounts match
        total_input = sum(inp.asset_amount for inp in params.inputs)
        total_output = sum(out.asset_amount for out in params.outputs)
        if total_input != total_output:
            errors.append(f"Asset amount mismatch: input {total_input} != output {total_output}")
    
    elif params.transfer_type == TransferType.NFT_TRANSFER:
        if len(params.inputs) != 1 or len(params.outputs) != 1:
            errors.append("NFT transfer should have exactly one input and one output")
        
        if params.inputs[0].asset_amount != 1 or params.outputs[0].asset_amount != 1:
            errors.append("NFT amounts should be 1")
    
    # Check fee parameters
    if params.fee_strategy == FeeStrategy.FIXED_FEE and not params.fixed_fee:
        errors.append("Fixed fee strategy requires fixed_fee parameter")
    
    if params.fee_strategy == FeeStrategy.FEE_RATE and params.fee_rate <= 0:
        errors.append("Fee rate must be positive")
    
    # Check UTXO validity
    for inp in params.inputs:
        if not inp.utxo.txid or inp.utxo.vout < 0:
            errors.append(f"Invalid UTXO reference: {inp.utxo.txid}:{inp.utxo.vout}")
        
        if inp.utxo.value <= 0:
            errors.append(f"Invalid UTXO value: {inp.utxo.value}")
    
    return len(errors) == 0, errors