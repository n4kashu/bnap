"""
Bitcoin Native Asset Protocol - Fungible Token Mint PSBT Builder

This module provides specialized PSBT construction for fungible token minting operations
within the Bitcoin Native Asset Protocol.
"""

import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from .builder import BasePSBTBuilder
from .utils import (
    create_p2wsh_script,
    create_op_return_script,
    create_asset_commitment,
    validate_asset_id,
    calculate_witness_script_hash
)
from .exceptions import (
    PSBTConstructionError,
    AssetMetadataError,
    InsufficientFundsError
)


@dataclass
class FungibleMintParameters:
    """Parameters for fungible token minting."""
    asset_id: str
    mint_amount: int
    recipient_address: Optional[str] = None
    recipient_script: Optional[bytes] = None
    change_address: Optional[str] = None
    change_script: Optional[bytes] = None
    metadata: Optional[Dict[str, str]] = None
    fee_rate: int = 1  # satoshis per vbyte


class FungibleMintPSBTBuilder(BasePSBTBuilder):
    """
    Specialized PSBT builder for fungible token mint transactions.
    
    This builder extends the base PSBT builder to handle fungible token minting
    with proper validator inputs, colored outputs, and asset metadata.
    """
    
    # Constants for mint transaction structure
    MIN_DUST_AMOUNT = 546  # Minimum output amount to avoid dust
    COLORED_OUTPUT_AMOUNT = 1000  # Standard amount for colored outputs
    
    def __init__(self, version: int = 2, locktime: int = 0):
        """
        Initialize fungible mint PSBT builder.
        
        Args:
            version: Transaction version (default: 2)
            locktime: Transaction locktime (default: 0)
        """
        super().__init__(version, locktime)
        self.mint_params: Optional[FungibleMintParameters] = None
        self.validator_input_index: Optional[int] = None
        self.colored_output_index: Optional[int] = None
        self.metadata_output_index: Optional[int] = None
        
    def set_mint_parameters(self, params: FungibleMintParameters) -> None:
        """
        Set parameters for the mint operation.
        
        Args:
            params: Mint parameters including asset ID, amount, and recipient
            
        Raises:
            AssetMetadataError: If parameters are invalid
        """
        if not validate_asset_id(params.asset_id):
            raise AssetMetadataError(f"Invalid asset ID format: {params.asset_id}")
        
        if params.mint_amount <= 0:
            raise AssetMetadataError(f"Mint amount must be positive: {params.mint_amount}")
        
        if params.mint_amount > 10**18:
            raise AssetMetadataError(f"Mint amount exceeds maximum: {params.mint_amount}")
        
        if params.recipient_address and params.recipient_script:
            raise AssetMetadataError("Cannot specify both recipient address and script")
        
        if not params.recipient_address and not params.recipient_script:
            raise AssetMetadataError("Must specify either recipient address or script")
        
        self.mint_params = params
        
    def add_validator_input(
        self,
        txid: str,
        vout: int,
        validator_script: bytes,
        utxo_amount: int,
        sequence: int = 0xfffffffe
    ) -> None:
        """
        Add validator input that authorizes the mint.
        
        Args:
            txid: Transaction ID of validator UTXO
            vout: Output index of validator UTXO
            validator_script: Validator witness script
            utxo_amount: Amount in validator UTXO
            sequence: Sequence number (default: RBF enabled)
        """
        if self.validator_input_index is not None:
            raise PSBTConstructionError("Validator input already added")
        
        # Create witness UTXO data (simplified - would need proper serialization)
        witness_utxo = struct.pack('<Q', utxo_amount) + validator_script
        
        self.add_input(
            txid=txid,
            vout=vout,
            sequence=sequence,
            witness_utxo=witness_utxo,
            witness_script=validator_script
        )
        
        self.validator_input_index = len(self.inputs) - 1
        
        # Add proprietary fields for asset metadata
        self.add_input_proprietary(
            self.validator_input_index,
            self.ASSET_ID_KEY,
            bytes.fromhex(self.mint_params.asset_id)
        )
        
        self.add_input_proprietary(
            self.validator_input_index,
            self.ASSET_TYPE_KEY,
            b'FUNGIBLE'
        )
        
    def add_colored_output(self) -> None:
        """
        Add colored output representing the minted tokens.
        
        The colored output contains the minted asset amount and is sent
        to the recipient address/script.
        """
        if not self.mint_params:
            raise PSBTConstructionError("Mint parameters not set")
        
        if self.colored_output_index is not None:
            raise PSBTConstructionError("Colored output already added")
        
        # Use recipient script or convert address to script
        if self.mint_params.recipient_script:
            output_script = self.mint_params.recipient_script
        else:
            # For now, create P2WPKH script (simplified)
            # In production, would need proper address decoding
            output_script = bytes([0x00, 0x14]) + bytes(20)  # P2WPKH placeholder
        
        self.add_output(
            script=output_script,
            amount=self.COLORED_OUTPUT_AMOUNT
        )
        
        self.colored_output_index = len(self.outputs) - 1
        
        # Add proprietary fields for asset tracking
        self.add_output_proprietary(
            self.colored_output_index,
            self.ASSET_ID_KEY,
            bytes.fromhex(self.mint_params.asset_id)
        )
        
        self.add_output_proprietary(
            self.colored_output_index,
            self.MINT_AMOUNT_KEY,
            struct.pack('<Q', self.mint_params.mint_amount)
        )
        
        # Add asset commitment for verification
        commitment = create_asset_commitment(
            self.mint_params.asset_id,
            self.mint_params.mint_amount
        )
        self.add_output_proprietary(
            self.colored_output_index,
            self.METADATA_HASH_KEY,
            commitment
        )
        
    def add_metadata_output(self) -> None:
        """
        Add OP_RETURN output with asset metadata.
        
        The metadata output contains protocol identifier and mint information
        encoded in an OP_RETURN script.
        """
        if not self.mint_params:
            raise PSBTConstructionError("Mint parameters not set")
        
        if self.metadata_output_index is not None:
            raise PSBTConstructionError("Metadata output already added")
        
        # Build metadata payload
        metadata_parts = [
            b'BNAP',  # Protocol identifier
            b'MINT',  # Operation type
            bytes.fromhex(self.mint_params.asset_id)[:8],  # First 8 bytes of asset ID
            struct.pack('<Q', self.mint_params.mint_amount)  # Amount
        ]
        
        # Concatenate metadata (max 80 bytes for OP_RETURN)
        metadata = b''.join(metadata_parts)
        if len(metadata) > 80:
            # Truncate if necessary
            metadata = metadata[:80]
        
        op_return_script = create_op_return_script(metadata)
        
        self.add_output(
            script=op_return_script,
            amount=0  # OP_RETURN outputs have 0 value
        )
        
        self.metadata_output_index = len(self.outputs) - 1
        
    def add_change_output(self, change_amount: int) -> None:
        """
        Add change output for remaining funds.
        
        Args:
            change_amount: Amount to return as change
        """
        if not self.mint_params:
            raise PSBTConstructionError("Mint parameters not set")
        
        if change_amount < self.MIN_DUST_AMOUNT:
            # Don't create dust outputs
            return
        
        # Use change script or convert address to script
        if self.mint_params.change_script:
            change_script = self.mint_params.change_script
        elif self.mint_params.change_address:
            # For now, create P2WPKH script (simplified)
            change_script = bytes([0x00, 0x14]) + bytes(20)  # P2WPKH placeholder
        else:
            # Default to same as recipient if no change address specified
            if self.mint_params.recipient_script:
                change_script = self.mint_params.recipient_script
            else:
                change_script = bytes([0x00, 0x14]) + bytes(20)  # P2WPKH placeholder
        
        self.add_output(
            script=change_script,
            amount=change_amount
        )
        
    def build_mint_transaction(
        self,
        validator_txid: str,
        validator_vout: int,
        validator_script: bytes,
        validator_amount: int,
        fee_amount: Optional[int] = None
    ) -> None:
        """
        Build complete mint transaction with all required components.
        
        Args:
            validator_txid: Transaction ID of validator UTXO
            validator_vout: Output index of validator UTXO
            validator_script: Validator witness script
            validator_amount: Amount in validator UTXO
            fee_amount: Transaction fee (or calculated from fee_rate)
            
        Raises:
            PSBTConstructionError: If transaction cannot be built
            InsufficientFundsError: If validator UTXO insufficient for fees
        """
        if not self.mint_params:
            raise PSBTConstructionError("Mint parameters must be set first")
        
        # Clear any existing transaction data
        self.inputs.clear()
        self.outputs.clear()
        self.psbt_inputs.clear()
        self.psbt_outputs.clear()
        
        # Add validator input
        self.add_validator_input(
            validator_txid,
            validator_vout,
            validator_script,
            validator_amount
        )
        
        # Add colored output for minted tokens
        self.add_colored_output()
        
        # Add metadata output
        self.add_metadata_output()
        
        # Calculate fee if not provided
        if fee_amount is None:
            # Estimate transaction size (approximate)
            estimated_size = 250 + len(validator_script) + 100  # Basic estimate
            fee_amount = estimated_size * self.mint_params.fee_rate
        
        # Calculate change amount
        total_output = self.COLORED_OUTPUT_AMOUNT  # Only colored output has value
        change_amount = validator_amount - total_output - fee_amount
        
        if change_amount < 0:
            raise InsufficientFundsError(
                required=total_output + fee_amount,
                available=validator_amount
            )
        
        # Add change output if above dust threshold
        if change_amount >= self.MIN_DUST_AMOUNT:
            self.add_change_output(change_amount)
        
        # Add global proprietary fields for transaction metadata
        self.add_global_proprietary(
            b'BNAP_TX_TYPE',
            b'FUNGIBLE_MINT'
        )
        
        self.add_global_proprietary(
            b'BNAP_VERSION',
            b'1.0.0'
        )
        
    def create_covenant_script(
        self,
        asset_id: str,
        authorized_minter: bytes,
        max_supply: int
    ) -> bytes:
        """
        Create P2WSH covenant script for validator output.
        
        Args:
            asset_id: Asset identifier
            authorized_minter: Public key of authorized minter
            max_supply: Maximum supply limit
            
        Returns:
            Witness script bytes
        """
        # Build covenant script with validation rules
        # This is a simplified example - real implementation would be more complex
        script_parts = []
        
        # Check minter authorization
        script_parts.append(bytes([0x21]))  # OP_PUSHDATA(33)
        script_parts.append(authorized_minter)
        script_parts.append(bytes([0xac]))  # OP_CHECKSIG
        
        # Verify asset ID matches
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
        script_parts.append(bytes.fromhex(asset_id))
        script_parts.append(bytes([0x87]))  # OP_EQUAL
        
        # Check supply limit (simplified)
        script_parts.append(bytes([0x08]))  # OP_PUSHDATA(8)
        script_parts.append(struct.pack('<Q', max_supply))
        script_parts.append(bytes([0xa4]))  # OP_LESSTHANOREQUAL
        
        # Combine with OP_BOOLAND operations
        script_parts.append(bytes([0x9a]))  # OP_BOOLAND
        script_parts.append(bytes([0x9a]))  # OP_BOOLAND
        
        return b''.join(script_parts)
        
    def validate_mint_transaction(self) -> List[str]:
        """
        Validate the mint transaction structure.
        
        Returns:
            List of validation issues (empty if valid)
        """
        issues = super().validate_structure()
        
        if not self.mint_params:
            issues.append("Mint parameters not set")
            return issues
        
        if self.validator_input_index is None:
            issues.append("Validator input not added")
        
        if self.colored_output_index is None:
            issues.append("Colored output not added")
        
        if self.metadata_output_index is None:
            issues.append("Metadata output not added")
        
        # Verify output ordering (colored, metadata, change)
        if self.colored_output_index is not None and self.metadata_output_index is not None:
            if self.colored_output_index > self.metadata_output_index:
                issues.append("Colored output must come before metadata output")
        
        # Verify proprietary fields are set correctly
        if self.validator_input_index is not None:
            input_props = self.psbt_inputs[self.validator_input_index].proprietary
            if self.ASSET_ID_KEY not in input_props:
                issues.append("Asset ID not set in validator input")
            if self.ASSET_TYPE_KEY not in input_props:
                issues.append("Asset type not set in validator input")
        
        if self.colored_output_index is not None:
            output_props = self.psbt_outputs[self.colored_output_index].proprietary
            if self.ASSET_ID_KEY not in output_props:
                issues.append("Asset ID not set in colored output")
            if self.MINT_AMOUNT_KEY not in output_props:
                issues.append("Mint amount not set in colored output")
        
        return issues
        
    def get_mint_summary(self) -> Dict[str, any]:
        """
        Get summary of the mint transaction.
        
        Returns:
            Dictionary with transaction details
        """
        if not self.mint_params:
            return {"error": "Mint parameters not set"}
        
        summary = {
            "asset_id": self.mint_params.asset_id,
            "mint_amount": self.mint_params.mint_amount,
            "transaction_id": self.get_transaction_id() if self.inputs else None,
            "validator_input": self.validator_input_index,
            "colored_output": self.colored_output_index,
            "metadata_output": self.metadata_output_index,
            "num_inputs": len(self.inputs),
            "num_outputs": len(self.outputs),
            "validation_issues": self.validate_mint_transaction()
        }
        
        if self.inputs and self.outputs:
            # Calculate fee if possible
            if self.validator_input_index is not None:
                validator_utxo = self.psbt_inputs[self.validator_input_index].witness_utxo
                if validator_utxo and len(validator_utxo) >= 8:
                    validator_amount = struct.unpack('<Q', validator_utxo[:8])[0]
                    total_output = sum(out.value for out in self.outputs)
                    summary["fee"] = validator_amount - total_output
        
        return summary