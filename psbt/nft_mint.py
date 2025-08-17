"""
Bitcoin Native Asset Protocol - NFT Mint PSBT Builder

This module provides specialized PSBT construction for NFT minting operations
within the Bitcoin Native Asset Protocol.
"""

import hashlib
import struct
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

from .builder import BasePSBTBuilder
from .utils import (
    create_p2wsh_script,
    create_op_return_script,
    validate_asset_id,
    calculate_witness_script_hash,
    double_sha256
)
from .exceptions import (
    PSBTConstructionError,
    AssetMetadataError,
    InsufficientFundsError
)


class MetadataScheme(Enum):
    """Supported metadata URI schemes for NFTs."""
    IPFS = "ipfs"
    HTTP = "http"
    HTTPS = "https"
    ON_CHAIN = "onchain"


@dataclass
class NFTMetadata:
    """NFT metadata structure."""
    name: str
    description: Optional[str] = None
    image_uri: Optional[str] = None
    attributes: Optional[Dict[str, Union[str, int, float]]] = None
    external_url: Optional[str] = None
    animation_url: Optional[str] = None
    content_hash: Optional[str] = None  # SHA256 hash of content


@dataclass
class NFTMintParameters:
    """Parameters for NFT minting."""
    collection_id: str  # 64-character hex string identifying the collection
    token_id: int  # Unique token ID within the collection
    metadata: NFTMetadata
    metadata_uri: Optional[str] = None  # URI to metadata JSON
    content_uri: Optional[str] = None  # URI to actual content (image, video, etc.)
    recipient_address: Optional[str] = None
    recipient_script: Optional[bytes] = None
    change_address: Optional[str] = None
    change_script: Optional[bytes] = None
    fee_rate: int = 1  # satoshis per vbyte
    
    def __post_init__(self):
        """Validate parameters after initialization."""
        if not validate_asset_id(self.collection_id):
            raise AssetMetadataError(f"Invalid collection ID format: {self.collection_id}")
        
        if self.token_id < 0 or self.token_id > 2**64 - 1:
            raise AssetMetadataError(f"Token ID must be 0 <= id <= {2**64 - 1}")
        
        if self.recipient_address and self.recipient_script:
            raise AssetMetadataError("Cannot specify both recipient address and script")
        
        if not self.recipient_address and not self.recipient_script:
            raise AssetMetadataError("Must specify either recipient address or script")


class NFTMintPSBTBuilder(BasePSBTBuilder):
    """
    Specialized PSBT builder for NFT mint transactions.
    
    This builder extends the base PSBT builder to handle NFT minting with
    unique token issuance, metadata commitments, and content references.
    """
    
    # Constants for NFT mint transaction structure
    MIN_DUST_AMOUNT = 546  # Minimum output amount to avoid dust
    NFT_OUTPUT_AMOUNT = 1000  # Standard amount for NFT outputs
    
    # Additional proprietary key prefixes for NFTs
    COLLECTION_ID_KEY = BasePSBTBuilder.BNAP_PROPRIETARY_PREFIX + b'CID'
    TOKEN_ID_KEY = BasePSBTBuilder.BNAP_PROPRIETARY_PREFIX + b'TID'
    CONTENT_HASH_KEY = BasePSBTBuilder.BNAP_PROPRIETARY_PREFIX + b'CHH'
    METADATA_URI_KEY = BasePSBTBuilder.BNAP_PROPRIETARY_PREFIX + b'MUR'
    CONTENT_URI_KEY = BasePSBTBuilder.BNAP_PROPRIETARY_PREFIX + b'CUR'
    METADATA_JSON_KEY = BasePSBTBuilder.BNAP_PROPRIETARY_PREFIX + b'MJS'
    
    def __init__(self, version: int = 2, locktime: int = 0):
        """
        Initialize NFT mint PSBT builder.
        
        Args:
            version: Transaction version (default: 2)
            locktime: Transaction locktime (default: 0)
        """
        super().__init__(version, locktime)
        self.mint_params: Optional[NFTMintParameters] = None
        self.validator_input_index: Optional[int] = None
        self.nft_output_index: Optional[int] = None
        self.metadata_output_index: Optional[int] = None
        
    def set_mint_parameters(self, params: NFTMintParameters) -> None:
        """
        Set parameters for the NFT mint operation.
        
        Args:
            params: NFT mint parameters including collection, token ID, and metadata
            
        Raises:
            AssetMetadataError: If parameters are invalid
        """
        # Validation is done in NFTMintParameters.__post_init__
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
        Add validator input that authorizes the NFT mint.
        
        Args:
            txid: Transaction ID of validator UTXO
            vout: Output index of validator UTXO
            validator_script: Validator witness script
            utxo_amount: Amount in validator UTXO
            sequence: Sequence number (default: RBF enabled)
        """
        if self.validator_input_index is not None:
            raise PSBTConstructionError("Validator input already added")
        
        if not self.mint_params:
            raise PSBTConstructionError("Mint parameters must be set first")
        
        # Create witness UTXO data
        witness_utxo = struct.pack('<Q', utxo_amount) + validator_script
        
        self.add_input(
            txid=txid,
            vout=vout,
            sequence=sequence,
            witness_utxo=witness_utxo,
            witness_script=validator_script
        )
        
        self.validator_input_index = len(self.inputs) - 1
        
        # Add proprietary fields for NFT metadata
        self.add_input_proprietary(
            self.validator_input_index,
            self.COLLECTION_ID_KEY,
            bytes.fromhex(self.mint_params.collection_id)
        )
        
        self.add_input_proprietary(
            self.validator_input_index,
            self.TOKEN_ID_KEY,
            struct.pack('<Q', self.mint_params.token_id)
        )
        
        self.add_input_proprietary(
            self.validator_input_index,
            self.ASSET_TYPE_KEY,
            b'NFT'
        )
        
    def add_nft_output(self) -> None:
        """
        Add NFT output representing the minted token.
        
        The NFT output contains a single token and is sent to the recipient
        address/script with embedded metadata commitments.
        """
        if not self.mint_params:
            raise PSBTConstructionError("Mint parameters not set")
        
        if self.nft_output_index is not None:
            raise PSBTConstructionError("NFT output already added")
        
        # Use recipient script or convert address to script
        if self.mint_params.recipient_script:
            output_script = self.mint_params.recipient_script
        else:
            # For now, create P2WPKH script (simplified)
            # In production, would need proper address decoding
            output_script = bytes([0x00, 0x14]) + bytes(20)  # P2WPKH placeholder
        
        self.add_output(
            script=output_script,
            amount=self.NFT_OUTPUT_AMOUNT
        )
        
        self.nft_output_index = len(self.outputs) - 1
        
        # Add proprietary fields for NFT tracking
        self.add_output_proprietary(
            self.nft_output_index,
            self.COLLECTION_ID_KEY,
            bytes.fromhex(self.mint_params.collection_id)
        )
        
        self.add_output_proprietary(
            self.nft_output_index,
            self.TOKEN_ID_KEY,
            struct.pack('<Q', self.mint_params.token_id)
        )
        
        self.add_output_proprietary(
            self.nft_output_index,
            self.ASSET_TYPE_KEY,
            b'NFT'
        )
        
        # Add metadata URIs if provided
        if self.mint_params.metadata_uri:
            self.add_output_proprietary(
                self.nft_output_index,
                self.METADATA_URI_KEY,
                self.mint_params.metadata_uri.encode('utf-8')
            )
        
        if self.mint_params.content_uri:
            self.add_output_proprietary(
                self.nft_output_index,
                self.CONTENT_URI_KEY,
                self.mint_params.content_uri.encode('utf-8')
            )
        
        # Add content hash if available
        if self.mint_params.metadata.content_hash:
            self.add_output_proprietary(
                self.nft_output_index,
                self.CONTENT_HASH_KEY,
                bytes.fromhex(self.mint_params.metadata.content_hash)
            )
        
        # Encode basic metadata as JSON and add to proprietary fields
        metadata_json = self._encode_metadata_json()
        if len(metadata_json) <= 1000:  # Reasonable limit for proprietary field
            self.add_output_proprietary(
                self.nft_output_index,
                self.METADATA_JSON_KEY,
                metadata_json.encode('utf-8')
            )
        
    def add_metadata_output(self) -> None:
        """
        Add OP_RETURN output with NFT metadata.
        
        The metadata output contains protocol identifier, collection ID,
        token ID, and content hash encoded in an OP_RETURN script.
        """
        if not self.mint_params:
            raise PSBTConstructionError("Mint parameters not set")
        
        if self.metadata_output_index is not None:
            raise PSBTConstructionError("Metadata output already added")
        
        # Build metadata payload
        metadata_parts = [
            b'BNAP',  # Protocol identifier (4 bytes)
            b'NFT',   # Asset type (3 bytes)
            bytes.fromhex(self.mint_params.collection_id)[:16],  # First 16 bytes of collection ID
            struct.pack('<Q', self.mint_params.token_id)  # Token ID (8 bytes)
        ]
        
        # Add content hash if available (up to 32 bytes)
        if self.mint_params.metadata.content_hash:
            content_hash = bytes.fromhex(self.mint_params.metadata.content_hash)
            # Truncate to fit in OP_RETURN (80 byte limit)
            remaining_space = 80 - sum(len(part) for part in metadata_parts)
            if remaining_space > 0:
                metadata_parts.append(content_hash[:remaining_space])
        
        # Concatenate metadata
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
        Build complete NFT mint transaction with all required components.
        
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
        self.validator_input_index = None
        self.nft_output_index = None
        self.metadata_output_index = None
        
        # Add validator input
        self.add_validator_input(
            validator_txid,
            validator_vout,
            validator_script,
            validator_amount
        )
        
        # Add NFT output for minted token
        self.add_nft_output()
        
        # Add metadata output
        self.add_metadata_output()
        
        # Calculate fee if not provided
        if fee_amount is None:
            # Estimate transaction size (approximate)
            estimated_size = 300 + len(validator_script) + 150  # Basic estimate
            fee_amount = estimated_size * self.mint_params.fee_rate
        
        # Calculate change amount
        total_output = self.NFT_OUTPUT_AMOUNT  # Only NFT output has value
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
            b'NFT_MINT'
        )
        
        self.add_global_proprietary(
            b'BNAP_VERSION',
            b'1.0.0'
        )
        
        # Add collection-level metadata
        self.add_global_proprietary(
            b'BNAP_COLLECTION',
            bytes.fromhex(self.mint_params.collection_id)
        )
        
    def create_collection_covenant_script(
        self,
        collection_id: str,
        authorized_minter: bytes,
        max_supply: int,
        royalty_address: Optional[bytes] = None,
        royalty_basis_points: int = 0
    ) -> bytes:
        """
        Create P2WSH covenant script for NFT collection validator output.
        
        Args:
            collection_id: Collection identifier
            authorized_minter: Public key of authorized minter
            max_supply: Maximum number of NFTs in collection
            royalty_address: Address for royalty payments (optional)
            royalty_basis_points: Royalty percentage in basis points (0-10000)
            
        Returns:
            Witness script bytes
        """
        script_parts = []
        
        # Check minter authorization
        script_parts.append(bytes([0x21]))  # OP_PUSHDATA(33)
        script_parts.append(authorized_minter)
        script_parts.append(bytes([0xac]))  # OP_CHECKSIG
        
        # Verify collection ID matches
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
        script_parts.append(bytes.fromhex(collection_id))
        script_parts.append(bytes([0x87]))  # OP_EQUAL
        
        # Check max supply limit
        script_parts.append(bytes([0x08]))  # OP_PUSHDATA(8)
        script_parts.append(struct.pack('<Q', max_supply))
        script_parts.append(bytes([0xa4]))  # OP_LESSTHANOREQUAL
        
        # Add royalty enforcement if specified
        if royalty_address and royalty_basis_points > 0:
            # Check royalty payment (simplified)
            script_parts.append(bytes([0x14]))  # OP_PUSHDATA(20)
            script_parts.append(royalty_address)
            script_parts.append(bytes([0x87]))  # OP_EQUAL
            
            script_parts.append(bytes([0x02]))  # OP_PUSHDATA(2)
            script_parts.append(struct.pack('<H', royalty_basis_points))
            script_parts.append(bytes([0xa4]))  # OP_LESSTHANOREQUAL
            
            script_parts.append(bytes([0x9a]))  # OP_BOOLAND
        
        # Combine all conditions
        script_parts.append(bytes([0x9a]))  # OP_BOOLAND
        script_parts.append(bytes([0x9a]))  # OP_BOOLAND
        
        return b''.join(script_parts)
        
    def _encode_metadata_json(self) -> str:
        """
        Encode NFT metadata as JSON string.
        
        Returns:
            JSON string representation of metadata
        """
        import json
        
        metadata_dict = {
            "name": self.mint_params.metadata.name,
            "token_id": self.mint_params.token_id,
            "collection_id": self.mint_params.collection_id
        }
        
        if self.mint_params.metadata.description:
            metadata_dict["description"] = self.mint_params.metadata.description
        
        if self.mint_params.metadata.image_uri:
            metadata_dict["image"] = self.mint_params.metadata.image_uri
        
        if self.mint_params.metadata.external_url:
            metadata_dict["external_url"] = self.mint_params.metadata.external_url
        
        if self.mint_params.metadata.animation_url:
            metadata_dict["animation_url"] = self.mint_params.metadata.animation_url
        
        if self.mint_params.metadata.attributes:
            metadata_dict["attributes"] = [
                {"trait_type": k, "value": v} 
                for k, v in self.mint_params.metadata.attributes.items()
            ]
        
        if self.mint_params.metadata.content_hash:
            metadata_dict["content_hash"] = self.mint_params.metadata.content_hash
        
        return json.dumps(metadata_dict, separators=(',', ':'))
        
    def calculate_content_hash(self, content: bytes) -> str:
        """
        Calculate SHA256 hash of content for metadata commitment.
        
        Args:
            content: Content bytes to hash
            
        Returns:
            Hex string of SHA256 hash
        """
        return hashlib.sha256(content).hexdigest()
        
    def validate_metadata_uri(self, uri: str) -> bool:
        """
        Validate metadata URI format and scheme.
        
        Args:
            uri: URI to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not uri:
            return False
        
        try:
            # Basic URI validation
            if uri.startswith('ipfs://'):
                # IPFS URIs should have valid hash
                ipfs_hash = uri[7:]  # Remove 'ipfs://' prefix
                return len(ipfs_hash) >= 10  # Relaxed minimum IPFS hash length
            elif uri.startswith(('http://', 'https://')):
                # HTTP(S) URIs should be valid URLs
                return '.' in uri and len(uri) > 10
            elif uri.startswith('onchain://'):
                # On-chain references should be valid transaction/output refs
                ref = uri[10:]  # Remove 'onchain://' prefix
                return ':' in ref and len(ref) > 10
            else:
                return False
        except Exception:
            return False
        
    def validate_mint_transaction(self) -> List[str]:
        """
        Validate the NFT mint transaction structure.
        
        Returns:
            List of validation issues (empty if valid)
        """
        issues = super().validate_structure()
        
        if not self.mint_params:
            issues.append("Mint parameters not set")
            return issues
        
        if self.validator_input_index is None:
            issues.append("Validator input not added")
        
        if self.nft_output_index is None:
            issues.append("NFT output not added")
        
        if self.metadata_output_index is None:
            issues.append("Metadata output not added")
        
        # Verify output ordering (NFT, metadata, change)
        if self.nft_output_index is not None and self.metadata_output_index is not None:
            if self.nft_output_index > self.metadata_output_index:
                issues.append("NFT output must come before metadata output")
        
        # Verify proprietary fields are set correctly
        if self.validator_input_index is not None:
            input_props = self.psbt_inputs[self.validator_input_index].proprietary
            if self.COLLECTION_ID_KEY not in input_props:
                issues.append("Collection ID not set in validator input")
            if self.TOKEN_ID_KEY not in input_props:
                issues.append("Token ID not set in validator input")
            if self.ASSET_TYPE_KEY not in input_props:
                issues.append("Asset type not set in validator input")
        
        if self.nft_output_index is not None:
            output_props = self.psbt_outputs[self.nft_output_index].proprietary
            if self.COLLECTION_ID_KEY not in output_props:
                issues.append("Collection ID not set in NFT output")
            if self.TOKEN_ID_KEY not in output_props:
                issues.append("Token ID not set in NFT output")
        
        # Validate metadata URIs if present
        if self.mint_params.metadata_uri and not self.validate_metadata_uri(self.mint_params.metadata_uri):
            issues.append("Invalid metadata URI format")
        
        if self.mint_params.content_uri and not self.validate_metadata_uri(self.mint_params.content_uri):
            issues.append("Invalid content URI format")
        
        return issues
        
    def get_mint_summary(self) -> Dict[str, any]:
        """
        Get summary of the NFT mint transaction.
        
        Returns:
            Dictionary with transaction details
        """
        if not self.mint_params:
            return {"error": "Mint parameters not set"}
        
        summary = {
            "collection_id": self.mint_params.collection_id,
            "token_id": self.mint_params.token_id,
            "metadata_name": self.mint_params.metadata.name,
            "transaction_id": self.get_transaction_id() if self.inputs else None,
            "validator_input": self.validator_input_index,
            "nft_output": self.nft_output_index,
            "metadata_output": self.metadata_output_index,
            "num_inputs": len(self.inputs),
            "num_outputs": len(self.outputs),
            "validation_issues": self.validate_mint_transaction()
        }
        
        if self.mint_params.metadata_uri:
            summary["metadata_uri"] = self.mint_params.metadata_uri
        
        if self.mint_params.content_uri:
            summary["content_uri"] = self.mint_params.content_uri
        
        if self.mint_params.metadata.content_hash:
            summary["content_hash"] = self.mint_params.metadata.content_hash
        
        if self.inputs and self.outputs:
            # Calculate fee if possible
            if self.validator_input_index is not None:
                validator_utxo = self.psbt_inputs[self.validator_input_index].witness_utxo
                if validator_utxo and len(validator_utxo) >= 8:
                    validator_amount = struct.unpack('<Q', validator_utxo[:8])[0]
                    total_output = sum(out.value for out in self.outputs)
                    summary["fee"] = validator_amount - total_output
        
        return summary