"""
Asset Commitment Generation for BNAP

This module generates asset commitments for Taproot key tweaking
and asset verification in Bitcoin Native Asset Protocol.

Asset commitments ensure that assets are properly bound to their
metadata and prevent double-spending through cryptographic commitments.
"""

import hashlib
import struct
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

from .exceptions import CommitmentError
from .keys import tagged_hash


class AssetType(Enum):
    """Asset type enumeration."""
    FUNGIBLE = "fungible"
    NFT = "nft"


class OperationType(Enum):
    """Operation type enumeration."""
    MINT = "mint"
    TRANSFER = "transfer"
    BURN = "burn"


@dataclass
class AssetCommitment:
    """
    Asset commitment data structure.
    """
    asset_id: bytes
    asset_type: AssetType
    amount: int
    operation: OperationType
    metadata_hash: Optional[bytes] = None
    collection_id: Optional[int] = None
    token_id: Optional[int] = None
    commitment_hash: Optional[bytes] = None
    
    def __post_init__(self):
        """Validate asset commitment data."""
        if len(self.asset_id) != 32:
            raise CommitmentError("Asset ID must be 32 bytes")
        
        if self.amount < 0:
            raise CommitmentError("Amount cannot be negative")
            
        if self.asset_type == AssetType.NFT and self.amount != 1:
            raise CommitmentError("NFT amount must be 1")
            
        if self.asset_type == AssetType.NFT:
            if self.collection_id is None or self.token_id is None:
                raise CommitmentError("NFT requires collection_id and token_id")
        
        if self.metadata_hash is not None and len(self.metadata_hash) != 32:
            raise CommitmentError("Metadata hash must be 32 bytes")


def serialize_asset_data(commitment: AssetCommitment) -> bytes:
    """
    Serialize asset commitment data for hashing.
    
    Args:
        commitment: Asset commitment to serialize
        
    Returns:
        Serialized commitment data
    """
    data = b""
    
    # Asset ID (32 bytes)
    data += commitment.asset_id
    
    # Asset type (1 byte)
    if commitment.asset_type == AssetType.FUNGIBLE:
        data += b'\x00'
    elif commitment.asset_type == AssetType.NFT:
        data += b'\x01'
    else:
        raise CommitmentError(f"Unknown asset type: {commitment.asset_type}")
    
    # Amount (8 bytes, little-endian)
    data += struct.pack('<Q', commitment.amount)
    
    # Operation type (1 byte)
    if commitment.operation == OperationType.MINT:
        data += b'\x00'
    elif commitment.operation == OperationType.TRANSFER:
        data += b'\x01'
    elif commitment.operation == OperationType.BURN:
        data += b'\x02'
    else:
        raise CommitmentError(f"Unknown operation type: {commitment.operation}")
    
    # NFT-specific fields (if applicable)
    if commitment.asset_type == AssetType.NFT:
        # Collection ID (4 bytes, little-endian)
        data += struct.pack('<I', commitment.collection_id or 0)
        
        # Token ID (8 bytes, little-endian)
        data += struct.pack('<Q', commitment.token_id or 0)
    
    # Metadata hash (32 bytes if present, otherwise 32 zero bytes)
    if commitment.metadata_hash is not None:
        data += commitment.metadata_hash
    else:
        data += b'\x00' * 32
    
    return data


def generate_asset_commitment(asset_id: bytes, asset_type: AssetType, amount: int,
                            operation: OperationType, metadata_hash: Optional[bytes] = None,
                            collection_id: Optional[int] = None, 
                            token_id: Optional[int] = None) -> AssetCommitment:
    """
    Generate asset commitment with commitment hash.
    
    Args:
        asset_id: 32-byte asset identifier
        asset_type: Type of asset (fungible or NFT)
        amount: Asset amount
        operation: Operation type (mint, transfer, burn)
        metadata_hash: Optional 32-byte metadata hash
        collection_id: NFT collection ID (required for NFTs)
        token_id: NFT token ID (required for NFTs)
        
    Returns:
        Asset commitment with computed hash
    """
    commitment = AssetCommitment(
        asset_id=asset_id,
        asset_type=asset_type,
        amount=amount,
        operation=operation,
        metadata_hash=metadata_hash,
        collection_id=collection_id,
        token_id=token_id
    )
    
    # Serialize and hash the commitment
    serialized_data = serialize_asset_data(commitment)
    commitment_hash = tagged_hash("BNAPCommitment", serialized_data)
    
    commitment.commitment_hash = commitment_hash
    return commitment


def commit_to_asset(asset_id: bytes, amount: int, operation: OperationType = OperationType.TRANSFER,
                   metadata_hash: Optional[bytes] = None) -> bytes:
    """
    Create simple asset commitment for fungible tokens.
    
    Args:
        asset_id: 32-byte asset identifier
        amount: Token amount
        operation: Operation type
        metadata_hash: Optional metadata hash
        
    Returns:
        32-byte commitment hash
    """
    commitment = generate_asset_commitment(
        asset_id=asset_id,
        asset_type=AssetType.FUNGIBLE,
        amount=amount,
        operation=operation,
        metadata_hash=metadata_hash
    )
    
    return commitment.commitment_hash


def commit_to_nft(asset_id: bytes, collection_id: int, token_id: int,
                 operation: OperationType = OperationType.TRANSFER,
                 metadata_hash: Optional[bytes] = None) -> bytes:
    """
    Create asset commitment for NFTs.
    
    Args:
        asset_id: 32-byte asset identifier
        collection_id: NFT collection identifier
        token_id: NFT token identifier
        operation: Operation type
        metadata_hash: Optional metadata hash
        
    Returns:
        32-byte commitment hash
    """
    commitment = generate_asset_commitment(
        asset_id=asset_id,
        asset_type=AssetType.NFT,
        amount=1,  # NFTs always have amount 1
        operation=operation,
        metadata_hash=metadata_hash,
        collection_id=collection_id,
        token_id=token_id
    )
    
    return commitment.commitment_hash


def verify_asset_commitment(commitment: AssetCommitment) -> bool:
    """
    Verify that an asset commitment hash is correct.
    
    Args:
        commitment: Asset commitment to verify
        
    Returns:
        True if commitment hash is valid
    """
    try:
        # Recompute the commitment hash
        serialized_data = serialize_asset_data(commitment)
        expected_hash = tagged_hash("BNAPCommitment", serialized_data)
        
        return commitment.commitment_hash == expected_hash
    except Exception:
        return False


def create_asset_commitment_tweak(commitment: AssetCommitment) -> bytes:
    """
    Create Taproot tweak from asset commitment for key tweaking.
    
    Args:
        commitment: Asset commitment
        
    Returns:
        32-byte tweak for Taproot key tweaking
    """
    if commitment.commitment_hash is None:
        raise CommitmentError("Commitment hash not computed")
    
    # Use commitment hash as the tweak
    # In practice, this might be combined with other data
    return commitment.commitment_hash


def batch_commit_assets(commitments: list) -> bytes:
    """
    Create batch commitment for multiple assets.
    
    Args:
        commitments: List of AssetCommitment objects
        
    Returns:
        32-byte batch commitment hash
    """
    if not commitments:
        raise CommitmentError("Cannot create batch commitment from empty list")
    
    # Sort commitments by their hash for deterministic ordering
    sorted_commitments = sorted(commitments, key=lambda c: c.commitment_hash or b'')
    
    # Concatenate all commitment hashes
    batch_data = b"".join(c.commitment_hash or b'\x00' * 32 for c in sorted_commitments)
    
    # Hash the concatenated data
    return tagged_hash("BNAPBatchCommitment", batch_data)


def commitment_merkle_root(commitments: list) -> bytes:
    """
    Create Merkle root of asset commitments for script tree construction.
    
    Args:
        commitments: List of AssetCommitment objects
        
    Returns:
        32-byte Merkle root
    """
    if not commitments:
        raise CommitmentError("Cannot create Merkle root from empty list")
    
    # Get commitment hashes
    hashes = [c.commitment_hash or b'\x00' * 32 for c in commitments]
    
    # Build Merkle tree
    return _build_merkle_tree(hashes)


def _build_merkle_tree(hashes: list) -> bytes:
    """
    Build Merkle tree from list of hashes.
    
    Args:
        hashes: List of 32-byte hashes
        
    Returns:
        32-byte Merkle root
    """
    if len(hashes) == 1:
        return hashes[0]
    
    # If odd number of hashes, duplicate the last one
    if len(hashes) % 2 == 1:
        hashes = hashes + [hashes[-1]]
    
    # Compute parent hashes
    parent_hashes = []
    for i in range(0, len(hashes), 2):
        left = hashes[i]
        right = hashes[i + 1]
        
        # Combine hashes with domain separation
        combined = left + right
        parent_hash = tagged_hash("BNAPMerkleNode", combined)
        parent_hashes.append(parent_hash)
    
    # Recursively build tree
    return _build_merkle_tree(parent_hashes)


# Utility functions for specific BNAP operations

def create_mint_commitment(asset_id: bytes, initial_supply: int, 
                          metadata_hash: Optional[bytes] = None) -> AssetCommitment:
    """
    Create commitment for asset minting operation.
    
    Args:
        asset_id: 32-byte asset identifier
        initial_supply: Initial token supply
        metadata_hash: Optional metadata hash
        
    Returns:
        Asset commitment for minting
    """
    return generate_asset_commitment(
        asset_id=asset_id,
        asset_type=AssetType.FUNGIBLE,
        amount=initial_supply,
        operation=OperationType.MINT,
        metadata_hash=metadata_hash
    )


def create_nft_mint_commitment(asset_id: bytes, collection_id: int, token_id: int,
                              metadata_hash: Optional[bytes] = None) -> AssetCommitment:
    """
    Create commitment for NFT minting operation.
    
    Args:
        asset_id: 32-byte asset identifier  
        collection_id: NFT collection identifier
        token_id: NFT token identifier
        metadata_hash: Optional metadata hash
        
    Returns:
        Asset commitment for NFT minting
    """
    return generate_asset_commitment(
        asset_id=asset_id,
        asset_type=AssetType.NFT,
        amount=1,
        operation=OperationType.MINT,
        metadata_hash=metadata_hash,
        collection_id=collection_id,
        token_id=token_id
    )


def create_transfer_commitment(asset_id: bytes, amount: int,
                              metadata_hash: Optional[bytes] = None) -> AssetCommitment:
    """
    Create commitment for asset transfer operation.
    
    Args:
        asset_id: 32-byte asset identifier
        amount: Transfer amount
        metadata_hash: Optional metadata hash
        
    Returns:
        Asset commitment for transfer
    """
    return generate_asset_commitment(
        asset_id=asset_id,
        asset_type=AssetType.FUNGIBLE,
        amount=amount,
        operation=OperationType.TRANSFER,
        metadata_hash=metadata_hash
    )


def create_burn_commitment(asset_id: bytes, amount: int,
                          metadata_hash: Optional[bytes] = None) -> AssetCommitment:
    """
    Create commitment for asset burn operation.
    
    Args:
        asset_id: 32-byte asset identifier
        amount: Burn amount
        metadata_hash: Optional metadata hash
        
    Returns:
        Asset commitment for burning
    """
    return generate_asset_commitment(
        asset_id=asset_id,
        asset_type=AssetType.FUNGIBLE,
        amount=amount,
        operation=OperationType.BURN,
        metadata_hash=metadata_hash
    )