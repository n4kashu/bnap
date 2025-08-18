"""
Tests for Crypto Asset Commitments Module

Tests asset commitment generation, verification, and batch operations for BNAP.
"""

import pytest
import hashlib
import secrets
from crypto.commitments import (
    AssetCommitment,
    AssetType,
    OperationType,
    generate_asset_commitment,
    commit_to_asset,
    commit_to_nft,
    verify_asset_commitment,
    create_asset_commitment_tweak,
    batch_commit_assets,
    commitment_merkle_root,
    create_mint_commitment,
    create_nft_mint_commitment,
    create_transfer_commitment,
    create_burn_commitment,
    serialize_asset_data,
)
from crypto.exceptions import CommitmentError


class TestAssetCommitmentBasic:
    """Test basic AssetCommitment functionality."""
    
    def test_asset_commitment_creation(self):
        """Test basic asset commitment creation."""
        asset_id = b'\x01' * 32
        commitment = AssetCommitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.TRANSFER
        )
        
        assert commitment.asset_id == asset_id
        assert commitment.asset_type == AssetType.FUNGIBLE
        assert commitment.amount == 1000
        assert commitment.operation == OperationType.TRANSFER
        assert commitment.metadata_hash is None
        assert commitment.collection_id is None
        assert commitment.token_id is None
        assert commitment.commitment_hash is None
    
    def test_asset_commitment_validation(self):
        """Test asset commitment validation."""
        # Invalid asset ID length
        with pytest.raises(CommitmentError, match="Asset ID must be 32 bytes"):
            AssetCommitment(
                asset_id=b'\x01' * 31,  # Wrong length
                asset_type=AssetType.FUNGIBLE,
                amount=100,
                operation=OperationType.MINT
            )
        
        # Negative amount
        with pytest.raises(CommitmentError, match="Amount cannot be negative"):
            AssetCommitment(
                asset_id=b'\x01' * 32,
                asset_type=AssetType.FUNGIBLE,
                amount=-1,
                operation=OperationType.MINT
            )
        
        # NFT with wrong amount
        with pytest.raises(CommitmentError, match="NFT amount must be 1"):
            AssetCommitment(
                asset_id=b'\x01' * 32,
                asset_type=AssetType.NFT,
                amount=2,
                operation=OperationType.MINT,
                collection_id=1,
                token_id=1
            )
        
        # NFT without collection_id
        with pytest.raises(CommitmentError, match="NFT requires collection_id and token_id"):
            AssetCommitment(
                asset_id=b'\x01' * 32,
                asset_type=AssetType.NFT,
                amount=1,
                operation=OperationType.MINT
            )
        
        # Invalid metadata hash length
        with pytest.raises(CommitmentError, match="Metadata hash must be 32 bytes"):
            AssetCommitment(
                asset_id=b'\x01' * 32,
                asset_type=AssetType.FUNGIBLE,
                amount=100,
                operation=OperationType.MINT,
                metadata_hash=b'\x02' * 31  # Wrong length
            )
    
    def test_nft_commitment_creation(self):
        """Test NFT asset commitment creation."""
        asset_id = b'\xaa' * 32
        commitment = AssetCommitment(
            asset_id=asset_id,
            asset_type=AssetType.NFT,
            amount=1,
            operation=OperationType.MINT,
            collection_id=42,
            token_id=1337
        )
        
        assert commitment.asset_type == AssetType.NFT
        assert commitment.amount == 1
        assert commitment.collection_id == 42
        assert commitment.token_id == 1337


class TestAssetSerialization:
    """Test asset commitment serialization."""
    
    def test_serialize_fungible_asset(self):
        """Test serialization of fungible asset."""
        asset_id = b'\x01' * 32
        metadata_hash = b'\x02' * 32
        
        commitment = AssetCommitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.TRANSFER,
            metadata_hash=metadata_hash
        )
        
        serialized = serialize_asset_data(commitment)
        
        # Check structure: asset_id(32) + type(1) + amount(8) + operation(1) + metadata(32)
        assert len(serialized) == 74
        assert serialized[:32] == asset_id
        assert serialized[32] == 0x00  # FUNGIBLE
        assert int.from_bytes(serialized[33:41], 'little') == 1000
        assert serialized[41] == 0x01  # TRANSFER
        assert serialized[42:74] == metadata_hash
    
    def test_serialize_nft_asset(self):
        """Test serialization of NFT asset."""
        asset_id = b'\xaa' * 32
        
        commitment = AssetCommitment(
            asset_id=asset_id,
            asset_type=AssetType.NFT,
            amount=1,
            operation=OperationType.MINT,
            collection_id=42,
            token_id=1337
        )
        
        serialized = serialize_asset_data(commitment)
        
        # Check structure: asset_id(32) + type(1) + amount(8) + operation(1) + collection(4) + token(8) + metadata(32)
        assert len(serialized) == 86
        assert serialized[:32] == asset_id
        assert serialized[32] == 0x01  # NFT
        assert int.from_bytes(serialized[33:41], 'little') == 1
        assert serialized[41] == 0x00  # MINT
        assert int.from_bytes(serialized[42:46], 'little') == 42  # collection_id
        assert int.from_bytes(serialized[46:54], 'little') == 1337  # token_id
        assert serialized[54:86] == b'\x00' * 32  # No metadata
    
    def test_serialize_deterministic(self):
        """Test that serialization is deterministic."""
        asset_id = b'\x03' * 32
        
        commitment = AssetCommitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=500,
            operation=OperationType.BURN
        )
        
        serialized1 = serialize_asset_data(commitment)
        serialized2 = serialize_asset_data(commitment)
        
        assert serialized1 == serialized2


class TestCommitmentGeneration:
    """Test asset commitment generation with hashing."""
    
    def test_generate_asset_commitment(self):
        """Test basic asset commitment generation."""
        asset_id = b'\x04' * 32
        
        commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=2000,
            operation=OperationType.MINT
        )
        
        assert commitment.asset_id == asset_id
        assert commitment.asset_type == AssetType.FUNGIBLE
        assert commitment.amount == 2000
        assert commitment.operation == OperationType.MINT
        assert commitment.commitment_hash is not None
        assert len(commitment.commitment_hash) == 32
    
    def test_generate_nft_commitment(self):
        """Test NFT commitment generation."""
        asset_id = b'\x05' * 32
        metadata_hash = b'\x06' * 32
        
        commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.NFT,
            amount=1,
            operation=OperationType.TRANSFER,
            metadata_hash=metadata_hash,
            collection_id=100,
            token_id=200
        )
        
        assert commitment.asset_type == AssetType.NFT
        assert commitment.collection_id == 100
        assert commitment.token_id == 200
        assert commitment.metadata_hash == metadata_hash
        assert commitment.commitment_hash is not None
        assert len(commitment.commitment_hash) == 32
    
    def test_commitment_deterministic(self):
        """Test that commitment generation is deterministic."""
        asset_id = b'\x07' * 32
        
        commitment1 = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1500,
            operation=OperationType.TRANSFER
        )
        
        commitment2 = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1500,
            operation=OperationType.TRANSFER
        )
        
        assert commitment1.commitment_hash == commitment2.commitment_hash
    
    def test_different_commitments_different_hashes(self):
        """Test that different commitments produce different hashes."""
        asset_id = b'\x08' * 32
        
        commitment1 = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.MINT
        )
        
        commitment2 = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=2000,  # Different amount
            operation=OperationType.MINT
        )
        
        assert commitment1.commitment_hash != commitment2.commitment_hash


class TestCommitmentVerification:
    """Test asset commitment verification."""
    
    def test_verify_valid_commitment(self):
        """Test verification of valid commitment."""
        asset_id = b'\x09' * 32
        
        commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=3000,
            operation=OperationType.BURN
        )
        
        assert verify_asset_commitment(commitment) is True
    
    def test_verify_invalid_commitment(self):
        """Test verification of invalid commitment."""
        asset_id = b'\x0a' * 32
        
        commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=3000,
            operation=OperationType.BURN
        )
        
        # Corrupt the hash
        commitment.commitment_hash = b'\xff' * 32
        
        assert verify_asset_commitment(commitment) is False
    
    def test_verify_missing_hash(self):
        """Test verification with missing hash."""
        asset_id = b'\x0b' * 32
        
        commitment = AssetCommitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.TRANSFER
        )
        # No commitment_hash set
        
        assert verify_asset_commitment(commitment) is False


class TestUtilityFunctions:
    """Test utility functions for specific operations."""
    
    def test_commit_to_asset(self):
        """Test simple asset commitment."""
        asset_id = b'\x0c' * 32
        
        hash_result = commit_to_asset(
            asset_id=asset_id,
            amount=5000,
            operation=OperationType.MINT
        )
        
        assert len(hash_result) == 32
        assert isinstance(hash_result, bytes)
    
    def test_commit_to_nft(self):
        """Test NFT commitment."""
        asset_id = b'\x0d' * 32
        
        hash_result = commit_to_nft(
            asset_id=asset_id,
            collection_id=300,
            token_id=400,
            operation=OperationType.TRANSFER
        )
        
        assert len(hash_result) == 32
        assert isinstance(hash_result, bytes)
    
    def test_create_asset_commitment_tweak(self):
        """Test Taproot tweak creation from commitment."""
        asset_id = b'\x0e' * 32
        
        commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.TRANSFER
        )
        
        tweak = create_asset_commitment_tweak(commitment)
        
        assert len(tweak) == 32
        assert tweak == commitment.commitment_hash
    
    def test_create_tweak_missing_hash(self):
        """Test tweak creation with missing commitment hash."""
        asset_id = b'\x0f' * 32
        
        commitment = AssetCommitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.TRANSFER
        )
        
        with pytest.raises(CommitmentError, match="Commitment hash not computed"):
            create_asset_commitment_tweak(commitment)


class TestSpecificOperations:
    """Test operation-specific commitment functions."""
    
    def test_create_mint_commitment(self):
        """Test mint commitment creation."""
        asset_id = b'\x10' * 32
        metadata_hash = b'\x11' * 32
        
        commitment = create_mint_commitment(
            asset_id=asset_id,
            initial_supply=10000,
            metadata_hash=metadata_hash
        )
        
        assert commitment.asset_type == AssetType.FUNGIBLE
        assert commitment.amount == 10000
        assert commitment.operation == OperationType.MINT
        assert commitment.metadata_hash == metadata_hash
        assert commitment.commitment_hash is not None
    
    def test_create_nft_mint_commitment(self):
        """Test NFT mint commitment creation."""
        asset_id = b'\x12' * 32
        
        commitment = create_nft_mint_commitment(
            asset_id=asset_id,
            collection_id=500,
            token_id=600
        )
        
        assert commitment.asset_type == AssetType.NFT
        assert commitment.amount == 1
        assert commitment.operation == OperationType.MINT
        assert commitment.collection_id == 500
        assert commitment.token_id == 600
        assert commitment.commitment_hash is not None
    
    def test_create_transfer_commitment(self):
        """Test transfer commitment creation."""
        asset_id = b'\x13' * 32
        
        commitment = create_transfer_commitment(
            asset_id=asset_id,
            amount=2500
        )
        
        assert commitment.asset_type == AssetType.FUNGIBLE
        assert commitment.amount == 2500
        assert commitment.operation == OperationType.TRANSFER
        assert commitment.commitment_hash is not None
    
    def test_create_burn_commitment(self):
        """Test burn commitment creation."""
        asset_id = b'\x14' * 32
        
        commitment = create_burn_commitment(
            asset_id=asset_id,
            amount=1000
        )
        
        assert commitment.asset_type == AssetType.FUNGIBLE
        assert commitment.amount == 1000
        assert commitment.operation == OperationType.BURN
        assert commitment.commitment_hash is not None


class TestBatchOperations:
    """Test batch commitment operations."""
    
    def test_batch_commit_assets(self):
        """Test batch commitment creation."""
        # Create multiple commitments
        commitments = []
        for i in range(5):
            asset_id = (i + 1).to_bytes(32, 'big')
            commitment = generate_asset_commitment(
                asset_id=asset_id,
                asset_type=AssetType.FUNGIBLE,
                amount=(i + 1) * 1000,
                operation=OperationType.TRANSFER
            )
            commitments.append(commitment)
        
        batch_hash = batch_commit_assets(commitments)
        
        assert len(batch_hash) == 32
        assert isinstance(batch_hash, bytes)
    
    def test_batch_commit_empty_list(self):
        """Test batch commitment with empty list."""
        with pytest.raises(CommitmentError, match="Cannot create batch commitment from empty list"):
            batch_commit_assets([])
    
    def test_batch_commit_deterministic(self):
        """Test that batch commitments are deterministic."""
        # Create same commitments twice
        commitments1 = []
        commitments2 = []
        
        for i in range(3):
            asset_id = (i + 10).to_bytes(32, 'big')
            
            commitment1 = generate_asset_commitment(
                asset_id=asset_id,
                asset_type=AssetType.FUNGIBLE,
                amount=(i + 1) * 500,
                operation=OperationType.MINT
            )
            
            commitment2 = generate_asset_commitment(
                asset_id=asset_id,
                asset_type=AssetType.FUNGIBLE,
                amount=(i + 1) * 500,
                operation=OperationType.MINT
            )
            
            commitments1.append(commitment1)
            commitments2.append(commitment2)
        
        batch_hash1 = batch_commit_assets(commitments1)
        batch_hash2 = batch_commit_assets(commitments2)
        
        assert batch_hash1 == batch_hash2
    
    def test_commitment_merkle_root(self):
        """Test Merkle root creation from commitments."""
        commitments = []
        for i in range(4):
            asset_id = (i + 20).to_bytes(32, 'big')
            commitment = generate_asset_commitment(
                asset_id=asset_id,
                asset_type=AssetType.FUNGIBLE,
                amount=(i + 1) * 100,
                operation=OperationType.TRANSFER
            )
            commitments.append(commitment)
        
        merkle_root = commitment_merkle_root(commitments)
        
        assert len(merkle_root) == 32
        assert isinstance(merkle_root, bytes)
    
    def test_merkle_root_empty_list(self):
        """Test Merkle root with empty list."""
        with pytest.raises(CommitmentError, match="Cannot create Merkle root from empty list"):
            commitment_merkle_root([])
    
    def test_merkle_root_single_commitment(self):
        """Test Merkle root with single commitment."""
        asset_id = b'\x30' * 32
        commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.MINT
        )
        
        merkle_root = commitment_merkle_root([commitment])
        
        # Single item Merkle root should be the commitment hash itself
        assert merkle_root == commitment.commitment_hash
    
    def test_merkle_root_odd_number(self):
        """Test Merkle root with odd number of commitments."""
        commitments = []
        for i in range(3):  # Odd number
            asset_id = (i + 40).to_bytes(32, 'big')
            commitment = generate_asset_commitment(
                asset_id=asset_id,
                asset_type=AssetType.FUNGIBLE,
                amount=(i + 1) * 200,
                operation=OperationType.TRANSFER
            )
            commitments.append(commitment)
        
        merkle_root = commitment_merkle_root(commitments)
        
        assert len(merkle_root) == 32
        assert isinstance(merkle_root, bytes)


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_large_amounts(self):
        """Test commitments with large amounts."""
        asset_id = b'\x50' * 32
        large_amount = 2**63 - 1  # Max int64
        
        commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=large_amount,
            operation=OperationType.MINT
        )
        
        assert commitment.amount == large_amount
        assert commitment.commitment_hash is not None
    
    def test_zero_amount(self):
        """Test commitment with zero amount."""
        asset_id = b'\x51' * 32
        
        commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=0,
            operation=OperationType.BURN
        )
        
        assert commitment.amount == 0
        assert commitment.commitment_hash is not None
    
    def test_all_operations(self):
        """Test all operation types produce different hashes."""
        asset_id = b'\x52' * 32
        amount = 1000
        
        mint_commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=amount,
            operation=OperationType.MINT
        )
        
        transfer_commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=amount,
            operation=OperationType.TRANSFER
        )
        
        burn_commitment = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=amount,
            operation=OperationType.BURN
        )
        
        # All should have different hashes
        hashes = [
            mint_commitment.commitment_hash,
            transfer_commitment.commitment_hash,
            burn_commitment.commitment_hash
        ]
        
        assert len(set(hashes)) == 3  # All unique
    
    def test_metadata_impact(self):
        """Test that metadata affects commitment hash."""
        asset_id = b'\x53' * 32
        metadata1 = b'\x01' * 32
        metadata2 = b'\x02' * 32
        
        commitment1 = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.MINT,
            metadata_hash=metadata1
        )
        
        commitment2 = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.MINT,
            metadata_hash=metadata2
        )
        
        commitment3 = generate_asset_commitment(
            asset_id=asset_id,
            asset_type=AssetType.FUNGIBLE,
            amount=1000,
            operation=OperationType.MINT
            # No metadata
        )
        
        # All should be different
        hashes = [
            commitment1.commitment_hash,
            commitment2.commitment_hash,
            commitment3.commitment_hash
        ]
        
        assert len(set(hashes)) == 3  # All unique


class TestRandomizedTesting:
    """Test with randomized inputs for robustness."""
    
    def test_random_commitments(self):
        """Test commitment generation with random inputs."""
        for _ in range(20):
            # Generate random asset ID
            asset_id = secrets.token_bytes(32)
            
            # Random amount
            amount = secrets.randbelow(1000000) + 1
            
            # Random operation
            operation = secrets.choice(list(OperationType))
            
            # Generate commitment
            commitment = generate_asset_commitment(
                asset_id=asset_id,
                asset_type=AssetType.FUNGIBLE,
                amount=amount,
                operation=operation
            )
            
            # Verify it's valid
            assert verify_asset_commitment(commitment) is True
            assert len(commitment.commitment_hash) == 32
    
    def test_random_nft_commitments(self):
        """Test NFT commitments with random inputs."""
        for _ in range(10):
            asset_id = secrets.token_bytes(32)
            collection_id = secrets.randbelow(10000)
            token_id = secrets.randbelow(1000000)
            operation = secrets.choice(list(OperationType))
            
            commitment = generate_asset_commitment(
                asset_id=asset_id,
                asset_type=AssetType.NFT,
                amount=1,
                operation=operation,
                collection_id=collection_id,
                token_id=token_id
            )
            
            assert verify_asset_commitment(commitment) is True
            assert commitment.collection_id == collection_id
            assert commitment.token_id == token_id