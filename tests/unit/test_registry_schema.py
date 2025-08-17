"""
Unit tests for registry schema models.
"""

import pytest
from datetime import datetime
from uuid import uuid4

from registry.schema import (
    AssetType, AssetStatus, SigningScheme, ScriptFormat,
    FungibleAsset, NFTAsset, ValidatorConfig, StateEntry,
    TransactionEntry, Registry, RegistryMetadata
)


class TestAssetModels:
    """Test asset model validation and functionality."""
    
    def test_fungible_asset_creation(self):
        """Test fungible asset creation with valid data."""
        asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test Token",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000000,
            per_mint_limit=1000
        )
        
        assert asset.asset_type == AssetType.FUNGIBLE
        assert asset.name == "Test Token"
        assert asset.symbol == "TEST"
        assert asset.maximum_supply == 1000000
        assert asset.per_mint_limit == 1000
        assert asset.status == AssetStatus.ACTIVE
        assert asset.script_format == ScriptFormat.P2TR
    
    def test_nft_asset_creation(self):
        """Test NFT asset creation with valid data."""
        asset = NFTAsset(
            asset_id="c" * 64,
            name="Test Collection",
            symbol="TESTNFT",
            issuer_pubkey="d" * 64,
            collection_size=100
        )
        
        assert asset.asset_type == AssetType.NFT
        assert asset.name == "Test Collection"
        assert asset.symbol == "TESTNFT"
        assert asset.collection_size == 100
    
    def test_asset_id_validation(self):
        """Test asset ID format validation."""
        # Valid asset ID
        valid_id = "a" * 64
        asset = FungibleAsset(
            asset_id=valid_id,
            name="Test",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        assert asset.asset_id == valid_id
        
        # Invalid asset ID - too short
        with pytest.raises(ValueError, match="Asset ID must be 64-character hex string"):
            FungibleAsset(
                asset_id="abc123",
                name="Test",
                symbol="TEST",
                issuer_pubkey="b" * 64,
                maximum_supply=1000,
                per_mint_limit=100
            )
        
        # Invalid asset ID - invalid characters
        with pytest.raises(ValueError, match="Asset ID must be 64-character hex string"):
            FungibleAsset(
                asset_id="g" * 64,
                name="Test",
                symbol="TEST",
                issuer_pubkey="b" * 64,
                maximum_supply=1000,
                per_mint_limit=100
            )
    
    def test_symbol_validation(self):
        """Test symbol format validation."""
        # Valid symbol
        asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test",
            symbol="TEST123",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        assert asset.symbol == "TEST123"
        
        # Invalid symbol - lowercase
        with pytest.raises(ValueError, match="Symbol must contain only uppercase letters and numbers"):
            FungibleAsset(
                asset_id="a" * 64,
                name="Test",
                symbol="test",
                issuer_pubkey="b" * 64,
                maximum_supply=1000,
                per_mint_limit=100
            )
    
    def test_supply_constraints_validation(self):
        """Test supply constraint validation."""
        # Valid constraints
        asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        assert asset.maximum_supply == 1000
        assert asset.per_mint_limit == 100
        
        # Invalid - per_mint_limit > maximum_supply
        with pytest.raises(ValueError, match="Per-mint limit cannot exceed maximum supply"):
            FungibleAsset(
                asset_id="a" * 64,
                name="Test",
                symbol="TEST",
                issuer_pubkey="b" * 64,
                maximum_supply=100,
                per_mint_limit=1000
            )


class TestValidatorConfig:
    """Test validator configuration model."""
    
    def test_validator_creation(self):
        """Test validator config creation."""
        validator = ValidatorConfig(
            validator_id="validator1",
            pubkey="a" * 64,
            signing_scheme=SigningScheme.SCHNORR,
            permissions=["mint", "transfer"]
        )
        
        assert validator.validator_id == "validator1"
        assert validator.pubkey == "a" * 64
        assert validator.signing_scheme == SigningScheme.SCHNORR
        assert validator.permissions == ["mint", "transfer"]
        assert validator.is_active is True
    
    def test_pubkey_validation(self):
        """Test public key validation."""
        # Valid pubkey
        validator = ValidatorConfig(
            validator_id="test",
            pubkey="0x" + "a" * 64
        )
        assert validator.pubkey == "a" * 64  # 0x prefix removed and lowercased
        
        # Invalid pubkey
        with pytest.raises(ValueError, match="Public key must be 32-33 byte hex string"):
            ValidatorConfig(
                validator_id="test",
                pubkey="invalid"
            )


class TestStateEntry:
    """Test state entry model."""
    
    def test_state_creation(self):
        """Test state entry creation."""
        state = StateEntry(asset_id="a" * 64)
        
        assert state.asset_id == "a" * 64
        assert state.minted_supply == 0
        assert state.transaction_count == 0
        assert state.last_mint_timestamp is None
        assert len(state.transaction_history) == 0
        assert len(state.issued_nft_ids) == 0
    
    def test_add_transaction(self):
        """Test adding transaction to state."""
        state = StateEntry(asset_id="a" * 64)
        
        tx = TransactionEntry(
            tx_id="b" * 64,
            amount=100,
            recipient="recipient_address"
        )
        
        state.add_transaction(tx)
        
        assert state.minted_supply == 100
        assert state.transaction_count == 1
        assert len(state.transaction_history) == 1
        assert state.last_mint_timestamp is not None
    
    def test_issue_nft(self):
        """Test NFT issuance."""
        state = StateEntry(asset_id="a" * 64)
        
        tx = TransactionEntry(
            tx_id="b" * 64,
            amount=1,
            recipient="recipient_address"
        )
        
        state.issue_nft(1, tx)
        
        assert 1 in state.issued_nft_ids
        assert state.minted_supply == 1
        assert state.transaction_count == 1
        
        # Test duplicate NFT ID
        with pytest.raises(ValueError, match="NFT token ID 1 already issued"):
            state.issue_nft(1, tx)


class TestTransactionEntry:
    """Test transaction entry model."""
    
    def test_transaction_creation(self):
        """Test transaction entry creation."""
        tx = TransactionEntry(
            tx_id="a" * 64,
            amount=100,
            recipient="test_address"
        )
        
        assert tx.tx_id == "a" * 64
        assert tx.amount == 100
        assert tx.recipient == "test_address"
        assert isinstance(tx.timestamp, datetime)
    
    def test_tx_id_validation(self):
        """Test transaction ID validation."""
        # Valid transaction ID
        tx = TransactionEntry(
            tx_id="A" * 64,
            amount=100
        )
        assert tx.tx_id == "a" * 64  # Lowercased
        
        # Invalid transaction ID
        with pytest.raises(ValueError, match="Transaction ID must be 64-character hex string"):
            TransactionEntry(
                tx_id="invalid",
                amount=100
            )


class TestRegistry:
    """Test registry model."""
    
    def test_registry_creation(self):
        """Test registry creation."""
        registry = Registry()
        
        assert isinstance(registry.metadata, RegistryMetadata)
        assert len(registry.validators) == 0
        assert len(registry.assets) == 0
        assert len(registry.state) == 0
    
    def test_add_asset(self):
        """Test adding asset to registry."""
        registry = Registry()
        
        asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test Token",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        
        registry.add_asset(asset)
        
        assert asset.asset_id in registry.assets
        assert asset.asset_id in registry.state
        assert registry.assets[asset.asset_id] == asset
        
        # Test duplicate asset
        with pytest.raises(ValueError, match="Asset .* already exists"):
            registry.add_asset(asset)
    
    def test_add_validator(self):
        """Test adding validator to registry."""
        registry = Registry()
        
        validator = ValidatorConfig(
            validator_id="test_validator",
            pubkey="a" * 64
        )
        
        registry.add_validator(validator)
        
        assert validator.validator_id in registry.validators
        assert registry.validators[validator.validator_id] == validator
        
        # Test duplicate validator
        with pytest.raises(ValueError, match="Validator .* already exists"):
            registry.add_validator(validator)
    
    def test_generate_asset_id(self):
        """Test asset ID generation."""
        registry = Registry()
        
        asset_id = registry.generate_asset_id(
            issuer_pubkey="a" * 64,
            name="Test Token",
            nonce="test_nonce"
        )
        
        assert len(asset_id) == 64
        assert all(c in "0123456789abcdef" for c in asset_id)
    
    def test_query_methods(self):
        """Test registry query methods."""
        registry = Registry()
        
        # Add test assets
        fungible = FungibleAsset(
            asset_id="a" * 64,
            name="Fungible Token",
            symbol="FT",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        
        nft = NFTAsset(
            asset_id="c" * 64,
            name="NFT Collection",
            symbol="NFT",
            issuer_pubkey="d" * 64,
            collection_size=100
        )
        
        registry.add_asset(fungible)
        registry.add_asset(nft)
        
        # Test get_asset
        assert registry.get_asset("a" * 64) == fungible
        assert registry.get_asset("c" * 64) == nft
        assert registry.get_asset("nonexistent") is None
        
        # Test list_assets
        all_assets = registry.list_assets()
        assert len(all_assets) == 2
        
        fungible_assets = registry.list_assets(AssetType.FUNGIBLE)
        assert len(fungible_assets) == 1
        assert fungible_assets[0] == fungible
        
        nft_assets = registry.list_assets(AssetType.NFT)
        assert len(nft_assets) == 1
        assert nft_assets[0] == nft


class TestRegistryMetadata:
    """Test registry metadata model."""
    
    def test_metadata_creation(self):
        """Test metadata creation."""
        metadata = RegistryMetadata()
        
        assert metadata.version == "1.0.0"
        assert metadata.description == "Bitcoin Native Asset Protocol Registry"
        assert metadata.network == "regtest"
        assert isinstance(metadata.created_at, datetime)
        assert isinstance(metadata.updated_at, datetime)
    
    def test_update_timestamp(self):
        """Test timestamp update."""
        metadata = RegistryMetadata()
        original_timestamp = metadata.updated_at
        
        # Small delay to ensure timestamp difference
        import time
        time.sleep(0.01)
        
        metadata.update_timestamp()
        assert metadata.updated_at > original_timestamp