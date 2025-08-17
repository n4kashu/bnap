"""
Unit tests for registry manager.
"""

import pytest
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

from registry.manager import RegistryManager, AssetExistsError, AssetNotFoundError
from registry.schema import (
    FungibleAsset, NFTAsset, AssetType, AssetStatus,
    ValidatorConfig, TransactionEntry
)
from registry.storage import RegistryStorage


class TestRegistryManager:
    """Test registry manager functionality."""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def registry_manager(self, temp_storage_dir):
        """Create registry manager with temporary storage."""
        return RegistryManager(storage_dir=temp_storage_dir, enable_cache=True)
    
    @pytest.fixture
    def sample_fungible_asset(self):
        """Create sample fungible asset."""
        return FungibleAsset(
            asset_id="a" * 64,
            name="Test Token",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000000,
            per_mint_limit=1000
        )
    
    @pytest.fixture
    def sample_nft_asset(self):
        """Create sample NFT asset."""
        return NFTAsset(
            asset_id="c" * 64,
            name="Test Collection",
            symbol="TESTNFT",
            issuer_pubkey="d" * 64,
            collection_size=100
        )
    
    def test_manager_initialization(self, registry_manager):
        """Test registry manager initialization."""
        assert registry_manager is not None
        assert registry_manager.cache is not None
        assert registry_manager._registry is not None
    
    def test_register_asset(self, registry_manager, sample_fungible_asset):
        """Test asset registration."""
        # Register asset
        checksum = registry_manager.register_asset(sample_fungible_asset)
        assert isinstance(checksum, str)
        assert len(checksum) == 64  # SHA-256 checksum
        
        # Verify asset exists
        assert registry_manager.asset_exists(sample_fungible_asset.asset_id)
        
        # Test duplicate registration
        with pytest.raises(AssetExistsError):
            registry_manager.register_asset(sample_fungible_asset)
    
    def test_register_validator(self, registry_manager):
        """Test validator registration."""
        validator = ValidatorConfig(
            validator_id="test_validator",
            pubkey="a" * 64,
            permissions=["mint", "transfer"]
        )
        
        checksum = registry_manager.register_validator(validator)
        assert isinstance(checksum, str)
        
        # Verify validator exists
        retrieved = registry_manager.get_validator("test_validator")
        assert retrieved is not None
        assert retrieved.validator_id == "test_validator"
    
    def test_get_asset_by_id(self, registry_manager, sample_fungible_asset):
        """Test asset retrieval by ID."""
        # Register asset first
        registry_manager.register_asset(sample_fungible_asset)
        
        # Retrieve asset
        retrieved = registry_manager.get_asset_by_id(sample_fungible_asset.asset_id)
        assert retrieved is not None
        assert retrieved.asset_id == sample_fungible_asset.asset_id
        assert retrieved.name == sample_fungible_asset.name
        
        # Test non-existent asset
        non_existent = registry_manager.get_asset_by_id("nonexistent")
        assert non_existent is None
    
    def test_update_asset_state(self, registry_manager, sample_fungible_asset):
        """Test asset state updates."""
        # Register asset first
        registry_manager.register_asset(sample_fungible_asset)
        
        # Create transaction entry
        tx_entry = TransactionEntry(
            tx_id="f" * 64,
            amount=100,
            recipient="test_address"
        )
        
        # Update state
        checksum = registry_manager.update_asset_state(
            sample_fungible_asset.asset_id,
            tx_entry
        )
        assert isinstance(checksum, str)
        
        # Verify state update
        state = registry_manager.get_asset_state(sample_fungible_asset.asset_id)
        assert state is not None
        assert state.minted_supply == 100
        assert state.transaction_count == 1
        assert len(state.transaction_history) == 1
        
        # Test non-existent asset
        with pytest.raises(AssetNotFoundError):
            registry_manager.update_asset_state("nonexistent", tx_entry)
    
    def test_nft_state_update(self, registry_manager, sample_nft_asset):
        """Test NFT-specific state updates."""
        # Register NFT asset
        registry_manager.register_asset(sample_nft_asset)
        
        # Create transaction entry for NFT
        tx_entry = TransactionEntry(
            tx_id="f" * 64,
            amount=1,
            recipient="test_address"
        )
        
        # Update state with NFT token ID
        registry_manager.update_asset_state(
            sample_nft_asset.asset_id,
            tx_entry,
            nft_token_id=1
        )
        
        # Verify NFT state
        state = registry_manager.get_asset_state(sample_nft_asset.asset_id)
        assert 1 in state.issued_nft_ids
        assert state.minted_supply == 1
    
    def test_list_assets(self, registry_manager, sample_fungible_asset, sample_nft_asset):
        """Test asset listing and filtering."""
        # Register both assets
        registry_manager.register_asset(sample_fungible_asset)
        registry_manager.register_asset(sample_nft_asset)
        
        # List all assets
        all_assets = registry_manager.list_assets()
        assert len(all_assets) == 2
        
        # List fungible assets only
        fungible_assets = registry_manager.list_assets(AssetType.FUNGIBLE)
        assert len(fungible_assets) == 1
        assert fungible_assets[0].asset_type == AssetType.FUNGIBLE
        
        # List NFT assets only
        nft_assets = registry_manager.list_assets(AssetType.NFT)
        assert len(nft_assets) == 1
        assert nft_assets[0].asset_type == AssetType.NFT
        
        # Test pagination
        limited_assets = registry_manager.list_assets(limit=1)
        assert len(limited_assets) == 1
        
        offset_assets = registry_manager.list_assets(offset=1)
        assert len(offset_assets) == 1
    
    def test_find_assets_by_issuer(self, registry_manager, sample_fungible_asset):
        """Test finding assets by issuer."""
        # Register asset
        registry_manager.register_asset(sample_fungible_asset)
        
        # Find by issuer
        assets = registry_manager.find_assets_by_issuer(sample_fungible_asset.issuer_pubkey)
        assert len(assets) == 1
        assert assets[0].issuer_pubkey == sample_fungible_asset.issuer_pubkey
        
        # Test non-existent issuer
        no_assets = registry_manager.find_assets_by_issuer("nonexistent")
        assert len(no_assets) == 0
    
    def test_find_assets_by_symbol(self, registry_manager, sample_fungible_asset):
        """Test finding assets by symbol."""
        # Register asset
        registry_manager.register_asset(sample_fungible_asset)
        
        # Find by symbol
        assets = registry_manager.find_assets_by_symbol(sample_fungible_asset.symbol)
        assert len(assets) == 1
        assert assets[0].symbol == sample_fungible_asset.symbol
        
        # Test case insensitive search
        assets_lower = registry_manager.find_assets_by_symbol(sample_fungible_asset.symbol.lower())
        assert len(assets_lower) == 1
    
    def test_get_asset_supply_info(self, registry_manager, sample_fungible_asset):
        """Test asset supply information retrieval."""
        # Register asset and update state
        registry_manager.register_asset(sample_fungible_asset)
        
        tx_entry = TransactionEntry(
            tx_id="f" * 64,
            amount=100,
            recipient="test_address"
        )
        registry_manager.update_asset_state(sample_fungible_asset.asset_id, tx_entry)
        
        # Get supply info
        info = registry_manager.get_asset_supply_info(sample_fungible_asset.asset_id)
        
        assert info['asset_id'] == sample_fungible_asset.asset_id
        assert info['asset_type'] == AssetType.FUNGIBLE
        assert info['minted_supply'] == 100
        assert info['maximum_supply'] == sample_fungible_asset.maximum_supply
        assert info['remaining_supply'] == sample_fungible_asset.maximum_supply - 100
        assert info['per_mint_limit'] == sample_fungible_asset.per_mint_limit
        
        # Test non-existent asset
        with pytest.raises(AssetNotFoundError):
            registry_manager.get_asset_supply_info("nonexistent")
    
    def test_nft_supply_info(self, registry_manager, sample_nft_asset):
        """Test NFT supply information."""
        # Register NFT and issue tokens
        registry_manager.register_asset(sample_nft_asset)
        
        tx_entry = TransactionEntry(
            tx_id="f" * 64,
            amount=1,
            recipient="test_address"
        )
        registry_manager.update_asset_state(
            sample_nft_asset.asset_id,
            tx_entry,
            nft_token_id=1
        )
        
        # Get supply info
        info = registry_manager.get_asset_supply_info(sample_nft_asset.asset_id)
        
        assert info['asset_type'] == AssetType.NFT
        assert info['collection_size'] == sample_nft_asset.collection_size
        assert info['issued_nft_count'] == 1
        assert info['available_nft_count'] == sample_nft_asset.collection_size - 1
        assert 1 in info['issued_nft_ids']
    
    def test_batch_register_assets(self, registry_manager, sample_fungible_asset, sample_nft_asset):
        """Test batch asset registration."""
        assets = [sample_fungible_asset, sample_nft_asset]
        
        checksum = registry_manager.batch_register_assets(assets)
        assert isinstance(checksum, str)
        
        # Verify both assets exist
        assert registry_manager.asset_exists(sample_fungible_asset.asset_id)
        assert registry_manager.asset_exists(sample_nft_asset.asset_id)
        
        # Test batch registration with duplicate
        with pytest.raises(AssetExistsError):
            registry_manager.batch_register_assets([sample_fungible_asset])
    
    def test_generate_asset_id(self, registry_manager):
        """Test asset ID generation."""
        asset_id = registry_manager.generate_asset_id(
            issuer_pubkey="a" * 64,
            name="Test Asset",
            asset_type=AssetType.FUNGIBLE
        )
        
        assert len(asset_id) == 64
        assert all(c in "0123456789abcdef" for c in asset_id)
        
        # Test uniqueness
        asset_id2 = registry_manager.generate_asset_id(
            issuer_pubkey="a" * 64,
            name="Test Asset",
            asset_type=AssetType.FUNGIBLE
        )
        assert asset_id != asset_id2
    
    def test_cache_functionality(self, registry_manager, sample_fungible_asset):
        """Test caching functionality."""
        # Register asset
        registry_manager.register_asset(sample_fungible_asset)
        
        # First retrieval (should cache)
        asset1 = registry_manager.get_asset_by_id(sample_fungible_asset.asset_id)
        
        # Second retrieval (should use cache)
        asset2 = registry_manager.get_asset_by_id(sample_fungible_asset.asset_id)
        
        assert asset1 == asset2
        
        # Test cache cleanup
        cleaned = registry_manager.cleanup_cache()
        assert isinstance(cleaned, int)
    
    def test_registry_stats(self, registry_manager, sample_fungible_asset, sample_nft_asset):
        """Test registry statistics."""
        # Register assets and validator
        registry_manager.register_asset(sample_fungible_asset)
        registry_manager.register_asset(sample_nft_asset)
        
        validator = ValidatorConfig(
            validator_id="test_validator",
            pubkey="a" * 64
        )
        registry_manager.register_validator(validator)
        
        # Get stats
        stats = registry_manager.get_registry_stats()
        
        assert stats['total_assets'] == 2
        assert stats['fungible_assets'] == 1
        assert stats['nft_assets'] == 1
        assert stats['active_assets'] == 2
        assert stats['total_validators'] == 1
        assert stats['active_validators'] == 1
        assert 'storage_info' in stats
        assert 'cache_info' in stats
    
    def test_reload_registry(self, registry_manager, sample_fungible_asset):
        """Test registry reload functionality."""
        # Register asset
        registry_manager.register_asset(sample_fungible_asset)
        
        # Verify asset exists
        assert registry_manager.asset_exists(sample_fungible_asset.asset_id)
        
        # Reload registry
        registry_manager.reload_registry()
        
        # Verify asset still exists after reload
        assert registry_manager.asset_exists(sample_fungible_asset.asset_id)
    
    def test_backup_and_restore(self, registry_manager, sample_fungible_asset):
        """Test backup and restore functionality."""
        # Register asset
        registry_manager.register_asset(sample_fungible_asset)
        
        # Create backup
        backup_success = registry_manager.backup_registry()
        assert backup_success
        
        # List backups
        backups = registry_manager.list_backups()
        assert len(backups) > 0
        
        # Test restore (using most recent backup)
        if backups:
            restore_success = registry_manager.restore_backup(backups[0])
            assert restore_success


class TestConcurrency:
    """Test concurrent access to registry manager."""
    
    @pytest.fixture
    def registry_manager(self):
        """Create registry manager for concurrency tests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield RegistryManager(storage_dir=temp_dir, enable_cache=True)
    
    def test_concurrent_asset_registration(self, registry_manager):
        """Test concurrent asset registration."""
        results = []
        errors = []
        
        def register_asset(asset_id_suffix):
            try:
                asset = FungibleAsset(
                    asset_id=f"{asset_id_suffix:064d}",
                    name=f"Test Token {asset_id_suffix}",
                    symbol=f"TEST{asset_id_suffix}",
                    issuer_pubkey="b" * 64,
                    maximum_supply=1000,
                    per_mint_limit=100
                )
                checksum = registry_manager.register_asset(asset)
                results.append((asset_id_suffix, checksum))
            except Exception as e:
                errors.append((asset_id_suffix, str(e)))
        
        # Create and start threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=register_asset, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(results) == 10
        assert len(errors) == 0
        
        # Verify all assets exist
        for i in range(10):
            asset_id = f"{i:064d}"
            assert registry_manager.asset_exists(asset_id)
    
    def test_concurrent_state_updates(self, registry_manager):
        """Test concurrent state updates."""
        # Register asset first
        asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test Token",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=10000,
            per_mint_limit=100
        )
        registry_manager.register_asset(asset)
        
        results = []
        errors = []
        
        def update_state(tx_id_suffix, amount):
            try:
                tx_entry = TransactionEntry(
                    tx_id=f"{tx_id_suffix:064d}",
                    amount=amount,
                    recipient=f"address_{tx_id_suffix}"
                )
                checksum = registry_manager.update_asset_state(asset.asset_id, tx_entry)
                results.append((tx_id_suffix, checksum))
            except Exception as e:
                errors.append((tx_id_suffix, str(e)))
        
        # Create and start threads
        threads = []
        for i in range(20):
            thread = threading.Thread(target=update_state, args=(i, 10))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(results) == 20
        assert len(errors) == 0
        
        # Verify final state
        state = registry_manager.get_asset_state(asset.asset_id)
        assert state.minted_supply == 200  # 20 threads * 10 amount each
        assert state.transaction_count == 20
    
    def test_concurrent_read_operations(self, registry_manager):
        """Test concurrent read operations."""
        # Register multiple assets
        assets = []
        for i in range(5):
            asset = FungibleAsset(
                asset_id=f"{i:064d}",
                name=f"Test Token {i}",
                symbol=f"TEST{i}",
                issuer_pubkey="b" * 64,
                maximum_supply=1000,
                per_mint_limit=100
            )
            registry_manager.register_asset(asset)
            assets.append(asset)
        
        results = []
        
        def read_operations(thread_id):
            thread_results = []
            for _ in range(100):  # Perform 100 read operations per thread
                # Random read operations
                import random
                asset_idx = random.randint(0, 4)
                asset_id = f"{asset_idx:064d}"
                
                retrieved_asset = registry_manager.get_asset_by_id(asset_id)
                assert retrieved_asset is not None
                
                state = registry_manager.get_asset_state(asset_id)
                assert state is not None
                
                thread_results.append((asset_id, retrieved_asset.name))
            
            results.extend(thread_results)
        
        # Create and start threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=read_operations, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(results) == 1000  # 10 threads * 100 operations each