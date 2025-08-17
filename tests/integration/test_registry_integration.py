"""
Integration tests for complete registry workflows.
"""

import pytest
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

from registry.manager import RegistryManager
from registry.schema import (
    FungibleAsset, NFTAsset, AssetType, AssetStatus,
    ValidatorConfig, TransactionEntry
)
from registry.migrations import MigrationManager
from registry.storage import RegistryStorage


class TestRegistryIntegration:
    """Test complete registry workflows and integration scenarios."""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def registry_manager(self, temp_storage_dir):
        """Create registry manager with temporary storage."""
        return RegistryManager(storage_dir=temp_storage_dir, enable_cache=True)
    
    def test_complete_asset_lifecycle(self, registry_manager):
        """Test complete asset lifecycle from creation to state updates."""
        # 1. Register validator
        validator = ValidatorConfig(
            validator_id="primary_validator",
            pubkey="a" * 64,
            permissions=["mint", "transfer", "burn"]
        )
        registry_manager.register_validator(validator)
        
        # 2. Create and register fungible asset
        asset = FungibleAsset(
            asset_id="b" * 64,
            name="Integration Test Token",
            symbol="ITT",
            issuer_pubkey="c" * 64,
            maximum_supply=1000000,
            per_mint_limit=1000,
            decimal_places=2
        )
        
        # Generate asset ID
        generated_id = registry_manager.generate_asset_id(
            issuer_pubkey=asset.issuer_pubkey,
            name=asset.name,
            asset_type=AssetType.FUNGIBLE
        )
        asset.asset_id = generated_id
        
        # Register asset
        checksum1 = registry_manager.register_asset(asset)
        assert checksum1 is not None
        
        # 3. Verify asset exists and can be retrieved
        retrieved_asset = registry_manager.get_asset_by_id(asset.asset_id)
        assert retrieved_asset is not None
        assert retrieved_asset.name == asset.name
        
        # 4. Perform multiple state updates
        transactions = []
        total_minted = 0
        
        for i in range(5):
            amount = 100 * (i + 1)
            tx = TransactionEntry(
                tx_id=f"{i:064d}",
                amount=amount,
                recipient=f"address_{i}",
                block_height=1000 + i
            )
            
            checksum = registry_manager.update_asset_state(asset.asset_id, tx)
            assert checksum is not None
            
            transactions.append(tx)
            total_minted += amount
        
        # 5. Verify final state
        state = registry_manager.get_asset_state(asset.asset_id)
        assert state.minted_supply == total_minted
        assert state.transaction_count == 5
        assert len(state.transaction_history) == 5
        
        # 6. Get supply information
        supply_info = registry_manager.get_asset_supply_info(asset.asset_id)
        assert supply_info['minted_supply'] == total_minted
        assert supply_info['remaining_supply'] == asset.maximum_supply - total_minted
        
        # 7. Test search functionality
        found_assets = registry_manager.find_assets_by_symbol("ITT")
        assert len(found_assets) == 1
        assert found_assets[0].asset_id == asset.asset_id
        
        issuer_assets = registry_manager.find_assets_by_issuer(asset.issuer_pubkey)
        assert len(issuer_assets) == 1
    
    def test_nft_collection_workflow(self, registry_manager):
        """Test complete NFT collection workflow."""
        # 1. Create NFT collection
        collection = NFTAsset(
            asset_id="d" * 64,
            name="Integration Test NFTs",
            symbol="ITNFT",
            issuer_pubkey="e" * 64,
            collection_size=10,
            content_hash="f" * 64,
            manifest_hash="g" * 64
        )
        
        registry_manager.register_asset(collection)
        
        # 2. Issue individual NFTs
        issued_tokens = []
        for token_id in range(1, 6):  # Issue 5 NFTs
            tx = TransactionEntry(
                tx_id=f"nft_{token_id:060d}",
                amount=1,
                recipient=f"owner_{token_id}",
                block_height=2000 + token_id
            )
            
            registry_manager.update_asset_state(
                collection.asset_id,
                tx,
                nft_token_id=token_id
            )
            issued_tokens.append(token_id)
        
        # 3. Verify NFT state
        state = registry_manager.get_asset_state(collection.asset_id)
        assert state.minted_supply == 5
        assert len(state.issued_nft_ids) == 5
        assert all(token_id in state.issued_nft_ids for token_id in issued_tokens)
        
        # 4. Get NFT supply info
        supply_info = registry_manager.get_asset_supply_info(collection.asset_id)
        assert supply_info['issued_nft_count'] == 5
        assert supply_info['available_nft_count'] == 5  # 10 - 5
        assert set(supply_info['issued_nft_ids']) == set(issued_tokens)
    
    def test_mixed_asset_registry(self, registry_manager):
        """Test registry with mixed asset types."""
        # Create multiple validators
        validators = [
            ValidatorConfig(
                validator_id=f"validator_{i}",
                pubkey=f"{i:064d}",
                permissions=["mint"] if i % 2 == 0 else ["mint", "transfer"]
            )
            for i in range(3)
        ]
        
        for validator in validators:
            registry_manager.register_validator(validator)
        
        # Create multiple fungible assets
        fungible_assets = [
            FungibleAsset(
                asset_id=f"fungible_{i:060d}",
                name=f"Token {i}",
                symbol=f"TOK{i}",
                issuer_pubkey=f"issuer_{i:060d}",
                maximum_supply=10000 * (i + 1),
                per_mint_limit=100 * (i + 1)
            )
            for i in range(3)
        ]
        
        # Create multiple NFT collections
        nft_assets = [
            NFTAsset(
                asset_id=f"nft_{i:064d}",
                name=f"Collection {i}",
                symbol=f"NFT{i}",
                issuer_pubkey=f"creator_{i:060d}",
                collection_size=50 * (i + 1)
            )
            for i in range(2)
        ]
        
        # Register all assets
        all_assets = fungible_assets + nft_assets
        for asset in all_assets:
            registry_manager.register_asset(asset)
        
        # Verify registry statistics
        stats = registry_manager.get_registry_stats()
        assert stats['total_assets'] == 5
        assert stats['fungible_assets'] == 3
        assert stats['nft_assets'] == 2
        assert stats['active_assets'] == 5
        assert stats['total_validators'] == 3
        
        # Test asset listing and filtering
        all_listed = registry_manager.list_assets()
        assert len(all_listed) == 5
        
        fungible_listed = registry_manager.list_assets(AssetType.FUNGIBLE)
        assert len(fungible_listed) == 3
        
        nft_listed = registry_manager.list_assets(AssetType.NFT)
        assert len(nft_listed) == 2
        
        # Test pagination
        paginated = registry_manager.list_assets(limit=2)
        assert len(paginated) == 2
        
        offset_paginated = registry_manager.list_assets(offset=2, limit=2)
        assert len(offset_paginated) == 2
    
    def test_backup_restore_workflow(self, registry_manager):
        """Test backup and restore functionality."""
        # Create initial data
        asset = FungibleAsset(
            asset_id="h" * 64,
            name="Backup Test Token",
            symbol="BTT",
            issuer_pubkey="i" * 64,
            maximum_supply=50000,
            per_mint_limit=500
        )
        
        registry_manager.register_asset(asset)
        
        # Update state
        tx = TransactionEntry(
            tx_id="j" * 64,
            amount=1000,
            recipient="test_address"
        )
        registry_manager.update_asset_state(asset.asset_id, tx)
        
        # Create backup
        backup_success = registry_manager.backup_registry()
        assert backup_success
        
        # Verify backup exists
        backups = registry_manager.list_backups()
        assert len(backups) > 0
        
        # Modify registry after backup
        tx2 = TransactionEntry(
            tx_id="k" * 64,
            amount=2000,
            recipient="test_address_2"
        )
        registry_manager.update_asset_state(asset.asset_id, tx2)
        
        # Verify state changed
        state_before_restore = registry_manager.get_asset_state(asset.asset_id)
        assert state_before_restore.minted_supply == 3000
        
        # Restore from backup
        latest_backup = backups[0]
        restore_success = registry_manager.restore_backup(latest_backup)
        assert restore_success
        
        # Verify restoration
        state_after_restore = registry_manager.get_asset_state(asset.asset_id)
        assert state_after_restore.minted_supply == 1000  # Back to original state
    
    def test_migration_integration(self, registry_manager):
        """Test schema migration integration."""
        # Create asset with old schema structure
        asset = FungibleAsset(
            asset_id="l" * 64,
            name="Migration Test Token",
            symbol="MTT",
            issuer_pubkey="m" * 64,
            maximum_supply=75000,
            per_mint_limit=750
        )
        
        registry_manager.register_asset(asset)
        
        # Get storage and migration manager
        storage = RegistryStorage(storage_dir=registry_manager.storage_dir)
        migration_manager = MigrationManager(storage)
        
        # Check if migration is needed
        needs_migration = migration_manager.needs_migration()
        
        if needs_migration:
            # Perform migration
            result = migration_manager.migrate()
            assert result['status'] == 'success'
            
            # Verify migration worked
            current_version = migration_manager.get_current_version()
            latest_version = migration_manager.migration_registry.get_latest_version()
            assert current_version == latest_version
        
        # Verify asset still accessible after migration
        retrieved_asset = registry_manager.get_asset_by_id(asset.asset_id)
        assert retrieved_asset is not None
        assert retrieved_asset.name == asset.name
    
    def test_concurrent_multi_operation_workflow(self, registry_manager):
        """Test concurrent operations across different asset types."""
        results = []
        errors = []
        
        def worker_thread(thread_id, operation_type):
            """Worker thread for concurrent operations."""
            try:
                if operation_type == "register_fungible":
                    for i in range(5):
                        asset = FungibleAsset(
                            asset_id=f"thread_{thread_id}_{i:060d}",
                            name=f"Thread {thread_id} Token {i}",
                            symbol=f"T{thread_id}T{i}",
                            issuer_pubkey=f"issuer_{thread_id:060d}",
                            maximum_supply=1000,
                            per_mint_limit=100
                        )
                        checksum = registry_manager.register_asset(asset)
                        results.append(f"registered_{asset.asset_id}")
                
                elif operation_type == "register_nft":
                    for i in range(3):
                        collection = NFTAsset(
                            asset_id=f"nft_thread_{thread_id}_{i:060d}",
                            name=f"Thread {thread_id} Collection {i}",
                            symbol=f"N{thread_id}C{i}",
                            issuer_pubkey=f"creator_{thread_id:060d}",
                            collection_size=20
                        )
                        checksum = registry_manager.register_asset(collection)
                        results.append(f"registered_{collection.asset_id}")
                
                elif operation_type == "register_validator":
                    for i in range(2):
                        validator = ValidatorConfig(
                            validator_id=f"thread_{thread_id}_validator_{i}",
                            pubkey=f"thread_{thread_id:060d}",
                            permissions=["mint", "transfer"]
                        )
                        checksum = registry_manager.register_validator(validator)
                        results.append(f"validator_{validator.validator_id}")
                
            except Exception as e:
                errors.append(f"Thread {thread_id} ({operation_type}): {str(e)}")
        
        # Create threads for different operations
        threads = []
        operations = ["register_fungible", "register_nft", "register_validator"]
        
        for i, operation in enumerate(operations):
            for thread_num in range(2):  # 2 threads per operation type
                thread = threading.Thread(
                    target=worker_thread,
                    args=(i * 2 + thread_num, operation)
                )
                threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) > 0
        
        # Verify registry state
        stats = registry_manager.get_registry_stats()
        assert stats['total_assets'] > 0
        assert stats['total_validators'] > 0
        
        # Verify all assets are accessible
        all_assets = registry_manager.list_assets()
        for asset in all_assets:
            retrieved = registry_manager.get_asset_by_id(asset.asset_id)
            assert retrieved is not None
    
    def test_error_recovery_scenarios(self, registry_manager):
        """Test error recovery and data consistency."""
        # Test duplicate asset registration
        asset = FungibleAsset(
            asset_id="n" * 64,
            name="Error Test Token",
            symbol="ETT",
            issuer_pubkey="o" * 64,
            maximum_supply=100000,
            per_mint_limit=1000
        )
        
        # First registration should succeed
        checksum1 = registry_manager.register_asset(asset)
        assert checksum1 is not None
        
        # Second registration should fail
        with pytest.raises(Exception):  # AssetExistsError
            registry_manager.register_asset(asset)
        
        # Registry should still be consistent
        retrieved = registry_manager.get_asset_by_id(asset.asset_id)
        assert retrieved is not None
        
        # Test state update on non-existent asset
        tx = TransactionEntry(
            tx_id="p" * 64,
            amount=500,
            recipient="test_address"
        )
        
        with pytest.raises(Exception):  # AssetNotFoundError
            registry_manager.update_asset_state("nonexistent", tx)
        
        # Original asset should still be accessible
        retrieved_again = registry_manager.get_asset_by_id(asset.asset_id)
        assert retrieved_again is not None
        
        # Valid state update should work
        checksum2 = registry_manager.update_asset_state(asset.asset_id, tx)
        assert checksum2 is not None
        
        final_state = registry_manager.get_asset_state(asset.asset_id)
        assert final_state.minted_supply == 500