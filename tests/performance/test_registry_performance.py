"""
Performance tests for registry operations.
"""

import pytest
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from registry.manager import RegistryManager
from registry.schema import FungibleAsset, NFTAsset, ValidatorConfig, TransactionEntry


@pytest.mark.performance
class TestRegistryPerformance:
    """Test registry performance under various load conditions."""
    
    @pytest.fixture
    def registry_manager(self):
        """Create registry manager for performance tests."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield RegistryManager(storage_dir=temp_dir, enable_cache=True)
    
    @pytest.fixture
    def large_dataset(self):
        """Create large dataset for performance testing."""
        assets = []
        validators = []
        transactions = []
        
        # Create 100 validators
        for i in range(100):
            validator = ValidatorConfig(
                validator_id=f"perf_validator_{i}",
                pubkey=f"{i:064d}",
                permissions=["mint", "transfer"] if i % 2 == 0 else ["mint"]
            )
            validators.append(validator)
        
        # Create 500 fungible assets
        for i in range(500):
            asset = FungibleAsset(
                asset_id=f"perf_asset_{i:060d}",
                name=f"Performance Token {i}",
                symbol=f"PERF{i}",
                issuer_pubkey=f"issuer_{i:060d}",
                maximum_supply=1000000,
                per_mint_limit=1000
            )
            assets.append(asset)
        
        # Create 100 NFT collections
        for i in range(100):
            nft = NFTAsset(
                asset_id=f"perf_nft_{i:060d}",
                name=f"Performance Collection {i}",
                symbol=f"PNFT{i}",
                issuer_pubkey=f"creator_{i:060d}",
                collection_size=100
            )
            assets.append(nft)
        
        # Create 10000 transactions
        for i in range(10000):
            tx = TransactionEntry(
                tx_id=f"perf_tx_{i:060d}",
                amount=100 + (i % 1000),
                recipient=f"address_{i % 1000}",
                block_height=1000 + i
            )
            transactions.append(tx)
        
        return {
            'validators': validators,
            'assets': assets,
            'transactions': transactions
        }
    
    def test_bulk_asset_registration_performance(self, registry_manager, large_dataset, performance_timer):
        """Test bulk asset registration performance."""
        assets = large_dataset['assets']
        
        with performance_timer() as timer:
            for asset in assets:
                registry_manager.register_asset(asset)
        
        elapsed = timer.elapsed()
        assets_per_second = len(assets) / elapsed
        
        print(f"\nBulk registration performance:")
        print(f"  Assets registered: {len(assets)}")
        print(f"  Time elapsed: {elapsed:.2f} seconds")
        print(f"  Assets per second: {assets_per_second:.2f}")
        
        # Performance assertions
        assert elapsed < 30.0  # Should complete within 30 seconds
        assert assets_per_second > 10  # Should handle at least 10 assets per second
        
        # Verify all assets were registered
        stats = registry_manager.get_registry_stats()
        assert stats['total_assets'] == len(assets)
    
    def test_concurrent_registration_performance(self, registry_manager, large_dataset, performance_timer):
        """Test concurrent asset registration performance."""
        assets = large_dataset['assets'][:200]  # Use subset for concurrency test
        
        def register_batch(asset_batch):
            """Register a batch of assets."""
            results = []
            for asset in asset_batch:
                try:
                    checksum = registry_manager.register_asset(asset)
                    results.append((asset.asset_id, checksum))
                except Exception as e:
                    results.append((asset.asset_id, str(e)))
            return results
        
        # Split assets into batches for concurrent processing
        batch_size = 20
        batches = [assets[i:i + batch_size] for i in range(0, len(assets), batch_size)]
        
        with performance_timer() as timer:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(register_batch, batch) for batch in batches]
                
                all_results = []
                for future in as_completed(futures):
                    all_results.extend(future.result())
        
        elapsed = timer.elapsed()
        assets_per_second = len(assets) / elapsed
        
        print(f"\nConcurrent registration performance:")
        print(f"  Assets registered: {len(assets)}")
        print(f"  Batches: {len(batches)}")
        print(f"  Time elapsed: {elapsed:.2f} seconds")
        print(f"  Assets per second: {assets_per_second:.2f}")
        
        # Performance assertions
        assert elapsed < 15.0  # Should be faster with concurrency
        assert assets_per_second > 15  # Should handle more assets per second
        
        # Verify all registrations succeeded
        successful_registrations = [r for r in all_results if len(r[1]) == 64]  # checksum length
        assert len(successful_registrations) == len(assets)
    
    def test_bulk_state_updates_performance(self, registry_manager, large_dataset, performance_timer):
        """Test bulk state update performance."""
        # Register a subset of assets first
        assets = large_dataset['assets'][:50]
        for asset in assets:
            registry_manager.register_asset(asset)
        
        # Use subset of transactions
        transactions = large_dataset['transactions'][:1000]
        
        with performance_timer() as timer:
            for i, tx in enumerate(transactions):
                asset_id = assets[i % len(assets)].asset_id
                registry_manager.update_asset_state(asset_id, tx)
        
        elapsed = timer.elapsed()
        updates_per_second = len(transactions) / elapsed
        
        print(f"\nBulk state updates performance:")
        print(f"  Updates performed: {len(transactions)}")
        print(f"  Assets involved: {len(assets)}")
        print(f"  Time elapsed: {elapsed:.2f} seconds")
        print(f"  Updates per second: {updates_per_second:.2f}")
        
        # Performance assertions
        assert elapsed < 20.0  # Should complete within 20 seconds
        assert updates_per_second > 25  # Should handle at least 25 updates per second
    
    def test_concurrent_state_updates_performance(self, registry_manager, large_dataset, performance_timer):
        """Test concurrent state update performance."""
        # Register assets first
        assets = large_dataset['assets'][:20]
        for asset in assets:
            registry_manager.register_asset(asset)
        
        # Use subset of transactions
        transactions = large_dataset['transactions'][:500]
        
        def update_batch(tx_batch):
            """Update states for a batch of transactions."""
            results = []
            for i, tx in enumerate(tx_batch):
                try:
                    asset_id = assets[i % len(assets)].asset_id
                    checksum = registry_manager.update_asset_state(asset_id, tx)
                    results.append((tx.tx_id, checksum))
                except Exception as e:
                    results.append((tx.tx_id, str(e)))
            return results
        
        # Split transactions into batches
        batch_size = 25
        batches = [transactions[i:i + batch_size] for i in range(0, len(transactions), batch_size)]
        
        with performance_timer() as timer:
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(update_batch, batch) for batch in batches]
                
                all_results = []
                for future in as_completed(futures):
                    all_results.extend(future.result())
        
        elapsed = timer.elapsed()
        updates_per_second = len(transactions) / elapsed
        
        print(f"\nConcurrent state updates performance:")
        print(f"  Updates performed: {len(transactions)}")
        print(f"  Batches: {len(batches)}")
        print(f"  Time elapsed: {elapsed:.2f} seconds")
        print(f"  Updates per second: {updates_per_second:.2f}")
        
        # Performance assertions
        assert elapsed < 10.0  # Should be faster with concurrency
        assert updates_per_second > 35  # Should handle more updates per second
        
        # Verify successful updates
        successful_updates = [r for r in all_results if len(r[1]) == 64]  # checksum length
        assert len(successful_updates) == len(transactions)
    
    def test_large_registry_query_performance(self, registry_manager, large_dataset, performance_timer):
        """Test query performance on large registry."""
        # Register all data
        validators = large_dataset['validators']
        assets = large_dataset['assets']
        
        # Register validators and assets
        for validator in validators:
            registry_manager.register_validator(validator)
        
        for asset in assets:
            registry_manager.register_asset(asset)
        
        # Test various query operations
        query_operations = []
        
        # Test list_assets performance
        with performance_timer() as timer:
            all_assets = registry_manager.list_assets()
        query_operations.append(("list_assets", timer.elapsed(), len(all_assets)))
        
        # Test filtered list_assets performance
        with performance_timer() as timer:
            fungible_assets = registry_manager.list_assets(AssetType.FUNGIBLE)
        query_operations.append(("list_fungible", timer.elapsed(), len(fungible_assets)))
        
        # Test pagination performance
        with performance_timer() as timer:
            paginated_assets = registry_manager.list_assets(limit=100)
        query_operations.append(("paginated_list", timer.elapsed(), len(paginated_assets)))
        
        # Test search operations
        with performance_timer() as timer:
            search_results = registry_manager.find_assets_by_symbol("PERF1")
        query_operations.append(("symbol_search", timer.elapsed(), len(search_results)))
        
        # Test individual asset retrieval
        test_asset_ids = [asset.asset_id for asset in assets[:100]]
        
        with performance_timer() as timer:
            for asset_id in test_asset_ids:
                registry_manager.get_asset_by_id(asset_id)
        query_operations.append(("individual_retrieval", timer.elapsed(), len(test_asset_ids)))
        
        # Test registry stats
        with performance_timer() as timer:
            stats = registry_manager.get_registry_stats()
        query_operations.append(("registry_stats", timer.elapsed(), 1))
        
        print(f"\nQuery performance on large registry:")
        print(f"  Total assets: {len(assets)}")
        print(f"  Total validators: {len(validators)}")
        
        for operation, elapsed, count in query_operations:
            operations_per_second = count / elapsed if elapsed > 0 else float('inf')
            print(f"  {operation}: {elapsed:.3f}s ({operations_per_second:.1f} ops/sec)")
            
            # Performance assertions
            if operation == "list_assets":
                assert elapsed < 1.0  # Should list all assets quickly
            elif operation == "individual_retrieval":
                assert elapsed < 0.5  # Should retrieve 100 assets quickly
            elif operation == "registry_stats":
                assert elapsed < 0.1  # Should compute stats quickly
    
    @pytest.mark.slow
    def test_memory_usage_under_load(self, registry_manager, large_dataset):
        """Test memory usage under heavy load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Register large dataset
        validators = large_dataset['validators']
        assets = large_dataset['assets']
        transactions = large_dataset['transactions'][:2000]  # Subset for memory test
        
        # Register validators
        for validator in validators:
            registry_manager.register_validator(validator)
        
        # Register assets
        for asset in assets:
            registry_manager.register_asset(asset)
        
        memory_after_registration = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform many state updates
        for i, tx in enumerate(transactions):
            asset_id = assets[i % len(assets)].asset_id
            registry_manager.update_asset_state(asset_id, tx)
            
            # Clean cache periodically to test memory management
            if i % 100 == 0:
                registry_manager.cleanup_cache()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        print(f"\nMemory usage analysis:")
        print(f"  Initial memory: {initial_memory:.1f} MB")
        print(f"  After registration: {memory_after_registration:.1f} MB")
        print(f"  Final memory: {final_memory:.1f} MB")
        print(f"  Memory increase: {final_memory - initial_memory:.1f} MB")
        
        # Memory usage should be reasonable
        memory_increase = final_memory - initial_memory
        assert memory_increase < 500  # Should not increase by more than 500MB
        
        # Test cache cleanup effectiveness
        cleaned_entries = registry_manager.cleanup_cache()
        memory_after_cleanup = process.memory_info().rss / 1024 / 1024  # MB
        
        print(f"  Cache entries cleaned: {cleaned_entries}")
        print(f"  Memory after cleanup: {memory_after_cleanup:.1f} MB")
    
    def test_file_system_performance(self, registry_manager, large_dataset, performance_timer):
        """Test file system operations performance."""
        assets = large_dataset['assets'][:100]
        
        # Test backup performance
        for asset in assets:
            registry_manager.register_asset(asset)
        
        with performance_timer() as timer:
            backup_success = registry_manager.backup_registry()
        
        backup_elapsed = timer.elapsed()
        assert backup_success
        
        # Test restore performance
        backups = registry_manager.list_backups()
        assert len(backups) > 0
        
        with performance_timer() as timer:
            restore_success = registry_manager.restore_backup(backups[0])
        
        restore_elapsed = timer.elapsed()
        assert restore_success
        
        # Test registry reload performance
        with performance_timer() as timer:
            registry_manager.reload_registry()
        
        reload_elapsed = timer.elapsed()
        
        print(f"\nFile system performance:")
        print(f"  Backup time: {backup_elapsed:.2f} seconds")
        print(f"  Restore time: {restore_elapsed:.2f} seconds")
        print(f"  Reload time: {reload_elapsed:.2f} seconds")
        
        # Performance assertions
        assert backup_elapsed < 5.0   # Backup should be fast
        assert restore_elapsed < 5.0  # Restore should be fast
        assert reload_elapsed < 2.0   # Reload should be very fast