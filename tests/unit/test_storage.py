"""
Unit tests for storage layer.
"""

import pytest
import tempfile
import threading
import time
import json
from pathlib import Path
from datetime import datetime

from registry.storage import (
    RegistryStorage, JSONStorage, FileLock, StorageError,
    CompressionType
)
from registry.schema import Registry, FungibleAsset


class TestFileLock:
    """Test file locking mechanism."""
    
    @pytest.fixture
    def temp_file(self):
        """Create temporary file for locking tests."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)
        
        yield temp_path
        
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()
    
    def test_file_lock_creation(self, temp_file):
        """Test file lock creation and basic usage."""
        lock = FileLock(temp_file)
        
        assert lock.lock_file == temp_file.with_suffix(temp_file.suffix + '.lock')
        assert not lock.is_locked()
    
    def test_file_lock_acquire_release(self, temp_file):
        """Test lock acquisition and release."""
        lock = FileLock(temp_file)
        
        # Acquire lock
        success = lock.acquire(timeout=1.0)
        assert success
        assert lock.is_locked()
        
        # Release lock
        lock.release()
        assert not lock.is_locked()
    
    def test_file_lock_context_manager(self, temp_file):
        """Test file lock as context manager."""
        lock = FileLock(temp_file)
        
        with lock:
            assert lock.is_locked()
        
        assert not lock.is_locked()
    
    def test_concurrent_file_locking(self, temp_file):
        """Test concurrent access with file locking."""
        results = []
        errors = []
        
        def worker_thread(thread_id):
            """Worker thread that tries to acquire lock."""
            try:
                lock = FileLock(temp_file)
                with lock:
                    # Simulate work while holding lock
                    results.append(f"thread_{thread_id}_start")
                    time.sleep(0.1)
                    results.append(f"thread_{thread_id}_end")
            except Exception as e:
                errors.append(f"thread_{thread_id}: {str(e)}")
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify no errors and proper serialization
        assert len(errors) == 0
        assert len(results) == 10  # 5 threads * 2 results each
        
        # Verify proper ordering (start/end pairs should be together)
        for i in range(5):
            start_idx = results.index(f"thread_{i}_start")
            end_idx = results.index(f"thread_{i}_end")
            assert end_idx == start_idx + 1  # End should immediately follow start


class TestJSONStorage:
    """Test JSON storage functionality."""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def json_storage(self, temp_storage_dir):
        """Create JSON storage instance."""
        return JSONStorage(
            file_path=Path(temp_storage_dir) / "test.json",
            enable_compression=False,
            backup_count=3
        )
    
    def test_json_storage_initialization(self, json_storage):
        """Test JSON storage initialization."""
        assert json_storage.file_path.name == "test.json"
        assert json_storage.enable_compression is False
        assert json_storage.backup_count == 3
        assert json_storage.compression_type == CompressionType.NONE
    
    def test_read_write_data(self, json_storage):
        """Test basic read/write operations."""
        test_data = {
            'test_key': 'test_value',
            'nested': {
                'number': 42,
                'list': [1, 2, 3]
            }
        }
        
        # Write data
        json_storage.write(test_data)
        assert json_storage.file_path.exists()
        
        # Read data
        read_data = json_storage.read()
        assert read_data == test_data
    
    def test_read_nonexistent_file(self, json_storage):
        """Test reading from non-existent file."""
        # Should return empty dict for non-existent file
        data = json_storage.read()
        assert data == {}
    
    def test_write_with_backup(self, json_storage):
        """Test writing with backup creation."""
        # Write initial data
        initial_data = {'version': 1, 'data': 'initial'}
        json_storage.write(initial_data)
        
        # Write updated data (should create backup)
        updated_data = {'version': 2, 'data': 'updated'}
        json_storage.write(updated_data)
        
        # Verify updated data
        current_data = json_storage.read()
        assert current_data == updated_data
        
        # Verify backup exists
        backups = json_storage.list_backups()
        assert len(backups) >= 1
        
        # Verify backup content
        latest_backup = backups[0]
        backup_data = json_storage.read_backup(latest_backup)
        assert backup_data == initial_data
    
    def test_backup_rotation(self, json_storage):
        """Test backup rotation when exceeding backup_count."""
        # Write multiple versions to trigger rotation
        for i in range(6):  # More than backup_count (3)
            data = {'version': i, 'data': f'version_{i}'}
            json_storage.write(data)
            time.sleep(0.01)  # Ensure different timestamps
        
        # Should only keep backup_count backups
        backups = json_storage.list_backups()
        assert len(backups) <= json_storage.backup_count
    
    def test_restore_from_backup(self, json_storage):
        """Test restoring from backup."""
        # Write initial data
        initial_data = {'important': 'data'}
        json_storage.write(initial_data)
        
        # Write corrupted data
        corrupted_data = {'corrupted': 'data'}
        json_storage.write(corrupted_data)
        
        # Restore from backup
        backups = json_storage.list_backups()
        assert len(backups) > 0
        
        success = json_storage.restore_from_backup(backups[0])
        assert success
        
        # Verify restoration
        restored_data = json_storage.read()
        assert restored_data == initial_data
    
    def test_compression_functionality(self, temp_storage_dir):
        """Test data compression."""
        # Create storage with compression enabled
        compressed_storage = JSONStorage(
            file_path=Path(temp_storage_dir) / "compressed.json",
            enable_compression=True,
            compression_type=CompressionType.GZIP
        )
        
        # Create large test data
        large_data = {
            'repeated_data': ['test_string' * 100] * 100,
            'metadata': {'compression': True}
        }
        
        # Write compressed data
        compressed_storage.write(large_data)
        
        # Read compressed data
        read_data = compressed_storage.read()
        assert read_data == large_data
        
        # Verify file is actually compressed (smaller than uncompressed)
        compressed_size = compressed_storage.file_path.stat().st_size
        
        # Write same data uncompressed for comparison
        uncompressed_storage = JSONStorage(
            file_path=Path(temp_storage_dir) / "uncompressed.json",
            enable_compression=False
        )
        uncompressed_storage.write(large_data)
        uncompressed_size = uncompressed_storage.file_path.stat().st_size
        
        # Compressed should be significantly smaller
        assert compressed_size < uncompressed_size * 0.5
    
    def test_atomic_operations(self, json_storage):
        """Test atomic write operations."""
        initial_data = {'atomic': 'test'}
        json_storage.write(initial_data)
        
        # Simulate interrupted write by checking temp file handling
        test_data = {'large': 'data' * 1000}
        
        # Write should complete atomically
        json_storage.write(test_data)
        
        # Verify no temp files left behind
        temp_files = list(json_storage.file_path.parent.glob("*.tmp"))
        assert len(temp_files) == 0
        
        # Verify data integrity
        read_data = json_storage.read()
        assert read_data == test_data
    
    def test_concurrent_read_write(self, json_storage):
        """Test concurrent read/write operations."""
        results = []
        errors = []
        
        def writer_thread(thread_id, iterations):
            """Writer thread function."""
            try:
                for i in range(iterations):
                    data = {
                        'thread_id': thread_id,
                        'iteration': i,
                        'timestamp': time.time()
                    }
                    json_storage.write(data)
                    results.append(f"write_{thread_id}_{i}")
                    time.sleep(0.01)
            except Exception as e:
                errors.append(f"Writer {thread_id}: {str(e)}")
        
        def reader_thread(thread_id, iterations):
            """Reader thread function."""
            try:
                for i in range(iterations):
                    data = json_storage.read()
                    if data:  # Only count successful reads of non-empty data
                        results.append(f"read_{thread_id}_{i}")
                    time.sleep(0.01)
            except Exception as e:
                errors.append(f"Reader {thread_id}: {str(e)}")
        
        # Create writer and reader threads
        threads = []
        
        # 2 writer threads
        for i in range(2):
            thread = threading.Thread(target=writer_thread, args=(i, 5))
            threads.append(thread)
        
        # 3 reader threads
        for i in range(3):
            thread = threading.Thread(target=reader_thread, args=(i, 5))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify no errors occurred
        assert len(errors) == 0
        
        # Verify operations completed
        write_results = [r for r in results if r.startswith('write_')]
        read_results = [r for r in results if r.startswith('read_')]
        
        assert len(write_results) == 10  # 2 writers * 5 iterations
        assert len(read_results) > 0    # At least some reads succeeded


class TestRegistryStorage:
    """Test registry-specific storage functionality."""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def registry_storage(self, temp_storage_dir):
        """Create registry storage instance."""
        return RegistryStorage(storage_dir=temp_storage_dir)
    
    def test_registry_storage_initialization(self, registry_storage):
        """Test registry storage initialization."""
        assert registry_storage.storage_dir.exists()
        assert registry_storage.registry_file.name == "registry.json"
        assert registry_storage.cache_ttl == 300  # 5 minutes default
    
    def test_save_load_registry(self, registry_storage):
        """Test saving and loading registry."""
        # Create test registry
        registry = Registry()
        
        # Add test asset
        test_asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test Asset",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        registry.add_asset(test_asset)
        
        # Save registry
        checksum = registry_storage.save_registry(registry)
        assert isinstance(checksum, str)
        assert len(checksum) == 64  # SHA-256 hex
        
        # Load registry
        loaded_registry = registry_storage.load_registry()
        assert loaded_registry is not None
        assert test_asset.asset_id in loaded_registry.assets
        assert loaded_registry.assets[test_asset.asset_id].name == test_asset.name
    
    def test_registry_checksum_verification(self, registry_storage):
        """Test registry checksum generation and verification."""
        registry = Registry()
        
        # Save registry and get checksum
        checksum1 = registry_storage.save_registry(registry)
        
        # Save same registry again - should get same checksum
        checksum2 = registry_storage.save_registry(registry)
        assert checksum1 == checksum2
        
        # Modify registry
        test_asset = FungibleAsset(
            asset_id="c" * 64,
            name="Modified Asset",
            symbol="MOD",
            issuer_pubkey="d" * 64,
            maximum_supply=2000,
            per_mint_limit=200
        )
        registry.add_asset(test_asset)
        
        # Save modified registry - should get different checksum
        checksum3 = registry_storage.save_registry(registry)
        assert checksum3 != checksum1
    
    def test_backup_restore_operations(self, registry_storage):
        """Test backup and restore operations."""
        # Create and save registry
        registry = Registry()
        test_asset = FungibleAsset(
            asset_id="e" * 64,
            name="Backup Test Asset",
            symbol="BTA",
            issuer_pubkey="f" * 64,
            maximum_supply=3000,
            per_mint_limit=300
        )
        registry.add_asset(test_asset)
        
        registry_storage.save_registry(registry)
        
        # Create backup
        backup_success = registry_storage.backup_registry()
        assert backup_success
        
        # List backups
        backups = registry_storage.list_backups()
        assert len(backups) > 0
        
        # Modify registry
        modified_asset = FungibleAsset(
            asset_id="g" * 64,
            name="Modified Asset",
            symbol="MOD",
            issuer_pubkey="h" * 64,
            maximum_supply=4000,
            per_mint_limit=400
        )
        registry.add_asset(modified_asset)
        registry_storage.save_registry(registry)
        
        # Verify modification
        loaded_registry = registry_storage.load_registry()
        assert modified_asset.asset_id in loaded_registry.assets
        
        # Restore from backup
        latest_backup = backups[0]
        restore_success = registry_storage.restore_backup(latest_backup)
        assert restore_success
        
        # Verify restoration
        restored_registry = registry_storage.load_registry()
        assert test_asset.asset_id in restored_registry.assets
        assert modified_asset.asset_id not in restored_registry.assets
    
    def test_storage_statistics(self, registry_storage):
        """Test storage statistics."""
        # Create registry with data
        registry = Registry()
        
        # Add multiple assets
        for i in range(10):
            asset = FungibleAsset(
                asset_id=f"{i:064d}",
                name=f"Asset {i}",
                symbol=f"A{i}",
                issuer_pubkey=f"issuer_{i:060d}",
                maximum_supply=1000 * (i + 1),
                per_mint_limit=100 * (i + 1)
            )
            registry.add_asset(asset)
        
        registry_storage.save_registry(registry)
        
        # Get storage statistics
        stats = registry_storage.get_storage_info()
        
        assert 'file_size' in stats
        assert 'backup_count' in stats
        assert 'last_modified' in stats
        assert 'checksum' in stats
        
        assert stats['file_size'] > 0
        assert isinstance(stats['last_modified'], str)
        assert len(stats['checksum']) == 64
    
    def test_error_handling(self, registry_storage):
        """Test error handling in storage operations."""
        # Test loading non-existent registry
        # Should create new empty registry, not raise error
        registry = registry_storage.load_registry()
        assert registry is not None
        assert len(registry.assets) == 0
        
        # Test restoring from non-existent backup
        success = registry_storage.restore_backup("nonexistent_backup.json.gz")
        assert not success
        
        # Test with invalid registry data
        invalid_json = '{"invalid": "json", "missing": "required_fields"}'
        registry_storage.registry_file.write_text(invalid_json)
        
        # Should handle gracefully and return empty registry
        registry = registry_storage.load_registry()
        assert registry is not None