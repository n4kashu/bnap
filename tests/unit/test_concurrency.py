"""
Unit tests for concurrency utilities.
"""

import pytest
import threading
import time
from unittest.mock import Mock, patch

from registry.concurrency import (
    ThreadSafeRegistry, RWLock, DeadlockDetector,
    OperationQueue, PerformanceMonitor
)
from registry.schema import Registry, FungibleAsset


class TestRWLock:
    """Test read-write lock implementation."""
    
    @pytest.fixture
    def rw_lock(self):
        """Create RWLock instance."""
        return RWLock()
    
    def test_read_lock_basic(self, rw_lock):
        """Test basic read lock functionality."""
        # Acquire read lock
        success = rw_lock.acquire_read(timeout=1.0)
        assert success
        
        # Release read lock
        rw_lock.release_read()
    
    def test_write_lock_basic(self, rw_lock):
        """Test basic write lock functionality."""
        # Acquire write lock
        success = rw_lock.acquire_write(timeout=1.0)
        assert success
        
        # Release write lock
        rw_lock.release_write()
    
    def test_multiple_readers(self, rw_lock):
        """Test multiple concurrent readers."""
        results = []
        
        def reader_thread(thread_id):
            success = rw_lock.acquire_read(timeout=1.0)
            if success:
                results.append(f"reader_{thread_id}_acquired")
                time.sleep(0.1)  # Hold lock briefly
                rw_lock.release_read()
                results.append(f"reader_{thread_id}_released")
        
        # Start multiple reader threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=reader_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # All readers should succeed
        acquired_count = len([r for r in results if 'acquired' in r])
        released_count = len([r for r in results if 'released' in r])
        assert acquired_count == 5
        assert released_count == 5
    
    def test_writer_exclusivity(self, rw_lock):
        """Test that writers are exclusive."""
        results = []
        
        def writer_thread(thread_id):
            success = rw_lock.acquire_write(timeout=1.0)
            if success:
                results.append(f"writer_{thread_id}_start")
                time.sleep(0.1)  # Hold lock briefly
                results.append(f"writer_{thread_id}_end")
                rw_lock.release_write()
        
        # Start multiple writer threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=writer_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify writers executed sequentially
        assert len(results) == 6  # 3 writers * 2 events each
        
        # Check that start/end pairs are properly nested
        for i in range(3):
            start_idx = results.index(f"writer_{i}_start")
            end_idx = results.index(f"writer_{i}_end")
            assert end_idx == start_idx + 1
    
    def test_reader_writer_interaction(self, rw_lock):
        """Test interaction between readers and writers."""
        results = []
        
        def reader_thread():
            success = rw_lock.acquire_read(timeout=2.0)
            if success:
                results.append("reader_acquired")
                time.sleep(0.2)
                results.append("reader_released")
                rw_lock.release_read()
        
        def writer_thread():
            time.sleep(0.1)  # Start slightly after reader
            success = rw_lock.acquire_write(timeout=2.0)
            if success:
                results.append("writer_acquired")
                time.sleep(0.1)
                results.append("writer_released")
                rw_lock.release_write()
        
        # Start reader first, then writer
        reader = threading.Thread(target=reader_thread)
        writer = threading.Thread(target=writer_thread)
        
        reader.start()
        writer.start()
        
        reader.join()
        writer.join()
        
        # Writer should wait for reader to finish
        assert results == [
            "reader_acquired",
            "reader_released", 
            "writer_acquired",
            "writer_released"
        ]
    
    def test_context_managers(self, rw_lock):
        """Test read/write lock context managers."""
        results = []
        
        # Test read context manager
        with rw_lock.read_lock():
            results.append("in_read_context")
        
        # Test write context manager
        with rw_lock.write_lock():
            results.append("in_write_context")
        
        assert results == ["in_read_context", "in_write_context"]


class TestDeadlockDetector:
    """Test deadlock detection functionality."""
    
    @pytest.fixture
    def detector(self):
        """Create deadlock detector."""
        return DeadlockDetector(check_interval=0.1)
    
    def test_detector_initialization(self, detector):
        """Test deadlock detector initialization."""
        assert detector.check_interval == 0.1
        assert len(detector.dependency_graph) == 0
        assert not detector.is_monitoring
    
    def test_dependency_tracking(self, detector):
        """Test dependency graph tracking."""
        # Add dependencies
        detector.add_dependency("thread_1", "resource_A")
        detector.add_dependency("thread_2", "resource_B")
        detector.add_dependency("thread_1", "resource_B")  # Potential deadlock setup
        
        # Check graph state
        assert "thread_1" in detector.dependency_graph
        assert "thread_2" in detector.dependency_graph
        assert "resource_A" in detector.dependency_graph["thread_1"]
        assert "resource_B" in detector.dependency_graph["thread_1"]
    
    def test_deadlock_detection(self, detector):
        """Test actual deadlock detection."""
        # Create deadlock scenario:
        # Thread 1 holds A, wants B
        # Thread 2 holds B, wants A
        detector.add_dependency("thread_1", "resource_A")
        detector.add_dependency("thread_1", "resource_B")  # wants B
        detector.add_dependency("thread_2", "resource_B")
        detector.add_dependency("thread_2", "resource_A")  # wants A
        
        # Detect deadlock
        deadlock_detected = detector.detect_deadlock()
        assert deadlock_detected
        
        # Get deadlock info
        cycles = detector.get_dependency_cycles()
        assert len(cycles) > 0
    
    def test_dependency_removal(self, detector):
        """Test dependency removal."""
        # Add dependencies
        detector.add_dependency("thread_1", "resource_A")
        detector.add_dependency("thread_1", "resource_B")
        
        # Remove dependency
        detector.remove_dependency("thread_1", "resource_A")
        
        # Verify removal
        assert "resource_A" not in detector.dependency_graph.get("thread_1", set())
        assert "resource_B" in detector.dependency_graph.get("thread_1", set())


class TestOperationQueue:
    """Test operation queue functionality."""
    
    @pytest.fixture
    def operation_queue(self):
        """Create operation queue."""
        return OperationQueue(max_size=10)
    
    def test_queue_initialization(self, operation_queue):
        """Test operation queue initialization."""
        assert operation_queue.max_size == 10
        assert operation_queue.queue.qsize() == 0
        assert not operation_queue.is_processing
    
    def test_enqueue_operation(self, operation_queue):
        """Test enqueueing operations."""
        def test_operation():
            return "test_result"
        
        # Enqueue operation
        operation_id = operation_queue.enqueue(test_operation, priority=1)
        assert operation_id is not None
        assert operation_queue.queue.qsize() == 1
    
    def test_operation_processing(self, operation_queue):
        """Test operation processing."""
        results = []
        
        def test_operation(value):
            results.append(value)
            return f"processed_{value}"
        
        # Enqueue operations
        op_id_1 = operation_queue.enqueue(lambda: test_operation("op1"), priority=1)
        op_id_2 = operation_queue.enqueue(lambda: test_operation("op2"), priority=2)
        
        # Start processing
        operation_queue.start_processing()
        
        # Wait for processing
        time.sleep(0.2)
        
        # Stop processing
        operation_queue.stop_processing()
        
        # Verify operations were processed
        assert len(results) == 2
        assert "op1" in results
        assert "op2" in results
    
    def test_priority_ordering(self, operation_queue):
        """Test priority-based operation ordering."""
        results = []
        
        def test_operation(value):
            results.append(value)
            time.sleep(0.05)  # Small delay to ensure ordering
        
        # Enqueue operations with different priorities
        operation_queue.enqueue(lambda: test_operation("low"), priority=1)
        operation_queue.enqueue(lambda: test_operation("high"), priority=3)
        operation_queue.enqueue(lambda: test_operation("medium"), priority=2)
        
        # Process operations
        operation_queue.start_processing()
        time.sleep(0.3)
        operation_queue.stop_processing()
        
        # Higher priority should be processed first
        assert results[0] == "high"
        assert results[1] == "medium"
        assert results[2] == "low"
    
    def test_queue_size_limit(self, operation_queue):
        """Test queue size limitations."""
        def dummy_operation():
            pass
        
        # Fill queue to capacity
        for i in range(operation_queue.max_size):
            op_id = operation_queue.enqueue(dummy_operation, priority=1)
            assert op_id is not None
        
        # Next operation should fail (queue full)
        overflow_id = operation_queue.enqueue(dummy_operation, priority=1)
        assert overflow_id is None


class TestPerformanceMonitor:
    """Test performance monitoring functionality."""
    
    @pytest.fixture
    def monitor(self):
        """Create performance monitor."""
        return PerformanceMonitor()
    
    def test_monitor_initialization(self, monitor):
        """Test performance monitor initialization."""
        assert monitor.monitoring_enabled
        assert len(monitor.operation_times) == 0
        assert len(monitor.error_counts) == 0
    
    def test_operation_timing(self, monitor):
        """Test operation timing measurement."""
        @monitor.time_operation
        def test_operation():
            time.sleep(0.1)
            return "result"
        
        # Execute operation
        result = test_operation()
        
        assert result == "result"
        assert "test_operation" in monitor.operation_times
        assert len(monitor.operation_times["test_operation"]) == 1
        assert monitor.operation_times["test_operation"][0] >= 0.1
    
    def test_error_tracking(self, monitor):
        """Test error count tracking."""
        @monitor.track_errors
        def failing_operation():
            raise ValueError("Test error")
        
        # Execute failing operation
        with pytest.raises(ValueError):
            failing_operation()
        
        assert "failing_operation" in monitor.error_counts
        assert monitor.error_counts["failing_operation"] == 1
        
        # Execute again
        with pytest.raises(ValueError):
            failing_operation()
        
        assert monitor.error_counts["failing_operation"] == 2
    
    def test_performance_statistics(self, monitor):
        """Test performance statistics calculation."""
        @monitor.time_operation
        def variable_operation(duration):
            time.sleep(duration)
        
        # Execute operations with different durations
        durations = [0.05, 0.1, 0.15, 0.2]
        for duration in durations:
            variable_operation(duration)
        
        # Get statistics
        stats = monitor.get_statistics()
        
        assert "variable_operation" in stats
        op_stats = stats["variable_operation"]
        
        assert op_stats["call_count"] == 4
        assert op_stats["min_time"] >= 0.05
        assert op_stats["max_time"] >= 0.2
        assert 0.1 <= op_stats["avg_time"] <= 0.15
    
    def test_monitoring_toggle(self, monitor):
        """Test monitoring enable/disable."""
        @monitor.time_operation
        def test_operation():
            time.sleep(0.05)
        
        # Execute with monitoring enabled
        test_operation()
        assert len(monitor.operation_times["test_operation"]) == 1
        
        # Disable monitoring
        monitor.disable_monitoring()
        test_operation()
        
        # Should not have recorded new timing
        assert len(monitor.operation_times["test_operation"]) == 1
        
        # Re-enable monitoring
        monitor.enable_monitoring()
        test_operation()
        
        # Should record new timing
        assert len(monitor.operation_times["test_operation"]) == 2


class TestThreadSafeRegistry:
    """Test thread-safe registry wrapper."""
    
    @pytest.fixture
    def thread_safe_registry(self):
        """Create thread-safe registry."""
        base_registry = Registry()
        return ThreadSafeRegistry(base_registry)
    
    def test_thread_safe_initialization(self, thread_safe_registry):
        """Test thread-safe registry initialization."""
        assert thread_safe_registry.registry is not None
        assert thread_safe_registry.rw_lock is not None
        assert thread_safe_registry.deadlock_detector is not None
        assert thread_safe_registry.performance_monitor is not None
    
    def test_concurrent_read_operations(self, thread_safe_registry):
        """Test concurrent read operations."""
        # Add test asset
        test_asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test Asset",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        thread_safe_registry.add_asset(test_asset)
        
        results = []
        
        def reader_thread(thread_id):
            for _ in range(10):
                asset = thread_safe_registry.get_asset(test_asset.asset_id)
                if asset:
                    results.append(f"thread_{thread_id}_read_success")
                time.sleep(0.01)
        
        # Start multiple reader threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=reader_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # All reads should succeed
        assert len(results) == 50  # 5 threads * 10 reads each
    
    def test_concurrent_write_operations(self, thread_safe_registry):
        """Test concurrent write operations."""
        results = []
        errors = []
        
        def writer_thread(thread_id):
            try:
                for i in range(5):
                    asset = FungibleAsset(
                        asset_id=f"thread_{thread_id}_{i:060d}",
                        name=f"Thread {thread_id} Asset {i}",
                        symbol=f"T{thread_id}A{i}",
                        issuer_pubkey=f"issuer_{thread_id:060d}",
                        maximum_supply=1000,
                        per_mint_limit=100
                    )
                    thread_safe_registry.add_asset(asset)
                    results.append(f"thread_{thread_id}_asset_{i}")
            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")
        
        # Start multiple writer threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=writer_thread, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(errors) == 0
        assert len(results) == 15  # 3 threads * 5 assets each
        
        # Verify all assets exist
        all_assets = thread_safe_registry.list_assets()
        assert len(all_assets) == 15
    
    def test_mixed_read_write_operations(self, thread_safe_registry):
        """Test mixed concurrent read/write operations."""
        # Add initial asset
        initial_asset = FungibleAsset(
            asset_id="initial" + "0" * 57,
            name="Initial Asset",
            symbol="INIT",
            issuer_pubkey="c" * 64,
            maximum_supply=5000,
            per_mint_limit=500
        )
        thread_safe_registry.add_asset(initial_asset)
        
        results = {'reads': 0, 'writes': 0, 'errors': 0}
        lock = threading.Lock()
        
        def reader_worker():
            try:
                for _ in range(20):
                    assets = thread_safe_registry.list_assets()
                    if assets:
                        with lock:
                            results['reads'] += 1
                    time.sleep(0.01)
            except Exception:
                with lock:
                    results['errors'] += 1
        
        def writer_worker(worker_id):
            try:
                for i in range(10):
                    asset = FungibleAsset(
                        asset_id=f"worker_{worker_id}_{i:060d}",
                        name=f"Worker {worker_id} Asset {i}",
                        symbol=f"W{worker_id}A{i}",
                        issuer_pubkey=f"worker_{worker_id:060d}",
                        maximum_supply=2000,
                        per_mint_limit=200
                    )
                    thread_safe_registry.add_asset(asset)
                    with lock:
                        results['writes'] += 1
                    time.sleep(0.02)
            except Exception:
                with lock:
                    results['errors'] += 1
        
        # Start mixed threads
        threads = []
        
        # 3 reader threads
        for _ in range(3):
            thread = threading.Thread(target=reader_worker)
            threads.append(thread)
        
        # 2 writer threads
        for i in range(2):
            thread = threading.Thread(target=writer_worker, args=(i,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        assert results['errors'] == 0
        assert results['reads'] == 60   # 3 readers * 20 reads
        assert results['writes'] == 20  # 2 writers * 10 writes
        
        # Verify final state
        final_assets = thread_safe_registry.list_assets()
        assert len(final_assets) == 21  # 1 initial + 20 written
    
    def test_performance_monitoring_integration(self, thread_safe_registry):
        """Test performance monitoring integration."""
        # Perform some operations
        test_asset = FungibleAsset(
            asset_id="d" * 64,
            name="Performance Test Asset",
            symbol="PTA",
            issuer_pubkey="e" * 64,
            maximum_supply=10000,
            per_mint_limit=1000
        )
        
        thread_safe_registry.add_asset(test_asset)
        thread_safe_registry.get_asset(test_asset.asset_id)
        thread_safe_registry.list_assets()
        
        # Get performance statistics
        stats = thread_safe_registry.get_performance_stats()
        
        assert isinstance(stats, dict)
        # Should have timing information for operations
        operation_names = list(stats.keys())
        assert len(operation_names) > 0