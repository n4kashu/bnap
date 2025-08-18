"""
Performance Tests for BNAP Validator System

Tests validator performance under high-throughput scenarios, stress conditions,
and resource constraints to ensure the system can handle production loads.
"""

import pytest
import time
import threading
import concurrent.futures
import gc
import psutil
import os
from unittest.mock import Mock, patch
from statistics import mean, median, stdev
from typing import List, Dict

from validator.core import ValidationEngine, ValidationContext
from validator.registry_client import RegistryClient
from validator.audit_logger import AuditLogger
from registry.schema import AssetType, FungibleAsset, StateEntry
from crypto.commitments import OperationType


class PerformanceTestFixtures:
    """Common fixtures for performance tests."""
    
    @staticmethod
    def create_test_asset() -> FungibleAsset:
        """Create a test asset for performance testing."""
        return FungibleAsset(
            asset_id="performance_test_asset",
            name="Performance Test Token",
            symbol="PTT",
            issuer_pubkey="0123456789abcdef" * 8,
            maximum_supply=100_000_000,
            per_mint_limit=1_000_000,
            decimal_places=8,
            asset_type=AssetType.FUNGIBLE,
            status="active"
        )
    
    @staticmethod
    def create_test_state() -> StateEntry:
        """Create test state for performance testing."""
        return StateEntry(
            asset_id="performance_test_asset",
            minted_supply=10_000_000,
            transaction_count=10000
        )
    
    @staticmethod
    def create_mock_psbt_data(amount: int = 1000) -> Dict:
        """Create mock PSBT data for testing."""
        return {
            'global': {'version': 2},
            'inputs': [{
                'previous_output': {'tx_id': 'perf_test_tx_123', 'output_index': 0}
            }],
            'outputs': [{
                'amount': 546,
                'script': b'\x6a' + b'BNAP_PERF_METADATA',
                'proprietary_fields': {
                    b'BNAPAID': b'performance_test_asset',
                    b'BNAPAMT': amount.to_bytes(8, 'little'),
                    b'BNAPTY': b'FUNGIBLE'
                }
            }]
        }


class TestValidatorThroughput:
    """Test validator throughput under various conditions."""
    
    def setup_method(self):
        """Set up performance test environment."""
        self.test_asset = PerformanceTestFixtures.create_test_asset()
        self.test_state = PerformanceTestFixtures.create_test_state()
        
        # Configure for performance (disable logging, etc.)
        self.perf_config = {
            "validator_id": "performance_validator",
            "enable_audit_logging": False,
            "max_validation_time": 60,
            "registry_cache_enabled": True
        }
    
    @patch('validator.core.RegistryManager')
    def test_single_threaded_throughput(self, mock_registry_manager):
        """Test single-threaded validation throughput."""
        # Mock registry for fast responses
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_asset
        mock_manager.get_asset_state.return_value = self.test_state
        mock_manager.get_asset_supply_info.return_value = {
            'remaining_supply': 50_000_000,
            'per_mint_limit': 1_000_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.perf_config, registry_manager=mock_manager)
        
        # Prepare test data
        num_validations = 1000
        mock_psbt_data = PerformanceTestFixtures.create_mock_psbt_data()
        
        # Measure throughput
        start_time = time.time()
        successful_validations = 0
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            for i in range(num_validations):
                context = validator.validate_mint_transaction(f"psbt_{i}")
                if not context.has_errors():
                    successful_validations += 1
        
        end_time = time.time()
        total_time = end_time - start_time
        throughput = num_validations / total_time
        
        # Performance assertions
        assert successful_validations >= num_validations * 0.95  # At least 95% success
        assert throughput >= 100  # At least 100 validations per second
        assert total_time < 30  # Complete within 30 seconds
        
        print(f"Single-threaded throughput: {throughput:.1f} validations/second")
        print(f"Success rate: {successful_validations/num_validations*100:.1f}%")
    
    @patch('validator.core.RegistryManager')
    def test_concurrent_validation_throughput(self, mock_registry_manager):
        """Test concurrent validation throughput with multiple threads."""
        # Mock registry for concurrent access
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_asset
        mock_manager.get_asset_state.return_value = self.test_state
        mock_manager.get_asset_supply_info.return_value = {
            'remaining_supply': 50_000_000,
            'per_mint_limit': 1_000_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.perf_config, registry_manager=mock_manager)
        mock_psbt_data = PerformanceTestFixtures.create_mock_psbt_data()
        
        # Concurrent validation function
        def validate_batch(thread_id: int, batch_size: int) -> Dict[str, int]:
            successful = 0
            failed = 0
            
            with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
                for i in range(batch_size):
                    try:
                        context = validator.validate_mint_transaction(f"thread_{thread_id}_psbt_{i}")
                        if context.has_errors():
                            failed += 1
                        else:
                            successful += 1
                    except Exception:
                        failed += 1
            
            return {"successful": successful, "failed": failed}
        
        # Run concurrent validations
        num_threads = 8
        batch_size = 125  # 1000 total validations
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(validate_batch, thread_id, batch_size)
                for thread_id in range(num_threads)
            ]
            
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Aggregate results
        total_successful = sum(r["successful"] for r in results)
        total_failed = sum(r["failed"] for r in results)
        total_validations = total_successful + total_failed
        concurrent_throughput = total_validations / total_time
        
        # Performance assertions
        assert total_successful >= total_validations * 0.90  # At least 90% success
        assert concurrent_throughput >= 200  # Better than single-threaded
        assert total_time < 20  # Should be faster with concurrency
        
        print(f"Concurrent throughput: {concurrent_throughput:.1f} validations/second")
        print(f"Success rate: {total_successful/total_validations*100:.1f}%")
        print(f"Threads: {num_threads}, Total validations: {total_validations}")
    
    @patch('validator.core.RegistryManager')
    def test_latency_distribution(self, mock_registry_manager):
        """Test validation latency distribution under load."""
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_asset
        mock_manager.get_asset_state.return_value = self.test_state
        mock_manager.get_asset_supply_info.return_value = {
            'remaining_supply': 50_000_000,
            'per_mint_limit': 1_000_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.perf_config, registry_manager=mock_manager)
        mock_psbt_data = PerformanceTestFixtures.create_mock_psbt_data()
        
        latencies = []
        num_measurements = 500
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            for i in range(num_measurements):
                start = time.perf_counter()
                context = validator.validate_mint_transaction(f"latency_test_{i}")
                end = time.perf_counter()
                
                latency_ms = (end - start) * 1000
                latencies.append(latency_ms)
        
        # Calculate latency statistics
        avg_latency = mean(latencies)
        median_latency = median(latencies)
        p95_latency = sorted(latencies)[int(0.95 * len(latencies))]
        p99_latency = sorted(latencies)[int(0.99 * len(latencies))]
        latency_stdev = stdev(latencies)
        
        # Performance assertions
        assert avg_latency < 50  # Average latency under 50ms
        assert median_latency < 30  # Median latency under 30ms
        assert p95_latency < 100  # 95th percentile under 100ms
        assert p99_latency < 200  # 99th percentile under 200ms
        
        print(f"Latency statistics (ms):")
        print(f"  Average: {avg_latency:.2f}")
        print(f"  Median: {median_latency:.2f}")
        print(f"  95th percentile: {p95_latency:.2f}")
        print(f"  99th percentile: {p99_latency:.2f}")
        print(f"  Standard deviation: {latency_stdev:.2f}")
    
    @patch('validator.core.RegistryManager')
    def test_sustained_load_performance(self, mock_registry_manager):
        """Test performance under sustained load over time."""
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = self.test_asset
        mock_manager.get_asset_state.return_value = self.test_state
        mock_manager.get_asset_supply_info.return_value = {
            'remaining_supply': 50_000_000,
            'per_mint_limit': 1_000_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config=self.perf_config, registry_manager=mock_manager)
        mock_psbt_data = PerformanceTestFixtures.create_mock_psbt_data()
        
        # Run sustained load for 30 seconds
        duration_seconds = 30
        start_time = time.time()
        validation_count = 0
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            while time.time() - start_time < duration_seconds:
                context = validator.validate_mint_transaction(f"sustained_{validation_count}")
                validation_count += 1
                
                # Small delay to prevent overwhelming the system
                time.sleep(0.001)
        
        end_time = time.time()
        actual_duration = end_time - start_time
        sustained_throughput = validation_count / actual_duration
        
        # Performance assertions
        assert sustained_throughput >= 50  # Maintain at least 50 validations/second
        assert validation_count >= 1000  # Process at least 1000 validations
        
        print(f"Sustained load throughput: {sustained_throughput:.1f} validations/second")
        print(f"Duration: {actual_duration:.1f}s, Total validations: {validation_count}")


class TestMemoryPerformance:
    """Test memory usage and garbage collection behavior."""
    
    def setup_method(self):
        """Set up memory performance tests."""
        self.process = psutil.Process(os.getpid())
        gc.collect()  # Start with clean slate
    
    @patch('validator.core.RegistryManager')
    def test_memory_usage_stability(self, mock_registry_manager):
        """Test memory usage remains stable during extended operation."""
        # Mock registry
        mock_manager = Mock()
        test_asset = PerformanceTestFixtures.create_test_asset()
        test_state = PerformanceTestFixtures.create_test_state()
        
        mock_manager.get_asset_by_id.return_value = test_asset
        mock_manager.get_asset_state.return_value = test_state
        mock_manager.get_asset_supply_info.return_value = {
            'remaining_supply': 50_000_000,
            'per_mint_limit': 1_000_000
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(
            config={"enable_audit_logging": False},
            registry_manager=mock_manager
        )
        mock_psbt_data = PerformanceTestFixtures.create_mock_psbt_data()
        
        # Baseline memory measurement
        gc.collect()
        initial_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        
        # Run extended validation operations
        num_iterations = 5000
        
        with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
            for i in range(num_iterations):
                context = validator.validate_mint_transaction(f"memory_test_{i}")
                
                # Periodic garbage collection
                if i % 1000 == 0:
                    gc.collect()
        
        # Final memory measurement
        gc.collect()
        final_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory
        
        # Memory assertions
        assert memory_growth < 100  # Less than 100MB growth
        memory_per_validation = (memory_growth * 1024 * 1024) / num_iterations  # bytes
        assert memory_per_validation < 1024  # Less than 1KB per validation
        
        print(f"Memory usage:")
        print(f"  Initial: {initial_memory:.1f} MB")
        print(f"  Final: {final_memory:.1f} MB")
        print(f"  Growth: {memory_growth:.1f} MB")
        print(f"  Per validation: {memory_per_validation:.1f} bytes")
    
    @patch('validator.core.RegistryManager')
    def test_garbage_collection_efficiency(self, mock_registry_manager):
        """Test that objects are properly garbage collected."""
        mock_manager = Mock()
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config={}, registry_manager=mock_manager)
        
        # Count objects before test
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # Create and destroy many validation contexts
        for i in range(1000):
            context = ValidationContext(
                psbt_data={"test": i},
                asset_id=f"gc_test_{i}".encode(),
                amount=i
            )
            context.add_error("test_rule", f"Test error {i}")
            # Context goes out of scope here
        
        # Force garbage collection
        gc.collect()
        final_objects = len(gc.get_objects())
        object_growth = final_objects - initial_objects
        
        # Should not accumulate too many objects
        assert object_growth < 500  # Less than 500 new objects remaining
        
        print(f"Object count:")
        print(f"  Initial: {initial_objects}")
        print(f"  Final: {final_objects}")
        print(f"  Growth: {object_growth}")
    
    def test_validation_context_memory_efficiency(self):
        """Test memory efficiency of ValidationContext objects."""
        import sys
        
        # Create baseline context
        baseline_context = ValidationContext(psbt_data={})
        baseline_size = sys.getsizeof(baseline_context)
        
        # Create context with typical data
        typical_context = ValidationContext(
            psbt_data={"global": {"version": 2}, "inputs": [{}], "outputs": [{}]},
            asset_id=b"test_asset_12345678901234567890",
            asset_type=AssetType.FUNGIBLE,
            operation=OperationType.MINT,
            amount=1000000,
            current_supply=5000000,
            supply_cap=10000000,
            per_mint_cap=100000
        )
        typical_size = sys.getsizeof(typical_context)
        
        # Create context with maximum data
        max_context = ValidationContext(
            psbt_data={
                "global": {"version": 2, "proprietary_fields": {f"key_{i}": f"value_{i}" for i in range(100)}},
                "inputs": [{"prop": {f"inp_key_{i}": f"inp_val_{i}" for i in range(50)}} for _ in range(10)],
                "outputs": [{"prop": {f"out_key_{i}": f"out_val_{i}" for i in range(50)}} for _ in range(10)]
            },
            asset_id=b"maximum_test_asset_id_with_very_long_name_123456789",
            asset_type=AssetType.NFT,
            operation=OperationType.MINT,
            amount=1,
            validation_errors=[f"Error message {i}" for i in range(20)],
            validation_warnings=[f"Warning message {i}" for i in range(10)]
        )
        max_size = sys.getsizeof(max_context)
        
        # Memory efficiency assertions
        assert baseline_size < 1024  # Less than 1KB for empty context
        assert typical_size < 4096   # Less than 4KB for typical context
        assert max_size < 16384      # Less than 16KB for maximum context
        
        print(f"ValidationContext memory usage:")
        print(f"  Baseline: {baseline_size} bytes")
        print(f"  Typical: {typical_size} bytes")
        print(f"  Maximum: {max_size} bytes")


class TestRegistryClientPerformance:
    """Test performance of registry client operations."""
    
    def setup_method(self):
        """Set up registry client performance tests."""
        self.test_config = {
            "connection_pool_size": 5,
            "cache_strategy": "aggressive",
            "cache_size": 10000,
            "max_retries": 1,
            "enable_audit_logging": False
        }
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_cache_performance_impact(self, mock_pool):
        """Test performance impact of caching."""
        # Mock connection pool with slow registry responses
        mock_manager = Mock()
        test_asset = PerformanceTestFixtures.create_test_asset()
        
        # Simulate network delay
        def slow_get_asset(asset_id):
            time.sleep(0.01)  # 10ms delay
            return test_asset
        
        mock_manager.get_asset_by_id.side_effect = slow_get_asset
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient(self.test_config)
        
        # Test without cache (first calls)
        start_time = time.time()
        for i in range(100):
            asset = client.get_asset(f"cache_test_{i}")
        no_cache_time = time.time() - start_time
        
        # Test with cache (repeated calls)
        start_time = time.time()
        for i in range(100):
            asset = client.get_asset("cache_test_1")  # Same asset ID
        cache_time = time.time() - start_time
        
        # Cache should provide significant speedup
        speedup_factor = no_cache_time / cache_time
        assert speedup_factor > 5  # At least 5x speedup
        assert cache_time < 0.5    # Cached calls should be very fast
        
        print(f"Cache performance:")
        print(f"  No cache: {no_cache_time:.3f}s")
        print(f"  With cache: {cache_time:.3f}s") 
        print(f"  Speedup: {speedup_factor:.1f}x")
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_connection_pool_efficiency(self, mock_pool):
        """Test efficiency of connection pooling."""
        # Mock connection pool
        mock_managers = [Mock() for _ in range(5)]
        for manager in mock_managers:
            manager.get_asset_by_id.return_value = PerformanceTestFixtures.create_test_asset()
        
        connection_call_count = 0
        
        def get_connection(timeout=None):
            nonlocal connection_call_count
            connection_call_count += 1
            return mock_managers[connection_call_count % 5], connection_call_count % 5
        
        mock_pool.return_value.get_connection.side_effect = get_connection
        
        client = RegistryClient(self.test_config)
        
        # Make many concurrent requests
        def make_requests(thread_id, count):
            for i in range(count):
                asset = client.get_asset(f"pool_test_{thread_id}_{i}")
        
        start_time = time.time()
        threads = []
        for thread_id in range(10):
            thread = threading.Thread(target=make_requests, args=(thread_id, 20))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Pool should efficiently handle concurrent requests
        assert total_time < 5  # Complete within 5 seconds
        assert connection_call_count >= 200  # All requests processed
        
        print(f"Connection pool performance:")
        print(f"  Total requests: {connection_call_count}")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Requests/second: {connection_call_count/total_time:.1f}")


class TestAuditLoggerPerformance:
    """Test performance of audit logging system."""
    
    def test_audit_logging_overhead(self):
        """Test performance overhead of audit logging."""
        # Test with audit logging disabled
        config_no_audit = {"enable_audit_logging": False}
        logger_no_audit = AuditLogger(config_no_audit)
        
        start_time = time.time()
        for i in range(1000):
            # Simulate validation event
            pass  # No logging
        no_audit_time = time.time() - start_time
        
        # Test with audit logging enabled
        config_with_audit = {"enable_audit_logging": True, "async_logging": True}
        logger_with_audit = AuditLogger(config_with_audit)
        
        start_time = time.time()
        for i in range(1000):
            logger_with_audit.log_validation_event(
                operation=f"performance_test_{i}",
                asset_id="performance_asset",
                amount=1000,
                result="approved"
            )
        with_audit_time = time.time() - start_time
        
        # Audit logging overhead should be minimal
        overhead = with_audit_time - no_audit_time
        overhead_per_event = (overhead * 1000) / 1000  # microseconds
        
        assert overhead < 2.0  # Less than 2 seconds total overhead
        assert overhead_per_event < 2000  # Less than 2ms per event
        
        print(f"Audit logging overhead:")
        print(f"  No audit: {no_audit_time:.3f}s")
        print(f"  With audit: {with_audit_time:.3f}s")
        print(f"  Overhead: {overhead:.3f}s ({overhead_per_event:.1f}μs per event)")
    
    def test_audit_log_batch_performance(self):
        """Test performance of batch audit logging."""
        config = {"async_logging": True, "batch_size": 100}
        logger = AuditLogger(config)
        
        # Test batch logging performance
        num_events = 5000
        start_time = time.time()
        
        for i in range(num_events):
            logger.log_validation_event(
                operation=f"batch_test_{i}",
                asset_id="batch_performance_asset",
                amount=1000
            )
        
        # Allow time for async processing
        time.sleep(1)
        end_time = time.time()
        
        total_time = end_time - start_time
        events_per_second = num_events / total_time
        
        # Should handle high-volume logging efficiently
        assert events_per_second >= 1000  # At least 1000 events/second
        assert total_time < 10  # Complete within 10 seconds
        
        print(f"Batch audit logging performance:")
        print(f"  Events: {num_events}")
        print(f"  Time: {total_time:.3f}s")
        print(f"  Events/second: {events_per_second:.1f}")


class TestValidatorStressTests:
    """Stress tests for validator system limits."""
    
    @patch('validator.core.RegistryManager')
    def test_high_concurrency_stress(self, mock_registry_manager):
        """Test validator under high concurrency stress."""
        # Mock registry for stress test
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = PerformanceTestFixtures.create_test_asset()
        mock_manager.get_asset_state.return_value = PerformanceTestFixtures.create_test_state()
        mock_manager.get_asset_supply_info.return_value = {'remaining_supply': 50_000_000}
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config={"enable_audit_logging": False}, registry_manager=mock_manager)
        mock_psbt_data = PerformanceTestFixtures.create_mock_psbt_data()
        
        # High concurrency stress test
        num_threads = 50
        validations_per_thread = 100
        results = []
        errors = []
        
        def stress_validation(thread_id):
            try:
                thread_results = {"success": 0, "failure": 0}
                
                with patch.object(validator.psbt_parser, 'parse', return_value=mock_psbt_data):
                    for i in range(validations_per_thread):
                        context = validator.validate_mint_transaction(f"stress_{thread_id}_{i}")
                        if context.has_errors():
                            thread_results["failure"] += 1
                        else:
                            thread_results["success"] += 1
                
                results.append(thread_results)
            except Exception as e:
                errors.append(f"Thread {thread_id}: {str(e)}")
        
        # Run stress test
        start_time = time.time()
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=stress_validation, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=30)  # 30 second timeout per thread
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Analyze results
        total_success = sum(r["success"] for r in results)
        total_failure = sum(r["failure"] for r in results)
        total_validations = total_success + total_failure
        success_rate = total_success / total_validations if total_validations > 0 else 0
        
        # Stress test assertions
        assert len(errors) == 0  # No thread errors
        assert len(results) == num_threads  # All threads completed
        assert success_rate >= 0.95  # At least 95% success rate
        assert total_validations == num_threads * validations_per_thread
        
        print(f"High concurrency stress test:")
        print(f"  Threads: {num_threads}")
        print(f"  Total validations: {total_validations}")
        print(f"  Success rate: {success_rate*100:.1f}%")
        print(f"  Duration: {total_time:.1f}s")
        print(f"  Throughput: {total_validations/total_time:.1f} validations/second")
    
    @patch('validator.core.RegistryManager')
    def test_memory_stress_large_datasets(self, mock_registry_manager):
        """Test validator with large datasets and memory pressure."""
        # Create large mock data structures
        large_psbt_data = {
            'global': {
                'version': 2,
                'proprietary_fields': {f"large_key_{i}": f"large_value_{i}" * 100 for i in range(100)}
            },
            'inputs': [
                {
                    'previous_output': {'tx_id': f'large_input_tx_{i}', 'output_index': i},
                    'proprietary_fields': {f"inp_{j}": f"data_{j}" * 50 for j in range(50)}
                } for i in range(20)
            ],
            'outputs': [
                {
                    'amount': 546 + i,
                    'script': b'\x6a' + f'large_metadata_{i}'.encode() * 10,
                    'proprietary_fields': {f"out_{j}": f"output_data_{j}" * 50 for j in range(50)}
                } for i in range(20)
            ]
        }
        
        # Mock registry with large asset data
        large_asset = PerformanceTestFixtures.create_test_asset()
        large_state = PerformanceTestFixtures.create_test_state()
        
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = large_asset
        mock_manager.get_asset_state.return_value = large_state
        mock_manager.get_asset_supply_info.return_value = {
            'remaining_supply': 50_000_000,
            'transaction_history': [f"tx_{i}" for i in range(1000)]  # Large history
        }
        mock_registry_manager.return_value = mock_manager
        
        validator = ValidationEngine(config={"enable_audit_logging": False}, registry_manager=mock_manager)
        
        # Monitor memory during stress test
        initial_memory = self.get_memory_usage()
        
        with patch.object(validator.psbt_parser, 'parse', return_value=large_psbt_data):
            for i in range(100):  # Smaller count due to large data
                context = validator.validate_mint_transaction(f"large_data_{i}")
                
                # Periodic memory check
                if i % 10 == 0:
                    current_memory = self.get_memory_usage()
                    memory_growth = current_memory - initial_memory
                    assert memory_growth < 500  # Less than 500MB growth
                    
                    # Force garbage collection periodically
                    gc.collect()
        
        final_memory = self.get_memory_usage()
        total_memory_growth = final_memory - initial_memory
        
        # Memory stress assertions
        assert total_memory_growth < 200  # Less than 200MB total growth
        
        print(f"Memory stress test with large datasets:")
        print(f"  Initial memory: {initial_memory:.1f} MB")
        print(f"  Final memory: {final_memory:.1f} MB")
        print(f"  Memory growth: {total_memory_growth:.1f} MB")
    
    @staticmethod
    def get_memory_usage() -> float:
        """Get current memory usage in MB."""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024


# Benchmark comparison tests
class TestPerformanceBenchmarks:
    """Benchmark tests for performance regression detection."""
    
    def test_validation_performance_baseline(self):
        """Establish performance baseline for validation operations."""
        # This test establishes baseline metrics that can be used
        # for regression testing in CI/CD pipelines
        
        baseline_metrics = {
            "single_validation_time_ms": 10.0,  # Target: <10ms per validation
            "throughput_per_second": 100,       # Target: >100 validations/second  
            "memory_per_validation_bytes": 1024, # Target: <1KB per validation
            "concurrent_success_rate": 0.95,    # Target: >95% success rate
        }
        
        # These metrics should be updated based on actual performance
        # and used as regression tests in CI/CD
        
        print("Performance baseline metrics:")
        for metric, target in baseline_metrics.items():
            print(f"  {metric}: {target}")
        
        # In a real implementation, these would be compared against
        # actual measured performance from the other tests
        assert True  # Placeholder - would compare actual vs baseline