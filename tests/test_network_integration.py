"""
Bitcoin Native Asset Protocol - Network Integration Tests

This module provides comprehensive integration tests for all network components
including RPC clients, broadcasting, monitoring, synchronization, and failover.
"""

import asyncio
import json
import os
import random
import shutil
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest

# Network components
try:
    from network.rpc import BitcoinRPCClient, RPCConfig, RPCError
    from network.broadcaster import TransactionBroadcaster, BroadcastPriority, BroadcastStatus
    from network.monitor import ConfirmationMonitor, MempoolMonitor, MonitoredTransaction
    from network.sync import RegistrySynchronizer, SyncConfig, SyncEventType
    from network.failover import MultiNodeRPCClient, NodeConfig, NodeType, LoadBalanceStrategy
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    from network.rpc import BitcoinRPCClient, RPCConfig, RPCError
    from network.broadcaster import TransactionBroadcaster, BroadcastPriority, BroadcastStatus
    from network.monitor import ConfirmationMonitor, MempoolMonitor, MonitoredTransaction
    from network.sync import RegistrySynchronizer, SyncConfig, SyncEventType
    from network.failover import MultiNodeRPCClient, NodeConfig, NodeType, LoadBalanceStrategy

# Registry components (mocked for integration tests)
try:
    from registry.manager import RegistryManager
    from registry.schema import FungibleAsset, AssetType, AssetStatus
except ImportError:
    # Create mock registry components for testing
    class MockRegistryManager:
        def __init__(self):
            self.assets = {}
        
        def get_all_assets(self):
            return list(self.assets.values())
        
        def get_asset(self, asset_id):
            return self.assets.get(asset_id)
        
        def register_asset(self, asset):
            self.assets[asset.asset_id] = asset
        
        def update_asset(self, asset):
            self.assets[asset.asset_id] = asset
    
    RegistryManager = MockRegistryManager


class RegtestEnvironment:
    """Helper class to manage regtest Bitcoin Core environment."""
    
    def __init__(self):
        self.datadir = None
        self.process = None
        self.rpc_port = None
        self.zmq_port = None
        self.rpc_user = "test"
        self.rpc_password = "test"
        
    def setup(self) -> bool:
        """Set up regtest environment."""
        try:
            # Create temporary directory
            self.datadir = tempfile.mkdtemp(prefix="bnap_regtest_")
            
            # Find available ports
            self.rpc_port = self._find_free_port(18332)
            self.zmq_port = self._find_free_port(28332)
            
            # Create bitcoin.conf
            conf_path = Path(self.datadir) / "bitcoin.conf"
            with open(conf_path, 'w') as f:
                f.write(f"""
regtest=1
server=1
daemon=1
txindex=1
rpcuser={self.rpc_user}
rpcpassword={self.rpc_password}
rpcport={self.rpc_port}
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
zmqpubhashblock=tcp://127.0.0.1:{self.zmq_port}
zmqpubrawtx=tcp://127.0.0.1:{self.zmq_port + 1}
fallbackfee=0.0001
""")
            
            # Try to start bitcoind (this may fail if not installed)
            try:
                cmd = [
                    'bitcoind',
                    f'-datadir={self.datadir}',
                    '-regtest',
                    '-server',
                    '-daemon'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    print(f"Failed to start bitcoind: {result.stderr}")
                    return False
                
                # Wait for RPC to be ready
                time.sleep(2)
                
                # Test RPC connection
                client = BitcoinRPCClient(RPCConfig(
                    host="localhost",
                    port=self.rpc_port,
                    username=self.rpc_user,
                    password=self.rpc_password
                ))
                
                # Generate initial blocks
                client.generatetoaddress(101, client.getnewaddress())
                
                return True
                
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                print(f"Failed to setup regtest environment: {e}")
                return False
                
        except Exception as e:
            print(f"Setup error: {e}")
            return False
    
    def teardown(self):
        """Clean up regtest environment."""
        if self.process:
            try:
                # Stop bitcoind
                subprocess.run([
                    'bitcoin-cli',
                    f'-datadir={self.datadir}',
                    '-regtest',
                    'stop'
                ], timeout=10)
                
                # Wait for process to stop
                time.sleep(2)
                
            except Exception as e:
                print(f"Error stopping bitcoind: {e}")
        
        # Clean up data directory
        if self.datadir and os.path.exists(self.datadir):
            shutil.rmtree(self.datadir, ignore_errors=True)
    
    def _find_free_port(self, start_port: int) -> int:
        """Find a free port starting from start_port."""
        import socket
        
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    return port
            except OSError:
                continue
        
        raise RuntimeError("No free ports available")
    
    def get_rpc_config(self) -> RPCConfig:
        """Get RPC configuration for this environment."""
        return RPCConfig(
            host="localhost",
            port=self.rpc_port,
            username=self.rpc_user,
            password=self.rpc_password
        )
    
    def get_rpc_client(self) -> BitcoinRPCClient:
        """Get RPC client for this environment."""
        return BitcoinRPCClient(self.get_rpc_config())


class NetworkIntegrationTestCase(unittest.TestCase):
    """Base class for network integration tests."""
    
    @classmethod
    def setUpClass(cls):
        """Set up regtest environment for all tests."""
        cls.regtest = RegtestEnvironment()
        
        # Try to set up regtest environment
        if not cls.regtest.setup():
            # Skip tests if Bitcoin Core is not available
            pytest.skip("Bitcoin Core not available for integration tests")
        
        cls.rpc_client = cls.regtest.get_rpc_client()
        cls.registry_manager = MockRegistryManager() if 'MockRegistryManager' in globals() else RegistryManager()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up regtest environment."""
        if hasattr(cls, 'regtest'):
            cls.regtest.teardown()
    
    def setUp(self):
        """Set up for each test."""
        # Generate some blocks to ensure we have coins
        try:
            self.rpc_client.generatetoaddress(10, self.rpc_client.getnewaddress())
        except Exception:
            pass  # May fail if already generated
    
    def create_test_transaction(self) -> Tuple[str, str]:
        """Create a test transaction and return (txid, raw_hex)."""
        try:
            # Get a UTXO
            unspent = self.rpc_client.listunspent(0, 999999)
            if not unspent:
                self.rpc_client.generatetoaddress(1, self.rpc_client.getnewaddress())
                unspent = self.rpc_client.listunspent(0, 999999)
            
            utxo = unspent[0]
            
            # Create recipient address
            recipient = self.rpc_client.getnewaddress()
            
            # Create transaction
            inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
            outputs = {recipient: 0.1}  # Send 0.1 BTC
            
            raw_tx = self.rpc_client.createrawtransaction(inputs, outputs)
            signed_tx = self.rpc_client.signrawtransactionwithwallet(raw_tx)
            
            if not signed_tx.get("complete"):
                raise Exception("Failed to sign transaction")
            
            return signed_tx["txid"], signed_tx["hex"]
            
        except Exception as e:
            self.fail(f"Failed to create test transaction: {e}")


class TestRPCClientIntegration(NetworkIntegrationTestCase):
    """Test RPC client integration with real Bitcoin Core."""
    
    def test_basic_rpc_calls(self):
        """Test basic RPC functionality."""
        # Test getblockcount
        height = self.rpc_client.getblockcount()
        self.assertIsInstance(height, int)
        self.assertGreaterEqual(height, 0)
        
        # Test getblockhash
        block_hash = self.rpc_client.getblockhash(0)
        self.assertIsInstance(block_hash, str)
        self.assertEqual(len(block_hash), 64)
        
        # Test getblock
        block = self.rpc_client.getblock(block_hash)
        self.assertIsInstance(block, dict)
        self.assertEqual(block["height"], 0)
    
    def test_transaction_operations(self):
        """Test transaction-related RPC calls."""
        txid, raw_hex = self.create_test_transaction()
        
        # Test getrawtransaction
        raw_tx = self.rpc_client.getrawtransaction(txid, True)
        self.assertIsInstance(raw_tx, dict)
        self.assertEqual(raw_tx["txid"], txid)
        
        # Test sendrawtransaction
        broadcast_txid = self.rpc_client.sendrawtransaction(raw_hex)
        self.assertEqual(broadcast_txid, txid)
        
        # Test getrawmempool
        mempool = self.rpc_client.getrawmempool()
        self.assertIn(txid, mempool)
    
    def test_connection_pooling(self):
        """Test RPC client connection pooling under load."""
        def make_rpc_call():
            return self.rpc_client.getblockcount()
        
        # Make concurrent RPC calls
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_rpc_call) for _ in range(50)]
            
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
        
        # All calls should succeed and return the same height (approximately)
        self.assertEqual(len(results), 50)
        self.assertTrue(all(isinstance(r, int) for r in results))
        
        # Heights should be within a small range (due to block generation during test)
        height_range = max(results) - min(results)
        self.assertLessEqual(height_range, 5)
    
    def test_error_handling(self):
        """Test RPC client error handling."""
        # Test invalid method
        with self.assertRaises(RPCError):
            self.rpc_client._call("invalidmethod")
        
        # Test invalid parameters
        with self.assertRaises(RPCError):
            self.rpc_client.getblockhash(-1)


class TestTransactionBroadcasterIntegration(NetworkIntegrationTestCase):
    """Test transaction broadcaster integration."""
    
    def setUp(self):
        super().setUp()
        self.broadcaster = TransactionBroadcaster(self.rpc_client)
    
    def test_successful_broadcast(self):
        """Test successful transaction broadcasting."""
        txid, raw_hex = self.create_test_transaction()
        
        # Broadcast transaction
        result = self.broadcaster.broadcast_transaction(txid, raw_hex)
        
        self.assertEqual(result.status, BroadcastStatus.SUCCESS)
        self.assertEqual(result.txid, txid)
        self.assertIsNone(result.error)
    
    def test_broadcast_with_priority(self):
        """Test broadcasting with different priorities."""
        # Create multiple transactions
        transactions = []
        for _ in range(3):
            txid, raw_hex = self.create_test_transaction()
            transactions.append((txid, raw_hex))
        
        # Broadcast with different priorities
        priorities = [BroadcastPriority.LOW, BroadcastPriority.NORMAL, BroadcastPriority.HIGH]
        
        results = []
        for (txid, raw_hex), priority in zip(transactions, priorities):
            result = self.broadcaster.broadcast_transaction(txid, raw_hex, priority)
            results.append(result)
        
        # All should succeed
        for result in results:
            self.assertEqual(result.status, BroadcastStatus.SUCCESS)
    
    def test_batch_broadcasting(self):
        """Test batch transaction broadcasting."""
        # Create multiple transactions
        transactions = []
        for _ in range(5):
            txid, raw_hex = self.create_test_transaction()
            transactions.append((txid, raw_hex))
        
        # Broadcast all transactions
        requests = []
        for txid, raw_hex in transactions:
            requests.append({
                'txid': txid,
                'raw_transaction': raw_hex,
                'priority': BroadcastPriority.NORMAL
            })
        
        results = []
        for request in requests:
            result = self.broadcaster.broadcast_transaction(
                request['txid'],
                request['raw_transaction'],
                request['priority']
            )
            results.append(result)
        
        # All should succeed
        successful = [r for r in results if r.status == BroadcastStatus.SUCCESS]
        self.assertEqual(len(successful), 5)
    
    def test_broadcast_statistics(self):
        """Test broadcasting statistics tracking."""
        initial_stats = self.broadcaster.get_statistics()
        
        # Broadcast some transactions
        for _ in range(3):
            txid, raw_hex = self.create_test_transaction()
            self.broadcaster.broadcast_transaction(txid, raw_hex)
        
        final_stats = self.broadcaster.get_statistics()
        
        # Stats should be updated
        self.assertGreaterEqual(
            final_stats['total_broadcasts'],
            initial_stats['total_broadcasts'] + 3
        )
        self.assertGreaterEqual(
            final_stats['successful_broadcasts'],
            initial_stats['successful_broadcasts'] + 3
        )


class TestConfirmationMonitoringIntegration(NetworkIntegrationTestCase):
    """Test confirmation monitoring integration."""
    
    def setUp(self):
        super().setUp()
        self.monitor = ConfirmationMonitor(self.rpc_client)
        self.monitor.start()
    
    def tearDown(self):
        self.monitor.stop()
    
    def test_transaction_confirmation_tracking(self):
        """Test tracking transaction confirmations."""
        txid, raw_hex = self.create_test_transaction()
        
        # Broadcast transaction
        broadcast_txid = self.rpc_client.sendrawtransaction(raw_hex)
        self.assertEqual(broadcast_txid, txid)
        
        # Add to monitoring
        self.assertTrue(self.monitor.add_transaction(txid, required_confirmations=1))
        
        # Generate block to confirm transaction
        self.rpc_client.generatetoaddress(1, self.rpc_client.getnewaddress())
        
        # Wait for monitoring to detect confirmation
        time.sleep(2)
        
        # Check transaction status
        tx_status = self.monitor.get_transaction_status(txid)
        self.assertIsNotNone(tx_status)
        self.assertGreaterEqual(tx_status.current_confirmations, 1)
    
    def test_multiple_transaction_monitoring(self):
        """Test monitoring multiple transactions."""
        transactions = []
        
        # Create and broadcast multiple transactions
        for _ in range(3):
            txid, raw_hex = self.create_test_transaction()
            self.rpc_client.sendrawtransaction(raw_hex)
            self.monitor.add_transaction(txid, required_confirmations=2)
            transactions.append(txid)
        
        # Generate blocks to confirm
        self.rpc_client.generatetoaddress(3, self.rpc_client.getnewaddress())
        
        # Wait for monitoring
        time.sleep(3)
        
        # Check all transactions
        for txid in transactions:
            status = self.monitor.get_transaction_status(txid)
            self.assertIsNotNone(status)
            self.assertGreaterEqual(status.current_confirmations, 2)
    
    def test_confirmation_callbacks(self):
        """Test confirmation event callbacks."""
        confirmed_transactions = []
        
        def confirmation_callback(tx: MonitoredTransaction):
            if tx.is_confirmed():
                confirmed_transactions.append(tx.txid)
        
        self.monitor.add_confirmation_callback(confirmation_callback)
        
        # Create and monitor transaction
        txid, raw_hex = self.create_test_transaction()
        self.rpc_client.sendrawtransaction(raw_hex)
        self.monitor.add_transaction(txid, required_confirmations=1)
        
        # Generate block
        self.rpc_client.generatetoaddress(1, self.rpc_client.getnewaddress())
        
        # Wait for callback
        time.sleep(3)
        
        # Check callback was triggered
        self.assertIn(txid, confirmed_transactions)


class TestMempoolMonitoringIntegration(NetworkIntegrationTestCase):
    """Test mempool monitoring integration."""
    
    def setUp(self):
        super().setUp()
        self.mempool_monitor = MempoolMonitor(self.rpc_client)
        self.mempool_monitor.start()
    
    def tearDown(self):
        self.mempool_monitor.stop()
    
    def test_mempool_transaction_detection(self):
        """Test detection of new mempool transactions."""
        detected_txs = []
        
        def mempool_callback(event):
            if event.event_type == "transaction_added":
                detected_txs.append(event.txid)
        
        self.mempool_monitor.add_event_callback(mempool_callback)
        
        # Create and broadcast transaction
        txid, raw_hex = self.create_test_transaction()
        self.rpc_client.sendrawtransaction(raw_hex)
        
        # Wait for detection
        time.sleep(2)
        
        # Check detection
        self.assertIn(txid, detected_txs)
    
    def test_mempool_fee_rate_analysis(self):
        """Test mempool fee rate analysis."""
        # Create transactions with different fee rates
        for _ in range(3):
            txid, raw_hex = self.create_test_transaction()
            self.rpc_client.sendrawtransaction(raw_hex)
        
        time.sleep(2)
        
        # Get fee analysis
        fee_analysis = self.mempool_monitor.get_fee_analysis()
        
        self.assertIsInstance(fee_analysis, dict)
        self.assertIn('average_fee_rate', fee_analysis)
        self.assertIn('median_fee_rate', fee_analysis)
        self.assertIn('total_transactions', fee_analysis)


class TestRegistrySynchronizationIntegration(NetworkIntegrationTestCase):
    """Test registry synchronization integration."""
    
    def setUp(self):
        super().setUp()
        self.confirmation_monitor = ConfirmationMonitor(self.rpc_client)
        self.mempool_monitor = MempoolMonitor(self.rpc_client)
        
        sync_config = SyncConfig(
            confirmation_threshold=1,
            batch_size=10,
            enable_mempool_tracking=True
        )
        
        self.synchronizer = RegistrySynchronizer(
            self.registry_manager,
            self.confirmation_monitor,
            self.mempool_monitor,
            sync_config
        )
        
        # Start components
        self.confirmation_monitor.start()
        self.mempool_monitor.start()
        self.synchronizer.start()
    
    def tearDown(self):
        self.synchronizer.stop()
        self.mempool_monitor.stop()
        self.confirmation_monitor.stop()
    
    def test_sync_event_processing(self):
        """Test synchronization event processing."""
        sync_events = []
        
        def sync_callback(event):
            sync_events.append(event)
        
        self.synchronizer.add_sync_callback(sync_callback)
        
        # Create test transaction (simulating BNAP transaction)
        txid, raw_hex = self.create_test_transaction()
        
        # Add to confirmation monitoring
        self.confirmation_monitor.add_transaction(txid)
        
        # Broadcast and confirm
        self.rpc_client.sendrawtransaction(raw_hex)
        self.rpc_client.generatetoaddress(2, self.rpc_client.getnewaddress())
        
        # Wait for sync processing
        time.sleep(3)
        
        # Check sync status
        sync_status = self.synchronizer.get_sync_status()
        self.assertEqual(sync_status['status'], 'running')
    
    def test_state_validation(self):
        """Test registry state validation."""
        # Perform state validation
        validation_results = self.synchronizer.validate_state()
        
        self.assertIsInstance(validation_results, dict)
        self.assertIn('valid', validation_results)
        self.assertIn('registry_height', validation_results)
        self.assertIn('blockchain_height', validation_results)
    
    def test_recovery_mechanism(self):
        """Test synchronization recovery mechanism."""
        # Force recovery
        current_height = self.rpc_client.getblockcount()
        self.synchronizer.force_recovery(current_height - 5)
        
        # Wait for recovery processing
        time.sleep(2)
        
        # Check status
        sync_status = self.synchronizer.get_sync_status()
        self.assertIsInstance(sync_status, dict)


class TestMultiNodeFailoverIntegration(NetworkIntegrationTestCase):
    """Test multi-node failover integration."""
    
    def test_single_node_operations(self):
        """Test multi-node client with single node."""
        primary_config = NodeConfig(
            node_id="primary",
            rpc_config=self.regtest.get_rpc_config(),
            node_type=NodeType.LOCAL,
            weight=1.0
        )
        
        multi_client = MultiNodeRPCClient([primary_config])
        
        try:
            # Test basic operations
            height = multi_client.get_block_count()
            self.assertIsInstance(height, int)
            
            # Test statistics
            stats = multi_client.get_node_statistics()
            self.assertEqual(stats['total_nodes'], 1)
            self.assertEqual(stats['global_stats']['nodes_online'], 1)
            
        finally:
            multi_client.close()
    
    def test_load_balancing_strategies(self):
        """Test different load balancing strategies."""
        strategies = [
            LoadBalanceStrategy.ROUND_ROBIN,
            LoadBalanceStrategy.WEIGHTED_RANDOM,
            LoadBalanceStrategy.LOWEST_LATENCY,
            LoadBalanceStrategy.LEAST_LOADED
        ]
        
        for strategy in strategies:
            primary_config = NodeConfig(
                node_id="primary",
                rpc_config=self.regtest.get_rpc_config(),
                node_type=NodeType.LOCAL,
                weight=1.0
            )
            
            multi_client = MultiNodeRPCClient([primary_config], strategy)
            
            try:
                # Test multiple calls with this strategy
                for _ in range(5):
                    height = multi_client.get_block_count()
                    self.assertIsInstance(height, int)
                
            finally:
                multi_client.close()


class TestNetworkPerformanceBenchmarks(NetworkIntegrationTestCase):
    """Performance benchmarks for network components."""
    
    def test_rpc_client_throughput(self):
        """Benchmark RPC client throughput."""
        start_time = time.time()
        call_count = 100
        
        for _ in range(call_count):
            self.rpc_client.getblockcount()
        
        elapsed = time.time() - start_time
        throughput = call_count / elapsed
        
        print(f"RPC Client Throughput: {throughput:.1f} calls/second")
        self.assertGreater(throughput, 10)  # At least 10 calls per second
    
    def test_broadcast_performance(self):
        """Benchmark transaction broadcasting performance."""
        broadcaster = TransactionBroadcaster(self.rpc_client)
        
        # Create test transactions
        transactions = []
        for _ in range(10):
            txid, raw_hex = self.create_test_transaction()
            transactions.append((txid, raw_hex))
        
        # Benchmark broadcasting
        start_time = time.time()
        
        results = []
        for txid, raw_hex in transactions:
            result = broadcaster.broadcast_transaction(txid, raw_hex)
            results.append(result)
        
        elapsed = time.time() - start_time
        throughput = len(transactions) / elapsed
        
        print(f"Broadcast Throughput: {throughput:.1f} tx/second")
        
        # Check all broadcasts succeeded
        successful = [r for r in results if r.status == BroadcastStatus.SUCCESS]
        self.assertEqual(len(successful), len(transactions))
    
    def test_confirmation_monitoring_scalability(self):
        """Test confirmation monitoring with many transactions."""
        monitor = ConfirmationMonitor(self.rpc_client)
        monitor.start()
        
        try:
            # Add many transactions to monitoring
            transaction_count = 50
            transactions = []
            
            for _ in range(transaction_count):
                txid, raw_hex = self.create_test_transaction()
                self.rpc_client.sendrawtransaction(raw_hex)
                monitor.add_transaction(txid, required_confirmations=1)
                transactions.append(txid)
            
            # Generate blocks to confirm all
            self.rpc_client.generatetoaddress(2, self.rpc_client.getnewaddress())
            
            # Wait for all confirmations
            start_time = time.time()
            confirmed_count = 0
            
            while confirmed_count < transaction_count and (time.time() - start_time) < 30:
                confirmed_count = 0
                for txid in transactions:
                    status = monitor.get_transaction_status(txid)
                    if status and status.is_confirmed():
                        confirmed_count += 1
                
                if confirmed_count < transaction_count:
                    time.sleep(1)
            
            elapsed = time.time() - start_time
            print(f"Monitored {transaction_count} confirmations in {elapsed:.1f}s")
            
            self.assertEqual(confirmed_count, transaction_count)
            self.assertLess(elapsed, 20)  # Should complete within 20 seconds
            
        finally:
            monitor.stop()


class TestNetworkStressTesting(NetworkIntegrationTestCase):
    """Stress tests for network components."""
    
    def test_concurrent_rpc_calls(self):
        """Test concurrent RPC calls under heavy load."""
        def make_concurrent_calls():
            results = []
            errors = []
            
            def rpc_worker():
                try:
                    for _ in range(10):
                        result = self.rpc_client.getblockcount()
                        results.append(result)
                except Exception as e:
                    errors.append(str(e))
            
            # Create multiple worker threads
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(rpc_worker) for _ in range(10)]
                
                for future in as_completed(futures):
                    future.result()  # Wait for completion
            
            return results, errors
        
        results, errors = make_concurrent_calls()
        
        # Should handle concurrent load without errors
        self.assertGreater(len(results), 50)  # At least some calls should succeed
        error_rate = len(errors) / (len(results) + len(errors))
        self.assertLess(error_rate, 0.1)  # Less than 10% error rate
    
    def test_memory_usage_under_load(self):
        """Test memory usage under sustained load."""
        import psutil
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create components
        broadcaster = TransactionBroadcaster(self.rpc_client)
        monitor = ConfirmationMonitor(self.rpc_client)
        monitor.start()
        
        try:
            # Sustained operation
            for _ in range(100):
                # Create and broadcast transaction
                txid, raw_hex = self.create_test_transaction()
                broadcaster.broadcast_transaction(txid, raw_hex)
                monitor.add_transaction(txid)
                
                # Generate block occasionally
                if _ % 10 == 0:
                    self.rpc_client.generatetoaddress(1, self.rpc_client.getnewaddress())
            
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory
            
            print(f"Memory usage increased by {memory_increase:.1f} MB")
            
            # Should not consume excessive memory
            self.assertLess(memory_increase, 100)  # Less than 100MB increase
            
        finally:
            monitor.stop()


def run_integration_tests():
    """Run all integration tests."""
    # Check if we can run integration tests
    try:
        subprocess.run(['which', 'bitcoind'], check=True, capture_output=True)
        subprocess.run(['which', 'bitcoin-cli'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Bitcoin Core not found. Skipping integration tests.")
        print("Install Bitcoin Core to run these tests:")
        print("- Ubuntu/Debian: sudo apt-get install bitcoind")
        print("- macOS: brew install bitcoin")
        return False
    
    # Create test suite
    test_classes = [
        TestRPCClientIntegration,
        TestTransactionBroadcasterIntegration,
        TestConfirmationMonitoringIntegration,
        TestMempoolMonitoringIntegration,
        TestRegistrySynchronizationIntegration,
        TestMultiNodeFailoverIntegration,
        TestNetworkPerformanceBenchmarks,
        TestNetworkStressTesting
    ]
    
    suite = unittest.TestSuite()
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    print("Bitcoin Native Asset Protocol - Network Integration Tests")
    print("=" * 60)
    
    success = run_integration_tests()
    
    if success:
        print("\n✓ All network integration tests passed!")
    else:
        print("\n✗ Some integration tests failed!")
        exit(1)