"""
Bitcoin Native Asset Protocol - Network Unit Tests

This module provides unit tests for network components that can run without Bitcoin Core.
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch, Mock
from datetime import datetime, timezone

try:
    from network.rpc import BitcoinRPCClient, RPCConfig, RPCError, RPCConnectionError
    from network.broadcaster import TransactionBroadcaster, BroadcastPriority, BroadcastStatus
    from network.monitor import ConfirmationMonitor, MempoolMonitor
    from network.sync import RegistrySynchronizer, SyncConfig, SyncEventType
    from network.failover import MultiNodeRPCClient, NodeConfig, NodeType, LoadBalanceStrategy
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    from network.rpc import BitcoinRPCClient, RPCConfig, RPCError, RPCConnectionError
    from network.broadcaster import TransactionBroadcaster, BroadcastPriority, BroadcastStatus
    from network.monitor import ConfirmationMonitor, MempoolMonitor
    from network.sync import RegistrySynchronizer, SyncConfig, SyncEventType
    from network.failover import MultiNodeRPCClient, NodeConfig, NodeType, LoadBalanceStrategy


class TestRPCClientUnit(unittest.TestCase):
    """Unit tests for RPC client without Bitcoin Core."""
    
    def setUp(self):
        self.config = RPCConfig(
            host="localhost",
            port=8332,
            username="test",
            password="test"
        )
    
    @patch('network.rpc.requests.post')
    def test_rpc_call_success(self, mock_post):
        """Test successful RPC call."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": 100,
            "error": None,
            "id": 1
        }
        mock_post.return_value = mock_response
        
        client = BitcoinRPCClient(self.config)
        result = client.getblockcount()
        
        self.assertEqual(result, 100)
        mock_post.assert_called_once()
    
    @patch('network.rpc.requests.post')
    def test_rpc_call_error(self, mock_post):
        """Test RPC call with error response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": None,
            "error": {"code": -1, "message": "Test error"},
            "id": 1
        }
        mock_post.return_value = mock_response
        
        client = BitcoinRPCClient(self.config)
        
        with self.assertRaises(RPCError) as context:
            client.getblockcount()
        
        self.assertEqual(context.exception.code, -1)
        self.assertEqual(context.exception.message, "Test error")
    
    @patch('network.rpc.requests.post')
    def test_connection_error(self, mock_post):
        """Test connection error handling."""
        mock_post.side_effect = Exception("Connection failed")
        
        client = BitcoinRPCClient(self.config)
        
        with self.assertRaises(RPCConnectionError):
            client.getblockcount()
    
    def test_config_validation(self):
        """Test RPC configuration validation."""
        # Test invalid port
        with self.assertRaises(ValueError):
            RPCConfig(host="localhost", port=0, username="test", password="test")
        
        # Test missing authentication
        with self.assertRaises(ValueError):
            RPCConfig(host="localhost", port=8332, username=None, password=None, cookie_file=None)


class TestTransactionBroadcasterUnit(unittest.TestCase):
    """Unit tests for transaction broadcaster."""
    
    def setUp(self):
        self.mock_rpc = MagicMock()
        self.broadcaster = TransactionBroadcaster(self.mock_rpc)
    
    def test_successful_broadcast(self):
        """Test successful transaction broadcast."""
        self.mock_rpc.sendrawtransaction.return_value = "test_txid"
        
        result = self.broadcaster.broadcast_transaction("test_txid", "test_hex")
        
        self.assertEqual(result.status, BroadcastStatus.SUCCESS)
        self.assertEqual(result.txid, "test_txid")
        self.assertIsNone(result.error)
        self.mock_rpc.sendrawtransaction.assert_called_once_with("test_hex", None)
    
    def test_broadcast_with_fee_rate(self):
        """Test broadcast with maximum fee rate."""
        self.mock_rpc.sendrawtransaction.return_value = "test_txid"
        
        result = self.broadcaster.broadcast_transaction("test_txid", "test_hex", max_fee_rate=0.001)
        
        self.assertEqual(result.status, BroadcastStatus.SUCCESS)
        self.mock_rpc.sendrawtransaction.assert_called_once_with("test_hex", 0.001)
    
    def test_broadcast_failure(self):
        """Test broadcast failure handling."""
        self.mock_rpc.sendrawtransaction.side_effect = RPCError(-25, "Missing inputs")
        
        result = self.broadcaster.broadcast_transaction("test_txid", "test_hex")
        
        self.assertEqual(result.status, BroadcastStatus.FAILED)
        self.assertIsNotNone(result.error)
        self.assertIn("Missing inputs", result.error)
    
    def test_priority_queue(self):
        """Test priority-based broadcasting."""
        self.mock_rpc.sendrawtransaction.return_value = "test_txid"
        
        # Broadcast with high priority
        result = self.broadcaster.broadcast_transaction("test_txid", "test_hex", BroadcastPriority.HIGH)
        
        self.assertEqual(result.status, BroadcastStatus.SUCCESS)
        self.assertEqual(result.request.priority, BroadcastPriority.HIGH)
    
    def test_statistics_tracking(self):
        """Test statistics tracking."""
        self.mock_rpc.sendrawtransaction.return_value = "test_txid"
        
        initial_stats = self.broadcaster.get_statistics()
        
        # Perform broadcasts
        self.broadcaster.broadcast_transaction("txid1", "hex1")
        self.broadcaster.broadcast_transaction("txid2", "hex2")
        
        final_stats = self.broadcaster.get_statistics()
        
        self.assertGreaterEqual(
            final_stats['total_broadcasts'],
            initial_stats['total_broadcasts'] + 2
        )
        self.assertGreaterEqual(
            final_stats['successful_broadcasts'],
            initial_stats['successful_broadcasts'] + 2
        )


class TestConfirmationMonitorUnit(unittest.TestCase):
    """Unit tests for confirmation monitor."""
    
    def setUp(self):
        self.mock_rpc = MagicMock()
        self.monitor = ConfirmationMonitor(self.mock_rpc)
    
    def test_add_transaction(self):
        """Test adding transaction to monitoring."""
        result = self.monitor.add_transaction("test_txid", required_confirmations=6)
        self.assertTrue(result)
        
        # Test duplicate addition
        result = self.monitor.add_transaction("test_txid", required_confirmations=6)
        self.assertFalse(result)
    
    def test_remove_transaction(self):
        """Test removing transaction from monitoring."""
        self.monitor.add_transaction("test_txid")
        
        result = self.monitor.remove_transaction("test_txid")
        self.assertTrue(result)
        
        # Test removing non-existent transaction
        result = self.monitor.remove_transaction("non_existent")
        self.assertFalse(result)
    
    def test_transaction_status(self):
        """Test getting transaction status."""
        self.monitor.add_transaction("test_txid", required_confirmations=3)
        
        status = self.monitor.get_transaction_status("test_txid")
        self.assertIsNotNone(status)
        self.assertEqual(status.txid, "test_txid")
        self.assertEqual(status.required_confirmations, 3)
        
        # Test non-existent transaction
        status = self.monitor.get_transaction_status("non_existent")
        self.assertIsNone(status)
    
    def test_callback_registration(self):
        """Test callback registration."""
        callback_called = []
        
        def test_callback(tx):
            callback_called.append(tx.txid)
        
        self.monitor.add_confirmation_callback(test_callback)
        
        # Callbacks list should contain our callback
        self.assertEqual(len(self.monitor._confirmation_callbacks), 1)


class TestMempoolMonitorUnit(unittest.TestCase):
    """Unit tests for mempool monitor."""
    
    def setUp(self):
        self.mock_rpc = MagicMock()
        self.monitor = MempoolMonitor(self.mock_rpc)
    
    def test_mempool_update(self):
        """Test mempool state update."""
        # Mock mempool response
        self.mock_rpc.getrawmempool.return_value = ["txid1", "txid2", "txid3"]
        
        # Update mempool state
        self.monitor._update_mempool_state()
        
        # Check internal state
        self.assertEqual(len(self.monitor._current_mempool), 3)
        self.assertIn("txid1", self.monitor._current_mempool)
    
    def test_event_callback(self):
        """Test event callback registration."""
        events_received = []
        
        def test_callback(event):
            events_received.append(event)
        
        self.monitor.add_event_callback(test_callback)
        
        # Callbacks list should contain our callback
        self.assertEqual(len(self.monitor._event_callbacks), 1)
    
    def test_fee_analysis(self):
        """Test fee rate analysis."""
        # Mock mempool with fee data
        self.mock_rpc.getrawmempool.return_value = {
            "txid1": {"fees": {"base": 0.001}},
            "txid2": {"fees": {"base": 0.002}},
            "txid3": {"fees": {"base": 0.0015}}
        }
        
        analysis = self.monitor.get_fee_analysis()
        
        self.assertIsInstance(analysis, dict)
        self.assertIn('total_transactions', analysis)


class TestRegistrySynchronizerUnit(unittest.TestCase):
    """Unit tests for registry synchronizer."""
    
    def setUp(self):
        self.mock_registry = MagicMock()
        self.mock_confirmation_monitor = MagicMock()
        self.mock_mempool_monitor = MagicMock()
        
        self.config = SyncConfig(
            confirmation_threshold=1,
            batch_size=10
        )
        
        self.synchronizer = RegistrySynchronizer(
            self.mock_registry,
            self.mock_confirmation_monitor,
            self.mock_mempool_monitor,
            self.config
        )
    
    def test_initialization(self):
        """Test synchronizer initialization."""
        self.assertEqual(self.synchronizer.config.confirmation_threshold, 1)
        self.assertEqual(self.synchronizer.config.batch_size, 10)
    
    def test_sync_callback(self):
        """Test sync callback registration."""
        callbacks_received = []
        
        def test_callback(event):
            callbacks_received.append(event)
        
        self.synchronizer.add_sync_callback(test_callback)
        
        # Should have our callback registered
        self.assertEqual(len(self.synchronizer._sync_callbacks), 1)
    
    def test_state_validation(self):
        """Test registry state validation."""
        # Mock registry methods
        self.mock_registry.get_all_assets.return_value = []
        self.synchronizer.confirmation_monitor.rpc_client.getblockcount.return_value = 100
        
        validation_results = self.synchronizer.validate_state()
        
        self.assertIsInstance(validation_results, dict)
        self.assertIn('valid', validation_results)
        self.assertIn('blockchain_height', validation_results)
    
    def test_sync_status(self):
        """Test sync status reporting."""
        status = self.synchronizer.get_sync_status()
        
        self.assertIsInstance(status, dict)
        self.assertIn('status', status)
        self.assertIn('last_processed_height', status)
        self.assertIn('statistics', status)


class TestMultiNodeRPCUnit(unittest.TestCase):
    """Unit tests for multi-node RPC client."""
    
    def setUp(self):
        self.node_config = NodeConfig(
            node_id="test_node",
            rpc_config=RPCConfig(
                host="localhost",
                port=8332,
                username="test",
                password="test"
            ),
            node_type=NodeType.LOCAL,
            weight=1.0
        )
    
    @patch('network.failover.BitcoinRPCClient')
    def test_client_initialization(self, mock_rpc_client):
        """Test multi-node client initialization."""
        mock_client_instance = MagicMock()
        mock_rpc_client.return_value = mock_client_instance
        
        client = MultiNodeRPCClient([self.node_config])
        
        self.assertEqual(len(client.nodes), 1)
        self.assertIn("test_node", client.nodes)
    
    @patch('network.failover.BitcoinRPCClient')
    def test_node_selection(self, mock_rpc_client):
        """Test node selection strategies."""
        mock_client_instance = MagicMock()
        mock_rpc_client.return_value = mock_client_instance
        
        client = MultiNodeRPCClient([self.node_config])
        
        # Test round-robin selection
        selected = client.select_node(client.nodes.get("test_node").enable_for_reads)
        self.assertIsNotNone(selected)
    
    @patch('network.failover.BitcoinRPCClient')
    def test_statistics(self, mock_rpc_client):
        """Test statistics collection."""
        mock_client_instance = MagicMock()
        mock_rpc_client.return_value = mock_client_instance
        
        client = MultiNodeRPCClient([self.node_config])
        
        stats = client.get_node_statistics()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('global_stats', stats)
        self.assertIn('node_stats', stats)
        self.assertIn('total_nodes', stats)
        self.assertEqual(stats['total_nodes'], 1)


def run_unit_tests():
    """Run all unit tests."""
    print("Running Network Component Unit Tests...")
    print("=" * 50)
    
    # Create test suite
    test_classes = [
        TestRPCClientUnit,
        TestTransactionBroadcasterUnit,
        TestConfirmationMonitorUnit,
        TestMempoolMonitorUnit,
        TestRegistrySynchronizerUnit,
        TestMultiNodeRPCUnit
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
    success = run_unit_tests()
    
    if success:
        print("\n✅ All network unit tests passed!")
    else:
        print("\n❌ Some unit tests failed!")
        exit(1)