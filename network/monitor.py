"""
Bitcoin Native Asset Protocol - Transaction Confirmation Monitoring

This module provides comprehensive transaction confirmation monitoring with
ZMQ subscription support, polling fallback, and blockchain reorganization detection.
"""

import asyncio
import json
import logging
import time
import threading
from typing import Dict, List, Optional, Set, Tuple, Union, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from collections import defaultdict, deque
import hashlib
import weakref

try:
    import zmq
    import zmq.asyncio
    ZMQ_AVAILABLE = True
except ImportError:
    ZMQ_AVAILABLE = False

try:
    from .rpc import BitcoinRPCClient, RPCConfig, RPCError
except ImportError:
    # For standalone testing
    from rpc import BitcoinRPCClient, RPCConfig, RPCError


class MonitoringMethod(Enum):
    """Methods for monitoring transactions."""
    ZMQ_ONLY = "zmq_only"
    POLLING_ONLY = "polling_only"
    HYBRID = "hybrid"  # ZMQ primary, polling fallback


class ConfirmationStatus(Enum):
    """Status of transaction confirmation."""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    REPLACED = "replaced"
    REORGANIZED = "reorganized"
    EXPIRED = "expired"


class ReorgEvent(Enum):
    """Types of blockchain reorganization events."""
    FORK_DETECTED = "fork_detected"
    BLOCK_REVERTED = "block_reverted"
    TRANSACTION_UNCONFIRMED = "transaction_unconfirmed"
    CHAIN_RESTORED = "chain_restored"


@dataclass
class MonitoredTransaction:
    """Represents a transaction being monitored for confirmations."""
    txid: str
    required_confirmations: int
    added_at: datetime
    last_checked: datetime
    current_confirmations: int = 0
    status: ConfirmationStatus = ConfirmationStatus.PENDING
    confirmed_at_height: Optional[int] = None
    confirmed_at_time: Optional[datetime] = None
    block_hash: Optional[str] = None
    callback: Optional[Callable[['MonitoredTransaction'], None]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize additional fields."""
        if not self.last_checked:
            self.last_checked = self.added_at
    
    def is_confirmed(self) -> bool:
        """Check if transaction has sufficient confirmations."""
        return (self.status == ConfirmationStatus.CONFIRMED and 
                self.current_confirmations >= self.required_confirmations)
    
    def get_age_seconds(self) -> float:
        """Get age of monitoring in seconds."""
        return (datetime.now(timezone.utc) - self.added_at).total_seconds()
    
    def get_progress(self) -> float:
        """Get confirmation progress as ratio (0.0 to 1.0)."""
        if self.required_confirmations <= 0:
            return 1.0
        return min(1.0, self.current_confirmations / self.required_confirmations)


@dataclass
class ReorganizationEvent:
    """Represents a blockchain reorganization event."""
    event_type: ReorgEvent
    timestamp: datetime
    old_height: Optional[int] = None
    new_height: Optional[int] = None
    old_block_hash: Optional[str] = None
    new_block_hash: Optional[str] = None
    affected_transactions: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitorConfig:
    """Configuration for confirmation monitoring."""
    zmq_address: str = "tcp://127.0.0.1:28332"
    zmq_topics: List[str] = field(default_factory=lambda: ["hashblock", "rawtx"])
    polling_interval_seconds: int = 30
    default_confirmations: int = 6
    max_monitoring_hours: int = 48
    reorg_detection_depth: int = 10
    batch_size: int = 100
    enable_zmq: bool = True
    enable_polling: bool = True
    monitoring_method: MonitoringMethod = MonitoringMethod.HYBRID


class ConfirmationMonitor:
    """
    Comprehensive transaction confirmation monitor with ZMQ and polling support.
    """
    
    def __init__(
        self,
        rpc_client: BitcoinRPCClient,
        config: Optional[MonitorConfig] = None
    ):
        """
        Initialize confirmation monitor.
        
        Args:
            rpc_client: Bitcoin RPC client
            config: Monitoring configuration
        """
        self.rpc_client = rpc_client
        self.config = config or MonitorConfig()
        self.logger = logging.getLogger(__name__)
        
        # Monitored transactions
        self._monitored_txs: Dict[str, MonitoredTransaction] = {}
        self._tx_lock = threading.RLock()
        
        # Block tracking for reorganization detection
        self._recent_blocks: deque = deque(maxlen=self.config.reorg_detection_depth)
        self._current_height = 0
        self._block_lock = threading.RLock()
        
        # ZMQ support
        self._zmq_context = None
        self._zmq_socket = None
        self._zmq_running = False
        self._zmq_thread = None
        
        # Polling support
        self._polling_running = False
        self._polling_thread = None
        
        # Event callbacks
        self._confirmation_callbacks: List[Callable[[MonitoredTransaction], None]] = []
        self._reorg_callbacks: List[Callable[[ReorganizationEvent], None]] = []
        
        # Statistics
        self._stats = {
            "total_monitored": 0,
            "confirmed_transactions": 0,
            "failed_transactions": 0,
            "reorganizations_detected": 0,
            "avg_confirmation_time": 0.0,
            "zmq_messages_received": 0,
            "polling_cycles": 0
        }
        self._stats_lock = threading.Lock()
        
        # Initialize based on configuration
        if self.config.enable_zmq and ZMQ_AVAILABLE:
            self._setup_zmq()
        elif self.config.enable_zmq and not ZMQ_AVAILABLE:
            self.logger.warning("ZMQ not available, falling back to polling only")
            self.config.monitoring_method = MonitoringMethod.POLLING_ONLY
    
    def add_transaction(
        self,
        txid: str,
        required_confirmations: Optional[int] = None,
        callback: Optional[Callable[[MonitoredTransaction], None]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Add transaction to monitoring.
        
        Args:
            txid: Transaction ID to monitor
            required_confirmations: Number of confirmations required
            callback: Callback for confirmation events
            metadata: Additional metadata
            
        Returns:
            True if successfully added
        """
        if not txid or len(txid) != 64:
            raise ValueError(f"Invalid transaction ID: {txid}")
        
        required_confirmations = required_confirmations or self.config.default_confirmations
        
        with self._tx_lock:
            if txid in self._monitored_txs:
                self.logger.warning(f"Transaction {txid} already being monitored")
                return False
            
            # Create monitored transaction
            monitored_tx = MonitoredTransaction(
                txid=txid,
                required_confirmations=required_confirmations,
                added_at=datetime.now(timezone.utc),
                last_checked=datetime.now(timezone.utc),
                callback=callback,
                metadata=metadata or {}
            )
            
            # Get initial confirmation status
            self._update_transaction_status(monitored_tx)
            
            self._monitored_txs[txid] = monitored_tx
            
            with self._stats_lock:
                self._stats["total_monitored"] += 1
            
            self.logger.info(f"Added transaction {txid} to monitoring (requires {required_confirmations} confirmations)")
            return True
    
    def remove_transaction(self, txid: str) -> bool:
        """
        Remove transaction from monitoring.
        
        Args:
            txid: Transaction ID to remove
            
        Returns:
            True if transaction was being monitored
        """
        with self._tx_lock:
            if txid in self._monitored_txs:
                del self._monitored_txs[txid]
                self.logger.info(f"Removed transaction {txid} from monitoring")
                return True
            return False
    
    def get_transaction_status(self, txid: str) -> Optional[MonitoredTransaction]:
        """
        Get current status of a monitored transaction.
        
        Args:
            txid: Transaction ID
            
        Returns:
            MonitoredTransaction if found, None otherwise
        """
        with self._tx_lock:
            return self._monitored_txs.get(txid)
    
    def get_all_transactions(self) -> List[MonitoredTransaction]:
        """Get all monitored transactions."""
        with self._tx_lock:
            return list(self._monitored_txs.values())
    
    def add_confirmation_callback(self, callback: Callable[[MonitoredTransaction], None]):
        """Add callback for confirmation events."""
        self._confirmation_callbacks.append(callback)
    
    def add_reorg_callback(self, callback: Callable[[ReorganizationEvent], None]):
        """Add callback for reorganization events."""
        self._reorg_callbacks.append(callback)
    
    def start(self):
        """Start monitoring services."""
        self.logger.info(f"Starting confirmation monitor (method: {self.config.monitoring_method.value})")
        
        # Update current block height
        try:
            self._current_height = self.rpc_client.getblockcount()
            self._update_recent_blocks()
        except Exception as e:
            self.logger.error(f"Failed to initialize block height: {e}")
        
        # Start ZMQ if enabled and available
        if (self.config.monitoring_method in [MonitoringMethod.ZMQ_ONLY, MonitoringMethod.HYBRID] 
            and ZMQ_AVAILABLE and self._zmq_context):
            self._start_zmq_monitoring()
        
        # Start polling if enabled
        if (self.config.monitoring_method in [MonitoringMethod.POLLING_ONLY, MonitoringMethod.HYBRID] 
            or not self._zmq_running):
            self._start_polling()
    
    def stop(self):
        """Stop all monitoring services."""
        self.logger.info("Stopping confirmation monitor")
        
        # Stop ZMQ
        self._stop_zmq_monitoring()
        
        # Stop polling
        self._stop_polling()
        
        # Clean up ZMQ
        if self._zmq_context:
            self._zmq_context.term()
    
    def cleanup_old_transactions(self, max_age_hours: Optional[int] = None) -> int:
        """
        Clean up old monitored transactions.
        
        Args:
            max_age_hours: Maximum age in hours (uses config default if None)
            
        Returns:
            Number of transactions cleaned up
        """
        max_age_hours = max_age_hours or self.config.max_monitoring_hours
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        
        removed_count = 0
        with self._tx_lock:
            expired_txids = []
            
            for txid, tx in self._monitored_txs.items():
                if tx.added_at < cutoff_time or tx.status in [
                    ConfirmationStatus.CONFIRMED,
                    ConfirmationStatus.FAILED,
                    ConfirmationStatus.EXPIRED
                ]:
                    expired_txids.append(txid)
            
            for txid in expired_txids:
                del self._monitored_txs[txid]
                removed_count += 1
        
        if removed_count > 0:
            self.logger.info(f"Cleaned up {removed_count} old monitored transactions")
        
        return removed_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        with self._stats_lock:
            stats = self._stats.copy()
        
        with self._tx_lock:
            pending_count = len([tx for tx in self._monitored_txs.values() 
                               if tx.status == ConfirmationStatus.PENDING])
            confirmed_count = len([tx for tx in self._monitored_txs.values() 
                                 if tx.is_confirmed()])
        
        return {
            **stats,
            "currently_monitored": len(self._monitored_txs),
            "pending_transactions": pending_count,
            "confirmed_ready": confirmed_count,
            "zmq_enabled": self._zmq_running,
            "polling_enabled": self._polling_running,
            "current_block_height": self._current_height,
            "recent_blocks_tracked": len(self._recent_blocks)
        }
    
    def estimate_confirmation_time(self, txid: str) -> Optional[timedelta]:
        """
        Estimate time until transaction is fully confirmed.
        
        Args:
            txid: Transaction ID
            
        Returns:
            Estimated time or None if not found
        """
        tx = self.get_transaction_status(txid)
        if not tx:
            return None
        
        if tx.is_confirmed():
            return timedelta(0)
        
        remaining_confirmations = max(0, tx.required_confirmations - tx.current_confirmations)
        
        # Estimate 10 minutes per block (Bitcoin average)
        estimated_minutes = remaining_confirmations * 10
        return timedelta(minutes=estimated_minutes)
    
    def _setup_zmq(self):
        """Set up ZMQ connection."""
        if not ZMQ_AVAILABLE:
            return
        
        try:
            self._zmq_context = zmq.Context()
            self._zmq_socket = self._zmq_context.socket(zmq.SUB)
            
            # Subscribe to configured topics
            for topic in self.config.zmq_topics:
                self._zmq_socket.setsockopt_string(zmq.SUBSCRIBE, topic)
            
            # Set socket options
            self._zmq_socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 second timeout
            
            self.logger.info(f"ZMQ configured for {self.config.zmq_address}")
            
        except Exception as e:
            self.logger.error(f"Failed to setup ZMQ: {e}")
            self._zmq_context = None
            self._zmq_socket = None
    
    def _start_zmq_monitoring(self):
        """Start ZMQ monitoring thread."""
        if not self._zmq_socket:
            return
        
        try:
            self._zmq_socket.connect(self.config.zmq_address)
            self._zmq_running = True
            self._zmq_thread = threading.Thread(target=self._zmq_worker, daemon=True)
            self._zmq_thread.start()
            self.logger.info("ZMQ monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start ZMQ monitoring: {e}")
            self._zmq_running = False
    
    def _stop_zmq_monitoring(self):
        """Stop ZMQ monitoring."""
        self._zmq_running = False
        if self._zmq_thread:
            self._zmq_thread.join(timeout=2.0)
        
        if self._zmq_socket:
            self._zmq_socket.close()
    
    def _zmq_worker(self):
        """ZMQ message processing worker."""
        self.logger.info("ZMQ worker thread started")
        
        while self._zmq_running:
            try:
                if not self._zmq_socket:
                    break
                
                # Receive message with timeout
                try:
                    topic = self._zmq_socket.recv_string(zmq.NOBLOCK)
                    data = self._zmq_socket.recv(zmq.NOBLOCK)
                    
                    with self._stats_lock:
                        self._stats["zmq_messages_received"] += 1
                    
                    # Process different message types
                    if topic == "hashblock":
                        self._process_block_message(data)
                    elif topic == "rawtx":
                        self._process_transaction_message(data)
                    
                except zmq.Again:
                    # No message available, continue
                    time.sleep(0.1)
                    continue
                    
            except Exception as e:
                if self._zmq_running:
                    self.logger.error(f"ZMQ worker error: {e}")
                    time.sleep(1.0)
        
        self.logger.info("ZMQ worker thread stopped")
    
    def _process_block_message(self, block_hash_bytes: bytes):
        """Process new block message from ZMQ."""
        block_hash = block_hash_bytes.hex()
        
        try:
            # Get block info
            block_info = self.rpc_client.getblock(block_hash, 1)
            new_height = block_info.get('height', 0)
            
            self.logger.debug(f"New block: {block_hash} (height: {new_height})")
            
            # Check for reorganization
            self._check_for_reorganization(new_height, block_hash, block_info)
            
            # Update monitored transactions
            self._update_all_transactions()
            
        except Exception as e:
            self.logger.error(f"Failed to process block message: {e}")
    
    def _process_transaction_message(self, tx_data: bytes):
        """Process new transaction message from ZMQ."""
        try:
            # Parse transaction (this is raw transaction data)
            tx_hex = tx_data.hex()
            
            # We could decode the transaction to get the TXID,
            # but for now we'll let the polling handle transaction updates
            self.logger.debug(f"New transaction received via ZMQ: {len(tx_hex)} bytes")
            
        except Exception as e:
            self.logger.error(f"Failed to process transaction message: {e}")
    
    def _start_polling(self):
        """Start polling thread."""
        if self._polling_running:
            return
        
        self._polling_running = True
        self._polling_thread = threading.Thread(target=self._polling_worker, daemon=True)
        self._polling_thread.start()
        self.logger.info(f"Polling monitoring started (interval: {self.config.polling_interval_seconds}s)")
    
    def _stop_polling(self):
        """Stop polling thread."""
        self._polling_running = False
        if self._polling_thread:
            self._polling_thread.join(timeout=self.config.polling_interval_seconds + 1)
    
    def _polling_worker(self):
        """Polling worker thread."""
        self.logger.info("Polling worker thread started")
        
        while self._polling_running:
            try:
                start_time = time.time()
                
                # Update block height and check for reorgs
                self._update_block_height()
                
                # Update all monitored transactions
                self._update_all_transactions()
                
                # Clean up old transactions
                self.cleanup_old_transactions()
                
                with self._stats_lock:
                    self._stats["polling_cycles"] += 1
                
                # Sleep for remaining time
                elapsed = time.time() - start_time
                sleep_time = max(0.1, self.config.polling_interval_seconds - elapsed)
                
                for _ in range(int(sleep_time * 10)):  # Check every 0.1s for shutdown
                    if not self._polling_running:
                        break
                    time.sleep(0.1)
                
            except Exception as e:
                if self._polling_running:
                    self.logger.error(f"Polling worker error: {e}")
                    time.sleep(5.0)
        
        self.logger.info("Polling worker thread stopped")
    
    def _update_block_height(self):
        """Update current block height and detect reorganizations."""
        try:
            new_height = self.rpc_client.getblockcount()
            
            with self._block_lock:
                if new_height > self._current_height:
                    # New blocks found
                    for height in range(self._current_height + 1, new_height + 1):
                        try:
                            block_hash = self.rpc_client.getblockhash(height)
                            block_info = self.rpc_client.getblock(block_hash, 1)
                            
                            self._check_for_reorganization(height, block_hash, block_info)
                            
                        except Exception as e:
                            self.logger.error(f"Failed to get block at height {height}: {e}")
                    
                    self._current_height = new_height
                    
                elif new_height < self._current_height:
                    # Potential reorganization (height decreased)
                    self.logger.warning(f"Block height decreased: {self._current_height} -> {new_height}")
                    self._handle_reorganization(new_height)
                    self._current_height = new_height
            
        except Exception as e:
            self.logger.error(f"Failed to update block height: {e}")
    
    def _check_for_reorganization(self, height: int, block_hash: str, block_info: Dict[str, Any]):
        """Check for blockchain reorganization."""
        with self._block_lock:
            # Add to recent blocks
            self._recent_blocks.append({
                'height': height,
                'hash': block_hash,
                'timestamp': block_info.get('time', int(time.time()))
            })
            
            # Check if we have a previous block at this height
            existing_blocks = [b for b in self._recent_blocks if b['height'] == height]
            
            if len(existing_blocks) > 1:
                # Multiple blocks at same height = reorganization
                old_block = existing_blocks[0]
                
                if old_block['hash'] != block_hash:
                    self.logger.warning(f"Reorganization detected at height {height}: {old_block['hash']} -> {block_hash}")
                    
                    reorg_event = ReorganizationEvent(
                        event_type=ReorgEvent.FORK_DETECTED,
                        timestamp=datetime.now(timezone.utc),
                        old_height=height,
                        new_height=height,
                        old_block_hash=old_block['hash'],
                        new_block_hash=block_hash
                    )
                    
                    self._handle_reorganization_event(reorg_event)
    
    def _handle_reorganization(self, new_height: int):
        """Handle blockchain reorganization."""
        with self._stats_lock:
            self._stats["reorganizations_detected"] += 1
        
        # Update recent blocks
        self._update_recent_blocks()
        
        # Check all monitored transactions for reorganization effects
        affected_txids = []
        
        with self._tx_lock:
            for txid, tx in self._monitored_txs.items():
                if (tx.confirmed_at_height and tx.confirmed_at_height > new_height):
                    # Transaction was confirmed in a block that's now invalid
                    tx.status = ConfirmationStatus.REORGANIZED
                    tx.current_confirmations = 0
                    tx.confirmed_at_height = None
                    tx.confirmed_at_time = None
                    tx.block_hash = None
                    affected_txids.append(txid)
        
        if affected_txids:
            reorg_event = ReorganizationEvent(
                event_type=ReorgEvent.TRANSACTION_UNCONFIRMED,
                timestamp=datetime.now(timezone.utc),
                new_height=new_height,
                affected_transactions=affected_txids
            )
            
            self._handle_reorganization_event(reorg_event)
    
    def _handle_reorganization_event(self, event: ReorganizationEvent):
        """Handle reorganization event and notify callbacks."""
        self.logger.info(f"Reorganization event: {event.event_type.value}")
        
        # Notify callbacks
        for callback in self._reorg_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Reorg callback error: {e}")
    
    def _update_recent_blocks(self):
        """Update recent blocks list."""
        try:
            with self._block_lock:
                self._recent_blocks.clear()
                
                for i in range(self.config.reorg_detection_depth):
                    height = self._current_height - i
                    if height < 0:
                        break
                    
                    try:
                        block_hash = self.rpc_client.getblockhash(height)
                        block_info = self.rpc_client.getblock(block_hash, 1)
                        
                        self._recent_blocks.appendleft({
                            'height': height,
                            'hash': block_hash,
                            'timestamp': block_info.get('time', int(time.time()))
                        })
                        
                    except Exception as e:
                        self.logger.error(f"Failed to get block at height {height}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Failed to update recent blocks: {e}")
    
    def _update_all_transactions(self):
        """Update status of all monitored transactions."""
        with self._tx_lock:
            txids_to_update = list(self._monitored_txs.keys())
        
        # Process in batches to avoid overwhelming RPC
        batch_size = self.config.batch_size
        for i in range(0, len(txids_to_update), batch_size):
            batch = txids_to_update[i:i + batch_size]
            
            for txid in batch:
                with self._tx_lock:
                    tx = self._monitored_txs.get(txid)
                    if tx and tx.status == ConfirmationStatus.PENDING:
                        self._update_transaction_status(tx)
            
            # Small delay between batches
            if len(batch) == batch_size:
                time.sleep(0.1)
    
    def _update_transaction_status(self, tx: MonitoredTransaction):
        """Update status of a single monitored transaction."""
        try:
            # Get transaction info
            try:
                raw_tx = self.rpc_client.getrawtransaction(tx.txid, True)
                
                confirmations = raw_tx.get('confirmations', 0)
                tx.current_confirmations = max(0, confirmations)
                tx.last_checked = datetime.now(timezone.utc)
                
                if confirmations > 0:
                    # Transaction is confirmed
                    if not tx.confirmed_at_time:
                        tx.confirmed_at_time = datetime.now(timezone.utc)
                    
                    tx.confirmed_at_height = self._current_height - confirmations + 1
                    tx.block_hash = raw_tx.get('blockhash')
                    
                    if confirmations >= tx.required_confirmations:
                        old_status = tx.status
                        tx.status = ConfirmationStatus.CONFIRMED
                        
                        if old_status != ConfirmationStatus.CONFIRMED:
                            self._notify_confirmation(tx)
                            
                            with self._stats_lock:
                                self._stats["confirmed_transactions"] += 1
                                
                                # Update average confirmation time
                                if tx.confirmed_at_time:
                                    conf_time = (tx.confirmed_at_time - tx.added_at).total_seconds()
                                    total_confirmed = self._stats["confirmed_transactions"]
                                    current_avg = self._stats["avg_confirmation_time"]
                                    self._stats["avg_confirmation_time"] = (
                                        (current_avg * (total_confirmed - 1) + conf_time) / total_confirmed
                                    )
                    
                else:
                    # Transaction not yet confirmed
                    tx.status = ConfirmationStatus.PENDING
                    tx.confirmed_at_height = None
                    tx.confirmed_at_time = None
                    tx.block_hash = None
                
            except RPCError as e:
                if e.code == -5:  # Transaction not found
                    # Check if transaction was replaced or failed
                    try:
                        # Try to get mempool entry
                        mempool_entry = self.rpc_client.getmempoolentry(tx.txid)
                        tx.status = ConfirmationStatus.PENDING
                    except RPCError:
                        # Not in mempool either - likely failed or replaced
                        tx.status = ConfirmationStatus.FAILED
                        
                        with self._stats_lock:
                            self._stats["failed_transactions"] += 1
                else:
                    raise
            
        except Exception as e:
            self.logger.error(f"Failed to update transaction {tx.txid}: {e}")
    
    def _notify_confirmation(self, tx: MonitoredTransaction):
        """Notify about transaction confirmation."""
        self.logger.info(f"Transaction {tx.txid} confirmed with {tx.current_confirmations} confirmations")
        
        # Call transaction-specific callback
        if tx.callback:
            try:
                tx.callback(tx)
            except Exception as e:
                self.logger.error(f"Transaction callback error for {tx.txid}: {e}")
        
        # Call global callbacks
        for callback in self._confirmation_callbacks:
            try:
                callback(tx)
            except Exception as e:
                self.logger.error(f"Confirmation callback error: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


# Convenience functions

def create_monitor(
    host: str = "localhost",
    port: int = 8332,
    username: str = "rpc",
    password: str = "rpc",
    zmq_address: str = "tcp://127.0.0.1:28332",
    default_confirmations: int = 6
) -> ConfirmationMonitor:
    """Create a confirmation monitor with custom configuration."""
    rpc_config = RPCConfig(
        host=host,
        port=port,
        username=username,
        password=password
    )
    
    monitor_config = MonitorConfig(
        zmq_address=zmq_address,
        default_confirmations=default_confirmations
    )
    
    rpc_client = BitcoinRPCClient(rpc_config)
    return ConfirmationMonitor(rpc_client, monitor_config)


# Testing and CLI interface

def test_monitor():
    """Test the confirmation monitor."""
    print("Testing Confirmation Monitor...")
    print("=" * 50)
    
    try:
        # Create monitor
        monitor = create_monitor()
        
        # Test connection
        if not monitor.rpc_client.test_connection():
            print("✗ Cannot connect to Bitcoin Core")
            return False
        
        print("✓ Connected to Bitcoin Core")
        
        # Start monitor
        monitor.start()
        print("✓ Monitor started")
        
        # Test statistics
        stats = monitor.get_statistics()
        print(f"✓ Statistics: {stats['currently_monitored']} transactions monitored")
        print(f"✓ Current height: {stats['current_block_height']}")
        print(f"✓ ZMQ enabled: {stats['zmq_enabled']}")
        print(f"✓ Polling enabled: {stats['polling_enabled']}")
        
        # Test cleanup
        cleaned = monitor.cleanup_old_transactions(1)  # Clean transactions older than 1 hour
        print(f"✓ Cleaned up {cleaned} old transactions")
        
        # Stop monitor
        monitor.stop()
        print("✓ Monitor stopped")
        
        print("\nConfirmation monitor test completed successfully!")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False


if __name__ == "__main__":
    import sys
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        success = test_monitor()
        sys.exit(0 if success else 1)
    
    else:
        print("Bitcoin Transaction Confirmation Monitor")
        print("Usage: python monitor.py test")
        print("\nFeatures:")
        print("- ZMQ subscription for real-time updates")
        print("- Polling fallback for reliability")
        print("- Blockchain reorganization detection")
        print("- Configurable confirmation thresholds")
        print("- Batch monitoring support")
        print("- Event callbacks and notifications")