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
import statistics

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


class MempoolEventType(Enum):
    """Types of mempool events."""
    TRANSACTION_ADDED = "transaction_added"
    TRANSACTION_REMOVED = "transaction_removed"
    TRANSACTION_REPLACED = "transaction_replaced"
    TRANSACTION_CONFLICTED = "transaction_conflicted"
    FEE_BUMP = "fee_bump"
    MEMPOOL_FULL = "mempool_full"


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
class MempoolTransaction:
    """Represents a transaction in the mempool."""
    txid: str
    size: int
    vsize: int
    weight: int
    fee: float
    fee_rate: float
    first_seen: datetime
    last_seen: datetime
    depends: List[str] = field(default_factory=list)
    spent_by: List[str] = field(default_factory=list)
    ancestors: int = 0
    descendants: int = 0
    ancestor_size: int = 0
    descendant_size: int = 0
    ancestor_fees: float = 0.0
    descendant_fees: float = 0.0
    bip125_replaceable: bool = False
    raw_transaction: Optional[str] = None
    
    def __post_init__(self):
        """Initialize additional fields."""
        if not self.last_seen:
            self.last_seen = self.first_seen


@dataclass
class MempoolEvent:
    """Represents a mempool event."""
    event_type: MempoolEventType
    timestamp: datetime
    txid: str
    transaction: Optional[MempoolTransaction] = None
    replaced_txid: Optional[str] = None
    conflicted_txids: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MempoolStats:
    """Statistics about mempool state."""
    size: int = 0
    bytes: int = 0
    usage: int = 0
    max_mempool: int = 0
    mempool_min_fee: float = 0.0
    min_relay_tx_fee: float = 0.0
    total_fees: float = 0.0
    avg_fee_rate: float = 0.0
    median_fee_rate: float = 0.0
    min_fee_rate: float = 0.0
    max_fee_rate: float = 0.0
    unbroadcast_count: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


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


class MempoolMonitor:
    """
    Comprehensive mempool monitor for tracking pending transactions and detecting conflicts.
    """
    
    def __init__(
        self,
        rpc_client: BitcoinRPCClient,
        config: Optional[MonitorConfig] = None
    ):
        """
        Initialize mempool monitor.
        
        Args:
            rpc_client: Bitcoin RPC client
            config: Monitoring configuration
        """
        self.rpc_client = rpc_client
        self.config = config or MonitorConfig()
        self.logger = logging.getLogger(__name__)
        
        # Mempool state
        self._mempool_txs: Dict[str, MempoolTransaction] = {}
        self._mempool_lock = threading.RLock()
        
        # Address and asset filtering
        self._watched_addresses: Set[str] = set()
        self._watched_assets: Set[str] = set()
        self._filter_lock = threading.RLock()
        
        # Conflict detection
        self._input_spending: Dict[str, str] = {}  # input_id -> txid
        self._conflicts: Dict[str, List[str]] = {}  # txid -> conflicted_txids
        
        # Event callbacks
        self._event_callbacks: List[Callable[[MempoolEvent], None]] = []
        self._stats_callbacks: List[Callable[[MempoolStats], None]] = []
        
        # Monitoring state
        self._monitoring_enabled = False
        self._monitoring_thread = None
        
        # Statistics
        self._current_stats = MempoolStats()
        self._historical_stats: deque = deque(maxlen=1000)  # Keep last 1000 stat snapshots
        self._stats_lock = threading.Lock()
        
        # Performance tracking
        self._last_update_time = None
        self._update_count = 0
    
    def add_watched_address(self, address: str):
        """Add address to watch for mempool events."""
        with self._filter_lock:
            self._watched_addresses.add(address.strip().lower())
        self.logger.info(f"Added watched address: {address}")
    
    def remove_watched_address(self, address: str):
        """Remove address from watch list."""
        with self._filter_lock:
            self._watched_addresses.discard(address.strip().lower())
        self.logger.info(f"Removed watched address: {address}")
    
    def add_watched_asset(self, asset_id: str):
        """Add asset ID to watch for mempool events."""
        with self._filter_lock:
            self._watched_assets.add(asset_id)
        self.logger.info(f"Added watched asset: {asset_id}")
    
    def remove_watched_asset(self, asset_id: str):
        """Remove asset ID from watch list."""
        with self._filter_lock:
            self._watched_assets.discard(asset_id)
        self.logger.info(f"Removed watched asset: {asset_id}")
    
    def add_event_callback(self, callback: Callable[[MempoolEvent], None]):
        """Add callback for mempool events."""
        self._event_callbacks.append(callback)
    
    def add_stats_callback(self, callback: Callable[[MempoolStats], None]):
        """Add callback for mempool statistics updates."""
        self._stats_callbacks.append(callback)
    
    def start(self):
        """Start mempool monitoring."""
        if self._monitoring_enabled:
            return
        
        self._monitoring_enabled = True
        self._monitoring_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self._monitoring_thread.start()
        
        self.logger.info("Mempool monitoring started")
    
    def stop(self):
        """Stop mempool monitoring."""
        self._monitoring_enabled = False
        
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5.0)
        
        self.logger.info("Mempool monitoring stopped")
    
    def get_mempool_transaction(self, txid: str) -> Optional[MempoolTransaction]:
        """Get mempool transaction by TXID."""
        with self._mempool_lock:
            return self._mempool_txs.get(txid)
    
    def get_all_mempool_transactions(self) -> List[MempoolTransaction]:
        """Get all current mempool transactions."""
        with self._mempool_lock:
            return list(self._mempool_txs.values())
    
    def get_transactions_by_fee_rate(self, min_fee_rate: float, max_fee_rate: Optional[float] = None) -> List[MempoolTransaction]:
        """Get transactions within fee rate range."""
        with self._mempool_lock:
            transactions = []
            for tx in self._mempool_txs.values():
                if tx.fee_rate >= min_fee_rate:
                    if max_fee_rate is None or tx.fee_rate <= max_fee_rate:
                        transactions.append(tx)
            return sorted(transactions, key=lambda t: t.fee_rate, reverse=True)
    
    def get_conflicts(self, txid: str) -> List[str]:
        """Get conflicting transaction IDs for given TXID."""
        return self._conflicts.get(txid, [])
    
    def get_current_stats(self) -> MempoolStats:
        """Get current mempool statistics."""
        with self._stats_lock:
            return self._current_stats
    
    def get_historical_stats(self, hours: int = 1) -> List[MempoolStats]:
        """Get historical mempool statistics for the last N hours."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        with self._stats_lock:
            return [
                stats for stats in self._historical_stats 
                if stats.timestamp >= cutoff_time
            ]
    
    def estimate_confirmation_probability(self, fee_rate: float) -> float:
        """
        Estimate probability of confirmation in next block based on current mempool.
        
        Args:
            fee_rate: Fee rate in sat/vB
            
        Returns:
            Probability between 0.0 and 1.0
        """
        with self._mempool_lock:
            if not self._mempool_txs:
                return 1.0
            
            # Calculate percentile of this fee rate
            all_fee_rates = [tx.fee_rate for tx in self._mempool_txs.values()]
            all_fee_rates.sort(reverse=True)
            
            # Find position in sorted list
            position = len(all_fee_rates)
            for i, rate in enumerate(all_fee_rates):
                if fee_rate >= rate:
                    position = i
                    break
            
            # Estimate based on position (assuming ~1MB blocks)
            block_capacity_vbytes = 1_000_000  # Approximate
            total_vbytes = sum(tx.vsize for tx in self._mempool_txs.values())
            
            if total_vbytes <= block_capacity_vbytes:
                return 1.0
            
            # Calculate cumulative vbytes up to this fee rate
            cumulative_vbytes = 0
            for rate in all_fee_rates:
                if rate < fee_rate:
                    break
                # Find transactions with this rate
                for tx in self._mempool_txs.values():
                    if tx.fee_rate == rate:
                        cumulative_vbytes += tx.vsize
            
            return min(1.0, block_capacity_vbytes / max(1, cumulative_vbytes))
    
    def _monitoring_worker(self):
        """Main monitoring worker thread."""
        self.logger.info("Mempool monitoring worker started")
        
        while self._monitoring_enabled:
            try:
                start_time = time.time()
                
                # Update mempool state
                self._update_mempool_state()
                
                # Update statistics
                self._update_statistics()
                
                self._update_count += 1
                self._last_update_time = datetime.now(timezone.utc)
                
                # Sleep for remaining time
                elapsed = time.time() - start_time
                sleep_time = max(0.1, self.config.polling_interval_seconds - elapsed)
                
                for _ in range(int(sleep_time * 10)):
                    if not self._monitoring_enabled:
                        break
                    time.sleep(0.1)
                
            except Exception as e:
                if self._monitoring_enabled:
                    self.logger.error(f"Mempool monitoring error: {e}")
                    time.sleep(5.0)
        
        self.logger.info("Mempool monitoring worker stopped")
    
    def _update_mempool_state(self):
        """Update current mempool state."""
        try:
            # Get current mempool
            current_mempool = self.rpc_client.getrawmempool(verbose=True)
            current_txids = set(current_mempool.keys())
            
            with self._mempool_lock:
                previous_txids = set(self._mempool_txs.keys())
                
                # Find new transactions
                new_txids = current_txids - previous_txids
                
                # Find removed transactions
                removed_txids = previous_txids - current_txids
                
                # Process new transactions
                for txid in new_txids:
                    tx_info = current_mempool.get(txid)
                    if tx_info:
                        mempool_tx = self._create_mempool_transaction(txid, tx_info)
                        self._mempool_txs[txid] = mempool_tx
                        
                        # Check for conflicts
                        self._check_for_conflicts(mempool_tx)
                        
                        # Emit event
                        if self._should_track_transaction(mempool_tx):
                            event = MempoolEvent(
                                event_type=MempoolEventType.TRANSACTION_ADDED,
                                timestamp=datetime.now(timezone.utc),
                                txid=txid,
                                transaction=mempool_tx
                            )
                            self._emit_event(event)
                
                # Process removed transactions
                for txid in removed_txids:
                    removed_tx = self._mempool_txs.pop(txid, None)
                    if removed_tx:
                        # Clean up conflict tracking
                        self._cleanup_conflicts(txid)
                        
                        # Emit event
                        if self._should_track_transaction(removed_tx):
                            event = MempoolEvent(
                                event_type=MempoolEventType.TRANSACTION_REMOVED,
                                timestamp=datetime.now(timezone.utc),
                                txid=txid,
                                transaction=removed_tx
                            )
                            self._emit_event(event)
                
                # Update existing transactions
                for txid in current_txids.intersection(previous_txids):
                    tx_info = current_mempool.get(txid)
                    if tx_info and txid in self._mempool_txs:
                        old_tx = self._mempool_txs[txid]
                        new_tx = self._create_mempool_transaction(txid, tx_info)
                        new_tx.first_seen = old_tx.first_seen  # Preserve original timestamp
                        
                        # Check for fee bumps (RBF)
                        if new_tx.fee > old_tx.fee:
                            event = MempoolEvent(
                                event_type=MempoolEventType.FEE_BUMP,
                                timestamp=datetime.now(timezone.utc),
                                txid=txid,
                                transaction=new_tx,
                                details={
                                    'old_fee': old_tx.fee,
                                    'new_fee': new_tx.fee,
                                    'fee_increase': new_tx.fee - old_tx.fee
                                }
                            )
                            if self._should_track_transaction(new_tx):
                                self._emit_event(event)
                        
                        self._mempool_txs[txid] = new_tx
                
        except Exception as e:
            self.logger.error(f"Failed to update mempool state: {e}")
    
    def _create_mempool_transaction(self, txid: str, tx_info: Dict[str, Any]) -> MempoolTransaction:
        """Create MempoolTransaction from RPC data."""
        now = datetime.now(timezone.utc)
        
        return MempoolTransaction(
            txid=txid,
            size=tx_info.get('size', 0),
            vsize=tx_info.get('vsize', 0),
            weight=tx_info.get('weight', 0),
            fee=tx_info.get('fee', 0.0),
            fee_rate=tx_info.get('fee', 0.0) / max(1, tx_info.get('vsize', 1)) * 100_000_000,  # sat/vB
            first_seen=now,
            last_seen=now,
            depends=tx_info.get('depends', []),
            spent_by=tx_info.get('spentby', []),
            ancestors=tx_info.get('ancestorcount', 0),
            descendants=tx_info.get('descendantcount', 0),
            ancestor_size=tx_info.get('ancestorsize', 0),
            descendant_size=tx_info.get('descendantsize', 0),
            ancestor_fees=tx_info.get('ancestorfees', 0.0),
            descendant_fees=tx_info.get('descendantfees', 0.0),
            bip125_replaceable=tx_info.get('bip125-replaceable', False)
        )
    
    def _check_for_conflicts(self, tx: MempoolTransaction):
        """Check for transaction conflicts based on spent inputs."""
        try:
            # Get raw transaction to analyze inputs
            raw_tx = self.rpc_client.getrawtransaction(tx.txid, True)
            
            conflicts = []
            
            # Check each input
            for vin in raw_tx.get('vin', []):
                if 'txid' in vin and 'vout' in vin:
                    input_id = f"{vin['txid']}:{vin['vout']}"
                    
                    # Check if this input is already being spent
                    if input_id in self._input_spending:
                        existing_txid = self._input_spending[input_id]
                        if existing_txid != tx.txid:
                            conflicts.append(existing_txid)
                    else:
                        self._input_spending[input_id] = tx.txid
            
            # Record conflicts
            if conflicts:
                self._conflicts[tx.txid] = conflicts
                
                # Emit conflict event
                event = MempoolEvent(
                    event_type=MempoolEventType.TRANSACTION_CONFLICTED,
                    timestamp=datetime.now(timezone.utc),
                    txid=tx.txid,
                    transaction=tx,
                    conflicted_txids=conflicts
                )
                self._emit_event(event)
                
                self.logger.warning(f"Transaction {tx.txid} conflicts with {conflicts}")
            
        except Exception as e:
            self.logger.error(f"Failed to check conflicts for {tx.txid}: {e}")
    
    def _cleanup_conflicts(self, txid: str):
        """Clean up conflict tracking for removed transaction."""
        # Remove from conflicts
        self._conflicts.pop(txid, None)
        
        # Remove from input spending tracking
        inputs_to_remove = [
            input_id for input_id, spending_txid in self._input_spending.items()
            if spending_txid == txid
        ]
        
        for input_id in inputs_to_remove:
            del self._input_spending[input_id]
    
    def _should_track_transaction(self, tx: MempoolTransaction) -> bool:
        """Check if transaction should be tracked based on filters."""
        with self._filter_lock:
            # If no filters set, track all transactions
            if not self._watched_addresses and not self._watched_assets:
                return True
            
            # Check address filters (would need to decode transaction to get addresses)
            # For now, we'll track all transactions when address filters are set
            if self._watched_addresses:
                return True  # Simplified - would need full transaction decoding
            
            # Check asset filters (would need to parse BNAP protocol data)
            if self._watched_assets:
                return True  # Simplified - would need BNAP protocol parsing
            
            return False
    
    def _update_statistics(self):
        """Update mempool statistics."""
        try:
            # Get basic mempool info
            mempool_info = self.rpc_client.getmempoolinfo()
            
            # Calculate additional statistics
            with self._mempool_lock:
                all_fees = [tx.fee_rate for tx in self._mempool_txs.values() if tx.fee_rate > 0]
                
                stats = MempoolStats(
                    size=mempool_info.get('size', 0),
                    bytes=mempool_info.get('bytes', 0),
                    usage=mempool_info.get('usage', 0),
                    max_mempool=mempool_info.get('maxmempool', 0),
                    mempool_min_fee=mempool_info.get('mempoolminfee', 0.0),
                    min_relay_tx_fee=mempool_info.get('minrelaytxfee', 0.0),
                    total_fees=sum(tx.fee for tx in self._mempool_txs.values()),
                    unbroadcast_count=mempool_info.get('unbroadcastcount', 0)
                )
                
                if all_fees:
                    stats.avg_fee_rate = statistics.mean(all_fees)
                    stats.median_fee_rate = statistics.median(all_fees)
                    stats.min_fee_rate = min(all_fees)
                    stats.max_fee_rate = max(all_fees)
            
            with self._stats_lock:
                self._current_stats = stats
                self._historical_stats.append(stats)
            
            # Notify stats callbacks
            for callback in self._stats_callbacks:
                try:
                    callback(stats)
                except Exception as e:
                    self.logger.error(f"Stats callback error: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to update statistics: {e}")
    
    def _emit_event(self, event: MempoolEvent):
        """Emit mempool event to all callbacks."""
        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Event callback error: {e}")
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring performance statistics."""
        return {
            'monitoring_enabled': self._monitoring_enabled,
            'update_count': self._update_count,
            'last_update_time': self._last_update_time.isoformat() if self._last_update_time else None,
            'mempool_transactions': len(self._mempool_txs),
            'watched_addresses': len(self._watched_addresses),
            'watched_assets': len(self._watched_assets),
            'active_conflicts': len(self._conflicts),
            'historical_stats_count': len(self._historical_stats),
            'event_callbacks': len(self._event_callbacks),
            'stats_callbacks': len(self._stats_callbacks)
        }
    
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


def create_mempool_monitor(
    host: str = "localhost",
    port: int = 8332,
    username: str = "rpc",
    password: str = "rpc",
    polling_interval: int = 30
) -> MempoolMonitor:
    """Create a mempool monitor with custom configuration."""
    rpc_config = RPCConfig(
        host=host,
        port=port,
        username=username,
        password=password
    )
    
    monitor_config = MonitorConfig(
        polling_interval_seconds=polling_interval,
        enable_zmq=False,  # Focus on polling for mempool
        enable_polling=True
    )
    
    rpc_client = BitcoinRPCClient(rpc_config)
    return MempoolMonitor(rpc_client, monitor_config)


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


def test_mempool_monitor():
    """Test the mempool monitor."""
    print("Testing Mempool Monitor...")
    print("=" * 50)
    
    try:
        # Create mempool monitor
        mempool_monitor = create_mempool_monitor(polling_interval=10)  # Fast polling for test
        
        # Test connection
        if not mempool_monitor.rpc_client.test_connection():
            print("✗ Cannot connect to Bitcoin Core")
            return False
        
        print("✓ Connected to Bitcoin Core")
        
        # Add event callback for testing
        def event_callback(event):
            print(f"  Event: {event.event_type.value} for {event.txid[:12]}...")
        
        mempool_monitor.add_event_callback(event_callback)
        
        # Add stats callback
        def stats_callback(stats):
            print(f"  Stats: {stats.size} transactions, avg fee: {stats.avg_fee_rate:.1f} sat/vB")
        
        mempool_monitor.add_stats_callback(stats_callback)
        
        # Start monitoring
        mempool_monitor.start()
        print("✓ Mempool monitor started")
        
        # Get initial statistics
        stats = mempool_monitor.get_current_stats()
        print(f"✓ Current mempool: {stats.size} transactions")
        print(f"✓ Total bytes: {stats.bytes:,}")
        print(f"✓ Memory usage: {stats.usage:,} bytes")
        
        # Test fee rate queries
        high_fee_txs = mempool_monitor.get_transactions_by_fee_rate(10.0)  # > 10 sat/vB
        print(f"✓ High fee transactions: {len(high_fee_txs)}")
        
        # Test monitoring statistics
        monitor_stats = mempool_monitor.get_monitoring_statistics()
        print(f"✓ Monitoring stats: {monitor_stats['mempool_transactions']} tracked")
        
        # Brief monitoring period
        print("✓ Monitoring for 5 seconds...")
        time.sleep(5)
        
        # Stop monitoring
        mempool_monitor.stop()
        print("✓ Mempool monitor stopped")
        
        print("\nMempool monitor test completed successfully!")
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
        print("Bitcoin Network Monitoring System")
        print("=" * 60)
        
        # Test confirmation monitor
        success1 = test_monitor()
        
        print()  # Separator
        
        # Test mempool monitor
        success2 = test_mempool_monitor()
        
        overall_success = success1 and success2
        if overall_success:
            print("\n🎉 All monitoring tests passed!")
        else:
            print(f"\n❌ Some tests failed: Confirmation={success1}, Mempool={success2}")
        
        sys.exit(0 if overall_success else 1)
    
    elif len(sys.argv) > 1 and sys.argv[1] == "mempool":
        success = test_mempool_monitor()
        sys.exit(0 if success else 1)
    
    else:
        print("Bitcoin Network Monitoring System")
        print("Usage: python monitor.py <command>")
        print("Commands:")
        print("  test     - Run both confirmation and mempool monitoring tests")
        print("  mempool  - Run mempool monitoring test only")
        print("\nFeatures:")
        print("- ZMQ subscription for real-time updates")
        print("- Polling fallback for reliability")
        print("- Blockchain reorganization detection")
        print("- Configurable confirmation thresholds")
        print("- Batch monitoring support")
        print("- Mempool monitoring with conflict detection")
        print("- Fee rate analysis and statistics")
        print("- Event callbacks and notifications")