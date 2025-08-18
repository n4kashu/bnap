"""
Bitcoin Native Asset Protocol - Transaction Broadcasting System

This module provides robust transaction broadcasting capabilities with retry logic,
error handling, and comprehensive monitoring for Bitcoin transactions.
"""

import asyncio
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Union, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import hashlib
import json
from pathlib import Path

try:
    from .rpc import BitcoinRPCClient, RPCConfig, RPCError, RPCTimeoutError, RPCConnectionError
except ImportError:
    # For standalone testing
    from rpc import BitcoinRPCClient, RPCConfig, RPCError, RPCTimeoutError, RPCConnectionError


class BroadcastStatus(Enum):
    """Status of transaction broadcast attempts."""
    PENDING = "pending"
    BROADCASTING = "broadcasting"
    SUCCESS = "success"
    FAILED = "failed"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    ABANDONED = "abandoned"


class BroadcastPriority(Enum):
    """Priority levels for transaction broadcasting."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@dataclass
class BroadcastAttempt:
    """Represents a single broadcast attempt."""
    timestamp: datetime
    success: bool
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    response_time_ms: float = 0.0
    node_info: Optional[str] = None
    
    def __post_init__(self):
        """Initialize timestamp if not provided."""
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class BroadcastConfig:
    """Configuration for transaction broadcasting."""
    max_attempts: int = 5
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    exponential_base: float = 2.0
    jitter_factor: float = 0.1
    timeout_seconds: int = 30
    max_fee_rate: Optional[float] = None  # BTC/kB
    abandon_after_hours: int = 24
    
    def get_retry_delay(self, attempt: int) -> float:
        """Calculate retry delay for given attempt number."""
        if attempt <= 0:
            return 0.0
        
        # Exponential backoff
        delay = self.initial_delay_seconds * (self.exponential_base ** (attempt - 1))
        delay = min(delay, self.max_delay_seconds)
        
        # Add jitter
        if self.jitter_factor > 0:
            import random
            jitter = delay * self.jitter_factor * random.random()
            delay += jitter
        
        return delay


@dataclass
class BroadcastRequest:
    """Represents a transaction broadcast request."""
    txid: str
    raw_transaction: str
    priority: BroadcastPriority = BroadcastPriority.NORMAL
    max_attempts: Optional[int] = None
    max_fee_rate: Optional[float] = None
    callback: Optional[Callable[['BroadcastResult'], None]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self):
        """Validate request after initialization."""
        if not self.txid or len(self.txid) != 64:
            raise ValueError(f"Invalid transaction ID: {self.txid}")
        
        if not self.raw_transaction:
            raise ValueError("Raw transaction cannot be empty")
        
        # Verify txid matches raw transaction
        try:
            import hashlib
            raw_bytes = bytes.fromhex(self.raw_transaction)
            computed_txid = hashlib.sha256(hashlib.sha256(raw_bytes).digest()).digest()[::-1].hex()
            if computed_txid != self.txid:
                logging.warning(f"TXID mismatch: provided={self.txid}, computed={computed_txid}")
        except Exception as e:
            logging.warning(f"Could not verify TXID: {e}")


@dataclass
class BroadcastResult:
    """Result of a broadcast operation."""
    request: BroadcastRequest
    status: BroadcastStatus
    attempts: List[BroadcastAttempt] = field(default_factory=list)
    final_error: Optional[str] = None
    broadcast_txid: Optional[str] = None
    total_time_seconds: float = 0.0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    
    def is_successful(self) -> bool:
        """Check if broadcast was successful."""
        return self.status == BroadcastStatus.SUCCESS
    
    def get_attempt_count(self) -> int:
        """Get number of broadcast attempts."""
        return len(self.attempts)
    
    def get_last_attempt(self) -> Optional[BroadcastAttempt]:
        """Get the last broadcast attempt."""
        return self.attempts[-1] if self.attempts else None
    
    def add_attempt(self, attempt: BroadcastAttempt):
        """Add a broadcast attempt."""
        self.attempts.append(attempt)
    
    def mark_completed(self, status: BroadcastStatus, final_error: Optional[str] = None):
        """Mark broadcast as completed."""
        self.status = status
        self.completed_at = datetime.now(timezone.utc)
        self.total_time_seconds = (self.completed_at - self.started_at).total_seconds()
        if final_error:
            self.final_error = final_error
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "txid": self.request.txid,
            "status": self.status.value,
            "priority": self.request.priority.value,
            "attempts": len(self.attempts),
            "successful": self.is_successful(),
            "total_time": self.total_time_seconds,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "final_error": self.final_error,
            "broadcast_txid": self.broadcast_txid,
            "metadata": self.request.metadata
        }


class TransactionBroadcaster:
    """
    Robust transaction broadcaster with retry logic and error handling.
    """
    
    def __init__(
        self, 
        rpc_client: BitcoinRPCClient,
        config: Optional[BroadcastConfig] = None
    ):
        """
        Initialize transaction broadcaster.
        
        Args:
            rpc_client: Bitcoin RPC client
            config: Broadcast configuration
        """
        self.rpc_client = rpc_client
        self.config = config or BroadcastConfig()
        self.logger = logging.getLogger(__name__)
        
        # Active broadcasts
        self._active_broadcasts: Dict[str, BroadcastResult] = {}
        self._broadcast_lock = threading.RLock()
        
        # Queue for pending broadcasts
        self._broadcast_queue: List[BroadcastRequest] = []
        self._queue_lock = threading.Lock()
        
        # Statistics
        self._stats = {
            "total_broadcasts": 0,
            "successful_broadcasts": 0,
            "failed_broadcasts": 0,
            "retry_broadcasts": 0,
            "abandoned_broadcasts": 0,
            "total_attempts": 0,
            "average_attempts": 0.0,
            "average_broadcast_time": 0.0
        }
        self._stats_lock = threading.Lock()
        
        # Background processing
        self._running = False
        self._worker_thread = None
        
        # Callbacks
        self._success_callbacks: List[Callable[[BroadcastResult], None]] = []
        self._failure_callbacks: List[Callable[[BroadcastResult], None]] = []
    
    def add_success_callback(self, callback: Callable[[BroadcastResult], None]):
        """Add callback for successful broadcasts."""
        self._success_callbacks.append(callback)
    
    def add_failure_callback(self, callback: Callable[[BroadcastResult], None]):
        """Add callback for failed broadcasts."""
        self._failure_callbacks.append(callback)
    
    def start(self):
        """Start background broadcast processing."""
        if self._running:
            return
        
        self._running = True
        self._worker_thread = threading.Thread(target=self._process_broadcasts, daemon=True)
        self._worker_thread.start()
        self.logger.info("Transaction broadcaster started")
    
    def stop(self):
        """Stop background broadcast processing."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
        self.logger.info("Transaction broadcaster stopped")
    
    def broadcast_transaction(
        self,
        txid: str,
        raw_transaction: str,
        priority: BroadcastPriority = BroadcastPriority.NORMAL,
        max_attempts: Optional[int] = None,
        max_fee_rate: Optional[float] = None,
        callback: Optional[Callable[[BroadcastResult], None]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> BroadcastResult:
        """
        Queue transaction for broadcasting.
        
        Args:
            txid: Transaction ID
            raw_transaction: Raw transaction hex
            priority: Broadcast priority
            max_attempts: Maximum broadcast attempts (overrides config)
            max_fee_rate: Maximum fee rate (overrides config)
            callback: Callback for broadcast result
            metadata: Additional metadata
            
        Returns:
            BroadcastResult object (initially pending)
        """
        request = BroadcastRequest(
            txid=txid,
            raw_transaction=raw_transaction,
            priority=priority,
            max_attempts=max_attempts,
            max_fee_rate=max_fee_rate,
            callback=callback,
            metadata=metadata or {}
        )
        
        # Create result object
        result = BroadcastResult(
            request=request,
            status=BroadcastStatus.PENDING
        )
        
        # Add to active broadcasts
        with self._broadcast_lock:
            self._active_broadcasts[txid] = result
        
        # Add to queue based on priority
        with self._queue_lock:
            if priority == BroadcastPriority.URGENT:
                self._broadcast_queue.insert(0, request)
            elif priority == BroadcastPriority.HIGH:
                # Insert after other urgent items
                urgent_count = sum(1 for req in self._broadcast_queue if req.priority == BroadcastPriority.URGENT)
                self._broadcast_queue.insert(urgent_count, request)
            else:
                self._broadcast_queue.append(request)
        
        self.logger.info(f"Queued transaction for broadcast: {txid} (priority: {priority.value})")
        return result
    
    def broadcast_transaction_sync(
        self,
        txid: str,
        raw_transaction: str,
        max_attempts: Optional[int] = None,
        max_fee_rate: Optional[float] = None
    ) -> BroadcastResult:
        """
        Broadcast transaction synchronously (blocking).
        
        Args:
            txid: Transaction ID
            raw_transaction: Raw transaction hex
            max_attempts: Maximum broadcast attempts
            max_fee_rate: Maximum fee rate
            
        Returns:
            Completed BroadcastResult
        """
        request = BroadcastRequest(
            txid=txid,
            raw_transaction=raw_transaction,
            priority=BroadcastPriority.URGENT,
            max_attempts=max_attempts,
            max_fee_rate=max_fee_rate
        )
        
        result = BroadcastResult(
            request=request,
            status=BroadcastStatus.BROADCASTING
        )
        
        self._perform_broadcast(result)
        return result
    
    def get_broadcast_status(self, txid: str) -> Optional[BroadcastResult]:
        """Get broadcast status for a transaction."""
        with self._broadcast_lock:
            return self._active_broadcasts.get(txid)
    
    def cancel_broadcast(self, txid: str) -> bool:
        """Cancel a pending broadcast."""
        with self._queue_lock:
            # Remove from queue
            original_length = len(self._broadcast_queue)
            self._broadcast_queue = [req for req in self._broadcast_queue if req.txid != txid]
            
            if len(self._broadcast_queue) < original_length:
                # Update result status
                with self._broadcast_lock:
                    if txid in self._active_broadcasts:
                        result = self._active_broadcasts[txid]
                        result.mark_completed(BroadcastStatus.ABANDONED, "Cancelled by user")
                
                self.logger.info(f"Cancelled broadcast for transaction: {txid}")
                return True
        
        return False
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get broadcast queue status."""
        with self._queue_lock:
            queue_by_priority = {}
            for priority in BroadcastPriority:
                queue_by_priority[priority.value] = sum(
                    1 for req in self._broadcast_queue if req.priority == priority
                )
            
            return {
                "total_queued": len(self._broadcast_queue),
                "by_priority": queue_by_priority,
                "oldest_request": self._broadcast_queue[0].created_at.isoformat() if self._broadcast_queue else None
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get broadcaster statistics."""
        with self._stats_lock:
            stats = self._stats.copy()
        
        with self._broadcast_lock:
            active_count = len(self._active_broadcasts)
            status_counts = {}
            for result in self._active_broadcasts.values():
                status = result.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "totals": stats,
            "active_broadcasts": active_count,
            "status_distribution": status_counts,
            "queue_status": self.get_queue_status(),
            "worker_running": self._running
        }
    
    def _process_broadcasts(self):
        """Background thread for processing broadcast queue."""
        self.logger.info("Broadcast worker thread started")
        
        while self._running:
            try:
                # Get next request from queue
                request = None
                with self._queue_lock:
                    if self._broadcast_queue:
                        request = self._broadcast_queue.pop(0)
                
                if request:
                    # Get result object
                    with self._broadcast_lock:
                        result = self._active_broadcasts.get(request.txid)
                    
                    if result:
                        # Perform broadcast
                        self._perform_broadcast(result)
                    
                else:
                    # No requests, sleep briefly
                    time.sleep(0.1)
                    
            except Exception as e:
                self.logger.error(f"Error in broadcast worker: {e}")
                time.sleep(1.0)
        
        self.logger.info("Broadcast worker thread stopped")
    
    def _perform_broadcast(self, result: BroadcastResult):
        """Perform the actual broadcast with retry logic."""
        request = result.request
        result.status = BroadcastStatus.BROADCASTING
        
        max_attempts = request.max_attempts or self.config.max_attempts
        max_fee_rate = request.max_fee_rate or self.config.max_fee_rate
        
        self.logger.info(f"Starting broadcast for {request.txid} (max attempts: {max_attempts})")
        
        for attempt_num in range(1, max_attempts + 1):
            try:
                # Wait before retry (except first attempt)
                if attempt_num > 1:
                    delay = self.config.get_retry_delay(attempt_num - 1)
                    self.logger.debug(f"Waiting {delay:.2f}s before retry {attempt_num}")
                    time.sleep(delay)
                
                # Attempt broadcast
                attempt_start = time.time()
                
                try:
                    # Broadcast transaction
                    broadcast_txid = self.rpc_client.sendrawtransaction(
                        request.raw_transaction, 
                        max_fee_rate
                    )
                    
                    response_time = (time.time() - attempt_start) * 1000
                    
                    # Success!
                    attempt = BroadcastAttempt(
                        timestamp=datetime.now(timezone.utc),
                        success=True,
                        response_time_ms=response_time,
                        node_info=f"{self.rpc_client.config.host}:{self.rpc_client.config.port}"
                    )
                    
                    result.add_attempt(attempt)
                    result.broadcast_txid = broadcast_txid
                    result.mark_completed(BroadcastStatus.SUCCESS)
                    
                    # Update statistics
                    self._update_stats(True, len(result.attempts), result.total_time_seconds)
                    
                    # Call callbacks
                    self._call_callbacks(result, success=True)
                    
                    self.logger.info(f"Successfully broadcast {request.txid} in {attempt_num} attempts")
                    return
                
                except RPCError as e:
                    response_time = (time.time() - attempt_start) * 1000
                    
                    attempt = BroadcastAttempt(
                        timestamp=datetime.now(timezone.utc),
                        success=False,
                        error_code=e.code,
                        error_message=e.message,
                        response_time_ms=response_time,
                        node_info=f"{self.rpc_client.config.host}:{self.rpc_client.config.port}"
                    )
                    
                    result.add_attempt(attempt)
                    
                    # Check if this is a permanent failure
                    if self._is_permanent_failure(e):
                        result.mark_completed(BroadcastStatus.REJECTED, f"Permanent failure: {e.message}")
                        self._update_stats(False, len(result.attempts), result.total_time_seconds)
                        self._call_callbacks(result, success=False)
                        self.logger.error(f"Permanent failure for {request.txid}: {e.message}")
                        return
                    
                    # Log retry attempt
                    self.logger.warning(f"Broadcast attempt {attempt_num} failed for {request.txid}: {e.message}")
                
            except Exception as e:
                # Unexpected error
                attempt = BroadcastAttempt(
                    timestamp=datetime.now(timezone.utc),
                    success=False,
                    error_message=str(e),
                    response_time_ms=0.0
                )
                
                result.add_attempt(attempt)
                self.logger.error(f"Unexpected error in broadcast attempt {attempt_num} for {request.txid}: {e}")
        
        # All attempts failed
        result.mark_completed(BroadcastStatus.FAILED, f"Failed after {max_attempts} attempts")
        self._update_stats(False, len(result.attempts), result.total_time_seconds)
        self._call_callbacks(result, success=False)
        self.logger.error(f"Failed to broadcast {request.txid} after {max_attempts} attempts")
    
    def _is_permanent_failure(self, error: RPCError) -> bool:
        """Check if an RPC error indicates a permanent failure."""
        # Common permanent failure codes
        permanent_codes = [
            -25,  # Missing inputs
            -26,  # Non-final transaction
            -27,  # Transaction already in blockchain
        ]
        
        # Check for specific error messages that indicate permanent failures
        permanent_messages = [
            "bad-txns-inputs-missingorspent",
            "txn-already-in-mempool",
            "txn-already-known",
            "insufficient priority",
            "min relay fee not met"
        ]
        
        if error.code in permanent_codes:
            return True
        
        if error.message and any(msg in error.message.lower() for msg in permanent_messages):
            return True
        
        return False
    
    def _update_stats(self, success: bool, attempts: int, total_time: float):
        """Update broadcaster statistics."""
        with self._stats_lock:
            self._stats["total_broadcasts"] += 1
            self._stats["total_attempts"] += attempts
            
            if success:
                self._stats["successful_broadcasts"] += 1
            else:
                self._stats["failed_broadcasts"] += 1
            
            if attempts > 1:
                self._stats["retry_broadcasts"] += 1
            
            # Update averages
            if self._stats["total_broadcasts"] > 0:
                self._stats["average_attempts"] = self._stats["total_attempts"] / self._stats["total_broadcasts"]
            
            total_time_sum = self._stats.get("total_time_sum", 0.0) + total_time
            self._stats["total_time_sum"] = total_time_sum
            self._stats["average_broadcast_time"] = total_time_sum / self._stats["total_broadcasts"]
    
    def _call_callbacks(self, result: BroadcastResult, success: bool):
        """Call appropriate callbacks for broadcast result."""
        try:
            # Call request-specific callback
            if result.request.callback:
                result.request.callback(result)
            
            # Call global callbacks
            callbacks = self._success_callbacks if success else self._failure_callbacks
            for callback in callbacks:
                callback(result)
                
        except Exception as e:
            self.logger.error(f"Error in callback: {e}")
    
    def cleanup_old_broadcasts(self, max_age_hours: int = 24):
        """Clean up old broadcast results."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        removed_count = 0
        
        with self._broadcast_lock:
            old_txids = [
                txid for txid, result in self._active_broadcasts.items()
                if result.completed_at and result.completed_at < cutoff_time
            ]
            
            for txid in old_txids:
                del self._active_broadcasts[txid]
                removed_count += 1
        
        if removed_count > 0:
            self.logger.info(f"Cleaned up {removed_count} old broadcast results")
        
        return removed_count
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


# Convenience functions

def create_broadcaster(
    host: str = "localhost",
    port: int = 8332,
    username: str = "rpc",
    password: str = "rpc",
    max_attempts: int = 5
) -> TransactionBroadcaster:
    """Create a transaction broadcaster with custom configuration."""
    rpc_config = RPCConfig(
        host=host,
        port=port,
        username=username,
        password=password
    )
    
    broadcast_config = BroadcastConfig(max_attempts=max_attempts)
    
    rpc_client = BitcoinRPCClient(rpc_config)
    return TransactionBroadcaster(rpc_client, broadcast_config)


# Testing and CLI interface

def test_broadcaster():
    """Test the transaction broadcaster with a mock transaction."""
    print("Testing Transaction Broadcaster...")
    print("=" * 50)
    
    try:
        # Create broadcaster
        broadcaster = create_broadcaster()
        
        # Test connection
        if not broadcaster.rpc_client.test_connection():
            print("✗ Cannot connect to Bitcoin Core")
            return False
        
        print("✓ Connected to Bitcoin Core")
        
        # Start broadcaster
        broadcaster.start()
        print("✓ Broadcaster started")
        
        # Test queue status
        queue_status = broadcaster.get_queue_status()
        print(f"✓ Queue status: {queue_status['total_queued']} items")
        
        # Test statistics
        stats = broadcaster.get_statistics()
        print(f"✓ Statistics available: {len(stats)} categories")
        
        # Clean up
        broadcaster.stop()
        broadcaster.rpc_client.close()
        print("✓ Broadcaster stopped")
        
        print("\nTransaction broadcaster test completed successfully!")
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
        success = test_broadcaster()
        sys.exit(0 if success else 1)
    
    else:
        print("Transaction Broadcasting System")
        print("Usage: python broadcaster.py test")
        print("\nFeatures:")
        print("- Robust retry logic with exponential backoff")
        print("- Priority-based broadcasting queue")
        print("- Comprehensive error handling and statistics")
        print("- Background processing with callbacks")
        print("- Configurable timeouts and fee rates")