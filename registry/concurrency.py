"""
Bitcoin Native Asset Protocol - Concurrency and Thread-Safety Utilities

This module provides enhanced thread-safety wrappers, concurrency control,
and performance monitoring for registry operations.
"""

import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from threading import RLock, Lock, Condition, current_thread
from typing import Any, Dict, List, Optional, Set, Callable, Union
from uuid import uuid4


class LockType(str, Enum):
    """Lock type enumeration."""
    READ = "read"
    WRITE = "write"


class OperationPriority(int, Enum):
    """Operation priority levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DeadlockError(Exception):
    """Deadlock detection exception."""
    pass


class ConcurrencyError(Exception):
    """General concurrency operation exception."""
    pass


class LockMetrics:
    """Lock performance metrics."""
    
    def __init__(self):
        self.acquisition_count = 0
        self.contention_count = 0
        self.total_wait_time = 0.0
        self.max_wait_time = 0.0
        self.active_locks = 0
        self.last_acquisition = None
        self.lock_history = deque(maxlen=100)  # Last 100 lock events
    
    def record_acquisition(self, wait_time: float, contended: bool) -> None:
        """Record lock acquisition metrics."""
        self.acquisition_count += 1
        self.total_wait_time += wait_time
        self.max_wait_time = max(self.max_wait_time, wait_time)
        self.active_locks += 1
        self.last_acquisition = datetime.utcnow()
        
        if contended:
            self.contention_count += 1
        
        self.lock_history.append({
            'timestamp': self.last_acquisition,
            'wait_time': wait_time,
            'contended': contended,
            'thread_id': threading.get_ident()
        })
    
    def record_release(self) -> None:
        """Record lock release."""
        self.active_locks = max(0, self.active_locks - 1)
    
    def get_contention_ratio(self) -> float:
        """Get lock contention ratio."""
        if self.acquisition_count == 0:
            return 0.0
        return self.contention_count / self.acquisition_count
    
    def get_average_wait_time(self) -> float:
        """Get average wait time."""
        if self.acquisition_count == 0:
            return 0.0
        return self.total_wait_time / self.acquisition_count


class ReadWriteLock:
    """Enhanced read-write lock with metrics and deadlock detection."""
    
    def __init__(self, name: str = "unnamed", timeout: float = 30.0):
        self.name = name
        self.timeout = timeout
        self._lock = RLock()
        self._readers = 0
        self._writers = 0
        self._write_ready = Condition(self._lock)
        self._read_ready = Condition(self._lock)
        self._metrics = LockMetrics()
        self._lock_holders: Dict[int, LockType] = {}
        self._waiting_threads: Set[int] = set()
    
    @contextmanager
    def read_lock(self):
        """Acquire read lock with context manager."""
        acquired = self.acquire_read()
        try:
            yield
        finally:
            if acquired:
                self.release_read()
    
    @contextmanager
    def write_lock(self):
        """Acquire write lock with context manager."""
        acquired = self.acquire_write()
        try:
            yield
        finally:
            if acquired:
                self.release_write()
    
    def acquire_read(self) -> bool:
        """Acquire read lock."""
        thread_id = threading.get_ident()
        start_time = time.time()
        contended = False
        
        with self._lock:
            self._waiting_threads.add(thread_id)
            
            try:
                # Wait for writers to finish
                while self._writers > 0:
                    contended = True
                    if not self._read_ready.wait(timeout=self.timeout):
                        return False
                
                self._readers += 1
                self._lock_holders[thread_id] = LockType.READ
                
                wait_time = time.time() - start_time
                self._metrics.record_acquisition(wait_time, contended)
                
                return True
                
            finally:
                self._waiting_threads.discard(thread_id)
    
    def release_read(self) -> None:
        """Release read lock."""
        thread_id = threading.get_ident()
        
        with self._lock:
            if thread_id not in self._lock_holders:
                raise ConcurrencyError("Thread does not hold read lock")
            
            if self._lock_holders[thread_id] != LockType.READ:
                raise ConcurrencyError("Thread holds wrong lock type")
            
            self._readers -= 1
            del self._lock_holders[thread_id]
            self._metrics.record_release()
            
            # Notify waiting writers
            if self._readers == 0:
                self._write_ready.notify_all()
    
    def acquire_write(self) -> bool:
        """Acquire write lock."""
        thread_id = threading.get_ident()
        start_time = time.time()
        contended = False
        
        with self._lock:
            self._waiting_threads.add(thread_id)
            
            try:
                # Wait for readers and writers to finish
                while self._readers > 0 or self._writers > 0:
                    contended = True
                    if not self._write_ready.wait(timeout=self.timeout):
                        return False
                
                self._writers += 1
                self._lock_holders[thread_id] = LockType.WRITE
                
                wait_time = time.time() - start_time
                self._metrics.record_acquisition(wait_time, contended)
                
                return True
                
            finally:
                self._waiting_threads.discard(thread_id)
    
    def release_write(self) -> None:
        """Release write lock."""
        thread_id = threading.get_ident()
        
        with self._lock:
            if thread_id not in self._lock_holders:
                raise ConcurrencyError("Thread does not hold write lock")
            
            if self._lock_holders[thread_id] != LockType.WRITE:
                raise ConcurrencyError("Thread holds wrong lock type")
            
            self._writers -= 1
            del self._lock_holders[thread_id]
            self._metrics.record_release()
            
            # Notify waiting readers and writers
            self._read_ready.notify_all()
            self._write_ready.notify_all()
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get lock performance metrics."""
        with self._lock:
            return {
                'name': self.name,
                'readers': self._readers,
                'writers': self._writers,
                'waiting_threads': len(self._waiting_threads),
                'acquisition_count': self._metrics.acquisition_count,
                'contention_count': self._metrics.contention_count,
                'contention_ratio': self._metrics.get_contention_ratio(),
                'average_wait_time': self._metrics.get_average_wait_time(),
                'max_wait_time': self._metrics.max_wait_time,
                'active_locks': self._metrics.active_locks,
                'last_acquisition': self._metrics.last_acquisition
            }


class OperationQueue:
    """Priority-based operation queue for high-concurrency scenarios."""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._queue = defaultdict(deque)  # Priority -> deque of operations
        self._lock = Lock()
        self._not_empty = Condition(self._lock)
        self._not_full = Condition(self._lock)
        self._size = 0
        self._stopped = False
    
    def put(
        self,
        operation: Callable,
        priority: OperationPriority = OperationPriority.MEDIUM,
        timeout: Optional[float] = None
    ) -> bool:
        """Add operation to queue."""
        with self._not_full:
            if self._stopped:
                return False
            
            # Wait for space if queue is full
            while self._size >= self.max_size:
                if not self._not_full.wait(timeout=timeout):
                    return False
                if self._stopped:
                    return False
            
            self._queue[priority].append({
                'operation': operation,
                'timestamp': datetime.utcnow(),
                'id': str(uuid4())
            })
            self._size += 1
            self._not_empty.notify()
            
            return True
    
    def get(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Get next operation from queue (highest priority first)."""
        with self._not_empty:
            while self._size == 0 and not self._stopped:
                if not self._not_empty.wait(timeout=timeout):
                    return None
            
            if self._stopped and self._size == 0:
                return None
            
            # Get highest priority operation
            for priority in sorted(OperationPriority, reverse=True):
                if self._queue[priority]:
                    operation = self._queue[priority].popleft()
                    self._size -= 1
                    self._not_full.notify()
                    return operation
            
            return None
    
    def stop(self) -> None:
        """Stop the queue and wake up waiting threads."""
        with self._lock:
            self._stopped = True
            self._not_empty.notify_all()
            self._not_full.notify_all()
    
    def size(self) -> int:
        """Get current queue size."""
        with self._lock:
            return self._size
    
    def is_stopped(self) -> bool:
        """Check if queue is stopped."""
        with self._lock:
            return self._stopped


class DeadlockDetector:
    """Deadlock detection and prevention system."""
    
    def __init__(self):
        self._lock_graph: Dict[int, Set[str]] = defaultdict(set)
        self._waiting_for: Dict[int, str] = {}
        self._lock = Lock()
    
    def register_lock_request(self, thread_id: int, lock_name: str) -> None:
        """Register that a thread is waiting for a lock."""
        with self._lock:
            self._waiting_for[thread_id] = lock_name
            self._check_deadlock(thread_id, lock_name)
    
    def register_lock_acquired(self, thread_id: int, lock_name: str) -> None:
        """Register that a thread has acquired a lock."""
        with self._lock:
            self._lock_graph[thread_id].add(lock_name)
            self._waiting_for.pop(thread_id, None)
    
    def register_lock_released(self, thread_id: int, lock_name: str) -> None:
        """Register that a thread has released a lock."""
        with self._lock:
            self._lock_graph[thread_id].discard(lock_name)
            if not self._lock_graph[thread_id]:
                del self._lock_graph[thread_id]
    
    def _check_deadlock(self, thread_id: int, requested_lock: str) -> None:
        """Check for potential deadlock."""
        visited = set()
        stack = [thread_id]
        
        while stack:
            current_thread = stack.pop()
            
            if current_thread in visited:
                # Cycle detected - potential deadlock
                raise DeadlockError(
                    f"Deadlock detected: Thread {thread_id} requesting {requested_lock}"
                )
            
            visited.add(current_thread)
            
            # Find threads holding locks that current thread is waiting for
            waiting_lock = self._waiting_for.get(current_thread)
            if waiting_lock:
                for tid, held_locks in self._lock_graph.items():
                    if waiting_lock in held_locks and tid not in visited:
                        stack.append(tid)


class ThreadSafeRegistry:
    """Thread-safe wrapper for registry operations."""
    
    def __init__(self, registry_manager):
        self.registry_manager = registry_manager
        self._rw_lock = ReadWriteLock("registry_operations")
        self._operation_queue = OperationQueue()
        self._deadlock_detector = DeadlockDetector()
        self._version = 0
        self._version_lock = Lock()
    
    def _increment_version(self) -> int:
        """Increment and return the new version number."""
        with self._version_lock:
            self._version += 1
            return self._version
    
    def _execute_with_optimistic_locking(
        self,
        operation: Callable,
        expected_version: Optional[int] = None
    ) -> Any:
        """Execute operation with optimistic locking."""
        if expected_version is not None and expected_version != self._version:
            raise ConcurrencyError(
                f"Version conflict: expected {expected_version}, current {self._version}"
            )
        
        result = operation()
        self._increment_version()
        return result
    
    def read_operation(self, operation: Callable, **kwargs) -> Any:
        """Execute read operation with read lock."""
        thread_id = threading.get_ident()
        
        try:
            self._deadlock_detector.register_lock_request(thread_id, "read")
            
            with self._rw_lock.read_lock():
                self._deadlock_detector.register_lock_acquired(thread_id, "read")
                return operation(**kwargs)
                
        finally:
            self._deadlock_detector.register_lock_released(thread_id, "read")
    
    def write_operation(self, operation: Callable, **kwargs) -> Any:
        """Execute write operation with write lock."""
        thread_id = threading.get_ident()
        
        try:
            self._deadlock_detector.register_lock_request(thread_id, "write")
            
            with self._rw_lock.write_lock():
                self._deadlock_detector.register_lock_acquired(thread_id, "write")
                return self._execute_with_optimistic_locking(operation, **kwargs)
                
        finally:
            self._deadlock_detector.register_lock_released(thread_id, "write")
    
    def queue_operation(
        self,
        operation: Callable,
        priority: OperationPriority = OperationPriority.MEDIUM,
        **kwargs
    ) -> str:
        """Queue operation for later execution."""
        operation_id = str(uuid4())
        
        def wrapped_operation():
            return operation(**kwargs)
        
        success = self._operation_queue.put(wrapped_operation, priority)
        
        if not success:
            raise ConcurrencyError("Failed to queue operation")
        
        return operation_id
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        return {
            'lock_metrics': self._rw_lock.get_metrics(),
            'queue_size': self._operation_queue.size(),
            'current_version': self._version,
            'thread_count': threading.active_count(),
            'current_thread': threading.get_ident()
        }


def thread_safe(lock_type: LockType = LockType.WRITE):
    """Decorator to make registry methods thread-safe."""
    
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not hasattr(self, '_thread_safe_wrapper'):
                # Create thread-safe wrapper on first use
                self._thread_safe_wrapper = ThreadSafeRegistry(self)
            
            if lock_type == LockType.READ:
                return self._thread_safe_wrapper.read_operation(func, self, *args, **kwargs)
            else:
                return self._thread_safe_wrapper.write_operation(func, self, *args, **kwargs)
        
        return wrapper
    
    return decorator


class ConcurrencyMonitor:
    """Monitor and analyze concurrency patterns."""
    
    def __init__(self):
        self._operations_log = deque(maxlen=10000)
        self._lock = Lock()
        self._start_time = datetime.utcnow()
    
    def log_operation(
        self,
        operation_name: str,
        thread_id: int,
        duration: float,
        lock_wait_time: float = 0.0
    ) -> None:
        """Log an operation for analysis."""
        with self._lock:
            self._operations_log.append({
                'operation': operation_name,
                'thread_id': thread_id,
                'timestamp': datetime.utcnow(),
                'duration': duration,
                'lock_wait_time': lock_wait_time
            })
    
    def get_concurrency_report(self) -> Dict[str, Any]:
        """Generate concurrency analysis report."""
        with self._lock:
            if not self._operations_log:
                return {'status': 'no_data'}
            
            operations = list(self._operations_log)
            
            # Calculate metrics
            total_ops = len(operations)
            unique_threads = len(set(op['thread_id'] for op in operations))
            avg_duration = sum(op['duration'] for op in operations) / total_ops
            avg_wait_time = sum(op['lock_wait_time'] for op in operations) / total_ops
            
            # Operation frequency
            op_counts = defaultdict(int)
            for op in operations:
                op_counts[op['operation']] += 1
            
            # Thread utilization
            thread_ops = defaultdict(int)
            for op in operations:
                thread_ops[op['thread_id']] += 1
            
            return {
                'status': 'active',
                'uptime': (datetime.utcnow() - self._start_time).total_seconds(),
                'total_operations': total_ops,
                'unique_threads': unique_threads,
                'average_duration': avg_duration,
                'average_wait_time': avg_wait_time,
                'operation_frequency': dict(op_counts),
                'thread_utilization': dict(thread_ops),
                'contention_ratio': avg_wait_time / avg_duration if avg_duration > 0 else 0
            }