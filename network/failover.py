"""
Bitcoin Native Asset Protocol - Multi-Node RPC with Failover and Load Balancing

This module provides enhanced RPC client capabilities with support for multiple
Bitcoin nodes, automatic failover, load balancing, and circuit breaker patterns.
"""

import logging
import random
import threading
import time
from typing import Dict, List, Optional, Union, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from collections import defaultdict, deque
import statistics

try:
    from .rpc import BitcoinRPCClient, RPCConfig, RPCError, RPCConnectionError, RPCTimeoutError
except ImportError:
    # For standalone testing
    from rpc import BitcoinRPCClient, RPCConfig, RPCError, RPCConnectionError, RPCTimeoutError


class NodeType(Enum):
    """Types of Bitcoin nodes."""
    LOCAL = "local"
    REMOTE = "remote"
    PUBLIC_API = "public_api"
    TESTNET = "testnet"
    REGTEST = "regtest"


class NodeStatus(Enum):
    """Status of a Bitcoin node."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"
    CIRCUIT_OPEN = "circuit_open"


class LoadBalanceStrategy(Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    WEIGHTED_RANDOM = "weighted_random"
    LOWEST_LATENCY = "lowest_latency"
    LEAST_LOADED = "least_loaded"


class OperationType(Enum):
    """Types of RPC operations."""
    READ = "read"
    WRITE = "write"
    BROADCAST = "broadcast"


@dataclass
class NodeHealth:
    """Health metrics for a Bitcoin node."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_response_time: float = 0.0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    consecutive_failures: int = 0
    avg_response_time: float = 0.0
    success_rate: float = 1.0
    score: float = 1.0
    
    def update_success(self, response_time: float):
        """Update metrics for successful request."""
        self.total_requests += 1
        self.successful_requests += 1
        self.total_response_time += response_time
        self.last_success = datetime.now(timezone.utc)
        self.consecutive_failures = 0
        self._recalculate_metrics()
    
    def update_failure(self):
        """Update metrics for failed request."""
        self.total_requests += 1
        self.failed_requests += 1
        self.last_failure = datetime.now(timezone.utc)
        self.consecutive_failures += 1
        self._recalculate_metrics()
    
    def _recalculate_metrics(self):
        """Recalculate derived metrics."""
        if self.total_requests > 0:
            self.success_rate = self.successful_requests / self.total_requests
            self.avg_response_time = self.total_response_time / max(1, self.successful_requests)
            
            # Calculate score based on success rate and response time
            # Higher success rate and lower response time = higher score
            latency_factor = min(1.0, 1000.0 / max(self.avg_response_time, 1.0))  # Favor <1s response
            self.score = (self.success_rate * 0.7) + (latency_factor * 0.3)


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker pattern."""
    failure_threshold: int = 5
    recovery_timeout_seconds: int = 60
    half_open_max_calls: int = 3


@dataclass
class CircuitBreakerState:
    """State of circuit breaker for a node."""
    state: str = "closed"  # closed, open, half_open
    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    next_attempt_time: Optional[datetime] = None
    half_open_successes: int = 0


@dataclass 
class NodeConfig:
    """Configuration for a Bitcoin node."""
    node_id: str
    rpc_config: RPCConfig
    node_type: NodeType = NodeType.REMOTE
    weight: float = 1.0
    priority: int = 1  # 1 = highest priority
    enable_for_reads: bool = True
    enable_for_writes: bool = True
    enable_for_broadcasts: bool = True
    circuit_breaker_config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)


class MultiNodeRPCClient:
    """
    Multi-node RPC client with failover, load balancing, and circuit breaker support.
    """
    
    def __init__(
        self,
        nodes: List[NodeConfig],
        load_balance_strategy: LoadBalanceStrategy = LoadBalanceStrategy.WEIGHTED_RANDOM,
        health_check_interval: int = 30
    ):
        """
        Initialize multi-node RPC client.
        
        Args:
            nodes: List of node configurations
            load_balance_strategy: Load balancing strategy
            health_check_interval: Health check interval in seconds
        """
        self.nodes = {node.node_id: node for node in nodes}
        self.load_balance_strategy = load_balance_strategy
        self.health_check_interval = health_check_interval
        
        self.logger = logging.getLogger(__name__)
        
        # RPC clients for each node
        self._clients: Dict[str, BitcoinRPCClient] = {}
        self._client_lock = threading.RLock()
        
        # Health tracking
        self._node_health: Dict[str, NodeHealth] = {}
        self._circuit_breakers: Dict[str, CircuitBreakerState] = {}
        self._health_lock = threading.RLock()
        
        # Load balancing state
        self._round_robin_index = 0
        self._last_used: Dict[str, datetime] = {}
        
        # Health monitoring
        self._health_monitor_running = False
        self._health_monitor_thread = None
        
        # Statistics
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "failover_events": 0,
            "circuit_breaker_trips": 0,
            "nodes_online": 0,
            "nodes_offline": 0
        }
        self._stats_lock = threading.Lock()
        
        # Initialize
        self._initialize_clients()
        self._initialize_health_tracking()
    
    def start_health_monitoring(self):
        """Start background health monitoring."""
        if self._health_monitor_running:
            return
        
        self._health_monitor_running = True
        self._health_monitor_thread = threading.Thread(target=self._health_monitor_worker, daemon=True)
        self._health_monitor_thread.start()
        
        self.logger.info("Multi-node health monitoring started")
    
    def stop_health_monitoring(self):
        """Stop background health monitoring."""
        self._health_monitor_running = False
        
        if self._health_monitor_thread:
            self._health_monitor_thread.join(timeout=5.0)
        
        self.logger.info("Multi-node health monitoring stopped")
    
    def get_node_status(self, node_id: str) -> NodeStatus:
        """Get current status of a specific node."""
        with self._health_lock:
            health = self._node_health.get(node_id)
            circuit_breaker = self._circuit_breakers.get(node_id)
            
            if not health or not circuit_breaker:
                return NodeStatus.OFFLINE
            
            # Check circuit breaker state
            if circuit_breaker.state == "open":
                return NodeStatus.CIRCUIT_OPEN
            
            # Check health metrics
            if health.consecutive_failures >= 3:
                return NodeStatus.UNHEALTHY
            elif health.success_rate < 0.8:
                return NodeStatus.DEGRADED
            else:
                return NodeStatus.HEALTHY
    
    def get_available_nodes(self, operation_type: OperationType) -> List[str]:
        """Get list of available nodes for given operation type."""
        available_nodes = []
        
        with self._health_lock:
            for node_id, node_config in self.nodes.items():
                # Check if node supports this operation type
                if operation_type == OperationType.READ and not node_config.enable_for_reads:
                    continue
                elif operation_type == OperationType.WRITE and not node_config.enable_for_writes:
                    continue
                elif operation_type == OperationType.BROADCAST and not node_config.enable_for_broadcasts:
                    continue
                
                # Check node status
                status = self.get_node_status(node_id)
                if status in [NodeStatus.HEALTHY, NodeStatus.DEGRADED]:
                    available_nodes.append(node_id)
        
        return available_nodes
    
    def select_node(self, operation_type: OperationType, exclude_nodes: Optional[List[str]] = None) -> Optional[str]:
        """
        Select best node for operation using configured load balancing strategy.
        
        Args:
            operation_type: Type of operation
            exclude_nodes: Nodes to exclude from selection
            
        Returns:
            Selected node ID or None if no nodes available
        """
        available_nodes = self.get_available_nodes(operation_type)
        
        if exclude_nodes:
            available_nodes = [n for n in available_nodes if n not in exclude_nodes]
        
        if not available_nodes:
            return None
        
        # Apply load balancing strategy
        if self.load_balance_strategy == LoadBalanceStrategy.ROUND_ROBIN:
            return self._select_round_robin(available_nodes)
        
        elif self.load_balance_strategy == LoadBalanceStrategy.WEIGHTED_RANDOM:
            return self._select_weighted_random(available_nodes)
        
        elif self.load_balance_strategy == LoadBalanceStrategy.LOWEST_LATENCY:
            return self._select_lowest_latency(available_nodes)
        
        elif self.load_balance_strategy == LoadBalanceStrategy.LEAST_LOADED:
            return self._select_least_loaded(available_nodes)
        
        else:
            # Fallback to random
            return random.choice(available_nodes)
    
    def execute_rpc_call(
        self,
        method: str,
        params: List[Any],
        operation_type: OperationType = OperationType.READ,
        max_retries: int = 3
    ) -> Any:
        """
        Execute RPC call with failover support.
        
        Args:
            method: RPC method name
            params: Method parameters
            operation_type: Type of operation for node selection
            max_retries: Maximum retry attempts
            
        Returns:
            RPC call result
            
        Raises:
            RPCError: If all nodes fail
        """
        excluded_nodes = []
        last_error = None
        
        for attempt in range(max_retries + 1):
            # Select node
            node_id = self.select_node(operation_type, excluded_nodes)
            
            if not node_id:
                if excluded_nodes:
                    # All nodes have been tried
                    break
                else:
                    # No nodes available
                    raise RPCConnectionError(-1, "No available nodes for operation")
            
            try:
                # Execute call
                result = self._execute_on_node(node_id, method, params)
                
                # Update success metrics
                self._update_node_success(node_id, 0.1)  # Placeholder response time
                
                with self._stats_lock:
                    self._stats["total_requests"] += 1
                    self._stats["successful_requests"] += 1
                
                return result
                
            except (RPCConnectionError, RPCTimeoutError) as e:
                # Node-specific error - try another node
                last_error = e
                self._update_node_failure(node_id)
                excluded_nodes.append(node_id)
                
                with self._stats_lock:
                    self._stats["total_requests"] += 1
                    self._stats["failed_requests"] += 1
                    if attempt > 0:
                        self._stats["failover_events"] += 1
                
                self.logger.warning(f"RPC call failed on node {node_id}: {e}")
                
            except RPCError as e:
                # RPC-level error - don't retry on other nodes
                with self._stats_lock:
                    self._stats["total_requests"] += 1
                    self._stats["failed_requests"] += 1
                
                raise e
        
        # All retries exhausted
        if last_error:
            raise last_error
        else:
            raise RPCConnectionError(-1, f"All nodes failed after {max_retries} retries")
    
    def broadcast_transaction(self, hex_string: str, max_fee_rate: Optional[float] = None) -> str:
        """Broadcast transaction to network using multiple nodes for redundancy."""
        return self.execute_rpc_call(
            "sendrawtransaction",
            [hex_string] + ([max_fee_rate] if max_fee_rate else []),
            OperationType.BROADCAST
        )
    
    def get_block_count(self) -> int:
        """Get current block count with load balancing."""
        return self.execute_rpc_call("getblockcount", [], OperationType.READ)
    
    def get_raw_mempool(self, verbose: bool = False) -> Union[List[str], Dict[str, Any]]:
        """Get raw mempool with load balancing."""
        return self.execute_rpc_call("getrawmempool", [verbose], OperationType.READ)
    
    def get_transaction(self, txid: str, verbose: bool = True) -> Union[str, Dict[str, Any]]:
        """Get transaction with load balancing."""
        return self.execute_rpc_call("getrawtransaction", [txid, verbose], OperationType.READ)
    
    def get_node_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics for all nodes."""
        with self._stats_lock:
            global_stats = self._stats.copy()
        
        node_stats = {}
        online_count = 0
        offline_count = 0
        
        with self._health_lock:
            for node_id in self.nodes:
                health = self._node_health.get(node_id, NodeHealth())
                status = self.get_node_status(node_id)
                
                if status in [NodeStatus.HEALTHY, NodeStatus.DEGRADED]:
                    online_count += 1
                else:
                    offline_count += 1
                
                node_stats[node_id] = {
                    "status": status.value,
                    "total_requests": health.total_requests,
                    "success_rate": health.success_rate,
                    "avg_response_time": health.avg_response_time,
                    "consecutive_failures": health.consecutive_failures,
                    "score": health.score,
                    "last_success": health.last_success.isoformat() if health.last_success else None,
                    "last_failure": health.last_failure.isoformat() if health.last_failure else None,
                    "circuit_breaker_state": self._circuit_breakers.get(node_id, CircuitBreakerState()).state
                }
        
        global_stats["nodes_online"] = online_count
        global_stats["nodes_offline"] = offline_count
        
        return {
            "global_stats": global_stats,
            "node_stats": node_stats,
            "load_balance_strategy": self.load_balance_strategy.value,
            "total_nodes": len(self.nodes)
        }
    
    def _initialize_clients(self):
        """Initialize RPC clients for all nodes."""
        with self._client_lock:
            for node_id, node_config in self.nodes.items():
                try:
                    client = BitcoinRPCClient(node_config.rpc_config)
                    self._clients[node_id] = client
                    self.logger.info(f"Initialized RPC client for node {node_id}")
                except Exception as e:
                    self.logger.error(f"Failed to initialize client for node {node_id}: {e}")
    
    def _initialize_health_tracking(self):
        """Initialize health tracking for all nodes."""
        with self._health_lock:
            for node_id in self.nodes:
                self._node_health[node_id] = NodeHealth()
                self._circuit_breakers[node_id] = CircuitBreakerState()
    
    def _execute_on_node(self, node_id: str, method: str, params: List[Any]) -> Any:
        """Execute RPC call on specific node."""
        # Check circuit breaker
        if not self._check_circuit_breaker(node_id):
            raise RPCConnectionError(-1, f"Circuit breaker open for node {node_id}")
        
        with self._client_lock:
            client = self._clients.get(node_id)
            if not client:
                raise RPCConnectionError(-1, f"No client available for node {node_id}")
        
        start_time = time.time()
        
        try:
            result = client._call(method, *params)
            response_time = time.time() - start_time
            
            # Update circuit breaker on success
            self._update_circuit_breaker_success(node_id)
            
            return result
            
        except Exception as e:
            # Update circuit breaker on failure
            self._update_circuit_breaker_failure(node_id)
            raise
    
    def _check_circuit_breaker(self, node_id: str) -> bool:
        """Check if circuit breaker allows request."""
        with self._health_lock:
            circuit_breaker = self._circuit_breakers.get(node_id)
            if not circuit_breaker:
                return True
            
            now = datetime.now(timezone.utc)
            
            if circuit_breaker.state == "closed":
                return True
            
            elif circuit_breaker.state == "open":
                # Check if we should try to recover
                if (circuit_breaker.next_attempt_time and 
                    now >= circuit_breaker.next_attempt_time):
                    circuit_breaker.state = "half_open"
                    circuit_breaker.half_open_successes = 0
                    self.logger.info(f"Circuit breaker for node {node_id} entering half-open state")
                    return True
                return False
            
            elif circuit_breaker.state == "half_open":
                # Allow limited requests in half-open state
                config = self.nodes[node_id].circuit_breaker_config
                return circuit_breaker.half_open_successes < config.half_open_max_calls
            
            return False
    
    def _update_circuit_breaker_success(self, node_id: str):
        """Update circuit breaker on successful request."""
        with self._health_lock:
            circuit_breaker = self._circuit_breakers.get(node_id)
            if not circuit_breaker:
                return
            
            if circuit_breaker.state == "half_open":
                circuit_breaker.half_open_successes += 1
                config = self.nodes[node_id].circuit_breaker_config
                
                if circuit_breaker.half_open_successes >= config.half_open_max_calls:
                    # Enough successes - close circuit breaker
                    circuit_breaker.state = "closed"
                    circuit_breaker.failure_count = 0
                    self.logger.info(f"Circuit breaker for node {node_id} closed after recovery")
    
    def _update_circuit_breaker_failure(self, node_id: str):
        """Update circuit breaker on failed request."""
        with self._health_lock:
            circuit_breaker = self._circuit_breakers.get(node_id)
            if not circuit_breaker:
                return
            
            circuit_breaker.failure_count += 1
            circuit_breaker.last_failure_time = datetime.now(timezone.utc)
            
            config = self.nodes[node_id].circuit_breaker_config
            
            if circuit_breaker.state == "closed":
                if circuit_breaker.failure_count >= config.failure_threshold:
                    # Trip circuit breaker
                    circuit_breaker.state = "open"
                    circuit_breaker.next_attempt_time = (
                        datetime.now(timezone.utc) + 
                        timedelta(seconds=config.recovery_timeout_seconds)
                    )
                    
                    with self._stats_lock:
                        self._stats["circuit_breaker_trips"] += 1
                    
                    self.logger.warning(f"Circuit breaker tripped for node {node_id}")
            
            elif circuit_breaker.state == "half_open":
                # Failed during recovery - back to open
                circuit_breaker.state = "open"
                circuit_breaker.next_attempt_time = (
                    datetime.now(timezone.utc) + 
                    timedelta(seconds=config.recovery_timeout_seconds)
                )
                self.logger.warning(f"Circuit breaker for node {node_id} failed during recovery")
    
    def _update_node_success(self, node_id: str, response_time: float):
        """Update node health metrics on successful request."""
        with self._health_lock:
            health = self._node_health.get(node_id)
            if health:
                health.update_success(response_time)
    
    def _update_node_failure(self, node_id: str):
        """Update node health metrics on failed request."""
        with self._health_lock:
            health = self._node_health.get(node_id)
            if health:
                health.update_failure()
    
    def _select_round_robin(self, available_nodes: List[str]) -> str:
        """Select node using round-robin strategy."""
        self._round_robin_index = (self._round_robin_index + 1) % len(available_nodes)
        return available_nodes[self._round_robin_index]
    
    def _select_weighted_random(self, available_nodes: List[str]) -> str:
        """Select node using weighted random strategy."""
        weights = []
        
        with self._health_lock:
            for node_id in available_nodes:
                node_config = self.nodes[node_id]
                health = self._node_health[node_id]
                
                # Combine configuration weight with health score
                weight = node_config.weight * health.score
                weights.append(weight)
        
        return random.choices(available_nodes, weights=weights)[0]
    
    def _select_lowest_latency(self, available_nodes: List[str]) -> str:
        """Select node with lowest average response time."""
        best_node = available_nodes[0]
        best_latency = float('inf')
        
        with self._health_lock:
            for node_id in available_nodes:
                health = self._node_health[node_id]
                if health.avg_response_time < best_latency:
                    best_latency = health.avg_response_time
                    best_node = node_id
        
        return best_node
    
    def _select_least_loaded(self, available_nodes: List[str]) -> str:
        """Select node that was used least recently."""
        best_node = available_nodes[0]
        oldest_use = datetime.now(timezone.utc)
        
        for node_id in available_nodes:
            last_used = self._last_used.get(node_id, datetime.min.replace(tzinfo=timezone.utc))
            if last_used < oldest_use:
                oldest_use = last_used
                best_node = node_id
        
        # Update last used time
        self._last_used[best_node] = datetime.now(timezone.utc)
        return best_node
    
    def _health_monitor_worker(self):
        """Background health monitoring worker."""
        self.logger.info("Multi-node health monitor started")
        
        while self._health_monitor_running:
            try:
                self._perform_health_checks()
                time.sleep(self.health_check_interval)
                
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
                time.sleep(10)
        
        self.logger.info("Multi-node health monitor stopped")
    
    def _perform_health_checks(self):
        """Perform health checks on all nodes."""
        for node_id in self.nodes:
            try:
                start_time = time.time()
                
                # Simple health check - get block count
                with self._client_lock:
                    client = self._clients.get(node_id)
                    if client:
                        client._call("getblockcount")
                
                response_time = time.time() - start_time
                self._update_node_success(node_id, response_time)
                
            except Exception as e:
                self._update_node_failure(node_id)
                self.logger.debug(f"Health check failed for node {node_id}: {e}")
    
    def add_node(self, node_config: NodeConfig) -> bool:
        """Add a new node to the client."""
        try:
            # Initialize client
            client = BitcoinRPCClient(node_config.rpc_config)
            
            with self._client_lock:
                self._clients[node_config.node_id] = client
            
            self.nodes[node_config.node_id] = node_config
            
            # Initialize health tracking
            with self._health_lock:
                self._node_health[node_config.node_id] = NodeHealth()
                self._circuit_breakers[node_config.node_id] = CircuitBreakerState()
            
            self.logger.info(f"Added node {node_config.node_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add node {node_config.node_id}: {e}")
            return False
    
    def remove_node(self, node_id: str) -> bool:
        """Remove a node from the client."""
        if node_id not in self.nodes:
            return False
        
        # Close client
        with self._client_lock:
            client = self._clients.pop(node_id, None)
            if client:
                client.close()
        
        # Remove from tracking
        self.nodes.pop(node_id, None)
        
        with self._health_lock:
            self._node_health.pop(node_id, None)
            self._circuit_breakers.pop(node_id, None)
        
        self.logger.info(f"Removed node {node_id}")
        return True
    
    def close(self):
        """Close all connections."""
        self.stop_health_monitoring()
        
        with self._client_lock:
            for client in self._clients.values():
                client.close()
            self._clients.clear()
    
    def __enter__(self):
        """Context manager entry."""
        self.start_health_monitoring()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Convenience functions

def create_multi_node_client(
    primary_node: Tuple[str, int, str, str],
    backup_nodes: Optional[List[Tuple[str, int, str, str]]] = None,
    strategy: LoadBalanceStrategy = LoadBalanceStrategy.WEIGHTED_RANDOM
) -> MultiNodeRPCClient:
    """
    Create multi-node RPC client with primary and backup nodes.
    
    Args:
        primary_node: (host, port, username, password) for primary node
        backup_nodes: List of (host, port, username, password) for backup nodes  
        strategy: Load balancing strategy
        
    Returns:
        Configured MultiNodeRPCClient
    """
    nodes = []
    
    # Add primary node
    host, port, username, password = primary_node
    primary_config = NodeConfig(
        node_id="primary",
        rpc_config=RPCConfig(host=host, port=port, username=username, password=password),
        node_type=NodeType.LOCAL,
        weight=2.0,  # Higher weight for primary
        priority=1
    )
    nodes.append(primary_config)
    
    # Add backup nodes
    if backup_nodes:
        for i, (host, port, username, password) in enumerate(backup_nodes):
            backup_config = NodeConfig(
                node_id=f"backup_{i+1}",
                rpc_config=RPCConfig(host=host, port=port, username=username, password=password),
                node_type=NodeType.REMOTE,
                weight=1.0,
                priority=2
            )
            nodes.append(backup_config)
    
    return MultiNodeRPCClient(nodes, strategy)


# Testing and CLI interface

def test_multi_node_client():
    """Test the multi-node RPC client."""
    print("Testing Multi-Node RPC Client...")
    print("=" * 50)
    
    try:
        # Create test node configurations
        primary_node = NodeConfig(
            node_id="test_primary",
            rpc_config=RPCConfig(host="localhost", port=8332, username="rpc", password="rpc"),
            node_type=NodeType.LOCAL,
            weight=2.0
        )
        
        backup_node = NodeConfig(
            node_id="test_backup", 
            rpc_config=RPCConfig(host="localhost", port=8333, username="rpc", password="rpc"),
            node_type=NodeType.REMOTE,
            weight=1.0
        )
        
        # Create client (this will fail connection but test structure)
        client = MultiNodeRPCClient([primary_node, backup_node])
        
        print(f"✓ Created multi-node client with {len(client.nodes)} nodes")
        
        # Test node selection
        available_nodes = client.get_available_nodes(OperationType.READ)
        print(f"✓ Available nodes for reads: {len(available_nodes)}")
        
        # Test statistics
        stats = client.get_node_statistics()
        print(f"✓ Node statistics: {stats['total_nodes']} total nodes")
        print(f"✓ Load balance strategy: {stats['load_balance_strategy']}")
        
        # Test node status
        for node_id in client.nodes:
            status = client.get_node_status(node_id)
            print(f"✓ Node {node_id} status: {status.value}")
        
        # Test circuit breaker
        cb_state = client._circuit_breakers["test_primary"]
        print(f"✓ Circuit breaker state: {cb_state.state}")
        
        print("\nMulti-node RPC client test completed successfully!")
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
        success = test_multi_node_client()
        sys.exit(0 if success else 1)
    
    else:
        print("Multi-Node RPC Client with Failover")
        print("Usage: python failover.py test")
        print("\nFeatures:")
        print("- Multiple Bitcoin node support with automatic failover")
        print("- Load balancing strategies: round-robin, weighted random, lowest latency")
        print("- Circuit breaker pattern to prevent cascading failures")
        print("- Health monitoring and node scoring")
        print("- Support for different node types: local, remote, public APIs")
        print("- Comprehensive statistics and performance monitoring")
        print("- Thread-safe operations with proper locking")