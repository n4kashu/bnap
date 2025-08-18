"""
Registry Integration Layer for BNAP Validator

This module provides robust integration with the asset registry for state queries,
updates, and caching. Includes connection pooling, retry logic, and graceful
handling of registry unavailability.
"""

import asyncio
import logging
import time
import json
from concurrent.futures import ThreadPoolExecutor, Future
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock, Event
from queue import Queue, Empty
import hashlib

from registry.manager import RegistryManager, RegistryError, AssetNotFoundError
from registry.schema import Asset, AssetType, StateEntry, TransactionEntry, ValidatorConfig
from validator.audit_logger import AuditLogger, AuditEventType, AuditResult, log_registry_op
from validator.error_reporting import get_error_reporter, report_system_error


class RegistryConnectionStatus(Enum):
    """Registry connection status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"


class CacheStrategy(Enum):
    """Cache strategy options."""
    AGGRESSIVE = "aggressive"      # Cache everything with long TTL
    MODERATE = "moderate"          # Cache frequently accessed data
    CONSERVATIVE = "conservative"  # Minimal caching
    DISABLED = "disabled"          # No caching


@dataclass
class RegistryQuery:
    """Registry query with retry and timeout configuration."""
    operation: str
    params: Dict[str, Any]
    max_retries: int = 3
    timeout_seconds: float = 10.0
    cache_ttl: Optional[float] = None
    priority: int = 1  # Higher number = higher priority
    created_at: float = field(default_factory=time.time)


@dataclass
class QueryResult:
    """Registry query result with metadata."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    cached: bool = False
    query_time_ms: float = 0.0
    retry_count: int = 0
    timestamp: float = field(default_factory=time.time)


class RegistryConnectionPool:
    """Connection pool for registry managers with health checking."""
    
    def __init__(self, 
                 pool_size: int = 5,
                 health_check_interval: float = 30.0,
                 connection_timeout: float = 5.0):
        self.pool_size = pool_size
        self.health_check_interval = health_check_interval
        self.connection_timeout = connection_timeout
        
        self.connections: List[RegistryManager] = []
        self.available_connections = Queue(maxsize=pool_size)
        self.connection_health: Dict[int, bool] = {}
        self.last_health_check = 0.0
        self.lock = RLock()
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize connections
        self._initialize_connections()
    
    def _initialize_connections(self):
        """Initialize connection pool."""
        for i in range(self.pool_size):
            try:
                manager = RegistryManager()
                self.connections.append(manager)
                self.available_connections.put(i)
                self.connection_health[i] = True
                self.logger.debug(f"Initialized registry connection {i}")
            except Exception as e:
                self.logger.error(f"Failed to initialize registry connection {i}: {e}")
                self.connection_health[i] = False
    
    def get_connection(self, timeout: float = 5.0) -> Optional[Tuple[RegistryManager, int]]:
        """Get an available connection from the pool."""
        try:
            # Check if health check is needed
            current_time = time.time()
            if current_time - self.last_health_check > self.health_check_interval:
                self._health_check()
            
            # Get available connection
            connection_id = self.available_connections.get(timeout=timeout)
            manager = self.connections[connection_id]
            
            return manager, connection_id
            
        except Empty:
            self.logger.warning("No available registry connections")
            return None
        except Exception as e:
            self.logger.error(f"Error getting registry connection: {e}")
            return None
    
    def return_connection(self, connection_id: int, healthy: bool = True):
        """Return connection to the pool."""
        try:
            self.connection_health[connection_id] = healthy
            if healthy:
                self.available_connections.put(connection_id)
            else:
                self.logger.warning(f"Connection {connection_id} returned as unhealthy")
                # Try to recreate the connection
                self._recreate_connection(connection_id)
        except Exception as e:
            self.logger.error(f"Error returning registry connection {connection_id}: {e}")
    
    def _health_check(self):
        """Perform health check on all connections."""
        with self.lock:
            self.last_health_check = time.time()
            
            for connection_id, manager in enumerate(self.connections):
                try:
                    # Simple health check - get registry stats
                    stats = manager.get_registry_stats()
                    self.connection_health[connection_id] = True
                except Exception as e:
                    self.logger.warning(f"Connection {connection_id} health check failed: {e}")
                    self.connection_health[connection_id] = False
                    self._recreate_connection(connection_id)
    
    def _recreate_connection(self, connection_id: int):
        """Recreate a failed connection."""
        try:
            new_manager = RegistryManager()
            self.connections[connection_id] = new_manager
            self.connection_health[connection_id] = True
            self.available_connections.put(connection_id)
            self.logger.info(f"Recreated registry connection {connection_id}")
        except Exception as e:
            self.logger.error(f"Failed to recreate connection {connection_id}: {e}")
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        healthy_count = sum(1 for healthy in self.connection_health.values() if healthy)
        available_count = self.available_connections.qsize()
        
        return {
            "total_connections": len(self.connections),
            "healthy_connections": healthy_count,
            "available_connections": available_count,
            "last_health_check": self.last_health_check,
            "connection_health": dict(self.connection_health)
        }


class RegistryCache:
    """Enhanced caching layer with TTL, LRU eviction, and cache statistics."""
    
    def __init__(self, 
                 max_size: int = 10000,
                 default_ttl: float = 300.0,
                 cleanup_interval: float = 60.0):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.access_times: Dict[str, float] = {}
        self.last_cleanup = time.time()
        self.lock = RLock()
        
        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "cleanups": 0,
            "size": 0
        }
        
        self.logger = logging.getLogger(__name__)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self.lock:
            if key not in self.cache:
                self.stats["misses"] += 1
                return None
            
            entry = self.cache[key]
            
            # Check if expired
            if time.time() - entry["created_at"] > entry["ttl"]:
                del self.cache[key]
                self.access_times.pop(key, None)
                self.stats["misses"] += 1
                self.stats["size"] = len(self.cache)
                return None
            
            # Update access time for LRU
            self.access_times[key] = time.time()
            self.stats["hits"] += 1
            
            return entry["value"]
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache."""
        with self.lock:
            ttl = ttl or self.default_ttl
            
            # Check if cleanup is needed
            if time.time() - self.last_cleanup > self.cleanup_interval:
                self._cleanup_expired()
            
            # Evict if at capacity
            if len(self.cache) >= self.max_size and key not in self.cache:
                self._evict_lru()
            
            self.cache[key] = {
                "value": value,
                "created_at": time.time(),
                "ttl": ttl
            }
            self.access_times[key] = time.time()
            self.stats["size"] = len(self.cache)
    
    def invalidate(self, key: str) -> bool:
        """Invalidate specific cache entry."""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                self.access_times.pop(key, None)
                self.stats["size"] = len(self.cache)
                return True
            return False
    
    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate keys matching pattern."""
        with self.lock:
            keys_to_remove = [k for k in self.cache.keys() if pattern in k]
            for key in keys_to_remove:
                del self.cache[key]
                self.access_times.pop(key, None)
            
            self.stats["size"] = len(self.cache)
            return len(keys_to_remove)
    
    def _cleanup_expired(self) -> int:
        """Clean up expired entries."""
        current_time = time.time()
        expired_keys = []
        
        for key, entry in self.cache.items():
            if current_time - entry["created_at"] > entry["ttl"]:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.cache[key]
            self.access_times.pop(key, None)
        
        self.last_cleanup = current_time
        self.stats["cleanups"] += 1
        self.stats["size"] = len(self.cache)
        
        return len(expired_keys)
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self.access_times:
            return
        
        lru_key = min(self.access_times, key=self.access_times.get)
        del self.cache[lru_key]
        del self.access_times[lru_key]
        self.stats["evictions"] += 1
        self.stats["size"] = len(self.cache)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                **self.stats,
                "hit_rate_percent": hit_rate,
                "max_size": self.max_size,
                "default_ttl": self.default_ttl
            }


class RegistryClient:
    """
    Robust registry integration client with connection pooling, retry logic,
    caching, and graceful degradation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize registry client.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Connection configuration
        self.connection_pool_size = self.config.get("connection_pool_size", 5)
        self.connection_timeout = self.config.get("connection_timeout", 5.0)
        self.max_retries = self.config.get("max_retries", 3)
        self.retry_delay = self.config.get("retry_delay", 1.0)
        self.health_check_interval = self.config.get("health_check_interval", 30.0)
        
        # Cache configuration
        self.cache_strategy = CacheStrategy(self.config.get("cache_strategy", "moderate"))
        self.cache_size = self.config.get("cache_size", 10000)
        self.default_cache_ttl = self.config.get("default_cache_ttl", 300.0)
        
        # Circuit breaker configuration
        self.circuit_breaker_threshold = self.config.get("circuit_breaker_threshold", 10)
        self.circuit_breaker_timeout = self.config.get("circuit_breaker_timeout", 60.0)
        
        # Initialize components
        self.connection_pool = RegistryConnectionPool(
            pool_size=self.connection_pool_size,
            health_check_interval=self.health_check_interval,
            connection_timeout=self.connection_timeout
        )
        
        self.cache = None
        if self.cache_strategy != CacheStrategy.DISABLED:
            self.cache = RegistryCache(
                max_size=self.cache_size,
                default_ttl=self.default_cache_ttl
            )
        
        # State tracking
        self.status = RegistryConnectionStatus.CONNECTED
        self.consecutive_failures = 0
        self.circuit_breaker_opened_at = None
        self.query_stats = {
            "total_queries": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "cached_queries": 0,
            "avg_query_time_ms": 0.0
        }
        
        # Audit logging
        self.audit_logger = AuditLogger() if self.config.get("enable_audit_logging", True) else None
        self.error_reporter = get_error_reporter()
        
        self.logger.info("RegistryClient initialized successfully")
    
    def is_circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open."""
        if self.circuit_breaker_opened_at is None:
            return False
        
        if time.time() - self.circuit_breaker_opened_at > self.circuit_breaker_timeout:
            self.circuit_breaker_opened_at = None
            self.consecutive_failures = 0
            self.status = RegistryConnectionStatus.CONNECTED
            self.logger.info("Circuit breaker closed - attempting reconnection")
            return False
        
        return True
    
    def _execute_query(self, query: RegistryQuery) -> QueryResult:
        """Execute a registry query with retry logic."""
        start_time = time.time()
        
        # Check circuit breaker
        if self.is_circuit_breaker_open():
            return QueryResult(
                success=False,
                error="Circuit breaker is open - registry unavailable",
                query_time_ms=(time.time() - start_time) * 1000
            )
        
        # Try cache first
        cache_key = self._generate_cache_key(query.operation, query.params)
        if self.cache and query.operation.startswith(("get_", "list_", "find_")):
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                self.query_stats["cached_queries"] += 1
                return QueryResult(
                    success=True,
                    data=cached_result,
                    cached=True,
                    query_time_ms=(time.time() - start_time) * 1000
                )
        
        # Execute query with retries
        last_error = None
        for retry in range(query.max_retries + 1):
            try:
                # Get connection from pool
                connection = self.connection_pool.get_connection(timeout=query.timeout_seconds)
                if not connection:
                    raise Exception("No available registry connections")
                
                manager, connection_id = connection
                
                try:
                    # Execute the operation
                    result = self._execute_operation(manager, query.operation, query.params)
                    
                    # Cache successful result
                    if self.cache and query.operation.startswith(("get_", "list_", "find_")):
                        cache_ttl = query.cache_ttl or self._get_cache_ttl(query.operation)
                        self.cache.set(cache_key, result, cache_ttl)
                    
                    # Return connection as healthy
                    self.connection_pool.return_connection(connection_id, healthy=True)
                    
                    # Update stats
                    self.consecutive_failures = 0
                    self.query_stats["successful_queries"] += 1
                    
                    query_time_ms = (time.time() - start_time) * 1000
                    self._update_avg_query_time(query_time_ms)
                    
                    return QueryResult(
                        success=True,
                        data=result,
                        query_time_ms=query_time_ms,
                        retry_count=retry
                    )
                
                except Exception as e:
                    # Return connection as unhealthy
                    self.connection_pool.return_connection(connection_id, healthy=False)
                    raise e
                
            except Exception as e:
                last_error = str(e)
                self.logger.warning(f"Registry query failed (attempt {retry + 1}): {e}")
                
                if retry < query.max_retries:
                    time.sleep(self.retry_delay * (2 ** retry))  # Exponential backoff
        
        # All retries failed
        self.consecutive_failures += 1
        self.query_stats["failed_queries"] += 1
        
        # Open circuit breaker if threshold reached
        if self.consecutive_failures >= self.circuit_breaker_threshold:
            self.circuit_breaker_opened_at = time.time()
            self.status = RegistryConnectionStatus.FAILED
            self.logger.error("Circuit breaker opened due to consecutive failures")
        
        return QueryResult(
            success=False,
            error=last_error,
            query_time_ms=(time.time() - start_time) * 1000,
            retry_count=query.max_retries
        )
    
    def _execute_operation(self, manager: RegistryManager, operation: str, params: Dict[str, Any]) -> Any:
        """Execute specific operation on registry manager."""
        if operation == "get_asset_by_id":
            return manager.get_asset_by_id(params["asset_id"])
        
        elif operation == "get_asset_state":
            return manager.get_asset_state(params["asset_id"])
        
        elif operation == "get_asset_supply_info":
            return manager.get_asset_supply_info(params["asset_id"])
        
        elif operation == "list_assets":
            return manager.list_assets(
                asset_type=params.get("asset_type"),
                status=params.get("status"),
                limit=params.get("limit"),
                offset=params.get("offset", 0)
            )
        
        elif operation == "find_assets_by_issuer":
            return manager.find_assets_by_issuer(params["issuer_pubkey"])
        
        elif operation == "find_assets_by_symbol":
            return manager.find_assets_by_symbol(params["symbol"])
        
        elif operation == "get_validator":
            return manager.get_validator(params["validator_id"])
        
        elif operation == "register_asset":
            return manager.register_asset(params["asset"])
        
        elif operation == "register_validator":
            return manager.register_validator(params["validator"])
        
        elif operation == "update_asset_state":
            return manager.update_asset_state(
                params["asset_id"],
                params["tx_entry"],
                params.get("nft_token_id")
            )
        
        elif operation == "get_registry_stats":
            return manager.get_registry_stats()
        
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    def _generate_cache_key(self, operation: str, params: Dict[str, Any]) -> str:
        """Generate cache key for operation and parameters."""
        # Create consistent cache key
        param_str = json.dumps(params, sort_keys=True, default=str)
        key_data = f"{operation}:{param_str}".encode('utf-8')
        return hashlib.sha256(key_data).hexdigest()[:16]
    
    def _get_cache_ttl(self, operation: str) -> float:
        """Get appropriate cache TTL for operation type."""
        if self.cache_strategy == CacheStrategy.AGGRESSIVE:
            return self.default_cache_ttl * 2
        elif self.cache_strategy == CacheStrategy.CONSERVATIVE:
            return self.default_cache_ttl / 2
        else:
            return self.default_cache_ttl
    
    def _update_avg_query_time(self, query_time_ms: float) -> None:
        """Update average query time."""
        total_queries = self.query_stats["total_queries"]
        current_avg = self.query_stats["avg_query_time_ms"]
        
        self.query_stats["avg_query_time_ms"] = (
            (current_avg * total_queries + query_time_ms) / (total_queries + 1)
        )
        self.query_stats["total_queries"] += 1
    
    # Public API methods
    
    def get_asset(self, asset_id: str, use_cache: bool = True) -> Optional[Asset]:
        """
        Get asset by ID.
        
        Args:
            asset_id: Asset identifier
            use_cache: Whether to use cache for this query
            
        Returns:
            Asset object or None if not found
        """
        query = RegistryQuery(
            operation="get_asset_by_id",
            params={"asset_id": asset_id},
            cache_ttl=self._get_cache_ttl("get_asset_by_id") if use_cache else 0
        )
        
        result = self._execute_query(query)
        
        if self.audit_logger:
            self.audit_logger.log_registry_operation(
                operation="get_asset",
                asset_id=asset_id,
                result=AuditResult.APPROVED if result.success else AuditResult.ERROR,
                context={
                    "cached": result.cached,
                    "query_time_ms": result.query_time_ms,
                    "retry_count": result.retry_count
                }
            )
        
        return result.data if result.success else None
    
    def get_asset_state(self, asset_id: str, use_cache: bool = True) -> Optional[StateEntry]:
        """
        Get asset state by ID.
        
        Args:
            asset_id: Asset identifier
            use_cache: Whether to use cache for this query
            
        Returns:
            StateEntry object or None if not found
        """
        query = RegistryQuery(
            operation="get_asset_state",
            params={"asset_id": asset_id},
            cache_ttl=self._get_cache_ttl("get_asset_state") if use_cache else 0
        )
        
        result = self._execute_query(query)
        return result.data if result.success else None
    
    def get_supply_info(self, asset_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive supply information for an asset.
        
        Args:
            asset_id: Asset identifier
            use_cache: Whether to use cache for this query
            
        Returns:
            Supply information dictionary or None if asset not found
        """
        query = RegistryQuery(
            operation="get_asset_supply_info",
            params={"asset_id": asset_id},
            cache_ttl=self._get_cache_ttl("get_asset_supply_info") if use_cache else 0
        )
        
        result = self._execute_query(query)
        return result.data if result.success else None
    
    def update_asset_state(self, 
                          asset_id: str, 
                          tx_entry: TransactionEntry,
                          nft_token_id: Optional[int] = None) -> bool:
        """
        Update asset state after successful validation.
        
        Args:
            asset_id: Asset identifier
            tx_entry: Transaction entry to add
            nft_token_id: NFT token ID (for NFT assets)
            
        Returns:
            True if update was successful
        """
        query = RegistryQuery(
            operation="update_asset_state",
            params={
                "asset_id": asset_id,
                "tx_entry": tx_entry,
                "nft_token_id": nft_token_id
            },
            max_retries=1,  # State updates should not be retried aggressively
            cache_ttl=0  # Never cache state updates
        )
        
        result = self._execute_query(query)
        
        if result.success:
            # Invalidate related cache entries
            if self.cache:
                self.cache.invalidate_pattern(asset_id)
        
        if self.audit_logger:
            self.audit_logger.log_registry_operation(
                operation="update_asset_state",
                asset_id=asset_id,
                result=AuditResult.APPROVED if result.success else AuditResult.ERROR,
                context={
                    "amount": tx_entry.amount,
                    "nft_token_id": nft_token_id,
                    "query_time_ms": result.query_time_ms
                }
            )
        
        return result.success
    
    def list_assets(self, 
                   asset_type: Optional[AssetType] = None,
                   status: Optional[str] = None,
                   limit: Optional[int] = None,
                   offset: int = 0,
                   use_cache: bool = True) -> List[Asset]:
        """
        List assets with filtering and pagination.
        
        Args:
            asset_type: Filter by asset type
            status: Filter by asset status
            limit: Maximum number of results
            offset: Pagination offset
            use_cache: Whether to use cache for this query
            
        Returns:
            List of assets
        """
        query = RegistryQuery(
            operation="list_assets",
            params={
                "asset_type": asset_type,
                "status": status,
                "limit": limit,
                "offset": offset
            },
            cache_ttl=self._get_cache_ttl("list_assets") if use_cache else 0
        )
        
        result = self._execute_query(query)
        return result.data if result.success else []
    
    def get_validator_config(self, validator_id: str) -> Optional[ValidatorConfig]:
        """
        Get validator configuration.
        
        Args:
            validator_id: Validator identifier
            
        Returns:
            ValidatorConfig object or None if not found
        """
        query = RegistryQuery(
            operation="get_validator",
            params={"validator_id": validator_id},
            cache_ttl=self._get_cache_ttl("get_validator")
        )
        
        result = self._execute_query(query)
        return result.data if result.success else None
    
    def register_asset(self, asset: Asset) -> bool:
        """
        Register a new asset.
        
        Args:
            asset: Asset to register
            
        Returns:
            True if registration was successful
        """
        query = RegistryQuery(
            operation="register_asset",
            params={"asset": asset},
            max_retries=1,  # Registration should not be retried aggressively
            cache_ttl=0  # Never cache registration operations
        )
        
        result = self._execute_query(query)
        
        if result.success and self.cache:
            # Clear relevant caches after registration
            self.cache.invalidate_pattern("list_")
            self.cache.invalidate_pattern("find_")
        
        return result.success
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get comprehensive connection status information."""
        pool_stats = self.connection_pool.get_pool_stats()
        cache_stats = self.cache.get_stats() if self.cache else {}
        
        return {
            "status": self.status.value,
            "circuit_breaker_open": self.is_circuit_breaker_open(),
            "consecutive_failures": self.consecutive_failures,
            "query_stats": self.query_stats,
            "pool_stats": pool_stats,
            "cache_stats": cache_stats,
            "config": {
                "cache_strategy": self.cache_strategy.value,
                "connection_pool_size": self.connection_pool_size,
                "max_retries": self.max_retries
            }
        }
    
    def invalidate_cache(self, pattern: Optional[str] = None) -> int:
        """
        Invalidate cache entries.
        
        Args:
            pattern: Pattern to match for invalidation (None = clear all)
            
        Returns:
            Number of entries invalidated
        """
        if not self.cache:
            return 0
        
        if pattern:
            return self.cache.invalidate_pattern(pattern)
        else:
            count = len(self.cache.cache)
            self.cache.cache.clear()
            self.cache.access_times.clear()
            self.cache.stats["size"] = 0
            return count
    
    def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        start_time = time.time()
        
        try:
            # Test basic registry connectivity
            query = RegistryQuery(
                operation="get_registry_stats",
                params={},
                timeout_seconds=5.0,
                max_retries=1,
                cache_ttl=0
            )
            
            result = self._execute_query(query)
            
            health_status = {
                "healthy": result.success,
                "response_time_ms": result.query_time_ms,
                "connection_status": self.status.value,
                "circuit_breaker_open": self.is_circuit_breaker_open(),
                "registry_stats": result.data if result.success else None,
                "error": result.error if not result.success else None,
                "timestamp": time.time()
            }
            
            return health_status
            
        except Exception as e:
            return {
                "healthy": False,
                "response_time_ms": (time.time() - start_time) * 1000,
                "connection_status": RegistryConnectionStatus.FAILED.value,
                "error": str(e),
                "timestamp": time.time()
            }


# Global registry client instance (singleton pattern)
_global_registry_client: Optional[RegistryClient] = None


def get_registry_client() -> RegistryClient:
    """Get the global registry client instance."""
    global _global_registry_client
    if _global_registry_client is None:
        _global_registry_client = RegistryClient()
    return _global_registry_client


def configure_registry_client(config: Dict[str, Any]) -> RegistryClient:
    """Configure the global registry client."""
    global _global_registry_client
    _global_registry_client = RegistryClient(config)
    return _global_registry_client


# Convenience functions for common registry operations

def get_asset_info(asset_id: str) -> Optional[Dict[str, Any]]:
    """Get comprehensive asset information including supply data."""
    client = get_registry_client()
    
    asset = client.get_asset(asset_id)
    if not asset:
        return None
    
    supply_info = client.get_supply_info(asset_id)
    
    return {
        "asset": asset,
        "supply_info": supply_info,
        "timestamp": time.time()
    }


def validate_asset_mint(asset_id: str, amount: int) -> Tuple[bool, Optional[str]]:
    """
    Validate if an asset mint is allowed based on current registry state.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    client = get_registry_client()
    
    try:
        supply_info = client.get_supply_info(asset_id)
        if not supply_info:
            return False, f"Asset {asset_id} not found in registry"
        
        if supply_info["asset_type"] == AssetType.FUNGIBLE:
            # Check supply limits
            remaining_supply = supply_info.get("remaining_supply", 0)
            if amount > remaining_supply:
                return False, f"Mint amount {amount} exceeds remaining supply {remaining_supply}"
            
            # Check per-mint limits
            per_mint_limit = supply_info.get("per_mint_limit")
            if per_mint_limit and amount > per_mint_limit:
                return False, f"Mint amount {amount} exceeds per-mint limit {per_mint_limit}"
        
        elif supply_info["asset_type"] == AssetType.NFT:
            # For NFTs, amount should be 1 and there should be available slots
            if amount != 1:
                return False, "NFT mint amount must be 1"
            
            available_count = supply_info.get("available_nft_count", 0)
            if available_count <= 0:
                return False, "No available NFT slots in collection"
        
        return True, None
        
    except Exception as e:
        return False, f"Error validating mint: {e}"


def update_mint_state(asset_id: str, tx_id: str, amount: int, recipient: str, nft_token_id: Optional[int] = None) -> bool:
    """
    Update registry state after successful mint validation.
    
    Args:
        asset_id: Asset identifier
        tx_id: Transaction ID
        amount: Minted amount
        recipient: Recipient address
        nft_token_id: NFT token ID (for NFT mints)
        
    Returns:
        True if update was successful
    """
    client = get_registry_client()
    
    try:
        tx_entry = TransactionEntry(
            tx_id=tx_id,
            amount=amount,
            recipient=recipient
        )
        
        return client.update_asset_state(asset_id, tx_entry, nft_token_id)
        
    except Exception as e:
        report_system_error("registry_client", "update_mint_state", e)
        return False