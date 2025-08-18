"""
Tests for BNAP Validator Registry Client

Comprehensive tests covering connection pooling, retry logic, caching,
and integration with the registry system.
"""

import pytest
import time
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from validator.registry_client import (
    RegistryClient,
    RegistryConnectionPool,
    RegistryCache,
    RegistryQuery,
    QueryResult,
    RegistryConnectionStatus,
    CacheStrategy,
    get_registry_client,
    configure_registry_client,
    get_asset_info,
    validate_asset_mint,
    update_mint_state
)
from registry.manager import RegistryManager, AssetNotFoundError
from registry.schema import Asset, AssetType, AssetStatus, StateEntry, TransactionEntry, FungibleAsset, NFTAsset


class TestRegistryConnectionPool:
    """Test connection pool functionality."""
    
    @patch('validator.registry_client.RegistryManager')
    def test_connection_pool_initialization(self, mock_registry_manager):
        """Test connection pool initialization."""
        mock_manager = Mock()
        mock_registry_manager.return_value = mock_manager
        
        pool = RegistryConnectionPool(pool_size=3)
        
        assert len(pool.connections) == 3
        assert pool.available_connections.qsize() == 3
        assert all(pool.connection_health.values())
    
    @patch('validator.registry_client.RegistryManager')
    def test_get_and_return_connection(self, mock_registry_manager):
        """Test getting and returning connections."""
        mock_manager = Mock()
        mock_registry_manager.return_value = mock_manager
        
        pool = RegistryConnectionPool(pool_size=2)
        
        # Get connection
        connection = pool.get_connection(timeout=1.0)
        assert connection is not None
        manager, connection_id = connection
        assert pool.available_connections.qsize() == 1
        
        # Return connection
        pool.return_connection(connection_id, healthy=True)
        assert pool.available_connections.qsize() == 2
    
    @patch('validator.registry_client.RegistryManager')
    def test_health_check(self, mock_registry_manager):
        """Test connection health checking."""
        mock_manager = Mock()
        mock_manager.get_registry_stats.return_value = {"total_assets": 5}
        mock_registry_manager.return_value = mock_manager
        
        pool = RegistryConnectionPool(pool_size=2, health_check_interval=0.1)
        
        # Trigger health check
        pool._health_check()
        
        # All connections should be healthy
        assert all(pool.connection_health.values())
    
    @patch('validator.registry_client.RegistryManager')
    def test_connection_recreation(self, mock_registry_manager):
        """Test recreation of failed connections."""
        mock_manager = Mock()
        mock_manager.get_registry_stats.side_effect = Exception("Connection failed")
        mock_registry_manager.return_value = mock_manager
        
        pool = RegistryConnectionPool(pool_size=1)
        
        # Simulate connection failure during health check
        pool._health_check()
        
        # Should attempt to recreate connection
        mock_registry_manager.assert_called()


class TestRegistryCache:
    """Test caching functionality."""
    
    def test_cache_basic_operations(self):
        """Test basic cache operations."""
        cache = RegistryCache(max_size=3, default_ttl=1.0)
        
        # Set values
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        
        # Get values
        assert cache.get("key1") == "value1"
        assert cache.get("key2") == "value2"
        assert cache.get("nonexistent") is None
        
        # Check stats
        stats = cache.get_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["size"] == 2
    
    def test_cache_ttl_expiration(self):
        """Test cache TTL expiration."""
        cache = RegistryCache(default_ttl=0.1)
        
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        
        # Wait for expiration
        time.sleep(0.15)
        assert cache.get("key1") is None
    
    def test_cache_lru_eviction(self):
        """Test LRU eviction when cache is full."""
        cache = RegistryCache(max_size=2, default_ttl=10.0)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        
        # Access key1 to make it more recently used
        cache.get("key1")
        
        # Add third item - should evict key2
        cache.set("key3", "value3")
        
        assert cache.get("key1") == "value1"
        assert cache.get("key3") == "value3"
        assert cache.get("key2") is None  # Should be evicted
    
    def test_cache_pattern_invalidation(self):
        """Test pattern-based cache invalidation."""
        cache = RegistryCache()
        
        cache.set("asset:123", "asset_data")
        cache.set("asset:456", "asset_data")
        cache.set("state:123", "state_data")
        cache.set("other:789", "other_data")
        
        # Invalidate asset-related entries
        invalidated = cache.invalidate_pattern("asset:")
        assert invalidated == 2
        
        assert cache.get("asset:123") is None
        assert cache.get("asset:456") is None
        assert cache.get("state:123") == "state_data"
        assert cache.get("other:789") == "other_data"


class TestRegistryClient:
    """Test registry client functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            "connection_pool_size": 2,
            "cache_strategy": "moderate",
            "cache_size": 100,
            "max_retries": 2,
            "enable_audit_logging": False
        }
    
    @patch('validator.registry_client.RegistryConnectionPool')
    @patch('validator.registry_client.RegistryCache')
    def test_client_initialization(self, mock_cache, mock_pool):
        """Test registry client initialization."""
        client = RegistryClient(self.config)
        
        assert client.connection_pool_size == 2
        assert client.cache_strategy == CacheStrategy.MODERATE
        assert client.status == RegistryConnectionStatus.CONNECTED
        
        mock_pool.assert_called_once()
        mock_cache.assert_called_once()
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_get_asset_success(self, mock_pool):
        """Test successful asset retrieval."""
        # Mock connection pool
        mock_manager = Mock()
        mock_asset = Mock()
        mock_manager.get_asset_by_id.return_value = mock_asset
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient(self.config)
        
        result = client.get_asset("asset_123")
        
        assert result == mock_asset
        mock_manager.get_asset_by_id.assert_called_once_with("asset_123")
        mock_pool.return_value.return_connection.assert_called_once_with(0, healthy=True)
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_get_asset_with_retry(self, mock_pool):
        """Test asset retrieval with retry logic."""
        # Mock connection pool
        mock_manager = Mock()
        mock_manager.get_asset_by_id.side_effect = [
            Exception("Temporary failure"),
            Exception("Another failure"),
            Mock()  # Success on third try
        ]
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient(self.config)
        
        with patch('time.sleep'):  # Speed up retries
            result = client.get_asset("asset_123")
        
        assert result is not None
        assert mock_manager.get_asset_by_id.call_count == 3
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_circuit_breaker_functionality(self, mock_pool):
        """Test circuit breaker opens after consecutive failures."""
        # Mock connection pool to always fail
        mock_manager = Mock()
        mock_manager.get_asset_by_id.side_effect = Exception("Connection failed")
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient({**self.config, "circuit_breaker_threshold": 2})
        
        with patch('time.sleep'):  # Speed up retries
            # First failure
            result1 = client.get_asset("asset_123")
            assert result1 is None
            assert client.consecutive_failures == 1
            
            # Second failure - should open circuit breaker
            result2 = client.get_asset("asset_456")
            assert result2 is None
            assert client.consecutive_failures >= 2
            assert client.is_circuit_breaker_open()
    
    @patch('validator.registry_client.RegistryConnectionPool')
    @patch('validator.registry_client.RegistryCache')
    def test_caching_behavior(self, mock_cache_class, mock_pool):
        """Test caching behavior for queries."""
        # Mock cache
        mock_cache = Mock()
        mock_cache.get.return_value = "cached_asset"
        mock_cache_class.return_value = mock_cache
        
        client = RegistryClient(self.config)
        
        # First call should hit cache
        result = client.get_asset("asset_123")
        
        assert result == "cached_asset"
        mock_cache.get.assert_called_once()
        
        # Should not hit the registry manager
        assert not mock_pool.return_value.get_connection.called
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_update_asset_state(self, mock_pool):
        """Test asset state update."""
        # Mock connection pool
        mock_manager = Mock()
        mock_manager.update_asset_state.return_value = "checksum_123"
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient(self.config)
        
        tx_entry = TransactionEntry(
            tx_id="tx_123",
            amount=1000,
            recipient="addr_123"
        )
        
        result = client.update_asset_state("asset_123", tx_entry)
        
        assert result is True
        mock_manager.update_asset_state.assert_called_once_with("asset_123", tx_entry, None)
    
    @patch('validator.registry_client.RegistryConnectionPool')
    @patch('validator.registry_client.RegistryCache')
    def test_cache_invalidation_on_update(self, mock_cache_class, mock_pool):
        """Test cache invalidation after state updates."""
        # Mock successful update
        mock_manager = Mock()
        mock_manager.update_asset_state.return_value = "checksum_123"
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        # Mock cache
        mock_cache = Mock()
        mock_cache_class.return_value = mock_cache
        
        client = RegistryClient(self.config)
        
        tx_entry = TransactionEntry(tx_id="tx_123", amount=1000, recipient="addr_123")
        
        result = client.update_asset_state("asset_123", tx_entry)
        
        assert result is True
        # Should invalidate cache entries related to the asset
        mock_cache.invalidate_pattern.assert_called_once_with("asset_123")
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_list_assets_with_pagination(self, mock_pool):
        """Test asset listing with pagination."""
        # Mock connection pool
        mock_manager = Mock()
        mock_assets = [Mock(), Mock(), Mock()]
        mock_manager.list_assets.return_value = mock_assets
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient(self.config)
        
        result = client.list_assets(
            asset_type=AssetType.FUNGIBLE,
            limit=10,
            offset=5
        )
        
        assert result == mock_assets
        mock_manager.list_assets.assert_called_once_with(
            asset_type=AssetType.FUNGIBLE,
            status=None,
            limit=10,
            offset=5
        )
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_connection_status_reporting(self, mock_pool):
        """Test connection status reporting."""
        # Mock pool stats
        mock_pool.return_value.get_pool_stats.return_value = {
            "total_connections": 2,
            "healthy_connections": 2,
            "available_connections": 1
        }
        
        client = RegistryClient(self.config)
        
        status = client.get_connection_status()
        
        assert status["status"] == RegistryConnectionStatus.CONNECTED.value
        assert "query_stats" in status
        assert "pool_stats" in status
        assert "config" in status
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_health_check(self, mock_pool):
        """Test health check functionality."""
        # Mock successful health check
        mock_manager = Mock()
        mock_manager.get_registry_stats.return_value = {"total_assets": 10}
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient(self.config)
        
        health_status = client.health_check()
        
        assert health_status["healthy"] is True
        assert health_status["registry_stats"]["total_assets"] == 10
        assert "response_time_ms" in health_status


class TestGlobalRegistryClient:
    """Test global registry client functionality."""
    
    def test_get_global_registry_client(self):
        """Test getting global registry client instance."""
        # Reset global instance
        import validator.registry_client
        validator.registry_client._global_registry_client = None
        
        client1 = get_registry_client()
        client2 = get_registry_client()
        
        # Should return same instance
        assert client1 is client2
        assert isinstance(client1, RegistryClient)
    
    def test_configure_global_registry_client(self):
        """Test configuring global registry client."""
        config = {"connection_pool_size": 10}
        
        client = configure_registry_client(config)
        
        assert client.connection_pool_size == 10
        assert get_registry_client() is client


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    @patch('validator.registry_client.get_registry_client')
    def test_get_asset_info(self, mock_get_client):
        """Test get_asset_info convenience function."""
        # Mock client
        mock_client = Mock()
        mock_asset = Mock()
        mock_supply_info = {"minted_supply": 1000}
        
        mock_client.get_asset.return_value = mock_asset
        mock_client.get_supply_info.return_value = mock_supply_info
        mock_get_client.return_value = mock_client
        
        result = get_asset_info("asset_123")
        
        assert result is not None
        assert result["asset"] == mock_asset
        assert result["supply_info"] == mock_supply_info
        assert "timestamp" in result
    
    @patch('validator.registry_client.get_registry_client')
    def test_validate_asset_mint_fungible(self, mock_get_client):
        """Test validate_asset_mint for fungible assets."""
        # Mock client
        mock_client = Mock()
        mock_client.get_supply_info.return_value = {
            "asset_type": AssetType.FUNGIBLE,
            "remaining_supply": 5000,
            "per_mint_limit": 1000
        }
        mock_get_client.return_value = mock_client
        
        # Valid mint
        is_valid, error = validate_asset_mint("asset_123", 500)
        assert is_valid is True
        assert error is None
        
        # Mint exceeds remaining supply
        is_valid, error = validate_asset_mint("asset_123", 6000)
        assert is_valid is False
        assert "remaining supply" in error
        
        # Mint exceeds per-mint limit
        is_valid, error = validate_asset_mint("asset_123", 1500)
        assert is_valid is False
        assert "per-mint limit" in error
    
    @patch('validator.registry_client.get_registry_client')
    def test_validate_asset_mint_nft(self, mock_get_client):
        """Test validate_asset_mint for NFT assets."""
        # Mock client
        mock_client = Mock()
        mock_client.get_supply_info.return_value = {
            "asset_type": AssetType.NFT,
            "available_nft_count": 10
        }
        mock_get_client.return_value = mock_client
        
        # Valid NFT mint
        is_valid, error = validate_asset_mint("nft_123", 1)
        assert is_valid is True
        assert error is None
        
        # Invalid amount for NFT
        is_valid, error = validate_asset_mint("nft_123", 5)
        assert is_valid is False
        assert "amount must be 1" in error
        
        # No available NFT slots
        mock_client.get_supply_info.return_value["available_nft_count"] = 0
        is_valid, error = validate_asset_mint("nft_123", 1)
        assert is_valid is False
        assert "No available NFT slots" in error
    
    @patch('validator.registry_client.get_registry_client')
    def test_update_mint_state(self, mock_get_client):
        """Test update_mint_state convenience function."""
        # Mock client
        mock_client = Mock()
        mock_client.update_asset_state.return_value = True
        mock_get_client.return_value = mock_client
        
        result = update_mint_state(
            asset_id="asset_123",
            tx_id="tx_456",
            amount=1000,
            recipient="addr_789"
        )
        
        assert result is True
        mock_client.update_asset_state.assert_called_once()
        
        # Check transaction entry was created correctly
        call_args = mock_client.update_asset_state.call_args
        tx_entry = call_args[0][1]  # Second argument is the TransactionEntry
        
        assert tx_entry.tx_id == "tx_456"
        assert tx_entry.amount == 1000
        assert tx_entry.recipient == "addr_789"


class TestQueryResult:
    """Test QueryResult data class."""
    
    def test_query_result_creation(self):
        """Test query result creation."""
        result = QueryResult(
            success=True,
            data={"test": "data"},
            query_time_ms=15.5,
            retry_count=1
        )
        
        assert result.success is True
        assert result.data == {"test": "data"}
        assert result.query_time_ms == 15.5
        assert result.retry_count == 1
        assert result.cached is False


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_high_load_scenario(self, mock_pool):
        """Test behavior under high load conditions."""
        # Mock connection pool with limited connections
        mock_manager = Mock()
        mock_manager.get_asset_by_id.return_value = Mock()
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient({"connection_pool_size": 2})
        
        # Simulate high load - many concurrent requests
        results = []
        for i in range(10):
            result = client.get_asset(f"asset_{i}")
            results.append(result)
        
        # All requests should complete successfully
        assert all(result is not None for result in results)
        assert mock_manager.get_asset_by_id.call_count == 10
    
    @patch('validator.registry_client.RegistryConnectionPool')
    def test_partial_failure_scenario(self, mock_pool):
        """Test behavior with partial system failures."""
        # Mock intermittent failures
        mock_manager = Mock()
        mock_manager.get_asset_by_id.side_effect = [
            Exception("Failure 1"),  # Fail
            Mock(),                  # Success
            Exception("Failure 2"),  # Fail
            Mock(),                  # Success
        ]
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient({
            "max_retries": 1,
            "circuit_breaker_threshold": 5
        })
        
        with patch('time.sleep'):  # Speed up retries
            results = []
            for i in range(4):
                result = client.get_asset(f"asset_{i}")
                results.append(result)
        
        # Should have 2 successful results (after retries)
        successful_results = [r for r in results if r is not None]
        assert len(successful_results) == 2
    
    @patch('validator.registry_client.RegistryConnectionPool')
    @patch('validator.registry_client.RegistryCache')
    def test_cache_effectiveness_scenario(self, mock_cache_class, mock_pool):
        """Test cache effectiveness in realistic usage patterns."""
        # Mock cache with realistic behavior
        cache_data = {}
        mock_cache = Mock()
        
        def cache_get(key):
            return cache_data.get(key)
        
        def cache_set(key, value, ttl=None):
            cache_data[key] = value
        
        mock_cache.get.side_effect = cache_get
        mock_cache.set.side_effect = cache_set
        mock_cache_class.return_value = mock_cache
        
        # Mock registry calls
        mock_manager = Mock()
        registry_call_count = 0
        
        def mock_get_asset(asset_id):
            nonlocal registry_call_count
            registry_call_count += 1
            return f"asset_data_{asset_id}"
        
        mock_manager.get_asset_by_id.side_effect = mock_get_asset
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient({"cache_strategy": "aggressive"})
        
        # First call - should hit registry and cache
        result1 = client.get_asset("popular_asset")
        assert registry_call_count == 1
        
        # Second call for same asset - should hit cache
        result2 = client.get_asset("popular_asset")
        assert result1 == result2
        assert registry_call_count == 1  # No additional registry call
        
        # Different asset - should hit registry again
        result3 = client.get_asset("other_asset")
        assert registry_call_count == 2


@pytest.fixture
def sample_fungible_asset():
    """Sample fungible asset for testing."""
    return FungibleAsset(
        asset_id="fungible_123",
        name="Test Token",
        symbol="TEST",
        issuer_pubkey="pubkey_123",
        maximum_supply=1000000,
        per_mint_limit=10000,
        decimal_places=8,
        asset_type=AssetType.FUNGIBLE,
        status=AssetStatus.ACTIVE
    )


@pytest.fixture
def sample_nft_asset():
    """Sample NFT asset for testing."""
    return NFTAsset(
        asset_id="nft_456",
        name="Test NFT Collection",
        symbol="TNFT",
        issuer_pubkey="pubkey_456",
        collection_size=1000,
        asset_type=AssetType.NFT,
        status=AssetStatus.ACTIVE,
        base_uri="https://example.com/metadata/"
    )


def test_registry_client_with_real_data(sample_fungible_asset, sample_nft_asset):
    """Test registry client with realistic asset data."""
    config = {
        "connection_pool_size": 1,
        "cache_strategy": "moderate",
        "enable_audit_logging": False
    }
    
    with patch('validator.registry_client.RegistryConnectionPool') as mock_pool:
        # Mock manager with realistic responses
        mock_manager = Mock()
        mock_manager.get_asset_by_id.side_effect = lambda aid: {
            "fungible_123": sample_fungible_asset,
            "nft_456": sample_nft_asset
        }.get(aid)
        
        mock_manager.get_supply_info.side_effect = lambda aid: {
            "fungible_123": {
                "asset_type": AssetType.FUNGIBLE,
                "minted_supply": 50000,
                "remaining_supply": 950000,
                "per_mint_limit": 10000
            },
            "nft_456": {
                "asset_type": AssetType.NFT,
                "issued_nft_count": 100,
                "available_nft_count": 900
            }
        }.get(aid)
        
        mock_pool.return_value.get_connection.return_value = (mock_manager, 0)
        
        client = RegistryClient(config)
        
        # Test fungible asset operations
        fungible_asset = client.get_asset("fungible_123")
        assert fungible_asset == sample_fungible_asset
        
        supply_info = client.get_supply_info("fungible_123")
        assert supply_info["remaining_supply"] == 950000
        
        # Test NFT asset operations
        nft_asset = client.get_asset("nft_456")
        assert nft_asset == sample_nft_asset
        
        nft_supply_info = client.get_supply_info("nft_456")
        assert nft_supply_info["available_nft_count"] == 900