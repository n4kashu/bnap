"""
Pytest configuration and fixtures for BNAP tests.
"""

import pytest
import tempfile
import threading
import time
from pathlib import Path
from datetime import datetime

from registry.manager import RegistryManager
from registry.storage import RegistryStorage
from registry.schema import (
    FungibleAsset, NFTAsset, ValidatorConfig, 
    TransactionEntry, AssetType
)


@pytest.fixture(scope="session")
def test_data_dir():
    """Create temporary test data directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def registry_storage(test_data_dir):
    """Create registry storage for testing."""
    return RegistryStorage(storage_dir=test_data_dir)


@pytest.fixture
def registry_manager(test_data_dir):
    """Create registry manager for testing."""
    return RegistryManager(storage_dir=test_data_dir, enable_cache=True)


@pytest.fixture
def sample_assets():
    """Create sample assets for testing."""
    fungible = FungibleAsset(
        asset_id="1" * 64,
        name="Test Fungible Token",
        symbol="TFT",
        issuer_pubkey="a" * 64,
        maximum_supply=1000000,
        per_mint_limit=1000,
        decimal_places=2
    )
    
    nft = NFTAsset(
        asset_id="2" * 64,
        name="Test NFT Collection",
        symbol="TNFT",
        issuer_pubkey="b" * 64,
        collection_size=100,
        content_hash="c" * 64,
        manifest_hash="d" * 64
    )
    
    return {"fungible": fungible, "nft": nft}


@pytest.fixture
def sample_validators():
    """Create sample validators for testing."""
    primary = ValidatorConfig(
        validator_id="primary_validator",
        pubkey="e" * 64,
        permissions=["mint", "transfer", "burn"]
    )
    
    secondary = ValidatorConfig(
        validator_id="secondary_validator",
        pubkey="f" * 64,
        permissions=["mint"],
        is_active=False
    )
    
    return {"primary": primary, "secondary": secondary}


@pytest.fixture
def sample_transactions():
    """Create sample transaction entries for testing."""
    return [
        TransactionEntry(
            tx_id=f"{i:064d}",
            amount=100 * (i + 1),
            recipient=f"address_{i}",
            block_height=1000 + i
        )
        for i in range(5)
    ]


@pytest.fixture
def populated_registry(registry_manager, sample_assets, sample_validators, sample_transactions):
    """Create a registry populated with test data."""
    # Register validators
    for validator in sample_validators.values():
        registry_manager.register_validator(validator)
    
    # Register assets
    for asset in sample_assets.values():
        registry_manager.register_asset(asset)
    
    # Add some transaction history
    fungible_asset = sample_assets["fungible"]
    for i, tx in enumerate(sample_transactions[:3]):  # Add 3 transactions
        registry_manager.update_asset_state(fungible_asset.asset_id, tx)
    
    # Issue some NFTs
    nft_asset = sample_assets["nft"]
    for i in range(3):
        tx = TransactionEntry(
            tx_id=f"nft_{i:060d}",
            amount=1,
            recipient=f"nft_owner_{i}"
        )
        registry_manager.update_asset_state(nft_asset.asset_id, tx, nft_token_id=i + 1)
    
    return registry_manager


class ThreadSafeCounter:
    """Thread-safe counter for testing."""
    
    def __init__(self, initial_value: int = 0):
        self._value = initial_value
        self._lock = threading.Lock()
    
    def increment(self) -> int:
        with self._lock:
            self._value += 1
            return self._value
    
    def get_value(self) -> int:
        with self._lock:
            return self._value


@pytest.fixture
def thread_counter():
    """Create thread-safe counter for testing."""
    return ThreadSafeCounter()


@pytest.fixture
def performance_timer():
    """Create performance timer for benchmarking."""
    class PerformanceTimer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
        
        def start(self):
            self.start_time = time.perf_counter()
        
        def stop(self):
            self.end_time = time.perf_counter()
        
        def elapsed(self) -> float:
            if self.start_time is None or self.end_time is None:
                return 0.0
            return self.end_time - self.start_time
        
        def __enter__(self):
            self.start()
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            self.stop()
    
    return PerformanceTimer


# Test markers for different test categories
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as a performance test"
    )
    config.addinivalue_line(
        "markers", "concurrency: mark test as a concurrency test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


# Pytest collection hooks
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Add markers based on test file paths
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Add markers based on test names
        if "performance" in item.name or "benchmark" in item.name:
            item.add_marker(pytest.mark.performance)
            item.add_marker(pytest.mark.slow)
        
        if "concurrent" in item.name or "thread" in item.name:
            item.add_marker(pytest.mark.concurrency)
        
        if "slow" in item.name or "large" in item.name:
            item.add_marker(pytest.mark.slow)