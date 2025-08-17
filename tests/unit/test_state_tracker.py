"""
Unit tests for state tracking and supply management.
"""

import pytest
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from registry.state_tracker import (
    StateTracker, SupplyManager, AnalyticsEngine,
    VelocityCalculator, EventNotifier, SupplyThresholdExceeded,
    InvalidSupplyOperation, SupplyOverflowError
)
from registry.schema import (
    StateEntry, TransactionEntry, AssetType, FungibleAsset, NFTAsset
)


class TestStateTracker:
    """Test state tracking functionality."""
    
    @pytest.fixture
    def state_tracker(self):
        """Create state tracker instance."""
        return StateTracker()
    
    def test_state_tracker_initialization(self, state_tracker):
        """Test state tracker initialization."""
        assert state_tracker.states == {}
        assert state_tracker.event_notifier is not None
        assert state_tracker.analytics_engine is not None
    
    def test_create_state_entry(self, state_tracker):
        """Test creating new state entries."""
        asset_id = "a" * 64
        
        state = state_tracker.create_state(asset_id)
        
        assert isinstance(state, StateEntry)
        assert state.asset_id == asset_id
        assert state.minted_supply == 0
        assert state.transaction_count == 0
        assert len(state.transaction_history) == 0
        assert asset_id in state_tracker.states
    
    def test_get_existing_state(self, state_tracker):
        """Test retrieving existing state."""
        asset_id = "b" * 64
        
        # Create state
        original_state = state_tracker.create_state(asset_id)
        
        # Retrieve state
        retrieved_state = state_tracker.get_state(asset_id)
        
        assert retrieved_state is original_state
        assert retrieved_state.asset_id == asset_id
    
    def test_get_nonexistent_state(self, state_tracker):
        """Test retrieving non-existent state."""
        nonexistent_id = "nonexistent" + "0" * 54
        
        state = state_tracker.get_state(nonexistent_id)
        assert state is None
    
    def test_update_state_with_transaction(self, state_tracker):
        """Test updating state with transaction."""
        asset_id = "c" * 64
        state_tracker.create_state(asset_id)
        
        tx = TransactionEntry(
            tx_id="d" * 64,
            amount=100,
            recipient="recipient_address",
            block_height=1000
        )
        
        updated_state = state_tracker.update_state(asset_id, tx)
        
        assert updated_state.minted_supply == 100
        assert updated_state.transaction_count == 1
        assert len(updated_state.transaction_history) == 1
        assert updated_state.transaction_history[0] == tx
        assert updated_state.last_mint_timestamp is not None
    
    def test_update_nft_state(self, state_tracker):
        """Test updating NFT state with token ID."""
        asset_id = "e" * 64
        state_tracker.create_state(asset_id)
        
        tx = TransactionEntry(
            tx_id="f" * 64,
            amount=1,
            recipient="nft_owner",
            block_height=2000
        )
        
        updated_state = state_tracker.update_nft_state(asset_id, tx, nft_token_id=1)
        
        assert 1 in updated_state.issued_nft_ids
        assert updated_state.minted_supply == 1
        assert updated_state.transaction_count == 1
    
    def test_duplicate_nft_token_id(self, state_tracker):
        """Test duplicate NFT token ID handling."""
        asset_id = "g" * 64
        state_tracker.create_state(asset_id)
        
        tx1 = TransactionEntry(
            tx_id="h" * 64,
            amount=1,
            recipient="owner1"
        )
        
        tx2 = TransactionEntry(
            tx_id="i" * 64,
            amount=1,
            recipient="owner2"
        )
        
        # First NFT should succeed
        state_tracker.update_nft_state(asset_id, tx1, nft_token_id=1)
        
        # Duplicate NFT ID should fail
        with pytest.raises(ValueError, match="NFT token ID 1 already issued"):
            state_tracker.update_nft_state(asset_id, tx2, nft_token_id=1)
    
    def test_concurrent_state_updates(self, state_tracker):
        """Test concurrent state updates."""
        asset_id = "j" * 64
        state_tracker.create_state(asset_id)
        
        results = []
        errors = []
        
        def update_worker(worker_id):
            try:
                for i in range(10):
                    tx = TransactionEntry(
                        tx_id=f"worker_{worker_id}_{i:060d}",
                        amount=10,
                        recipient=f"address_{worker_id}_{i}"
                    )
                    state = state_tracker.update_state(asset_id, tx)
                    results.append(state.minted_supply)
            except Exception as e:
                errors.append(f"Worker {worker_id}: {str(e)}")
        
        # Start multiple worker threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=update_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(errors) == 0
        assert len(results) == 50  # 5 workers * 10 updates each
        
        # Verify final state
        final_state = state_tracker.get_state(asset_id)
        assert final_state.minted_supply == 500  # 5 * 10 * 10
        assert final_state.transaction_count == 50
    
    def test_get_all_states(self, state_tracker):
        """Test retrieving all states."""
        # Create multiple states
        asset_ids = [f"{i:064d}" for i in range(5)]
        
        for asset_id in asset_ids:
            state_tracker.create_state(asset_id)
        
        all_states = state_tracker.get_all_states()
        
        assert len(all_states) == 5
        assert all(isinstance(state, StateEntry) for state in all_states)
        assert set(state.asset_id for state in all_states) == set(asset_ids)
    
    def test_clear_state(self, state_tracker):
        """Test clearing individual state."""
        asset_id = "k" * 64
        state_tracker.create_state(asset_id)
        
        # Verify state exists
        assert state_tracker.get_state(asset_id) is not None
        
        # Clear state
        cleared = state_tracker.clear_state(asset_id)
        assert cleared
        
        # Verify state removed
        assert state_tracker.get_state(asset_id) is None
        assert asset_id not in state_tracker.states
    
    def test_clear_all_states(self, state_tracker):
        """Test clearing all states."""
        # Create multiple states
        for i in range(3):
            state_tracker.create_state(f"{i:064d}")
        
        # Verify states exist
        assert len(state_tracker.states) == 3
        
        # Clear all states
        cleared_count = state_tracker.clear_all_states()
        assert cleared_count == 3
        
        # Verify all states removed
        assert len(state_tracker.states) == 0


class TestSupplyManager:
    """Test supply management functionality."""
    
    @pytest.fixture
    def supply_manager(self):
        """Create supply manager instance."""
        return SupplyManager()
    
    def test_supply_manager_initialization(self, supply_manager):
        """Test supply manager initialization."""
        assert supply_manager.overflow_protection
        assert supply_manager.threshold_monitoring
        assert supply_manager.event_notifier is not None
    
    def test_check_mint_validity_fungible(self, supply_manager):
        """Test mint validity checking for fungible assets."""
        asset = FungibleAsset(
            asset_id="a" * 64,
            name="Test Token",
            symbol="TEST",
            issuer_pubkey="b" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        
        state = StateEntry(asset_id=asset.asset_id)
        
        # Valid mint
        is_valid, reason = supply_manager.check_mint_validity(asset, state, 50)
        assert is_valid
        assert reason is None
        
        # Exceeds per-mint limit
        is_valid, reason = supply_manager.check_mint_validity(asset, state, 150)
        assert not is_valid
        assert "per-mint limit" in reason
        
        # Would exceed maximum supply
        state.minted_supply = 950
        is_valid, reason = supply_manager.check_mint_validity(asset, state, 100)
        assert not is_valid
        assert "maximum supply" in reason
    
    def test_check_mint_validity_nft(self, supply_manager):
        """Test mint validity checking for NFT assets."""
        nft_asset = NFTAsset(
            asset_id="c" * 64,
            name="Test Collection",
            symbol="TESTNFT",
            issuer_pubkey="d" * 64,
            collection_size=10
        )
        
        state = StateEntry(asset_id=nft_asset.asset_id)
        
        # Valid NFT mint
        is_valid, reason = supply_manager.check_nft_mint_validity(
            nft_asset, state, nft_token_id=1
        )
        assert is_valid
        assert reason is None
        
        # Collection full
        state.issued_nft_ids = set(range(1, 11))  # All tokens issued
        is_valid, reason = supply_manager.check_nft_mint_validity(
            nft_asset, state, nft_token_id=11
        )
        assert not is_valid
        assert "collection is full" in reason
        
        # Duplicate token ID
        state.issued_nft_ids = {1, 2, 3}
        is_valid, reason = supply_manager.check_nft_mint_validity(
            nft_asset, state, nft_token_id=2
        )
        assert not is_valid
        assert "already issued" in reason
    
    def test_supply_overflow_protection(self, supply_manager):
        """Test supply overflow protection."""
        asset = FungibleAsset(
            asset_id="e" * 64,
            name="Overflow Test",
            symbol="OVF",
            issuer_pubkey="f" * 64,
            maximum_supply=2**63 - 1,  # Near max int
            per_mint_limit=2**62
        )
        
        state = StateEntry(asset_id=asset.asset_id)
        state.minted_supply = 2**62  # Already at half capacity
        
        # This would cause overflow
        with pytest.raises(SupplyOverflowError):
            supply_manager.check_mint_validity(asset, state, 2**62)
    
    def test_supply_analytics(self, supply_manager):
        """Test supply analytics calculation."""
        asset = FungibleAsset(
            asset_id="g" * 64,
            name="Analytics Test",
            symbol="ANL",
            issuer_pubkey="h" * 64,
            maximum_supply=10000,
            per_mint_limit=1000
        )
        
        state = StateEntry(asset_id=asset.asset_id)
        state.minted_supply = 2500
        state.transaction_count = 10
        
        analytics = supply_manager.get_supply_analytics(asset, state)
        
        assert analytics['current_supply'] == 2500
        assert analytics['maximum_supply'] == 10000
        assert analytics['remaining_supply'] == 7500
        assert analytics['supply_percentage'] == 25.0
        assert analytics['transaction_count'] == 10
        assert analytics['average_mint_size'] == 250.0  # 2500 / 10
    
    def test_threshold_monitoring(self, supply_manager):
        """Test supply threshold monitoring."""
        asset = FungibleAsset(
            asset_id="i" * 64,
            name="Threshold Test",
            symbol="THR",
            issuer_pubkey="j" * 64,
            maximum_supply=1000,
            per_mint_limit=100
        )
        
        # Set up threshold monitoring
        thresholds = [50.0, 75.0, 90.0]  # 50%, 75%, 90%
        supply_manager.set_supply_thresholds(asset.asset_id, thresholds)
        
        state = StateEntry(asset_id=asset.asset_id)
        
        # Test threshold triggering
        with patch.object(supply_manager.event_notifier, 'notify') as mock_notify:
            # Trigger 50% threshold
            state.minted_supply = 500
            supply_manager.check_supply_thresholds(asset, state)
            mock_notify.assert_called()
            
            # Reset mock
            mock_notify.reset_mock()
            
            # Trigger 75% threshold
            state.minted_supply = 750
            supply_manager.check_supply_thresholds(asset, state)
            mock_notify.assert_called()
    
    def test_supply_velocity_calculation(self, supply_manager):
        """Test supply velocity calculation."""
        velocity_calc = VelocityCalculator()
        
        # Create transaction history
        now = datetime.utcnow()
        transactions = []
        
        for i in range(10):
            tx = TransactionEntry(
                tx_id=f"{i:064d}",
                amount=100,
                recipient=f"address_{i}"
            )
            # Manually set timestamp for predictable velocity
            tx.timestamp = now - timedelta(minutes=i * 10)
            transactions.append(tx)
        
        # Calculate velocity (tokens per hour)
        velocity = velocity_calc.calculate_velocity(transactions, window_hours=2)
        
        # Should include transactions from last 2 hours (last 12 transactions)
        assert velocity > 0
        
        # Calculate daily velocity
        daily_velocity = velocity_calc.calculate_daily_velocity(transactions)
        assert daily_velocity > 0


class TestAnalyticsEngine:
    """Test analytics engine functionality."""
    
    @pytest.fixture
    def analytics_engine(self):
        """Create analytics engine instance."""
        return AnalyticsEngine()
    
    def test_analytics_initialization(self, analytics_engine):
        """Test analytics engine initialization."""
        assert analytics_engine.enabled
        assert analytics_engine.metrics == {}
        assert analytics_engine.aggregation_window == 3600  # 1 hour
    
    def test_record_metric(self, analytics_engine):
        """Test metric recording."""
        analytics_engine.record_metric("mint_count", 1)
        analytics_engine.record_metric("mint_count", 2)
        analytics_engine.record_metric("mint_volume", 1000)
        
        assert "mint_count" in analytics_engine.metrics
        assert "mint_volume" in analytics_engine.metrics
        assert len(analytics_engine.metrics["mint_count"]) == 2
        assert analytics_engine.metrics["mint_count"] == [1, 2]
    
    def test_calculate_statistics(self, analytics_engine):
        """Test statistics calculation."""
        # Record sample data
        values = [10, 20, 30, 40, 50]
        for value in values:
            analytics_engine.record_metric("test_metric", value)
        
        stats = analytics_engine.calculate_statistics("test_metric")
        
        assert stats['count'] == 5
        assert stats['sum'] == 150
        assert stats['mean'] == 30.0
        assert stats['min'] == 10
        assert stats['max'] == 50
        assert stats['std_dev'] > 0
    
    def test_get_metrics_summary(self, analytics_engine):
        """Test metrics summary generation."""
        # Record various metrics
        analytics_engine.record_metric("mints", 10)
        analytics_engine.record_metric("mints", 15)
        analytics_engine.record_metric("burns", 5)
        analytics_engine.record_metric("transfers", 25)
        
        summary = analytics_engine.get_metrics_summary()
        
        assert "mints" in summary
        assert "burns" in summary
        assert "transfers" in summary
        
        assert summary["mints"]["count"] == 2
        assert summary["mints"]["sum"] == 25
        assert summary["burns"]["count"] == 1
        assert summary["transfers"]["count"] == 1
    
    def test_time_series_analysis(self, analytics_engine):
        """Test time series analysis."""
        # Record timestamped metrics
        now = datetime.utcnow()
        
        for i in range(24):  # 24 hours of data
            timestamp = now - timedelta(hours=i)
            analytics_engine.record_timestamped_metric(
                "hourly_mints", 
                value=10 + i,  # Increasing trend
                timestamp=timestamp
            )
        
        # Analyze trend
        trend = analytics_engine.analyze_trend("hourly_mints", hours=24)
        
        assert trend['direction'] in ['increasing', 'decreasing', 'stable']
        assert 'slope' in trend
        assert 'r_squared' in trend
    
    def test_metric_aggregation(self, analytics_engine):
        """Test metric aggregation over time windows."""
        # Record metrics over time
        base_time = datetime.utcnow()
        
        for i in range(60):  # 60 minutes of data
            timestamp = base_time - timedelta(minutes=i)
            analytics_engine.record_timestamped_metric(
                "per_minute_mints",
                value=1,
                timestamp=timestamp
            )
        
        # Aggregate by hour
        hourly_aggregates = analytics_engine.aggregate_by_hour("per_minute_mints")
        
        assert len(hourly_aggregates) == 1  # Should be 1 hour bucket
        assert hourly_aggregates[0]['count'] == 60  # 60 minutes of data


class TestEventNotifier:
    """Test event notification functionality."""
    
    @pytest.fixture
    def event_notifier(self):
        """Create event notifier instance."""
        return EventNotifier()
    
    def test_event_notifier_initialization(self, event_notifier):
        """Test event notifier initialization."""
        assert event_notifier.enabled
        assert event_notifier.subscribers == {}
        assert event_notifier.event_history == []
    
    def test_subscribe_to_events(self, event_notifier):
        """Test event subscription."""
        callback_called = []
        
        def test_callback(event_data):
            callback_called.append(event_data)
        
        # Subscribe to events
        event_notifier.subscribe("supply_threshold", test_callback)
        
        # Notify event
        event_data = {"asset_id": "test", "threshold": 50.0}
        event_notifier.notify("supply_threshold", event_data)
        
        # Verify callback was called
        assert len(callback_called) == 1
        assert callback_called[0] == event_data
    
    def test_multiple_subscribers(self, event_notifier):
        """Test multiple subscribers for same event."""
        callbacks_called = {"callback1": [], "callback2": []}
        
        def callback1(event_data):
            callbacks_called["callback1"].append(event_data)
        
        def callback2(event_data):
            callbacks_called["callback2"].append(event_data)
        
        # Subscribe both callbacks
        event_notifier.subscribe("test_event", callback1)
        event_notifier.subscribe("test_event", callback2)
        
        # Notify event
        event_data = {"message": "test"}
        event_notifier.notify("test_event", event_data)
        
        # Both callbacks should be called
        assert len(callbacks_called["callback1"]) == 1
        assert len(callbacks_called["callback2"]) == 1
        assert callbacks_called["callback1"][0] == event_data
        assert callbacks_called["callback2"][0] == event_data
    
    def test_unsubscribe_from_events(self, event_notifier):
        """Test event unsubscription."""
        callback_called = []
        
        def test_callback(event_data):
            callback_called.append(event_data)
        
        # Subscribe and notify
        event_notifier.subscribe("test_event", test_callback)
        event_notifier.notify("test_event", {"test": 1})
        
        assert len(callback_called) == 1
        
        # Unsubscribe and notify again
        event_notifier.unsubscribe("test_event", test_callback)
        event_notifier.notify("test_event", {"test": 2})
        
        # Should not have been called again
        assert len(callback_called) == 1
    
    def test_event_history(self, event_notifier):
        """Test event history tracking."""
        # Notify several events
        event_notifier.notify("event1", {"data": "first"})
        event_notifier.notify("event2", {"data": "second"})
        event_notifier.notify("event1", {"data": "third"})
        
        # Check history
        history = event_notifier.get_event_history()
        assert len(history) == 3
        
        # Filter by event type
        event1_history = event_notifier.get_event_history(event_type="event1")
        assert len(event1_history) == 2
        
        # Recent events
        recent = event_notifier.get_recent_events(count=2)
        assert len(recent) == 2
    
    def test_error_handling_in_callbacks(self, event_notifier):
        """Test error handling in event callbacks."""
        successful_calls = []
        
        def failing_callback(event_data):
            raise ValueError("Callback error")
        
        def working_callback(event_data):
            successful_calls.append(event_data)
        
        # Subscribe both callbacks
        event_notifier.subscribe("test_event", failing_callback)
        event_notifier.subscribe("test_event", working_callback)
        
        # Notify event
        event_data = {"test": "data"}
        event_notifier.notify("test_event", event_data)
        
        # Working callback should still be called despite failing one
        assert len(successful_calls) == 1
        assert successful_calls[0] == event_data


class TestCustomExceptions:
    """Test custom exception classes."""
    
    def test_supply_threshold_exceeded(self):
        """Test SupplyThresholdExceeded exception."""
        exception = SupplyThresholdExceeded(
            asset_id="test_asset",
            current_supply=750,
            threshold=500,
            maximum_supply=1000
        )
        
        assert exception.asset_id == "test_asset"
        assert exception.current_supply == 750
        assert exception.threshold == 500
        assert exception.maximum_supply == 1000
        
        expected_message = (
            "Supply threshold exceeded for asset test_asset: "
            "current=750, threshold=500, maximum=1000"
        )
        assert str(exception) == expected_message
    
    def test_invalid_supply_operation(self):
        """Test InvalidSupplyOperation exception."""
        exception = InvalidSupplyOperation(
            operation="mint",
            asset_id="test_asset",
            reason="Exceeds per-mint limit"
        )
        
        assert exception.operation == "mint"
        assert exception.asset_id == "test_asset"
        assert exception.reason == "Exceeds per-mint limit"
        
        expected_message = (
            "Invalid supply operation 'mint' for asset test_asset: "
            "Exceeds per-mint limit"
        )
        assert str(exception) == expected_message
    
    def test_supply_overflow_error(self):
        """Test SupplyOverflowError exception."""
        exception = SupplyOverflowError(
            asset_id="test_asset",
            current_supply=2**62,
            additional_amount=2**62
        )
        
        assert exception.asset_id == "test_asset"
        assert exception.current_supply == 2**62
        assert exception.additional_amount == 2**62
        
        expected_message = (
            f"Supply overflow detected for asset test_asset: "
            f"current={2**62}, additional={2**62}"
        )
        assert str(exception) == expected_message