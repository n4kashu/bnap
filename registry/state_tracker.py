"""
Bitcoin Native Asset Protocol - State Tracking and Supply Management

This module provides state management for tracking minted amounts, enforcing
supply caps, maintaining issuance history, and providing analytics.
"""

import time
from datetime import datetime, timedelta
from enum import Enum
from threading import RLock
from typing import Dict, List, Optional, Tuple, Union, Any, Callable

from .schema import (
    Asset, AssetType, FungibleAsset, NFTAsset, 
    StateEntry, TransactionEntry
)


class SupplyEvent(str, Enum):
    """Supply-related event types."""
    MINT_ALLOWED = "mint_allowed"
    MINT_DENIED = "mint_denied"
    SUPPLY_WARNING = "supply_warning"
    SUPPLY_EXHAUSTED = "supply_exhausted"
    MINT_LIMIT_REACHED = "mint_limit_reached"


class MintValidationResult:
    """Result of mint validation check."""
    
    def __init__(
        self,
        allowed: bool,
        reason: str = "",
        event_type: SupplyEvent = SupplyEvent.MINT_ALLOWED,
        remaining_supply: int = 0,
        utilization_percent: float = 0.0
    ):
        self.allowed = allowed
        self.reason = reason
        self.event_type = event_type
        self.remaining_supply = remaining_supply
        self.utilization_percent = utilization_percent
        self.timestamp = datetime.utcnow()


class SupplyAnalytics:
    """Supply analytics and reporting."""
    
    def __init__(self, asset: Asset, state: StateEntry):
        self.asset = asset
        self.state = state
        self._calculate_metrics()
    
    def _calculate_metrics(self) -> None:
        """Calculate key supply metrics."""
        if isinstance(self.asset, FungibleAsset):
            self.total_supply = self.asset.maximum_supply
            self.minted_supply = self.state.minted_supply
            self.remaining_supply = self.total_supply - self.minted_supply
            self.utilization_percent = (self.minted_supply / self.total_supply) * 100
            self.is_exhausted = self.remaining_supply <= 0
            
        elif isinstance(self.asset, NFTAsset):
            self.total_supply = self.asset.collection_size
            self.minted_supply = len(self.state.issued_nft_ids)
            self.remaining_supply = self.total_supply - self.minted_supply
            self.utilization_percent = (self.minted_supply / self.total_supply) * 100
            self.is_exhausted = self.remaining_supply <= 0
    
    def get_utilization_band(self) -> str:
        """Get utilization band (low/medium/high/exhausted)."""
        if self.is_exhausted:
            return "exhausted"
        elif self.utilization_percent >= 90:
            return "high"
        elif self.utilization_percent >= 50:
            return "medium"
        else:
            return "low"
    
    def get_velocity_metrics(self, period_days: int = 30) -> Dict[str, float]:
        """Calculate minting velocity over specified period."""
        cutoff_date = datetime.utcnow() - timedelta(days=period_days)
        
        recent_transactions = [
            tx for tx in self.state.transaction_history
            if tx.timestamp >= cutoff_date
        ]
        
        total_amount = sum(tx.amount for tx in recent_transactions)
        tx_count = len(recent_transactions)
        
        # Calculate daily averages
        daily_amount = total_amount / period_days if period_days > 0 else 0
        daily_tx_count = tx_count / period_days if period_days > 0 else 0
        
        return {
            'period_days': period_days,
            'total_amount': total_amount,
            'transaction_count': tx_count,
            'daily_amount_avg': daily_amount,
            'daily_tx_count_avg': daily_tx_count,
            'avg_amount_per_tx': total_amount / tx_count if tx_count > 0 else 0
        }
    
    def predict_exhaustion(self) -> Optional[datetime]:
        """Predict when supply will be exhausted based on recent velocity."""
        if self.is_exhausted:
            return None
        
        velocity = self.get_velocity_metrics(30)
        daily_rate = velocity['daily_amount_avg']
        
        if daily_rate <= 0:
            return None  # No recent activity
        
        days_to_exhaustion = self.remaining_supply / daily_rate
        return datetime.utcnow() + timedelta(days=days_to_exhaustion)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analytics to dictionary."""
        return {
            'asset_id': self.asset.asset_id,
            'asset_type': self.asset.asset_type,
            'total_supply': self.total_supply,
            'minted_supply': self.minted_supply,
            'remaining_supply': self.remaining_supply,
            'utilization_percent': round(self.utilization_percent, 2),
            'utilization_band': self.get_utilization_band(),
            'is_exhausted': self.is_exhausted,
            'transaction_count': self.state.transaction_count,
            'last_mint_timestamp': self.state.last_mint_timestamp,
            'velocity_30d': self.get_velocity_metrics(30),
            'predicted_exhaustion': self.predict_exhaustion()
        }


class StateTracker:
    """State tracking and supply management system."""
    
    def __init__(self, warning_threshold: float = 0.9):
        """
        Initialize state tracker.
        
        Args:
            warning_threshold: Supply utilization threshold for warnings (0.0-1.0)
        """
        self.warning_threshold = warning_threshold
        self._lock = RLock()
        self._event_callbacks: List[Callable[[SupplyEvent, Dict], None]] = []
        self._state_snapshots: Dict[str, List[Tuple[datetime, StateEntry]]] = {}
    
    def add_event_callback(self, callback: Callable[[SupplyEvent, Dict], None]) -> None:
        """Add callback for supply events."""
        self._event_callbacks.append(callback)
    
    def _emit_event(self, event_type: SupplyEvent, data: Dict[str, Any]) -> None:
        """Emit supply event to registered callbacks."""
        for callback in self._event_callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                # Log error but don't let callback failures affect operation
                print(f"Warning: Event callback failed: {e}")
    
    def check_mint_allowed(
        self,
        asset: Asset,
        state: StateEntry,
        mint_amount: int,
        nft_token_id: Optional[int] = None
    ) -> MintValidationResult:
        """
        Check if mint operation is allowed.
        
        Args:
            asset: Asset definition
            state: Current asset state
            mint_amount: Amount to mint
            nft_token_id: NFT token ID (for NFTs)
            
        Returns:
            MintValidationResult with validation outcome
        """
        with self._lock:
            if isinstance(asset, FungibleAsset):
                return self._check_fungible_mint(asset, state, mint_amount)
            elif isinstance(asset, NFTAsset):
                return self._check_nft_mint(asset, state, nft_token_id or 0)
            else:
                return MintValidationResult(
                    allowed=False,
                    reason="Unsupported asset type",
                    event_type=SupplyEvent.MINT_DENIED
                )
    
    def _check_fungible_mint(
        self,
        asset: FungibleAsset,
        state: StateEntry,
        mint_amount: int
    ) -> MintValidationResult:
        """Check fungible token mint validation."""
        # Check per-mint limit
        if mint_amount > asset.per_mint_limit:
            result = MintValidationResult(
                allowed=False,
                reason=f"Mint amount {mint_amount} exceeds per-mint limit {asset.per_mint_limit}",
                event_type=SupplyEvent.MINT_LIMIT_REACHED
            )
            self._emit_event(result.event_type, {
                'asset_id': asset.asset_id,
                'mint_amount': mint_amount,
                'per_mint_limit': asset.per_mint_limit
            })
            return result
        
        # Check supply constraints
        new_total = state.minted_supply + mint_amount
        if new_total > asset.maximum_supply:
            remaining = asset.maximum_supply - state.minted_supply
            result = MintValidationResult(
                allowed=False,
                reason=f"Mint would exceed maximum supply. Requested: {mint_amount}, Available: {remaining}",
                event_type=SupplyEvent.SUPPLY_EXHAUSTED,
                remaining_supply=remaining
            )
            self._emit_event(result.event_type, {
                'asset_id': asset.asset_id,
                'mint_amount': mint_amount,
                'available_supply': remaining,
                'maximum_supply': asset.maximum_supply
            })
            return result
        
        # Calculate utilization
        utilization = new_total / asset.maximum_supply
        remaining = asset.maximum_supply - new_total
        
        # Check warning threshold
        if utilization >= self.warning_threshold:
            self._emit_event(SupplyEvent.SUPPLY_WARNING, {
                'asset_id': asset.asset_id,
                'utilization_percent': utilization * 100,
                'remaining_supply': remaining
            })
        
        return MintValidationResult(
            allowed=True,
            reason="Mint allowed",
            event_type=SupplyEvent.MINT_ALLOWED,
            remaining_supply=remaining,
            utilization_percent=utilization * 100
        )
    
    def _check_nft_mint(
        self,
        asset: NFTAsset,
        state: StateEntry,
        token_id: int
    ) -> MintValidationResult:
        """Check NFT mint validation."""
        # Check if token ID already issued
        if token_id in state.issued_nft_ids:
            result = MintValidationResult(
                allowed=False,
                reason=f"NFT token ID {token_id} already issued",
                event_type=SupplyEvent.MINT_DENIED
            )
            self._emit_event(result.event_type, {
                'asset_id': asset.asset_id,
                'token_id': token_id
            })
            return result
        
        # Check collection size limit
        if len(state.issued_nft_ids) >= asset.collection_size:
            result = MintValidationResult(
                allowed=False,
                reason=f"Collection exhausted. Maximum size: {asset.collection_size}",
                event_type=SupplyEvent.SUPPLY_EXHAUSTED,
                remaining_supply=0
            )
            self._emit_event(result.event_type, {
                'asset_id': asset.asset_id,
                'collection_size': asset.collection_size
            })
            return result
        
        # Calculate utilization
        new_count = len(state.issued_nft_ids) + 1
        utilization = new_count / asset.collection_size
        remaining = asset.collection_size - new_count
        
        # Check warning threshold
        if utilization >= self.warning_threshold:
            self._emit_event(SupplyEvent.SUPPLY_WARNING, {
                'asset_id': asset.asset_id,
                'utilization_percent': utilization * 100,
                'remaining_supply': remaining
            })
        
        return MintValidationResult(
            allowed=True,
            reason="NFT mint allowed",
            event_type=SupplyEvent.MINT_ALLOWED,
            remaining_supply=remaining,
            utilization_percent=utilization * 100
        )
    
    def increment_minted_supply(
        self,
        state: StateEntry,
        tx_entry: TransactionEntry,
        nft_token_id: Optional[int] = None
    ) -> StateEntry:
        """
        Atomically increment minted supply with overflow protection.
        
        Args:
            state: Current state entry
            tx_entry: Transaction entry to add
            nft_token_id: NFT token ID (for NFTs)
            
        Returns:
            Updated state entry
        """
        with self._lock:
            # Create snapshot before modification
            self._create_state_snapshot(state)
            
            try:
                if nft_token_id is not None:
                    # NFT issuance
                    state.issue_nft(nft_token_id, tx_entry)
                else:
                    # Fungible token minting
                    # Check for overflow
                    if state.minted_supply + tx_entry.amount < state.minted_supply:
                        raise OverflowError("Minted supply overflow detected")
                    
                    state.add_transaction(tx_entry)
                
                return state
                
            except Exception as e:
                # Rollback on error
                self._rollback_state(state)
                raise
    
    def _create_state_snapshot(self, state: StateEntry) -> None:
        """Create a snapshot of state for rollback."""
        if state.asset_id not in self._state_snapshots:
            self._state_snapshots[state.asset_id] = []
        
        # Keep only last 10 snapshots
        snapshots = self._state_snapshots[state.asset_id]
        if len(snapshots) >= 10:
            snapshots.pop(0)
        
        # Create deep copy of state
        snapshot = StateEntry(
            asset_id=state.asset_id,
            minted_supply=state.minted_supply,
            last_mint_timestamp=state.last_mint_timestamp,
            transaction_count=state.transaction_count,
            transaction_history=state.transaction_history[:],
            issued_nft_ids=state.issued_nft_ids[:]
        )
        
        snapshots.append((datetime.utcnow(), snapshot))
    
    def _rollback_state(self, state: StateEntry) -> bool:
        """Rollback state to last snapshot."""
        snapshots = self._state_snapshots.get(state.asset_id, [])
        if not snapshots:
            return False
        
        # Get most recent snapshot
        _, snapshot = snapshots[-1]
        
        # Restore state
        state.minted_supply = snapshot.minted_supply
        state.last_mint_timestamp = snapshot.last_mint_timestamp
        state.transaction_count = snapshot.transaction_count
        state.transaction_history = snapshot.transaction_history[:]
        state.issued_nft_ids = snapshot.issued_nft_ids[:]
        
        return True
    
    def get_supply_analytics(self, asset: Asset, state: StateEntry) -> SupplyAnalytics:
        """Get comprehensive supply analytics."""
        return SupplyAnalytics(asset, state)
    
    def check_supply_thresholds(
        self,
        assets_and_states: List[Tuple[Asset, StateEntry]]
    ) -> List[Dict[str, Any]]:
        """
        Check supply thresholds for multiple assets.
        
        Args:
            assets_and_states: List of (asset, state) tuples
            
        Returns:
            List of alerts for assets exceeding thresholds
        """
        alerts = []
        
        for asset, state in assets_and_states:
            analytics = self.get_supply_analytics(asset, state)
            
            if analytics.utilization_percent >= self.warning_threshold * 100:
                alerts.append({
                    'asset_id': asset.asset_id,
                    'asset_name': asset.name,
                    'alert_type': 'supply_warning',
                    'utilization_percent': analytics.utilization_percent,
                    'remaining_supply': analytics.remaining_supply,
                    'predicted_exhaustion': analytics.predict_exhaustion(),
                    'timestamp': datetime.utcnow()
                })
        
        return alerts
    
    def get_historical_usage(
        self,
        state: StateEntry,
        period_days: int = 30,
        bucket_hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Get historical usage patterns bucketed by time.
        
        Args:
            state: Asset state
            period_days: Period to analyze
            bucket_hours: Hours per bucket
            
        Returns:
            List of usage buckets with timestamps and amounts
        """
        cutoff_date = datetime.utcnow() - timedelta(days=period_days)
        bucket_delta = timedelta(hours=bucket_hours)
        
        # Filter transactions to period
        transactions = [
            tx for tx in state.transaction_history
            if tx.timestamp >= cutoff_date
        ]
        
        if not transactions:
            return []
        
        # Create time buckets
        buckets = {}
        current_time = cutoff_date
        end_time = datetime.utcnow()
        
        while current_time < end_time:
            bucket_key = current_time.replace(minute=0, second=0, microsecond=0)
            buckets[bucket_key] = {
                'timestamp': bucket_key,
                'amount': 0,
                'transaction_count': 0
            }
            current_time += bucket_delta
        
        # Populate buckets with transaction data
        for tx in transactions:
            # Find appropriate bucket
            bucket_time = tx.timestamp.replace(minute=0, second=0, microsecond=0)
            
            # Round down to nearest bucket
            hours_diff = (bucket_time - cutoff_date).total_seconds() / 3600
            bucket_index = int(hours_diff // bucket_hours) * bucket_hours
            bucket_key = cutoff_date + timedelta(hours=bucket_index)
            
            if bucket_key in buckets:
                buckets[bucket_key]['amount'] += tx.amount
                buckets[bucket_key]['transaction_count'] += 1
        
        return sorted(buckets.values(), key=lambda x: x['timestamp'])
    
    def clear_snapshots(self, asset_id: Optional[str] = None) -> None:
        """Clear state snapshots for memory management."""
        with self._lock:
            if asset_id:
                self._state_snapshots.pop(asset_id, None)
            else:
                self._state_snapshots.clear()