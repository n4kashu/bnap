"""
Per-Mint Limit Enforcement Rule

This module implements the MintLimitRule class that validates whether
individual mint transactions exceed the per-mint limit defined for an asset.
Supports various limit types and handles batch mints and multi-output transactions.
"""

import logging
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum

from validator.core import ValidationRule, ValidationContext
from registry.schema import AssetType, FungibleAsset, NFTAsset
from crypto.commitments import OperationType


class LimitType(str, Enum):
    """Types of mint limits supported."""
    PER_TRANSACTION = "per_transaction"  # Maximum per single transaction
    PER_ADDRESS = "per_address"         # Maximum per recipient address
    TIME_BASED = "time_based"           # Maximum per time window


@dataclass
class MintOutput:
    """Represents a mint output from a PSBT transaction."""
    address: str
    amount: int
    asset_id: bytes
    output_index: int


@dataclass
class MintAnalysis:
    """Analysis result for a mint transaction."""
    total_amount: int
    outputs: List[MintOutput]
    unique_addresses: int
    max_amount_per_address: int
    is_batch_mint: bool
    
    def get_amount_by_address(self) -> Dict[str, int]:
        """Get total amount minted per address."""
        amounts = {}
        for output in self.outputs:
            amounts[output.address] = amounts.get(output.address, 0) + output.amount
        return amounts


class MintLimitRule(ValidationRule):
    """
    Validation rule that enforces per-mint limits for assets.
    
    This rule ensures that individual mint transactions do not exceed
    the per-mint limits defined for an asset. It supports different
    limit types and handles complex scenarios like batch mints.
    """
    
    def __init__(self, strict_mode: bool = True, allow_batch_mints: bool = True):
        """
        Initialize the mint limit rule.
        
        Args:
            strict_mode: If True, enforces all limit types strictly
            allow_batch_mints: If True, allows batch mints to multiple addresses
        """
        super().__init__(
            name="mint_limit",
            description="Enforces per-mint transaction limits for assets"
        )
        
        self.strict_mode = strict_mode
        self.allow_batch_mints = allow_batch_mints
        
        # Statistics tracking
        self.stats = {
            "validations_performed": 0,
            "rejected_over_limit": 0,
            "rejected_batch_not_allowed": 0,
            "approved_within_limit": 0,
            "batch_mints_processed": 0,
            "single_mints_processed": 0
        }
    
    def is_applicable(self, context: ValidationContext) -> bool:
        """
        Check if this rule applies to the given validation context.
        
        This rule applies to:
        - Mint operations only
        - Assets with defined per-mint limits
        
        Args:
            context: Validation context
            
        Returns:
            True if this rule should be applied
        """
        if not self.enabled:
            return False
        
        # Only apply to mint operations
        if context.operation != OperationType.MINT:
            return False
        
        # Must have asset ID and amount (and amount must be positive for mints)
        if not context.asset_id or context.amount is None or context.amount <= 0:
            return False
        
        # Must have per-mint cap defined
        if context.per_mint_cap is None:
            return False
        
        return True
    
    def validate(self, context: ValidationContext) -> bool:
        """
        Validate that the mint transaction doesn't exceed per-mint limits.
        
        Args:
            context: Validation context containing transaction data
            
        Returns:
            True if validation passes, False otherwise
        """
        self.stats["validations_performed"] += 1
        
        try:
            # Analyze the mint transaction
            mint_analysis = self._analyze_mint_transaction(context)
            if mint_analysis is None:
                context.add_error(self.name, "Failed to analyze mint transaction")
                return False
            
            # Get per-mint limit from context
            per_mint_limit = context.per_mint_cap
            
            # Update statistics
            if mint_analysis.is_batch_mint:
                self.stats["batch_mints_processed"] += 1
            else:
                self.stats["single_mints_processed"] += 1
            
            # Validate batch mint allowance
            if mint_analysis.is_batch_mint and not self.allow_batch_mints:
                self.stats["rejected_batch_not_allowed"] += 1
                context.add_error(
                    self.name,
                    f"Batch mints not allowed for this asset. "
                    f"Transaction mints to {mint_analysis.unique_addresses} addresses"
                )
                return False
            
            # Validate total transaction amount
            if not self._validate_transaction_limit(mint_analysis, per_mint_limit, context):
                return False
            
            # Validate per-address limits if in strict mode
            if self.strict_mode and not self._validate_address_limits(mint_analysis, per_mint_limit, context):
                return False
            
            # Validation passed
            self.stats["approved_within_limit"] += 1
            self.logger.debug(
                f"Mint limit validation passed: total={mint_analysis.total_amount}, "
                f"limit={per_mint_limit}, addresses={mint_analysis.unique_addresses}"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Mint limit validation error: {e}")
            context.add_error(self.name, f"Mint limit validation failed: {str(e)}")
            return False
    
    def _analyze_mint_transaction(self, context: ValidationContext) -> Optional[MintAnalysis]:
        """
        Analyze the mint transaction to extract mint outputs and amounts.
        
        Args:
            context: Validation context
            
        Returns:
            MintAnalysis object or None if analysis failed
        """
        try:
            # In a real implementation, this would parse PSBT outputs
            # For now, we'll use the context data and simulate the analysis
            
            # Extract basic transaction information
            total_amount = context.amount or 0
            asset_id = context.asset_id
            
            # Simulate mint outputs analysis from PSBT data
            # In production, this would parse actual PSBT output scripts
            mint_outputs = self._extract_mint_outputs(context)
            
            # Calculate analysis metrics
            unique_addresses = len(set(output.address for output in mint_outputs))
            amounts_by_address = {}
            for output in mint_outputs:
                amounts_by_address[output.address] = amounts_by_address.get(output.address, 0) + output.amount
            
            max_amount_per_address = max(amounts_by_address.values()) if amounts_by_address else 0
            is_batch_mint = unique_addresses > 1
            
            analysis = MintAnalysis(
                total_amount=total_amount,
                outputs=mint_outputs,
                unique_addresses=unique_addresses,
                max_amount_per_address=max_amount_per_address,
                is_batch_mint=is_batch_mint
            )
            
            self.logger.debug(
                f"Mint analysis: total={total_amount}, addresses={unique_addresses}, "
                f"batch={is_batch_mint}, max_per_address={max_amount_per_address}"
            )
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze mint transaction: {e}")
            return None
    
    def _extract_mint_outputs(self, context: ValidationContext) -> List[MintOutput]:
        """
        Extract mint outputs from PSBT transaction data.
        
        Args:
            context: Validation context
            
        Returns:
            List of MintOutput objects
        """
        mint_outputs = []
        
        try:
            psbt_data = context.psbt_data
            outputs = psbt_data.get("outputs", [])
            
            # For now, simulate a single output mint
            # In production, this would parse actual PSBT outputs and OP_RETURN data
            if context.amount and context.asset_id:
                # Simulate recipient address (would be extracted from output script)
                recipient_address = "bc1qexampleaddress123456789"
                
                mint_output = MintOutput(
                    address=recipient_address,
                    amount=context.amount,
                    asset_id=context.asset_id,
                    output_index=0
                )
                mint_outputs.append(mint_output)
            
            # TODO: In production implementation:
            # 1. Parse each PSBT output
            # 2. Identify OP_RETURN outputs with BNAP metadata
            # 3. Extract asset IDs and amounts from OP_RETURN data
            # 4. Match with recipient addresses from other outputs
            # 5. Handle multi-output batch mints
            
            self.logger.debug(f"Extracted {len(mint_outputs)} mint outputs")
            return mint_outputs
            
        except Exception as e:
            self.logger.error(f"Failed to extract mint outputs: {e}")
            return []
    
    def _validate_transaction_limit(self, analysis: MintAnalysis, limit: int, context: ValidationContext) -> bool:
        """
        Validate total transaction amount against per-mint limit.
        
        Args:
            analysis: Mint transaction analysis
            limit: Per-mint limit
            context: Validation context
            
        Returns:
            True if validation passes
        """
        if analysis.total_amount > limit:
            self.stats["rejected_over_limit"] += 1
            
            context.add_error(
                self.name,
                f"Transaction mint amount {analysis.total_amount} exceeds per-mint limit {limit}"
            )
            
            # Add detailed information
            context.add_warning(
                self.name,
                f"Mint details - Total: {analysis.total_amount:,}, "
                f"Limit: {limit:,}, "
                f"Addresses: {analysis.unique_addresses}, "
                f"Batch mint: {analysis.is_batch_mint}"
            )
            
            return False
        
        return True
    
    def _validate_address_limits(self, analysis: MintAnalysis, limit: int, context: ValidationContext) -> bool:
        """
        Validate per-address amounts against per-mint limit.
        
        Args:
            analysis: Mint transaction analysis
            limit: Per-mint limit
            context: Validation context
            
        Returns:
            True if validation passes
        """
        amounts_by_address = analysis.get_amount_by_address()
        
        for address, amount in amounts_by_address.items():
            if amount > limit:
                self.stats["rejected_over_limit"] += 1
                
                context.add_error(
                    self.name,
                    f"Address {address[:10]}... receives {amount} which exceeds per-mint limit {limit}"
                )
                
                return False
        
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rule statistics."""
        total_processed = self.stats["batch_mints_processed"] + self.stats["single_mints_processed"]
        batch_rate = (self.stats["batch_mints_processed"] / total_processed * 100) if total_processed > 0 else 0
        
        return {
            **self.stats,
            "batch_mint_rate_percent": round(batch_rate, 2),
            "strict_mode": self.strict_mode,
            "allow_batch_mints": self.allow_batch_mints
        }
    
    def validate_asset_configuration(self, asset_data: Dict[str, Any]) -> bool:
        """
        Validate asset configuration for per-mint limits.
        
        Args:
            asset_data: Asset configuration data
            
        Returns:
            True if configuration is valid
        """
        try:
            asset_type = asset_data.get("asset_type")
            per_mint_limit = asset_data.get("per_mint_limit")
            maximum_supply = asset_data.get("maximum_supply")
            
            if per_mint_limit is None:
                self.logger.warning("No per_mint_limit specified in asset configuration")
                return True  # Not required
            
            # Validate per-mint limit is positive
            if not isinstance(per_mint_limit, int) or per_mint_limit <= 0:
                self.logger.error(f"Invalid per_mint_limit: {per_mint_limit}")
                return False
            
            # Validate per-mint limit doesn't exceed maximum supply
            if maximum_supply and per_mint_limit > maximum_supply:
                self.logger.error(
                    f"Per-mint limit {per_mint_limit} exceeds maximum supply {maximum_supply}"
                )
                return False
            
            # Asset type specific validations
            if asset_type == AssetType.FUNGIBLE.value:
                if per_mint_limit > 10**15:  # Reasonable upper limit for fungible tokens
                    self.logger.error(f"Per-mint limit too large for fungible asset: {per_mint_limit}")
                    return False
            
            elif asset_type == AssetType.NFT.value:
                if per_mint_limit > 1000:  # Reasonable upper limit for NFT batch mints
                    self.logger.error(f"Per-mint limit too large for NFT asset: {per_mint_limit}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Asset configuration validation error: {e}")
            return False
    
    def estimate_max_transactions_needed(self, total_amount: int, per_mint_limit: int) -> int:
        """
        Estimate the minimum number of transactions needed to mint a total amount.
        
        Args:
            total_amount: Total amount to mint
            per_mint_limit: Per-mint limit
            
        Returns:
            Minimum number of transactions needed
        """
        if per_mint_limit <= 0:
            return -1  # Invalid limit
        
        return (total_amount + per_mint_limit - 1) // per_mint_limit  # Ceiling division
    
    def suggest_mint_strategy(self, total_amount: int, per_mint_limit: int) -> Dict[str, Any]:
        """
        Suggest an optimal minting strategy for a given amount and limit.
        
        Args:
            total_amount: Total amount to mint
            per_mint_limit: Per-mint limit
            
        Returns:
            Dictionary with suggested strategy
        """
        if per_mint_limit <= 0:
            return {"error": "Invalid per-mint limit"}
        
        if total_amount <= per_mint_limit:
            return {
                "transactions_needed": 1,
                "strategy": "single",
                "amounts": [total_amount],
                "remainder": 0
            }
        
        num_full_transactions = total_amount // per_mint_limit
        remainder = total_amount % per_mint_limit
        
        amounts = [per_mint_limit] * num_full_transactions
        if remainder > 0:
            amounts.append(remainder)
        
        return {
            "transactions_needed": len(amounts),
            "strategy": "batch" if len(amounts) > 1 else "single",
            "amounts": amounts,
            "remainder": remainder
        }


# Utility functions for mint limit validation

def create_mint_limit_rule(config: Optional[Dict[str, Any]] = None) -> MintLimitRule:
    """
    Create a MintLimitRule with configuration.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured MintLimitRule instance
    """
    config = config or {}
    
    strict_mode = config.get("strict_mode", True)
    allow_batch_mints = config.get("allow_batch_mints", True)
    
    return MintLimitRule(
        strict_mode=strict_mode,
        allow_batch_mints=allow_batch_mints
    )


def validate_mint_limit_quick(mint_amount: int, per_mint_limit: int) -> tuple[bool, str]:
    """
    Quick mint limit validation without full rule context.
    
    Args:
        mint_amount: Amount to mint in transaction
        per_mint_limit: Per-mint limit
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if mint_amount <= 0 or per_mint_limit <= 0:
        return False, "Invalid mint parameters"
    
    if mint_amount > per_mint_limit:
        excess = mint_amount - per_mint_limit
        return False, f"Mint amount {mint_amount} exceeds limit {per_mint_limit} by {excess}"
    
    return True, ""


def analyze_mint_outputs(outputs: List[Dict[str, Any]], asset_id: bytes) -> MintAnalysis:
    """
    Analyze mint outputs from PSBT data.
    
    Args:
        outputs: List of output dictionaries from PSBT
        asset_id: Asset ID to filter for
        
    Returns:
        MintAnalysis object
    """
    mint_outputs = []
    total_amount = 0
    
    for i, output in enumerate(outputs):
        # In production, this would parse OP_RETURN data and match with addresses
        # For now, create placeholder analysis
        amount = output.get("amount", 0)
        address = output.get("address", f"address_{i}")
        
        mint_output = MintOutput(
            address=address,
            amount=amount,
            asset_id=asset_id,
            output_index=i
        )
        
        mint_outputs.append(mint_output)
        total_amount += amount
    
    unique_addresses = len(set(output.address for output in mint_outputs))
    amounts_by_address = {}
    for output in mint_outputs:
        amounts_by_address[output.address] = amounts_by_address.get(output.address, 0) + output.amount
    
    max_amount_per_address = max(amounts_by_address.values()) if amounts_by_address else 0
    is_batch_mint = unique_addresses > 1
    
    return MintAnalysis(
        total_amount=total_amount,
        outputs=mint_outputs,
        unique_addresses=unique_addresses,
        max_amount_per_address=max_amount_per_address,
        is_batch_mint=is_batch_mint
    )