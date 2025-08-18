"""
Bitcoin Native Asset Protocol - Asset-Specific Script Templates

This module provides reusable script templates for different asset types and operations.
Templates support parameter substitution and compilation to both P2WSH and Taproot scripts.
"""

import hashlib
import json
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from scripts.p2wsh_covenant import P2WSHCovenantBuilder, CovenantType
from scripts.taproot_covenant import TaprootCovenantBuilder, TaprootOutput
from crypto.commitments import AssetCommitment
from registry.schema import AssetType


class TemplateType(Enum):
    """Types of script templates."""
    FUNGIBLE_MINT = "fungible_mint"
    FUNGIBLE_TRANSFER = "fungible_transfer"
    FUNGIBLE_BURN = "fungible_burn"
    NFT_MINT = "nft_mint"
    NFT_TRANSFER = "nft_transfer"
    NFT_BURN = "nft_burn"
    MULTISIG = "multisig"
    TIMELOCK = "timelock"
    ALLOWLIST = "allowlist"
    DELEGATION = "delegation"


class ScriptFormat(Enum):
    """Target script formats."""
    P2WSH = "p2wsh"
    TAPROOT = "taproot"
    BOTH = "both"


@dataclass
class TemplateParameter:
    """Parameter definition for script templates."""
    name: str
    type: str  # "bytes", "int", "str", "bool"
    required: bool = True
    default_value: Optional[Any] = None
    description: str = ""
    validation_rule: Optional[Callable[[Any], bool]] = None
    
    def validate(self, value: Any) -> bool:
        """Validate parameter value."""
        if value is None and self.required:
            return False
        
        if value is None and not self.required:
            return True
        
        # Type validation
        if self.type == "bytes":
            if not isinstance(value, bytes):
                return False
        elif self.type == "int":
            if not isinstance(value, int):
                return False
        elif self.type == "str":
            if not isinstance(value, str):
                return False
        elif self.type == "bool":
            if not isinstance(value, bool):
                return False
        
        # Custom validation rule
        if self.validation_rule:
            return self.validation_rule(value)
        
        return True


@dataclass
class ScriptTemplate(ABC):
    """Base class for all script templates."""
    template_type: TemplateType
    name: str
    description: str
    parameters: List[TemplateParameter] = field(default_factory=list)
    supported_formats: List[ScriptFormat] = field(default_factory=lambda: [ScriptFormat.BOTH])
    version: str = "1.0"
    
    def get_required_parameters(self) -> List[str]:
        """Get list of required parameter names."""
        return [p.name for p in self.parameters if p.required]
    
    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, str]:
        """Validate parameters and return error messages."""
        errors = {}
        
        for param in self.parameters:
            value = params.get(param.name)
            
            if not param.validate(value):
                if value is None and param.required:
                    errors[param.name] = f"Required parameter '{param.name}' is missing"
                else:
                    errors[param.name] = f"Invalid value for parameter '{param.name}'"
        
        return errors
    
    @abstractmethod
    def compile_p2wsh(self, params: Dict[str, Any]) -> bytes:
        """Compile template to P2WSH witness script."""
        pass
    
    @abstractmethod
    def compile_taproot(self, params: Dict[str, Any]) -> TaprootOutput:
        """Compile template to Taproot output."""
        pass
    
    def compile(
        self, 
        params: Dict[str, Any], 
        format: ScriptFormat = ScriptFormat.P2WSH
    ) -> Union[bytes, TaprootOutput]:
        """Compile template with given parameters."""
        # Validate parameters
        errors = self.validate_parameters(params)
        if errors:
            raise ValueError(f"Parameter validation failed: {errors}")
        
        # Fill in default values
        compiled_params = {}
        for param in self.parameters:
            if param.name in params:
                compiled_params[param.name] = params[param.name]
            elif param.default_value is not None:
                compiled_params[param.name] = param.default_value
        
        # Compile to requested format
        if format == ScriptFormat.P2WSH:
            return self.compile_p2wsh(compiled_params)
        elif format == ScriptFormat.TAPROOT:
            return self.compile_taproot(compiled_params)
        else:
            raise ValueError(f"Unsupported script format: {format}")


class FungibleMintTemplate(ScriptTemplate):
    """Template for fungible token minting scripts."""
    
    def __init__(self):
        super().__init__(
            template_type=TemplateType.FUNGIBLE_MINT,
            name="Fungible Token Mint",
            description="Script template for minting fungible tokens with supply limits",
            parameters=[
                TemplateParameter(
                    name="validator_pubkey",
                    type="bytes",
                    description="Validator's public key (32 or 33 bytes)",
                    validation_rule=lambda x: len(x) in [32, 33]
                ),
                TemplateParameter(
                    name="asset_id",
                    type="bytes",
                    description="Asset identifier (32 bytes)",
                    validation_rule=lambda x: len(x) == 32
                ),
                TemplateParameter(
                    name="supply_limit",
                    type="int",
                    description="Maximum total supply",
                    validation_rule=lambda x: x > 0
                ),
                TemplateParameter(
                    name="per_mint_limit",
                    type="int",
                    description="Maximum amount per mint",
                    validation_rule=lambda x: x > 0
                ),
                TemplateParameter(
                    name="current_supply",
                    type="int",
                    default_value=0,
                    required=False,
                    description="Current circulating supply"
                ),
                TemplateParameter(
                    name="mint_amount",
                    type="int",
                    default_value=1,
                    required=False,
                    description="Amount being minted in this operation"
                )
            ]
        )
    
    def compile_p2wsh(self, params: Dict[str, Any]) -> bytes:
        """Compile to P2WSH witness script."""
        builder = P2WSHCovenantBuilder()
        
        # Ensure 33-byte pubkey for P2WSH
        validator_pubkey = params["validator_pubkey"]
        if len(validator_pubkey) == 32:
            # Add prefix for compressed pubkey
            validator_pubkey = b'\x02' + validator_pubkey
        
        return builder.create_supply_limit_covenant(
            validator_pubkey=validator_pubkey,
            supply_limit=params["supply_limit"],
            current_supply=params["current_supply"],
            mint_amount=params["mint_amount"]
        )
    
    def compile_taproot(self, params: Dict[str, Any]) -> TaprootOutput:
        """Compile to Taproot output."""
        builder = TaprootCovenantBuilder()
        
        # Ensure 32-byte pubkey for Taproot
        validator_pubkey = params["validator_pubkey"]
        if len(validator_pubkey) == 33:
            # Remove prefix for x-only pubkey
            validator_pubkey = validator_pubkey[1:]
        
        asset_commitment = AssetCommitment(
            asset_id=params["asset_id"],
            amount=params["mint_amount"],
            operation="mint"
        )
        
        mint_conditions = {
            "supply_limit": params["supply_limit"],
            "current_supply": params["current_supply"],
            "mint_amount": params["mint_amount"]
        }
        
        return builder.create_asset_mint_covenant(
            validator_pubkey=validator_pubkey,
            asset_commitment=asset_commitment,
            mint_conditions=mint_conditions
        )


class NFTMintTemplate(ScriptTemplate):
    """Template for NFT minting scripts."""
    
    def __init__(self):
        super().__init__(
            template_type=TemplateType.NFT_MINT,
            name="NFT Mint",
            description="Script template for minting NFTs with collection limits",
            parameters=[
                TemplateParameter(
                    name="validator_pubkey",
                    type="bytes",
                    description="Validator's public key",
                    validation_rule=lambda x: len(x) in [32, 33]
                ),
                TemplateParameter(
                    name="asset_id",
                    type="bytes",
                    description="Collection asset ID (32 bytes)",
                    validation_rule=lambda x: len(x) == 32
                ),
                TemplateParameter(
                    name="collection_size",
                    type="int",
                    description="Maximum collection size",
                    validation_rule=lambda x: x > 0
                ),
                TemplateParameter(
                    name="token_id",
                    type="int",
                    description="Unique token ID within collection",
                    validation_rule=lambda x: x >= 0
                ),
                TemplateParameter(
                    name="content_hash",
                    type="bytes",
                    description="Hash of NFT content (32 bytes)",
                    validation_rule=lambda x: len(x) == 32
                ),
                TemplateParameter(
                    name="minted_count",
                    type="int",
                    default_value=0,
                    required=False,
                    description="Number of NFTs already minted"
                )
            ]
        )
    
    def compile_p2wsh(self, params: Dict[str, Any]) -> bytes:
        """Compile to P2WSH witness script."""
        builder = P2WSHCovenantBuilder()
        
        validator_pubkey = params["validator_pubkey"]
        if len(validator_pubkey) == 32:
            validator_pubkey = b'\x02' + validator_pubkey
        
        # For NFTs, amount is always 1
        return builder.create_supply_limit_covenant(
            validator_pubkey=validator_pubkey,
            supply_limit=params["collection_size"],
            current_supply=params["minted_count"],
            mint_amount=1
        )
    
    def compile_taproot(self, params: Dict[str, Any]) -> TaprootOutput:
        """Compile to Taproot output."""
        builder = TaprootCovenantBuilder()
        
        validator_pubkey = params["validator_pubkey"]
        if len(validator_pubkey) == 33:
            validator_pubkey = validator_pubkey[1:]
        
        asset_commitment = AssetCommitment(
            asset_id=params["asset_id"],
            amount=1,  # NFTs are always amount 1
            operation="nft_mint",
            nft_token_id=params["token_id"],
            content_hash=params["content_hash"]
        )
        
        mint_conditions = {
            "supply_limit": params["collection_size"],
            "current_supply": params["minted_count"],
            "mint_amount": 1
        }
        
        return builder.create_asset_mint_covenant(
            validator_pubkey=validator_pubkey,
            asset_commitment=asset_commitment,
            mint_conditions=mint_conditions
        )


class TransferTemplate(ScriptTemplate):
    """Template for asset transfer scripts."""
    
    def __init__(self):
        super().__init__(
            template_type=TemplateType.FUNGIBLE_TRANSFER,
            name="Asset Transfer",
            description="Script template for transferring assets with optional allowlist",
            parameters=[
                TemplateParameter(
                    name="validator_pubkey",
                    type="bytes",
                    description="Validator's public key",
                    validation_rule=lambda x: len(x) in [32, 33]
                ),
                TemplateParameter(
                    name="asset_id",
                    type="bytes",
                    description="Asset identifier (32 bytes)",
                    validation_rule=lambda x: len(x) == 32
                ),
                TemplateParameter(
                    name="transfer_amount",
                    type="int",
                    description="Amount being transferred",
                    validation_rule=lambda x: x > 0
                ),
                TemplateParameter(
                    name="allowlist_root",
                    type="bytes",
                    required=False,
                    description="Merkle root of allowed recipients (32 bytes)",
                    validation_rule=lambda x: x is None or len(x) == 32
                ),
                TemplateParameter(
                    name="recipient_hash",
                    type="bytes",
                    required=False,
                    description="Hash of recipient for allowlist verification",
                    validation_rule=lambda x: x is None or len(x) == 32
                )
            ]
        )
    
    def compile_p2wsh(self, params: Dict[str, Any]) -> bytes:
        """Compile to P2WSH witness script."""
        builder = P2WSHCovenantBuilder()
        
        validator_pubkey = params["validator_pubkey"]
        if len(validator_pubkey) == 32:
            validator_pubkey = b'\x02' + validator_pubkey
        
        if params.get("allowlist_root"):
            return builder.create_allowlist_covenant(
                validator_pubkey=validator_pubkey,
                allowlist_root=params["allowlist_root"],
                recipient_hash=params["recipient_hash"]
            )
        else:
            return builder.create_validator_covenant(validator_pubkey)
    
    def compile_taproot(self, params: Dict[str, Any]) -> TaprootOutput:
        """Compile to Taproot output."""
        builder = TaprootCovenantBuilder()
        
        validator_pubkey = params["validator_pubkey"]
        if len(validator_pubkey) == 33:
            validator_pubkey = validator_pubkey[1:]
        
        asset_commitment = AssetCommitment(
            asset_id=params["asset_id"],
            amount=params["transfer_amount"],
            operation="transfer"
        )
        
        transfer_rules = {}
        if params.get("allowlist_root"):
            transfer_rules["allowlist_required"] = True
            transfer_rules["allowlist_root"] = params["allowlist_root"]
        
        return builder.create_asset_transfer_covenant(
            validator_pubkey=validator_pubkey,
            asset_commitment=asset_commitment,
            transfer_rules=transfer_rules
        )


class MultisigTemplate(ScriptTemplate):
    """Template for multi-signature scripts."""
    
    def __init__(self):
        super().__init__(
            template_type=TemplateType.MULTISIG,
            name="Multi-Signature",
            description="Script template for multi-signature validation",
            parameters=[
                TemplateParameter(
                    name="validator_pubkeys",
                    type="bytes",  # Actually list of bytes
                    description="List of validator public keys"
                ),
                TemplateParameter(
                    name="required_signatures",
                    type="int",
                    description="Number of required signatures",
                    validation_rule=lambda x: x > 0
                ),
                TemplateParameter(
                    name="asset_id",
                    type="bytes",
                    required=False,
                    description="Asset identifier for asset-specific multisig"
                )
            ]
        )
    
    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, str]:
        """Override to handle list validation."""
        errors = super().validate_parameters(params)
        
        # Special validation for pubkey list
        pubkeys = params.get("validator_pubkeys", [])
        if not isinstance(pubkeys, list):
            errors["validator_pubkeys"] = "validator_pubkeys must be a list"
        elif len(pubkeys) == 0:
            errors["validator_pubkeys"] = "At least one validator pubkey required"
        elif not all(isinstance(pk, bytes) for pk in pubkeys):
            errors["validator_pubkeys"] = "All validator pubkeys must be bytes"
        elif not all(len(pk) in [32, 33] for pk in pubkeys):
            errors["validator_pubkeys"] = "All pubkeys must be 32 or 33 bytes"
        
        # Check required signatures vs total keys
        required_sigs = params.get("required_signatures", 0)
        if required_sigs > len(pubkeys):
            errors["required_signatures"] = "Required signatures cannot exceed total keys"
        
        return errors
    
    def compile_p2wsh(self, params: Dict[str, Any]) -> bytes:
        """Compile to P2WSH witness script."""
        builder = P2WSHCovenantBuilder()
        
        # Ensure 33-byte pubkeys for P2WSH
        pubkeys = []
        for pk in params["validator_pubkeys"]:
            if len(pk) == 32:
                pubkeys.append(b'\x02' + pk)
            else:
                pubkeys.append(pk)
        
        return builder.create_multisig_validator_covenant(
            validator_pubkeys=pubkeys,
            required_signatures=params["required_signatures"],
            asset_id=params.get("asset_id")
        )
    
    def compile_taproot(self, params: Dict[str, Any]) -> TaprootOutput:
        """Compile to Taproot output."""
        builder = TaprootCovenantBuilder()
        
        # For Taproot, use the first key as internal key
        # and create script tree with multisig options
        internal_pubkey = params["validator_pubkeys"][0]
        if len(internal_pubkey) == 33:
            internal_pubkey = internal_pubkey[1:]
        
        # Create multisig scripts for script tree
        scripts = []
        for i in range(len(params["validator_pubkeys"])):
            # Simple 1-of-1 scripts for each validator
            pk = params["validator_pubkeys"][i]
            if len(pk) == 33:
                pk = pk[1:]
            
            script = builder._create_tapscript_validator_sig(pk)
            scripts.append(script)
        
        asset_commitment = None
        if params.get("asset_id"):
            asset_commitment = AssetCommitment(
                asset_id=params["asset_id"],
                amount=1,
                operation="multisig"
            )
        
        return builder.create_script_path_covenant(
            internal_pubkey=internal_pubkey,
            scripts=scripts,
            asset_commitment=asset_commitment
        )


class TimelockTemplate(ScriptTemplate):
    """Template for time-locked scripts."""
    
    def __init__(self):
        super().__init__(
            template_type=TemplateType.TIMELOCK,
            name="Time Lock",
            description="Script template for time-locked operations",
            parameters=[
                TemplateParameter(
                    name="validator_pubkey",
                    type="bytes",
                    description="Validator's public key",
                    validation_rule=lambda x: len(x) in [32, 33]
                ),
                TemplateParameter(
                    name="lock_time",
                    type="int",
                    description="Lock time value",
                    validation_rule=lambda x: x >= 0
                ),
                TemplateParameter(
                    name="lock_type",
                    type="str",
                    default_value="absolute",
                    required=False,
                    description="Type of time lock ('absolute' or 'relative')",
                    validation_rule=lambda x: x in ["absolute", "relative"]
                ),
                TemplateParameter(
                    name="asset_id",
                    type="bytes",
                    required=False,
                    description="Asset identifier for asset-specific timelock"
                )
            ]
        )
    
    def compile_p2wsh(self, params: Dict[str, Any]) -> bytes:
        """Compile to P2WSH witness script."""
        builder = P2WSHCovenantBuilder()
        
        validator_pubkey = params["validator_pubkey"]
        if len(validator_pubkey) == 32:
            validator_pubkey = b'\x02' + validator_pubkey
        
        return builder.create_time_locked_covenant(
            validator_pubkey=validator_pubkey,
            lock_time=params["lock_time"],
            lock_type=params["lock_type"]
        )
    
    def compile_taproot(self, params: Dict[str, Any]) -> TaprootOutput:
        """Compile to Taproot output."""
        builder = TaprootCovenantBuilder()
        
        validator_pubkey = params["validator_pubkey"]
        if len(validator_pubkey) == 33:
            validator_pubkey = validator_pubkey[1:]
        
        # Create timelock script
        timelock_script = builder._create_tapscript_timelock(
            validator_pubkey=validator_pubkey,
            lock_time=params["lock_time"],
            lock_type=params["lock_type"]
        )
        
        asset_commitment = None
        if params.get("asset_id"):
            asset_commitment = AssetCommitment(
                asset_id=params["asset_id"],
                amount=1,
                operation="timelock"
            )
        
        return builder.create_script_path_covenant(
            internal_pubkey=validator_pubkey,
            scripts=[timelock_script],
            asset_commitment=asset_commitment
        )


class ScriptTemplateRegistry:
    """Registry for managing script templates."""
    
    def __init__(self):
        """Initialize template registry."""
        self.templates: Dict[TemplateType, ScriptTemplate] = {}
        self._register_default_templates()
    
    def _register_default_templates(self):
        """Register default templates."""
        self.register_template(FungibleMintTemplate())
        self.register_template(NFTMintTemplate())
        self.register_template(TransferTemplate())
        self.register_template(MultisigTemplate())
        self.register_template(TimelockTemplate())
    
    def register_template(self, template: ScriptTemplate):
        """Register a new template."""
        self.templates[template.template_type] = template
    
    def get_template(self, template_type: TemplateType) -> Optional[ScriptTemplate]:
        """Get template by type."""
        return self.templates.get(template_type)
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List all registered templates."""
        return [
            {
                "type": template.template_type.value,
                "name": template.name,
                "description": template.description,
                "parameters": [
                    {
                        "name": p.name,
                        "type": p.type,
                        "required": p.required,
                        "description": p.description
                    }
                    for p in template.parameters
                ],
                "supported_formats": [f.value for f in template.supported_formats],
                "version": template.version
            }
            for template in self.templates.values()
        ]
    
    def compile_template(
        self,
        template_type: TemplateType,
        parameters: Dict[str, Any],
        format: ScriptFormat = ScriptFormat.P2WSH
    ) -> Union[bytes, TaprootOutput]:
        """Compile template with parameters."""
        template = self.get_template(template_type)
        if not template:
            raise ValueError(f"Unknown template type: {template_type}")
        
        return template.compile(parameters, format)
    
    def validate_template_parameters(
        self,
        template_type: TemplateType,
        parameters: Dict[str, Any]
    ) -> Dict[str, str]:
        """Validate parameters for a template."""
        template = self.get_template(template_type)
        if not template:
            raise ValueError(f"Unknown template type: {template_type}")
        
        return template.validate_parameters(parameters)


# Global template registry instance
_template_registry = None


def get_template_registry() -> ScriptTemplateRegistry:
    """Get the global template registry."""
    global _template_registry
    if _template_registry is None:
        _template_registry = ScriptTemplateRegistry()
    return _template_registry


# Convenience functions

def create_fungible_mint_script(
    validator_pubkey: bytes,
    asset_id: bytes,
    supply_limit: int,
    per_mint_limit: int,
    format: ScriptFormat = ScriptFormat.P2WSH
) -> Union[bytes, TaprootOutput]:
    """Create fungible token mint script."""
    registry = get_template_registry()
    
    params = {
        "validator_pubkey": validator_pubkey,
        "asset_id": asset_id,
        "supply_limit": supply_limit,
        "per_mint_limit": per_mint_limit
    }
    
    return registry.compile_template(TemplateType.FUNGIBLE_MINT, params, format)


def create_nft_mint_script(
    validator_pubkey: bytes,
    asset_id: bytes,
    collection_size: int,
    token_id: int,
    content_hash: bytes,
    format: ScriptFormat = ScriptFormat.P2WSH
) -> Union[bytes, TaprootOutput]:
    """Create NFT mint script."""
    registry = get_template_registry()
    
    params = {
        "validator_pubkey": validator_pubkey,
        "asset_id": asset_id,
        "collection_size": collection_size,
        "token_id": token_id,
        "content_hash": content_hash
    }
    
    return registry.compile_template(TemplateType.NFT_MINT, params, format)


def create_transfer_script(
    validator_pubkey: bytes,
    asset_id: bytes,
    transfer_amount: int,
    allowlist_root: Optional[bytes] = None,
    format: ScriptFormat = ScriptFormat.P2WSH
) -> Union[bytes, TaprootOutput]:
    """Create asset transfer script."""
    registry = get_template_registry()
    
    params = {
        "validator_pubkey": validator_pubkey,
        "asset_id": asset_id,
        "transfer_amount": transfer_amount
    }
    
    if allowlist_root:
        params["allowlist_root"] = allowlist_root
    
    return registry.compile_template(TemplateType.FUNGIBLE_TRANSFER, params, format)


def create_multisig_script(
    validator_pubkeys: List[bytes],
    required_signatures: int,
    asset_id: Optional[bytes] = None,
    format: ScriptFormat = ScriptFormat.P2WSH
) -> Union[bytes, TaprootOutput]:
    """Create multi-signature script."""
    registry = get_template_registry()
    
    params = {
        "validator_pubkeys": validator_pubkeys,
        "required_signatures": required_signatures
    }
    
    if asset_id:
        params["asset_id"] = asset_id
    
    return registry.compile_template(TemplateType.MULTISIG, params, format)


def create_timelock_script(
    validator_pubkey: bytes,
    lock_time: int,
    lock_type: str = "absolute",
    asset_id: Optional[bytes] = None,
    format: ScriptFormat = ScriptFormat.P2WSH
) -> Union[bytes, TaprootOutput]:
    """Create time-locked script."""
    registry = get_template_registry()
    
    params = {
        "validator_pubkey": validator_pubkey,
        "lock_time": lock_time,
        "lock_type": lock_type
    }
    
    if asset_id:
        params["asset_id"] = asset_id
    
    return registry.compile_template(TemplateType.TIMELOCK, params, format)


# Template utilities

def get_template_info(template_type: TemplateType) -> Optional[Dict[str, Any]]:
    """Get detailed information about a template."""
    registry = get_template_registry()
    template = registry.get_template(template_type)
    
    if not template:
        return None
    
    return {
        "type": template.template_type.value,
        "name": template.name,
        "description": template.description,
        "parameters": [
            {
                "name": p.name,
                "type": p.type,
                "required": p.required,
                "default_value": p.default_value,
                "description": p.description
            }
            for p in template.parameters
        ],
        "supported_formats": [f.value for f in template.supported_formats],
        "version": template.version
    }


def list_all_templates() -> List[Dict[str, Any]]:
    """List all available templates."""
    registry = get_template_registry()
    return registry.list_templates()


def validate_template_params(
    template_type: TemplateType,
    parameters: Dict[str, Any]
) -> Tuple[bool, Dict[str, str]]:
    """Validate parameters for a template."""
    registry = get_template_registry()
    
    try:
        errors = registry.validate_template_parameters(template_type, parameters)
        return len(errors) == 0, errors
    except ValueError as e:
        return False, {"template": str(e)}


# CLI interface for template testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "list":
            templates = list_all_templates()
            print("Available Script Templates:")
            print("-" * 40)
            for template in templates:
                print(f"Type: {template['type']}")
                print(f"Name: {template['name']}")
                print(f"Description: {template['description']}")
                print(f"Parameters: {len(template['parameters'])}")
                print(f"Formats: {', '.join(template['supported_formats'])}")
                print("-" * 40)
        
        elif command == "test":
            print("Testing script template compilation...")
            
            # Test fungible mint template
            try:
                validator_key = b'\x02' + b'\x01' * 32
                asset_id = b'\x02' * 32
                
                script = create_fungible_mint_script(
                    validator_pubkey=validator_key,
                    asset_id=asset_id,
                    supply_limit=1000000,
                    per_mint_limit=10000,
                    format=ScriptFormat.P2WSH
                )
                
                print(f"✓ Fungible mint P2WSH script: {len(script)} bytes")
                
                taproot_output = create_fungible_mint_script(
                    validator_pubkey=validator_key,
                    asset_id=asset_id,
                    supply_limit=1000000,
                    per_mint_limit=10000,
                    format=ScriptFormat.TAPROOT
                )
                
                print(f"✓ Fungible mint Taproot output: {taproot_output.tweaked_pubkey.hex()[:16]}...")
                
            except Exception as e:
                print(f"✗ Fungible mint test failed: {e}")
            
            print("Template testing completed.")
        
        else:
            print(f"Unknown command: {command}")
            print("Available commands: list, test")
    
    else:
        print("Script Template Management")
        print("Usage: python templates.py <command>")
        print("Commands:")
        print("  list - List all available templates")
        print("  test - Test template compilation")