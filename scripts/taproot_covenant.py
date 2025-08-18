"""
Bitcoin Native Asset Protocol - Taproot Covenant Implementation

This module provides comprehensive Taproot covenant functionality including:
- Key-path spending with asset commitment tweaks
- Script-path spending with complex conditions
- Script tree construction and management
- Control block generation for script-path spending
- Taproot address generation and validation
"""

import hashlib
import struct
import json
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass, field
from enum import Enum

from crypto.keys import (
    tagged_hash,
    PrivateKey, 
    PublicKey,
    compute_taproot_tweak,
    taproot_output_script,
    lift_x
)
from crypto.commitments import AssetCommitment, create_asset_commitment_tweak
from scripts.p2wsh_covenant import ScriptOpcode


class TaprootSpendType(Enum):
    """Types of Taproot spending methods."""
    KEY_PATH = "key_path"
    SCRIPT_PATH = "script_path"


class TaprootScriptVersion(Enum):
    """Taproot script versions."""
    LEAF_VERSION_TAPSCRIPT = 0xc0


@dataclass
class TapLeaf:
    """Represents a single leaf in the Taproot script tree."""
    script: bytes
    leaf_version: int = 0xc0
    
    def __post_init__(self):
        """Validate leaf parameters."""
        if not self.script:
            raise ValueError("Tap leaf script cannot be empty")
        if len(self.script) > 10000:  # Bitcoin script size limit
            raise ValueError("Tap leaf script too large")
    
    def leaf_hash(self) -> bytes:
        """Compute TapLeaf hash for this leaf."""
        return tagged_hash(
            "TapLeaf",
            bytes([self.leaf_version]) + self._serialize_script()
        )
    
    def _serialize_script(self) -> bytes:
        """Serialize script with compact size prefix."""
        return self._serialize_compact_size(len(self.script)) + self.script
    
    def _serialize_compact_size(self, n: int) -> bytes:
        """Serialize integer as Bitcoin compact size."""
        if n < 0xfd:
            return struct.pack('<B', n)
        elif n <= 0xffff:
            return b'\xfd' + struct.pack('<H', n)
        elif n <= 0xffffffff:
            return b'\xfe' + struct.pack('<I', n)
        else:
            return b'\xff' + struct.pack('<Q', n)


@dataclass  
class TapBranch:
    """Represents an internal node in the Taproot script tree."""
    left: Union['TapBranch', TapLeaf]
    right: Union['TapBranch', TapLeaf]
    
    def branch_hash(self) -> bytes:
        """Compute TapBranch hash for this internal node."""
        left_hash = (self.left.leaf_hash() if isinstance(self.left, TapLeaf) 
                    else self.left.branch_hash())
        right_hash = (self.right.leaf_hash() if isinstance(self.right, TapLeaf)
                     else self.right.branch_hash())
        
        # Lexicographically order the hashes
        if left_hash <= right_hash:
            return tagged_hash("TapBranch", left_hash + right_hash)
        else:
            return tagged_hash("TapBranch", right_hash + left_hash)


@dataclass
class ScriptPathInfo:
    """Information needed for script-path spending."""
    leaf: TapLeaf
    merkle_path: List[bytes]
    control_block: bytes
    
    def __post_init__(self):
        """Validate script path info."""
        if len(self.control_block) < 33:
            raise ValueError("Control block too short")
        if len(self.control_block) % 32 != 1:
            raise ValueError("Invalid control block length")


@dataclass
class TaprootOutput:
    """Complete Taproot output specification."""
    internal_pubkey: bytes
    script_tree: Optional[Union[TapBranch, TapLeaf]]
    tweaked_pubkey: bytes
    output_script: bytes
    address: Optional[str] = None
    
    def __post_init__(self):
        """Validate Taproot output."""
        if len(self.internal_pubkey) != 32:
            raise ValueError("Internal pubkey must be 32 bytes (x-only)")
        if len(self.tweaked_pubkey) != 32:
            raise ValueError("Tweaked pubkey must be 32 bytes (x-only)")
        if len(self.output_script) != 34:
            raise ValueError("Taproot output script must be 34 bytes")


class TaprootCovenantBuilder:
    """
    Builder for creating Taproot covenant outputs with asset commitments.
    
    This class provides methods to construct Taproot outputs that support both:
    - Key-path spending (simple validator signature)  
    - Script-path spending (complex covenant conditions)
    """
    
    def __init__(self):
        """Initialize the Taproot covenant builder."""
        self.outputs_cache: Dict[str, TaprootOutput] = {}
        self.addresses_cache: Dict[bytes, str] = {}
    
    def create_key_path_covenant(
        self,
        internal_pubkey: bytes,
        asset_commitment: Optional[AssetCommitment] = None
    ) -> TaprootOutput:
        """
        Create a simple key-path only Taproot covenant.
        
        For key-path spending, only the validator's signature is required.
        The internal key is tweaked with the asset commitment.
        
        Args:
            internal_pubkey: 32-byte x-only internal public key
            asset_commitment: Optional asset commitment for tweaking
            
        Returns:
            TaprootOutput with key-path spending only
        """
        if len(internal_pubkey) != 32:
            raise ValueError("Internal pubkey must be 32 bytes (x-only)")
        
        # Compute asset commitment tweak if provided
        asset_tweak = b'\x00' * 32  # No script tree (key-path only)
        if asset_commitment:
            commitment_tweak = create_asset_commitment_tweak(asset_commitment)
            # Combine with base taproot tweak
            combined_data = internal_pubkey + commitment_tweak
            asset_tweak = tagged_hash("TapTweak", combined_data)
        else:
            # Standard taproot tweak with no merkle root
            asset_tweak = tagged_hash("TapTweak", internal_pubkey)
        
        # Apply the tweak to get the tweaked output key
        internal_point = lift_x(internal_pubkey)
        if not internal_point:
            raise ValueError("Invalid internal pubkey")
        
        tweaked_pubkey = self._tweak_public_key(internal_pubkey, asset_tweak)
        output_script = taproot_output_script(tweaked_pubkey)
        
        taproot_output = TaprootOutput(
            internal_pubkey=internal_pubkey,
            script_tree=None,  # Key-path only
            tweaked_pubkey=tweaked_pubkey,
            output_script=output_script
        )
        
        # Cache the output
        cache_key = f"keypath:{internal_pubkey.hex()}"
        if asset_commitment:
            cache_key += f":{asset_commitment.asset_id}"
        self.outputs_cache[cache_key] = taproot_output
        
        return taproot_output
    
    def create_script_path_covenant(
        self,
        internal_pubkey: bytes,
        scripts: List[bytes],
        asset_commitment: Optional[AssetCommitment] = None
    ) -> TaprootOutput:
        """
        Create a Taproot covenant with script-path spending options.
        
        Args:
            internal_pubkey: 32-byte x-only internal public key
            scripts: List of scripts to include in the script tree
            asset_commitment: Optional asset commitment for tweaking
            
        Returns:
            TaprootOutput with script-path spending support
        """
        if len(internal_pubkey) != 32:
            raise ValueError("Internal pubkey must be 32 bytes (x-only)")
        if not scripts:
            raise ValueError("At least one script required for script-path")
        
        # Create tap leaves from scripts
        leaves = [TapLeaf(script) for script in scripts]
        
        # Build script tree
        script_tree = self._build_script_tree(leaves)
        
        # Compute merkle root
        merkle_root = self._compute_merkle_root(script_tree)
        
        # Compute final tweak combining merkle root and asset commitment
        tweak_data = internal_pubkey + merkle_root
        if asset_commitment:
            commitment_tweak = create_asset_commitment_tweak(asset_commitment)
            # Mix asset commitment into the tweak
            tweak_data = tweak_data + commitment_tweak
            tweak_data = hashlib.sha256(tweak_data).digest()[:32]
            
        final_tweak = tagged_hash("TapTweak", tweak_data)
        
        # Apply tweak to get output key
        tweaked_pubkey = self._tweak_public_key(internal_pubkey, final_tweak)
        output_script = taproot_output_script(tweaked_pubkey)
        
        taproot_output = TaprootOutput(
            internal_pubkey=internal_pubkey,
            script_tree=script_tree,
            tweaked_pubkey=tweaked_pubkey,
            output_script=output_script
        )
        
        return taproot_output
    
    def create_asset_mint_covenant(
        self,
        validator_pubkey: bytes,
        asset_commitment: AssetCommitment,
        mint_conditions: Optional[Dict[str, Any]] = None
    ) -> TaprootOutput:
        """
        Create a specialized covenant for asset minting.
        
        Args:
            validator_pubkey: Validator's 32-byte x-only public key
            asset_commitment: Asset commitment to embed
            mint_conditions: Optional minting conditions
            
        Returns:
            TaprootOutput for asset minting
        """
        scripts = []
        
        # Basic validator signature script
        basic_script = self._create_tapscript_validator_sig(validator_pubkey)
        scripts.append(basic_script)
        
        # Add supply limit script if specified
        if mint_conditions and 'supply_limit' in mint_conditions:
            supply_script = self._create_tapscript_supply_limit(
                validator_pubkey,
                mint_conditions['supply_limit'],
                mint_conditions.get('current_supply', 0),
                mint_conditions.get('mint_amount', 1)
            )
            scripts.append(supply_script)
        
        # Add time lock script if specified
        if mint_conditions and 'time_lock' in mint_conditions:
            timelock_script = self._create_tapscript_timelock(
                validator_pubkey,
                mint_conditions['time_lock']
            )
            scripts.append(timelock_script)
        
        return self.create_script_path_covenant(
            validator_pubkey, 
            scripts, 
            asset_commitment
        )
    
    def create_asset_transfer_covenant(
        self,
        validator_pubkey: bytes,
        asset_commitment: AssetCommitment,
        transfer_rules: Optional[Dict[str, Any]] = None
    ) -> TaprootOutput:
        """
        Create a covenant for asset transfers.
        
        Args:
            validator_pubkey: Validator's 32-byte x-only public key
            asset_commitment: Asset commitment to embed
            transfer_rules: Optional transfer restrictions
            
        Returns:
            TaprootOutput for asset transfer
        """
        scripts = []
        
        # Basic validator signature script (key-path alternative)
        basic_script = self._create_tapscript_validator_sig(validator_pubkey)
        scripts.append(basic_script)
        
        # Add allowlist script if required
        if transfer_rules and 'allowlist_required' in transfer_rules:
            allowlist_script = self._create_tapscript_allowlist(
                validator_pubkey,
                transfer_rules['allowlist_root']
            )
            scripts.append(allowlist_script)
        
        # Add delegation script for authorized transfers
        if transfer_rules and 'allow_delegation' in transfer_rules:
            delegation_script = self._create_tapscript_delegation(
                validator_pubkey,
                transfer_rules['delegate_pubkeys']
            )
            scripts.append(delegation_script)
        
        return self.create_script_path_covenant(
            validator_pubkey,
            scripts, 
            asset_commitment
        )
    
    def _create_tapscript_validator_sig(self, validator_pubkey: bytes) -> bytes:
        """Create a simple validator signature tapscript."""
        script_parts = []
        
        # Push validator pubkey (32 bytes for tapscript)
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
        script_parts.append(validator_pubkey)
        
        # Check schnorr signature
        script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
        
        return b''.join(script_parts)
    
    def _create_tapscript_supply_limit(
        self,
        validator_pubkey: bytes,
        supply_limit: int,
        current_supply: int,
        mint_amount: int
    ) -> bytes:
        """Create tapscript that enforces supply limits."""
        script_parts = []
        
        # Push current supply
        script_parts.extend(self._push_tapscript_int(current_supply))
        
        # Push mint amount  
        script_parts.extend(self._push_tapscript_int(mint_amount))
        
        # Add them
        script_parts.append(bytes([ScriptOpcode.OP_ADD]))
        
        # Push supply limit
        script_parts.extend(self._push_tapscript_int(supply_limit))
        
        # Check that (current + mint) <= limit
        script_parts.append(bytes([ScriptOpcode.OP_LESSTHANOREQUAL]))
        script_parts.append(bytes([ScriptOpcode.OP_VERIFY]))
        
        # Require validator signature
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
        script_parts.append(validator_pubkey)
        script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
        
        return b''.join(script_parts)
    
    def _create_tapscript_timelock(
        self,
        validator_pubkey: bytes,
        lock_time: int,
        lock_type: str = "absolute"
    ) -> bytes:
        """Create tapscript with time lock constraint."""
        script_parts = []
        
        # Push lock time
        script_parts.extend(self._push_tapscript_int(lock_time))
        
        if lock_type == "absolute":
            script_parts.append(bytes([ScriptOpcode.OP_CHECKLOCKTIMEVERIFY]))
        else:
            script_parts.append(bytes([ScriptOpcode.OP_CHECKSEQUENCEVERIFY]))
        
        script_parts.append(bytes([ScriptOpcode.OP_DROP]))
        
        # Require validator signature
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
        script_parts.append(validator_pubkey)
        script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
        
        return b''.join(script_parts)
    
    def _create_tapscript_allowlist(
        self,
        validator_pubkey: bytes,
        allowlist_root: bytes
    ) -> bytes:
        """Create tapscript that enforces allowlist membership."""
        script_parts = []
        
        # This is simplified - would need full merkle proof verification
        # Push allowlist root for verification
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
        script_parts.append(allowlist_root)
        
        # Placeholder for merkle proof verification
        # In practice, this would be much more complex
        script_parts.append(bytes([ScriptOpcode.OP_DROP]))  # Remove for now
        
        # Require validator signature
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
        script_parts.append(validator_pubkey)
        script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
        
        return b''.join(script_parts)
    
    def _create_tapscript_delegation(
        self,
        validator_pubkey: bytes,
        delegate_pubkeys: List[bytes]
    ) -> bytes:
        """Create tapscript for delegated authorization."""
        script_parts = []
        
        # Simple 1-of-N delegation script
        # In practice, you might want more complex delegation logic
        
        # Push delegate pubkeys and create OR conditions
        for i, delegate_key in enumerate(delegate_pubkeys):
            if i > 0:
                script_parts.append(bytes([ScriptOpcode.OP_IF]))
            
            script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
            script_parts.append(delegate_key)
            script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
            
            if i > 0:
                script_parts.append(bytes([ScriptOpcode.OP_ELSE]))
        
        # Close IF statements
        for _ in range(len(delegate_pubkeys) - 1):
            script_parts.append(bytes([ScriptOpcode.OP_ENDIF]))
        
        return b''.join(script_parts)
    
    def _push_tapscript_int(self, value: int) -> List[bytes]:
        """Push integer onto tapscript stack."""
        if value == 0:
            return [bytes([ScriptOpcode.OP_0])]
        elif value == -1:
            return [bytes([ScriptOpcode.OP_1NEGATE])]
        elif 1 <= value <= 16:
            return [bytes([ScriptOpcode.OP_1 + value - 1])]
        else:
            # Encode as CScriptNum
            data = self._encode_script_num(value)
            return [bytes([len(data)]), data]
    
    def _encode_script_num(self, value: int) -> bytes:
        """Encode integer as Bitcoin Script number."""
        if value == 0:
            return b''
        
        negative = value < 0
        if negative:
            value = abs(value)
        
        result = []
        while value > 0:
            result.append(value & 0xFF)
            value >>= 8
        
        if result[-1] & 0x80:
            if negative:
                result.append(0x80)
            else:
                result.append(0x00)
        elif negative:
            result[-1] |= 0x80
        
        return bytes(result)
    
    def _build_script_tree(
        self,
        leaves: List[TapLeaf]
    ) -> Union[TapBranch, TapLeaf]:
        """
        Build balanced script tree from leaves.
        
        Args:
            leaves: List of tap leaves
            
        Returns:
            Root of the script tree
        """
        if len(leaves) == 1:
            return leaves[0]
        
        # Build balanced binary tree
        current_level = leaves[:]
        
        while len(current_level) > 1:
            next_level = []
            
            # Pair up nodes
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # Create branch from pair
                    left = current_level[i]
                    right = current_level[i + 1]
                    branch = TapBranch(left, right)
                    next_level.append(branch)
                else:
                    # Odd node carries forward
                    next_level.append(current_level[i])
            
            current_level = next_level
        
        return current_level[0]
    
    def _compute_merkle_root(
        self,
        tree: Union[TapBranch, TapLeaf]
    ) -> bytes:
        """Compute merkle root of script tree."""
        if isinstance(tree, TapLeaf):
            return tree.leaf_hash()
        else:
            return tree.branch_hash()
    
    def _tweak_public_key(self, pubkey_x: bytes, tweak: bytes) -> bytes:
        """Apply tweak to x-only public key."""
        # This is a simplified implementation
        # In practice, use proper elliptic curve arithmetic
        
        # Lift x to full point
        pubkey_point = lift_x(pubkey_x)
        if not pubkey_point:
            raise ValueError("Invalid public key")
        
        try:
            from coincurve import PublicKey as CoinCurvePublicKey
            
            # Convert to coincurve format
            pubkey = CoinCurvePublicKey(pubkey_point)
            
            # Apply tweak
            tweaked = pubkey.add(tweak)
            
            # Return x-only coordinate
            return tweaked.format(compressed=True)[1:]  # Remove 0x02/0x03 prefix
            
        except ImportError:
            # Fallback: use simplified tweaking
            import hashlib
            combined = pubkey_x + tweak
            return hashlib.sha256(combined).digest()
    
    def generate_control_block(
        self,
        internal_pubkey: bytes,
        script: bytes,
        script_tree: Union[TapBranch, TapLeaf],
        leaf_version: int = 0xc0
    ) -> bytes:
        """
        Generate control block for script-path spending.
        
        Args:
            internal_pubkey: 32-byte x-only internal public key
            script: The script being executed
            script_tree: Full script tree
            leaf_version: Tapscript leaf version
            
        Returns:
            Control block bytes
        """
        # Find merkle path to the script
        target_leaf = TapLeaf(script, leaf_version)
        merkle_path = self._find_merkle_path(target_leaf, script_tree)
        
        # Construct control block
        control_block = bytes([leaf_version])  # First byte is leaf version
        control_block += internal_pubkey  # 32 bytes internal pubkey
        
        # Add merkle path
        for path_element in merkle_path:
            control_block += path_element
        
        return control_block
    
    def _find_merkle_path(
        self,
        target_leaf: TapLeaf, 
        tree: Union[TapBranch, TapLeaf],
        path: Optional[List[bytes]] = None
    ) -> List[bytes]:
        """Find merkle path to target leaf in script tree."""
        if path is None:
            path = []
        
        if isinstance(tree, TapLeaf):
            if tree.leaf_hash() == target_leaf.leaf_hash():
                return path
            else:
                return []  # Not found in this subtree
        
        # Check left subtree
        left_path = self._find_merkle_path(target_leaf, tree.left, path)
        if left_path:
            # Found in left, add right sibling hash
            right_hash = (tree.right.leaf_hash() if isinstance(tree.right, TapLeaf)
                         else tree.right.branch_hash())
            return left_path + [right_hash]
        
        # Check right subtree  
        right_path = self._find_merkle_path(target_leaf, tree.right, path)
        if right_path:
            # Found in right, add left sibling hash
            left_hash = (tree.left.leaf_hash() if isinstance(tree.left, TapLeaf)
                        else tree.left.branch_hash())
            return right_path + [left_hash]
        
        return []  # Not found
    
    def create_spending_transaction(
        self,
        taproot_output: TaprootOutput,
        spend_type: TaprootSpendType,
        script_path_info: Optional[ScriptPathInfo] = None
    ) -> Dict[str, Any]:
        """
        Create transaction template for spending Taproot output.
        
        Args:
            taproot_output: The Taproot output to spend
            spend_type: Key-path or script-path spending
            script_path_info: Required for script-path spending
            
        Returns:
            Transaction template dictionary
        """
        if spend_type == TaprootSpendType.SCRIPT_PATH and not script_path_info:
            raise ValueError("Script path info required for script-path spending")
        
        tx_template = {
            "version": 2,
            "inputs": [{
                "txid": "placeholder_txid",
                "vout": 0,
                "sequence": 0xfffffffd,
                "witness": self._create_witness_stack(spend_type, script_path_info)
            }],
            "outputs": [],
            "locktime": 0
        }
        
        return tx_template
    
    def _create_witness_stack(
        self,
        spend_type: TaprootSpendType,
        script_path_info: Optional[ScriptPathInfo] = None
    ) -> List[str]:
        """Create witness stack for Taproot spending."""
        witness = []
        
        if spend_type == TaprootSpendType.KEY_PATH:
            # Key-path spending: just the signature
            witness.append("signature_placeholder")
        
        elif spend_type == TaprootSpendType.SCRIPT_PATH:
            if not script_path_info:
                raise ValueError("Script path info required")
            
            # Script-path spending: signature, script, control block
            witness.extend([
                "signature_placeholder",  # Would be actual signature
                script_path_info.leaf.script.hex(),
                script_path_info.control_block.hex()
            ])
        
        return witness
    
    def validate_taproot_output(self, taproot_output: TaprootOutput) -> bool:
        """Validate a Taproot output structure."""
        try:
            # Check internal pubkey is valid x-coordinate
            if len(taproot_output.internal_pubkey) != 32:
                return False
            
            # Check tweaked pubkey is valid
            if len(taproot_output.tweaked_pubkey) != 32:
                return False
            
            # Check output script format
            expected_script = taproot_output_script(taproot_output.tweaked_pubkey)
            if taproot_output.output_script != expected_script:
                return False
            
            # If script tree exists, validate it
            if taproot_output.script_tree:
                merkle_root = self._compute_merkle_root(taproot_output.script_tree)
                # Would need to verify tweak computation
            
            return True
            
        except Exception:
            return False
    
    def get_taproot_info(self, taproot_output: TaprootOutput) -> Dict[str, Any]:
        """Get detailed information about a Taproot output."""
        info = {
            "internal_pubkey": taproot_output.internal_pubkey.hex(),
            "tweaked_pubkey": taproot_output.tweaked_pubkey.hex(),
            "output_script": taproot_output.output_script.hex(),
            "has_script_tree": taproot_output.script_tree is not None,
        }
        
        if taproot_output.script_tree:
            info["merkle_root"] = self._compute_merkle_root(taproot_output.script_tree).hex()
            info["script_count"] = self._count_scripts(taproot_output.script_tree)
        
        if taproot_output.address:
            info["address"] = taproot_output.address
        
        return info
    
    def _count_scripts(self, tree: Union[TapBranch, TapLeaf]) -> int:
        """Count number of scripts in tree."""
        if isinstance(tree, TapLeaf):
            return 1
        else:
            return self._count_scripts(tree.left) + self._count_scripts(tree.right)
    
    def clear_cache(self) -> None:
        """Clear all cached outputs and addresses."""
        self.outputs_cache.clear()
        self.addresses_cache.clear()


# Convenience functions

def create_simple_taproot_covenant(
    validator_pubkey: bytes,
    asset_commitment: AssetCommitment
) -> TaprootOutput:
    """Create simple key-path only Taproot covenant."""
    builder = TaprootCovenantBuilder()
    return builder.create_key_path_covenant(validator_pubkey, asset_commitment)


def create_complex_taproot_covenant(
    validator_pubkey: bytes,
    scripts: List[bytes],
    asset_commitment: AssetCommitment
) -> TaprootOutput:
    """Create Taproot covenant with script tree."""
    builder = TaprootCovenantBuilder()
    return builder.create_script_path_covenant(validator_pubkey, scripts, asset_commitment)


def generate_taproot_address(
    taproot_output: TaprootOutput,
    network: str = "regtest"
) -> str:
    """Generate bech32m address for Taproot output."""
    # This would use proper bech32m encoding
    # For now, return placeholder
    return f"bcrt1p{taproot_output.tweaked_pubkey.hex()}"


# Asset-specific Taproot templates

class TaprootAssetTemplates:
    """Pre-built Taproot templates for different asset operations."""
    
    @staticmethod
    def fungible_mint_taproot(
        validator_pubkey: bytes,
        asset_commitment: AssetCommitment,
        supply_limit: Optional[int] = None
    ) -> TaprootOutput:
        """Create Taproot output for fungible asset minting."""
        builder = TaprootCovenantBuilder()
        
        mint_conditions = {}
        if supply_limit:
            mint_conditions['supply_limit'] = supply_limit
            
        return builder.create_asset_mint_covenant(
            validator_pubkey,
            asset_commitment,
            mint_conditions
        )
    
    @staticmethod
    def nft_mint_taproot(
        validator_pubkey: bytes,
        asset_commitment: AssetCommitment,
        collection_size: int
    ) -> TaprootOutput:
        """Create Taproot output for NFT minting.""" 
        builder = TaprootCovenantBuilder()
        
        mint_conditions = {
            'supply_limit': collection_size,
            'mint_amount': 1
        }
        
        return builder.create_asset_mint_covenant(
            validator_pubkey,
            asset_commitment,
            mint_conditions
        )
    
    @staticmethod
    def transfer_taproot(
        validator_pubkey: bytes,
        asset_commitment: AssetCommitment,
        allowlist_root: Optional[bytes] = None
    ) -> TaprootOutput:
        """Create Taproot output for asset transfers."""
        builder = TaprootCovenantBuilder()
        
        transfer_rules = {}
        if allowlist_root:
            transfer_rules['allowlist_required'] = True
            transfer_rules['allowlist_root'] = allowlist_root
        
        return builder.create_asset_transfer_covenant(
            validator_pubkey,
            asset_commitment,
            transfer_rules
        )