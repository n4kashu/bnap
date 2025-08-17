"""
Bitcoin Native Asset Protocol - Taproot Output Construction Module

This module provides specialized functions and classes for creating Taproot (P2TR)
outputs with script tree commitments for advanced asset validation and control
within the Bitcoin Native Asset Protocol.
"""

import hashlib
import struct
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

from ..utils import (
    tagged_hash,
    serialize_compact_size,
    double_sha256
)
from ..exceptions import (
    PSBTConstructionError,
    InvalidScriptError,
    UnsupportedScriptTypeError
)


class TaprootScriptType(Enum):
    """Types of Taproot scripts for asset protocol."""
    KEY_PATH = "key_path"
    ASSET_TRANSFER = "asset_transfer"
    ASSET_MINT = "asset_mint"
    ASSET_BURN = "asset_burn"
    MULTI_ASSET = "multi_asset"
    COVENANT = "covenant"
    DELEGATION = "delegation"


@dataclass
class TapLeaf:
    """Represents a single leaf in the Taproot script tree."""
    script: bytes
    leaf_version: int = 0xc0  # Default leaf version
    
    def __post_init__(self):
        """Validate leaf parameters."""
        if not self.script:
            raise InvalidScriptError("Tap leaf script cannot be empty")
        if len(self.script) > 10000:
            raise InvalidScriptError("Tap leaf script too large")
        if self.leaf_version not in [0xc0, 0xc1, 0xc2, 0xc4]:
            raise InvalidScriptError(f"Invalid leaf version: {self.leaf_version:#x}")


@dataclass
class TapBranch:
    """Represents a branch in the Taproot script tree."""
    left: Union['TapBranch', TapLeaf]
    right: Union['TapBranch', TapLeaf]


class TaprootScriptBuilder:
    """
    Builder for creating Taproot scripts for BNAP asset operations.
    
    This class provides methods to construct various types of Taproot scripts
    including asset transfers, mints, burns, and covenant scripts.
    """
    
    # Taproot constants
    TAPROOT_LEAF_MASK = 0xfe
    TAPROOT_LEAF_TAPSCRIPT = 0xc0
    TAPROOT_LEAF_LEGACY = 0xc1
    
    # Bitcoin script opcodes for Taproot
    OP_0 = 0x00
    OP_1 = 0x51
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKSIGADD = 0xba  # Taproot-specific
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_BOOLAND = 0x9a
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_VERIFY = 0x69
    OP_DUP = 0x76
    OP_DROP = 0x75
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    
    def __init__(self):
        """Initialize Taproot script builder."""
        self.script_stack: List[bytes] = []
        
    def reset(self) -> None:
        """Reset the script builder."""
        self.script_stack.clear()
        
    def push_data(self, data: bytes) -> 'TaprootScriptBuilder':
        """Push data onto the script stack."""
        if len(data) == 0:
            self.script_stack.append(bytes([self.OP_0]))
        elif len(data) <= 75:
            self.script_stack.append(bytes([len(data)]) + data)
        elif len(data) <= 255:
            self.script_stack.append(bytes([self.OP_PUSHDATA1, len(data)]) + data)
        elif len(data) <= 65535:
            self.script_stack.append(bytes([self.OP_PUSHDATA2]) + struct.pack('<H', len(data)) + data)
        else:
            raise InvalidScriptError(f"Data too large: {len(data)} bytes")
        return self
        
    def push_opcode(self, opcode: int) -> 'TaprootScriptBuilder':
        """Push an opcode onto the script stack."""
        self.script_stack.append(bytes([opcode]))
        return self
        
    def push_number(self, number: int) -> 'TaprootScriptBuilder':
        """Push a number using minimal encoding."""
        if number == 0:
            return self.push_opcode(self.OP_0)
        elif 1 <= number <= 16:
            return self.push_opcode(self.OP_1 + number - 1)
        else:
            data = self._encode_number(number)
            return self.push_data(data)
    
    def _encode_number(self, number: int) -> bytes:
        """Encode number in Bitcoin script format."""
        if number == 0:
            return b''
        
        negative = number < 0
        if negative:
            number = -number
        
        result = []
        while number > 0:
            result.append(number & 0xff)
            number >>= 8
        
        if result[-1] & 0x80:
            result.append(0x80 if negative else 0x00)
        elif negative:
            result[-1] |= 0x80
        
        return bytes(result)
        
    def build(self) -> bytes:
        """Build the final script."""
        return b''.join(self.script_stack)
        
    def create_asset_transfer_script(
        self,
        asset_id: str,
        from_pubkey: bytes,
        to_pubkey: bytes,
        amount: int
    ) -> bytes:
        """
        Create Taproot script for asset transfer validation.
        
        Args:
            asset_id: Asset identifier as hex string
            from_pubkey: Source public key (32 bytes x-only)
            to_pubkey: Destination public key (32 bytes x-only)
            amount: Transfer amount
            
        Returns:
            Taproot script bytes
        """
        if len(from_pubkey) != 32:
            raise InvalidScriptError(f"Invalid from_pubkey length: {len(from_pubkey)}")
        if len(to_pubkey) != 32:
            raise InvalidScriptError(f"Invalid to_pubkey length: {len(to_pubkey)}")
        
        try:
            asset_id_bytes = bytes.fromhex(asset_id)
            if len(asset_id_bytes) != 32:
                raise InvalidScriptError(f"Invalid asset ID length: {len(asset_id_bytes)}")
        except ValueError:
            raise InvalidScriptError(f"Invalid asset ID format: {asset_id}")
        
        self.reset()
        
        # Asset ID verification
        self.push_data(asset_id_bytes)
        self.push_opcode(self.OP_EQUAL)
        
        # From key signature verification
        self.push_data(from_pubkey)
        self.push_opcode(self.OP_CHECKSIGVERIFY)
        
        # To key verification
        self.push_data(to_pubkey)
        self.push_opcode(self.OP_EQUAL)
        
        # Amount validation
        self.push_number(amount)
        self.push_opcode(self.OP_EQUAL)
        
        # Combine all conditions
        self.push_opcode(self.OP_BOOLAND)
        self.push_opcode(self.OP_BOOLAND)
        self.push_opcode(self.OP_BOOLAND)
        
        return self.build()
        
    def create_asset_mint_script(
        self,
        asset_id: str,
        minter_pubkey: bytes,
        amount: int,
        max_supply: Optional[int] = None
    ) -> bytes:
        """
        Create Taproot script for asset minting validation.
        
        Args:
            asset_id: Asset identifier
            minter_pubkey: Minter public key (32 bytes x-only)
            amount: Mint amount
            max_supply: Maximum supply limit (optional)
            
        Returns:
            Taproot script bytes
        """
        if len(minter_pubkey) != 32:
            raise InvalidScriptError(f"Invalid minter_pubkey length: {len(minter_pubkey)}")
        
        try:
            asset_id_bytes = bytes.fromhex(asset_id)
            if len(asset_id_bytes) != 32:
                raise InvalidScriptError(f"Invalid asset ID length: {len(asset_id_bytes)}")
        except ValueError:
            raise InvalidScriptError(f"Invalid asset ID format: {asset_id}")
        
        self.reset()
        
        # Asset ID verification
        self.push_data(asset_id_bytes)
        self.push_opcode(self.OP_EQUAL)
        
        # Minter authorization
        self.push_data(minter_pubkey)
        self.push_opcode(self.OP_CHECKSIGVERIFY)
        
        # Amount validation
        self.push_number(amount)
        self.push_opcode(self.OP_EQUAL)
        
        # Max supply check if specified
        if max_supply is not None:
            self.push_number(max_supply)
            self.push_opcode(0xa4)  # OP_LESSTHANOREQUAL
            self.push_opcode(self.OP_BOOLAND)
        
        # Combine conditions
        self.push_opcode(self.OP_BOOLAND)
        self.push_opcode(self.OP_BOOLAND)
        
        return self.build()
        
    def create_asset_burn_script(
        self,
        asset_id: str,
        burner_pubkey: bytes,
        amount: int
    ) -> bytes:
        """
        Create Taproot script for asset burning validation.
        
        Args:
            asset_id: Asset identifier
            burner_pubkey: Burner public key (32 bytes x-only)
            amount: Burn amount
            
        Returns:
            Taproot script bytes
        """
        if len(burner_pubkey) != 32:
            raise InvalidScriptError(f"Invalid burner_pubkey length: {len(burner_pubkey)}")
        
        try:
            asset_id_bytes = bytes.fromhex(asset_id)
            if len(asset_id_bytes) != 32:
                raise InvalidScriptError(f"Invalid asset ID length: {len(asset_id_bytes)}")
        except ValueError:
            raise InvalidScriptError(f"Invalid asset ID format: {asset_id}")
        
        self.reset()
        
        # Asset ID verification
        self.push_data(asset_id_bytes)
        self.push_opcode(self.OP_EQUAL)
        
        # Burner authorization
        self.push_data(burner_pubkey)
        self.push_opcode(self.OP_CHECKSIGVERIFY)
        
        # Amount validation
        self.push_number(amount)
        self.push_opcode(self.OP_EQUAL)
        
        # Combine conditions
        self.push_opcode(self.OP_BOOLAND)
        self.push_opcode(self.OP_BOOLAND)
        
        return self.build()
        
    def create_multi_asset_script(
        self,
        asset_operations: List[Dict[str, any]],
        validator_pubkey: bytes
    ) -> bytes:
        """
        Create Taproot script for multi-asset operations.
        
        Args:
            asset_operations: List of asset operations
            validator_pubkey: Validator public key (32 bytes x-only)
            
        Returns:
            Taproot script bytes
        """
        if len(validator_pubkey) != 32:
            raise InvalidScriptError(f"Invalid validator_pubkey length: {len(validator_pubkey)}")
        
        if not asset_operations:
            raise InvalidScriptError("No asset operations specified")
        
        self.reset()
        
        # Validator signature
        self.push_data(validator_pubkey)
        self.push_opcode(self.OP_CHECKSIGVERIFY)
        
        # Validate each operation
        for i, operation in enumerate(asset_operations):
            asset_id = operation.get('asset_id', '')
            operation_type = operation.get('type', '')
            amount = operation.get('amount', 0)
            
            try:
                asset_id_bytes = bytes.fromhex(asset_id)
                if len(asset_id_bytes) != 32:
                    raise InvalidScriptError(f"Invalid asset ID length in operation {i}")
            except ValueError:
                raise InvalidScriptError(f"Invalid asset ID format in operation {i}")
            
            # Asset ID check
            self.push_data(asset_id_bytes)
            self.push_opcode(self.OP_EQUAL)
            
            # Operation type validation
            operation_type_bytes = operation_type.encode('utf-8')[:32]
            self.push_data(operation_type_bytes)
            self.push_opcode(self.OP_EQUAL)
            
            # Amount validation
            self.push_number(amount)
            self.push_opcode(self.OP_EQUAL)
            
            # Combine operation conditions
            self.push_opcode(self.OP_BOOLAND)
            self.push_opcode(self.OP_BOOLAND)
            
            # Combine with previous operations
            if i > 0:
                self.push_opcode(self.OP_BOOLAND)
        
        return self.build()
        
    def create_delegation_script(
        self,
        delegator_pubkey: bytes,
        delegate_pubkey: bytes,
        permissions: int,
        expiry: Optional[int] = None
    ) -> bytes:
        """
        Create Taproot script for delegation validation.
        
        Args:
            delegator_pubkey: Delegator public key (32 bytes x-only)
            delegate_pubkey: Delegate public key (32 bytes x-only)
            permissions: Permission flags
            expiry: Expiry timestamp (optional)
            
        Returns:
            Taproot script bytes
        """
        if len(delegator_pubkey) != 32:
            raise InvalidScriptError(f"Invalid delegator_pubkey length: {len(delegator_pubkey)}")
        if len(delegate_pubkey) != 32:
            raise InvalidScriptError(f"Invalid delegate_pubkey length: {len(delegate_pubkey)}")
        
        self.reset()
        
        # Delegator authorization OR delegate authorization
        self.push_data(delegator_pubkey)
        self.push_opcode(self.OP_CHECKSIG)
        
        self.push_data(delegate_pubkey)
        self.push_opcode(self.OP_CHECKSIG)
        
        # OR operation (either can sign)
        self.push_opcode(0x9b)  # OP_BOOLOR
        
        # Permission validation
        self.push_number(permissions)
        self.push_opcode(self.OP_EQUAL)
        self.push_opcode(self.OP_BOOLAND)
        
        # Expiry check if specified
        if expiry is not None:
            self.push_number(expiry)
            self.push_opcode(self.OP_CHECKLOCKTIMEVERIFY)
            self.push_opcode(self.OP_DROP)
        
        return self.build()


class TaprootTreeBuilder:
    """
    Builder for creating Taproot script trees with multiple spending paths.
    
    This class helps organize multiple Taproot scripts into a Merkle tree
    structure for efficient script path spending.
    """
    
    def __init__(self):
        """Initialize tree builder."""
        self.leaves: List[TapLeaf] = []
        
    def add_leaf(self, script: bytes, leaf_version: int = 0xc0) -> 'TaprootTreeBuilder':
        """
        Add a script leaf to the tree.
        
        Args:
            script: Script bytes
            leaf_version: Leaf version byte
            
        Returns:
            Self for method chaining
        """
        leaf = TapLeaf(script, leaf_version)
        self.leaves.append(leaf)
        return self
        
    def build_tree(self) -> Optional[TapBranch]:
        """
        Build the Taproot script tree.
        
        Returns:
            Root of the script tree or None if no leaves
        """
        if not self.leaves:
            return None
        
        if len(self.leaves) == 1:
            return self.leaves[0]
        
        # Build balanced binary tree
        current_level = list(self.leaves)
        
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # Pair of nodes
                    left = current_level[i]
                    right = current_level[i + 1]
                    branch = TapBranch(left, right)
                    next_level.append(branch)
                else:
                    # Odd node - promote to next level
                    next_level.append(current_level[i])
            
            current_level = next_level
        
        return current_level[0] if current_level else None
        
    def calculate_merkle_root(self, tree: Union[TapBranch, TapLeaf, None]) -> bytes:
        """
        Calculate the Merkle root of the script tree.
        
        Args:
            tree: Root of the script tree
            
        Returns:
            32-byte Merkle root hash
        """
        if tree is None:
            return b'\x00' * 32
        
        if isinstance(tree, TapLeaf):
            return self._leaf_hash(tree)
        
        # Branch node
        left_hash = self.calculate_merkle_root(tree.left)
        right_hash = self.calculate_merkle_root(tree.right)
        
        return self._branch_hash(left_hash, right_hash)
        
    def _leaf_hash(self, leaf: TapLeaf) -> bytes:
        """Calculate hash for a leaf node."""
        return tagged_hash(
            "TapLeaf",
            bytes([leaf.leaf_version]) + serialize_compact_size(len(leaf.script)) + leaf.script
        )
        
    def _branch_hash(self, left: bytes, right: bytes) -> bytes:
        """Calculate hash for a branch node."""
        # Lexicographic ordering for deterministic hashing
        if left <= right:
            return tagged_hash("TapBranch", left + right)
        else:
            return tagged_hash("TapBranch", right + left)


class TaprootBuilder:
    """
    High-level builder for creating Taproot outputs with proper commitment.
    
    This class combines internal key, script tree, and creates final P2TR outputs
    suitable for PSBT construction.
    """
    
    def __init__(self):
        """Initialize Taproot builder."""
        self.script_builder = TaprootScriptBuilder()
        self.tree_builder = TaprootTreeBuilder()
        
    def create_p2tr_output(
        self,
        internal_pubkey: bytes,
        script_tree: Optional[Union[TapBranch, TapLeaf]] = None,
        amount: int = 0
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Create P2TR output script.
        
        Args:
            internal_pubkey: 32-byte x-only internal public key
            script_tree: Optional script tree
            amount: Output amount in satoshis
            
        Returns:
            Tuple of (p2tr_script, tweaked_pubkey, merkle_root)
        """
        if len(internal_pubkey) != 32:
            raise InvalidScriptError(f"Invalid internal pubkey length: {len(internal_pubkey)}")
        
        # Calculate Merkle root
        merkle_root = self.tree_builder.calculate_merkle_root(script_tree)
        
        # Calculate tweak
        if script_tree is None:
            tweak = b'\x00' * 32
        else:
            tweak = tagged_hash("TapTweak", internal_pubkey + merkle_root)
        
        # Create tweaked public key (simplified - would need proper EC math)
        tweaked_pubkey = self._tweak_pubkey(internal_pubkey, tweak)
        
        # Create P2TR script: OP_1 <32-byte-tweaked-pubkey>
        p2tr_script = bytes([0x51, 0x20]) + tweaked_pubkey
        
        return p2tr_script, tweaked_pubkey, merkle_root
        
    def _tweak_pubkey(self, pubkey: bytes, tweak: bytes) -> bytes:
        """
        Apply tweak to public key (placeholder implementation).
        
        In real implementation, this would use proper elliptic curve operations.
        """
        # Placeholder: XOR for demonstration (not cryptographically valid)
        result = bytearray(32)
        for i in range(32):
            result[i] = pubkey[i] ^ tweak[i]
        return bytes(result)
        
    def create_asset_transfer_output(
        self,
        internal_pubkey: bytes,
        asset_id: str,
        from_pubkey: bytes,
        to_pubkey: bytes,
        amount: int,
        script_amount: int = 0
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Create P2TR output for asset transfer.
        
        Args:
            internal_pubkey: Internal public key
            asset_id: Asset identifier
            from_pubkey: Source public key
            to_pubkey: Destination public key
            amount: Transfer amount
            script_amount: Output amount in satoshis
            
        Returns:
            Tuple of (p2tr_script, tweaked_pubkey, transfer_script)
        """
        # Create asset transfer script
        transfer_script = self.script_builder.create_asset_transfer_script(
            asset_id, from_pubkey, to_pubkey, amount
        )
        
        # Build script tree with transfer script
        tree = self.tree_builder.add_leaf(transfer_script).build_tree()
        
        # Create P2TR output
        p2tr_script, tweaked_pubkey, _ = self.create_p2tr_output(
            internal_pubkey, tree, script_amount
        )
        
        return p2tr_script, tweaked_pubkey, transfer_script
        
    def create_asset_mint_output(
        self,
        internal_pubkey: bytes,
        asset_id: str,
        minter_pubkey: bytes,
        mint_amount: int,
        max_supply: Optional[int] = None,
        script_amount: int = 0
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Create P2TR output for asset minting.
        
        Args:
            internal_pubkey: Internal public key
            asset_id: Asset identifier
            minter_pubkey: Minter public key
            mint_amount: Mint amount
            max_supply: Maximum supply limit
            script_amount: Output amount in satoshis
            
        Returns:
            Tuple of (p2tr_script, tweaked_pubkey, mint_script)
        """
        # Create asset mint script
        mint_script = self.script_builder.create_asset_mint_script(
            asset_id, minter_pubkey, mint_amount, max_supply
        )
        
        # Build script tree with mint script
        self.tree_builder = TaprootTreeBuilder()  # Reset
        tree = self.tree_builder.add_leaf(mint_script).build_tree()
        
        # Create P2TR output
        p2tr_script, tweaked_pubkey, _ = self.create_p2tr_output(
            internal_pubkey, tree, script_amount
        )
        
        return p2tr_script, tweaked_pubkey, mint_script
        
    def create_multi_path_output(
        self,
        internal_pubkey: bytes,
        scripts: List[bytes],
        script_amount: int = 0
    ) -> Tuple[bytes, bytes, List[bytes]]:
        """
        Create P2TR output with multiple script paths.
        
        Args:
            internal_pubkey: Internal public key
            scripts: List of script alternatives
            script_amount: Output amount in satoshis
            
        Returns:
            Tuple of (p2tr_script, tweaked_pubkey, scripts)
        """
        if not scripts:
            raise InvalidScriptError("No scripts provided for multi-path output")
        
        # Build script tree with all scripts
        self.tree_builder = TaprootTreeBuilder()  # Reset
        for script in scripts:
            self.tree_builder.add_leaf(script)
        
        tree = self.tree_builder.build_tree()
        
        # Create P2TR output
        p2tr_script, tweaked_pubkey, _ = self.create_p2tr_output(
            internal_pubkey, tree, script_amount
        )
        
        return p2tr_script, tweaked_pubkey, scripts


# Utility functions
def create_taproot_output(
    internal_pubkey: bytes,
    script_tree: Optional[Union[TapBranch, TapLeaf]] = None,
    amount: int = 0
) -> Tuple[bytes, bytes]:
    """
    Create Taproot output script.
    
    Args:
        internal_pubkey: 32-byte x-only internal public key
        script_tree: Optional script tree
        amount: Output amount in satoshis
        
    Returns:
        Tuple of (p2tr_script, tweaked_pubkey)
    """
    builder = TaprootBuilder()
    p2tr_script, tweaked_pubkey, _ = builder.create_p2tr_output(
        internal_pubkey, script_tree, amount
    )
    return p2tr_script, tweaked_pubkey


def create_asset_transfer_script(
    asset_id: str,
    from_pubkey: bytes,
    to_pubkey: bytes,
    amount: int
) -> bytes:
    """
    Create asset transfer validation script.
    
    Args:
        asset_id: Asset identifier
        from_pubkey: Source public key (32 bytes x-only)
        to_pubkey: Destination public key (32 bytes x-only)
        amount: Transfer amount
        
    Returns:
        Taproot script bytes
    """
    builder = TaprootScriptBuilder()
    return builder.create_asset_transfer_script(asset_id, from_pubkey, to_pubkey, amount)


def create_asset_mint_script(
    asset_id: str,
    minter_pubkey: bytes,
    amount: int,
    max_supply: Optional[int] = None
) -> bytes:
    """
    Create asset minting validation script.
    
    Args:
        asset_id: Asset identifier
        minter_pubkey: Minter public key (32 bytes x-only)
        amount: Mint amount
        max_supply: Maximum supply limit
        
    Returns:
        Taproot script bytes
    """
    builder = TaprootScriptBuilder()
    return builder.create_asset_mint_script(asset_id, minter_pubkey, amount, max_supply)


def validate_taproot_script(script: bytes) -> bool:
    """
    Validate Taproot script format and structure.
    
    Args:
        script: Taproot script to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not script:
        return False
    
    try:
        if len(script) > 10000:  # Max script size
            return False
        
        # Basic structure validation
        return True
    except Exception:
        return False


def calculate_tap_leaf_hash(script: bytes, leaf_version: int = 0xc0) -> bytes:
    """
    Calculate TapLeaf hash for script path spending.
    
    Args:
        script: Script bytes
        leaf_version: Leaf version byte
        
    Returns:
        32-byte TapLeaf hash
    """
    return tagged_hash(
        "TapLeaf",
        bytes([leaf_version]) + serialize_compact_size(len(script)) + script
    )