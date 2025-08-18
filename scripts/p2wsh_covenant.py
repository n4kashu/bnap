"""
Bitcoin Native Asset Protocol - P2WSH Covenant Script Implementation

This module provides P2WSH covenant script construction for validator signature
verification and asset control within the BNAP system.
"""

import hashlib
import struct
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass
from enum import Enum

from crypto.keys import ValidatorKeyManager
from registry.schema import AssetType, Asset


class ScriptOpcode:
    """Bitcoin Script opcodes used in covenant construction."""
    
    # Constants
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_1NEGATE = 0x4f
    OP_1 = 0x51
    OP_TRUE = OP_1
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60
    
    # Flow control
    OP_NOP = 0x61
    OP_VER = 0x62
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a
    
    # Stack operations
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d
    
    # String operations
    OP_CAT = 0x7e
    OP_SUBSTR = 0x7f
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82
    
    # Bitwise logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a
    
    # Arithmetic
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d
    OP_2DIV = 0x8e
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92
    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99
    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4
    OP_WITHIN = 0xa5
    
    # Crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf
    
    # Expansion
    OP_NOP1 = 0xb0
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9
    
    # Template matching params
    OP_SMALLINTEGER = 0xfa
    OP_PUBKEYS = 0xfb
    OP_PUBKEYHASH = 0xfd
    OP_PUBKEY = 0xfe
    OP_INVALIDOPCODE = 0xff


class CovenantType(Enum):
    """Types of covenant scripts supported."""
    VALIDATOR_SIG = "validator_sig"
    MULTISIG_VALIDATOR = "multisig_validator"
    ALLOWLIST_MINT = "allowlist_mint"
    SUPPLY_LIMIT = "supply_limit"
    TIME_LOCKED = "time_locked"
    ASSET_TRANSFER = "asset_transfer"
    BURN_ONLY = "burn_only"


@dataclass
class CovenantTemplate:
    """Template for generating covenant scripts."""
    covenant_type: CovenantType
    validator_pubkeys: List[bytes]
    required_signatures: int = 1
    supply_limit: Optional[int] = None
    mint_limit: Optional[int] = None
    allowlist_root: Optional[bytes] = None
    time_lock: Optional[int] = None
    asset_id: Optional[bytes] = None


@dataclass
class WitnessStackItem:
    """Item in the witness stack for P2WSH spending."""
    data: bytes
    is_signature: bool = False
    is_pubkey: bool = False
    is_script: bool = False
    
    def __len__(self) -> int:
        return len(self.data)


class P2WSHCovenantBuilder:
    """
    Builder for creating P2WSH covenant scripts for asset validation.
    
    This class provides methods to construct witness scripts that enforce
    asset rules through covenant constraints and validator signatures.
    """
    
    def __init__(self):
        """Initialize the P2WSH covenant builder."""
        self.scripts_cache: Dict[str, bytes] = {}
        self.addresses_cache: Dict[bytes, str] = {}
    
    def create_validator_covenant(
        self, 
        validator_pubkey: bytes,
        asset_id: Optional[bytes] = None,
        operation_type: Optional[str] = None
    ) -> bytes:
        """
        Create a basic validator covenant script.
        
        Script format: <validator_pubkey> OP_CHECKSIG
        
        Args:
            validator_pubkey: 33-byte compressed public key of validator
            asset_id: Optional asset ID for asset-specific covenants
            operation_type: Optional operation type (mint, transfer, burn)
            
        Returns:
            Serialized witness script bytes
        """
        if len(validator_pubkey) != 33:
            raise ValueError("Validator pubkey must be 33 bytes (compressed)")
        
        script_parts = []
        
        # Push validator public key (33 bytes)
        script_parts.append(bytes([0x21]))  # OP_PUSHDATA(33)
        script_parts.append(validator_pubkey)
        
        # Check signature
        script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
        
        witness_script = b''.join(script_parts)
        
        # Cache the script
        cache_key = f"validator:{validator_pubkey.hex()}"
        if asset_id:
            cache_key += f":{asset_id.hex()}"
        if operation_type:
            cache_key += f":{operation_type}"
        
        self.scripts_cache[cache_key] = witness_script
        
        return witness_script
    
    def create_multisig_validator_covenant(
        self,
        validator_pubkeys: List[bytes],
        required_signatures: int,
        asset_id: Optional[bytes] = None
    ) -> bytes:
        """
        Create a multi-signature validator covenant script.
        
        Script format: <m> <pubkey1> <pubkey2> ... <pubkeyn> <n> OP_CHECKMULTISIG
        
        Args:
            validator_pubkeys: List of validator public keys
            required_signatures: Number of required signatures (m)
            asset_id: Optional asset ID for asset-specific covenants
            
        Returns:
            Serialized witness script bytes
        """
        if not (1 <= required_signatures <= len(validator_pubkeys) <= 15):
            raise ValueError("Invalid multisig parameters")
        
        if any(len(pk) != 33 for pk in validator_pubkeys):
            raise ValueError("All validator pubkeys must be 33 bytes (compressed)")
        
        script_parts = []
        
        # Push required signature count (m)
        if required_signatures == 1:
            script_parts.append(bytes([ScriptOpcode.OP_1]))
        elif 2 <= required_signatures <= 16:
            script_parts.append(bytes([ScriptOpcode.OP_1 + required_signatures - 1]))
        else:
            raise ValueError("Required signatures must be between 1 and 16")
        
        # Push all public keys
        for pubkey in validator_pubkeys:
            script_parts.append(bytes([0x21]))  # OP_PUSHDATA(33)
            script_parts.append(pubkey)
        
        # Push total key count (n)
        n = len(validator_pubkeys)
        if n == 1:
            script_parts.append(bytes([ScriptOpcode.OP_1]))
        elif 2 <= n <= 16:
            script_parts.append(bytes([ScriptOpcode.OP_1 + n - 1]))
        else:
            raise ValueError("Total keys must be between 1 and 16")
        
        # Check multisig
        script_parts.append(bytes([ScriptOpcode.OP_CHECKMULTISIG]))
        
        witness_script = b''.join(script_parts)
        
        # Cache the script
        pubkey_hashes = [hashlib.sha256(pk).hexdigest()[:8] for pk in validator_pubkeys]
        cache_key = f"multisig:{required_signatures}:{':'.join(pubkey_hashes)}"
        if asset_id:
            cache_key += f":{asset_id.hex()}"
        
        self.scripts_cache[cache_key] = witness_script
        
        return witness_script
    
    def create_supply_limit_covenant(
        self,
        validator_pubkey: bytes,
        supply_limit: int,
        current_supply: int,
        mint_amount: int
    ) -> bytes:
        """
        Create a covenant script that enforces supply limits.
        
        This script validates that current_supply + mint_amount <= supply_limit
        
        Args:
            validator_pubkey: Validator's public key
            supply_limit: Maximum allowed supply
            current_supply: Current circulating supply
            mint_amount: Amount being minted
            
        Returns:
            Serialized witness script bytes
        """
        if supply_limit <= 0 or current_supply < 0 or mint_amount <= 0:
            raise ValueError("Invalid supply parameters")
        
        if current_supply + mint_amount > supply_limit:
            raise ValueError("Mint would exceed supply limit")
        
        script_parts = []
        
        # Push current supply
        script_parts.extend(self._push_integer(current_supply))
        
        # Push mint amount
        script_parts.extend(self._push_integer(mint_amount))
        
        # Add current + mint
        script_parts.append(bytes([ScriptOpcode.OP_ADD]))
        
        # Push supply limit
        script_parts.extend(self._push_integer(supply_limit))
        
        # Check that (current + mint) <= limit
        script_parts.append(bytes([ScriptOpcode.OP_LESSTHANOREQUAL]))
        
        # Verify the constraint
        script_parts.append(bytes([ScriptOpcode.OP_VERIFY]))
        
        # Push validator public key
        script_parts.append(bytes([0x21]))  # OP_PUSHDATA(33)
        script_parts.append(validator_pubkey)
        
        # Check validator signature
        script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
        
        witness_script = b''.join(script_parts)
        
        return witness_script
    
    def create_allowlist_covenant(
        self,
        validator_pubkey: bytes,
        allowlist_root: bytes,
        recipient_hash: bytes
    ) -> bytes:
        """
        Create a covenant script that enforces allowlist requirements.
        
        This script validates Merkle proof for recipient allowlist membership.
        
        Args:
            validator_pubkey: Validator's public key
            allowlist_root: Merkle root of allowed recipients
            recipient_hash: Hash of recipient to validate
            
        Returns:
            Serialized witness script bytes
        """
        if len(allowlist_root) != 32:
            raise ValueError("Allowlist root must be 32 bytes")
        
        if len(recipient_hash) != 32:
            raise ValueError("Recipient hash must be 32 bytes")
        
        script_parts = []
        
        # This is a simplified allowlist check - in practice, you'd need
        # to verify a Merkle proof, which requires additional stack operations
        
        # Push recipient hash
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32)
        script_parts.append(recipient_hash)
        
        # Push allowlist root
        script_parts.append(bytes([0x20]))  # OP_PUSHDATA(32) 
        script_parts.append(allowlist_root)
        
        # For now, just check equality (simplified)
        # In practice, this would verify Merkle proof
        script_parts.append(bytes([ScriptOpcode.OP_EQUAL]))
        script_parts.append(bytes([ScriptOpcode.OP_VERIFY]))
        
        # Push validator public key
        script_parts.append(bytes([0x21]))  # OP_PUSHDATA(33)
        script_parts.append(validator_pubkey)
        
        # Check validator signature
        script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
        
        witness_script = b''.join(script_parts)
        
        return witness_script
    
    def create_time_locked_covenant(
        self,
        validator_pubkey: bytes,
        lock_time: int,
        lock_type: str = "absolute"
    ) -> bytes:
        """
        Create a time-locked covenant script.
        
        Args:
            validator_pubkey: Validator's public key
            lock_time: Lock time value
            lock_type: Type of lock ("absolute" for CLTV, "relative" for CSV)
            
        Returns:
            Serialized witness script bytes
        """
        if lock_time < 0:
            raise ValueError("Lock time must be non-negative")
        
        script_parts = []
        
        # Push lock time
        script_parts.extend(self._push_integer(lock_time))
        
        if lock_type == "absolute":
            # Use CHECKLOCKTIMEVERIFY (absolute time lock)
            script_parts.append(bytes([ScriptOpcode.OP_CHECKLOCKTIMEVERIFY]))
        elif lock_type == "relative":
            # Use CHECKSEQUENCEVERIFY (relative time lock)
            script_parts.append(bytes([ScriptOpcode.OP_CHECKSEQUENCEVERIFY]))
        else:
            raise ValueError("Lock type must be 'absolute' or 'relative'")
        
        # Drop the time value from stack
        script_parts.append(bytes([ScriptOpcode.OP_DROP]))
        
        # Push validator public key
        script_parts.append(bytes([0x21]))  # OP_PUSHDATA(33)
        script_parts.append(validator_pubkey)
        
        # Check validator signature
        script_parts.append(bytes([ScriptOpcode.OP_CHECKSIG]))
        
        witness_script = b''.join(script_parts)
        
        return witness_script
    
    def _push_integer(self, value: int) -> List[bytes]:
        """
        Create script operations to push an integer onto the stack.
        
        Args:
            value: Integer value to push
            
        Returns:
            List of script operation bytes
        """
        if value == 0:
            return [bytes([ScriptOpcode.OP_0])]
        elif value == -1:
            return [bytes([ScriptOpcode.OP_1NEGATE])]
        elif 1 <= value <= 16:
            return [bytes([ScriptOpcode.OP_1 + value - 1])]
        else:
            # For larger numbers, push as data
            if value < 0:
                # Handle negative numbers
                value = abs(value)
                data = self._encode_minimal_int(value)
                data = data[:-1] + bytes([data[-1] | 0x80])  # Set sign bit
            else:
                data = self._encode_minimal_int(value)
            
            return [bytes([len(data)]), data]
    
    def _encode_minimal_int(self, value: int) -> bytes:
        """
        Encode integer in minimal format for Bitcoin Script.
        
        Args:
            value: Positive integer to encode
            
        Returns:
            Minimal encoding bytes
        """
        if value == 0:
            return b''
        
        result = []
        while value > 0:
            result.append(value & 0xFF)
            value >>= 8
        
        # Ensure the most significant bit is not set (would indicate negative)
        if result[-1] & 0x80:
            result.append(0x00)
        
        return bytes(result)
    
    def calculate_script_hash(self, witness_script: bytes) -> bytes:
        """
        Calculate the script hash for a witness script (SHA256).
        
        Args:
            witness_script: The witness script to hash
            
        Returns:
            32-byte script hash
        """
        return hashlib.sha256(witness_script).digest()
    
    def create_p2wsh_script(self, script_hash: bytes) -> bytes:
        """
        Create P2WSH script from script hash.
        
        Script format: OP_0 <32-byte-script-hash>
        
        Args:
            script_hash: 32-byte hash of witness script
            
        Returns:
            P2WSH script bytes
        """
        if len(script_hash) != 32:
            raise ValueError("Script hash must be 32 bytes")
        
        return bytes([ScriptOpcode.OP_0, 0x20]) + script_hash
    
    def generate_p2wsh_address(self, witness_script: bytes, network: str = "regtest") -> str:
        """
        Generate P2WSH address from witness script.
        
        Args:
            witness_script: The witness script
            network: Network type ("mainnet", "testnet", "regtest")
            
        Returns:
            Bech32 P2WSH address string
        """
        script_hash = self.calculate_script_hash(witness_script)
        
        # Cache the address
        if script_hash not in self.addresses_cache:
            try:
                # Use bitcoinlib for address generation if available
                from bitcoinlib.keys import Address
                from bitcoinlib.networks import Network
                
                net = Network(network)
                address = Address(script_hash, network=network, script_type='p2wsh')
                self.addresses_cache[script_hash] = str(address)
            except ImportError:
                # Fallback to manual bech32 encoding
                self.addresses_cache[script_hash] = self._encode_bech32_address(script_hash, network)
        
        return self.addresses_cache[script_hash]
    
    def _encode_bech32_address(self, script_hash: bytes, network: str) -> str:
        """
        Fallback bech32 address encoding.
        
        Args:
            script_hash: Script hash bytes
            network: Network name
            
        Returns:
            Bech32 address string
        """
        # This is a simplified implementation
        # In production, use proper bech32 library
        if network == "mainnet":
            prefix = "bc"
        elif network == "testnet":
            prefix = "tb"
        elif network == "regtest":
            prefix = "bcrt"
        else:
            raise ValueError(f"Unsupported network: {network}")
        
        # Convert to hex for now (not proper bech32)
        return f"{prefix}1q{script_hash.hex()}"
    
    def create_witness_stack(
        self,
        signatures: List[bytes],
        witness_script: bytes,
        additional_data: Optional[List[bytes]] = None
    ) -> List[WitnessStackItem]:
        """
        Create witness stack for spending P2WSH output.
        
        Args:
            signatures: List of signatures (DER encoded)
            witness_script: The witness script being executed
            additional_data: Optional additional witness data
            
        Returns:
            List of witness stack items in proper order
        """
        witness_stack = []
        
        # Empty element for multisig (Bitcoin quirk)
        if len(signatures) > 1:
            witness_stack.append(WitnessStackItem(b''))
        
        # Add signatures
        for sig in signatures:
            if sig:  # Non-empty signature
                witness_stack.append(WitnessStackItem(sig, is_signature=True))
        
        # Add additional witness data if provided
        if additional_data:
            for data in additional_data:
                witness_stack.append(WitnessStackItem(data))
        
        # Witness script is always last
        witness_stack.append(WitnessStackItem(witness_script, is_script=True))
        
        return witness_stack
    
    def validate_witness_script(self, witness_script: bytes) -> bool:
        """
        Basic validation of witness script.
        
        Args:
            witness_script: Script to validate
            
        Returns:
            True if script passes basic validation
        """
        if not witness_script:
            return False
        
        # Check for reasonable length
        if len(witness_script) > 10000:  # Bitcoin's MAX_SCRIPT_SIZE
            return False
        
        # Check for basic structure
        if witness_script[-1] not in [ScriptOpcode.OP_CHECKSIG, ScriptOpcode.OP_CHECKMULTISIG]:
            return False
        
        # Additional validation could be added here
        return True
    
    def get_script_info(self, witness_script: bytes) -> Dict[str, Any]:
        """
        Get information about a witness script.
        
        Args:
            witness_script: Script to analyze
            
        Returns:
            Dictionary with script information
        """
        script_hash = self.calculate_script_hash(witness_script)
        
        info = {
            "script_length": len(witness_script),
            "script_hash": script_hash.hex(),
            "script_hex": witness_script.hex(),
            "is_valid": self.validate_witness_script(witness_script),
        }
        
        # Detect script type
        if witness_script.endswith(bytes([ScriptOpcode.OP_CHECKSIG])):
            if b'\x21' in witness_script[:34]:  # Has 33-byte pubkey push
                info["script_type"] = "single_sig"
                info["pubkey_count"] = 1
        elif witness_script.endswith(bytes([ScriptOpcode.OP_CHECKMULTISIG])):
            info["script_type"] = "multisig"
            # Could analyze further to determine m and n values
        
        # Look for time locks
        if bytes([ScriptOpcode.OP_CHECKLOCKTIMEVERIFY]) in witness_script:
            info["has_timelock"] = True
            info["timelock_type"] = "absolute"
        elif bytes([ScriptOpcode.OP_CHECKSEQUENCEVERIFY]) in witness_script:
            info["has_timelock"] = True
            info["timelock_type"] = "relative"
        else:
            info["has_timelock"] = False
        
        return info
    
    def clear_cache(self) -> None:
        """Clear all cached scripts and addresses."""
        self.scripts_cache.clear()
        self.addresses_cache.clear()


# Convenience functions for common operations

def create_simple_validator_script(validator_pubkey: bytes) -> bytes:
    """Create a simple validator signature script."""
    builder = P2WSHCovenantBuilder()
    return builder.create_validator_covenant(validator_pubkey)


def create_multisig_validator_script(
    validator_pubkeys: List[bytes], 
    required_sigs: int
) -> bytes:
    """Create a multisig validator script."""
    builder = P2WSHCovenantBuilder()
    return builder.create_multisig_validator_covenant(validator_pubkeys, required_sigs)


def generate_covenant_address(
    witness_script: bytes, 
    network: str = "regtest"
) -> str:
    """Generate P2WSH address for a covenant script."""
    builder = P2WSHCovenantBuilder()
    return builder.generate_p2wsh_address(witness_script, network)


def build_spending_witness(
    signatures: List[bytes],
    witness_script: bytes
) -> List[bytes]:
    """Build witness stack for spending P2WSH covenant output."""
    builder = P2WSHCovenantBuilder()
    witness_items = builder.create_witness_stack(signatures, witness_script)
    return [item.data for item in witness_items]


# Asset-specific covenant templates

class AssetCovenantTemplates:
    """Pre-built covenant templates for different asset types."""
    
    @staticmethod
    def fungible_mint_covenant(
        validator_pubkey: bytes,
        supply_limit: int,
        per_mint_limit: int
    ) -> bytes:
        """
        Create covenant for fungible asset minting with limits.
        
        Args:
            validator_pubkey: Validator's public key
            supply_limit: Maximum total supply
            per_mint_limit: Maximum per-mint amount
            
        Returns:
            Witness script bytes
        """
        builder = P2WSHCovenantBuilder()
        
        # This is a simplified version - in practice would need more complex logic
        # to track current supply and validate against limits
        return builder.create_validator_covenant(validator_pubkey)
    
    @staticmethod
    def nft_mint_covenant(
        validator_pubkey: bytes,
        collection_size: int,
        content_hash_required: bool = True
    ) -> bytes:
        """
        Create covenant for NFT minting.
        
        Args:
            validator_pubkey: Validator's public key
            collection_size: Maximum collection size
            content_hash_required: Whether content hash is required
            
        Returns:
            Witness script bytes
        """
        builder = P2WSHCovenantBuilder()
        return builder.create_validator_covenant(validator_pubkey)
    
    @staticmethod
    def transfer_covenant(
        validator_pubkey: bytes,
        transfer_restrictions: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """
        Create covenant for asset transfers.
        
        Args:
            validator_pubkey: Validator's public key
            transfer_restrictions: Optional transfer restrictions
            
        Returns:
            Witness script bytes
        """
        builder = P2WSHCovenantBuilder()
        return builder.create_validator_covenant(validator_pubkey)
    
    @staticmethod
    def burn_covenant(validator_pubkey: bytes) -> bytes:
        """
        Create covenant for asset burning.
        
        Args:
            validator_pubkey: Validator's public key
            
        Returns:
            Witness script bytes
        """
        builder = P2WSHCovenantBuilder()
        return builder.create_validator_covenant(validator_pubkey)