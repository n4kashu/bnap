"""
Tests for P2WSH Output Construction Module
"""

import pytest
import hashlib
from psbt.outputs.p2wsh import (
    WitnessScriptBuilder,
    CovenantScriptBuilder,
    P2WSHBuilder,
    ScriptType,
    ScriptTemplate,
    create_p2wsh_output,
    create_validator_script,
    create_multisig_script,
    create_asset_commitment_script,
    validate_witness_script,
    calculate_script_hash
)
from psbt.exceptions import InvalidScriptError, UnsupportedScriptTypeError


class TestWitnessScriptBuilder:
    """Test WitnessScriptBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = WitnessScriptBuilder()
        self.test_pubkey = b'\x02' + b'\x01' * 32  # Valid compressed pubkey
        self.test_pubkey2 = b'\x03' + b'\x02' * 32  # Another valid compressed pubkey
        self.test_pubkey3 = b'\x02' + b'\x03' * 32  # Third valid compressed pubkey
    
    def test_initialization(self):
        """Test builder initialization."""
        assert len(self.builder.script_stack) == 0
    
    def test_reset(self):
        """Test builder reset functionality."""
        self.builder.push_data(b'test')
        assert len(self.builder.script_stack) > 0
        
        self.builder.reset()
        assert len(self.builder.script_stack) == 0
    
    def test_push_data_empty(self):
        """Test pushing empty data."""
        self.builder.push_data(b'')
        script = self.builder.build()
        assert script == bytes([self.builder.OP_0])
    
    def test_push_data_small_numbers(self):
        """Test pushing small numbers (1-16)."""
        self.builder.reset()
        self.builder.push_data(bytes([1]))
        script = self.builder.build()
        assert script == bytes([self.builder.OP_1])
        
        self.builder.reset()
        self.builder.push_data(bytes([16]))
        script = self.builder.build()
        assert script == bytes([self.builder.OP_1 + 15])
    
    def test_push_data_direct(self):
        """Test direct data push (1-75 bytes)."""
        test_data = b'hello'
        self.builder.push_data(test_data)
        script = self.builder.build()
        
        expected = bytes([len(test_data)]) + test_data
        assert script == expected
    
    def test_push_data_pushdata1(self):
        """Test OP_PUSHDATA1 for data 76-255 bytes."""
        test_data = b'x' * 100
        self.builder.push_data(test_data)
        script = self.builder.build()
        
        expected = bytes([self.builder.OP_PUSHDATA1, len(test_data)]) + test_data
        assert script == expected
    
    def test_push_data_pushdata2(self):
        """Test OP_PUSHDATA2 for data 256-65535 bytes."""
        test_data = b'x' * 300
        self.builder.push_data(test_data)
        script = self.builder.build()
        
        expected = bytes([self.builder.OP_PUSHDATA2]) + len(test_data).to_bytes(2, 'little') + test_data
        assert script == expected
    
    def test_push_opcode(self):
        """Test pushing opcodes."""
        self.builder.push_opcode(self.builder.OP_CHECKSIG)
        script = self.builder.build()
        assert script == bytes([self.builder.OP_CHECKSIG])
    
    def test_push_number_zero(self):
        """Test pushing number zero."""
        self.builder.push_number(0)
        script = self.builder.build()
        assert script == bytes([self.builder.OP_0])
    
    def test_push_number_small(self):
        """Test pushing small numbers (1-16)."""
        self.builder.push_number(5)
        script = self.builder.build()
        assert script == bytes([self.builder.OP_1 + 4])
    
    def test_push_number_large(self):
        """Test pushing large numbers."""
        self.builder.push_number(21)
        script = self.builder.build()
        
        # Should encode as minimal bytes
        assert len(script) > 1  # Should be encoded as data
        assert script[0] == 1  # Length byte
        assert script[1] == 21  # Number byte
    
    def test_create_validator_script(self):
        """Test creating simple validator script."""
        script = self.builder.create_validator_script(self.test_pubkey)
        
        # Should be: <pubkey> OP_CHECKSIG
        expected_length = 1 + len(self.test_pubkey) + 1  # push_length + pubkey + OP_CHECKSIG
        assert len(script) == expected_length
        assert script[-1] == self.builder.OP_CHECKSIG
        assert self.test_pubkey in script
    
    def test_create_validator_script_invalid_pubkey(self):
        """Test validator script with invalid public key."""
        invalid_pubkey = b'\x02' + b'\x01' * 31  # 32 bytes instead of 33
        
        with pytest.raises(InvalidScriptError, match="Invalid public key length"):
            self.builder.create_validator_script(invalid_pubkey)
    
    def test_create_multisig_script(self):
        """Test creating multisig script."""
        public_keys = [self.test_pubkey, self.test_pubkey2]
        script = self.builder.create_multisig_script(2, public_keys)
        
        # Should contain both public keys and proper opcodes
        assert self.test_pubkey in script
        assert self.test_pubkey2 in script
        assert script[-1] == self.builder.OP_CHECKMULTISIG
        
        # Should start with OP_2 for required sigs
        assert script[0] == self.builder.OP_2
    
    def test_create_multisig_script_invalid_sigs(self):
        """Test multisig script with invalid signature requirements."""
        public_keys = [self.test_pubkey, self.test_pubkey2]
        
        # Too many required sigs
        with pytest.raises(InvalidScriptError, match="Invalid required signatures count"):
            self.builder.create_multisig_script(3, public_keys)
        
        # Zero required sigs
        with pytest.raises(InvalidScriptError, match="Invalid required signatures count"):
            self.builder.create_multisig_script(0, public_keys)
    
    def test_create_multisig_script_too_many_keys(self):
        """Test multisig script with too many public keys."""
        public_keys = [self.test_pubkey] * 16  # More than 15 keys
        
        with pytest.raises(InvalidScriptError, match="Too many public keys"):
            self.builder.create_multisig_script(1, public_keys)
    
    def test_create_multisig_script_invalid_pubkey(self):
        """Test multisig script with invalid public key."""
        invalid_pubkey = b'\x02' + b'\x01' * 31  # Wrong length
        public_keys = [self.test_pubkey, invalid_pubkey]
        
        with pytest.raises(InvalidScriptError, match="Invalid public key length"):
            self.builder.create_multisig_script(2, public_keys)
    
    def test_create_timelock_script(self):
        """Test creating timelock script."""
        locktime = 500000  # Block height
        script = self.builder.create_timelock_script(self.test_pubkey, locktime)
        
        # Should contain pubkey and OP_CHECKSIG
        assert self.test_pubkey in script
        assert bytes([self.builder.OP_CHECKSIG]) in script
        assert bytes([self.builder.OP_CHECKLOCKTIMEVERIFY]) in script
        assert bytes([self.builder.OP_DROP]) in script
    
    def test_create_timelock_script_sequence(self):
        """Test creating sequence-based timelock script."""
        sequence = 144  # ~1 day in blocks
        script = self.builder.create_timelock_script(
            self.test_pubkey, sequence, use_sequence=True
        )
        
        assert bytes([self.builder.OP_CHECKSEQUENCEVERIFY]) in script
        assert bytes([self.builder.OP_CHECKLOCKTIMEVERIFY]) not in script
    
    def test_create_hash_timelock_script(self):
        """Test creating HTLC script."""
        hash_lock = hashlib.sha256(b'secret').digest()
        timeout = 500000
        
        script = self.builder.create_hash_timelock_script(
            hash_lock, self.test_pubkey, timeout
        )
        
        # Should contain hash, pubkey, and control flow opcodes
        assert hash_lock in script
        assert self.test_pubkey in script
        assert bytes([0xa8]) in script  # OP_SHA256
        assert bytes([0x63]) in script  # OP_IF
        assert bytes([0x67]) in script  # OP_ELSE
        assert bytes([0x68]) in script  # OP_ENDIF
    
    def test_create_hash_timelock_script_invalid_hash(self):
        """Test HTLC script with invalid hash length."""
        invalid_hash = b'short_hash'
        
        with pytest.raises(InvalidScriptError, match="Invalid hash length"):
            self.builder.create_hash_timelock_script(
                invalid_hash, self.test_pubkey, 500000
            )


class TestCovenantScriptBuilder:
    """Test CovenantScriptBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = CovenantScriptBuilder()
        self.test_pubkey = b'\x02' + b'\x01' * 32
        self.test_pubkey2 = b'\x03' + b'\x02' * 32
        self.asset_id = "1234567890abcdef" * 4  # 64-char hex string
    
    def test_create_asset_commitment_script(self):
        """Test creating asset commitment covenant script."""
        script = self.builder.create_asset_commitment_script(
            self.asset_id, self.test_pubkey
        )
        
        # Should contain pubkey and asset ID
        assert self.test_pubkey in script
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
        
        # Should have OP_CHECKSIG and OP_EQUAL
        assert bytes([self.builder.script_builder.OP_CHECKSIG]) in script
        assert bytes([self.builder.script_builder.OP_EQUAL]) in script
        assert bytes([self.builder.script_builder.OP_BOOLAND]) in script
    
    def test_create_asset_commitment_script_with_supply_limit(self):
        """Test asset commitment script with supply limit."""
        max_supply = 21000000
        script = self.builder.create_asset_commitment_script(
            self.asset_id, self.test_pubkey, max_supply
        )
        
        # Should contain supply limit validation
        assert bytes([0xa4]) in script  # OP_LESSTHANOREQUAL
        
        # Should have multiple OP_BOOLAND operations
        booland_count = script.count(bytes([self.builder.script_builder.OP_BOOLAND]))
        assert booland_count >= 2
    
    def test_create_asset_commitment_script_invalid_asset_id(self):
        """Test asset commitment script with invalid asset ID."""
        invalid_asset_id = "invalid_hex"
        
        with pytest.raises(InvalidScriptError, match="Invalid asset ID format"):
            self.builder.create_asset_commitment_script(
                invalid_asset_id, self.test_pubkey
            )
    
    def test_create_asset_commitment_script_wrong_length_asset_id(self):
        """Test asset commitment script with wrong length asset ID."""
        short_asset_id = "1234567890abcdef"  # Too short
        
        with pytest.raises(InvalidScriptError, match="Invalid asset ID length"):
            self.builder.create_asset_commitment_script(
                short_asset_id, self.test_pubkey
            )
    
    def test_create_asset_commitment_script_invalid_pubkey(self):
        """Test asset commitment script with invalid public key."""
        invalid_pubkey = b'\x02' + b'\x01' * 31  # Wrong length
        
        with pytest.raises(InvalidScriptError, match="Invalid public key length"):
            self.builder.create_asset_commitment_script(
                self.asset_id, invalid_pubkey
            )
    
    def test_create_multisig_covenant_script(self):
        """Test creating multisig covenant script."""
        public_keys = [self.test_pubkey, self.test_pubkey2]
        script = self.builder.create_multisig_covenant_script(
            2, public_keys, self.asset_id
        )
        
        # Should contain both public keys
        assert self.test_pubkey in script
        assert self.test_pubkey2 in script
        
        # Should contain asset ID
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
        
        # Should have multisig and asset validation opcodes
        assert bytes([self.builder.script_builder.OP_CHECKMULTISIG]) in script
        assert bytes([self.builder.script_builder.OP_EQUAL]) in script
        assert bytes([self.builder.script_builder.OP_BOOLAND]) in script
    
    def test_create_multisig_covenant_script_invalid_sigs(self):
        """Test multisig covenant with invalid signature requirements."""
        public_keys = [self.test_pubkey, self.test_pubkey2]
        
        with pytest.raises(InvalidScriptError, match="Invalid required signatures count"):
            self.builder.create_multisig_covenant_script(
                3, public_keys, self.asset_id
            )


class TestP2WSHBuilder:
    """Test P2WSHBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = P2WSHBuilder()
        self.test_pubkey = b'\x02' + b'\x01' * 32
        self.test_pubkey2 = b'\x03' + b'\x02' * 32
        self.asset_id = "1234567890abcdef" * 4
    
    def test_create_p2wsh_output(self):
        """Test creating P2WSH output."""
        witness_script = create_validator_script(self.test_pubkey)
        p2wsh_script, script_hash = self.builder.create_p2wsh_output(witness_script)
        
        # P2WSH script should be OP_0 + 32-byte hash
        assert len(p2wsh_script) == 34
        assert p2wsh_script[0] == 0x00  # OP_0
        assert p2wsh_script[1] == 0x20  # Push 32 bytes
        
        # Script hash should be 32 bytes
        assert len(script_hash) == 32
        
        # Hash should match calculated hash
        expected_hash = hashlib.sha256(witness_script).digest()
        assert script_hash == expected_hash
    
    def test_create_p2wsh_output_empty_script(self):
        """Test creating P2WSH output with empty script."""
        with pytest.raises(InvalidScriptError, match="Witness script cannot be empty"):
            self.builder.create_p2wsh_output(b'')
    
    def test_create_validator_output(self):
        """Test creating validator P2WSH output."""
        p2wsh_script, witness_script, script_hash = self.builder.create_validator_output(
            self.test_pubkey
        )
        
        # Should return all three components
        assert len(p2wsh_script) == 34
        assert len(witness_script) > 0
        assert len(script_hash) == 32
        
        # Witness script should contain pubkey and OP_CHECKSIG
        assert self.test_pubkey in witness_script
        assert witness_script[-1] == 0xac  # OP_CHECKSIG
    
    def test_create_multisig_output(self):
        """Test creating multisig P2WSH output."""
        public_keys = [self.test_pubkey, self.test_pubkey2]
        p2wsh_script, witness_script, script_hash = self.builder.create_multisig_output(
            2, public_keys
        )
        
        # Should contain both public keys
        assert self.test_pubkey in witness_script
        assert self.test_pubkey2 in witness_script
        
        # Should end with OP_CHECKMULTISIG
        assert witness_script[-1] == 0xae  # OP_CHECKMULTISIG
    
    def test_create_covenant_output(self):
        """Test creating covenant P2WSH output."""
        p2wsh_script, witness_script, script_hash = self.builder.create_covenant_output(
            self.asset_id, self.test_pubkey
        )
        
        # Should contain pubkey and asset ID
        assert self.test_pubkey in witness_script
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in witness_script
    
    def test_create_covenant_output_with_supply_limit(self):
        """Test creating covenant output with supply limit."""
        max_supply = 1000000
        p2wsh_script, witness_script, script_hash = self.builder.create_covenant_output(
            self.asset_id, self.test_pubkey, max_supply=max_supply
        )
        
        # Should contain supply limit validation
        assert bytes([0xa4]) in witness_script  # OP_LESSTHANOREQUAL
    
    def test_create_htlc_output(self):
        """Test creating HTLC P2WSH output."""
        hash_lock = hashlib.sha256(b'secret').digest()
        timeout = 500000
        
        p2wsh_script, witness_script, script_hash = self.builder.create_htlc_output(
            hash_lock, self.test_pubkey, timeout
        )
        
        # Should contain hash lock and pubkey
        assert hash_lock in witness_script
        assert self.test_pubkey in witness_script
        
        # Should have conditional opcodes
        assert bytes([0x63]) in witness_script  # OP_IF
        assert bytes([0x67]) in witness_script  # OP_ELSE
        assert bytes([0x68]) in witness_script  # OP_ENDIF


class TestUtilityFunctions:
    """Test utility functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.test_pubkey = b'\x02' + b'\x01' * 32
        self.test_pubkey2 = b'\x03' + b'\x02' * 32
        self.asset_id = "1234567890abcdef" * 4
    
    def test_create_p2wsh_output_function(self):
        """Test standalone create_p2wsh_output function."""
        witness_script = create_validator_script(self.test_pubkey)
        p2wsh_script, script_hash = create_p2wsh_output(witness_script)
        
        assert len(p2wsh_script) == 34
        assert len(script_hash) == 32
    
    def test_create_validator_script_function(self):
        """Test standalone create_validator_script function."""
        script = create_validator_script(self.test_pubkey)
        
        assert self.test_pubkey in script
        assert script[-1] == 0xac  # OP_CHECKSIG
    
    def test_create_multisig_script_function(self):
        """Test standalone create_multisig_script function."""
        public_keys = [self.test_pubkey, self.test_pubkey2]
        script = create_multisig_script(2, public_keys)
        
        assert self.test_pubkey in script
        assert self.test_pubkey2 in script
        assert script[-1] == 0xae  # OP_CHECKMULTISIG
    
    def test_create_asset_commitment_script_function(self):
        """Test standalone create_asset_commitment_script function."""
        script = create_asset_commitment_script(self.asset_id, self.test_pubkey)
        
        assert self.test_pubkey in script
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
    
    def test_validate_witness_script_valid(self):
        """Test witness script validation with valid scripts."""
        # Valid validator script
        script = create_validator_script(self.test_pubkey)
        assert validate_witness_script(script) == True
        
        # Valid multisig script
        public_keys = [self.test_pubkey, self.test_pubkey2]
        script = create_multisig_script(2, public_keys)
        assert validate_witness_script(script) == True
    
    def test_validate_witness_script_invalid(self):
        """Test witness script validation with invalid scripts."""
        # Empty script
        assert validate_witness_script(b'') == False
        
        # Script too large
        large_script = b'\x01' * 10001
        assert validate_witness_script(large_script) == False
        
        # Script with invalid opcode
        invalid_script = b'\xff\x01\x02'
        assert validate_witness_script(invalid_script) == False
    
    def test_calculate_script_hash(self):
        """Test script hash calculation."""
        script = create_validator_script(self.test_pubkey)
        script_hash = calculate_script_hash(script)
        
        assert len(script_hash) == 32
        
        # Should match hashlib calculation
        expected_hash = hashlib.sha256(script).digest()
        assert script_hash == expected_hash


class TestScriptIntegration:
    """Test integration between different script types."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.test_pubkey = b'\x02' + b'\x01' * 32
        self.asset_id = "1234567890abcdef" * 4
        self.builder = P2WSHBuilder()
    
    def test_validator_to_p2wsh_integration(self):
        """Test complete flow from validator script to P2WSH output."""
        # Create validator script
        witness_script = create_validator_script(self.test_pubkey)
        
        # Create P2WSH output
        p2wsh_script, script_hash = create_p2wsh_output(witness_script)
        
        # Verify hash consistency
        calculated_hash = calculate_script_hash(witness_script)
        assert script_hash == calculated_hash
        
        # Verify P2WSH script format
        assert p2wsh_script == bytes([0x00, 0x20]) + script_hash
    
    def test_covenant_to_p2wsh_integration(self):
        """Test complete flow from covenant script to P2WSH output."""
        # Create covenant script
        witness_script = create_asset_commitment_script(self.asset_id, self.test_pubkey)
        
        # Create P2WSH output using builder
        p2wsh_script, _, script_hash = self.builder.create_covenant_output(
            self.asset_id, self.test_pubkey
        )
        
        # Verify script validation
        assert validate_witness_script(witness_script) == True
        
        # Verify hash calculation
        expected_hash = calculate_script_hash(witness_script)
        assert script_hash == expected_hash
    
    def test_multisig_to_p2wsh_integration(self):
        """Test complete flow from multisig script to P2WSH output."""
        public_keys = [self.test_pubkey, b'\x03' + b'\x02' * 32]
        
        # Create multisig script
        witness_script = create_multisig_script(2, public_keys)
        
        # Create P2WSH output using builder
        p2wsh_script, _, script_hash = self.builder.create_multisig_output(
            2, public_keys
        )
        
        # Verify script components
        for pubkey in public_keys:
            assert pubkey in witness_script
        
        # Verify hash consistency
        calculated_hash = calculate_script_hash(witness_script)
        assert script_hash == calculated_hash