"""
Tests for Taproot Output Construction Module
"""

import pytest
import hashlib
from psbt.outputs.taproot import (
    TaprootScriptBuilder,
    TaprootTreeBuilder,
    TaprootBuilder,
    TapLeaf,
    TapBranch,
    TaprootScriptType,
    create_taproot_output,
    create_asset_transfer_script,
    create_asset_mint_script,
    validate_taproot_script,
    calculate_tap_leaf_hash
)
from psbt.exceptions import InvalidScriptError


class TestTapLeaf:
    """Test TapLeaf dataclass functionality."""
    
    def test_valid_tap_leaf(self):
        """Test creating valid TapLeaf."""
        script = b'\x20' + b'\x01' * 32 + b'\xac'  # Simple script
        leaf = TapLeaf(script, 0xc0)
        
        assert leaf.script == script
        assert leaf.leaf_version == 0xc0
    
    def test_tap_leaf_empty_script(self):
        """Test TapLeaf with empty script."""
        with pytest.raises(InvalidScriptError, match="Tap leaf script cannot be empty"):
            TapLeaf(b'', 0xc0)
    
    def test_tap_leaf_script_too_large(self):
        """Test TapLeaf with script too large."""
        large_script = b'\x01' * 10001
        with pytest.raises(InvalidScriptError, match="Tap leaf script too large"):
            TapLeaf(large_script, 0xc0)
    
    def test_tap_leaf_invalid_version(self):
        """Test TapLeaf with invalid leaf version."""
        script = b'\x20' + b'\x01' * 32 + b'\xac'
        with pytest.raises(InvalidScriptError, match="Invalid leaf version"):
            TapLeaf(script, 0x99)  # Invalid version


class TestTaprootScriptBuilder:
    """Test TaprootScriptBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = TaprootScriptBuilder()
        self.test_pubkey = b'\x01' * 32  # 32-byte x-only pubkey
        self.test_pubkey2 = b'\x02' * 32
        self.asset_id = "deadbeefcafebabe" * 4  # 64-char hex string
    
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
    
    def test_push_data_small(self):
        """Test pushing small data."""
        test_data = b'hello'
        self.builder.push_data(test_data)
        script = self.builder.build()
        
        expected = bytes([len(test_data)]) + test_data
        assert script == expected
    
    def test_push_data_pushdata1(self):
        """Test OP_PUSHDATA1 for medium data."""
        test_data = b'x' * 100
        self.builder.push_data(test_data)
        script = self.builder.build()
        
        expected = bytes([self.builder.OP_PUSHDATA1, len(test_data)]) + test_data
        assert script == expected
    
    def test_push_data_pushdata2(self):
        """Test OP_PUSHDATA2 for larger data."""
        test_data = b'x' * 300
        self.builder.push_data(test_data)
        script = self.builder.build()
        
        assert script.startswith(bytes([self.builder.OP_PUSHDATA2]))
        assert test_data in script
    
    def test_push_data_too_large(self):
        """Test pushing data that's too large."""
        large_data = b'x' * 100000
        with pytest.raises(InvalidScriptError, match="Data too large"):
            self.builder.push_data(large_data)
    
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
        """Test pushing small numbers."""
        self.builder.push_number(5)
        script = self.builder.build()
        assert script == bytes([self.builder.OP_1 + 4])
    
    def test_push_number_large(self):
        """Test pushing large numbers."""
        self.builder.push_number(1000)
        script = self.builder.build()
        assert len(script) > 1  # Should be encoded as data
    
    def test_create_asset_transfer_script(self):
        """Test creating asset transfer script."""
        script = self.builder.create_asset_transfer_script(
            self.asset_id, self.test_pubkey, self.test_pubkey2, 100
        )
        
        # Should contain asset ID, public keys, and validation opcodes
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
        assert self.test_pubkey in script
        assert self.test_pubkey2 in script
        assert bytes([self.builder.OP_EQUAL]) in script
        assert bytes([self.builder.OP_CHECKSIGVERIFY]) in script
        assert bytes([self.builder.OP_BOOLAND]) in script
    
    def test_create_asset_transfer_script_invalid_from_pubkey(self):
        """Test asset transfer script with invalid from pubkey."""
        invalid_pubkey = b'\x01' * 31  # Wrong length
        
        with pytest.raises(InvalidScriptError, match="Invalid from_pubkey length"):
            self.builder.create_asset_transfer_script(
                self.asset_id, invalid_pubkey, self.test_pubkey2, 100
            )
    
    def test_create_asset_transfer_script_invalid_to_pubkey(self):
        """Test asset transfer script with invalid to pubkey."""
        invalid_pubkey = b'\x02' * 33  # Wrong length
        
        with pytest.raises(InvalidScriptError, match="Invalid to_pubkey length"):
            self.builder.create_asset_transfer_script(
                self.asset_id, self.test_pubkey, invalid_pubkey, 100
            )
    
    def test_create_asset_transfer_script_invalid_asset_id(self):
        """Test asset transfer script with invalid asset ID."""
        invalid_asset_id = "not_hex"
        
        with pytest.raises(InvalidScriptError, match="Invalid asset ID format"):
            self.builder.create_asset_transfer_script(
                invalid_asset_id, self.test_pubkey, self.test_pubkey2, 100
            )
    
    def test_create_asset_mint_script(self):
        """Test creating asset mint script."""
        script = self.builder.create_asset_mint_script(
            self.asset_id, self.test_pubkey, 1000
        )
        
        # Should contain asset ID, minter pubkey, and validation opcodes
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
        assert self.test_pubkey in script
        assert bytes([self.builder.OP_EQUAL]) in script
        assert bytes([self.builder.OP_CHECKSIGVERIFY]) in script
        assert bytes([self.builder.OP_BOOLAND]) in script
    
    def test_create_asset_mint_script_with_max_supply(self):
        """Test asset mint script with max supply limit."""
        max_supply = 21000000
        script = self.builder.create_asset_mint_script(
            self.asset_id, self.test_pubkey, 1000, max_supply
        )
        
        # Should contain supply limit validation
        assert bytes([0xa4]) in script  # OP_LESSTHANOREQUAL
        
        # Should have multiple OP_BOOLAND operations
        booland_count = script.count(bytes([self.builder.OP_BOOLAND]))
        assert booland_count >= 2
    
    def test_create_asset_mint_script_invalid_minter(self):
        """Test asset mint script with invalid minter pubkey."""
        invalid_pubkey = b'\x01' * 31  # Wrong length
        
        with pytest.raises(InvalidScriptError, match="Invalid minter_pubkey length"):
            self.builder.create_asset_mint_script(
                self.asset_id, invalid_pubkey, 1000
            )
    
    def test_create_asset_burn_script(self):
        """Test creating asset burn script."""
        script = self.builder.create_asset_burn_script(
            self.asset_id, self.test_pubkey, 500
        )
        
        # Should contain asset ID, burner pubkey, and validation opcodes
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
        assert self.test_pubkey in script
        assert bytes([self.builder.OP_EQUAL]) in script
        assert bytes([self.builder.OP_CHECKSIGVERIFY]) in script
        assert bytes([self.builder.OP_BOOLAND]) in script
    
    def test_create_asset_burn_script_invalid_burner(self):
        """Test asset burn script with invalid burner pubkey."""
        invalid_pubkey = b'\x01' * 33  # Wrong length
        
        with pytest.raises(InvalidScriptError, match="Invalid burner_pubkey length"):
            self.builder.create_asset_burn_script(
                self.asset_id, invalid_pubkey, 500
            )
    
    def test_create_multi_asset_script(self):
        """Test creating multi-asset script."""
        operations = [
            {
                'asset_id': self.asset_id,
                'type': 'transfer',
                'amount': 100
            },
            {
                'asset_id': "1234567890abcdef" * 4,
                'type': 'mint',
                'amount': 500
            }
        ]
        
        script = self.builder.create_multi_asset_script(operations, self.test_pubkey)
        
        # Should contain validator pubkey
        assert self.test_pubkey in script
        assert bytes([self.builder.OP_CHECKSIGVERIFY]) in script
        
        # Should contain both asset IDs
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
        
        asset_id2_bytes = bytes.fromhex("1234567890abcdef" * 4)
        assert asset_id2_bytes in script
        
        # Should have operation type strings
        assert b'transfer' in script
        assert b'mint' in script
    
    def test_create_multi_asset_script_empty_operations(self):
        """Test multi-asset script with no operations."""
        with pytest.raises(InvalidScriptError, match="No asset operations specified"):
            self.builder.create_multi_asset_script([], self.test_pubkey)
    
    def test_create_multi_asset_script_invalid_validator(self):
        """Test multi-asset script with invalid validator pubkey."""
        operations = [{'asset_id': self.asset_id, 'type': 'transfer', 'amount': 100}]
        invalid_pubkey = b'\x01' * 31
        
        with pytest.raises(InvalidScriptError, match="Invalid validator_pubkey length"):
            self.builder.create_multi_asset_script(operations, invalid_pubkey)
    
    def test_create_delegation_script(self):
        """Test creating delegation script."""
        permissions = 0x0f  # Some permission flags
        script = self.builder.create_delegation_script(
            self.test_pubkey, self.test_pubkey2, permissions
        )
        
        # Should contain both public keys
        assert self.test_pubkey in script
        assert self.test_pubkey2 in script
        
        # Should have signature checking opcodes
        assert bytes([self.builder.OP_CHECKSIG]) in script
        assert bytes([0x9b]) in script  # OP_BOOLOR
        assert bytes([self.builder.OP_EQUAL]) in script
        assert bytes([self.builder.OP_BOOLAND]) in script
    
    def test_create_delegation_script_with_expiry(self):
        """Test delegation script with expiry."""
        permissions = 0x0f
        expiry = 500000
        script = self.builder.create_delegation_script(
            self.test_pubkey, self.test_pubkey2, permissions, expiry
        )
        
        # Should contain expiry validation
        assert bytes([self.builder.OP_CHECKLOCKTIMEVERIFY]) in script
        assert bytes([self.builder.OP_DROP]) in script
    
    def test_create_delegation_script_invalid_delegator(self):
        """Test delegation script with invalid delegator pubkey."""
        invalid_pubkey = b'\x01' * 31
        
        with pytest.raises(InvalidScriptError, match="Invalid delegator_pubkey length"):
            self.builder.create_delegation_script(
                invalid_pubkey, self.test_pubkey2, 0x0f
            )
    
    def test_create_delegation_script_invalid_delegate(self):
        """Test delegation script with invalid delegate pubkey."""
        invalid_pubkey = b'\x02' * 33
        
        with pytest.raises(InvalidScriptError, match="Invalid delegate_pubkey length"):
            self.builder.create_delegation_script(
                self.test_pubkey, invalid_pubkey, 0x0f
            )


class TestTaprootTreeBuilder:
    """Test TaprootTreeBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = TaprootTreeBuilder()
        self.script1 = b'\x20' + b'\x01' * 32 + b'\xac'
        self.script2 = b'\x20' + b'\x02' * 32 + b'\xac'
        self.script3 = b'\x20' + b'\x03' * 32 + b'\xac'
    
    def test_add_leaf(self):
        """Test adding script leaves."""
        self.builder.add_leaf(self.script1)
        assert len(self.builder.leaves) == 1
        assert self.builder.leaves[0].script == self.script1
        assert self.builder.leaves[0].leaf_version == 0xc0
    
    def test_add_leaf_custom_version(self):
        """Test adding leaf with custom version."""
        self.builder.add_leaf(self.script1, 0xc1)
        assert self.builder.leaves[0].leaf_version == 0xc1
    
    def test_build_tree_empty(self):
        """Test building tree with no leaves."""
        tree = self.builder.build_tree()
        assert tree is None
    
    def test_build_tree_single_leaf(self):
        """Test building tree with single leaf."""
        self.builder.add_leaf(self.script1)
        tree = self.builder.build_tree()
        
        assert isinstance(tree, TapLeaf)
        assert tree.script == self.script1
    
    def test_build_tree_two_leaves(self):
        """Test building tree with two leaves."""
        self.builder.add_leaf(self.script1)
        self.builder.add_leaf(self.script2)
        tree = self.builder.build_tree()
        
        assert isinstance(tree, TapBranch)
        assert isinstance(tree.left, TapLeaf)
        assert isinstance(tree.right, TapLeaf)
    
    def test_build_tree_three_leaves(self):
        """Test building tree with three leaves."""
        self.builder.add_leaf(self.script1)
        self.builder.add_leaf(self.script2)
        self.builder.add_leaf(self.script3)
        tree = self.builder.build_tree()
        
        assert isinstance(tree, TapBranch)
        # Should have proper tree structure
        assert tree is not None
    
    def test_calculate_merkle_root_none(self):
        """Test Merkle root calculation with None tree."""
        root = self.builder.calculate_merkle_root(None)
        assert root == b'\x00' * 32
    
    def test_calculate_merkle_root_single_leaf(self):
        """Test Merkle root calculation with single leaf."""
        leaf = TapLeaf(self.script1)
        root = self.builder.calculate_merkle_root(leaf)
        
        assert len(root) == 32
        assert root != b'\x00' * 32
    
    def test_calculate_merkle_root_branch(self):
        """Test Merkle root calculation with branch."""
        leaf1 = TapLeaf(self.script1)
        leaf2 = TapLeaf(self.script2)
        branch = TapBranch(leaf1, leaf2)
        
        root = self.builder.calculate_merkle_root(branch)
        
        assert len(root) == 32
        assert root != b'\x00' * 32
    
    def test_leaf_hash_consistency(self):
        """Test leaf hash consistency."""
        leaf = TapLeaf(self.script1)
        hash1 = self.builder._leaf_hash(leaf)
        hash2 = self.builder._leaf_hash(leaf)
        
        assert hash1 == hash2
        assert len(hash1) == 32
    
    def test_branch_hash_ordering(self):
        """Test branch hash lexicographic ordering."""
        left_hash = b'\x01' * 32
        right_hash = b'\x02' * 32
        
        hash1 = self.builder._branch_hash(left_hash, right_hash)
        hash2 = self.builder._branch_hash(right_hash, left_hash)
        
        # Should be the same due to lexicographic ordering
        assert hash1 == hash2


class TestTaprootBuilder:
    """Test TaprootBuilder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = TaprootBuilder()
        self.internal_pubkey = b'\x01' * 32
        self.test_pubkey = b'\x02' * 32
        self.asset_id = "deadbeefcafebabe" * 4
    
    def test_create_p2tr_output(self):
        """Test creating basic P2TR output."""
        p2tr_script, tweaked_pubkey, merkle_root = self.builder.create_p2tr_output(
            self.internal_pubkey
        )
        
        # P2TR script should be OP_1 + 32-byte tweaked pubkey
        assert len(p2tr_script) == 34
        assert p2tr_script[0] == 0x51  # OP_1
        assert p2tr_script[1] == 0x20  # Push 32 bytes
        
        # Tweaked pubkey should be 32 bytes
        assert len(tweaked_pubkey) == 32
        
        # Merkle root should be 32 bytes of zeros (no script tree)
        assert merkle_root == b'\x00' * 32
    
    def test_create_p2tr_output_invalid_pubkey(self):
        """Test P2TR output with invalid internal pubkey."""
        invalid_pubkey = b'\x01' * 31  # Wrong length
        
        with pytest.raises(InvalidScriptError, match="Invalid internal pubkey length"):
            self.builder.create_p2tr_output(invalid_pubkey)
    
    def test_create_p2tr_output_with_script_tree(self):
        """Test P2TR output with script tree."""
        # Create simple script tree
        script = b'\x20' + b'\x01' * 32 + b'\xac'
        leaf = TapLeaf(script)
        
        p2tr_script, tweaked_pubkey, merkle_root = self.builder.create_p2tr_output(
            self.internal_pubkey, leaf
        )
        
        assert len(p2tr_script) == 34
        assert len(tweaked_pubkey) == 32
        assert merkle_root != b'\x00' * 32  # Should have non-zero root
    
    def test_create_asset_transfer_output(self):
        """Test creating asset transfer P2TR output."""
        p2tr_script, tweaked_pubkey, transfer_script = self.builder.create_asset_transfer_output(
            self.internal_pubkey, self.asset_id, self.test_pubkey, b'\x03' * 32, 100
        )
        
        # Should return valid P2TR output
        assert len(p2tr_script) == 34
        assert p2tr_script[0] == 0x51  # OP_1
        
        # Tweaked pubkey should be valid
        assert len(tweaked_pubkey) == 32
        
        # Transfer script should contain expected elements
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in transfer_script
        assert self.test_pubkey in transfer_script
    
    def test_create_asset_mint_output(self):
        """Test creating asset mint P2TR output."""
        p2tr_script, tweaked_pubkey, mint_script = self.builder.create_asset_mint_output(
            self.internal_pubkey, self.asset_id, self.test_pubkey, 1000
        )
        
        # Should return valid P2TR output
        assert len(p2tr_script) == 34
        assert len(tweaked_pubkey) == 32
        
        # Mint script should contain expected elements
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in mint_script
        assert self.test_pubkey in mint_script
    
    def test_create_asset_mint_output_with_max_supply(self):
        """Test asset mint output with max supply."""
        max_supply = 21000000
        p2tr_script, tweaked_pubkey, mint_script = self.builder.create_asset_mint_output(
            self.internal_pubkey, self.asset_id, self.test_pubkey, 1000, max_supply
        )
        
        # Should contain supply limit validation
        assert bytes([0xa4]) in mint_script  # OP_LESSTHANOREQUAL
    
    def test_create_multi_path_output(self):
        """Test creating multi-path P2TR output."""
        scripts = [
            b'\x20' + b'\x01' * 32 + b'\xac',
            b'\x20' + b'\x02' * 32 + b'\xac',
            b'\x20' + b'\x03' * 32 + b'\xac'
        ]
        
        p2tr_script, tweaked_pubkey, returned_scripts = self.builder.create_multi_path_output(
            self.internal_pubkey, scripts
        )
        
        assert len(p2tr_script) == 34
        assert len(tweaked_pubkey) == 32
        assert returned_scripts == scripts
    
    def test_create_multi_path_output_empty_scripts(self):
        """Test multi-path output with no scripts."""
        with pytest.raises(InvalidScriptError, match="No scripts provided"):
            self.builder.create_multi_path_output(self.internal_pubkey, [])
    
    def test_tweak_pubkey_deterministic(self):
        """Test that pubkey tweaking is deterministic."""
        tweak = b'\x05' * 32
        
        result1 = self.builder._tweak_pubkey(self.internal_pubkey, tweak)
        result2 = self.builder._tweak_pubkey(self.internal_pubkey, tweak)
        
        assert result1 == result2
        assert len(result1) == 32


class TestUtilityFunctions:
    """Test utility functions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.internal_pubkey = b'\x01' * 32
        self.test_script = b'\x20' + b'\x01' * 32 + b'\xac'
        self.asset_id = "deadbeefcafebabe" * 4
        self.test_pubkey = b'\x02' * 32
    
    def test_create_taproot_output_function(self):
        """Test standalone create_taproot_output function."""
        p2tr_script, tweaked_pubkey = create_taproot_output(self.internal_pubkey)
        
        assert len(p2tr_script) == 34
        assert len(tweaked_pubkey) == 32
    
    def test_create_taproot_output_with_tree(self):
        """Test create_taproot_output with script tree."""
        leaf = TapLeaf(self.test_script)
        p2tr_script, tweaked_pubkey = create_taproot_output(self.internal_pubkey, leaf)
        
        assert len(p2tr_script) == 34
        assert len(tweaked_pubkey) == 32
    
    def test_create_asset_transfer_script_function(self):
        """Test standalone create_asset_transfer_script function."""
        script = create_asset_transfer_script(
            self.asset_id, self.test_pubkey, b'\x03' * 32, 100
        )
        
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
        assert self.test_pubkey in script
    
    def test_create_asset_mint_script_function(self):
        """Test standalone create_asset_mint_script function."""
        script = create_asset_mint_script(self.asset_id, self.test_pubkey, 1000)
        
        asset_id_bytes = bytes.fromhex(self.asset_id)
        assert asset_id_bytes in script
        assert self.test_pubkey in script
    
    def test_create_asset_mint_script_with_max_supply(self):
        """Test asset mint script with max supply."""
        max_supply = 21000000
        script = create_asset_mint_script(
            self.asset_id, self.test_pubkey, 1000, max_supply
        )
        
        assert bytes([0xa4]) in script  # OP_LESSTHANOREQUAL
    
    def test_validate_taproot_script_valid(self):
        """Test Taproot script validation with valid script."""
        script = create_asset_transfer_script(
            self.asset_id, self.test_pubkey, b'\x03' * 32, 100
        )
        assert validate_taproot_script(script) == True
    
    def test_validate_taproot_script_empty(self):
        """Test Taproot script validation with empty script."""
        assert validate_taproot_script(b'') == False
    
    def test_validate_taproot_script_too_large(self):
        """Test Taproot script validation with script too large."""
        large_script = b'\x01' * 10001
        assert validate_taproot_script(large_script) == False
    
    def test_calculate_tap_leaf_hash(self):
        """Test TapLeaf hash calculation."""
        leaf_hash = calculate_tap_leaf_hash(self.test_script)
        
        assert len(leaf_hash) == 32
        
        # Should be consistent
        leaf_hash2 = calculate_tap_leaf_hash(self.test_script)
        assert leaf_hash == leaf_hash2
    
    def test_calculate_tap_leaf_hash_custom_version(self):
        """Test TapLeaf hash with custom version."""
        leaf_hash1 = calculate_tap_leaf_hash(self.test_script, 0xc0)
        leaf_hash2 = calculate_tap_leaf_hash(self.test_script, 0xc1)
        
        # Different versions should produce different hashes
        assert leaf_hash1 != leaf_hash2


class TestTaprootIntegration:
    """Test integration between different Taproot components."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.internal_pubkey = b'\x01' * 32
        self.asset_id = "deadbeefcafebabe" * 4
        self.test_pubkey = b'\x02' * 32
        self.builder = TaprootBuilder()
    
    def test_transfer_script_to_p2tr_integration(self):
        """Test complete flow from transfer script to P2TR output."""
        # Create transfer script
        transfer_script = create_asset_transfer_script(
            self.asset_id, self.test_pubkey, b'\x03' * 32, 100
        )
        
        # Build script tree
        tree_builder = TaprootTreeBuilder()
        tree = tree_builder.add_leaf(transfer_script).build_tree()
        
        # Create P2TR output
        p2tr_script, tweaked_pubkey, merkle_root = self.builder.create_p2tr_output(
            self.internal_pubkey, tree
        )
        
        # Verify integration
        assert len(p2tr_script) == 34
        assert p2tr_script[0] == 0x51  # OP_1
        assert len(tweaked_pubkey) == 32
        assert merkle_root != b'\x00' * 32
    
    def test_mint_script_to_p2tr_integration(self):
        """Test complete flow from mint script to P2TR output."""
        # Create mint script
        mint_script = create_asset_mint_script(
            self.asset_id, self.test_pubkey, 1000, 21000000
        )
        
        # Verify script validation
        assert validate_taproot_script(mint_script) == True
        
        # Calculate leaf hash
        leaf_hash = calculate_tap_leaf_hash(mint_script)
        assert len(leaf_hash) == 32
        
        # Create P2TR output using builder
        p2tr_script, tweaked_pubkey, _ = self.builder.create_asset_mint_output(
            self.internal_pubkey, self.asset_id, self.test_pubkey, 1000, 21000000
        )
        
        # Verify output format
        assert p2tr_script == bytes([0x51, 0x20]) + tweaked_pubkey
    
    def test_multi_script_tree_integration(self):
        """Test integration with multiple scripts in tree."""
        # Create multiple scripts
        transfer_script = create_asset_transfer_script(
            self.asset_id, self.test_pubkey, b'\x03' * 32, 100
        )
        mint_script = create_asset_mint_script(
            self.asset_id, self.test_pubkey, 500
        )
        
        scripts = [transfer_script, mint_script]
        
        # Create multi-path output
        p2tr_script, tweaked_pubkey, returned_scripts = self.builder.create_multi_path_output(
            self.internal_pubkey, scripts
        )
        
        # Verify all scripts are returned
        assert len(returned_scripts) == 2
        assert transfer_script in returned_scripts
        assert mint_script in returned_scripts
        
        # Verify P2TR output
        assert len(p2tr_script) == 34
        assert len(tweaked_pubkey) == 32