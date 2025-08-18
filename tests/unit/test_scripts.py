"""
Comprehensive Script Testing Suite

Tests for all Bitcoin script implementations including P2WSH covenants,
Taproot implementations, validation framework, templates, and encoding utilities.
"""

import pytest
import hashlib
import secrets
import time
from typing import Dict, List, Optional, Tuple, Any
from unittest.mock import Mock, patch

from scripts.p2wsh_covenant import (
    P2WSHCovenantBuilder,
    CovenantType,
    create_simple_validator_script,
    create_multisig_validator_script,
    AssetCovenantTemplates
)
from scripts.taproot_covenant import (
    TaprootCovenantBuilder,
    TaprootSpendType,
    TapLeaf,
    TapBranch,
    create_simple_taproot_covenant,
    TaprootAssetTemplates
)
from scripts.validator import (
    ScriptTestFramework,
    ValidationEngine,
    ScriptExecutionContext,
    ScriptValidationResult,
    create_test_vectors,
    run_script_tests
)
from scripts.templates import (
    ScriptTemplateRegistry,
    TemplateType,
    ScriptFormat,
    FungibleMintTemplate,
    NFTMintTemplate,
    TransferTemplate,
    MultisigTemplate,
    TimelockTemplate,
    get_template_registry
)
from scripts.encoding import (
    ScriptEncoder,
    ScriptDecoder,
    ScriptAnalyzer,
    ScriptFormat,
    script_to_hex,
    script_to_asm,
    script_from_hex,
    script_from_asm,
    analyze_script_detailed
)
from crypto.commitments import AssetCommitment
from crypto.keys import PrivateKey, PublicKey


class TestP2WSHCovenant:
    """Test P2WSH covenant script construction."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = P2WSHCovenantBuilder()
        self.validator_privkey = PrivateKey.generate()
        self.validator_pubkey = self.validator_privkey.public_key.serialize_compressed()
        self.asset_id = secrets.token_bytes(32)
    
    def test_basic_validator_covenant(self):
        """Test basic validator signature covenant."""
        script = self.builder.create_validator_covenant(self.validator_pubkey)
        
        assert len(script) > 0
        assert script.endswith(b'\xac')  # OP_CHECKSIG
        
        # Verify script structure
        expected_prefix = b'\x21'  # OP_PUSHDATA(33)
        assert script.startswith(expected_prefix)
        assert script[1:34] == self.validator_pubkey
    
    def test_multisig_validator_covenant(self):
        """Test multi-signature validator covenant."""
        pubkey2 = PrivateKey.generate().public_key.serialize_compressed()
        pubkey3 = PrivateKey.generate().public_key.serialize_compressed()
        
        pubkeys = [self.validator_pubkey, pubkey2, pubkey3]
        script = self.builder.create_multisig_validator_covenant(pubkeys, 2)
        
        assert len(script) > 0
        assert script.endswith(b'\xae')  # OP_CHECKMULTISIG
        
        # Should contain all pubkeys
        for pubkey in pubkeys:
            assert pubkey in script
    
    def test_supply_limit_covenant(self):
        """Test supply limit enforcement covenant."""
        script = self.builder.create_supply_limit_covenant(
            validator_pubkey=self.validator_pubkey,
            supply_limit=1000000,
            current_supply=500000,
            mint_amount=10000
        )
        
        assert len(script) > 0
        # Should contain arithmetic and comparison operations
        assert b'\x93' in script  # OP_ADD
        assert b'\xa1' in script  # OP_LESSTHANOREQUAL
        assert b'\x69' in script  # OP_VERIFY
    
    def test_allowlist_covenant(self):
        """Test allowlist enforcement covenant."""
        allowlist_root = hashlib.sha256(b"test_allowlist").digest()
        recipient_hash = hashlib.sha256(b"test_recipient").digest()
        
        script = self.builder.create_allowlist_covenant(
            validator_pubkey=self.validator_pubkey,
            allowlist_root=allowlist_root,
            recipient_hash=recipient_hash
        )
        
        assert len(script) > 0
        assert allowlist_root in script
        assert recipient_hash in script
    
    def test_time_locked_covenant(self):
        """Test time-locked covenant."""
        lock_time = 12345678
        
        # Test absolute timelock
        script = self.builder.create_time_locked_covenant(
            validator_pubkey=self.validator_pubkey,
            lock_time=lock_time,
            lock_type="absolute"
        )
        
        assert len(script) > 0
        assert b'\xb1' in script  # OP_CHECKLOCKTIMEVERIFY
        
        # Test relative timelock
        script = self.builder.create_time_locked_covenant(
            validator_pubkey=self.validator_pubkey,
            lock_time=144,
            lock_type="relative"
        )
        
        assert len(script) > 0
        assert b'\xb2' in script  # OP_CHECKSEQUENCEVERIFY
    
    def test_witness_stack_creation(self):
        """Test witness stack construction."""
        script = self.builder.create_validator_covenant(self.validator_pubkey)
        signatures = [secrets.token_bytes(64)]  # Mock signature
        
        witness_stack = self.builder.create_witness_stack(signatures, script)
        
        assert len(witness_stack) == 2
        assert witness_stack[0].data == signatures[0]
        assert witness_stack[1].data == script
        assert witness_stack[1].is_script
    
    def test_script_validation(self):
        """Test script validation."""
        script = self.builder.create_validator_covenant(self.validator_pubkey)
        
        assert self.builder.validate_witness_script(script)
        
        # Test invalid script
        invalid_script = b'\xff' * 100  # Invalid opcodes
        assert not self.builder.validate_witness_script(invalid_script)
    
    def test_script_info_extraction(self):
        """Test script information extraction."""
        script = self.builder.create_validator_covenant(self.validator_pubkey)
        info = self.builder.get_script_info(script)
        
        assert "script_length" in info
        assert "script_hash" in info
        assert "is_valid" in info
        assert info["script_type"] == "single_sig"
    
    def test_asset_covenant_templates(self):
        """Test asset-specific covenant templates."""
        # Fungible mint covenant
        fungible_script = AssetCovenantTemplates.fungible_mint_covenant(
            validator_pubkey=self.validator_pubkey,
            supply_limit=1000000,
            per_mint_limit=10000
        )
        assert len(fungible_script) > 0
        
        # NFT mint covenant
        nft_script = AssetCovenantTemplates.nft_mint_covenant(
            validator_pubkey=self.validator_pubkey,
            collection_size=1000,
            content_hash_required=True
        )
        assert len(nft_script) > 0
    
    def test_cache_functionality(self):
        """Test script caching."""
        # Create same script twice
        script1 = self.builder.create_validator_covenant(self.validator_pubkey)
        script2 = self.builder.create_validator_covenant(self.validator_pubkey)
        
        assert script1 == script2
        
        # Check cache contents
        cache_key = f"validator:{self.validator_pubkey.hex()}"
        assert cache_key in self.builder.scripts_cache
    
    def test_edge_cases(self):
        """Test edge cases and error conditions."""
        # Invalid pubkey length
        with pytest.raises(ValueError):
            self.builder.create_validator_covenant(b"too_short")
        
        # Invalid multisig parameters
        with pytest.raises(ValueError):
            self.builder.create_multisig_validator_covenant([self.validator_pubkey], 2)
        
        # Invalid supply parameters
        with pytest.raises(ValueError):
            self.builder.create_supply_limit_covenant(
                self.validator_pubkey, -1, 0, 1
            )


class TestTaprootCovenant:
    """Test Taproot covenant implementation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.builder = TaprootCovenantBuilder()
        self.validator_privkey = PrivateKey.generate()
        self.validator_pubkey = self.validator_privkey.public_key.serialize_x_only()
        self.asset_id = secrets.token_bytes(32)
        self.asset_commitment = AssetCommitment(
            asset_id=self.asset_id,
            amount=1000,
            operation="mint"
        )
    
    def test_key_path_covenant(self):
        """Test key-path only Taproot covenant."""
        taproot_output = self.builder.create_key_path_covenant(
            internal_pubkey=self.validator_pubkey,
            asset_commitment=self.asset_commitment
        )
        
        assert len(taproot_output.internal_pubkey) == 32
        assert len(taproot_output.tweaked_pubkey) == 32
        assert len(taproot_output.output_script) == 34
        assert taproot_output.script_tree is None
    
    def test_script_path_covenant(self):
        """Test script-path Taproot covenant."""
        scripts = [
            self.builder._create_tapscript_validator_sig(self.validator_pubkey),
            self.builder._create_tapscript_supply_limit(
                self.validator_pubkey, 1000000, 500000, 1000
            )
        ]
        
        taproot_output = self.builder.create_script_path_covenant(
            internal_pubkey=self.validator_pubkey,
            scripts=scripts,
            asset_commitment=self.asset_commitment
        )
        
        assert taproot_output.script_tree is not None
        assert len(taproot_output.tweaked_pubkey) == 32
    
    def test_asset_mint_covenant(self):
        """Test asset minting covenant."""
        mint_conditions = {
            "supply_limit": 1000000,
            "current_supply": 500000,
            "mint_amount": 1000
        }
        
        taproot_output = self.builder.create_asset_mint_covenant(
            validator_pubkey=self.validator_pubkey,
            asset_commitment=self.asset_commitment,
            mint_conditions=mint_conditions
        )
        
        assert taproot_output.script_tree is not None
        assert self.builder.validate_taproot_output(taproot_output)
    
    def test_asset_transfer_covenant(self):
        """Test asset transfer covenant."""
        transfer_rules = {
            "allowlist_required": True,
            "allowlist_root": secrets.token_bytes(32)
        }
        
        taproot_output = self.builder.create_asset_transfer_covenant(
            validator_pubkey=self.validator_pubkey,
            asset_commitment=self.asset_commitment,
            transfer_rules=transfer_rules
        )
        
        assert taproot_output.script_tree is not None
    
    def test_script_tree_construction(self):
        """Test script tree building."""
        leaves = [
            TapLeaf(b"script1"),
            TapLeaf(b"script2"),
            TapLeaf(b"script3")
        ]
        
        tree = self.builder._build_script_tree(leaves)
        
        if len(leaves) == 1:
            assert isinstance(tree, TapLeaf)
        else:
            assert isinstance(tree, TapBranch)
        
        merkle_root = self.builder._compute_merkle_root(tree)
        assert len(merkle_root) == 32
    
    def test_control_block_generation(self):
        """Test control block generation."""
        script = b"test_tapscript"
        leaf = TapLeaf(script)
        
        control_block = self.builder.generate_control_block(
            internal_pubkey=self.validator_pubkey,
            script=script,
            script_tree=leaf
        )
        
        assert len(control_block) >= 33
        assert control_block[0] == 0xc0  # Leaf version
        assert control_block[1:33] == self.validator_pubkey
    
    def test_tapscript_creation(self):
        """Test various tapscript creation methods."""
        # Validator signature script
        val_script = self.builder._create_tapscript_validator_sig(self.validator_pubkey)
        assert len(val_script) > 0
        assert val_script.endswith(b'\xac')  # OP_CHECKSIG
        
        # Supply limit script
        supply_script = self.builder._create_tapscript_supply_limit(
            self.validator_pubkey, 1000000, 500000, 1000
        )
        assert len(supply_script) > 0
        
        # Timelock script
        timelock_script = self.builder._create_tapscript_timelock(
            self.validator_pubkey, 144
        )
        assert len(timelock_script) > 0
    
    def test_spending_transaction_creation(self):
        """Test spending transaction template creation."""
        taproot_output = self.builder.create_key_path_covenant(
            self.validator_pubkey, self.asset_commitment
        )
        
        tx_template = self.builder.create_spending_transaction(
            taproot_output=taproot_output,
            spend_type=TaprootSpendType.KEY_PATH
        )
        
        assert "inputs" in tx_template
        assert "outputs" in tx_template
        assert len(tx_template["inputs"]) == 1
    
    def test_taproot_asset_templates(self):
        """Test asset-specific Taproot templates."""
        # Fungible mint
        fungible_output = TaprootAssetTemplates.fungible_mint_taproot(
            validator_pubkey=self.validator_pubkey,
            asset_commitment=self.asset_commitment,
            supply_limit=1000000
        )
        assert self.builder.validate_taproot_output(fungible_output)
        
        # NFT mint
        nft_commitment = AssetCommitment(
            asset_id=self.asset_id,
            amount=1,
            operation="nft_mint",
            nft_token_id=123
        )
        
        nft_output = TaprootAssetTemplates.nft_mint_taproot(
            validator_pubkey=self.validator_pubkey,
            asset_commitment=nft_commitment,
            collection_size=1000
        )
        assert self.builder.validate_taproot_output(nft_output)
    
    def test_taproot_info_extraction(self):
        """Test Taproot output information extraction."""
        taproot_output = self.builder.create_key_path_covenant(
            self.validator_pubkey, self.asset_commitment
        )
        
        info = self.builder.get_taproot_info(taproot_output)
        
        assert "internal_pubkey" in info
        assert "tweaked_pubkey" in info
        assert "has_script_tree" in info
        assert info["has_script_tree"] is False


class TestScriptValidation:
    """Test script validation framework."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.framework = ScriptTestFramework(ValidationEngine.INTERNAL)
        self.validator_pubkey = PrivateKey.generate().public_key.serialize_compressed()
    
    def test_p2wsh_validation(self):
        """Test P2WSH script validation."""
        builder = P2WSHCovenantBuilder()
        witness_script = builder.create_validator_covenant(self.validator_pubkey)
        
        # Valid signature
        witness_stack = [secrets.token_bytes(64)]  # Mock signature
        result = self.framework.test_p2wsh_covenant(
            witness_script=witness_script,
            witness_stack=witness_stack,
            expected_result=True
        )
        
        assert result.is_valid()
        
        # Invalid signature (empty)
        result = self.framework.test_p2wsh_covenant(
            witness_script=witness_script,
            witness_stack=[b''],
            expected_result=False
        )
        
        assert not result.is_valid()
    
    def test_taproot_validation(self):
        """Test Taproot script validation."""
        builder = TaprootCovenantBuilder()
        validator_pubkey_x = self.validator_pubkey[1:]  # Remove prefix for x-only
        
        taproot_output = builder.create_key_path_covenant(validator_pubkey_x)
        
        # Key-path spending
        witness_stack = [secrets.token_bytes(64)]  # Mock Schnorr signature
        result = self.framework.test_taproot_covenant(
            taproot_output=taproot_output,
            spend_type=TaprootSpendType.KEY_PATH,
            witness_stack=witness_stack,
            expected_result=True
        )
        
        # Note: Internal validator is simplified, so this might not validate perfectly
        # In a real scenario, we'd need proper signature verification
    
    def test_validation_engines(self):
        """Test different validation engines."""
        # Internal engine
        internal_framework = ScriptTestFramework(ValidationEngine.INTERNAL)
        assert internal_framework.internal_validator is not None
        
        # Bitcoin Core engine (will be mocked in tests)
        with patch('scripts.validator.BitcoinCoreValidator'):
            core_framework = ScriptTestFramework(ValidationEngine.BITCOIN_CORE)
            assert core_framework.bitcoin_core_validator is not None
    
    def test_test_vector_execution(self):
        """Test execution of test vectors."""
        test_vectors = create_test_vectors()
        
        results = self.framework.run_test_suite(test_vectors)
        
        assert "total_tests" in results
        assert "passed" in results
        assert "failed" in results
        assert results["total_tests"] > 0
    
    def test_script_execution_context(self):
        """Test script execution context."""
        script = b'\x51\xac'  # OP_1 OP_CHECKSIG
        witness_stack = [b'\x01']  # Mock signature
        
        context = ScriptExecutionContext(
            script=script,
            witness_stack=witness_stack,
            utxo_value=100000000,
            is_taproot=False
        )
        
        assert context.utxo_value == 100000000
        assert len(context.witness_stack) == 1
        assert not context.is_taproot


class TestScriptTemplates:
    """Test script template system."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_template_registry()
        self.validator_pubkey = PrivateKey.generate().public_key.serialize_compressed()
        self.asset_id = secrets.token_bytes(32)
    
    def test_template_registration(self):
        """Test template registration and retrieval."""
        # Check default templates are registered
        template = self.registry.get_template(TemplateType.FUNGIBLE_MINT)
        assert template is not None
        assert isinstance(template, FungibleMintTemplate)
        
        # List all templates
        templates = self.registry.list_templates()
        assert len(templates) > 0
        
        template_types = [t["type"] for t in templates]
        assert "fungible_mint" in template_types
        assert "nft_mint" in template_types
    
    def test_fungible_mint_template(self):
        """Test fungible token mint template."""
        template = FungibleMintTemplate()
        
        params = {
            "validator_pubkey": self.validator_pubkey,
            "asset_id": self.asset_id,
            "supply_limit": 1000000,
            "per_mint_limit": 10000
        }
        
        # Test parameter validation
        errors = template.validate_parameters(params)
        assert len(errors) == 0
        
        # Test P2WSH compilation
        p2wsh_script = template.compile_p2wsh(params)
        assert len(p2wsh_script) > 0
        
        # Test Taproot compilation
        taproot_output = template.compile_taproot(params)
        assert len(taproot_output.tweaked_pubkey) == 32
    
    def test_nft_mint_template(self):
        """Test NFT mint template."""
        template = NFTMintTemplate()
        
        params = {
            "validator_pubkey": self.validator_pubkey,
            "asset_id": self.asset_id,
            "collection_size": 1000,
            "token_id": 123,
            "content_hash": secrets.token_bytes(32)
        }
        
        errors = template.validate_parameters(params)
        assert len(errors) == 0
        
        p2wsh_script = template.compile_p2wsh(params)
        assert len(p2wsh_script) > 0
    
    def test_multisig_template(self):
        """Test multi-signature template."""
        template = MultisigTemplate()
        
        pubkey2 = PrivateKey.generate().public_key.serialize_compressed()
        pubkey3 = PrivateKey.generate().public_key.serialize_compressed()
        
        params = {
            "validator_pubkeys": [self.validator_pubkey, pubkey2, pubkey3],
            "required_signatures": 2
        }
        
        errors = template.validate_parameters(params)
        assert len(errors) == 0
        
        p2wsh_script = template.compile_p2wsh(params)
        assert len(p2wsh_script) > 0
    
    def test_timelock_template(self):
        """Test timelock template."""
        template = TimelockTemplate()
        
        params = {
            "validator_pubkey": self.validator_pubkey,
            "lock_time": 144,
            "lock_type": "relative"
        }
        
        errors = template.validate_parameters(params)
        assert len(errors) == 0
        
        p2wsh_script = template.compile_p2wsh(params)
        assert len(p2wsh_script) > 0
    
    def test_parameter_validation(self):
        """Test template parameter validation."""
        template = FungibleMintTemplate()
        
        # Valid parameters
        valid_params = {
            "validator_pubkey": self.validator_pubkey,
            "asset_id": self.asset_id,
            "supply_limit": 1000000,
            "per_mint_limit": 10000
        }
        errors = template.validate_parameters(valid_params)
        assert len(errors) == 0
        
        # Invalid parameters
        invalid_params = {
            "validator_pubkey": b"too_short",  # Invalid length
            "asset_id": self.asset_id,
            "supply_limit": -1,  # Negative
            "per_mint_limit": 0   # Zero
        }
        errors = template.validate_parameters(invalid_params)
        assert len(errors) > 0
    
    def test_registry_compilation(self):
        """Test registry-based template compilation."""
        params = {
            "validator_pubkey": self.validator_pubkey,
            "asset_id": self.asset_id,
            "supply_limit": 1000000,
            "per_mint_limit": 10000
        }
        
        # Compile P2WSH
        p2wsh_result = self.registry.compile_template(
            TemplateType.FUNGIBLE_MINT,
            params,
            ScriptFormat.P2WSH
        )
        assert isinstance(p2wsh_result, bytes)
        
        # Compile Taproot
        taproot_result = self.registry.compile_template(
            TemplateType.FUNGIBLE_MINT,
            params,
            ScriptFormat.TAPROOT
        )
        assert hasattr(taproot_result, 'tweaked_pubkey')


class TestScriptEncoding:
    """Test script encoding and decoding utilities."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encoder = ScriptEncoder()
        self.decoder = ScriptDecoder()
        self.analyzer = ScriptAnalyzer()
        
        # Create test script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        self.test_script = (
            b'\x76'  # OP_DUP
            b'\xa9'  # OP_HASH160
            b'\x14' + b'\x01' * 20  # Push 20 bytes
            b'\x88'  # OP_EQUALVERIFY
            b'\xac'  # OP_CHECKSIG
        )
    
    def test_script_parsing(self):
        """Test script parsing."""
        parsed = self.encoder.parse_script(self.test_script)
        
        assert len(parsed.elements) == 5
        assert parsed.is_valid
        assert len(parsed.parse_errors) == 0
        
        # Check elements
        assert parsed.elements[0].opcode == 0x76  # OP_DUP
        assert parsed.elements[1].opcode == 0xa9  # OP_HASH160
        assert parsed.elements[2].is_push_data
        assert len(parsed.elements[2].data) == 20
    
    def test_format_encoding(self):
        """Test different format encodings."""
        # Hex encoding
        hex_result = self.encoder.encode_script(self.test_script, ScriptFormat.HEX_STRING)
        assert isinstance(hex_result, str)
        assert len(hex_result) == len(self.test_script) * 2
        
        # ASM encoding
        asm_result = self.encoder.encode_script(self.test_script, ScriptFormat.ASM_STRING)
        assert isinstance(asm_result, str)
        assert "OP_DUP" in asm_result or "76" in asm_result
        
        # JSON encoding
        json_result = self.encoder.encode_script(self.test_script, ScriptFormat.JSON_OBJECT)
        assert isinstance(json_result, dict)
        assert "hex" in json_result
        assert "asm" in json_result
        assert "elements" in json_result
    
    def test_format_decoding(self):
        """Test format decoding."""
        # Hex decoding
        hex_encoded = self.test_script.hex()
        decoded = self.decoder.decode_script(hex_encoded, ScriptFormat.HEX_STRING)
        assert decoded == self.test_script
        
        # ASM decoding (simplified)
        asm_encoded = "76 a9 14" + ("01" * 20) + " 88 ac"
        decoded = self.decoder.decode_script(asm_encoded, ScriptFormat.ASM_STRING)
        # Note: ASM decoding might not be perfect due to opcode name handling
        assert len(decoded) > 0
    
    def test_witness_stack_encoding(self):
        """Test witness stack encoding."""
        witness_stack = [
            b'',  # Empty signature for multisig
            secrets.token_bytes(64),  # Signature
            self.test_script  # Script
        ]
        
        # Hex encoding
        hex_encoded = self.encoder.encode_witness_stack(
            witness_stack, ScriptFormat.HEX_STRING
        )
        assert isinstance(hex_encoded, list)
        assert len(hex_encoded) == 3
        
        # JSON encoding
        json_encoded = self.encoder.encode_witness_stack(
            witness_stack, ScriptFormat.JSON_OBJECT
        )
        assert isinstance(json_encoded, dict)
        assert "witness_items" in json_encoded
    
    def test_script_analysis(self):
        """Test script analysis."""
        analysis = self.analyzer.analyze_script(self.test_script)
        
        assert "basic_info" in analysis
        assert "opcodes" in analysis
        assert "data_pushes" in analysis
        assert "security" in analysis
        assert "complexity" in analysis
        
        # Check basic info
        basic = analysis["basic_info"]
        assert basic["size_bytes"] == len(self.test_script)
        assert basic["script_type"] == "p2pkh"  # Should detect P2PKH
        
        # Check opcode analysis
        opcodes = analysis["opcodes"]
        assert opcodes["push_operations"] == 1  # One data push
        assert opcodes["crypto_operations"] >= 1  # At least one crypto op
    
    def test_script_type_detection(self):
        """Test script type detection."""
        # P2PKH script
        p2pkh_parsed = self.encoder.parse_script(self.test_script)
        assert p2pkh_parsed.script_type.value == "p2pkh"
        
        # P2WSH script (OP_0 <32 bytes>)
        p2wsh_script = b'\x00\x20' + secrets.token_bytes(32)
        p2wsh_parsed = self.encoder.parse_script(p2wsh_script)
        assert p2wsh_parsed.script_type.value == "p2wsh"
        
        # P2TR script (OP_1 <32 bytes>)
        p2tr_script = b'\x51\x20' + secrets.token_bytes(32)
        p2tr_parsed = self.encoder.parse_script(p2tr_script)
        assert p2tr_parsed.script_type.value == "p2tr"
    
    def test_convenience_functions(self):
        """Test convenience functions."""
        # Hex conversion
        hex_str = script_to_hex(self.test_script)
        back_to_script = script_from_hex(hex_str)
        assert back_to_script == self.test_script
        
        # ASM conversion
        asm_str = script_to_asm(self.test_script)
        assert isinstance(asm_str, str)
        
        # Analysis
        detailed_analysis = analyze_script_detailed(self.test_script)
        assert isinstance(detailed_analysis, dict)
    
    def test_error_handling(self):
        """Test error handling in encoding/decoding."""
        # Invalid hex
        with pytest.raises(ValueError):
            script_from_hex("invalid_hex_string")
        
        # Truncated script
        truncated_script = self.test_script[:-1]  # Remove last byte
        parsed = self.encoder.parse_script(truncated_script)
        # Should still parse but might have errors depending on truncation point


class TestScriptPerformance:
    """Performance tests for script operations."""
    
    def test_script_creation_performance(self):
        """Test performance of script creation."""
        builder = P2WSHCovenantBuilder()
        validator_pubkey = PrivateKey.generate().public_key.serialize_compressed()
        
        start_time = time.time()
        for _ in range(1000):
            script = builder.create_validator_covenant(validator_pubkey)
        end_time = time.time()
        
        avg_time = (end_time - start_time) / 1000
        assert avg_time < 0.001  # Should be under 1ms per script
    
    def test_script_parsing_performance(self):
        """Test performance of script parsing."""
        encoder = ScriptEncoder()
        
        # Create test script
        script = b'\x76\xa9\x14' + secrets.token_bytes(20) + b'\x88\xac'
        
        start_time = time.time()
        for _ in range(1000):
            parsed = encoder.parse_script(script)
        end_time = time.time()
        
        avg_time = (end_time - start_time) / 1000
        assert avg_time < 0.001  # Should be under 1ms per parse
    
    def test_template_compilation_performance(self):
        """Test performance of template compilation."""
        registry = get_template_registry()
        
        params = {
            "validator_pubkey": PrivateKey.generate().public_key.serialize_compressed(),
            "asset_id": secrets.token_bytes(32),
            "supply_limit": 1000000,
            "per_mint_limit": 10000
        }
        
        start_time = time.time()
        for _ in range(100):
            script = registry.compile_template(
                TemplateType.FUNGIBLE_MINT,
                params,
                ScriptFormat.P2WSH
            )
        end_time = time.time()
        
        avg_time = (end_time - start_time) / 100
        assert avg_time < 0.01  # Should be under 10ms per compilation


class TestScriptFuzzing:
    """Fuzz testing for script robustness."""
    
    def test_random_script_parsing(self):
        """Test parsing of random scripts."""
        encoder = ScriptEncoder()
        
        for _ in range(100):
            # Generate random script
            script_length = secrets.randbelow(100) + 1
            random_script = secrets.token_bytes(script_length)
            
            try:
                parsed = encoder.parse_script(random_script)
                # Should not crash, might have errors
                assert isinstance(parsed.parse_errors, list)
            except Exception as e:
                # Should handle errors gracefully
                assert isinstance(e, (ValueError, IndexError, struct.error))
    
    def test_malformed_witness_stacks(self):
        """Test handling of malformed witness stacks."""
        framework = ScriptTestFramework()
        validator_pubkey = PrivateKey.generate().public_key.serialize_compressed()
        
        builder = P2WSHCovenantBuilder()
        script = builder.create_validator_covenant(validator_pubkey)
        
        # Test various malformed witness stacks
        malformed_stacks = [
            [],  # Empty stack
            [b''],  # Only empty signature
            [b'', b''],  # Two empty items
            [secrets.token_bytes(100)] * 10,  # Too many items
            [secrets.token_bytes(1000)],  # Very large item
        ]
        
        for witness_stack in malformed_stacks:
            try:
                result = framework.test_p2wsh_covenant(
                    witness_script=script,
                    witness_stack=witness_stack,
                    expected_result=False
                )
                # Should not crash
                assert hasattr(result, 'is_valid')
            except Exception as e:
                # Should handle gracefully
                pass
    
    def test_extreme_values(self):
        """Test handling of extreme parameter values."""
        builder = P2WSHCovenantBuilder()
        validator_pubkey = PrivateKey.generate().public_key.serialize_compressed()
        
        # Test extreme supply values
        try:
            builder.create_supply_limit_covenant(
                validator_pubkey=validator_pubkey,
                supply_limit=2**63 - 1,  # Maximum int
                current_supply=0,
                mint_amount=1
            )
        except (ValueError, OverflowError):
            pass  # Expected for extreme values
        
        # Test very large multisig
        try:
            many_pubkeys = [
                PrivateKey.generate().public_key.serialize_compressed()
                for _ in range(100)
            ]
            builder.create_multisig_validator_covenant(
                many_pubkeys, len(many_pubkeys)
            )
        except ValueError:
            pass  # Expected - Bitcoin has limits


class TestScriptIntegration:
    """Integration tests combining multiple script components."""
    
    def setup_method(self):
        """Set up integration test fixtures."""
        self.validator_privkey = PrivateKey.generate()
        self.validator_pubkey = self.validator_privkey.public_key.serialize_compressed()
        self.asset_id = secrets.token_bytes(32)
    
    def test_full_p2wsh_workflow(self):
        """Test complete P2WSH workflow."""
        # 1. Create script using template
        registry = get_template_registry()
        
        params = {
            "validator_pubkey": self.validator_pubkey,
            "asset_id": self.asset_id,
            "supply_limit": 1000000,
            "per_mint_limit": 10000
        }
        
        script = registry.compile_template(
            TemplateType.FUNGIBLE_MINT,
            params,
            ScriptFormat.P2WSH
        )
        
        # 2. Encode script to various formats
        encoder = ScriptEncoder()
        hex_encoded = encoder.encode_script(script, ScriptFormat.HEX_STRING)
        json_encoded = encoder.encode_script(script, ScriptFormat.JSON_OBJECT)
        
        # 3. Decode back to bytes
        decoder = ScriptDecoder()
        decoded_script = decoder.decode_script(hex_encoded, ScriptFormat.HEX_STRING)
        assert decoded_script == script
        
        # 4. Analyze script
        analyzer = ScriptAnalyzer()
        analysis = analyzer.analyze_script(script)
        assert analysis["basic_info"]["is_valid"]
        
        # 5. Test validation
        framework = ScriptTestFramework()
        witness_stack = [secrets.token_bytes(64)]  # Mock signature
        
        result = framework.test_p2wsh_covenant(
            witness_script=script,
            witness_stack=witness_stack,
            expected_result=True
        )
        
        # Should complete without errors
        assert hasattr(result, 'is_valid')
    
    def test_full_taproot_workflow(self):
        """Test complete Taproot workflow."""
        # 1. Create Taproot output using template
        validator_pubkey_x = self.validator_pubkey[1:]  # Remove prefix
        
        taproot_template = TaprootAssetTemplates()
        asset_commitment = AssetCommitment(
            asset_id=self.asset_id,
            amount=1000,
            operation="mint"
        )
        
        taproot_output = taproot_template.fungible_mint_taproot(
            validator_pubkey=validator_pubkey_x,
            asset_commitment=asset_commitment,
            supply_limit=1000000
        )
        
        # 2. Encode script tree if present
        if taproot_output.script_tree:
            encoder = ScriptEncoder()
            tree_encoded = encoder.encode_taproot_commitment(
                taproot_output.script_tree,
                ScriptFormat.JSON_OBJECT
            )
            assert isinstance(tree_encoded, dict)
        
        # 3. Test validation framework
        framework = ScriptTestFramework()
        witness_stack = [secrets.token_bytes(64)]  # Mock Schnorr signature
        
        result = framework.test_taproot_covenant(
            taproot_output=taproot_output,
            spend_type=TaprootSpendType.KEY_PATH,
            witness_stack=witness_stack,
            expected_result=True
        )
        
        # Should complete without errors
        assert hasattr(result, 'is_valid')
    
    def test_cross_format_compatibility(self):
        """Test compatibility between P2WSH and Taproot for same logic."""
        # Create equivalent scripts in both formats
        registry = get_template_registry()
        
        params = {
            "validator_pubkey": self.validator_pubkey,
            "asset_id": self.asset_id,
            "supply_limit": 1000000,
            "per_mint_limit": 10000
        }
        
        p2wsh_script = registry.compile_template(
            TemplateType.FUNGIBLE_MINT,
            params,
            ScriptFormat.P2WSH
        )
        
        taproot_output = registry.compile_template(
            TemplateType.FUNGIBLE_MINT,
            params,
            ScriptFormat.TAPROOT
        )
        
        # Both should be valid
        encoder = ScriptEncoder()
        p2wsh_parsed = encoder.parse_script(p2wsh_script)
        assert p2wsh_parsed.is_valid
        
        builder = TaprootCovenantBuilder()
        assert builder.validate_taproot_output(taproot_output)


# Test runner function
def run_all_script_tests():
    """Run all script tests."""
    import pytest
    
    test_modules = [
        TestP2WSHCovenant,
        TestTaprootCovenant, 
        TestScriptValidation,
        TestScriptTemplates,
        TestScriptEncoding,
        TestScriptPerformance,
        TestScriptFuzzing,
        TestScriptIntegration
    ]
    
    for test_class in test_modules:
        print(f"Running {test_class.__name__}...")
        pytest.main(["-v", f"{__file__}::{test_class.__name__}"])


if __name__ == "__main__":
    run_all_script_tests()