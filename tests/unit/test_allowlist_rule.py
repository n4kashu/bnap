"""
Tests for Allowlist Rule with Merkle Proof Verification

Tests the AllowlistRule validation logic including Merkle proof verification,
caching, batch processing, and various hash functions.
"""

import pytest
import time
import hashlib
from unittest.mock import Mock, patch

from validator.core import ValidationContext
from validator.rules.allowlist import (
    AllowlistRule,
    MerkleProof,
    AllowlistEntry,
    HashFunction,
    ProofFormat,
    create_allowlist_rule,
    build_merkle_tree,
    verify_allowlist_proof
)
from registry.schema import AssetType
from crypto.commitments import OperationType


class TestMerkleProof:
    """Test MerkleProof data class."""
    
    def test_merkle_proof_creation(self):
        """Test basic Merkle proof creation."""
        leaf_hash = b'\\x01' * 32
        proof_hashes = [b'\\x02' * 32, b'\\x03' * 32]
        
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            proof_hashes=proof_hashes,
            leaf_index=2,
            tree_size=8,
            hash_function=HashFunction.SHA256
        )
        
        assert proof.leaf_hash == leaf_hash
        assert proof.proof_hashes == proof_hashes
        assert proof.leaf_index == 2
        assert proof.tree_size == 8
        assert proof.hash_function == HashFunction.SHA256
    
    def test_merkle_proof_validation(self):
        """Test Merkle proof validation on creation."""
        leaf_hash = b'\\x01' * 32
        proof_hashes = [b'\\x02' * 32]
        
        # Valid proof
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            proof_hashes=proof_hashes,
            leaf_index=1,
            tree_size=2
        )
        assert proof.leaf_index == 1
        
        # Invalid leaf index - negative
        with pytest.raises(ValueError, match="Invalid leaf index"):
            MerkleProof(
                leaf_hash=leaf_hash,
                proof_hashes=proof_hashes,
                leaf_index=-1,
                tree_size=2
            )
        
        # Invalid leaf index - too large
        with pytest.raises(ValueError, match="Invalid leaf index"):
            MerkleProof(
                leaf_hash=leaf_hash,
                proof_hashes=proof_hashes,
                leaf_index=2,
                tree_size=2
            )
    
    def test_merkle_proof_length_validation(self):
        """Test Merkle proof length validation."""
        leaf_hash = b'\\x01' * 32
        
        # Tree size 4 should need max 2 proof hashes
        too_many_hashes = [b'\\x02' * 32] * 5
        
        with pytest.raises(ValueError, match="Proof too long"):
            MerkleProof(
                leaf_hash=leaf_hash,
                proof_hashes=too_many_hashes,
                leaf_index=0,
                tree_size=4
            )


class TestAllowlistEntry:
    """Test AllowlistEntry data class."""
    
    def test_allowlist_entry_creation(self):
        """Test basic allowlist entry creation."""
        proof = MerkleProof(
            leaf_hash=b'\\x01' * 32,
            proof_hashes=[b'\\x02' * 32],
            leaf_index=0,
            tree_size=2
        )
        
        entry = AllowlistEntry(
            address="bc1qexample123",
            proof=proof
        )
        
        assert entry.address == "bc1qexample123"
        assert entry.proof == proof
        assert entry.verified is False
        assert entry.last_verified is None
        assert entry.verification_count == 0
    
    def test_mark_verified(self):
        """Test marking entry as verified."""
        proof = MerkleProof(
            leaf_hash=b'\\x01' * 32,
            proof_hashes=[],
            leaf_index=0,
            tree_size=1
        )
        
        entry = AllowlistEntry("address", proof)
        
        # Initially not verified
        assert not entry.verified
        assert entry.verification_count == 0
        
        # Mark as verified
        entry.mark_verified()
        
        assert entry.verified is True
        assert isinstance(entry.last_verified, float)
        assert entry.verification_count == 1
        
        # Mark again
        entry.mark_verified()
        assert entry.verification_count == 2


class TestAllowlistRule:
    """Test AllowlistRule functionality."""
    
    def test_rule_creation(self):
        """Test basic rule creation."""
        rule = AllowlistRule()
        
        assert rule.name == "allowlist"
        assert "allowlist" in rule.description.lower()
        assert rule.enabled is True
        assert rule.enable_caching is True
        assert rule.cache_ttl == 3600
        assert rule.strict_verification is True
        assert rule.max_proof_size == 64
    
    def test_rule_creation_with_config(self):
        """Test rule creation with custom configuration."""
        rule = AllowlistRule(
            enable_caching=False,
            cache_ttl=1800,
            strict_verification=False,
            max_proof_size=32
        )
        
        assert rule.enable_caching is False
        assert rule.cache_ttl == 1800
        assert rule.strict_verification is False
        assert rule.max_proof_size == 32
    
    def test_applicability_mint_operation(self):
        """Test rule applicability for mint operations."""
        rule = AllowlistRule()
        
        # Valid mint operation with allowlist
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            allowlist_root=b'\\x02' * 32
        )
        
        assert rule.is_applicable(context) is True
    
    def test_applicability_non_mint_operation(self):
        """Test rule applicability for non-mint operations."""
        rule = AllowlistRule()
        
        # Transfer operation should not be applicable
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.TRANSFER,
            allowlist_root=b'\\x02' * 32
        )
        
        assert rule.is_applicable(context) is False
    
    def test_applicability_no_allowlist(self):
        """Test rule applicability when no allowlist is configured."""
        rule = AllowlistRule()
        
        # No allowlist root means no allowlist required
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            allowlist_root=None
        )
        
        assert rule.is_applicable(context) is False
    
    def test_applicability_missing_data(self):
        """Test rule applicability with missing required data."""
        rule = AllowlistRule()
        
        # Missing asset_id
        context = ValidationContext(
            psbt_data={},
            asset_id=None,
            operation=OperationType.MINT,
            allowlist_root=b'\\x02' * 32
        )
        assert rule.is_applicable(context) is False
    
    def test_validation_no_recipients_strict(self):
        """Test validation with no recipients in strict mode."""
        rule = AllowlistRule(strict_verification=True)
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            allowlist_root=b'\\x02' * 32
        )
        
        # Mock _extract_recipients to return empty dict
        with patch.object(rule, '_extract_recipients', return_value={}):
            result = rule.validate(context)
            
            assert result is False
            assert context.has_errors()
            assert "No recipients found" in context.validation_errors[0]
    
    def test_validation_no_recipients_non_strict(self):
        """Test validation with no recipients in non-strict mode."""
        rule = AllowlistRule(strict_verification=False)
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            allowlist_root=b'\\x02' * 32
        )
        
        # Mock _extract_recipients to return empty dict
        with patch.object(rule, '_extract_recipients', return_value={}):
            result = rule.validate(context)
            
            # Should pass in non-strict mode
            assert result is True
            assert not context.has_errors()
    
    def test_validation_success_with_valid_proof(self):
        """Test successful validation with valid Merkle proof."""
        rule = AllowlistRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            allowlist_root=b'\\x02' * 32
        )
        
        # Mock recipient extraction and verification
        test_address = "bc1qtest123"
        recipients = {test_address: {"leaf_hash": "deadbeef", "proof_hashes": []}}
        
        with patch.object(rule, '_extract_recipients', return_value=recipients):
            with patch.object(rule, '_verify_recipient', return_value=True):
                result = rule.validate(context)
                
                assert result is True
                assert not context.has_errors()
                assert rule.stats["addresses_verified"] == 1
    
    def test_validation_failure_with_invalid_proof(self):
        """Test validation failure with invalid Merkle proof."""
        rule = AllowlistRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            allowlist_root=b'\\x02' * 32
        )
        
        # Mock recipient extraction and verification
        test_address = "bc1qtest123"
        recipients = {test_address: {"leaf_hash": "deadbeef", "proof_hashes": []}}
        
        with patch.object(rule, '_extract_recipients', return_value=recipients):
            with patch.object(rule, '_verify_recipient', return_value=False):
                result = rule.validate(context)
                
                assert result is False
                # Errors would be added by _verify_recipient
                assert rule.stats["addresses_rejected"] == 1
    
    def test_hash_functions(self):
        """Test different hash functions."""
        rule = AllowlistRule()
        test_data = b"test_data"
        
        # Test SHA256
        hash_sha256 = rule._hash_data(test_data, HashFunction.SHA256)
        assert len(hash_sha256) == 32
        assert hash_sha256 == hashlib.sha256(test_data).digest()
        
        # Test SHA3_256
        hash_sha3 = rule._hash_data(test_data, HashFunction.SHA3_256)
        assert len(hash_sha3) == 32
        assert hash_sha3 == hashlib.sha3_256(test_data).digest()
        
        # Test BLAKE2B
        hash_blake2b = rule._hash_data(test_data, HashFunction.BLAKE2B)
        assert len(hash_blake2b) == 32
        assert hash_blake2b == hashlib.blake2b(test_data, digest_size=32).digest()
        
        # Test unsupported function
        with pytest.raises(ValueError, match="Unsupported hash function"):
            rule._hash_data(test_data, "unsupported")
    
    def test_address_hashing(self):
        """Test address hashing."""
        rule = AllowlistRule()
        address = "bc1qexample123456789"
        
        # Test different hash functions
        hash_sha256 = rule._hash_address(address, HashFunction.SHA256)
        hash_sha3 = rule._hash_address(address, HashFunction.SHA3_256)
        
        assert len(hash_sha256) == 32
        assert len(hash_sha3) == 32
        assert hash_sha256 != hash_sha3
        
        # Same address should produce same hash
        hash_again = rule._hash_address(address, HashFunction.SHA256)
        assert hash_sha256 == hash_again
    
    def test_merkle_proof_verification(self):
        """Test Merkle proof verification logic."""
        rule = AllowlistRule()
        
        # Create simple 2-leaf tree
        leaf1 = hashlib.sha256(b"address1").digest()
        leaf2 = hashlib.sha256(b"address2").digest()
        root = hashlib.sha256(leaf1 + leaf2).digest()
        
        # Create proof for leaf1 (index 0)
        proof = MerkleProof(
            leaf_hash=leaf1,
            proof_hashes=[leaf2],
            leaf_index=0,
            tree_size=2,
            hash_function=HashFunction.SHA256
        )
        
        assert rule._verify_merkle_proof(proof, root) is True
        
        # Test with wrong root
        wrong_root = hashlib.sha256(b"wrong").digest()
        assert rule._verify_merkle_proof(proof, wrong_root) is False
    
    def test_proof_parsing_valid(self):
        """Test parsing of valid proof data."""
        rule = AllowlistRule()
        address = "bc1qtest123"
        
        # Create expected leaf hash
        expected_leaf = rule._hash_address(address, HashFunction.SHA256)
        
        proof_data = {
            "leaf_hash": expected_leaf.hex(),
            "proof_hashes": ["deadbeef" * 8, "cafebabe" * 8],
            "leaf_index": 1,
            "tree_size": 4,
            "hash_function": "sha256"
        }
        
        merkle_proof = rule._parse_proof_data(address, proof_data)
        
        assert merkle_proof is not None
        assert merkle_proof.leaf_hash == expected_leaf
        assert len(merkle_proof.proof_hashes) == 2
        assert merkle_proof.leaf_index == 1
        assert merkle_proof.tree_size == 4
        assert merkle_proof.hash_function == HashFunction.SHA256
    
    def test_proof_parsing_invalid(self):
        """Test parsing of invalid proof data."""
        rule = AllowlistRule()
        address = "bc1qtest123"
        
        # Missing required fields
        invalid_proof = {
            "proof_hashes": [],
            "leaf_index": 0
        }
        
        merkle_proof = rule._parse_proof_data(address, invalid_proof)
        assert merkle_proof is None
        
        # Wrong leaf hash
        wrong_leaf_proof = {
            "leaf_hash": "deadbeef" * 8,  # Wrong hash
            "proof_hashes": [],
            "leaf_index": 0,
            "tree_size": 1,
            "hash_function": "sha256"
        }
        
        merkle_proof = rule._parse_proof_data(address, wrong_leaf_proof)
        assert merkle_proof is None
        
        # Proof too large
        large_proof = {
            "leaf_hash": rule._hash_address(address, HashFunction.SHA256).hex(),
            "proof_hashes": ["deadbeef" * 8] * 100,  # Too many hashes
            "leaf_index": 0,
            "tree_size": 1,
            "hash_function": "sha256"
        }
        
        merkle_proof = rule._parse_proof_data(address, large_proof)
        assert merkle_proof is None
    
    def test_caching_enabled(self):
        """Test allowlist caching functionality."""
        rule = AllowlistRule(enable_caching=True, cache_ttl=300)
        
        asset_id = "01" * 32
        address = "bc1qtest123"
        
        # Create mock proof
        proof = MerkleProof(
            leaf_hash=b'\\x01' * 32,
            proof_hashes=[],
            leaf_index=0,
            tree_size=1
        )
        
        # Cache verification
        rule._cache_verification(asset_id, address, proof, True)
        
        # Should be able to retrieve
        entry = rule._get_cached_entry(asset_id, address)
        assert entry is not None
        assert entry.verified is True
        assert entry.address == address
        
        # Test cache hit
        assert not rule._is_cache_expired(entry)
    
    def test_caching_expiration(self):
        """Test cache entry expiration."""
        rule = AllowlistRule(enable_caching=True, cache_ttl=1)  # 1 second TTL
        
        asset_id = "01" * 32
        address = "bc1qtest123"
        
        proof = MerkleProof(
            leaf_hash=b'\\x01' * 32,
            proof_hashes=[],
            leaf_index=0,
            tree_size=1
        )
        
        rule._cache_verification(asset_id, address, proof, True)
        entry = rule._get_cached_entry(asset_id, address)
        
        # Initially not expired
        assert not rule._is_cache_expired(entry)
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired now
        assert rule._is_cache_expired(entry)
    
    def test_cache_clearing(self):
        """Test cache clearing functionality."""
        rule = AllowlistRule(enable_caching=True)
        
        asset1 = "01" * 32
        asset2 = "02" * 32
        address1 = "address1"
        address2 = "address2"
        
        proof = MerkleProof(b'\\x01' * 32, [], 0, 1)
        
        # Populate cache
        rule._cache_verification(asset1, address1, proof, True)
        rule._cache_verification(asset1, address2, proof, True)
        rule._cache_verification(asset2, address1, proof, True)
        
        assert len(rule.allowlist_cache) == 2
        assert len(rule.allowlist_cache[asset1]) == 2
        
        # Clear specific entry
        rule.clear_cache(asset1, address1)
        assert len(rule.allowlist_cache[asset1]) == 1
        assert address2 in rule.allowlist_cache[asset1]
        
        # Clear all entries for asset
        rule.clear_cache(asset1)
        assert asset1 not in rule.allowlist_cache
        assert asset2 in rule.allowlist_cache
        
        # Clear entire cache
        rule.clear_cache()
        assert len(rule.allowlist_cache) == 0
    
    def test_statistics(self):
        """Test statistics tracking."""
        rule = AllowlistRule()
        
        stats = rule.get_statistics()
        
        expected_keys = [
            "validations_performed",
            "proofs_verified",
            "proofs_failed", 
            "cache_hits",
            "cache_misses",
            "addresses_verified",
            "addresses_rejected",
            "cache_hit_rate_percent",
            "proof_verification_rate_percent",
            "cached_assets",
            "total_cached_addresses"
        ]
        
        for key in expected_keys:
            assert key in stats
        
        # Test after operations
        rule.stats["cache_hits"] = 3
        rule.stats["cache_misses"] = 7
        rule.stats["proofs_verified"] = 8
        rule.stats["proofs_failed"] = 2
        
        updated_stats = rule.get_statistics()
        assert updated_stats["cache_hit_rate_percent"] == 30.0  # 3/10
        assert updated_stats["proof_verification_rate_percent"] == 80.0  # 8/10
    
    def test_recipient_extraction_simulation(self):
        """Test recipient extraction simulation."""
        rule = AllowlistRule()
        
        context = ValidationContext(
            psbt_data={"outputs": []},
            asset_id=b'\\x01' * 32,
            amount=1000
        )
        
        recipients = rule._extract_recipients(context)
        
        # Should extract simulated recipient
        assert len(recipients) == 1
        assert "bc1qexampleallowlist123456789" in recipients
    
    def test_recipient_extraction_with_proofs(self):
        """Test recipient extraction with embedded proof data."""
        rule = AllowlistRule()
        
        # Mock PSBT with proprietary allowlist proof data
        context = ValidationContext(
            psbt_data={
                "outputs": [],
                "proprietary": {
                    "allowlist_proofs": {
                        "address1": {"leaf_hash": "deadbeef", "proof_hashes": []},
                        "address2": {"leaf_hash": "cafebabe", "proof_hashes": ["beef"]}
                    }
                }
            },
            asset_id=b'\\x01' * 32,
            amount=1000
        )
        
        recipients = rule._extract_recipients(context)
        
        assert len(recipients) == 2
        assert "address1" in recipients
        assert "address2" in recipients
        assert recipients["address1"]["leaf_hash"] == "deadbeef"


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_create_allowlist_rule(self):
        """Test allowlist rule creation utility."""
        rule = create_allowlist_rule()
        assert isinstance(rule, AllowlistRule)
        assert rule.enable_caching is True
        assert rule.cache_ttl == 3600
        
        # With custom config
        config = {
            "enable_caching": False,
            "cache_ttl": 1800,
            "strict_verification": False,
            "max_proof_size": 32
        }
        rule = create_allowlist_rule(config)
        assert rule.enable_caching is False
        assert rule.cache_ttl == 1800
        assert rule.strict_verification is False
        assert rule.max_proof_size == 32
    
    def test_build_merkle_tree_simple(self):
        """Test building simple Merkle tree."""
        addresses = ["address1", "address2"]
        
        root_hash, proofs = build_merkle_tree(addresses)
        
        assert isinstance(root_hash, bytes)
        assert len(root_hash) == 32
        assert len(proofs) == 2
        
        # Check proof structure
        for address in addresses:
            assert address in proofs
            proof_data = proofs[address]
            assert "leaf_hash" in proof_data
            assert "proof_hashes" in proof_data
            assert "leaf_index" in proof_data
            assert "tree_size" in proof_data
            assert "hash_function" in proof_data
    
    def test_build_merkle_tree_larger(self):
        """Test building larger Merkle tree."""
        addresses = [f"address{i}" for i in range(8)]
        
        root_hash, proofs = build_merkle_tree(addresses, HashFunction.SHA3_256)
        
        assert len(proofs) == 8
        assert all(proof_data["hash_function"] == "sha3_256" for proof_data in proofs.values())
        
        # Each proof in 8-leaf tree should have 3 hashes (log2(8))
        for proof_data in proofs.values():
            assert len(proof_data["proof_hashes"]) == 3
    
    def test_build_merkle_tree_empty(self):
        """Test building Merkle tree with empty address list."""
        with pytest.raises(ValueError, match="Cannot build Merkle tree from empty"):
            build_merkle_tree([])
    
    def test_verify_allowlist_proof_utility(self):
        """Test quick allowlist proof verification utility."""
        # Build a simple tree
        addresses = ["test_address", "other_address"]
        root_hash, proofs = build_merkle_tree(addresses)
        
        # Test valid proof
        proof_data = proofs["test_address"]
        is_valid = verify_allowlist_proof("test_address", proof_data, root_hash.hex())
        assert is_valid is True
        
        # Test wrong address
        is_valid = verify_allowlist_proof("wrong_address", proof_data, root_hash.hex())
        assert is_valid is False
        
        # Test invalid proof data
        invalid_proof = {"invalid": "data"}
        is_valid = verify_allowlist_proof("test_address", invalid_proof, root_hash.hex())
        assert is_valid is False
    
    def test_end_to_end_verification(self):
        """Test end-to-end Merkle proof verification."""
        # Build allowlist
        addresses = ["alice", "bob", "charlie", "dave"]
        root_hash, proofs = build_merkle_tree(addresses)
        
        # Verify each address
        for address in addresses:
            proof_data = proofs[address]
            is_valid = verify_allowlist_proof(address, proof_data, root_hash.hex())
            assert is_valid is True
            
        # Verify non-allowlisted address fails
        eve_proof = proofs["alice"]  # Use Alice's proof for Eve
        is_valid = verify_allowlist_proof("eve", eve_proof, root_hash.hex())
        assert is_valid is False


class TestIntegration:
    """Integration tests with ValidationEngine."""
    
    def test_rule_integration(self):
        """Test allowlist rule integration with ValidationEngine."""
        from validator.core import ValidationEngine
        
        engine = ValidationEngine()
        
        # Check that AllowlistRule is registered by default
        rule_names = [rule.name for rule in engine.rules]
        assert "allowlist" in rule_names
        
        # Get the allowlist rule
        allowlist_rule = engine.rule_registry["allowlist"]
        assert isinstance(allowlist_rule, AllowlistRule)
        
        # Test statistics access
        stats = allowlist_rule.get_statistics()
        assert isinstance(stats, dict)
        assert "validations_performed" in stats


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_invalid_hash_function(self):
        """Test handling of invalid hash functions."""
        rule = AllowlistRule()
        
        with pytest.raises(ValueError, match="Unsupported hash function"):
            rule._hash_data(b"test", "invalid_function")
    
    def test_merkle_proof_with_mismatched_hashes(self):
        """Test Merkle proof verification with mismatched hash lengths."""
        rule = AllowlistRule()
        
        # Create proof with different hash lengths
        leaf_hash = b'\\x01' * 32
        invalid_sibling = b'\\x02' * 16  # Wrong length
        
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            proof_hashes=[invalid_sibling],
            leaf_index=0,
            tree_size=2
        )
        
        root = b'\\x03' * 32
        result = rule._verify_merkle_proof(proof, root)
        assert result is False
    
    def test_recipient_verification_exception_handling(self):
        """Test handling of exceptions during recipient verification."""
        rule = AllowlistRule()
        
        context = ValidationContext(
            psbt_data={},
            asset_id=b'\\x01' * 32,
            operation=OperationType.MINT,
            allowlist_root=b'\\x02' * 32
        )
        
        # Mock _extract_recipients to raise exception
        with patch.object(rule, '_extract_recipients', side_effect=Exception("Extract error")):
            result = rule.validate(context)
            
            assert result is False
            assert context.has_errors()
            assert "Extract error" in context.validation_errors[0]