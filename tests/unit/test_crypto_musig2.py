"""
Tests for Crypto MuSig2 Module

Tests MuSig2 nonce generation, session management, and partial signature aggregation
for multi-party signing scenarios.
"""

import pytest
import hashlib
import secrets
from crypto.musig2 import (
    MuSig2Nonce,
    MuSig2Session,
    MuSig2Error,
    SessionState,
    generate_nonce_pair,
    aggregate_public_nonces,
    compute_key_coefficients,
    aggregate_public_keys,
    create_signing_session,
    add_nonce_to_session,
    finalize_nonce_aggregation,
    compute_challenge,
    generate_partial_signature,
    add_partial_signature,
    aggregate_partial_signatures,
    validate_nonce_uniqueness,
    serialize_session_state,
    get_session_info,
)
from crypto.keys import PrivateKey, PublicKey
from crypto.signatures import SchnorrSignature


class TestMuSig2Nonce:
    """Test MuSig2 nonce data structure."""
    
    def test_nonce_creation(self):
        """Test basic MuSig2 nonce creation."""
        secnonce = (12345, 67890)
        pubnonce = (b'\x01' * 32, b'\x02' * 32)
        
        nonce = MuSig2Nonce(secnonce=secnonce, pubnonce=pubnonce)
        
        assert nonce.secnonce == secnonce
        assert nonce.pubnonce == pubnonce
    
    def test_nonce_validation(self):
        """Test MuSig2 nonce validation."""
        # Valid nonce
        valid_nonce = MuSig2Nonce(
            secnonce=(100, 200),
            pubnonce=(b'\x01' * 32, b'\x02' * 32)
        )
        assert valid_nonce.secnonce == (100, 200)
        
        # Invalid secnonce length
        with pytest.raises(MuSig2Error, match="Secret nonce must be a 2-tuple"):
            MuSig2Nonce(secnonce=(100,), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        
        # Invalid secnonce values
        with pytest.raises(MuSig2Error, match="Secret nonce components must be positive integers"):
            MuSig2Nonce(secnonce=(0, 100), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        
        # Invalid pubnonce length
        with pytest.raises(MuSig2Error, match="Public nonce must be a 2-tuple"):
            MuSig2Nonce(secnonce=(100, 200), pubnonce=(b'\x01' * 32,))
        
        # Invalid pubnonce component length
        with pytest.raises(MuSig2Error, match="Public nonce components must be 32 bytes"):
            MuSig2Nonce(secnonce=(100, 200), pubnonce=(b'\x01' * 31, b'\x02' * 32))


class TestMuSig2Session:
    """Test MuSig2 session management."""
    
    def test_session_creation(self):
        """Test basic session creation."""
        private_keys = [PrivateKey() for _ in range(3)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"test message"
        
        session = MuSig2Session(
            session_id="test_session",
            public_keys=public_keys,
            message=message
        )
        
        assert session.session_id == "test_session"
        assert len(session.public_keys) == 3
        assert session.message == message
        assert session.state == SessionState.INITIALIZED
        assert session.num_signers == 3
        assert not session.is_complete
        assert not session.all_nonces_received
        assert not session.all_partial_signatures_received
    
    def test_session_validation(self):
        """Test session validation."""
        # Too few public keys
        with pytest.raises(MuSig2Error, match="MuSig2 requires at least 2 public keys"):
            MuSig2Session(
                session_id="test",
                public_keys=[PrivateKey().public_key()],
                message=b"test"
            )
        
        # Too many public keys
        many_keys = [PrivateKey().public_key() for _ in range(101)]
        with pytest.raises(MuSig2Error, match="Too many public keys for MuSig2 session"):
            MuSig2Session(
                session_id="test",
                public_keys=many_keys,
                message=b"test"
            )
        
        # Empty message
        with pytest.raises(MuSig2Error, match="Message cannot be empty"):
            MuSig2Session(
                session_id="test",
                public_keys=[PrivateKey().public_key() for _ in range(2)],
                message=b""
            )
    
    def test_session_properties(self):
        """Test session property methods."""
        private_keys = [PrivateKey() for _ in range(2)]
        public_keys = [pk.public_key() for pk in private_keys]
        
        session = MuSig2Session(
            session_id="prop_test",
            public_keys=public_keys,
            message=b"test"
        )
        
        assert session.num_signers == 2
        assert not session.is_complete
        assert not session.all_nonces_received
        assert not session.all_partial_signatures_received
        
        # Add nonces to test properties
        nonce1 = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        nonce2 = MuSig2Nonce(secnonce=(3, 4), pubnonce=(b'\x03' * 32, b'\x04' * 32))
        
        session.received_nonces[0] = nonce1
        assert not session.all_nonces_received
        
        session.received_nonces[1] = nonce2
        assert session.all_nonces_received


class TestNonceGeneration:
    """Test MuSig2 nonce generation."""
    
    def test_nonce_generation_basic(self):
        """Test basic nonce generation."""
        private_key = PrivateKey()
        public_keys = [PrivateKey().public_key() for _ in range(3)]
        message = b"test message"
        
        nonce = generate_nonce_pair(private_key, public_keys, message)
        
        assert isinstance(nonce, MuSig2Nonce)
        assert len(nonce.secnonce) == 2
        assert len(nonce.pubnonce) == 2
        assert all(isinstance(k, int) and k > 0 for k in nonce.secnonce)
        assert all(isinstance(r, bytes) and len(r) == 32 for r in nonce.pubnonce)
    
    def test_nonce_generation_with_aux_rand(self):
        """Test nonce generation with auxiliary randomness."""
        private_key = PrivateKey()
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        message = b"test message"
        aux_rand = secrets.token_bytes(32)
        
        nonce = generate_nonce_pair(private_key, public_keys, message, aux_rand)
        
        assert isinstance(nonce, MuSig2Nonce)
        assert len(nonce.secnonce) == 2
        assert len(nonce.pubnonce) == 2
    
    def test_nonce_generation_deterministic(self):
        """Test that nonce generation is deterministic with same inputs."""
        private_key = PrivateKey(b'\x01' * 32)
        public_keys = [PrivateKey(b'\x02' * 32).public_key(), PrivateKey(b'\x03' * 32).public_key()]
        message = b"deterministic test"
        aux_rand = b'\x04' * 32
        
        nonce1 = generate_nonce_pair(private_key, public_keys, message, aux_rand)
        nonce2 = generate_nonce_pair(private_key, public_keys, message, aux_rand)
        
        assert nonce1.secnonce == nonce2.secnonce
        assert nonce1.pubnonce == nonce2.pubnonce
    
    def test_nonce_generation_invalid_aux_rand(self):
        """Test nonce generation with invalid auxiliary randomness."""
        private_key = PrivateKey()
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        message = b"test"
        
        with pytest.raises(MuSig2Error, match="Auxiliary randomness must be 32 bytes"):
            generate_nonce_pair(private_key, public_keys, message, b"short")
    
    def test_nonce_generation_different_inputs(self):
        """Test that different inputs produce different nonces."""
        private_key = PrivateKey()
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        
        nonce1 = generate_nonce_pair(private_key, public_keys, b"message1")
        nonce2 = generate_nonce_pair(private_key, public_keys, b"message2")
        
        assert nonce1.secnonce != nonce2.secnonce
        assert nonce1.pubnonce != nonce2.pubnonce


class TestNonceAggregation:
    """Test public nonce aggregation."""
    
    def test_aggregate_public_nonces_basic(self):
        """Test basic public nonce aggregation."""
        # Generate some nonces
        nonces = []
        for i in range(3):
            private_key = PrivateKey((i + 1).to_bytes(32, 'big'))
            public_keys = [PrivateKey().public_key() for _ in range(3)]
            message = b"test message"
            nonce = generate_nonce_pair(private_key, public_keys, message)
            nonces.append(nonce)
        
        aggregated = aggregate_public_nonces(nonces)
        
        assert isinstance(aggregated, tuple)
        assert len(aggregated) == 2
        assert all(isinstance(r, bytes) and len(r) == 32 for r in aggregated)
    
    def test_aggregate_public_nonces_insufficient(self):
        """Test aggregation with insufficient nonces."""
        nonce = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        
        with pytest.raises(MuSig2Error, match="Need at least 2 nonces to aggregate"):
            aggregate_public_nonces([nonce])
    
    def test_nonce_uniqueness_validation(self):
        """Test nonce uniqueness validation."""
        # Create unique nonces
        unique_nonces = [
            MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32)),
            MuSig2Nonce(secnonce=(3, 4), pubnonce=(b'\x03' * 32, b'\x04' * 32)),
        ]
        
        assert validate_nonce_uniqueness(unique_nonces) is True
        
        # Create duplicate nonces
        duplicate_nonces = [
            MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32)),
            MuSig2Nonce(secnonce=(3, 4), pubnonce=(b'\x01' * 32, b'\x02' * 32)),  # Same pubnonce
        ]
        
        assert validate_nonce_uniqueness(duplicate_nonces) is False


class TestKeyAggregation:
    """Test MuSig2 key aggregation."""
    
    def test_compute_key_coefficients(self):
        """Test key coefficient computation."""
        public_keys = [PrivateKey().public_key() for _ in range(3)]
        
        coefficients = compute_key_coefficients(public_keys)
        
        assert isinstance(coefficients, dict)
        assert len(coefficients) == 3
        assert all(isinstance(i, int) and isinstance(c, int) for i, c in coefficients.items())
        assert all(i in range(3) for i in coefficients.keys())
        assert all(c > 0 for c in coefficients.values())
    
    def test_compute_key_coefficients_insufficient(self):
        """Test coefficient computation with insufficient keys."""
        with pytest.raises(MuSig2Error, match="Need at least 2 public keys"):
            compute_key_coefficients([PrivateKey().public_key()])
    
    def test_compute_key_coefficients_deterministic(self):
        """Test that coefficients are deterministic."""
        public_keys = [PrivateKey(i.to_bytes(32, 'big')).public_key() for i in range(1, 4)]
        
        coeffs1 = compute_key_coefficients(public_keys)
        coeffs2 = compute_key_coefficients(public_keys)
        
        assert coeffs1 == coeffs2
    
    def test_aggregate_public_keys(self):
        """Test public key aggregation."""
        public_keys = [PrivateKey().public_key() for _ in range(3)]
        
        aggregated = aggregate_public_keys(public_keys)
        
        assert isinstance(aggregated, PublicKey)
        assert len(aggregated.x_only) == 32
    
    def test_aggregate_public_keys_with_coefficients(self):
        """Test key aggregation with pre-computed coefficients."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        coefficients = compute_key_coefficients(public_keys)
        
        aggregated = aggregate_public_keys(public_keys, coefficients)
        
        assert isinstance(aggregated, PublicKey)


class TestSessionManagement:
    """Test MuSig2 session workflow."""
    
    def test_create_signing_session(self):
        """Test signing session creation."""
        public_keys = [PrivateKey().public_key() for _ in range(3)]
        message = b"session test message"
        
        session = create_signing_session("test_session", public_keys, message)
        
        assert isinstance(session, MuSig2Session)
        assert session.session_id == "test_session"
        assert session.public_keys == public_keys
        assert session.message == message
        assert session.state == SessionState.INITIALIZED
    
    def test_add_nonce_to_session(self):
        """Test adding nonces to session."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("nonce_test", public_keys, b"test")
        
        nonce = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        
        # Add first nonce
        add_nonce_to_session(session, 0, nonce)
        
        assert 0 in session.received_nonces
        assert session.received_nonces[0] == nonce
        assert session.state == SessionState.NONCES_GENERATED
        assert not session.all_nonces_received
        
        # Add second nonce
        nonce2 = MuSig2Nonce(secnonce=(3, 4), pubnonce=(b'\x03' * 32, b'\x04' * 32))
        add_nonce_to_session(session, 1, nonce2)
        
        assert session.all_nonces_received
        assert session.state == SessionState.NONCES_SHARED
    
    def test_add_nonce_invalid_index(self):
        """Test adding nonce with invalid signer index."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("invalid_test", public_keys, b"test")
        nonce = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        
        with pytest.raises(MuSig2Error, match="Invalid signer index"):
            add_nonce_to_session(session, 2, nonce)  # Index 2 is invalid for 2 signers
    
    def test_add_duplicate_nonce(self):
        """Test adding duplicate nonce from same signer."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("dup_test", public_keys, b"test")
        nonce = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        
        add_nonce_to_session(session, 0, nonce)
        
        with pytest.raises(MuSig2Error, match="Nonce already received from signer"):
            add_nonce_to_session(session, 0, nonce)
    
    def test_nonce_reuse_detection(self):
        """Test nonce reuse detection."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("reuse_test", public_keys, b"test")
        
        # Same pubnonce (reuse)
        nonce1 = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        nonce2 = MuSig2Nonce(secnonce=(3, 4), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        
        add_nonce_to_session(session, 0, nonce1)
        
        with pytest.raises(MuSig2Error, match="Nonce reuse detected"):
            add_nonce_to_session(session, 1, nonce2)
    
    def test_finalize_nonce_aggregation(self):
        """Test nonce aggregation finalization."""
        # Create session with generated nonces
        private_keys = [PrivateKey() for _ in range(2)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"aggregation test"
        session = create_signing_session("agg_test", public_keys, message)
        
        # Generate and add nonces
        for i, private_key in enumerate(private_keys):
            nonce = generate_nonce_pair(private_key, public_keys, message)
            add_nonce_to_session(session, i, nonce)
        
        # Finalize aggregation
        finalize_nonce_aggregation(session)
        
        assert session.state == SessionState.NONCES_AGGREGATED
        assert session.aggregated_nonce is not None
        assert session.aggregated_pubkey is not None
        assert session.key_coefficients is not None
        assert len(session.key_coefficients) == 2
    
    def test_finalize_nonce_aggregation_incomplete(self):
        """Test finalizing aggregation with incomplete nonces."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("incomplete_test", public_keys, b"test")
        
        # Only add one nonce
        nonce = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        add_nonce_to_session(session, 0, nonce)
        
        with pytest.raises(MuSig2Error, match="Not all nonces received yet"):
            finalize_nonce_aggregation(session)


class TestChallengeComputation:
    """Test MuSig2 challenge computation."""
    
    def test_compute_challenge_basic(self):
        """Test basic challenge computation."""
        # Create and setup session
        private_keys = [PrivateKey() for _ in range(2)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"challenge test"
        session = create_signing_session("challenge_test", public_keys, message)
        
        # Add nonces and finalize
        for i, private_key in enumerate(private_keys):
            nonce = generate_nonce_pair(private_key, public_keys, message)
            add_nonce_to_session(session, i, nonce)
        
        finalize_nonce_aggregation(session)
        
        # Compute challenge
        challenge = compute_challenge(session)
        
        assert isinstance(challenge, int)
        assert challenge > 0
        assert session.challenge == challenge
        assert session.state == SessionState.CHALLENGE_COMPUTED
    
    def test_compute_challenge_invalid_state(self):
        """Test challenge computation with invalid state."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("invalid_challenge", public_keys, b"test")
        
        with pytest.raises(MuSig2Error, match="Invalid session state"):
            compute_challenge(session)


class TestPartialSignatures:
    """Test partial signature generation and aggregation."""
    
    def test_generate_partial_signature(self):
        """Test partial signature generation."""
        # Setup complete session
        private_keys = [PrivateKey() for _ in range(2)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"partial sig test"
        session = create_signing_session("partial_test", public_keys, message)
        
        # Generate nonces
        nonces = []
        for i, private_key in enumerate(private_keys):
            nonce = generate_nonce_pair(private_key, public_keys, message)
            nonces.append(nonce)
            add_nonce_to_session(session, i, nonce)
        
        finalize_nonce_aggregation(session)
        compute_challenge(session)
        
        # Generate partial signature
        partial_sig = generate_partial_signature(session, 0, private_keys[0], nonces[0])
        
        assert isinstance(partial_sig, int)
        assert partial_sig > 0
        assert 0 in session.partial_signatures
        assert session.partial_signatures[0] == partial_sig
        assert session.state == SessionState.PARTIAL_SIGNATURES_GENERATED
    
    def test_add_partial_signature(self):
        """Test adding partial signatures to session."""
        # Setup session through challenge computation
        private_keys = [PrivateKey() for _ in range(2)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"add partial test"
        session = create_signing_session("add_partial", public_keys, message)
        
        # Setup through challenge
        for i, private_key in enumerate(private_keys):
            nonce = generate_nonce_pair(private_key, public_keys, message)
            add_nonce_to_session(session, i, nonce)
        
        finalize_nonce_aggregation(session)
        compute_challenge(session)
        
        # Add partial signature
        add_partial_signature(session, 0, 12345)
        
        assert 0 in session.partial_signatures
        assert session.partial_signatures[0] == 12345
    
    def test_add_partial_signature_invalid(self):
        """Test adding invalid partial signature."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("invalid_partial", public_keys, b"test")
        
        # Invalid signer index
        with pytest.raises(MuSig2Error, match="Invalid signer index"):
            add_partial_signature(session, 2, 12345)
        
        # Invalid signature value (too large)
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        with pytest.raises(MuSig2Error, match="Invalid partial signature value"):
            add_partial_signature(session, 0, curve_order)
    
    def test_aggregate_partial_signatures(self):
        """Test aggregating partial signatures."""
        # Setup complete session
        private_keys = [PrivateKey() for _ in range(2)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"aggregate test"
        session = create_signing_session("aggregate_test", public_keys, message)
        
        # Generate nonces
        nonces = []
        for i, private_key in enumerate(private_keys):
            nonce = generate_nonce_pair(private_key, public_keys, message)
            nonces.append(nonce)
            add_nonce_to_session(session, i, nonce)
        
        finalize_nonce_aggregation(session)
        compute_challenge(session)
        
        # Generate all partial signatures
        for i, private_key in enumerate(private_keys):
            generate_partial_signature(session, i, private_key, nonces[i])
        
        # Aggregate signatures
        final_sig = aggregate_partial_signatures(session)
        
        assert isinstance(final_sig, SchnorrSignature)
        assert len(final_sig.r) == 32
        assert len(final_sig.s) == 32
        assert session.final_signature == final_sig
        assert session.state == SessionState.SIGNATURE_AGGREGATED
    
    def test_aggregate_partial_signatures_incomplete(self):
        """Test aggregating with incomplete partial signatures."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("incomplete_agg", public_keys, b"test")
        
        # Add only one partial signature
        add_partial_signature(session, 0, 12345)
        
        with pytest.raises(MuSig2Error, match="Not all partial signatures received"):
            aggregate_partial_signatures(session)


class TestUtilityFunctions:
    """Test MuSig2 utility functions."""
    
    def test_serialize_session_state(self):
        """Test session state serialization."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("serialize_test", public_keys, b"test message")
        
        serialized = serialize_session_state(session)
        
        assert isinstance(serialized, dict)
        assert serialized['session_id'] == "serialize_test"
        assert serialized['state'] == "initialized"
        assert serialized['num_signers'] == 2
        assert serialized['message'] == b"test message".hex()
        assert len(serialized['public_keys']) == 2
        assert serialized['is_complete'] is False
    
    def test_get_session_info(self):
        """Test session info formatting."""
        public_keys = [PrivateKey().public_key() for _ in range(3)]
        session = create_signing_session("info_test", public_keys, b"test")
        
        info = get_session_info(session)
        
        assert isinstance(info, str)
        assert "info_test" in info
        assert "initialized" in info
        assert "Signers: 3" in info
        assert "Nonces received: 0/3" in info
        assert "Complete: False" in info


class TestEndToEndWorkflow:
    """Test complete MuSig2 signing workflow."""
    
    def test_complete_2_of_2_signing(self):
        """Test complete 2-of-2 MuSig2 signing workflow."""
        # Setup participants
        private_keys = [PrivateKey() for _ in range(2)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"End-to-end MuSig2 test message"
        
        # Create session
        session = create_signing_session("e2e_test", public_keys, message)
        assert session.state == SessionState.INITIALIZED
        
        # Generate nonces for each participant
        nonces = []
        for i, private_key in enumerate(private_keys):
            nonce = generate_nonce_pair(private_key, public_keys, message)
            nonces.append(nonce)
            add_nonce_to_session(session, i, nonce)
        
        assert session.state == SessionState.NONCES_SHARED
        assert session.all_nonces_received
        
        # Finalize nonce aggregation
        finalize_nonce_aggregation(session)
        assert session.state == SessionState.NONCES_AGGREGATED
        
        # Compute challenge
        challenge = compute_challenge(session)
        assert session.state == SessionState.CHALLENGE_COMPUTED
        assert challenge > 0
        
        # Generate partial signatures
        for i, private_key in enumerate(private_keys):
            partial_sig = generate_partial_signature(session, i, private_key, nonces[i])
            assert partial_sig > 0
        
        assert session.state == SessionState.PARTIAL_SIGNATURES_GENERATED
        assert session.all_partial_signatures_received
        
        # Aggregate final signature
        final_signature = aggregate_partial_signatures(session)
        assert session.state == SessionState.SIGNATURE_AGGREGATED
        
        # Validate final signature
        assert isinstance(final_signature, SchnorrSignature)
        assert len(final_signature.r) == 32
        assert len(final_signature.s) == 32
        assert session.final_signature == final_signature
    
    def test_complete_3_of_3_signing(self):
        """Test complete 3-of-3 MuSig2 signing workflow."""
        # Setup participants
        private_keys = [PrivateKey() for _ in range(3)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"3-of-3 MuSig2 test"
        
        # Create session
        session = create_signing_session("3of3_test", public_keys, message)
        
        # Complete workflow
        nonces = []
        for i, private_key in enumerate(private_keys):
            nonce = generate_nonce_pair(private_key, public_keys, message)
            nonces.append(nonce)
            add_nonce_to_session(session, i, nonce)
        
        finalize_nonce_aggregation(session)
        compute_challenge(session)
        
        for i, private_key in enumerate(private_keys):
            generate_partial_signature(session, i, private_key, nonces[i])
        
        final_signature = aggregate_partial_signatures(session)
        
        # Validate result
        assert isinstance(final_signature, SchnorrSignature)
        assert session.num_signers == 3
        assert len(session.partial_signatures) == 3
        assert session.state == SessionState.SIGNATURE_AGGREGATED
    
    def test_deterministic_signing(self):
        """Test that MuSig2 signing is deterministic with same inputs."""
        # Use fixed keys for determinism
        private_keys = [PrivateKey(i.to_bytes(32, 'big')) for i in range(1, 3)]
        public_keys = [pk.public_key() for pk in private_keys]
        message = b"deterministic test"
        aux_rand = b'\x42' * 32
        
        # Sign twice with same parameters
        signatures = []
        for _ in range(2):
            session = create_signing_session("det_test", public_keys, message)
            
            nonces = []
            for i, private_key in enumerate(private_keys):
                nonce = generate_nonce_pair(private_key, public_keys, message, aux_rand)
                nonces.append(nonce)
                add_nonce_to_session(session, i, nonce)
            
            finalize_nonce_aggregation(session)
            compute_challenge(session)
            
            for i, private_key in enumerate(private_keys):
                generate_partial_signature(session, i, private_key, nonces[i])
            
            final_signature = aggregate_partial_signatures(session)
            signatures.append(final_signature)
        
        # Should be identical
        assert signatures[0].r == signatures[1].r
        assert signatures[0].s == signatures[1].s


class TestErrorConditions:
    """Test various error conditions and edge cases."""
    
    def test_workflow_state_violations(self):
        """Test state machine violations."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("state_test", public_keys, b"test")
        
        # Try to compute challenge before aggregation
        with pytest.raises(MuSig2Error, match="Invalid session state"):
            compute_challenge(session)
        
        # Try to generate partial signature before challenge
        nonce = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        with pytest.raises(MuSig2Error, match="Invalid session state"):
            generate_partial_signature(session, 0, PrivateKey(), nonce)
    
    def test_security_violations(self):
        """Test security violation detection."""
        public_keys = [PrivateKey().public_key() for _ in range(2)]
        session = create_signing_session("security_test", public_keys, b"test")
        
        # Nonce reuse
        same_nonce = MuSig2Nonce(secnonce=(1, 2), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        add_nonce_to_session(session, 0, same_nonce)
        
        # Try to reuse same nonce (different secnonce but same pubnonce)
        reused_nonce = MuSig2Nonce(secnonce=(3, 4), pubnonce=(b'\x01' * 32, b'\x02' * 32))
        with pytest.raises(MuSig2Error, match="Nonce reuse detected"):
            add_nonce_to_session(session, 1, reused_nonce)


class TestRandomizedTesting:
    """Test with randomized inputs for robustness."""
    
    def test_random_multisig_scenarios(self):
        """Test MuSig2 with random scenarios."""
        for num_signers in [2, 3, 5]:
            for _ in range(3):  # Test multiple rounds
                # Generate random participants
                private_keys = [PrivateKey() for _ in range(num_signers)]
                public_keys = [pk.public_key() for pk in private_keys]
                message = secrets.token_bytes(secrets.randbelow(100) + 1)
                
                # Run complete workflow
                session = create_signing_session(f"random_{num_signers}", public_keys, message)
                
                nonces = []
                for i, private_key in enumerate(private_keys):
                    nonce = generate_nonce_pair(private_key, public_keys, message)
                    nonces.append(nonce)
                    add_nonce_to_session(session, i, nonce)
                
                finalize_nonce_aggregation(session)
                compute_challenge(session)
                
                for i, private_key in enumerate(private_keys):
                    generate_partial_signature(session, i, private_key, nonces[i])
                
                final_signature = aggregate_partial_signatures(session)
                
                # Validate result
                assert isinstance(final_signature, SchnorrSignature)
                assert session.state == SessionState.SIGNATURE_AGGREGATED
                assert len(session.partial_signatures) == num_signers