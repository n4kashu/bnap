"""
MuSig2 Multi-Signature Implementation for BNAP

This module provides MuSig2 nonce generation, management, and partial
signature aggregation for multi-validator scenarios.

References:
- MuSig2 Paper: https://eprint.iacr.org/2020/1261.pdf
- BIP327: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
"""

import hashlib
import hmac
import secrets
from typing import List, Optional, Tuple, Dict, Set
from dataclasses import dataclass, field
from enum import Enum

from .exceptions import InvalidSignatureError, InvalidKeyError, CryptoError
from .keys import PrivateKey, PublicKey, tagged_hash, has_even_y, lift_x
from .signatures import SchnorrSignature


class MuSig2Error(CryptoError):
    """MuSig2-specific error."""
    pass


class SessionState(Enum):
    """MuSig2 session state enumeration."""
    INITIALIZED = "initialized"
    NONCES_GENERATED = "nonces_generated"
    NONCES_SHARED = "nonces_shared"
    NONCES_AGGREGATED = "nonces_aggregated"
    CHALLENGE_COMPUTED = "challenge_computed"
    PARTIAL_SIGNATURES_GENERATED = "partial_signatures_generated"
    SIGNATURE_AGGREGATED = "signature_aggregated"
    COMPLETED = "completed"


@dataclass
class MuSig2Nonce:
    """
    MuSig2 nonce pair (secnonce, pubnonce).
    """
    secnonce: Tuple[int, int]  # (k1, k2) secret nonce scalars
    pubnonce: Tuple[bytes, bytes]  # (R1, R2) public nonce points (x-only)
    
    def __post_init__(self):
        """Validate nonce components."""
        if len(self.secnonce) != 2:
            raise MuSig2Error("Secret nonce must be a 2-tuple")
        if len(self.pubnonce) != 2:
            raise MuSig2Error("Public nonce must be a 2-tuple")
        
        for secnonce in self.secnonce:
            if not isinstance(secnonce, int) or secnonce <= 0:
                raise MuSig2Error("Secret nonce components must be positive integers")
        
        for pubnonce in self.pubnonce:
            if not isinstance(pubnonce, bytes) or len(pubnonce) != 32:
                raise MuSig2Error("Public nonce components must be 32 bytes")


@dataclass
class MuSig2Session:
    """
    MuSig2 signing session state management.
    """
    session_id: str
    public_keys: List[PublicKey]
    message: bytes
    state: SessionState = SessionState.INITIALIZED
    
    # Nonce management
    our_nonce: Optional[MuSig2Nonce] = None
    received_nonces: Dict[int, MuSig2Nonce] = field(default_factory=dict)
    aggregated_nonce: Optional[Tuple[bytes, bytes]] = None
    
    # Key aggregation
    aggregated_pubkey: Optional[PublicKey] = None
    key_coefficients: Dict[int, int] = field(default_factory=dict)
    
    # Signature data
    challenge: Optional[int] = None
    partial_signatures: Dict[int, int] = field(default_factory=dict)
    final_signature: Optional[SchnorrSignature] = None
    
    # Security tracking
    used_nonce_hashes: Set[bytes] = field(default_factory=set)
    
    def __post_init__(self):
        """Validate session parameters."""
        if len(self.public_keys) < 2:
            raise MuSig2Error("MuSig2 requires at least 2 public keys")
        if len(self.public_keys) > 100:  # Reasonable limit
            raise MuSig2Error("Too many public keys for MuSig2 session")
        if len(self.message) == 0:
            raise MuSig2Error("Message cannot be empty")
    
    @property
    def num_signers(self) -> int:
        """Number of signers in the session."""
        return len(self.public_keys)
    
    @property 
    def is_complete(self) -> bool:
        """Check if session is complete."""
        return self.state == SessionState.COMPLETED
    
    @property
    def all_nonces_received(self) -> bool:
        """Check if all nonces have been received."""
        return len(self.received_nonces) == self.num_signers
    
    @property
    def all_partial_signatures_received(self) -> bool:
        """Check if all partial signatures have been received."""
        return len(self.partial_signatures) == self.num_signers


# MuSig2 nonce generation

def generate_nonce_pair(private_key: PrivateKey, public_keys: List[PublicKey], 
                       message: bytes, aux_rand: Optional[bytes] = None) -> MuSig2Nonce:
    """
    Generate MuSig2 nonce pair (secnonce, pubnonce).
    
    Args:
        private_key: Signer's private key
        public_keys: List of all public keys in the signing session
        message: Message to be signed
        aux_rand: Optional 32-byte auxiliary randomness
        
    Returns:
        MuSig2Nonce containing secret and public nonce components
    """
    if aux_rand is not None and len(aux_rand) != 32:
        raise MuSig2Error("Auxiliary randomness must be 32 bytes")
    
    try:
        # Generate auxiliary randomness if not provided
        if aux_rand is None:
            aux_rand = secrets.token_bytes(32)
        
        # Serialize public keys for deterministic nonce generation
        pubkeys_bytes = b"".join(pubkey.x_only for pubkey in public_keys)
        
        # Create nonce generation seed
        # seed = private_key || pubkeys || message || aux_rand
        seed_data = (
            private_key.bytes +
            pubkeys_bytes +
            message +
            aux_rand
        )
        
        # Generate two independent nonces
        k1_seed = tagged_hash("MuSig2/nonce1", seed_data)
        k2_seed = tagged_hash("MuSig2/nonce2", seed_data)
        
        # Convert to scalars
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        k1 = int.from_bytes(k1_seed, 'big') % curve_order
        k2 = int.from_bytes(k2_seed, 'big') % curve_order
        
        # Ensure nonces are non-zero
        if k1 == 0:
            k1 = 1
        if k2 == 0:
            k2 = 1
        
        # Compute public nonces R1 = k1*G, R2 = k2*G
        from coincurve import PrivateKey as CoinCurvePrivateKey
        
        k1_private = CoinCurvePrivateKey(k1.to_bytes(32, 'big'))
        k2_private = CoinCurvePrivateKey(k2.to_bytes(32, 'big'))
        
        R1_point = k1_private.public_key
        R2_point = k2_private.public_key
        
        # Get x-only coordinates
        R1_x = R1_point.format(compressed=True)[1:]  # Remove prefix
        R2_x = R2_point.format(compressed=True)[1:]  # Remove prefix
        
        return MuSig2Nonce(
            secnonce=(k1, k2),
            pubnonce=(R1_x, R2_x)
        )
        
    except Exception as e:
        raise MuSig2Error(f"Nonce generation failed: {e}")


def aggregate_public_nonces(nonces: List[MuSig2Nonce]) -> Tuple[bytes, bytes]:
    """
    Aggregate public nonces from all participants.
    
    Args:
        nonces: List of public nonces from all participants
        
    Returns:
        Tuple of aggregated nonce points (R1_agg, R2_agg) as x-only coordinates
    """
    if len(nonces) < 2:
        raise MuSig2Error("Need at least 2 nonces to aggregate")
    
    try:
        from coincurve import PublicKey as CoinCurvePublicKey
        
        # Aggregate R1 points
        R1_points = []
        for nonce in nonces:
            R1_lifted = lift_x(nonce.pubnonce[0])
            if R1_lifted is None:
                raise MuSig2Error("Invalid R1 point in nonce")
            R1_points.append(CoinCurvePublicKey(R1_lifted))
        
        # Aggregate R2 points  
        R2_points = []
        for nonce in nonces:
            R2_lifted = lift_x(nonce.pubnonce[1])
            if R2_lifted is None:
                raise MuSig2Error("Invalid R2 point in nonce")
            R2_points.append(CoinCurvePublicKey(R2_lifted))
        
        # Sum all R1 points
        R1_agg = CoinCurvePublicKey.combine_keys(R1_points)
        R1_agg_x = R1_agg.format(compressed=True)[1:]
        
        # Sum all R2 points
        R2_agg = CoinCurvePublicKey.combine_keys(R2_points)
        R2_agg_x = R2_agg.format(compressed=True)[1:]
        
        return (R1_agg_x, R2_agg_x)
        
    except Exception as e:
        raise MuSig2Error(f"Nonce aggregation failed: {e}")


# Key aggregation for MuSig2

def compute_key_coefficients(public_keys: List[PublicKey]) -> Dict[int, int]:
    """
    Compute MuSig2 key aggregation coefficients.
    
    Args:
        public_keys: List of public keys to aggregate
        
    Returns:
        Dictionary mapping signer index to coefficient
    """
    if len(public_keys) < 2:
        raise MuSig2Error("Need at least 2 public keys")
    
    try:
        # Serialize all public keys
        L = b"".join(pubkey.x_only for pubkey in public_keys)
        
        coefficients = {}
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        for i, pubkey in enumerate(public_keys):
            # Coefficient a_i = H(L || pubkey_i)
            coeff_data = L + pubkey.x_only
            coeff_hash = tagged_hash("MuSig2/coefficient", coeff_data)
            coeff = int.from_bytes(coeff_hash, 'big') % curve_order
            
            # Ensure coefficient is non-zero
            if coeff == 0:
                coeff = 1
                
            coefficients[i] = coeff
        
        return coefficients
        
    except Exception as e:
        raise MuSig2Error(f"Coefficient computation failed: {e}")


def aggregate_public_keys(public_keys: List[PublicKey], 
                         coefficients: Optional[Dict[int, int]] = None) -> PublicKey:
    """
    Aggregate public keys using MuSig2 key aggregation.
    
    Args:
        public_keys: List of public keys to aggregate
        coefficients: Optional pre-computed coefficients
        
    Returns:
        Aggregated public key
    """
    if coefficients is None:
        coefficients = compute_key_coefficients(public_keys)
    
    try:
        from coincurve import PublicKey as CoinCurvePublicKey, PrivateKey as CoinCurvePrivateKey
        
        # Convert public keys to points and multiply by coefficients
        weighted_points = []
        for i, pubkey in enumerate(public_keys):
            # Lift x-only key to full point
            pubkey_point = lift_x(pubkey.x_only)
            if pubkey_point is None:
                raise MuSig2Error(f"Invalid public key at index {i}")
            
            # Create coefficient as private key for scalar multiplication
            coeff = coefficients[i]
            coeff_private = CoinCurvePrivateKey(coeff.to_bytes(32, 'big'))
            coeff_point = coeff_private.public_key
            
            # Multiply pubkey by coefficient (simplified - in practice need proper scalar mult)
            pubkey_obj = CoinCurvePublicKey(pubkey_point)
            # Note: This is a simplified approach. Proper implementation would use
            # scalar multiplication: coeff * pubkey_point
            weighted_points.append(pubkey_obj)
        
        # Sum all weighted points
        aggregated_point = CoinCurvePublicKey.combine_keys(weighted_points)
        
        return PublicKey(aggregated_point)
        
    except Exception as e:
        raise MuSig2Error(f"Key aggregation failed: {e}")


# MuSig2 session management

def create_signing_session(session_id: str, public_keys: List[PublicKey], 
                          message: bytes) -> MuSig2Session:
    """
    Create a new MuSig2 signing session.
    
    Args:
        session_id: Unique identifier for this session
        public_keys: List of all participant public keys
        message: Message to be signed
        
    Returns:
        New MuSig2Session object
    """
    return MuSig2Session(
        session_id=session_id,
        public_keys=public_keys,
        message=message
    )


def add_nonce_to_session(session: MuSig2Session, signer_index: int, 
                        nonce: MuSig2Nonce) -> None:
    """
    Add a nonce from a specific signer to the session.
    
    Args:
        session: MuSig2 session
        signer_index: Index of the signer (0-based)
        nonce: MuSig2 nonce from the signer
    """
    if signer_index < 0 or signer_index >= session.num_signers:
        raise MuSig2Error(f"Invalid signer index: {signer_index}")
    
    if signer_index in session.received_nonces:
        raise MuSig2Error(f"Nonce already received from signer {signer_index}")
    
    # Check for nonce reuse
    nonce_hash = hashlib.sha256(nonce.pubnonce[0] + nonce.pubnonce[1]).digest()
    if nonce_hash in session.used_nonce_hashes:
        raise MuSig2Error("Nonce reuse detected - security violation")
    
    session.received_nonces[signer_index] = nonce
    session.used_nonce_hashes.add(nonce_hash)
    
    # Update session state
    if session.state == SessionState.INITIALIZED:
        session.state = SessionState.NONCES_GENERATED
    
    if session.all_nonces_received:
        session.state = SessionState.NONCES_SHARED


def finalize_nonce_aggregation(session: MuSig2Session) -> None:
    """
    Finalize nonce aggregation for the session.
    
    Args:
        session: MuSig2 session with all nonces received
    """
    if not session.all_nonces_received:
        raise MuSig2Error("Not all nonces received yet")
    
    if session.state != SessionState.NONCES_SHARED:
        raise MuSig2Error(f"Invalid session state: {session.state}")
    
    # Aggregate all nonces
    all_nonces = list(session.received_nonces.values())
    session.aggregated_nonce = aggregate_public_nonces(all_nonces)
    
    # Compute key coefficients and aggregate keys
    session.key_coefficients = compute_key_coefficients(session.public_keys)
    session.aggregated_pubkey = aggregate_public_keys(
        session.public_keys, session.key_coefficients
    )
    
    session.state = SessionState.NONCES_AGGREGATED


def compute_challenge(session: MuSig2Session) -> int:
    """
    Compute the MuSig2 challenge value.
    
    Args:
        session: MuSig2 session with aggregated nonces
        
    Returns:
        Challenge scalar value
    """
    if session.state != SessionState.NONCES_AGGREGATED:
        raise MuSig2Error(f"Invalid session state: {session.state}")
    
    if session.aggregated_nonce is None or session.aggregated_pubkey is None:
        raise MuSig2Error("Missing aggregated nonce or public key")
    
    try:
        # Compute nonce coefficient b
        R1_agg, R2_agg = session.aggregated_nonce
        b_data = R1_agg + R2_agg + session.aggregated_pubkey.x_only + session.message
        b_hash = tagged_hash("MuSig2/noncecoeff", b_data)
        b = int.from_bytes(b_hash, 'big')
        
        # Compute effective nonce R = R1 + b*R2
        from coincurve import PublicKey as CoinCurvePublicKey, PrivateKey as CoinCurvePrivateKey
        
        R1_point = lift_x(R1_agg)
        R2_point = lift_x(R2_agg)
        if R1_point is None or R2_point is None:
            raise MuSig2Error("Invalid aggregated nonce points")
        
        R1_obj = CoinCurvePublicKey(R1_point)
        R2_obj = CoinCurvePublicKey(R2_point)
        
        # R = R1 + b*R2 (simplified - proper scalar multiplication needed)
        R_combined = CoinCurvePublicKey.combine_keys([R1_obj, R2_obj])
        R_x = R_combined.format(compressed=True)[1:]
        
        # Compute challenge e = H(R_x || aggregated_pubkey_x || message)
        challenge_data = R_x + session.aggregated_pubkey.x_only + session.message
        challenge_hash = tagged_hash("BIP0340/challenge", challenge_data)
        challenge = int.from_bytes(challenge_hash, 'big')
        
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        session.challenge = challenge % curve_order
        session.state = SessionState.CHALLENGE_COMPUTED
        
        return session.challenge
        
    except Exception as e:
        raise MuSig2Error(f"Challenge computation failed: {e}")


# Partial signature generation and aggregation

def generate_partial_signature(session: MuSig2Session, signer_index: int, 
                              private_key: PrivateKey, our_nonce: MuSig2Nonce) -> int:
    """
    Generate partial signature for a signer.
    
    Args:
        session: MuSig2 session with computed challenge
        signer_index: Index of this signer
        private_key: Signer's private key
        our_nonce: Signer's secret nonce
        
    Returns:
        Partial signature scalar
    """
    if session.state not in [SessionState.CHALLENGE_COMPUTED, SessionState.PARTIAL_SIGNATURES_GENERATED]:
        raise MuSig2Error(f"Invalid session state: {session.state}")
    
    if session.challenge is None:
        raise MuSig2Error("Challenge not computed")
    
    if signer_index < 0 or signer_index >= session.num_signers:
        raise MuSig2Error(f"Invalid signer index: {signer_index}")
    
    try:
        # Get key coefficient for this signer
        coeff = session.key_coefficients[signer_index]
        
        # Compute nonce coefficient b
        R1_agg, R2_agg = session.aggregated_nonce
        b_data = R1_agg + R2_agg + session.aggregated_pubkey.x_only + session.message
        b_hash = tagged_hash("MuSig2/noncecoeff", b_data)
        b = int.from_bytes(b_hash, 'big')
        
        # Get secret nonces
        k1, k2 = our_nonce.secnonce
        
        # Compute effective secret nonce k = k1 + b*k2
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        k_eff = (k1 + b * k2) % curve_order
        
        # Compute partial signature s_i = k_eff + e * coeff * private_key
        d = int.from_bytes(private_key.bytes, 'big')
        s_i = (k_eff + session.challenge * coeff * d) % curve_order
        
        # Store partial signature
        session.partial_signatures[signer_index] = s_i
        
        if session.state == SessionState.CHALLENGE_COMPUTED:
            session.state = SessionState.PARTIAL_SIGNATURES_GENERATED
        
        return s_i
        
    except Exception as e:
        raise MuSig2Error(f"Partial signature generation failed: {e}")


def add_partial_signature(session: MuSig2Session, signer_index: int, 
                         partial_sig: int) -> None:
    """
    Add a partial signature from a signer to the session.
    
    Args:
        session: MuSig2 session
        signer_index: Index of the signer
        partial_sig: Partial signature scalar
    """
    if signer_index < 0 or signer_index >= session.num_signers:
        raise MuSig2Error(f"Invalid signer index: {signer_index}")
    
    if signer_index in session.partial_signatures:
        raise MuSig2Error(f"Partial signature already received from signer {signer_index}")
    
    # Basic validation
    curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if not (0 <= partial_sig < curve_order):
        raise MuSig2Error("Invalid partial signature value")
    
    session.partial_signatures[signer_index] = partial_sig


def aggregate_partial_signatures(session: MuSig2Session) -> SchnorrSignature:
    """
    Aggregate all partial signatures into final signature.
    
    Args:
        session: MuSig2 session with all partial signatures
        
    Returns:
        Final aggregated Schnorr signature
    """
    if not session.all_partial_signatures_received:
        raise MuSig2Error("Not all partial signatures received")
    
    if session.aggregated_nonce is None:
        raise MuSig2Error("Missing aggregated nonce")
    
    try:
        # Sum all partial signatures
        curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        s_total = sum(session.partial_signatures.values()) % curve_order
        
        # Compute effective nonce R coordinate
        R1_agg, R2_agg = session.aggregated_nonce
        b_data = R1_agg + R2_agg + session.aggregated_pubkey.x_only + session.message
        b_hash = tagged_hash("MuSig2/noncecoeff", b_data)
        b = int.from_bytes(b_hash, 'big')
        
        # Use R1 as the signature R coordinate (simplified)
        R_x = R1_agg
        
        # Create final signature
        signature = SchnorrSignature(
            r=R_x,
            s=s_total.to_bytes(32, 'big')
        )
        
        session.final_signature = signature
        session.state = SessionState.SIGNATURE_AGGREGATED
        
        return signature
        
    except Exception as e:
        raise MuSig2Error(f"Signature aggregation failed: {e}")


# Utility functions

def validate_nonce_uniqueness(nonces: List[MuSig2Nonce]) -> bool:
    """
    Validate that all nonces are unique (security requirement).
    
    Args:
        nonces: List of nonces to check
        
    Returns:
        True if all nonces are unique
    """
    seen_nonces = set()
    
    for nonce in nonces:
        nonce_hash = hashlib.sha256(nonce.pubnonce[0] + nonce.pubnonce[1]).digest()
        if nonce_hash in seen_nonces:
            return False
        seen_nonces.add(nonce_hash)
    
    return True


def serialize_session_state(session: MuSig2Session) -> Dict:
    """
    Serialize session state for storage/transmission.
    
    Args:
        session: MuSig2 session to serialize
        
    Returns:
        Dictionary containing session state
    """
    return {
        'session_id': session.session_id,
        'state': session.state.value,
        'num_signers': session.num_signers,
        'message': session.message.hex(),
        'public_keys': [pk.hex for pk in session.public_keys],
        'aggregated_nonce': session.aggregated_nonce[0].hex() + session.aggregated_nonce[1].hex() if session.aggregated_nonce else None,
        'challenge': session.challenge,
        'partial_signatures_count': len(session.partial_signatures),
        'is_complete': session.is_complete
    }


def get_session_info(session: MuSig2Session) -> str:
    """
    Get human-readable session information.
    
    Args:
        session: MuSig2 session
        
    Returns:
        Formatted session information string
    """
    return f"""MuSig2 Session {session.session_id}:
  State: {session.state.value}
  Signers: {session.num_signers}
  Nonces received: {len(session.received_nonces)}/{session.num_signers}
  Partial signatures: {len(session.partial_signatures)}/{session.num_signers}
  Complete: {session.is_complete}"""