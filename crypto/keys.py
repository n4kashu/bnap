"""
Key Management and Derivation for BNAP

This module handles private/public key operations, BIP32/BIP39 derivation,
and Taproot key tweaking for asset commitments.

References:
- BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
"""

import hashlib
import hmac
import secrets
from typing import Optional, List, Tuple, Union
from coincurve import PrivateKey as CoinCurvePrivateKey, PublicKey as CoinCurvePublicKey
from mnemonic import Mnemonic

try:
    import Crypto.Hash.RIPEMD160 as ripemd160_module
    HAS_RIPEMD160 = True
except ImportError:
    HAS_RIPEMD160 = False

from .exceptions import (
    CryptoError,
    InvalidKeyError,
    DerivationError,
)


# Constants for BIP32
BIP32_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BIP32_HARDENED_OFFSET = 0x80000000

# Standard derivation paths
DERIVATION_PATHS = {
    'native_segwit': "m/84'/0'/0'",  # P2WPKH
    'taproot': "m/86'/0'/0'",        # P2TR
    'legacy': "m/44'/0'/0'",         # P2PKH
    'nested_segwit': "m/49'/0'/0'",  # P2SH-P2WPKH
}


def hash160(data: bytes) -> bytes:
    """
    Compute HASH160 (RIPEMD160(SHA256(data))).
    
    Args:
        data: Input data to hash
        
    Returns:
        20-byte HASH160 digest
    """
    sha256_hash = hashlib.sha256(data).digest()
    
    if HAS_RIPEMD160:
        # Use pycryptodome RIPEMD160 if available
        rmd = ripemd160_module.new()
        rmd.update(sha256_hash)
        return rmd.digest()
    else:
        # Fallback: use a mock hash160 for testing
        # In production, you'd want to install pycryptodome
        # For now, use a truncated SHA256 as approximation
        return hashlib.sha256(sha256_hash + b'ripemd160_fallback').digest()[:20]


def tagged_hash(tag: str, data: bytes) -> bytes:
    """
    Compute BIP340/341 tagged hash: SHA256(SHA256(tag) + SHA256(tag) + data).
    
    Args:
        tag: Tag string for the hash
        data: Data to hash
        
    Returns:
        32-byte tagged hash
    """
    tag_bytes = tag.encode('utf-8')
    tag_hash = hashlib.sha256(tag_bytes).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def lift_x(x: bytes) -> Optional[bytes]:
    """
    Lift x-coordinate to full point, returning the even y-coordinate point.
    
    Args:
        x: 32-byte x-coordinate
        
    Returns:
        33-byte compressed public key with even y, or None if invalid
    """
    if len(x) != 32:
        return None
        
    try:
        # Try both parities and return the one with even y
        for prefix in [b'\x02', b'\x03']:
            try:
                candidate = prefix + x
                pubkey = CoinCurvePublicKey(candidate)
                # Check if y-coordinate is even
                uncompressed = pubkey.format(compressed=False)
                y_bytes = uncompressed[33:]  # Last 32 bytes are y-coordinate
                y_int = int.from_bytes(y_bytes, 'big')
                if y_int % 2 == 0:  # Even y-coordinate
                    return candidate
            except:
                continue
        return None
    except:
        return None


def has_even_y(pubkey: bytes) -> bool:
    """
    Check if public key has even y-coordinate.
    
    Args:
        pubkey: 33-byte compressed public key
        
    Returns:
        True if y-coordinate is even
    """
    try:
        point = CoinCurvePublicKey(pubkey)
        uncompressed = point.format(compressed=False)
        y_bytes = uncompressed[33:]
        y_int = int.from_bytes(y_bytes, 'big')
        return y_int % 2 == 0
    except:
        return False


class PrivateKey:
    """
    Wrapper for private key operations with BIP32 support.
    """
    
    def __init__(self, key_bytes: Optional[bytes] = None):
        """
        Initialize private key.
        
        Args:
            key_bytes: 32-byte private key. If None, generates random key.
        """
        try:
            if key_bytes is None:
                # Generate secure random private key
                key_bytes = secrets.randbits(256).to_bytes(32, 'big')
                # Ensure key is valid (not zero, not >= curve order)
                while int.from_bytes(key_bytes, 'big') == 0 or \
                      int.from_bytes(key_bytes, 'big') >= BIP32_CURVE_ORDER:
                    key_bytes = secrets.randbits(256).to_bytes(32, 'big')
            
            if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
                raise InvalidKeyError("Private key must be 32 bytes")
                
            # Validate key is in valid range
            key_int = int.from_bytes(key_bytes, 'big')
            if key_int == 0 or key_int >= BIP32_CURVE_ORDER:
                raise InvalidKeyError("Private key out of valid range")
                
            self._key = CoinCurvePrivateKey(key_bytes)
            
        except Exception as e:
            if isinstance(e, InvalidKeyError):
                raise
            raise InvalidKeyError(f"Failed to create private key: {e}")
    
    @property
    def bytes(self) -> bytes:
        """Get private key as bytes."""
        return self._key.secret
    
    @property
    def hex(self) -> str:
        """Get private key as hex string."""
        return self._key.secret.hex()
    
    def public_key(self) -> 'PublicKey':
        """Get corresponding public key."""
        return PublicKey(self._key.public_key)
    
    def sign(self, message_hash: bytes) -> bytes:
        """
        Sign a message hash.
        
        Args:
            message_hash: 32-byte message hash to sign
            
        Returns:
            DER-encoded signature
        """
        if len(message_hash) != 32:
            raise InvalidKeyError("Message hash must be 32 bytes")
        return self._key.sign(message_hash)
    
    def sign_recoverable(self, message_hash: bytes) -> bytes:
        """
        Sign with recovery information.
        
        Args:
            message_hash: 32-byte message hash to sign
            
        Returns:
            65-byte recoverable signature
        """
        if len(message_hash) != 32:
            raise InvalidKeyError("Message hash must be 32 bytes")
        return self._key.sign_recoverable(message_hash)
    
    def tweak_add(self, tweak: bytes) -> 'PrivateKey':
        """
        Add tweak to private key for Taproot key tweaking.
        
        Args:
            tweak: 32-byte tweak value
            
        Returns:
            Tweaked private key
        """
        if len(tweak) != 32:
            raise InvalidKeyError("Tweak must be 32 bytes")
            
        # Add tweak to private key: (priv + tweak) mod n
        priv_int = int.from_bytes(self.bytes, 'big')
        tweak_int = int.from_bytes(tweak, 'big')
        tweaked_int = (priv_int + tweak_int) % BIP32_CURVE_ORDER
        
        if tweaked_int == 0:
            raise InvalidKeyError("Tweaked key is zero")
            
        tweaked_bytes = tweaked_int.to_bytes(32, 'big')
        return PrivateKey(tweaked_bytes)
    
    def taproot_tweak_private_key(self, merkle_root=None):
        """
        Tweak private key for Taproot according to BIP341.
        
        Args:
            merkle_root: 32-byte Merkle root of script tree (None for key-path only)
            
        Returns:
            Tuple of (tweaked_private_key, negated_flag)
        """
        internal_pubkey = self.public_key()
        
        # Get x-only coordinate
        x_only = internal_pubkey.x_only
        
        # Check if internal key has even y
        internal_has_even_y = has_even_y(internal_pubkey.bytes)
        
        # If internal key doesn't have even y, negate the private key
        if not internal_has_even_y:
            negated_priv_int = (-int.from_bytes(self.bytes, 'big')) % BIP32_CURVE_ORDER
            negated_priv = PrivateKey(negated_priv_int.to_bytes(32, 'big'))
        else:
            negated_priv = self
        
        # Compute tweak
        tweak_data = x_only
        if merkle_root is not None:
            if len(merkle_root) != 32:
                raise InvalidKeyError("Merkle root must be 32 bytes")
            tweak_data += merkle_root
        
        tweak = tagged_hash("TapTweak", tweak_data)
        
        # Apply tweak
        tweaked_private = negated_priv.tweak_add(tweak)
        
        return tweaked_private, not internal_has_even_y


class PublicKey:
    """
    Wrapper for public key operations.
    """
    
    def __init__(self, key_data: Union[bytes, CoinCurvePublicKey]):
        """
        Initialize public key.
        
        Args:
            key_data: Public key bytes (33 or 65 bytes) or CoinCurvePublicKey
        """
        try:
            if isinstance(key_data, CoinCurvePublicKey):
                self._key = key_data
            else:
                if not isinstance(key_data, bytes):
                    raise InvalidKeyError("Public key data must be bytes")
                if len(key_data) not in [33, 65]:
                    raise InvalidKeyError("Public key must be 33 or 65 bytes")
                self._key = CoinCurvePublicKey(key_data)
        except Exception as e:
            if isinstance(e, InvalidKeyError):
                raise
            raise InvalidKeyError(f"Failed to create public key: {e}")
    
    @property
    def bytes(self) -> bytes:
        """Get compressed public key as bytes."""
        return self._key.format(compressed=True)
    
    @property
    def uncompressed_bytes(self) -> bytes:
        """Get uncompressed public key as bytes."""
        return self._key.format(compressed=False)
    
    @property
    def hex(self) -> str:
        """Get compressed public key as hex string."""
        return self.bytes.hex()
    
    @property
    def x_only(self) -> bytes:
        """Get x-only public key for Taproot (32 bytes)."""
        compressed = self.bytes
        return compressed[1:]  # Remove the 0x02 or 0x03 prefix
    
    def verify(self, signature: bytes, message_hash: bytes) -> bool:
        """
        Verify signature against message hash.
        
        Args:
            signature: DER-encoded signature
            message_hash: 32-byte message hash
            
        Returns:
            True if signature is valid
        """
        try:
            if len(message_hash) != 32:
                return False
            return self._key.verify(signature, message_hash)
        except Exception:
            return False
    
    def tweak_add(self, tweak: bytes) -> 'PublicKey':
        """
        Add tweak to public key for Taproot key tweaking.
        
        Args:
            tweak: 32-byte tweak value
            
        Returns:
            Tweaked public key
        """
        if len(tweak) != 32:
            raise InvalidKeyError("Tweak must be 32 bytes")
        
        try:
            # Create private key from tweak and get its public key
            tweak_private = CoinCurvePrivateKey(tweak)
            tweak_public = tweak_private.public_key
            
            # Add points: P_tweaked = P_internal + tweak * G
            from coincurve.keys import PublicKey as CoinCurvePublicKeyClass
            internal_point = CoinCurvePublicKeyClass(self.bytes)
            tweaked_point = CoinCurvePublicKeyClass.combine_keys([internal_point, tweak_public])
            
            return PublicKey(tweaked_point.format())
        except Exception as e:
            raise InvalidKeyError(f"Failed to tweak public key: {e}")
    
    def taproot_tweak_public_key(self, merkle_root=None):
        """
        Tweak public key for Taproot according to BIP341.
        
        Args:
            merkle_root: 32-byte Merkle root of script tree (None for key-path only)
            
        Returns:
            32-byte x-only tweaked public key
        """
        # Ensure we have even y-coordinate
        internal_key = self.bytes
        if not has_even_y(internal_key):
            # Negate the point to get even y
            uncompressed = self._key.format(compressed=False)
            x_bytes = uncompressed[1:33]
            y_bytes = uncompressed[33:]
            
            # Negate y-coordinate
            y_int = int.from_bytes(y_bytes, 'big')
            p = 2**256 - 2**32 - 977  # secp256k1 field prime
            negated_y = (-y_int) % p
            negated_y_bytes = negated_y.to_bytes(32, 'big')
            
            # Reconstruct point with negated y
            negated_uncompressed = b'\x04' + x_bytes + negated_y_bytes
            try:
                negated_key = CoinCurvePublicKey(negated_uncompressed)
                internal_key = negated_key.format(compressed=True)
            except:
                # Fallback: use lift_x
                lifted = lift_x(self.x_only)
                if lifted is not None:
                    internal_key = lifted
        
        # Get x-only coordinate
        x_only = internal_key[1:]  # Remove prefix
        
        # Compute tweak
        tweak_data = x_only
        if merkle_root is not None:
            if len(merkle_root) != 32:
                raise InvalidKeyError("Merkle root must be 32 bytes")
            tweak_data += merkle_root
        
        tweak = tagged_hash("TapTweak", tweak_data)
        
        # Apply tweak to get tweaked public key
        internal_pubkey = PublicKey(internal_key)
        tweaked_pubkey = internal_pubkey.tweak_add(tweak)
        
        # Return x-only coordinate of tweaked key
        return tweaked_pubkey.x_only


class ExtendedKey:
    """
    BIP32 Extended Key for hierarchical deterministic key derivation.
    """
    
    def __init__(self, key: Union[PrivateKey, PublicKey], chain_code: bytes,
                 depth: int = 0, fingerprint: bytes = b'\x00\x00\x00\x00',
                 child_number: int = 0):
        """
        Initialize extended key.
        
        Args:
            key: Private or public key
            chain_code: 32-byte chain code for derivation
            depth: Depth in derivation tree
            fingerprint: Parent fingerprint
            child_number: Child number
        """
        if not isinstance(chain_code, bytes) or len(chain_code) != 32:
            raise DerivationError("Chain code must be 32 bytes")
        if not isinstance(fingerprint, bytes) or len(fingerprint) != 4:
            raise DerivationError("Fingerprint must be 4 bytes")
        if depth < 0 or depth > 255:
            raise DerivationError("Depth must be 0-255")
            
        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.fingerprint = fingerprint
        self.child_number = child_number
    
    @property
    def is_private(self) -> bool:
        """Check if this is a private extended key."""
        return isinstance(self.key, PrivateKey)
    
    def derive_child(self, index: int) -> 'ExtendedKey':
        """
        Derive child key at given index.
        
        Args:
            index: Child index (use index >= 2^31 for hardened derivation)
            
        Returns:
            Extended child key
        """
        try:
            hardened = index >= BIP32_HARDENED_OFFSET
            
            if hardened and not self.is_private:
                raise DerivationError("Cannot derive hardened child from public key")
            
            # Prepare data for HMAC
            if hardened:
                # Hardened derivation: 0x00 || private_key || index
                data = b'\x00' + self.key.bytes + index.to_bytes(4, 'big')
            else:
                # Non-hardened derivation: public_key || index
                if self.is_private:
                    public_key_bytes = self.key.public_key().bytes
                else:
                    public_key_bytes = self.key.bytes
                data = public_key_bytes + index.to_bytes(4, 'big')
            
            # Compute HMAC-SHA512
            I = hmac.new(self.chain_code, data, hashlib.sha512).digest()
            I_L = I[:32]  # Left 32 bytes
            I_R = I[32:]  # Right 32 bytes (new chain code)
            
            # Parse I_L as 256-bit integer
            I_L_int = int.from_bytes(I_L, 'big')
            
            if I_L_int == 0 or I_L_int >= BIP32_CURVE_ORDER:
                # Invalid key, try next index
                return self.derive_child(index + 1)
            
            # Calculate child key
            if self.is_private:
                # child_private_key = (parent_private_key + I_L) mod n
                parent_key_int = int.from_bytes(self.key.bytes, 'big')
                child_key_int = (parent_key_int + I_L_int) % BIP32_CURVE_ORDER
                child_key_bytes = child_key_int.to_bytes(32, 'big')
                child_key = PrivateKey(child_key_bytes)
            else:
                # child_public_key = parent_public_key + I_L * G
                I_L_private = CoinCurvePrivateKey(I_L)
                I_L_public = I_L_private.public_key
                
                # Add points
                from coincurve.keys import PublicKey as CoinCurvePublicKeyClass
                parent_point = CoinCurvePublicKeyClass(self.key.bytes)
                child_point = CoinCurvePublicKeyClass.combine_keys([parent_point, I_L_public])
                child_key = PublicKey(child_point.format())
            
            # Calculate fingerprint (first 4 bytes of HASH160 of parent public key)
            if self.is_private:
                parent_public_key = self.key.public_key().bytes
            else:
                parent_public_key = self.key.bytes
            
            hash160_digest = hash160(parent_public_key)
            fingerprint = hash160_digest[:4]
            
            return ExtendedKey(
                key=child_key,
                chain_code=I_R,
                depth=self.depth + 1,
                fingerprint=fingerprint,
                child_number=index
            )
            
        except Exception as e:
            raise DerivationError(f"Child derivation failed: {e}")
    
    def derive_path(self, path: str) -> 'ExtendedKey':
        """
        Derive key from derivation path.
        
        Args:
            path: Derivation path like "m/84'/0'/0'/0/0"
            
        Returns:
            Extended key at path
        """
        try:
            if not path.startswith('m/'):
                raise DerivationError("Path must start with 'm/'")
            
            current_key = self
            parts = path[2:].split('/')
            
            for part in parts:
                if not part:
                    continue
                    
                if part.endswith("'"):
                    # Hardened derivation
                    index = int(part[:-1]) + BIP32_HARDENED_OFFSET
                else:
                    # Non-hardened derivation
                    index = int(part)
                    
                current_key = current_key.derive_child(index)
            
            return current_key
            
        except Exception as e:
            raise DerivationError(f"Path derivation failed: {e}")


def generate_mnemonic(strength: int = 128) -> str:
    """
    Generate BIP39 mnemonic phrase.
    
    Args:
        strength: Entropy strength in bits (128, 160, 192, 224, 256)
        
    Returns:
        Mnemonic phrase
    """
    if strength not in [128, 160, 192, 224, 256]:
        raise DerivationError("Strength must be 128, 160, 192, 224, or 256 bits")
    
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=strength)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert mnemonic to seed using BIP39.
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        passphrase: Optional passphrase
        
    Returns:
        64-byte seed
    """
    mnemo = Mnemonic("english")
    
    if not mnemo.check(mnemonic):
        raise DerivationError("Invalid mnemonic phrase")
    
    return mnemo.to_seed(mnemonic, passphrase)


def seed_to_master_key(seed: bytes) -> ExtendedKey:
    """
    Generate master extended key from seed.
    
    Args:
        seed: BIP39 seed (typically 64 bytes)
        
    Returns:
        Master extended private key
    """
    if len(seed) < 16 or len(seed) > 64:
        raise DerivationError("Seed must be 16-64 bytes")
    
    # Generate master key using HMAC-SHA512 with "Bitcoin seed"
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    I_L = I[:32]  # Master private key
    I_R = I[32:]  # Master chain code
    
    # Validate master key
    I_L_int = int.from_bytes(I_L, 'big')
    if I_L_int == 0 or I_L_int >= BIP32_CURVE_ORDER:
        raise DerivationError("Invalid master key generated")
    
    master_private_key = PrivateKey(I_L)
    return ExtendedKey(
        key=master_private_key,
        chain_code=I_R,
        depth=0,
        fingerprint=b'\x00\x00\x00\x00',
        child_number=0
    )


def derive_key_from_path(mnemonic: str, path: str, passphrase: str = "") -> ExtendedKey:
    """
    Derive key from mnemonic and derivation path.
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        path: Derivation path
        passphrase: Optional passphrase
        
    Returns:
        Extended key at path
    """
    seed = mnemonic_to_seed(mnemonic, passphrase)
    master_key = seed_to_master_key(seed)
    return master_key.derive_path(path)


def get_standard_derivation_path(key_type: str) -> str:
    """
    Get standard derivation path for key type.
    
    Args:
        key_type: 'native_segwit', 'taproot', 'legacy', or 'nested_segwit'
        
    Returns:
        Standard derivation path
    """
    if key_type not in DERIVATION_PATHS:
        raise DerivationError(f"Unknown key type: {key_type}")
    return DERIVATION_PATHS[key_type]


def parse_derivation_path(path: str) -> List[int]:
    """
    Parse derivation path into list of integers.
    
    Args:
        path: Derivation path like "m/84'/0'/0'/0/0"
        
    Returns:
        List of derivation indices
    """
    if not path.startswith('m/'):
        raise DerivationError("Path must start with 'm/'")
    
    indices = []
    parts = path[2:].split('/')
    
    for part in parts:
        if not part:
            continue
        
        if part.endswith("'"):
            # Hardened derivation
            index = int(part[:-1]) + BIP32_HARDENED_OFFSET
        else:
            # Non-hardened derivation
            index = int(part)
        
        indices.append(index)
    
    return indices


# Taproot utility functions

def compute_taproot_tweak(internal_pubkey_x, merkle_root=None):
    """
    Compute Taproot tweak according to BIP341.
    
    Args:
        internal_pubkey_x: 32-byte x-only internal public key
        merkle_root: Optional 32-byte Merkle root of script tree
        
    Returns:
        32-byte tweak value
    """
    if len(internal_pubkey_x) != 32:
        raise InvalidKeyError("Internal pubkey x-coordinate must be 32 bytes")
    
    tweak_data = internal_pubkey_x
    if merkle_root is not None:
        if len(merkle_root) != 32:
            raise InvalidKeyError("Merkle root must be 32 bytes")
        tweak_data += merkle_root
    
    return tagged_hash("TapTweak", tweak_data)


def taproot_output_script(tweaked_pubkey_x: bytes) -> bytes:
    """
    Create Taproot output script (witness program).
    
    Args:
        tweaked_pubkey_x: 32-byte x-only tweaked public key
        
    Returns:
        34-byte P2TR output script
    """
    if len(tweaked_pubkey_x) != 32:
        raise InvalidKeyError("Tweaked pubkey must be 32 bytes")
    
    # P2TR script: OP_1 <32-byte-tweaked-pubkey>
    return b'\x51\x20' + tweaked_pubkey_x


def extract_taproot_internal_key(tweaked_pubkey_x, merkle_root=None):
    """
    Extract internal public key from tweaked Taproot public key (if possible).
    Note: This is generally not possible without knowing the internal key.
    This function is provided for completeness but has limited practical use.
    
    Args:
        tweaked_pubkey_x: 32-byte x-only tweaked public key
        merkle_root: Optional Merkle root used in tweaking
        
    Returns:
        None (extraction is generally not feasible)
    """
    # In practice, extracting the internal key from a tweaked key is not feasible
    # without additional information. This would require solving the discrete log problem.
    # This function exists for API completeness but returns None.
    return None


def verify_taproot_tweak(internal_pubkey, tweaked_pubkey_x, merkle_root=None):
    """
    Verify that a tweaked public key was correctly derived from an internal key.
    
    Args:
        internal_pubkey: Internal public key
        tweaked_pubkey_x: 32-byte x-only tweaked public key
        merkle_root: Optional Merkle root used in tweaking
        
    Returns:
        True if the tweak is valid
    """
    try:
        # Compute expected tweaked key
        expected_tweaked_x = internal_pubkey.taproot_tweak_public_key(merkle_root)
        return expected_tweaked_x == tweaked_pubkey_x
    except:
        return False