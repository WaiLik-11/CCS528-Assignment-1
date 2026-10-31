"""PQC and symmetric-crypto wrappers shared by Tasks 2-5.

ML-DSA-65 (FIPS 204) signatures, ML-KEM-768 (FIPS 203) key encapsulation,
HKDF-SHA256 key derivation and AES-256-GCM authenticated encryption.
Private keys are never stored here; callers own them.
"""

import os

import oqs
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SIG_ALG = "ML-DSA-65"
KEM_ALG = "ML-KEM-768"
NONCE_SIZE = 12

# ML-DSA
def keygen_sig(algo: str = SIG_ALG) -> tuple[bytes, bytes]:
    """Return (public_key, secret_key)."""
    with oqs.Signature(algo) as s:
        pk = s.generate_keypair()
        return pk, s.export_secret_key()

def sign(sk: bytes, msg: bytes, algo: str = SIG_ALG) -> bytes:
    with oqs.Signature(algo, secret_key=sk) as s:
        return s.sign(msg)

def verify(pk: bytes, msg: bytes, sig: bytes, algo: str = SIG_ALG) -> bool:
    """True only for a valid signature; never raises on malformed input."""
    try:
        with oqs.Signature(algo) as s:
            return bool(s.verify(msg, sig, pk))
    except Exception:
        return False

# ML-KEM
def keygen_kem(algo: str = KEM_ALG) -> tuple[bytes, bytes]:
    """Return (public_key, secret_key)."""
    with oqs.KeyEncapsulation(algo) as k:
        pk = k.generate_keypair()
        return pk, k.export_secret_key()

def encaps(pk: bytes, algo: str = KEM_ALG) -> tuple[bytes, bytes]:
    """Return (ciphertext, shared_secret)."""
    with oqs.KeyEncapsulation(algo) as k:
        return k.encap_secret(pk)

def decaps(sk: bytes, ct: bytes, algo: str = KEM_ALG) -> bytes:
    """Return the shared secret. A tampered ct yields a different secret (implicit rejection)."""
    with oqs.KeyEncapsulation(algo, secret_key=sk) as k:
        return k.decap_secret(ct)

# HKDF + AES-256-GCM
def derive_key(shared_secret: bytes, context: bytes = b"") -> bytes:
    """Derive a 32-byte AES key; context binds the key to its use."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context
    ).derive(shared_secret)

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return nonce || ciphertext+tag with a fresh random nonce."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes | None:
    """Return plaintext, or None if authentication fails."""
    try:
        return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
    except (InvalidTag, ValueError):
        return None