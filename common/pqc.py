"""Cryptography primitives for PQC demo.

Algorithms:
- ML-KEM-512/768/1024: NIST FIPS 203
- ML-DSA-44/65/87: NIST FIPS 204
- HKDF-SHA-256: NIST SP 800-56C Rev. 2
- AES-256-GCM: NIST SP 800-38D
"""
import hashlib
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SIG_NIST_LEVELS = {"ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5}
KEM_NIST_LEVELS = {"ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5}
SIG_PARAMETER_SETS = tuple(SIG_NIST_LEVELS)
KEM_PARAMETER_SETS = tuple(KEM_NIST_LEVELS)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def nist_level(mechanism: str) -> int:
    """Claimed NIST security level of an ML-KEM or ML-DSA parameter set."""
    return {**SIG_NIST_LEVELS, **KEM_NIST_LEVELS}[mechanism]

class PQCSigner:
    """ML-DSA signing context. Private key remains inside liboqs context."""
    def __init__(self, sig_name: str):
        self.sig_name = sig_name
        self._ctx = oqs.Signature(sig_name)
        self.public_key = self._ctx.generate_keypair()

    def sign(self, message: bytes, context: bytes = b"") -> bytes:
        if context:
            return self._ctx.sign_with_ctx_str(message, context)
        return self._ctx.sign(message)

    @property
    def private_key_size(self) -> int:
        """Size of the signing key in bytes."""
        return len(self._ctx.export_secret_key())

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes, sig_name: str, context: bytes = b"") -> bool:
        """True only for a valid signature; malformed keys or signatures return False."""
        with oqs.Signature(sig_name) as verifier:
            if context:
                return verifier.verify_with_ctx_str(message, signature, context, public_key)
            return verifier.verify(message, signature, public_key)


class PQCKEMRecipient:
    """ML-KEM recipient; retains decapsulation context/private key."""
    def __init__(self, kem_name: str):
        self.kem_name = kem_name
        self._ctx = oqs.KeyEncapsulation(kem_name)
        self.public_key = self._ctx.generate_keypair()

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return self._ctx.decap_secret(ciphertext)

    @property
    def private_key_size(self) -> int:
        """Size of the decapsulation key in bytes (the key itself is not exposed)."""
        return len(self._ctx.export_secret_key())


def kem_encapsulate(public_key: bytes, kem_name: str) -> tuple[bytes, bytes]:
    """Return (KEM ciphertext, shared secret) for the recipient's public key."""
    with oqs.KeyEncapsulation(kem_name) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret


def derive_aes_key(shared_secret: bytes, kem_ciphertext: bytes, context: bytes) -> bytes:
    """Derive a 32-byte AES-256 key bound to the KEM ciphertext."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"CCS528-key|" + context + b"|" + sha256(kem_ciphertext),
    ).derive(shared_secret)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypts plaintext with AES-256-GCM. Returns (nonce, ciphertext_and_tag)."""
    import os
    nonce = os.urandom(12)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext_and_tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
    """Raises InvalidTag if ciphertext, tag, nonce, or AAD is invalid."""
    return AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)
