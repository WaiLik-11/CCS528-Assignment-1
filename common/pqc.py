"""Cryptography primitives for PQC demo.

Algorithms:
- ML-KEM-512/768/1024: NIST FIPS 203
- ML-DSA-65: NIST FIPS 204
- HKDF-SHA-256: NIST SP 800-56C Rev. 2
- AES-256-GCM: NIST SP 800-38D
"""
import hashlib
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SIG_NAME = "ML-DSA-65"
KEM_PARAMETER_SETS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

class PQCSigner:
    """ML-DSA signing context. Private key remains inside liboqs context."""
    def __init__(self):
        self._ctx = oqs.Signature(SIG_NAME)
        self.public_key = self._ctx.generate_keypair()

    def sign(self, message: bytes) -> bytes:
        return self._ctx.sign(message)

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(SIG_NAME) as verifier:
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
        salt=b"PQBlockchain-salt",
        info=b"PQBlockchain|" + context + b"|" + sha256(kem_ciphertext),
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
