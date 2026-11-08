"""One-shot ML-KEM + HKDF + AES-256-GCM transport for secure submission of signed transactions to a validator node."""
import hmac
from common.pqc import (
    kem_encapsulate, derive_aes_key, aes_gcm_encrypt, aes_gcm_decrypt, sha256,
)
from .transaction import Transaction, canonical_json

KEM_NAME = "ML-KEM-768"
AAD_PREFIX = b"PQBlockchain-secure-submission|"

def _transaction_metadata(tx):
    return {
        "txid": tx.txid,
        "sender": tx.sender,
        "recipient": tx.recipient,
        "transaction_nonce": tx.nonce,
    }

def _aad_for_submission(kem_ciphertext, metadata):
    return AAD_PREFIX + sha256(kem_ciphertext) + b"|" + canonical_json(metadata)

def encrypt_submission(validator_public_key, payload, expected_fingerprint):
    """Reject an untrusted/substituted validator KEM key before encapsulation."""
    actual = sha256(validator_public_key).hex()
    if not hmac.compare_digest(actual, expected_fingerprint):
        raise ValueError("Validator ML-KEM public-key fingerprint mismatch")

    # Retrieve transaction metadata from the payload for AAD binding
    tx = Transaction.from_bytes(payload)
    metadata = _transaction_metadata(tx)

    # Encrypt the payload with a one-shot ML-KEM + HKDF + AES-256-GCM envelop
    kem_ct, shared_secret = kem_encapsulate(validator_public_key, KEM_NAME)
    key = derive_aes_key(shared_secret, kem_ct, context=AAD_PREFIX)
    nonce, ciphertext = aes_gcm_encrypt(
        key, payload, aad=_aad_for_submission(kem_ct, metadata)
    )
    return {
        "kem_ciphertext": kem_ct,
        "nonce": nonce,
        "ciphertext": ciphertext,
        **metadata,
    }

def decrypt_submission(validator_kem, envelope):
    kem_ct = envelope["kem_ciphertext"]
    metadata = {
        name: envelope[name]
        for name in ("txid", "sender", "recipient", "transaction_nonce")
    }
    shared_secret = validator_kem.decapsulate(kem_ct)
    key = derive_aes_key(shared_secret, kem_ct, context=AAD_PREFIX)
    plaintext = aes_gcm_decrypt(
        key,
        envelope["nonce"],
        envelope["ciphertext"],
        aad=_aad_for_submission(kem_ct, metadata),
    )
    if _transaction_metadata(Transaction.from_bytes(plaintext)) != metadata:
        raise ValueError("Envelope transaction metadata does not match decrypted payload")
    return plaintext
