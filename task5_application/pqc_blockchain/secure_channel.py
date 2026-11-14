"""One-shot ML-KEM + HKDF + AES-256-GCM transport for secure submission of signed transactions to a validator node."""
import hmac
from common.pqc import (
    PQCKEMRecipient, kem_encapsulate, derive_aes_key, aes_gcm_encrypt, aes_gcm_decrypt, sha256,
)

KEM_NAME = "ML-KEM-768"
HKDF_CONTEXT = b"submission-key"

def encrypt_submission(validator_public_key, payload, expected_fingerprint):
    """Reject an untrusted/substituted validator KEM key before encapsulation."""
    actual = sha256(validator_public_key).hex()

    # Compare the actual fingerprint with the expected one
    # Attacks stopped: MITM attacks with substituted validator keys
    if not hmac.compare_digest(actual, expected_fingerprint):
        raise ValueError("Validator ML-KEM public-key fingerprint mismatch")

    # Encrypt the payload with a one-shot ML-KEM + HKDF + AES-256-GCM envelope.
    # Every transaction field is inside the ciphertext; nothing about it is sent in the clear.
    kem_ct, shared_secret = kem_encapsulate(validator_public_key, KEM_NAME)
    key = derive_aes_key(shared_secret, kem_ct, context=HKDF_CONTEXT)
    nonce, ciphertext = aes_gcm_encrypt(key, payload)
    return {
        "kem_ciphertext": kem_ct,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }

def decrypt_submission(validator_kem: PQCKEMRecipient, envelope):
    # Attacks stopped: any change to the KEM ciphertext, AES nonce or AES ciphertext (InvalidTag)
    kem_ct = envelope["kem_ciphertext"]
    shared_secret = validator_kem.decapsulate(kem_ct)
    key = derive_aes_key(shared_secret, kem_ct, context=HKDF_CONTEXT)
    return aes_gcm_decrypt(key, envelope["nonce"], envelope["ciphertext"])
