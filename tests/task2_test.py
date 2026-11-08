import unittest
from cryptography.exceptions import InvalidTag
from common.pqc import (
    KEM_PARAMETER_SETS, PQCKEMRecipient, kem_encapsulate,
    derive_aes_key, aes_gcm_encrypt, aes_gcm_decrypt,
)
from task2_mlkem.main import SESSION_CONTEXT, flip_bit, measure

KEM = "ML-KEM-768"  # parameter set for the single-set tests

# FIPS 203 encapsulation key, decapsulation key, ciphertext sizes in bytes.
FIPS203_SIZES = {
    "ML-KEM-512": (800, 1632, 768),
    "ML-KEM-768": (1184, 2400, 1088),
    "ML-KEM-1024": (1568, 3168, 1568),
}

class MLKEMTests(unittest.TestCase):
    def test_both_parties_obtain_same_shared_secret(self):
        for name in KEM_PARAMETER_SETS:
            with self.subTest(kem=name):
                alice = PQCKEMRecipient(name)
                ciphertext, bob_secret = kem_encapsulate(alice.public_key, name)
                self.assertEqual(alice.decapsulate(ciphertext), bob_secret)
                self.assertEqual(len(bob_secret), 32)

    def test_sizes_match_fips203(self):
        for name, (pk, sk, ct) in FIPS203_SIZES.items():
            with self.subTest(kem=name):
                alice = PQCKEMRecipient(name)
                ciphertext, _ = kem_encapsulate(alice.public_key, name)
                self.assertEqual(len(alice.public_key), pk)
                self.assertEqual(alice.private_key_size, sk)
                self.assertEqual(len(ciphertext), ct)

    def test_encapsulation_is_randomized(self):
        alice = PQCKEMRecipient(KEM)
        ct1, ss1 = kem_encapsulate(alice.public_key, KEM)
        ct2, ss2 = kem_encapsulate(alice.public_key, KEM)
        self.assertNotEqual(ct1, ct2)
        self.assertNotEqual(ss1, ss2)

    def test_tampered_ciphertext_implicitly_rejected(self):
        alice = PQCKEMRecipient(KEM)
        ciphertext, bob_secret = kem_encapsulate(alice.public_key, KEM)
        tampered = flip_bit(ciphertext)
        rejected = alice.decapsulate(tampered)  # no exception: implicit rejection
        self.assertNotEqual(rejected, bob_secret)
        self.assertEqual(alice.decapsulate(tampered), rejected)

    def test_wrong_private_key_gets_different_secret(self):
        alice, eve = PQCKEMRecipient(KEM), PQCKEMRecipient(KEM)
        ciphertext, bob_secret = kem_encapsulate(alice.public_key, KEM)
        self.assertNotEqual(eve.decapsulate(ciphertext), bob_secret)

    def test_aes_gcm_session_from_shared_secret(self):
        alice = PQCKEMRecipient(KEM)
        ciphertext, bob_secret = kem_encapsulate(alice.public_key, KEM)
        bob_key = derive_aes_key(bob_secret, ciphertext, SESSION_CONTEXT)
        alice_key = derive_aes_key(alice.decapsulate(ciphertext), ciphertext, SESSION_CONTEXT)
        nonce, sealed = aes_gcm_encrypt(bob_key, b"hello Alice", b"seq=1")
        self.assertEqual(aes_gcm_decrypt(alice_key, nonce, sealed, b"seq=1"), b"hello Alice")
        with self.assertRaises(InvalidTag):
            aes_gcm_decrypt(alice_key, nonce, flip_bit(sealed), b"seq=1")
        with self.assertRaises(InvalidTag):
            aes_gcm_decrypt(alice_key, nonce, sealed, b"seq=2")

    def test_session_key_from_tampered_kem_ciphertext_fails(self):
        alice = PQCKEMRecipient(KEM)
        ciphertext, bob_secret = kem_encapsulate(alice.public_key, KEM)
        tampered = flip_bit(ciphertext)
        nonce, sealed = aes_gcm_encrypt(derive_aes_key(bob_secret, ciphertext, SESSION_CONTEXT), b"hi")
        alice_key = derive_aes_key(alice.decapsulate(tampered), tampered, SESSION_CONTEXT)
        with self.assertRaises(InvalidTag):
            aes_gcm_decrypt(alice_key, nonce, sealed)

    def test_measure_reports_all_metrics(self):
        row = measure("ML-KEM-512", runs=5)
        for key in ("keygen_mean_ms", "encaps_mean_ms", "decaps_mean_ms",
                    "public_key_bytes", "private_key_bytes", "ciphertext_bytes"):
            self.assertGreater(row[key], 0)

if __name__ == "__main__":
    unittest.main()
