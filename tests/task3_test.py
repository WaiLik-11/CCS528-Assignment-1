import unittest

import oqs

from common.display import flip_bit
from common.pqc import SIG_PARAMETER_SETS, PQCSigner
from task3_mldsa.main import (
    ORIGINAL_MESSAGE,
    PAYMENT_CONTEXT,
    TAMPERED_MESSAGE,
    measure,
    message_representative,
)

SIG = "ML-DSA-65"  # parameter set for the single-set tests

# FIPS 204 Table 2: public key, private key, signature sizes in bytes.
FIPS204_SIZES = {
    "ML-DSA-44": (1312, 2560, 2420),
    "ML-DSA-65": (1952, 4032, 3309),
    "ML-DSA-87": (2592, 4896, 4627),
}

class MLDSATests(unittest.TestCase):
    def test_experiment_a_original_message_verifies(self):
        for name in SIG_PARAMETER_SETS:
            with self.subTest(sig=name):
                alice = PQCSigner(name)
                signature = alice.sign(ORIGINAL_MESSAGE)
                self.assertTrue(PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, signature, name))

    def test_experiment_b_tampered_message_fails(self):
        for name in SIG_PARAMETER_SETS:
            with self.subTest(sig=name):
                alice = PQCSigner(name)
                signature = alice.sign(ORIGINAL_MESSAGE)
                self.assertFalse(PQCSigner.verify(alice.public_key, TAMPERED_MESSAGE, signature, name))

    def test_sizes_match_fips204(self):
        for name, (pk, sk, sig) in FIPS204_SIZES.items():
            with self.subTest(sig=name):
                alice = PQCSigner(name)
                self.assertEqual(len(alice.public_key), pk)
                self.assertEqual(alice.private_key_size, sk)
                self.assertEqual(len(alice.sign(ORIGINAL_MESSAGE)), sig)

    def test_signing_is_randomized(self):
        alice = PQCSigner(SIG)
        first, second = alice.sign(ORIGINAL_MESSAGE), alice.sign(ORIGINAL_MESSAGE)
        self.assertNotEqual(first, second)
        self.assertTrue(PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, second, SIG))

    def test_modified_signature_rejected(self):
        alice = PQCSigner(SIG)
        signature = alice.sign(ORIGINAL_MESSAGE)
        for label, tampered in {
            "first bit": flip_bit(signature, 0),
            "last bit": flip_bit(signature, -1, 7),
            "truncated": signature[:-1],
            "extended": signature + b"\x00",
            "empty": b"",
        }.items():
            with self.subTest(change=label):
                self.assertFalse(PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, tampered, SIG))

    def test_wrong_public_key_rejected(self):
        alice, mallory = PQCSigner(SIG), PQCSigner(SIG)
        signature = alice.sign(ORIGINAL_MESSAGE)
        self.assertFalse(PQCSigner.verify(mallory.public_key, ORIGINAL_MESSAGE, signature, SIG))
        forged = mallory.sign(TAMPERED_MESSAGE)
        self.assertFalse(PQCSigner.verify(alice.public_key, TAMPERED_MESSAGE, forged, SIG))

    def test_context_string_separates_domains(self):
        alice = PQCSigner(SIG)
        signature = alice.sign(ORIGINAL_MESSAGE, PAYMENT_CONTEXT)
        self.assertTrue(PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, signature, SIG, PAYMENT_CONTEXT))
        self.assertFalse(PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, signature, SIG))
        self.assertFalse(PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, signature, SIG, b"other"))

    def test_message_representative_matches_liboqs(self):
        # Signing our own mu with the external-mu variant must give a signature that plain ML-DSA accepts.
        signer = oqs.Signature(SIG)
        public_key = signer.generate_keypair()
        for context in (b"", PAYMENT_CONTEXT):
            with self.subTest(context=context):
                mu = message_representative(public_key, ORIGINAL_MESSAGE, context)
                with oqs.Signature(f"{SIG}-extmu", signer.export_secret_key()) as extmu:
                    signature = extmu.sign(mu)
                self.assertTrue(PQCSigner.verify(public_key, ORIGINAL_MESSAGE, signature, SIG, context))

    def test_measure_reports_all_metrics(self):
        row = measure("ML-DSA-44", runs=5)
        for key in ("keygen_mean_ms", "sign_mean_ms", "verify_mean_ms", "verify_tampered_mean_ms",
                    "public_key_bytes", "private_key_bytes", "signature_bytes"):
            self.assertGreater(row[key], 0)

if __name__ == "__main__":
    unittest.main()
