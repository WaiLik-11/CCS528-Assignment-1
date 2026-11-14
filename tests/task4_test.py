import unittest
from common.timing import sample_cpu_ms
from task4_benchmark.main import (
    CLASSICAL_KEMS, CLASSICAL_SIGS, add_keygen_cpu,
    measure_classical_kem, measure_classical_sig, private_size, public_size,
)

RUNS = 3  # just enough samples for summarize(); RSA-3072 keygen is slow

class ClassicalKEMTests(unittest.TestCase):
    def test_measure_reports_all_metrics(self):
        for name in CLASSICAL_KEMS:
            with self.subTest(kem=name):
                row = measure_classical_kem(name, runs=RUNS)
                for key in ("keygen_mean_ms", "encaps_mean_ms", "decaps_mean_ms",
                            "public_key_bytes", "ciphertext_bytes"):
                    self.assertIn(key, row)
                    self.assertGreaterEqual(row[key], 0)

    def test_x25519_sizes(self):
        keygen, _, _ = CLASSICAL_KEMS["X25519"]
        sk = keygen()
        self.assertEqual(public_size(sk.public_key()), 32)
        self.assertEqual(private_size(sk), 32)

class ClassicalSignatureTests(unittest.TestCase):
    def test_measure_reports_all_metrics(self):
        for name in CLASSICAL_SIGS:
            with self.subTest(sig=name):
                row = measure_classical_sig(name, runs=RUNS)
                for key in ("keygen_mean_ms", "sign_mean_ms", "verify_mean_ms",
                            "public_key_bytes", "signature_bytes"):
                    self.assertIn(key, row)
                    self.assertGreaterEqual(row[key], 0)

class KeygenCPUTimingTests(unittest.TestCase):
    def test_sample_cpu_ms_returns_nonnegative_samples(self):
        samples = sample_cpu_ms(lambda: sum(range(1000)), samples=5)
        self.assertEqual(len(samples), 5)
        self.assertTrue(all(s >= 0 for s in samples))

    def test_add_keygen_cpu_adds_columns(self):
        rows = [measure_classical_kem("X25519", runs=RUNS)]
        add_keygen_cpu(rows, {"X25519": CLASSICAL_KEMS["X25519"][0]})
        for key in ("keygen_cpu_mean_ms", "keygen_cpu_std_ms", "keygen_cpu_median_ms"):
            self.assertIn(key, rows[0])
            self.assertGreaterEqual(rows[0][key], 0)

if __name__ == "__main__":
    unittest.main()
