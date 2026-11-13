import unittest

from qiskit.quantum_info import Statevector

from task1_shor.main import build_multiplier, run_attack, valid_a_values

class ShorTests(unittest.TestCase):
    def test_multiplier_implements_modular_multiplication(self):
        # build_multiplier(a) must map every reachable work-register value |x> to |x * a mod 15>
        # (x = 0 is excluded: the work register only ever holds values from {1..14}, never 0)
        for a in valid_a_values:
            circuit = build_multiplier(a)
            for x in range(1, 15):
                output = Statevector.from_label(format(x, "04b")).evolve(circuit)
                expected = format((x * a) % 15, "04b")
                self.assertEqual(output.probabilities_dict().get(expected, 0), 1.0, f"a={a}, x={x}")

    def test_gcd_shortcut_skips_the_quantum_step(self):
        result = run_attack(3, shots=16)  # gcd(3, 15) = 3, already a factor classically
        self.assertEqual(result["factors"], (3, 5))
        self.assertNotIn("qc", result)

    def test_run_attack_recovers_the_real_factors(self):
        result = run_attack(7, shots=512)
        self.assertEqual(result["factors"], (3, 5))
        self.assertGreater(result["success_rate"], 0.3)

    def test_every_valid_a_gives_the_real_factors_or_the_known_a14_failure(self):
        for a in valid_a_values:
            result = run_attack(a, shots=256)
            if a == 14:
                self.assertIsNone(result["factors"])  # 14 = -1 mod 15, only trivial factors
            else:
                self.assertEqual(result["factors"], (3, 5), f"a = {a}")
