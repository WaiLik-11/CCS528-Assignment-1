"""Task 1 (BREAK): Shor's algorithm factoring an RSA modulus N = 15 = 3 x 5.

Pipeline:  public key (N, e) -> find period r of a^x mod N (quantum) -> factors p, q
           -> phi = (p-1)(q-1) -> private key d -> decrypt the ciphertext.

Only the period finding needs a quantum computer. Everything else is classical.
"""
import time
from fractions import Fraction
from math import gcd

from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister, transpile
from qiskit.circuit.library import QFTGate
from qiskit_aer import AerSimulator

from common.display import boolean_colour, format_colour, section
from common.results import DATA_DIR, FIGURES_DIR, environment, save_json

# --- Toy RSA key generation (what the victim does) ---
p = 3
q = 5
N = p * q
phi_N = (p-1) * (q-1)
exponent_e = 7
d = pow(exponent_e, -1, phi_N) # -> d = e^-1 mod phi_N --> d = 7^-1 mod 8 = 7

# Encryption / decrypting a small message
message = 2
ciphertext = pow(message, exponent_e, N)    # m^e mod N -> ciphertext = 2^7 mod 15 = 8 
decrypted_message = pow(ciphertext, d, N)   # c^d mod N -> decrypted = 8^7 mod 15 = 2

# Example if we relate to Task 5 (Transfer)
vocabulary = ["Alice", "pays", "Bob", "RM", "100"]
def sentence_to_numbers(sentence: str) -> list[int]:
    return [vocabulary.index(word) + 2 for word in sentence.split()]

def numbers_to_sentence(numbers: list[int]) -> str:
    return " ".join(vocabulary[number - 2] for number in numbers)

message_sentence = "Alice pays Bob RM 100"
message_numbers = sentence_to_numbers(message_sentence)
cipher_numbers = [pow(n, exponent_e, N) for n in message_numbers]
decrypted_numbers = [pow(c, d, N) for c in cipher_numbers]

def main() -> None:
    separator = "=" * 56
    subsection = "-" * 56

    print(separator)
    print("TASK 1 | RSA EXAMPLE")
    print(separator)
    print("KEYS")
    print(f"  Public : N = {N}, e = {exponent_e}")
    print(f"  Secret : p = {p}, q = {q}, d = {d}")
    print(subsection)
    print("INTEGER MESSAGE")
    print(f"  Plaintext  : {message}")
    print(f"  Ciphertext : {ciphertext}")
    print(f"  Decrypted  : {decrypted_message}")
    print(subsection)
    print("SENTENCE EXAMPLE")
    print(f"  Message    : {message_sentence} -> {message_numbers}")
    print(f"  Ciphertext : {cipher_numbers}")
    print(f"  Decrypted  : {decrypted_numbers} -> {numbers_to_sentence(decrypted_numbers)}")
    print(separator)

if __name__ == "__main__":
    main()
