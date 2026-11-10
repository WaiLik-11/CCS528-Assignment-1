"""Task 1 (BREAK): Shor's algorithm factoring an RSA modulus N = 15 = 3 x 5.

Pipeline:  public key (N, e) -> find period r of a^x mod N (quantum) -> factors p, q
           -> phi = (p-1)(q-1) -> private key d -> decrypt the ciphertext.

Only the period finding needs a quantum computer. Everything else is classical.
"""
import argparse
import time
from fractions import Fraction
from math import gcd

from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister, transpile
from qiskit.circuit.library import QFTGate
from qiskit_aer import AerSimulator

from common.display import boolean_colour, format_colour, section
from common.results import DATA_DIR, FIGURES_DIR, environment, save_json

# --- Toy RSA key generation ---
# ========================================================================
# VICTIME SIDE: p,q are secret. Only N and e are public. 
# ========================================================================
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

# ========================================================================
# ATTACKER SIDE: Only uses what is public (N, e) & intercepted ciphertext
# ========================================================================
"""Attacker never uses p,q, phi_N or d. They:
    1. Factor N by trying 2,3,4.. until one divides by 15. This will give p=3,q=5
    2. Compute phi = (p-1)(q-1)
    3. Compute d = e^-1 mod phi
    4. Decrypt the ciphertext using c^d mod N
"""
def attacker_decryption(n: int) -> tuple[int, int]:
    for candidate in range(2, n):
        if n % candidate == 0:
            return candidate, n // candidate
    raise ValueError("Failed to factor the given number")

public_N = N
public_e = exponent_e
found_p, found_q = attacker_decryption(public_N)
found_phi = (found_p - 1) * (found_q - 1)
found_d = pow(public_e, -1, found_phi)
cracked_message = [pow(c, found_d, public_N) for c in cipher_numbers]

def main(side: str | None = None) -> None:
    separator = "=" * 56
    subsection = "-" * 56
    show_victim = side in (None, "victim")
    show_attacker = side in (None, "attacker")

    print(separator)
    title = {
        None: "VICTIM AND ATTACKER",
        "victim": "VICTIM SIDE",
        "attacker": "ATTACKER SIDE",
    }[side]
    print(f"TASK 1 | RSA: {title}")
    print(separator)
    if show_victim:
        print("VICTIM SIDE | RSA key owner")
        print(f"  Public key (shared) : N = {N}, e = {exponent_e}")
        print(f"  Private key (kept)  : p = {p}, q = {q}, d = {d}")
        print(f"  Plaintext           : {message}")
        print(f"  Ciphertext sent     : {ciphertext}")
        print(f"  Local decrypt check : {decrypted_message}")
        print(subsection)
        print("VICTIM SIDE | Sentence Example transfer")
        print(f"  Message             : {message_sentence} -> {message_numbers}")
        print(f"  Ciphertext sent     : {cipher_numbers}")
        print(f"  Local decrypt check : {decrypted_numbers} -> {numbers_to_sentence(decrypted_numbers)}")

    if show_attacker:
        if show_victim:
            print(subsection)
        print("ATTACKER SIDE | Starts with public key and intercepted ciphertext")
        print(f"  Public key          : N = {public_N}, e = {public_e}")
        print(f"  Intercepted         : {cipher_numbers}")
        print(f"  Factors recovered  : {found_p} x {found_q}")
        print(f"  Private exponent    : d = {found_d}")
        print(f"  Decrypted message   : {cracked_message} -> {numbers_to_sentence(cracked_message)}")
    print(separator)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Show the RSA victim and attacker example.")
    side_group = parser.add_mutually_exclusive_group()
    side_group.add_argument("--victim", dest="side", action="store_const", const="victim",
                            help="show only the victim side")
    side_group.add_argument("--attacker", dest="side", action="store_const", const="attacker",
                            help="show only the attacker side")
    main(parser.parse_args().side)
