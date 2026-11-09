"""Task 2 (PROTECT): ML-KEM (FIPS 203) key establishment and an AES-256-GCM session.

Alice (receiver) and Bob (sender) establish a shared secret with ML-KEM:

    Alice: KeyGen -> (pk, sk), publishes pk (public key)
    Bob:   Encaps(pk) -> (ciphertext, shared secret ss)
    Alice: Decaps(sk, ciphertext) -> recovered shared secret ss'
    Check: ss == ss'

ss is then expanded with HKDF-SHA-256 into AES-256-GCM session keys. The
benchmark measures key generation, encapsulation and decapsulation times and the
key and ciphertext sizes for ML-KEM-512, ML-KEM-768 and ML-KEM-1024.
"""
import argparse
import hmac
import oqs
from cryptography.exceptions import InvalidTag

from common.display import boolean_colour, flip_bit, format_colour, preview, section
from common.plotting import plot_time_and_size
from common.pqc import (
    KEM_PARAMETER_SETS,
    PQCKEMRecipient,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    derive_aes_key,
    kem_encapsulate,
    nist_level,
    sha256,
)
from common.results import DATA_DIR, FIGURES_DIR, environment, save_json
from common.timing import sample_ms, summarize

SESSION_CONTEXT = b"Task2-MLKEM-session"
BOB_TO_ALICE = SESSION_CONTEXT + b"|bob->alice"
ALICE_TO_BOB = SESSION_CONTEXT + b"|alice->bob"

OPERATIONS = ("keygen", "encaps", "decaps")

# --------------------------------------------------------------------------
# Part 1: KeyGen -> Encaps -> (ciphertext + shared secret) -> Decaps
# --------------------------------------------------------------------------
def key_establishment(kem_name: str) -> tuple[PQCKEMRecipient, bytes, bytes, bytes]:
    section(f"PART 1: ML-KEM key establishment ({kem_name}, NIST level {nist_level(kem_name)})")

    print("\n[Step 1] Key Generation (Alice)")
    alice = PQCKEMRecipient(kem_name)
    print(f"  Encapsulation key pk (public): {preview(alice.public_key)}")
    print(f"  Decapsulation key sk (private): {alice.private_key_size} bytes, kept inside Alice's liboqs context")
    print(format_colour("  Alice -> Bob: pk is sent over the untrusted network"))

    print("\n[Step 2] Encapsulation (Bob, using only Alice's public pk)")
    ciphertext, bob_secret = kem_encapsulate(alice.public_key, kem_name)
    print(f"  Ciphertext ct: {preview(ciphertext)}")
    print(f"  Bob's secret ss: {bob_secret.hex()}")
    print(format_colour("  Bob -> Alice: c is sent over the untrusted network (K never leaves Bob)"))

    print("\n[Step 3] Decapsulation (Alice, using her private sk)")
    alice_secret = alice.decapsulate(ciphertext)
    print(f"  Alice's secret ss': {alice_secret.hex()}")

    print("\n[Step 4] Verification")
    agreed = hmac.compare_digest(alice_secret, bob_secret)
    print(f"  ss == ss': {boolean_colour(agreed)}")
    print(format_colour("  Both parties now hold the same 256-bit secret; an eavesdropper saw only pk and ct."))
    return alice, ciphertext, alice_secret, bob_secret

# --------------------------------------------------------------------------
# Part 2: what an attacker gets from tampering or from a different key pair
# --------------------------------------------------------------------------
def negative_tests(alice: PQCKEMRecipient, ciphertext: bytes, bob_secret: bytes) -> bytes:
    section(f"PART 2: Negative tests {format_colour("(TODO: CHECK WITH DR MANMEET IF ATTACKS TESTS ARE NEEDED FOR TASK 2)", "red")}")

    print("\n[Test A] Mallory tampers with the ciphertext (one bit of ct flipped in transit)")
    tampered = flip_bit(ciphertext)
    print(f"  Tampered Ciphertext ct: {format_colour(preview(tampered), 'yellow')}")
    print(format_colour("  Alice attempts to decapsulate the tampered ciphertext..."))
    rejected_secret = alice.decapsulate(tampered)
    print(f"  Decaps(sk, ct*) = {rejected_secret.hex()}")
    print(f"  Matches Bob's ss: {boolean_colour(hmac.compare_digest(rejected_secret, bob_secret))}")
    print(format_colour("""  Implicit rejection: Decaps re-encrypts the recovered message and, on mismatch,
  returns ss* = J(z || ct*) from a secret seed z instead of raising an error.
  The attacker learns nothing about sk, and the mismatch surfaces later as an
  AES-GCM authentication failure (see Part 3, Test D).
    """))

    print("\n[Test B] Eve decapsulates the intercepted ct with her own key pair")
    eve = PQCKEMRecipient(alice.kem_name)
    eve_secret = eve.decapsulate(ciphertext)
    print(f"  Eve's secret: {eve_secret.hex()}")
    print(f"  Matches Bob's ss: {boolean_colour(hmac.compare_digest(eve_secret, bob_secret))}")
    print(format_colour("  Only the holder of sk can recover ss from ct."))
    return rejected_secret

# --------------------------------------------------------------------------
# Part 3: shared secret -> HKDF -> AES-256-GCM secure session
# --------------------------------------------------------------------------
def secure_session(ciphertext: bytes, alice_secret: bytes, bob_secret: bytes, rejected_secret: bytes) -> None:
    section("PART 3: Secure symmetric session (HKDF-SHA-256 -> AES-256-GCM)")

    # Each side derives its keys independently from its own copy of the secret.
    # Separate keys per direction, and both bound to the KEM ciphertext via HKDF info.
    bob_keys = {d: derive_aes_key(bob_secret, ciphertext, d) for d in (BOB_TO_ALICE, ALICE_TO_BOB)}
    alice_keys = {d: derive_aes_key(alice_secret, ciphertext, d) for d in (BOB_TO_ALICE, ALICE_TO_BOB)}
    print("\n[Key derivation]")
    for direction in (BOB_TO_ALICE, ALICE_TO_BOB):
        label = direction.split(b"|")[1].decode()
        same = hmac.compare_digest(bob_keys[direction], alice_keys[direction])
        print(f"  {label:<11} AES-256 key fingerprint SHA-256: {sha256(alice_keys[direction]).hex()[:16]}...  identical on both sides: {boolean_colour(same)}")

    print("\n[Test C] Encrypted exchange")
    req_m = b"Bob: please confirm the wire transfer of RM 5,000 to account 1234."
    req_aad = b"txn=1|bob->alice"
    req_nonce, req_aes_ct = aes_gcm_encrypt(bob_keys[BOB_TO_ALICE], req_m, req_aad)
    print(f"  Bob encrypts: {len(req_m)} B plaintext -> {len(req_aes_ct)} B ciphertext+tag, nonce {req_nonce.hex()}")
    print(f"    AES ciphertext: {preview(req_aes_ct)}")
    aes_pt = aes_gcm_decrypt(alice_keys[BOB_TO_ALICE], req_nonce, req_aes_ct, req_aad)
    print(f"    Alice decrypts: {format_colour(aes_pt.decode(), 'green')}")

    res_m = b"Alice: confirmed."
    res_aad = b"txn=1|alice->bob"
    res_nonce, res_aes_ct = aes_gcm_encrypt(alice_keys[ALICE_TO_BOB], res_m, res_aad)
    print(f"  Alice encrypts: {len(res_m)} B plaintext -> {len(res_aes_ct)} B ciphertext+tag, nonce {res_nonce.hex()}")
    print(f"    AES ciphertext: {preview(res_aes_ct)}")
    res_aes_pt = aes_gcm_decrypt(bob_keys[ALICE_TO_BOB], res_nonce, res_aes_ct, res_aad)
    print(f"    Bob decrypts: {format_colour(res_aes_pt.decode(), 'green')}")

    print("\n[Test D] Session integrity checks (each must raise InvalidTag)")
    rejected_key = derive_aes_key(rejected_secret, flip_bit(ciphertext), BOB_TO_ALICE)
    attempts = {
        "AES ciphertext bit flipped": (alice_keys[BOB_TO_ALICE], flip_bit(req_aes_ct), req_aad),
        "Associated data altered (txn=2)": (alice_keys[BOB_TO_ALICE], req_aes_ct, b"txn=2|bob->alice"),
        "Key from tampered KEM ciphertext": (rejected_key, req_aes_ct, req_aad),
    }
    for name, (key, data, associated) in attempts.items():
        try:
            aes_gcm_decrypt(key, req_nonce, data, associated)
            print(format_colour(f"  {name}: ERROR, accepted", "red"))
        except InvalidTag:
            print(f"  {name}: {format_colour('rejected (InvalidTag)', 'red')}")

# --------------------------------------------------------------------------
# Part 4: measurements for every ML-KEM (FIPS 203) parameter set
# --------------------------------------------------------------------------
def measure(kem_name: str, runs: int) -> dict:
    recipient = PQCKEMRecipient(kem_name)
    ciphertext, _ = kem_encapsulate(recipient.public_key, kem_name)

    timings = {
        "keygen": summarize(sample_ms(lambda: PQCKEMRecipient(kem_name), runs)),
        "encaps": summarize(sample_ms(lambda: kem_encapsulate(recipient.public_key, kem_name), runs)),
        "decaps": summarize(sample_ms(lambda: recipient.decapsulate(ciphertext), runs)),
    }

    row = {"parameter_set": kem_name, "nist_level": nist_level(kem_name), "runs": runs}
    for op in OPERATIONS:
        for stat in ("mean", "std", "median"):
            row[f"{op}_{stat}_ms"] = round(timings[op][stat], 6)
    row.update({
        "public_key_bytes": len(recipient.public_key),
        "private_key_bytes": recipient.private_key_size,
        "ciphertext_bytes": len(ciphertext),
    })
    return row


def benchmark(runs: int) -> list[dict]:
    section(f"PART 4: Measurements ({runs} runs per operation, after 5 warm-up calls)")
    rows = [measure(name, runs) for name in KEM_PARAMETER_SETS]

    print(f"\n{'Parameter set':<13} {'Lvl':>3}  {'KeyGen ms':>17}  {'Encaps ms':>17}  {'Decaps ms':>17}")
    for r in rows:
        cells = "  ".join(f"{r[f'{op}_mean_ms']:>8.4f} ± {r[f'{op}_std_ms']:<6.4f}" for op in OPERATIONS)
        print(f"{r['parameter_set']:<13} {r['nist_level']:>3}  {cells}")

    print(f"\n{'Parameter set':<13} {'pk B':>6} {'sk B':>6} {'ct B':>6}")
    for r in rows:
        print(f"{r['parameter_set']:<13} {r['public_key_bytes']:>6} {r['private_key_bytes']:>6} {r['ciphertext_bytes']:>6}")

    json_path = save_json({"environment": environment(), "results": rows}, DATA_DIR / "task2" / "mlkem_benchmark.json")
    print(f"\nSaved {json_path.relative_to(DATA_DIR.parent.parent)}")
    fig_path = plot_time_and_size(
        rows, OPERATIONS, ("KeyGen", "Encaps", "Decaps"),
        ("public_key_bytes", "private_key_bytes", "ciphertext_bytes"), ("Public key", "Private key", "Ciphertext"),
        f"ML-KEM (FIPS 203) via liboqs {oqs.oqs_version()}, {rows[0]['runs']} runs",
        FIGURES_DIR / "task2" / "mlkem_benchmark.png",
    )
    print(f"Saved {fig_path.relative_to(DATA_DIR.parent.parent)}")
    return rows

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kem", choices=KEM_PARAMETER_SETS, default="ML-KEM-768", help="parameter set for the walkthrough (default: %(default)s)")
    parser.add_argument("--benchmark", action="store_true", help="run the benchmark")
    parser.add_argument("--runs", type=int, default=1000, help="samples per operation in the benchmark (default: %(default)s)")
    args = parser.parse_args()

    alice, ciphertext, alice_secret, bob_secret = key_establishment(args.kem)
    rejected_secret = negative_tests(alice, ciphertext, bob_secret)
    secure_session(ciphertext, alice_secret, bob_secret, rejected_secret)
    if args.benchmark:
        benchmark(args.runs)

if __name__ == "__main__":
    main()
