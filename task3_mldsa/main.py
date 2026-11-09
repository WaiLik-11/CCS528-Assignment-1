"""Task 3 (PROTECT): ML-DSA (FIPS 204) digital signatures and tampering experiments.

Alice (signer) authorises a payment and Bob (verifier) checks it with her public key:

    Alice: KeyGen -> (pk, sk), publishes pk
    Alice: Sign(sk, M) -> signature sigma, sends (M, sigma)
    Bob:   Verify(pk, M, sigma) -> True / False

Experiment A verifies the original message. Experiment B modifies the message after
it was signed and shows that verification fails, then records key generation, signing
and verification times and the public key, private key and signature sizes. Further
tests tamper with the message, the signature, the public key and the context string.
"""
import argparse
import hashlib

import oqs

from common.display import boolean_colour, flip_bit, format_colour, preview, section
from common.plotting import plot_time_and_size
from common.pqc import SIG_PARAMETER_SETS, PQCSigner, nist_level
from common.results import DATA_DIR, FIGURES_DIR, environment, save_json
from common.timing import sample_ms, summarize

ORIGINAL_MESSAGE = b"Alice authorises payment of RM 5,000 to Bob, account 1234, ref INV-2026-528."
# Mallory edits the amount in transit: same length, one character different.
TAMPERED_MESSAGE = b"Alice authorises payment of RM 9,000 to Bob, account 1234, ref INV-2026-528."
PAYMENT_CONTEXT = b"CCS528-payment"

OPERATIONS = ("keygen", "sign", "verify")
SIZE_KEYS = ("public_key_bytes", "private_key_bytes", "signature_bytes")

def message_representative(public_key: bytes, message: bytes, context: bytes = b"") -> bytes:
    """mu = H(tr || M') from FIPS 204 Algorithms 2 and 7, the 64-byte value that ML-DSA actually signs.

    tr = H(pk) binds mu to the signer's public key, and M' = 0 || len(ctx) || ctx || M binds it to the
    context string and every bit of the message. H is SHAKE256.
    """
    tr = hashlib.shake_256(public_key).digest(64)
    formatted = bytes([0, len(context)]) + context + message
    return hashlib.shake_256(tr + formatted).digest(64)

def bit_difference(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

def highlight_difference(message: bytes, reference: bytes) -> str:
    """Decode message, colouring the bytes that differ from reference in yellow."""
    return "".join(
        format_colour(chr(c), "yellow") if i >= len(reference) or c != reference[i] else chr(c)
        for i, c in enumerate(message)
    )

def verdict(accepted: bool) -> str:
    return format_colour("VALID (accepted)", "green") if accepted else format_colour("INVALID (rejected)", "red")

# --------------------------------------------------------------------------
# Part 1: KeyGen -> Sign -> Signature -> Verify
# --------------------------------------------------------------------------
def sign_and_verify(sig_name: str) -> tuple[PQCSigner, bytes]:
    section(f"PART 1: ML-DSA signing ({sig_name}, NIST level {nist_level(sig_name)})")

    print("\n[Step 1] Key Generation (Alice)")
    alice = PQCSigner(sig_name)
    print(f"  Verification key pk (public): {preview(alice.public_key)}")
    print(f"  Signing key sk (private): {alice.private_key_size} bytes, kept inside Alice's liboqs context")
    print(format_colour("  Alice publishes pk; Bob must obtain it through a trusted channel (certificate or registry)"))

    print("\n[Step 2] Signing (Alice, using her private sk)")
    print(f"  Message M: {ORIGINAL_MESSAGE.decode()}")
    mu = message_representative(alice.public_key, ORIGINAL_MESSAGE)
    print(f"  mu = SHAKE256(SHAKE256(pk) || 0 || 0 || M): {preview(mu)}")
    signature = alice.sign(ORIGINAL_MESSAGE)

    print("\n[Step 3] Signature")
    print(f"  sigma = (c~, z, h): {preview(signature)}")
    print(format_colour("  c~ = commitment hash, z = masked response vector, h = hint bits"))
    print(format_colour("  Alice -> Bob: (M, sigma) travels over the untrusted network"))

    print("\n[Step 4] Verification (Bob, using only Alice's public pk)")
    valid = PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, signature, sig_name)
    print(f"  Verify(pk, M, sigma) = {boolean_colour(valid)}")
    return alice, signature

# --------------------------------------------------------------------------
# Part 2: Experiment A: Original Message
# --------------------------------------------------------------------------
def experiment_a(alice: PQCSigner, signature: bytes) -> None:
    section("EXPERIMENT A: Original Message")
    sig_name = alice.sig_name

    print(f"\n  Bob receives M:  {ORIGINAL_MESSAGE.decode()}")
    accepted = PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, signature, sig_name)
    print(f"  Verify(pk, M, sigma): {verdict(accepted)}")

    print("\n  ML-DSA signing is hedged (randomised by default): signing M again gives a different sigma")
    second = alice.sign(ORIGINAL_MESSAGE)
    second_ok = PQCSigner.verify(alice.public_key, ORIGINAL_MESSAGE, second, sig_name)
    print(f"  sigma' = {preview(second)}")
    print(f"  sigma' != sigma: {boolean_colour(second != signature)}   Verify(pk, M, sigma'): {verdict(second_ok)}")

    print(format_colour("""
  Integrity: the message Bob received hashes to the same mu that Alice signed.
  Authenticity: only the holder of the sk matching pk can produce a sigma that
  verifies, so the payment instruction came from Alice. Anyone with pk can re-check
  the same (M, sigma), which gives non-repudiation as long as sk stays secret.
  """))

# --------------------------------------------------------------------------
# Part 3: Experiment B: Tampered Message (modified after signing)
# --------------------------------------------------------------------------
def experiment_b(alice: PQCSigner, signature: bytes) -> None:
    section("EXPERIMENT B: Tampered Message (modified after signing)")
    sig_name = alice.sig_name

    print(f"\n  Alice signed: {ORIGINAL_MESSAGE.decode()}")
    print(f"  Bob receives: {highlight_difference(TAMPERED_MESSAGE, ORIGINAL_MESSAGE)}")
    print(f"  Bits changed in M: {bit_difference(ORIGINAL_MESSAGE, TAMPERED_MESSAGE)} of {len(ORIGINAL_MESSAGE) * 8}, signature sigma left unchanged")

    mu = message_representative(alice.public_key, ORIGINAL_MESSAGE)
    mu_tampered = message_representative(alice.public_key, TAMPERED_MESSAGE)
    print(f"\n  mu  (original): {preview(mu)}")
    print(f"  mu* (tampered): {format_colour(preview(mu_tampered), 'yellow')}")
    print(f"  Bits of mu that differ: {bit_difference(mu, mu_tampered)} of {len(mu) * 8} (about half, avalanche effect)")

    accepted = PQCSigner.verify(alice.public_key, TAMPERED_MESSAGE, signature, sig_name)
    print(f"\n  Verify(pk, M*, sigma): {verdict(accepted)}")
    print(format_colour("""
  Verification recomputes the commitment w1' from (pk, z, h) and mu*, then checks
  c~ == H(mu* || w1'). Because mu* differs from the mu that Alice committed to, the
  check fails. Mallory cannot forge sigma without Alice's sk, so the change to
  the amount is detected (Integrity) and the forged instruction cannot be
  attributed to Alice (Authenticity)."""))

# --------------------------------------------------------------------------
# Part 4: further tampering of the message, signature, public key and context
# --------------------------------------------------------------------------
def tampering_tests(alice: PQCSigner, signature: bytes) -> None:
    section("PART 4: Further tampering tests (every attempt must be rejected)")
    sig_name, pk, m = alice.sig_name, alice.public_key, ORIGINAL_MESSAGE

    mallory = PQCSigner(sig_name)
    forged_signature = mallory.sign(TAMPERED_MESSAGE)
    other_message = b"Alice authorises payment of RM 20 to Carol, account 7777, ref INV-2026-119."
    other_signature = alice.sign(other_message)
    context_signature = alice.sign(m, PAYMENT_CONTEXT)

    # (category, description, public key, message, signature, context)
    cases = [
        ("Message", "Single bit flipped (last byte, bit 0)", pk, flip_bit(m, -1), signature, b""),
        ("Message", "Trailing space appended", pk, m + b" ", signature, b""),
        ("Message", "Last byte removed", pk, m[:-1], signature, b""),
        ("Message", "Empty message", pk, b"", signature, b""),
        
        ("Signature", "First bit flipped (inside c~)", pk, m, flip_bit(signature, 0), b""),
        ("Signature", "Middle bit flipped (inside z)", pk, m, flip_bit(signature, len(signature) // 2), b""),
        ("Signature", "Last bit flipped (inside hint h)", pk, m, flip_bit(signature, -1, 7), b""),
        ("Signature", "Truncated by one byte", pk, m, signature[:-1], b""),
        ("Signature", "One zero byte appended", pk, m, signature + b"\x00", b""),
        ("Signature", "All-zero signature", pk, m, bytes(len(signature)), b""),
        ("Signature", "Valid sigma of another message transplanted", pk, m, other_signature, b""),

        ("Key", "Alice's sigma checked with Mallory's pk", mallory.public_key, m, signature, b""),
        ("Key", "Mallory signs M* with her sk, checked with Alice's pk", pk, TAMPERED_MESSAGE, forged_signature, b""),
        ("Key", "Public key: single bit flipped", flip_bit(pk), m, signature, b""),

        ("Context", "Signed with ctx 'payment', verified without ctx", pk, m, context_signature, b""),
        ("Context", "Signed with ctx 'payment', verified with ctx 'other'", pk, m, context_signature, b"CCS528-other"),
    ]

    print(f"\n  {'Target':<10} {'Modification':<55} Result")
    for category, description, key, message, sig, context in cases:
        accepted = PQCSigner.verify(key, message, sig, sig_name, context)
        print(f"  {category:<10} {description:<55} {verdict(accepted)}")

    # Control cases: these must verify (VALID), otherwise the rejections above would mean nothing.
    controls = [
        ("Signed with ctx 'payment', verified with ctx 'payment'", pk, m, context_signature, PAYMENT_CONTEXT),
        ("Mallory's sigma on M* checked with Mallory's own pk", mallory.public_key, TAMPERED_MESSAGE, forged_signature, b""),
    ]
    print(f"\n  {'Control':<10} {'(must be accepted)':<55}")
    for description, key, message, sig, context in controls:
        accepted = PQCSigner.verify(key, message, sig, sig_name, context)
        print(f"  {'':<10} {description:<55} {verdict(accepted)}")

# --------------------------------------------------------------------------
# Part 5: measurements for every ML-DSA (FIPS 204) parameter set
# --------------------------------------------------------------------------
def measure(sig_name: str, runs: int) -> dict:
    signer = PQCSigner(sig_name)
    signature = signer.sign(ORIGINAL_MESSAGE)

    timings = {
        "keygen": summarize(sample_ms(lambda: PQCSigner(sig_name), runs)),
        "sign": summarize(sample_ms(lambda: signer.sign(ORIGINAL_MESSAGE), runs)),
        "verify": summarize(sample_ms(lambda: PQCSigner.verify(signer.public_key, ORIGINAL_MESSAGE, signature, sig_name), runs)),
        "verify_tampered": summarize(sample_ms(lambda: PQCSigner.verify(signer.public_key, TAMPERED_MESSAGE, signature, sig_name), runs)),
    }

    row = {"parameter_set": sig_name, "nist_level": nist_level(sig_name), "runs": runs}
    for op, stats in timings.items():
        for stat in ("mean", "std", "median", "max"):
            row[f"{op}_{stat}_ms"] = round(stats[stat], 6)
    row.update({
        "public_key_bytes": len(signer.public_key),
        "private_key_bytes": signer.private_key_size,
        "signature_bytes": len(signature),
    })
    return row

def benchmark(runs: int) -> list[dict]:
    section(f"PART 5: Measurements ({runs} runs per operation, after 5 warm-up calls)")
    rows = [measure(name, runs) for name in SIG_PARAMETER_SETS]

    print(f"\n{'Parameter set':<13} {'Lvl':>3}  {'KeyGen ms':>17}  {'Sign ms':>17}  {'Verify ms':>17}  {'Verify M* ms':>17}")
    for r in rows:
        cells = "  ".join(f"{r[f'{op}_mean_ms']:>8.4f} ± {r[f'{op}_std_ms']:<6.4f}" for op in (*OPERATIONS, "verify_tampered"))
        print(f"{r['parameter_set']:<13} {r['nist_level']:>3}  {cells}")

    print(f"\n{'Parameter set':<13} {'pk B':>6} {'sk B':>6} {'sig B':>6}")
    for r in rows:
        print(f"{r['parameter_set']:<13} {r['public_key_bytes']:>6} {r['private_key_bytes']:>6} {r['signature_bytes']:>6}")

    json_path = save_json({"environment": environment(), "results": rows}, DATA_DIR / "task3" / "mldsa_benchmark.json")
    print(f"\nSaved {json_path.relative_to(DATA_DIR.parent.parent)}")
    fig_path = plot_time_and_size(
        rows, OPERATIONS, ("KeyGen", "Sign", "Verify"),
        SIZE_KEYS, ("Public key", "Private key", "Signature"),
        f"ML-DSA (FIPS 204) via liboqs {oqs.oqs_version()}, {runs} runs",
        FIGURES_DIR / "task3" / "mldsa_benchmark.png",
    )
    print(f"Saved {fig_path.relative_to(DATA_DIR.parent.parent)}")
    return rows

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sig", choices=SIG_PARAMETER_SETS, default="ML-DSA-65", help="parameter set for the walkthrough and experiments (default: %(default)s)")
    parser.add_argument("--benchmark", action="store_true", help="run the benchmark")
    parser.add_argument("--runs", type=int, default=1000, help="samples per operation in the benchmark (default: %(default)s)")
    args = parser.parse_args()

    alice, signature = sign_and_verify(args.sig)
    experiment_a(alice, signature)
    experiment_b(alice, signature)
    tampering_tests(alice, signature)

    if args.benchmark:
        benchmark(args.runs)

if __name__ == "__main__":
    main()
