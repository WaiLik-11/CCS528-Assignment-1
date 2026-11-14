"""Task 4: Classical versus Post-Quantum Cryptography (experimental comparison).

Key establishment:  RSA-3072-OAEP, ECDH-P256, X25519   vs  ML-KEM-512/768/1024 (Task 2)
Digital signatures: RSA-3072-PSS, ECDSA-P256, Ed25519  vs  ML-DSA-44/65/87     (Task 3)

Metrics: (1) key-generation wall-clock and CPU time, (2) operation time (encaps/decaps,
sign/verify), (3) key / ciphertext / signature size, (4) communication overhead (bytes on
the wire). The classical schemes are timed with the same sample_ms()/summarize() helpers
as the PQC rows, so all numbers are directly comparable.
"""

import argparse
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from common.display import format_colour, section
from common.plotting import plot_time_and_size
from common.pqc import KEM_PARAMETER_SETS, PQCKEMRecipient, PQCSigner, SIG_PARAMETER_SETS
from common.results import DATA_DIR, FIGURES_DIR, environment, save_csv, save_json
from common.timing import sample_cpu_ms, sample_ms, summarize
from task2_mlkem.main import measure as measure_mlkem   
from task3_mldsa.main import measure as measure_mldsa   
from task3_mldsa.main import ORIGINAL_MESSAGE

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)

# Classical key establishment, written in the same KEM shape as ML-KEM:
#   encaps(pk) -> (ciphertext, secret)    decaps(sk, ciphertext) -> secret
# For ECDH the "ciphertext" is the sender's ephemeral public key.
def rsa_encaps(pk):
    secret = os.urandom(32)                       # random 256-bit secret, encrypted to pk
    return pk.encrypt(secret, OAEP), secret

def rsa_decaps(sk, ct):
    return sk.decrypt(ct, OAEP)

def p256_encaps(pk):
    eph = ec.generate_private_key(ec.SECP256R1())
    ct = eph.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return ct, eph.exchange(ec.ECDH(), pk)

def p256_decaps(sk, ct):
    return sk.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ct))

def x25519_encaps(pk):
    eph = x25519.X25519PrivateKey.generate()
    return eph.public_key().public_bytes_raw(), eph.exchange(pk)

def x25519_decaps(sk, ct):
    return sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct))

# name -> (keygen, encaps, decaps). All three are ~128-bit classical security (≈ NIST level 1).
CLASSICAL_KEMS = {
    "RSA-3072": (lambda: rsa.generate_private_key(65537, 3072), rsa_encaps, rsa_decaps),
    "ECDH-P256": (lambda: ec.generate_private_key(ec.SECP256R1()), p256_encaps, p256_decaps),
    "X25519": (x25519.X25519PrivateKey.generate, x25519_encaps, x25519_decaps),
}

# name -> (keygen, sign, verify). verify raises InvalidSignature on failure.
CLASSICAL_SIGS = {
    "RSA-3072-PSS": (lambda: rsa.generate_private_key(65537, 3072),
                     lambda sk, m: sk.sign(m, PSS, hashes.SHA256()),
                     lambda pk, m, s: pk.verify(s, m, PSS, hashes.SHA256())),
    "ECDSA-P256": (lambda: ec.generate_private_key(ec.SECP256R1()),
                   lambda sk, m: sk.sign(m, ec.ECDSA(hashes.SHA256())),
                   lambda pk, m, s: pk.verify(s, m, ec.ECDSA(hashes.SHA256()))),
    "Ed25519": (ed25519.Ed25519PrivateKey.generate,
                lambda sk, m: sk.sign(m),
                lambda pk, m, s: pk.verify(s, m)),
}

# Key sizes in their compact wire encodings
def public_size(pk) -> int:
    if isinstance(pk, rsa.RSAPublicKey):
        return len(pk.public_bytes(Encoding.DER, PublicFormat.PKCS1))           # modulus n + exponent e
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return len(pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))  # 0x04 || x || y
    return len(pk.public_bytes_raw())                                           # X25519 / Ed25519

def private_size(sk) -> int:
    if isinstance(sk, rsa.RSAPrivateKey):                                       # n, e, d, p, q + CRT values
        return len(sk.private_bytes(Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    if isinstance(sk, ec.EllipticCurvePrivateKey):
        return (sk.curve.key_size + 7) // 8                                     # secret scalar
    return 32

def classical_row(name: str, runs: int, timings: dict, sk, extra: dict) -> dict:
    """Same keys as the Task 2/3 rows, so classical and PQC rows go into one table."""
    row = {"parameter_set": name, "nist_level": 1, "quantum_safe": False, "runs": runs}
    for op, stats in timings.items():
        for stat in ("mean", "std", "median"):
            row[f"{op}_{stat}_ms"] = round(stats[stat], 6)
    row.update({"public_key_bytes": public_size(sk.public_key()), "private_key_bytes": private_size(sk), **extra})
    return row

def measure_classical_kem(name: str, runs: int) -> dict:
    keygen, encaps, decaps = CLASSICAL_KEMS[name]
    sk = keygen()
    pk = sk.public_key()
    ct, secret = encaps(pk)
    assert decaps(sk, ct) == secret, f"{name}: shared secrets differ"   # correctness before timing
    timings = {
        "keygen": summarize(sample_ms(keygen, runs)),
        "encaps": summarize(sample_ms(lambda: encaps(pk), runs)),
        "decaps": summarize(sample_ms(lambda: decaps(sk, ct), runs)),
    }
    return classical_row(name, runs, timings, sk, {"ciphertext_bytes": len(ct)})

def measure_classical_sig(name: str, runs: int) -> dict:
    keygen, sign, verify = CLASSICAL_SIGS[name]
    sk = keygen()
    pk = sk.public_key()
    signature = sign(sk, ORIGINAL_MESSAGE)
    verify(pk, ORIGINAL_MESSAGE, signature)                             # raises if invalid
    timings = {
        "keygen": summarize(sample_ms(keygen, runs)),
        "sign": summarize(sample_ms(lambda: sign(sk, ORIGINAL_MESSAGE), runs)),
        "verify": summarize(sample_ms(lambda: verify(pk, ORIGINAL_MESSAGE, signature), runs)),
    }
    return classical_row(name, runs, timings, sk, {"signature_bytes": len(signature)})


# Comparison: classical rows first, then the PQC rows from Task 2 / Task 3
KEM_COLUMNS = ("parameter_set", "nist_level", "quantum_safe",
               "keygen_mean_ms", "keygen_std_ms", "keygen_cpu_mean_ms", "keygen_cpu_std_ms",
               "encaps_mean_ms", "encaps_std_ms", "decaps_mean_ms", "decaps_std_ms",
               "public_key_bytes", "ciphertext_bytes", "handshake_bytes")
SIG_COLUMNS = ("parameter_set", "nist_level", "quantum_safe",
               "keygen_mean_ms", "keygen_std_ms", "keygen_cpu_mean_ms", "keygen_cpu_std_ms",
               "sign_mean_ms", "sign_std_ms", "verify_mean_ms", "verify_std_ms",
               "public_key_bytes", "signature_bytes", "signed_message_bytes")

def add_keygen_cpu(rows: list[dict], keygen_fns: dict) -> None:
    """CPU time (user + system) of key generation, alongside its wall-clock time."""
    for r in rows:
        stats = summarize(sample_cpu_ms(keygen_fns[r["parameter_set"]]))
        for stat in ("mean", "std", "median"):
            r[f"keygen_cpu_{stat}_ms"] = round(stats[stat], 6)

def compare_kems(runs: int) -> list[dict]:
    section("KEY ESTABLISHMENT: RSA / ECDH vs ML-KEM")
    rows = [measure_classical_kem(n, runs) for n in CLASSICAL_KEMS]
    rows += [{**measure_mlkem(n, runs), "quantum_safe": True} for n in KEM_PARAMETER_SETS]
    for r in rows:   # communication overhead: pk (receiver -> sender) + ct (sender -> receiver)
        r["handshake_bytes"] = r["public_key_bytes"] + r["ciphertext_bytes"]
    keygen_fns = {n: keygen for n, (keygen, _, _) in CLASSICAL_KEMS.items()}
    keygen_fns.update({n: (lambda n=n: PQCKEMRecipient(n)) for n in KEM_PARAMETER_SETS})
    add_keygen_cpu(rows, keygen_fns)
    print_table(rows, ("keygen", "keygen_cpu", "encaps", "decaps"), ("public_key_bytes", "ciphertext_bytes", "handshake_bytes"))
    return [{k: r[k] for k in KEM_COLUMNS} for r in rows]

def compare_sigs(runs: int) -> list[dict]:
    section("DIGITAL SIGNATURES: RSA / ECDSA / Ed25519 vs ML-DSA")
    rows = [measure_classical_sig(n, runs) for n in CLASSICAL_SIGS]
    rows += [{**measure_mldsa(n, runs), "quantum_safe": True} for n in SIG_PARAMETER_SETS]
    for r in rows:   # communication overhead: verifier needs pk once, then one signature per message
        r["signed_message_bytes"] = r["public_key_bytes"] + r["signature_bytes"]
    keygen_fns = {n: keygen for n, (keygen, _, _) in CLASSICAL_SIGS.items()}
    keygen_fns.update({n: (lambda n=n: PQCSigner(n)) for n in SIG_PARAMETER_SETS})
    add_keygen_cpu(rows, keygen_fns)
    print_table(rows, ("keygen", "keygen_cpu", "sign", "verify"), ("public_key_bytes", "signature_bytes", "signed_message_bytes"))
    return [{k: r[k] for k in SIG_COLUMNS} for r in rows]

def print_table(rows: list[dict], ops: tuple[str, ...], sizes: tuple[str, ...]) -> None:
    header = "  ".join(f"{op + ' ms':>19}" for op in ops) + "  " + "  ".join(f"{s.replace('_bytes', ' B'):>18}" for s in sizes)
    print(f"\n{'Scheme':<13} {'PQ-safe':>7}  {header}")
    for r in rows:
        safe = format_colour("yes", "green") if r["quantum_safe"] else format_colour(" no", "red")
        times = "  ".join(f"{r[f'{op}_mean_ms']:>10.4f} ± {r[f'{op}_std_ms']:<6.4f}" for op in ops)
        size_cells = "  ".join(f"{r[s]:>18}" for s in sizes)
        print(f"{r['parameter_set']:<13} {safe:>16}  {times}  {size_cells}")

def save(kem_rows: list[dict], sig_rows: list[dict], runs: int) -> None:
    section("Saving results")
    out = DATA_DIR / "task4"
    paths = [
        save_json({"environment": environment(), "kem": kem_rows, "signature": sig_rows}, out / "comparison.json"),
        save_csv(kem_rows, out / "kem_comparison.csv"),
        save_csv(sig_rows, out / "signature_comparison.csv"),
        plot_time_and_size(
            kem_rows, ("keygen", "encaps", "decaps"), ("KeyGen", "Encaps", "Decaps"),
            ("public_key_bytes", "ciphertext_bytes", "handshake_bytes"), ("Public key", "Ciphertext", "Handshake (pk+ct)"),
            f"Key establishment: classical vs ML-KEM, {runs} runs (log scale)",
            FIGURES_DIR / "task4" / "kem_comparison.png", log_scale=True,
        ),
        plot_time_and_size(
            sig_rows, ("keygen", "sign", "verify"), ("KeyGen", "Sign", "Verify"),
            ("public_key_bytes", "signature_bytes", "signed_message_bytes"), ("Public key", "Signature", "pk + signature"),
            f"Signatures: classical vs ML-DSA, {runs} runs (log scale)",
            FIGURES_DIR / "task4" / "signature_comparison.png", log_scale=True,
        ),
    ]
    for p in paths:
        print(f"Saved {p.relative_to(DATA_DIR.parent.parent)}")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=100,
                        help="samples per operation (default: %(default)s; RSA-3072 keygen dominates the run time)")
    args = parser.parse_args()

    kem_rows = compare_kems(args.runs)
    sig_rows = compare_sigs(args.runs)
    save(kem_rows, sig_rows, args.runs)

if __name__ == "__main__":
    main()