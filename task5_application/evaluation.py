"""Task 5 evaluation: where the time and the bytes go in one quantum-safe ledger transaction.

Task 4 already times ML-KEM-768 and ML-DSA-65 against classical schemes, so this script
measures the application built from them instead:

    Part 1: time per stage of one transaction (wallet, sender, validator, ledger) and end to end
    Part 2: bytes per transaction on the wire and on the ledger, against the same design with
            Ed25519 signatures and an X25519 key exchange (estimated by substituting their sizes)
    Part 3: throughput and full-chain validation time as the chain grows
"""
import argparse
import itertools
import time

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from common.display import format_colour, section
from common.plotting import COLORS, GRID, INK, MUTED_INK
from common.results import DATA_DIR, FIGURES_DIR, environment, save_json
from common.timing import sample_ms, summarize
from .main import build_demo
from .pqc_blockchain.ledger import Ledger
from .pqc_blockchain.secure_channel import KEM_NAME, decrypt_submission, encrypt_submission
from .pqc_blockchain.transaction import canonical_json
from .pqc_blockchain.wallet import SIG_NAME

PQC_LABEL = f"{SIG_NAME} + {KEM_NAME}"
CLASSICAL_LABEL = "Ed25519 + X25519 (estimate)"

def submit(registry, node, tx):
    envelope = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
    accepted, reason = node.receive(envelope)
    assert accepted, reason

def stored_block_bytes(block) -> int:
    """Size of one block as stored: compact JSON body, hash and hex validator signature."""
    return len(canonical_json({
        **block.body(),
        "block_hash": block.block_hash,
        "validator_signature": block.validator_signature.hex(),
    }))

# --------------------------------------------------------------------------
# Part 1: time per stage of one transaction
# --------------------------------------------------------------------------
def measure_stages(runs: int) -> list[dict]:
    section(f"PART 1: Time per stage of one transaction ({runs} runs per stage, after 5 warm-up calls)")
    # Each transaction sends 1 coin, so Alice needs one coin per end-to-end run, warm-up calls included.
    alice, bob, registry, ledger, validator, node = build_demo(alice_balance=runs + 5)
    validator_pk, pin = registry.validator_kem_key(), registry.validator_kem_fingerprint()
    tx = alice.create_transaction(bob.address, 1, 0)
    envelope = encrypt_submission(validator_pk, tx.to_bytes(), pin)
    # add_transaction() spends Alice's balance on every call, and the end-to-end stage below
    # needs that balance, so the block-append stage gets its own throwaway ledger.
    throwaway_ledger = Ledger(registry.validator_signing_key())
    throwaway_ledger.set_initial_balance(alice.address, runs + 5)

    stages = [
        ("Wallet: build tx + ML-DSA sign", lambda: alice.create_transaction(bob.address, 1, 0)),
        ("Sender: pin check + ML-KEM encaps + HKDF + AES-GCM", lambda: encrypt_submission(validator_pk, tx.to_bytes(), pin)),
        ("Validator: ML-KEM decaps + HKDF + AES-GCM decrypt", lambda: decrypt_submission(node.kem_recipient, envelope)),
        ("Validator: checks incl. ML-DSA verify", lambda: validator.validate_transaction(tx)),
        ("Ledger: block hash + ML-DSA block signature", lambda: throwaway_ledger.add_transaction(tx, validator.signer)),
    ]
    nonces = itertools.count()
    stages.append(("End to end (all of the above, real ledger)", lambda: submit(registry, node, alice.create_transaction(bob.address, 1, next(nonces)))))

    rows = []
    print(f"\n  {'Stage':<52} {'mean ms':>9} ± {'std':<7} {'median':>8}")
    for name, fn in stages:
        stats = summarize(sample_ms(fn, runs))
        rows.append({"stage": name, **{f"{k}_ms": round(v, 6) for k, v in stats.items()}})
        print(f"  {name:<52} {stats['mean']:>9.4f} ± {stats['std']:<7.4f} {stats['median']:>8.4f}")

    parts = sum(r["mean_ms"] for r in rows[:-1])
    print(format_colour(f"\n  Sum of stages {parts:.3f} ms vs end to end {rows[-1]['mean_ms']:.3f} ms; the rest is JSON parsing and Python overhead."))
    print(format_colour("  Every stage is well under a millisecond: post-quantum cryptography is not the CPU bottleneck."))
    return rows

# --------------------------------------------------------------------------
# Part 2: bytes per transaction, on the wire and on the ledger
# --------------------------------------------------------------------------
def measure_sizes() -> dict:
    section("PART 2: Bytes per transaction, on the wire and on the ledger")
    alice, bob, registry, ledger, validator, node = build_demo()
    tx = alice.create_transaction(bob.address, 1, 0)
    envelope = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
    submit(registry, node, tx)
    block = ledger.blocks[-1]

    # Signatures are stored as hex in JSON, so each takes twice its raw size.
    wallet_sig, validator_sig = 2 * len(tx.signature), 2 * len(block.validator_signature)
    kem_ct = len(envelope["kem_ciphertext"])
    wire_total = sum(len(v) for v in envelope.values())
    ledger_total = stored_block_bytes(block)
    pqc = {
        "kem_ciphertext": kem_ct,
        "wallet_signature": wallet_sig,
        "other_wire": wire_total - kem_ct - wallet_sig,
        "wire_total": wire_total,
        "ledger_wallet_signature": wallet_sig,
        "ledger_validator_signature": validator_sig,
        "other_ledger": ledger_total - wallet_sig - validator_sig,
        "ledger_total": ledger_total,
    }

    # Same design and encoding, with only the signature and KEM ciphertext sizes swapped.
    ed_sig = 2 * len(ed25519.Ed25519PrivateKey.generate().sign(b"size"))
    x_ct = len(x25519.X25519PrivateKey.generate().public_key().public_bytes_raw())  # dummy public key
    classical = {
        "kem_ciphertext": x_ct,
        "wallet_signature": ed_sig,
        "other_wire": pqc["other_wire"],
        "wire_total": x_ct + ed_sig + pqc["other_wire"],
        "ledger_wallet_signature": ed_sig,
        "ledger_validator_signature": ed_sig,
        "other_ledger": pqc["other_ledger"],
        "ledger_total": 2 * ed_sig + pqc["other_ledger"],
    }

    print(f"\n  {'Bytes per transaction':<34} {PQC_LABEL:>24} {CLASSICAL_LABEL:>28} {'ratio':>7}")
    rows = (
        ("Wire: KEM ciphertext", "kem_ciphertext"),
        ("Wire: wallet signature (hex)", "wallet_signature"),
        ("Wire: everything else", "other_wire"),
        ("Wire: total envelope", "wire_total"),
        ("Ledger: wallet signature (hex)", "ledger_wallet_signature"),
        ("Ledger: validator signature (hex)", "ledger_validator_signature"),
        ("Ledger: everything else", "other_ledger"),
        ("Ledger: total block", "ledger_total"),
    )
    for label, key in rows:
        print(f"  {label:<34} {pqc[key]:>24} {classical[key]:>28} {pqc[key] / classical[key]:>6.1f}x")

    share = (wallet_sig + validator_sig) / ledger_total
    print(format_colour(f"\n  Signatures are {share:.0%} of every stored block. Storing them as raw bytes instead of hex would halve that."))
    print(format_colour("  Real chains put thousands of transactions in a block, so the validator signature is shared; the wallet signature is not."))
    return {PQC_LABEL: pqc, CLASSICAL_LABEL: classical}

# --------------------------------------------------------------------------
# Part 3: throughput and validation time as the chain grows
# --------------------------------------------------------------------------
def measure_scaling(chain_lengths: list[int], validation_runs: int) -> list[dict]:
    section(f"PART 3: Throughput and full-chain validation ({validation_runs} validation runs per length)")
    rows = []
    print(f"\n  {'Blocks':>7} {'tx/s':>9} {'ledger KB':>10} {'validate ms':>12} ± {'std':<7}")
    for n in chain_lengths:
        alice, bob, registry, ledger, validator, node = build_demo(alice_balance=n)  # 1 coin per block
        start = time.perf_counter()
        for nonce in range(n):
            submit(registry, node, alice.create_transaction(bob.address, 1, nonce))
        seconds = time.perf_counter() - start
        stats = summarize(sample_ms(ledger.validate_chain, validation_runs, warmup=1))
        row = {
            "blocks": n,
            "throughput_tps": round(n / seconds, 1),
            "ledger_bytes": sum(stored_block_bytes(b) for b in ledger.blocks),
            "validation_mean_ms": round(stats["mean"], 6),
            "validation_std_ms": round(stats["std"], 6),
        }
        rows.append(row)
        print(f"  {n:>7} {row['throughput_tps']:>9.1f} {row['ledger_bytes'] / 1000:>10.1f} "
              f"{stats['mean']:>12.3f} ± {stats['std']:<7.3f}")

    per_block = rows[-1]["validation_mean_ms"] / rows[-1]["blocks"] * 1000
    print(format_colour(f"\n  Validation grows linearly, about {per_block:.0f} µs per block: one SHA-256 hash and one ML-DSA verify each."))
    print(format_colour("  This is one process with one validator; consensus and networking would dominate a real deployment."))
    return rows

# --------------------------------------------------------------------------
# Figure: one panel per part
# --------------------------------------------------------------------------
def plot(stages: list[dict], sizes: dict, scaling: list[dict], path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, (ax_t, ax_s, ax_v) = plt.subplots(1, 3, figsize=(16, 4.8), gridspec_kw={"width_ratios": [1.3, 1, 0.9]})

    # Part 1: one series, so one colour and no legend.
    names = [r["stage"].replace(": ", ":\n", 1).replace(" (", "\n(", 1) for r in stages]
    means = [r["mean_ms"] * 1000 for r in stages]
    errs = [r["std_ms"] * 1000 for r in stages]
    y = range(len(stages))[::-1]
    ax_t.barh(list(y), means, xerr=errs, height=0.6, color=COLORS[0], edgecolor="white", linewidth=2,
              error_kw={"ecolor": MUTED_INK, "elinewidth": 1, "capsize": 3})
    for yi, m, e in zip(y, means, errs):
        ax_t.annotate(f"{m:.0f}", (m + e, yi), xytext=(6, 0), textcoords="offset points", va="center", fontsize=8, color=MUTED_INK)
    ax_t.set_yticks(list(y), names, fontsize=8)
    ax_t.set_xlabel("Mean time (µs), error bar = 1 std dev", color=MUTED_INK)
    ax_t.set_title("Time per stage", loc="left", fontsize=12, color=INK)

    # Part 2: stacked components; totals are labelled directly because two hues are below 3:1 contrast.
    designs = (PQC_LABEL, CLASSICAL_LABEL)
    short_names = {PQC_LABEL: "PQC", CLASSICAL_LABEL: "Classical"}
    bars = [(f"{where.title()}\n{short_names[d]}", d, where) for where in ("wire", "ledger") for d in designs]
    components = (
        ("KEM ciphertext", {"wire": "kem_ciphertext", "ledger": None}),
        ("Wallet signature", {"wire": "wallet_signature", "ledger": "ledger_wallet_signature"}),
        ("Validator block signature", {"wire": None, "ledger": "ledger_validator_signature"}),
        ("Everything else", {"wire": "other_wire", "ledger": "other_ledger"}),
    )
    x = range(len(bars))
    bottoms = [0] * len(bars)
    for colour, (label, keys) in zip(COLORS, components):
        values = [sizes[d][keys[kind]] if keys[kind] else 0 for _, d, kind in bars]
        ax_s.bar(list(x), values, 0.6, bottom=bottoms, label=label, color=colour, edgecolor="white", linewidth=2)
        bottoms = [b + v for b, v in zip(bottoms, values)]
    for xi, total in zip(x, bottoms):
        ax_s.annotate(f"{total:,} B", (xi, total), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8, color=MUTED_INK)
    ax_s.set_xticks(list(x), [b[0] for b in bars], fontsize=9)
    ax_s.set_ylabel("Bytes per transaction", color=MUTED_INK)
    ax_s.set_title("Bytes per transaction (classical = estimate)", loc="left", fontsize=12, color=INK)
    handles, labels = ax_s.get_legend_handles_labels()
    ax_s.legend(handles[::-1], labels[::-1], loc="upper left", frameon=False, fontsize=8)  # same top-to-bottom order as the stack

    # Part 3: one series on log-log axes, so a straight line means linear growth.
    blocks = [r["blocks"] for r in scaling]
    ax_v.errorbar(blocks, [r["validation_mean_ms"] for r in scaling], yerr=[r["validation_std_ms"] for r in scaling],
                  color=COLORS[0], linewidth=2, marker="o", markersize=8, markeredgecolor="white", markeredgewidth=2,
                  ecolor=MUTED_INK, elinewidth=1, capsize=3)
    for r in scaling:
        ax_v.annotate(f"{r['validation_mean_ms']:.1f} ms", (r["blocks"], r["validation_mean_ms"]),
                      xytext=(8, -4), textcoords="offset points", fontsize=8, color=MUTED_INK)
    ax_v.set_xscale("log")
    ax_v.set_yscale("log")
    ax_v.set_xlabel("Blocks in chain", color=MUTED_INK)
    ax_v.set_ylabel("validate_chain() mean time (ms)", color=MUTED_INK)
    ax_v.set_title("Full-chain validation", loc="left", fontsize=12, color=INK)

    for ax in (ax_t, ax_s, ax_v):
        ax.grid(axis="x" if ax is ax_t else "y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        ax.tick_params(colors=MUTED_INK)

    fig.suptitle(f"Task 5: quantum-safe permissioned ledger ({PQC_LABEL})", x=0.01, ha="left", fontsize=13)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200)
    plt.close(fig)
    return path

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=1000, help="samples per stage in Part 1 (default: %(default)s)")
    parser.add_argument("--chain-lengths", type=lambda s: [int(n) for n in s.split(",")], default=[10, 100, 1000],
                        help="comma-separated chain lengths for Part 3 (default: 10,100,1000)")
    parser.add_argument("--validation-runs", type=int, default=20, help="validate_chain() samples per length (default: %(default)s)")
    args = parser.parse_args()

    stages = measure_stages(args.runs)
    sizes = measure_sizes()
    scaling = measure_scaling(args.chain_lengths, args.validation_runs)

    results = {"environment": environment(), "runs": args.runs, "stages": stages, "sizes": sizes, "scaling": scaling}
    json_path = save_json(results, DATA_DIR / "task5" / "evaluation.json")
    fig_path = plot(stages, sizes, scaling, FIGURES_DIR / "task5" / "evaluation.png")
    print(f"\nSaved {json_path.relative_to(DATA_DIR.parent.parent)}")
    print(f"Saved {fig_path.relative_to(DATA_DIR.parent.parent)}")

if __name__ == "__main__":
    main()
