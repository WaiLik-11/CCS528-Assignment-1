import time
import math
import statistics
from fractions import Fraction

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

from results import FIGURES_DIR, DATA_DIR, save_json

# RSA Public Key (only N and e are public, p and q are secret)
N = 15
e = 7
message = 2
ciphertext = pow(message, e, N)  # anyone can encrypt with the public key: 2^7 mod 15 = 8
print(f"RSA public key: (N = {N}, e = {e}) | Intercepted ciphertext c = {ciphertext}")

n_count = 2 * N.bit_length()
shots = 1024
valid_a_values = [2, 4, 7, 8, 11, 13, 14]  # every a < 15 with gcd(a, 15) = 1
repeats = 5

def build_multiplier(a):
    qc = QuantumCircuit(4)
    if a in (2, 13):
        qc.swap(2, 3); qc.swap(1, 2); qc.swap(0, 1)
    elif a in (4, 11):
        qc.swap(1, 3); qc.swap(0, 2)
    elif a in (7, 8):
        qc.swap(0, 1); qc.swap(1, 2); qc.swap(2, 3)
    # a = 1 and a = 14 need no swaps
    if a in (7, 11, 13, 14):
        qc.x(range(4))  # flipping every bit turns x into 15 - x, i.e. -x mod 15
    return qc


def run_attack(a, shots=1024, verbose=False):
    """Run every stage of Shor's algorithm for one value of a. Returns a dict of results."""
    result = {"a": a}

    if verbose:
        print(f"Input N = {N}, selected a = {a}")

    if math.gcd(a, N) != 1:
        sharedFactor = math.gcd(a, N)
        if verbose:
            print(f"Factor found classically: {sharedFactor}")
        result["factors"] = (sharedFactor, N // sharedFactor)
        return result
    if verbose:
        print(f"GCD check: gcd({a}, {N}) = 1 -> no shared factor, use quantum period finding\n")

    qc = QuantumCircuit(n_count + 4, n_count)
    qc.h(range(n_count))
    qc.x(n_count)

    for k in range(n_count):
        power = pow(a, 2**k, N)
        gate = build_multiplier(power).to_gate(label=f"x{power} mod 15").control()
        qc.append(gate, [k, n_count, n_count + 1, n_count + 2, n_count + 3])

    # iQFT
    for qubit in range(n_count // 2):
        qc.swap(qubit, n_count - qubit - 1)
    for j in range(n_count):
        for m in range(j):
            qc.cp(-np.pi / (2 ** (j - m)), m, j)
        qc.h(j)
    if verbose:
        print("Inverse QFT applied to the counting register")

    qc.measure(range(n_count), range(n_count))

    simulator = AerSimulator()
    transpiled_qc = transpile(qc, simulator)
    start = time.time()
    counts = simulator.run(transpiled_qc, shots=shots).result().get_counts()
    elapsed = time.time() - start

    if verbose:
        print("Measured States -> Estimated Period (r):")

    valid_r = None
    successful_shots = 0
    for bitstring, count in sorted(counts.items()):
        phase = int(bitstring, 2) / (2 ** n_count)
        r = Fraction(phase).limit_denominator(N).denominator
        if verbose:
            print(f"  {bitstring} ({count} shots) -> Phase {phase:.2f} -> r = {r}")
        if r % 2 == 0 and pow(a, r, N) == 1 and pow(a, r // 2, N) != N - 1:
            valid_r = r
            successful_shots += count

    factors = None
    if valid_r is not None:
        f1 = math.gcd(a ** (valid_r // 2) - 1, N)
        f2 = math.gcd(a ** (valid_r // 2) + 1, N)
        factors = (min(f1, f2), max(f1, f2))
        if verbose:
            print(f"\nPeriod found: r = {valid_r} (check: {a}^{valid_r} mod {N} = {pow(a, valid_r, N)})")
            print(f"Classical factor extraction: gcd({a}^{valid_r // 2}-1, {N}) = {f1}, "
                  f"gcd({a}^{valid_r // 2}+1, {N}) = {f2}")
            print(f"Factors of {N}: {factors[0]} and {factors[1]}")

    result.update({
        "qc": qc,
        "counts": counts,
        "valid_r": valid_r,
        "factors": factors,
        "qubits": transpiled_qc.num_qubits,
        "depth": transpiled_qc.depth(),
        "gates": sum(transpiled_qc.count_ops().values()),
        "time_s": elapsed,
        "success_rate": successful_shots / shots,
    })
    return result

def save_circuit_diagram(circuit, a):
    fig = circuit.draw("mpl", fold=-1)
    path = FIGURES_DIR / "task1" / f"shor_circuit_a{a}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Circuit diagram saved to {path}")

def save_histogram(counts, a):
    fig, ax = plt.subplots(figsize=(9, 4))
    for bitstring, count in counts.items():
        y = int(bitstring, 2)
        phase = y / (2 ** n_count)
        r = Fraction(phase).limit_denominator(N).denominator
        ax.bar(y, count)
        ax.annotate(f"r={r}", (y, count), ha="center", va="bottom", fontsize=8)
    ax.set_xlabel("Measured value y")
    ax.set_ylabel(f"Shots (of {shots})")
    ax.set_title(f"Shor's algorithm histogram, N={N}, a={a}")
    path = FIGURES_DIR / "task1" / f"histogram_a{a}.png"
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"Histogram saved to {path}")

def run_experiments():
    """Metrics (qubits, depth, gates, time, success rate) for every valid a, repeated runs."""
    rows = []
    for a in valid_a_values:
        times, rates = [], []
        for _ in range(repeats):
            result = run_attack(a, shots=shots, verbose=False)
            times.append(result["time_s"])
            rates.append(result["success_rate"])
        rows.append({
            "a": a,
            "qubits": result["qubits"],
            "depth": result["depth"],
            "gates": result["gates"],
            "shots": shots,
            "repeats": repeats,
            "time_s_mean": statistics.fmean(times),
            "time_s_std": statistics.stdev(times),
            "success_rate_mean": statistics.fmean(rates),
            "success_rate_std": statistics.stdev(rates),
        })
        print(f"a={a:2d} | qubits={rows[-1]['qubits']} | depth={rows[-1]['depth']:4d} | "
              f"gates={rows[-1]['gates']:4d} | time={rows[-1]['time_s_mean']:.4f}s +/- {rows[-1]['time_s_std']:.4f} | "
              f"success={rows[-1]['success_rate_mean']:.1%} +/- {rows[-1]['success_rate_std']:.1%}")

    save_json({"N": N, "n_count": n_count, "shots": shots, "repeats": repeats, "results": rows},
              DATA_DIR / "task1" / "shor_results.json")
    return rows

if __name__ == "__main__":
    result = run_attack(a=2, shots=shots, verbose=True)
    print(f"\nFactors found: {result['factors']}")
    save_circuit_diagram(result["qc"], a=2)
    save_histogram(result["counts"], a=2)

    p, q = result["factors"]
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    decrypted = pow(ciphertext, d, N)
    print(f"phi(N) = ({p}-1)({q}-1) = {phi}")
    print(f"Private key recovered: d = {e}^-1 mod {phi} = {d}")
    print(f"Decrypted ciphertext: {ciphertext}^{d} mod {N} = {decrypted} (original message was {message})")

    print("\nMetrics across every valid a:")
    run_experiments()