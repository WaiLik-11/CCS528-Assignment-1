# CCS528 Programming Assignment 1: From Shor to Lattices

**Programming Quantum Threats and Post-Quantum Protection**

| Member | Student ID |
|--------|-----------|
| AU WAI LIK | 25203542 |
| TIFFANY TIEN NEE PRAGASAM | 25203306 |

---

## 1. Overview

| Phase | Task | Description | Folder |
|-------|------|-------------|--------|
| BREAK | 1 | Shor's algorithm factoring an RSA modulus (N = 15) | [task1_shor/](task1_shor/) |
| PROTECT | 2 | ML-KEM (FIPS 203) key establishment and an AES-GCM session | [task2_mlkem/](task2_mlkem/) |
| PROTECT | 3 | ML-DSA (FIPS 204) signatures with tampering experiments | [task3_mldsa/](task3_mldsa/) |
| COMPARE | 4 | Classical (RSA/ECDH/ECDSA) vs PQC benchmarks | [task4_benchmark/](task4_benchmark/README.md) |
| APPLY | 5 | Quantum-safe permissioned blockchain PoC using ML-DSA, ML-KEM, HKDF, AES-GCM, and a hash-linked ledger | [task5_application/](task5_application/) |

## 2. Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| [uv](https://docs.astral.sh/uv/) | latest | Installs Python 3.12 and every dependency from `uv.lock`, so both machines get identical versions |
| Git | any | Version control |
| C compiler | see below | Needed once to build `liboqs`, the C library behind `liboqs-python` (uv installs CMake and Ninja) |

The C compiler is the only part that differs between operating systems:

| OS | How to get the C compiler |
|----|---------------------------|
| macOS | `xcode-select --install`. Skip this if `xcode-select -p` already prints a path; installing Git usually installs it too |
| Windows | Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and tick **Desktop development with C++** |

Install uv:

```bash
# macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

## 3. Libraries / Toolkits

| Library | Used in | Role |
|---------|---------|------|
| [Qiskit](https://quantum.cloud.ibm.com/) and Qiskit Aer | Task 1 | Builds the Shor circuit (modular exponentiation, inverse QFT) and simulates it |
| [liboqs](https://github.com/open-quantum-safe/liboqs) / [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) | Tasks 2, 3, 4, 5 | Open Quantum Safe implementations of ML-KEM-512/768/1024 and ML-DSA-44/65/87 |
| [cryptography](https://cryptography.io/) | Tasks 2, 4, 5 | AES-256-GCM, HKDF, and the classical RSA/ECDH/ECDSA baselines (OpenSSL backend) |
| NumPy, pandas | Tasks 1, 4 | Numerical work and storing results |
| matplotlib | Tasks 1, 4 | Circuit diagrams, histograms and benchmark graphs |

## 4. Installation

```bash
git clone https://github.com/WaiLik-11/CCS528-Assignment-1.git
cd CCS528-Assignment-1

uv sync          # creates .venv with Python 3.12 and the exact versions in uv.lock

# On first import, liboqs-python downloads and builds liboqs into ~/_oqs (needs internet, takes a few minutes, once per machine).

# On Windows, if the build cannot find a compiler, run it from the "x64 Native Tools Command Prompt for VS".
uv run python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"
```

To add a dependency, run `uv add <package>` and commit both `pyproject.toml` and `uv.lock`.

## 5. Execution Procedure

Run all commands from the repository root.

```bash
uv run python -m task1_shor.main                           # BREAK:   Shor's algorithm for N = 15, then metrics for every valid a
uv run python -m task2_mlkem.main                          # PROTECT: ML-KEM and an AES-GCM session (add --benchmark for timings)
uv run python -m task3_mldsa.main                          # PROTECT: ML-DSA Experiments A and B (add --benchmark for timings)
uv run python -m task4_benchmark.main                      # COMPARE: classical vs PQC, writes CSVs and graphs to results/
uv run python -m task5_application.main --mode normal      # APPLY: quantum-safe blockchain demo
uv run python -m task5_application.main --mode attacks     # APPLY: replay / tamper / ledger attack scenarios
uv run python -m task5_application.evaluation              # APPLY: timing, size, and throughput measurements
```

Notes:

- Each task is a separate Python module, so run it with `python -m` from the repository root, not by opening the file directly.
- Task 4 is the slowest because it generates many RSA-3072 keys. Use `--runs 20` for a quick run.
- Running a task overwrites its files in [results/](results/) (CSV, JSON, figures and circuit diagrams). Run `git checkout -- results/` to restore the submitted copies.

See each task's README for its options, expected output and explanation of the results.

## 6. Program Structure

```
CCS528-Assignment-1/
├── README.md               # This file (deliverable B)
├── pyproject.toml          # Python dependencies (managed by uv)
├── uv.lock                 # Exact pinned versions, shared by the team
├── .python-version         # Python 3.12
├── .gitignore
├── common/                 # Shared helpers (PQC wrappers, timing, console output, plots, result saving)
├── task1_shor/             # Task 1: BREAK, Shor's algorithm
├── task2_mlkem/            # Task 2: PROTECT, ML-KEM (FIPS 203)
├── task3_mldsa/            # Task 3: PROTECT, ML-DSA (FIPS 204)
├── task4_benchmark/        # Task 4: Classical vs PQC comparison
├── task5_application/      # Task 5: APPLY, quantum-safe prototype
└── results/                # Generated outputs (evidence for the technical report)
    ├── data/               #   raw CSV/JSON measurements
    ├── figures/            #   graphs and circuit diagrams
    └── screenshots/        #   terminal screenshots
```

## 7. What Each Task Covers

### Task 1: Shor's Algorithm
- Program prints every stage: Input N → choose a → GCD check → quantum period finding → inverse QFT → measurement → period estimation (continued fractions) → classical factor extraction → factors
- Circuit diagram and measurement histogram saved to `results/figures/task1/`, with each peak explained
- Metrics: qubit count, circuit depth, gate counts, shots, execution time and success rate for every valid `a`, repeated 5 times
- Explanation of how this breaks RSA (factoring N gives φ(N), which gives the private key d), with a toy RSA key recovered as proof
- Limitations: hard-coded modular multiplication, simulator vs real hardware, noise, and qubit estimates for RSA-2048

Details, results and explanation: [task1_shor/README.md](task1_shor/README.md).

### Task 2: ML-KEM
- KeyGen → Encaps → (ciphertext, shared secret) → Decaps → recovered secret, run as two separate parties (Alice and Bob)
- Check that the shared secrets are equal, plus negative tests (tampered ciphertext gives a different secret because of implicit rejection)
- Shared secret passed through HKDF into AES-256-GCM to encrypt and decrypt messages
- Metrics for ML-KEM-512, 768 and 1024: keygen, encaps and decaps times (mean and standard deviation), plus pk, sk and ct sizes
- Explanation of the Module-LWE basis and why Shor's algorithm does not apply

Details, results and explanation: [task2_mlkem/README.md](task2_mlkem/README.md).

### Task 3: ML-DSA and Tampering
- KeyGen → Sign → Signature → Verify
- **Experiment A**: original message verifies
- **Experiment B**: tampered message fails verification
- 16 further tampering tests (message, signature, public key, context string) plus 2 control cases
- Metrics for ML-DSA-44, 65 and 87: keygen, sign and verify times, plus pk, sk and signature sizes
- Explanation of what integrity, authenticity and non-repudiation mean here

Details, results and explanation: [task3_mldsa/README.md](task3_mldsa/README.md).

### Task 4: Benchmarking
- Key establishment: RSA-3072-OAEP, ECDH-P256 and X25519 vs ML-KEM
- Signatures: RSA-3072-PSS, ECDSA-P256 and Ed25519 vs ML-DSA
- Metrics: wall-clock time, CPU time (key generation), key/ciphertext/signature sizes and communication overhead, 200 runs with mean and standard deviation
- Tables and graphs in `results/`, with an analysis of the security, performance and resource trade-offs

Details, results and explanation: [task4_benchmark/README.md](task4_benchmark/README.md).

### Task 5: Quantum-Safe Permissioned Blockchain
- Security problem and threat model, architecture, and the roles of ML-DSA-65 (transactions and blocks), ML-KEM-768 + HKDF + AES-256-GCM (confidential submission) and a SHA-256 hash-linked ledger
- Normal operation, six attack scenarios (replay, ciphertext tampering, KEM key substitution, modified transaction, impersonation, ledger tampering) and how each is detected
- Evaluation: per-stage timings, bytes per transaction, throughput and chain validation time

Details, results and explanation: [task5_application/README.md](task5_application/README.md).

The evaluation script measures the application rather than the primitives (Task 4 already compares those): the mean ± standard deviation time of each stage of one transaction over 1000 runs, the bytes per transaction on the wire and on the ledger against the same design with Ed25519 and X25519 (an estimate made by substituting their sizes), and throughput and full-chain validation time for chains of 10, 100 and 1000 blocks. Results are saved to `results/data/task5/evaluation.json` and `results/figures/task5/evaluation.png`. These outputs support the coursework demo rather than production benchmarking.

## 8. References

1. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
2. NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*, 2024.
3. P. W. Shor, "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer," *SIAM J. Comput.*, 1997.
4. Open Quantum Safe project: https://openquantumsafe.org/
5. Qiskit documentation: https://quantum.cloud.ibm.com/
