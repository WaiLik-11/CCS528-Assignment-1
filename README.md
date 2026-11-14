# CCS528 Programming Assignment 1: From Shor to Lattices

**Programming Quantum Threats and Post-Quantum Protection**

| Member | Student ID |
|--------|-----------|
| AU WAI LIK | 25203542 |
| TIFFANY TIEN NEE PRAGASAM | 25203306 |

- **Submission deadline:** 17/11/2026 (Tuesday, before 5 pm), via E-learn
- **Demonstration:** 24/11/2026
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
git clone <repo-url>
cd assignment-1

uv sync          # creates .venv with Python 3.12 and the exact versions in uv.lock

# On first import, liboqs-python builds liboqs into ~/_oqs (this takes a few minutes, once per machine).

# On Windows, if the build cannot find a compiler, run it from the "x64 Native Tools Command Prompt for VS".
uv run python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"
```

To add a dependency, run `uv add <package>` and commit both `pyproject.toml` and `uv.lock`.

## 5. Execution Procedure

Run all commands from the repository root.

```bash
uv run python -m task1_shor.main                           # BREAK:   Shor's algorithm for N = 15
uv run python -m task1_shor.main --a 14                    # BREAK:   a failing choice of a (14 = -1 mod 15)
uv run python -m task1_shor.main --experiments            # BREAK:   metrics for every valid a, saved to results/
uv run python -m task2_mlkem.main                          # PROTECT: ML-KEM and an AES-GCM session
uv run python -m task3_mldsa.main                          # PROTECT: ML-DSA, Experiments A and B (--benchmark for all parameter sets)
uv run python -m task4_benchmark.main                      # COMPARE: writes CSVs and graphs to results/
uv run python -m task5_application.main --mode normal      # APPLY: quantum-safe blockchain demo
uv run python -m task5_application.main --mode attacks     # APPLY: replay / tamper / ledger attack scenarios
uv run python -m task5_application.evaluation              # APPLY: timing, size, and throughput measurements
uv run pytest                                              # run tests
```

Outputs (CSV files, figures, circuit diagrams, and JSON measurements) are written to [results/](results/).

## 6. Program Structure

```
assignment-1/
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
├── tests/                  # Correctness tests (pytest)
├── results/                # Generated outputs (deliverable C evidence)
│   ├── data/               #   raw CSV/JSON measurements
│   ├── figures/            #   graphs and circuit diagrams
│   └── screenshots/        #   terminal screenshots for the report
├── report/                 # Technical report source and final PDF
└── rubric/                 # Assignment brief and rubric (reference only)
```

## 7. Team Workflow

1. Never commit directly to `main`. Create a branch for each task: `git checkout -b task2-mlkem`.
2. Commit small changes often, then open a Pull Request so your teammate can review before merging.
3. Pull before starting work: `git pull origin main`.
4. Do not commit `.venv/`, build folders or large generated files (see `.gitignore`).
5. Keep this repository **private** so other groups cannot copy it.

## 8. Rubric Checklist (each criterion is 20%)

> The rubric says: *"Simply executing existing toolkit examples without modification, experimentation or explanation will receive limited marks."*
> Every task therefore needs original code, its own experiments, and a written explanation.

### Task 1: Shor's Algorithm (20%)
- [x] Program prints every stage: Input N → choose a → GCD check → quantum period finding → inverse QFT → measurement → period estimation (continued fractions) → classical factor extraction → factors
- [x] Circuit diagram saved to `results/figures/`
- [x] Measurement histogram, with each peak explained (e.g. which values of s/r it represents)
- [x] Metrics: qubit count, circuit depth, gate counts, number of shots, execution time, success rate across several values of `a` and repeated runs
- [x] Explanation of how this breaks RSA (factoring N gives φ(N), which gives the private key d), with a toy RSA key recovered as proof
- [x] **Limitations**: hard-coded modular multiplication, simulator vs real hardware, noise, and qubit estimates for RSA-2048

Details, results and explanation: [task1_shor/README.md](task1_shor/README.md).

### Task 2: ML-KEM (20%)
- [x] KeyGen → Encaps → (ciphertext, shared secret) → Decaps → recovered secret, run as two separate parties (Alice and Bob)
- [x] Check that the shared secrets are equal, plus a negative test (tampered ciphertext gives a different secret because of implicit rejection)
- [x] Shared secret passed through HKDF into AES-256-GCM to encrypt and decrypt a message
- [x] Metrics for ML-KEM-512, 768 and 1024: keygen, encaps and decaps times (mean and standard deviation over N runs), plus pk, sk and ct sizes
- [x] Explanation of the Module-LWE basis and why Shor's algorithm does not apply

Details, results and explanation: [task2_mlkem/README.md](task2_mlkem/README.md).

### Task 3: ML-DSA and Tampering (20%)
- [x] KeyGen → Sign → Signature → Verify
- [x] **Experiment A**: original message verifies
- [x] **Experiment B**: tampered message fails verification
- [x] Extra tampering tests: flipped signature bit, wrong public key, truncated signature, single-bit message change, transplanted signature, context-string mismatch
- [x] Metrics for ML-DSA-44, 65 and 87: keygen, sign and verify times, plus pk, sk and signature sizes
- [x] Explanation of what integrity, authenticity and non-repudiation mean here

Details, results and explanation: [task3_mldsa/README.md](task3_mldsa/README.md).

### Task 4: Benchmarking (20%)
- [x] KEM comparison: RSA-OAEP / ECDH (X25519, P-256) vs ML-KEM
- [x] Signature comparison: RSA-PSS / ECDSA / Ed25519 vs ML-DSA
- [x] 4 metrics (wall-clock time, CPU time, key/ciphertext/signature sizes, communication overhead), 200 runs with mean and standard deviation
- [x] Tables and graphs in `results/`
- [x] Critical analysis of the security, performance and resource trade-offs

Details, results and explanation: [task4_benchmark/README.md](task4_benchmark/README.md).

### Task 5: Quantum-Safe Permissioned Blockchain PoC (20%)
- [ ] Chosen environment, plus the security problem and threat model (attacker capabilities, assets, out-of-scope assumptions)
- [ ] Architecture diagram showing wallet signing, secure transport, validator checks, and hash-linked ledger
- [ ] Normal operation: ML-DSA authentication → ML-KEM key establishment → HKDF → AES-GCM payload encryption → ledger append
- [ ] At least one attack or failure scenario (e.g. replay, ciphertext tampering, KEM key substitution, ledger mutation) and how it is detected
- [ ] Explanation of the security purpose of each component and the trusted registry assumptions
- [ ] Demonstration of the local prototype's evaluation metrics: timings, sizes, throughput, and chain validation results

#### Task 5 prototype

Run the prototype from the repository root:

```bash
uv run python -m task5_application.main --mode normal
uv run python -m task5_application.main --mode attacks
uv run python -m task5_application.evaluation
```

This application is a local permissioned-ledger prototype. Wallets derive addresses from their ML-DSA public keys, a trusted registry keeps the authorized participant set and pinned validator ML-KEM public key, and each signed transfer is submitted through a secure ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM channel before being appended to a SHA-256 hash-linked ledger. The actual implementation lives in `task5_application/main.py` and the modules under `task5_application/pqc_blockchain/`.

```text
Alice wallet            Secure channel               Validator node                Ledger
creates tx +    -->  ML-KEM-768 -> HKDF ->   -->  decrypt, verify,        -->  hash-linked blocks,
ML-DSA signature     AES-256-GCM                  nonce/balance checks,      balances, nonces,
                                                  signature validation      rejection log
```

The validator accepts only registered participants, positive transfers, valid ML-DSA signatures, the expected next sender nonce, and enough balance. The sender checks that the validator KEM fingerprint matches the trusted registry value before encapsulating a fresh KEM shared secret, and the encrypted payload is bound to the KEM ciphertext hash and transaction metadata using AES-GCM AAD. Accepted transfers become hash-linked blocks.

The threat model assumes an untrusted network attacker can read, alter, forge, or replay submitted transactions, and that a ledger reader should not learn the plaintext payment note. The attack experiments cover replayed transactions, ciphertext modification, KEM key substitution, and mutation of stored blocks. Signatures, nonce checks, AES-GCM tags, and chain validation detect those failures. The prototype is intentionally limited: it does not implement distributed consensus, network transport, persistent custody, or production key management. The registry and validator KEM fingerprint are trusted in this simulation, and the ledger is local and permissioned rather than a production blockchain.

The evaluation script reports median ML-KEM/ML-DSA timings, payload size and ledger growth, end-to-end transaction latency, throughput, and full-chain validation times for configurable sample counts. These outputs support the coursework demo rather than production benchmarking.

## 9. References

1. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
2. NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*, 2024.
3. P. W. Shor, "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer," *SIAM J. Comput.*, 1997.
4. Open Quantum Safe project: https://openquantumsafe.org/
5. Qiskit documentation: https://quantum.cloud.ibm.com/
