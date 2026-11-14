# CCS528 Technical Paper 1: Overview Aligned to the Recommended Paper Structure

This is an outline, not the finished paper. It follows the nine headings in `RECOMMENDED PAPER STRUCTURE template.dotx` exactly. It reuses content from `technical-paper-draft.md` and maps every programming rubric criterion (5 × 20%) to a section. All numbers come from the repo's committed `results/data/` files or from a re-run of every task (Nov 2026, macOS / Apple Silicon, in a temporary copy so committed results were not overwritten).

---

## Front Matter (as in the template)

| Field | Content |
|---|---|
| Heading | CCS528 TECHNICAL PAPER 1 |
| TITLE | From Quantum Vulnerability to Quantum-Safe Systems: Analysing the Transition from Classical to Post-Quantum Cryptography |
| STUDENT'S NAME | AU WAI LIK (25203542) · TIFFANY TIEN NEE PRAGASAM (25203306) |
| INSTRUCTOR NAME | _[fill in]_ |
| Abstract + Keywords | Not listed in the template, but keep them. Use the abstract from the draft (≈200 words): problem → method (5 tasks) → three findings → proposed ledger. |

**Research question (state in §1, answer in §9):** How does quantum computing undermine current public-key cryptography, and how can lattice-based PQC be integrated into an emerging system in practice?

**Narrative thread:** BREAK (Task 1) → WHY LATTICES → PROTECT (Tasks 2–3) → COMPARE (Task 4) → APPLY (Task 5) → EVALUATE.

---

## Mapping: Draft Sections → Template Sections

| Template section | Draft source | Change needed |
|---|---|---|
| 1. Introduction | Draft §1 | **Add** a short primer on quantum computing (qubits, superposition, interference, measurement) and on what public-key crypto protects. The template asks for both, and the draft currently skips them. |
| 2. Classical Cryptography and Quantum Threat | Draft §2.1, §2.2, §2.4 (Table 2), §3.1 | Move §3.1 ("larger RSA keys don't help") here as the closing argument. Move the Shor *results* (Table 1) to §5. |
| 3. Lattice-Based PQC | Draft §3.2–3.4 | Mostly unchanged. Open with one sentence on the NIST PQC families. |
| 4. ML-KEM and ML-DSA | Draft §4.1–4.4 | Keep design and security roles here. Move the experimental *evidence* (tamper results) to §5. |
| 5. Experimental Results and Analysis | Draft §2.3 + Task 2/3 evidence + §5 | Becomes one results section covering Tasks 1–4. |
| 6. Proposed Quantum-Safe Application | Draft §6.1–6.4 | Unchanged structure. Keep prototype *description* here. |
| 7. Security and Performance Discussion | Draft §6.5 + §7.1–7.4 | Prototype metrics and attack results now serve as evaluation evidence. "Practicality" is renamed **Deployment**, matching the template wording. |
| 8. Future Work | Draft §7.5 | Promoted to its own top-level section and expanded. |
| 9. Conclusion | Draft §8 | Add one sentence per finding that answers the research question directly. |
| References | Draft references [1]–[21] | Re-number after moving sections. Add the tool references the brief requires (Qiskit, liboqs/OQS, `cryptography`/OpenSSL). |

---

## 1. Introduction

> *Template: introduce quantum computing, cryptographic security and the quantum threat.*

- **Cryptographic security:** public-key crypto provides key establishment (confidentiality) and digital signatures (authenticity, integrity, non-repudiation). TLS, PKI, blockchains and secure messaging all rely on RSA/ECC.
- **Quantum computing (new, 1 paragraph):** a qubit can be in a superposition of states; *n* qubits span 2ⁿ amplitudes; quantum gates use **interference** to amplify correct answers; measurement returns one outcome with some probability. The speed-up applies to specific mathematical structures, such as hidden periods, not to every computation. This sets up §2.
- **The quantum threat:** Shor (exponential speed-up, breaks RSA/ECC) vs Grover (quadratic speed-up, AES-256 is still fine). Mosca's inequality *x + y > z* and "harvest now, decrypt later" [15]. NIST IR 8547 transition timeline: deprecate by 2030, disallow by 2035 [12].
- **Research question and contributions:** (i) a 12-qubit Shor simulation with toy RSA key recovery; (ii) ML-KEM and ML-DSA implementations with negative/tamper tests; (iii) a 200-run classical vs PQC benchmark; (iv) a quantum-safe permissioned ledger design with a working prototype.
- **Paper roadmap:** one sentence per section, §2–§9.

## 2. Classical Cryptography and Quantum Threat

> *Template: discuss RSA/ECC and Shor's algorithm.* · Rubric criterion 1 (theory side).

**2.1 Classical foundations** (draft §2.1)
- RSA: *d = e⁻¹ mod φ(N)*, so factoring breaks RSA. GNFS runs in sub-exponential time, which is why 3072-bit moduli are needed.
- DH/DSA: the discrete logarithm problem. ECC: the ECDLP; Pollard rho takes *O(√n)*, which explains why 256-bit ECC ≈ 3072-bit RSA.
- The shared weakness: all three reduce to **period finding over an abelian group**.

**2.2 How Shor's algorithm works** (draft §2.2)
- The five stages, matching the assignment brief's pipeline: *Input N → select a → GCD check → quantum period finding → inverse QFT → measurement → period estimation (continued fractions) → classical factor extraction*.
- Extending the same approach to DLP/ECDLP. Grover's algorithm in contrast: symmetric primitives survive with doubled key sizes.

**2.3 Toy demonstration vs a real attack** (draft §2.4, Table 2)
- Our multiplier is hard-coded for N = 15 (Smolin et al. [20]).
- Resource estimates: RSA-2048 needs ~20 M physical qubits (2021) [4], then < 1 M (2025) [5]; P-256 needs ~2,330 logical qubits [6]. Two points to make: the gap is engineering, not mathematics, and **ECC is the easier quantum target**.

**2.4 Why larger RSA keys are not enough** (moved from draft §3.1)
- A polynomial-time attack against polynomial-cost defence: post-quantum RSA would need ~1 TB keys [7].
- Our data: RSA-3072 keygen took 115 ± 79 ms. This leads into §3.

## 3. Lattice-Based Post-Quantum Cryptography

> *Template: discuss lattice problems, LWE and Module-LWE.* · Supports rubric criteria 2–3 ("explains the role of ML-KEM in post-quantum security").

- **3.1 PQC families:** lattice, code-based, hash-based, multivariate and isogeny. Lattices were chosen for their balance of speed, size and security evidence [19].
- **3.2 Lattices and SVP/CVP:** a lattice basis; good vs bad bases; hardness in high dimensions (BKZ, sieving); no hidden abelian subgroup for a quantum computer to exploit. *Suggested figure: a 2-D lattice with good and bad bases (draw it yourselves).*
- **3.3 LWE:** *b = A·s + e mod q*. Without noise, Gaussian elimination solves it; with noise, it becomes a CVP instance. Noise is the source of security, and it explains both decryption failure (ML-KEM) and rejection sampling (ML-DSA). Regev's worst-case to average-case reduction [8].
- **3.4 Ring-LWE → Module-LWE:** structure buys efficiency. ML-KEM uses *n = 256, q = 3329, k ∈ {2,3,4}*. Evidence: public key size 800 → 1,184 → 1,568 B grows linearly with *k*.

## 4. ML-KEM and ML-DSA

> *Template: discuss their design objectives and security roles.* · Rubric criteria 2 and 3 (explanation side).

- **4.1 Design objectives and roles:** draft Table 3 (purpose, IND-CCA2 vs EUF-CMA, hard problem, what each replaces, urgency, what each does *not* provide). A KEM without authentication allows MITM; a signature alone gives no confidentiality.
- **4.2 ML-KEM (FIPS 203):** KeyGen / Encaps / Decaps; the Fujisaki–Okamoto re-encryption check and **implicit rejection**; the KEM-DEM pattern (HKDF-SHA-256 with info bound to H(ct), one key per direction, then AES-256-GCM); the parallel with TLS `X25519MLKEM768` [16].
- **4.3 ML-DSA (FIPS 204):** Fiat–Shamir with aborts. Explain *μ = H(H(pk) ‖ ctx ‖ M)*, commitment *w*, challenge *c*, response *z*, and the abort condition. Hedged (randomised) signing: re-signing M gives a different σ, and both verify.
- **4.4 Security properties:** integrity, authenticity (Module-SIS), non-repudiation (contrast with MAC/GCM tags). A signature proves possession of a key, not identity, so a PKI or registry is required (this motivates §6).
- **4.5 Critical comparison:** the shared Module-LWE foundation (shared NTT hardware vs monoculture risk; SLH-DSA and HQC as backups); implementation risk (ML-DSA's secret-dependent rejection loop vs ML-KEM's ~2⁻¹⁶⁴ decryption failure).

## 5. Experimental Results and Analysis

> *Template: present and critically analyse selected results from the Programming Assignment.* · Rubric criteria 1–4 (evidence side). Start with a short **setup table**: libraries, versions and the machine used for each dataset (see the warning below).

**5.1 Task 1: Shor's algorithm for N = 15**
- Setup: Qiskit + Aer, 12 qubits (8 counting + 4 work), 1024 shots, 5 repeats for each valid *a*.
- Figures: `results/figures/task1/shor_circuit_a2.png`, `histogram_a2.png`.
- Histogram for a = 2: four peaks of ~25% each at 0, 64, 128, 192, giving phases 0, 0.25, 0.5, 0.75. r = 4 is recovered from 0.25 and 0.75; 0.5 gives the rejected candidate r = 2; 0 carries no information.
- Table 1 (draft): depth 16–29, gates 55–70, success ≈ 50% for a ∈ {2,4,7,8,11,13} (re-run: 49.4–50.8%), **0% for a = 14** because 14 ≡ −1 mod 15.
- RSA break: φ = 8, d = 7⁻¹ mod 8 = 7, c = 8 decrypts to m = 2.
- Analysis: why Shor's algorithm is probabilistic and must retry with new values of *a*.

**5.2 Task 2: ML-KEM key establishment**
- Alice and Bob end up with the same 32-byte secret (ss == ss′: True).
- Negative tests: a 1-bit change to ct gives a *different* secret with no error (implicit rejection); Eve's own key fails to recover ss.
- Session: HKDF → AES-256-GCM. A flipped ciphertext bit, altered AAD, or a key derived from a tampered ct all fail with `InvalidTag`.
- Table: ML-KEM-512/768/1024. Sizes pk 800/1,184/1,568; sk 1,632/2,400/3,168; ct 768/1,088/1,568 B. Times (Linux, 1,000 runs): keygen 0.012/0.016/0.020 ms. Figure `results/figures/task2/mlkem_benchmark.png`.

**5.3 Task 3: ML-DSA and tampering**
- Experiment A: VALID. Experiment B (RM 5,000 changed to RM 9,000: 2 of 608 bits): μ changes in 268 of 512 bits (avalanche effect), result INVALID.
- Extended matrix: **16 of 16 attacks rejected** (4 on the message, 7 on the signature, 3 on the key, 2 on the context string), plus 2 controls accepted. Highlight the "Mallory's σ verifies under Mallory's pk" control.
- Table: ML-DSA-44/65/87. pk 1,312/1,952/2,592; sk 2,560/4,032/4,896; σ 2,420/3,309/4,627 B. Signing σ/mean ≈ 60% shows the rejection-sampling tail. Figure `results/figures/task3/mldsa_benchmark.png`.

**5.4 Task 4: Classical vs PQC benchmark** (draft §5, Tables 4–5)
- Metrics (the rubric asks for at least 3; we report 4): wall-clock time, CPU time, key/ciphertext/signature sizes, communication overhead. 200 runs, mean ± std. Figures `results/figures/task4/kem_comparison.png`, `signature_comparison.png`.
- Analysis in four parts. **Security:** note the mismatch in NIST levels. **Performance:** compared with RSA, ML-KEM-768 keygen is ~650× faster; compared with ECC, ~7.5× slower but < 1 ms. **Size:** 35.5× (ML-KEM-768 vs X25519 handshake), 54.8× (ML-DSA-65 vs Ed25519 pk + σ). **Communication:** MTU fragmentation, 802.15.4 frames, ledger storage.
- Takeaway: **the cost is size, not speed.** This drives the design in §6.

## 6. Proposed Quantum-Safe Application

> *Template: present the selected problem, architecture and proposed solution.* · Rubric criterion 5 (architecture, threat assumptions, security purpose).

- **6.1 Environment and problem:** a permissioned blockchain (inter-bank settlement / supply chain). Three reasons it is demanding: long-lived signatures, HNDL-sensitive submissions, permanent replication.
- **6.2 Threat model:** attacker capabilities (read, modify, replay, inject, alter stored blocks, future CRQC), assets, and out-of-scope items (key extraction from endpoints, consensus attacks, side channels). Trusted-registry assumption.
- **6.3 Security requirements:** R1–R6 table from the draft.
- **6.4 Architecture:** the draft's diagram, redrawn as a proper figure for the Word version. Wallet → hybrid secure channel → validator → hash-linked ledger, with the trusted registry.
- **6.5 Component roles:** the draft table mapping component → mechanism → requirement → justification.
- **6.6 Original contribution: size-aware ledger design.** Binary encoding (σ goes from 6,618 hex characters to 3,309 B) and checkpointed signature pruning. Also the `alg_id` field for crypto-agility.
- **6.7 Prototype scope:** say clearly what Task 5 implements (ML-DSA-65 wallets, address = SHA-256(pk), registry, fingerprint-pinned ML-KEM-768 → HKDF → AES-256-GCM with AAD, nonce and balance checks, SHA-256 chain) and what is only proposed (hybrid KEM, signed registry, pruning, consensus).

## 7. Security and Performance Discussion

> *Template: evaluate security, performance, deployment and limitations.*

**7.1 Security evaluation**
- Prototype attack results, each mapped to a requirement: **replay** rejected (`expected 1, got 0`, R4); **ciphertext tamper** rejected (`InvalidTag`, R2/R3); **KEM key substitution** rejected (fingerprint mismatch, R2); **ledger mutation** detected (`chain valid: False`, R3).
- Property table (confidentiality, integrity, authentication, quantum resistance) with the remaining gap for each: registry as trust anchor, Module-LWE monoculture, and the decision not to use hybrid signatures.

**7.2 Performance evaluation**
- Task 5 evaluation over 50 transactions: sign/verify, encaps/decaps, AES-GCM, end-to-end latency, throughput, ledger growth (**7,050 B/tx**, about 94% of which is the hex signature), full-chain validation time.
- Report the run's machine next to the numbers (see the warning below). Point out that the public-key layer dominates processing time while AES-GCM is negligible.

**7.3 Deployment**
- Servers and validators can deploy this today (liboqs, OpenSSL ≥ 3.5).
- Constrained clients (4 KB sk, 27+ 802.15.4 frames per signature): options are ML-DSA-44, gateway delegation, or FN-DSA.
- Migrating existing ledgers: re-keying accounts, and accounts whose keys are lost. NIST 2030/2035 deadlines.

**7.4 Limitations**
- Shor: compiled using the known answer, noise-free simulator.
- Benchmarks: a single machine per dataset, Python bindings, mismatched NIST levels, no energy or memory measurements.
- Prototype: no consensus layer, network transport, hybrid KEM, pruning or side-channel hardening.

## 8. Future Work

> *Template: discuss potential improvements.* (Promoted from draft §7.5.)

1. Implement the hybrid X25519 + ML-KEM-768 channel and checkpoint pruning, then measure the actual storage saved.
2. Run a general modular-exponentiation Shor circuit (e.g. N = 21) to show how resources grow with N; run on noisy simulators or IBM hardware.
3. Benchmark on embedded hardware (ARM Cortex-M4 / pqm4) and add memory and energy measurements.
4. Compare ML-DSA with FN-DSA and SLH-DSA in the ledger to test the trade-off between size, speed and assumption diversity.
5. Add level-matched classical baselines (P-384/P-521, RSA-7680) and run every benchmark on one machine.
6. Add a multi-node consensus layer and constant-time / side-channel review.

## 9. Conclusion

> *Template: summarise the major findings.* Answer the research question in 4 short points:

1. **Threat:** RSA, DH and ECC all reduce to period finding, which Shor's algorithm solves. Our simulation shows the full mechanism from period finding to private-key recovery, and resource estimates show the engineering gap closing.
2. **Remedy:** larger keys cannot fix a polynomial-time attack. Module-LWE offers worst-case hardness with no known quantum shortcut.
3. **Cost:** PQC is faster than RSA but 35–55× larger than ECC. Bandwidth and storage matter more than CPU time.
4. **Integration:** the ledger design treats size, identity binding, hybrid key exchange and crypto-agility as first-class concerns. Migration is a systems-engineering problem.

## References

- Keep draft references [1]–[21] in IEEE style and re-number them in order of first citation after the restructure.
- Add tool references required by the brief: Qiskit [IBM], Open Quantum Safe / liboqs, `cryptography` (OpenSSL backend), and optionally PQClean.
- Check [12] (NIST IR 8547): confirm the edition and date you cite (initial public draft vs final).

---

## Rubric Coverage Checklist

| Rubric criterion (20% each) | "Excellent" descriptor needs | Where it is covered |
|---|---|---|
| 1. Shor's algorithm | Key stages (period finding, QFT/measurement, classical post-processing), correct interpretation, simulation limitations | §2.2, §2.3, §5.1, §7.4 |
| 2. ML-KEM | KeyGen/Encaps/Decaps, shared-secret agreement, role in PQ security | §3, §4.2, §5.2 |
| 3. ML-DSA + tampering | Sign/verify, meaningful tampering tests, integrity and authenticity implications | §4.3–4.4, §5.3 |
| 4. Benchmarking | Systematic, appropriate metrics, clear presentation, critical analysis | §5.4 (tables + 2 graphs + 4-part analysis) |
| 5. Quantum-safe prototype | Functional, correct PQC workflow, architecture, threat assumptions, security purpose | §6, §7.1–7.2 |
| General | "Not just running toolkit examples": modification, experimentation, explanation | Negative tests, 16-attack matrix, a = 14 failure analysis, size-aware design (§6.6) |
| Deliverable C | Screenshots, tables, graphs | Figures listed above. `results/screenshots/` is currently **empty**, so capture terminal screenshots for each task. |

## Issues Found While Running the Repo (fix before submission)

| # | Issue | Impact on the paper |
|---|---|---|
| 1 | **Datasets come from different machines.** Task 2/3 JSON: Linux x86_64. Task 4 JSON: Windows 11 / Intel. Draft Task 5 figures (2.88 ms, 317 tx/s): unlabelled. Today's macOS re-run of Task 5: 0.32 ms end-to-end, ~3,047 tx/s. | Label the machine on every table. Don't compare absolute times across tables. The draft says Windows is ~10× slower than Linux because of "wrapper overhead", but both runs use the same Python wrapper, so the gap more likely comes from the liboqs build or CPU. Reword this, or re-run Tasks 2–5 on one machine. |
| 2 | Ratios such as "RSA verify is 19× faster than ML-DSA-65" hold only for the Windows Task 4 data. | Cite the Task 4 dataset explicitly for these ratios. |
| 3 | `task1_shor/main.py` has no argument parsing, so `--a 14` and `--experiments` (documented in the README) are ignored and the script always runs a = 2 plus the full experiment. | No a = 14 screenshot can be produced as documented. Either add the flags or correct the README. |
| 4 | Task 2 prints `PART 2: Negative tests (TODO: CHECK WITH DR MANMEET ...)`. | Remove before taking screenshots. |
| 5 | README Task 5 checklist items are still unchecked. | Tick them once the paper covers them. |
| 6 | Tests: `pytest`: 36 passed, 32 subtests passed. | Can be cited as verification evidence (FIPS sizes are checked). |
