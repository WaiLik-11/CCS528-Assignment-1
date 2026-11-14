# Task 4: COMPARE, Classical versus Post-Quantum Cryptography

```bash
uv run python -m task4_benchmark.main                # 100 runs per operation (default)
uv run python -m task4_benchmark.main --runs 200      # more repeats, steadier mean/std, slower (RSA keygen dominates)
```

Outputs: `results/data/task4/{comparison.json, kem_comparison.csv, signature_comparison.csv}` and `results/figures/task4/{kem_comparison.png, signature_comparison.png}`.

## 1. What the program does

Task 4 does not introduce any new cryptography. It takes the classical baselines (RSA, ECDH, ECDSA, Ed25519) and benchmarks them the same way, then re-uses `measure()` from [task2_mlkem/main.py](../task2_mlkem/main.py) and [task3_mldsa/main.py](../task3_mldsa/main.py) directly, so the ML-KEM/ML-DSA numbers are exactly the same code already proven correct in Tasks 2 and 3.

| Comparison | Classical | Post-quantum | Metrics recorded |
|---|---|---|---|
| Key establishment | RSA-3072-OAEP, ECDH-P256, X25519 | ML-KEM-512 / 768 / 1024 | keygen time (wall-clock + CPU), encaps time, decaps time, public-key size, ciphertext size, handshake bytes |
| Digital signatures | RSA-3072-PSS, ECDSA-P256, Ed25519 | ML-DSA-44 / 65 / 87 | keygen time (wall-clock + CPU), sign time, verify time, public-key size, signature size, signed-message bytes |

Every classical scheme is wrapped in the same `(keygen, encaps, decaps)` / `(keygen, sign, verify)` shape as the PQC schemes, so all rows can be timed with the same `sample_ms()`/`summarize()` helpers and placed in one table. `keygen_cpu` is a second, independent timer (CPU time, i.e. user+system time) measured with `sample_cpu_ms()`, useful because RSA key generation time varies a lot (it searches for large primes) — CPU time confirms whether that variance is real computation or just OS scheduling noise. "Handshake bytes" / "signed-message bytes" is the communication-overhead metric: how many bytes actually have to cross the network for one exchange.

## 2. Results (200 runs, Windows 11, Python 3.12, liboqs 0.16.0)

### Key establishment

| Scheme | PQ-safe | KeyGen (µs) | KeyGen CPU (µs) | Encaps (µs) | Decaps (µs) | Public key (B) | Ciphertext (B) | Handshake (B) |
|---|---|---|---|---|---|---|---|---|
| RSA-3072    | no  | 121,242 ± 78,738 | 112,500 ± 71,080 | 30.1 ± 1.5  | 1,306.5 ± 91.0 | 398  | 384  | 782  |
| ECDH-P256   | no  | 9.1 ± 0.4         | 8.8 ± 2.8         | 48.3 ± 1.5  | 41.1 ± 1.8    | 65   | 65   | 130  |
| X25519      | no  | 18.8 ± 1.5        | 17.5 ± 3.6         | 42.7 ± 15.9 | 23.1 ± 0.6    | 32   | 32   | 64   |
| ML-KEM-512  | yes | 110.8 ± 4.0       | 109.9 ± 25.0       | 141.0 ± 8.1 | 166.7 ± 5.6   | 800  | 768  | 1,568 |
| ML-KEM-768  | yes | 177.7 ± 5.4       | 177.0 ± 62.3       | 201.2 ± 28.4| 253.3 ± 19.5  | 1,184| 1,088| 2,272 |
| ML-KEM-1024 | yes | 262.2 ± 21.6      | 256.3 ± 96.2       | 290.4 ± 21.7| 346.0 ± 30.5  | 1,568| 1,568| 3,136 |

### Digital signatures

| Scheme | PQ-safe | KeyGen (µs) | KeyGen CPU (µs) | Sign (µs) | Verify (µs) | Public key (B) | Signature (B) | Signed message (B) |
|---|---|---|---|---|---|---|---|---|
| RSA-3072-PSS | no  | 117,992 ± 75,199 | 150,000 ± 122,235 | 1,383.5 ± 109.7 | 31.4 ± 2.4  | 398  | 384  | 782  |
| ECDSA-P256   | no  | 9.0 ± 0.3        | 9.3 ± 1.9          | 18.0 ± 0.6      | 46.6 ± 12.9 | 65   | 70   | 135  |
| Ed25519      | no  | 17.7 ± 0.6       | 17.9 ± 3.7         | 17.4 ± 0.6      | 48.2 ± 2.8  | 32   | 64   | 96   |
| ML-DSA-44    | yes | 317.9 ± 21.6     | 317.4 ± 61.4       | 1,356.7 ± 777.7 | 373.0 ± 43.2| 1,312| 2,420| 3,732 |
| ML-DSA-65    | yes | 565.6 ± 54.5     | 561.5 ± 114.8      | 1,813.9 ± 1,066.1| 606.8 ± 59.1| 1,952| 3,309| 5,261 |
| ML-DSA-87    | yes | 898.1 ± 50.6     | 878.9 ± 200.4      | 2,311.9 ± 1,234.8| 947.3 ± 64.8| 2,592| 4,627| 7,219 |

![Key establishment: classical vs ML-KEM](../results/figures/task4/kem_comparison.png)
![Signatures: classical vs ML-DSA](../results/figures/task4/signature_comparison.png)

## 3. Security, performance and resource trade-offs

- **Time:** every classical and PQC operation here finishes in well under 2.5 ms, except RSA-3072 key generation, which takes **~100–120 ms and swings wildly** (±65–78 ms) because it searches for two large random primes by trial division — a fundamentally different, much more expensive process than the lattice arithmetic ML-KEM/ML-DSA use. ECDH/X25519/Ed25519 keygen (a single scalar multiply) stays under 20 µs. ML-KEM and ML-DSA keygen are slightly slower than ECC (hundreds of µs, not single-digit µs) but still two to three orders of magnitude faster than RSA.
- **Size is the real cost of going post-quantum.** ML-KEM-768's 1,184-byte public key + 1,088-byte ciphertext (2,272 bytes/handshake) is about **17× larger** than X25519's 64-byte handshake. ML-DSA-65's 1,952-byte key + 3,309-byte signature (5,261 bytes) is roughly **39× larger** than Ed25519's 96 bytes. For a protocol with tight bandwidth (e.g. constrained IoT links), this is the dominant trade-off, not CPU time.
- **Security level isn't a fair like-for-like comparison.** RSA-3072/P-256/X25519/Ed25519 all sit at roughly NIST level 1 (~128-bit classical security); the table has no classical equivalent of ML-KEM-768/1024 or ML-DSA-65/87 (NIST levels 3 and 5), since classical schemes don't have a direct "level 3/5" classical counterpart in this comparison. Comparing ML-KEM-768 against RSA-3072 is therefore only approximate.
- **CPU time mostly confirms wall-clock time**, except for RSA-3072 keygen, where the CPU-time estimate (`keygen_cpu`) is itself noisy because it is averaged over only 20 repeats (to keep the benchmark fast) versus 200 repeats for wall-clock time — the two RSA numbers in the table above should be read as "both roughly 100–150 ms, both highly variable," not compared digit-for-digit.
- **Bottom line:** against RSA specifically, ML-KEM/ML-DSA are a win on both time and predictability, at the cost of bigger keys/signatures. Against ECC (ECDH/X25519/Ed25519), classical schemes are still faster and far smaller per operation — the price of quantum safety here is almost entirely extra bytes on the wire, not extra CPU time.

## 4. Limitations

- Single-machine, single-run numbers (Windows 11, Python 3.12); absolute values will differ on other hardware, though the relative ordering between schemes should not.
- `keygen_cpu` uses `time.process_time()`, which only advances in ~15 ms steps on Windows. Fast keygens (ECDH/X25519/ML-KEM/ML-DSA) are measured by batching many calls together (see `sample_cpu_ms()` in [common/timing.py](../common/timing.py)) so the result stays meaningful; CPU and memory usage under concurrent load are out of scope.
- Only one classical curve (P-256/X25519) and one RSA modulus size (3072-bit) are benchmarked; a full NIST-level-matched comparison would also need P-384/P-521 and larger RSA moduli.
