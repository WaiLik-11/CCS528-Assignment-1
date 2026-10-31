# Task 5: Post-Quantum Secure Blockchain Transactions (APPLY)

A small local, permissioned blockchain prototype. Users authorize transfers with **ML-DSA-65**, the transaction details travel to the node encrypted with **ML-KEM-768 + HKDF + AES-256-GCM**, and accepted transactions go into a **hash-linked ledger**.

> Prototype only. It does not make Bitcoin or Ethereum quantum-safe, has no real consensus, and does not demonstrate a quantum attack.

## 1. Security problem and threat model

Classical signature and key-exchange algorithms could be broken by a future quantum computer (Task 1). The prototype protects three things:

| Concern | Mechanism |
|---|---|
| Transaction authenticity | ML-DSA-65 signature checked against the sender's registered public key |
| Confidentiality in transit | ML-KEM-768 shared secret, HKDF, AES-256-GCM |
| Ledger integrity | SHA-256 hash links and `validate_chain()` |

- **Attacker can:** read and modify network traffic, submit transactions, resubmit captured ones, edit stored blocks.
- **Attacker cannot:** steal private keys or break ML-DSA/ML-KEM/AES.
- **Assets:** balances, signed transactions, private payloads, ledger history.
- **Out of scope:** consensus, a full chain rebuild by a powerful attacker, side channels, real money.

## 2. Architecture

```
Alice wallet            Secure channel               Validator node                Ledger
creates tx +    -->  ML-KEM-768 -> HKDF ->   -->  decrypt, then check:   -->  hash-linked blocks,
ML-DSA signature     AES-256-GCM                  chain_id, sender,           balances, nonces,
                                                  signature, nonce, balance   rejection log
```

Each part has one job:

| Component | Algorithm | Purpose |
|---|---|---|
| Transaction signature | ML-DSA-65 | Authenticity and integrity of the transaction |
| Node KEM key signed by the node's ML-DSA key | ML-DSA-65 | Stops key substitution (MITM) |
| Key establishment | ML-KEM-768 | Shared secret between client and node |
| Key derivation | HKDF-SHA256 | Turns the secret into an AES key |
| Payload encryption | AES-256-GCM | Confidentiality and tamper detection |
| Ledger | SHA-256 | Detects edits to stored blocks |

ML-KEM is used only for key establishment. ML-DSA is used only for signing.

## 3. Transaction format

```
Transaction{chain_id, sender, recipient, amount:int, nonce:int, timestamp}
signed bytes = canonical JSON (sorted keys, no spaces, UTF-8)
signature    = ML-DSA-65 over those bytes
```

`chain_id` blocks cross-chain replay, and the per-sender `nonce` blocks same-chain replay.

Validator checks run in this order: chain_id, sender registered, signature, nonce, amount > 0, sufficient balance. Each rejection has a reason code (`BAD_SIGNATURE`, `REPLAY`, `INSUFFICIENT_BALANCE`, ...).

## 4. Folder structure

```
common/pqc.py             ML-DSA, ML-KEM, HKDF, AES-GCM wrappers (shared by Tasks 2-5)
common/timing.py          timing helpers
common/results.py         save CSV/JSON results
task5_application/
  config.py               CHAIN_ID, algorithm names
  wallet.py               user keys (private keys go in gitignored keys/)
  registry.py             permissioned public-key registry
  transaction.py          tx format, canonical bytes, sign/verify
  secure_channel.py       ML-KEM -> HKDF -> AES-GCM envelope
  validator.py            acceptance rules
  ledger.py               Block, Chain, validate_chain()
  node.py                 decrypt -> validate -> append
  attacks.py              attack simulations
  evaluation.py           timings, sizes, graphs
  main.py                 CLI demo
tests/task5/              pytest tests
results/{data,figures,screenshots}/task5/
```

## 5. Attack experiments

| # | Attack | Expected result | Required |
|---|---|---|---|
| 1 | Change amount/recipient after signing | Signature fails, no balance change | Yes |
| 2 | Mallory signs as Alice | Verification against Alice's key fails | Yes |
| 3 | Replay an accepted transaction | Rejected: nonce already used | Yes |
| 4 | Capture or modify ciphertext | Unreadable; AES-GCM authentication fails | If time |
| 4b | Swap the node's ML-KEM public key | Client rejects: key signature invalid | If time |
| 5 | Edit an old block | `validate_chain()` reports the bad block | If time |

## 6. Running

```bash
uv sync
uv run python -m task5_application.main     # demo (once #14 is done)
uv run pytest tests/task5                   # tests
```

## 7. Work plan

Tracked in issue #5 with sub-issues #6-#14. Order: #6, #7, #8 in parallel, then #9, then #10 and #11, then #12, #13, #14. Use one branch per issue (for example `t5-1-pqc-wrappers`) and open a PR for the other person to review.