# Task 5: Post-Quantum Secure Blockchain Transactions (APPLY)

This prototype demonstrates a minimal, local, permissioned blockchain workflow using:

- ML-DSA-65 digital signatures (FIPS 204)
- ML-KEM-768 key-establishment (FIPS 203)
- HKDF-SHA-256 key derivation
- AES-256-GCM payload encryption
- SHA-256 hash-linked blocks
- Public-key-derived wallet addresses and a trusted validator registry

Users authorize transfers with ML-DSA-65, the transaction payload is encrypted with ML-KEM-768 + HKDF + AES-256-GCM, and accepted transactions are appended to a hash-linked ledger.

> This is a local PoC, not a distributed blockchain implementation. It intentionally excludes consensus, network-wide validation, persistent storage, and full production key management.

## 1. Security problem and threat model

A future quantum computer could break classical public-key cryptography. This prototype focuses on three goals:

| Concern | Mechanism |
|---|---|
| Transaction authenticity | ML-DSA-65 signature verified against the sender's registered public key |
| Confidentiality in transit | ML-KEM-768 shared secret, HKDF, AES-256-GCM |
| Ledger integrity | SHA-256 hash links and `ledger.validate_chain()` |

- Attacker can: read or tamper with network traffic, forge submitted transactions, replay captured transactions, and alter stored blocks.
- Attacker cannot: steal private keys or break ML-DSA, ML-KEM, or AES.
- Assets: wallet balances, signed transactions, encrypted payloads, ledger history.
- Out of scope: consensus, large-scale deployment, full PKI, side-channel hardening, real money.

## 2. Architecture

```text
Alice wallet                  Secure channel                   Validator node              Ledger
creates tx +    -->  ML-KEM-768 -> HKDF -> AES-256-GCM  -->  decrypt, verify,       -->  hash-linked blocks,
ML-DSA signature                                             nonce/balance checks,       balances, nonces,
                                                             signature validation        rejection log
```

The implementation is split into the following modules:

| Module | Purpose |
|---|---|
| `task5_application/main.py` | CLI entry point that runs the normal and attack demos |
| `task5_application/pqc_blockchain/wallet.py` | Wallet creation, address derivation, signed transactions |
| `task5_application/pqc_blockchain/registry.py` | Trusted wallet registry and pinned validator KEM key |
| `task5_application/pqc_blockchain/transaction.py` | Canonical transaction encoding and signing helpers |
| `task5_application/pqc_blockchain/secure_channel.py` | ML-KEM + HKDF + AES-GCM submission envelope |
| `task5_application/pqc_blockchain/validator.py` | Acceptance checks: signature, nonce, balance, and sender validity |
| `task5_application/pqc_blockchain/ledger.py` | Genesis block, transaction blocks, hash-chain validation |
| `task5_application/pqc_blockchain/node.py` | Decrypts a submission and passes it to the validator |
| `task5_application/evaluation.py` | Timing, size, and throughput measurements |

## 3. Transaction model

Transactions are encoded using canonical JSON bytes and signed over those bytes:

```text
Transaction { sender, recipient, amount, nonce, timestamp }
canonical bytes = sorted keys, compact JSON, UTF-8
signature = ML-DSA-65 over signing bytes
```

The sender nonce prevents same-chain replay, and each block stores the hash of the previous block so the chain can detect mutation.

## 4. Attack experiments covered

| # | Attack | Security mechanism | Expected detection |
|---|---|---|---|
| 1 | Replay an accepted transaction | Per-sender nonce + validator nonce check | the second submission is rejected because the expected nonce has already been used |
| 2 | Tamper with ciphertext | AES-256-GCM authentication tag and AAD binding | decryption fails with an integrity error because the tag no longer matches |
| 3 | Swap the validator KEM public key | trusted public-key fingerprint check before ML-KEM encapsulation | `encrypt_submission()` rejects the mismatched validator key before the encrypted payload is created |
| 4 | Modify a historical block | SHA-256 hash chaining in `Ledger.validate_chain()` | the chain no longer hashes correctly and `validate_chain()` returns `False` |
| 5 | Change the amount or recipient after signing | ML-DSA-65 signature verification over canonical bytes | transaction verification fails because the signed payload no longer matches |
| 6 | Attempt to impersonate another wallet | ML-DSA verification against the registered sender public key | the attacker-supplied signature does not verify for the registered identity, so the transaction is rejected |

## 5. Running the demo

Run everything from the repository root:

```bash
uv run python -m task5_application.main --mode normal
uv run python -m task5_application.main --mode attacks
uv run python -m task5_application.evaluation
```

To validate the logic with the included tests:

```bash
uv run pytest tests/task5_test.py -v
```

## 6. Notes

- Wallet addresses are derived from the SHA-256 hash of the ML-DSA public key.
- The registry trusts the validator KEM public key fingerprint before a sender encrypts a fresh KEM ciphertext.
- The prototype is designed for coursework demonstration and is not intended as a production-grade blockchain implementation.
