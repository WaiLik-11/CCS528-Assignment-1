"""Reproducible timing and serialized-size measurements for the local PoC."""
import argparse
import statistics
import time
from collections.abc import Callable

from common.pqc import (
    PQCKEMRecipient,
    PQCSigner,
    aes_gcm_encrypt,
    derive_aes_key,
    kem_encapsulate,
)
from .pqc_blockchain.ledger import Ledger
from .pqc_blockchain.secure_channel import KEM_NAME, encrypt_submission
from .pqc_blockchain.transaction import canonical_json
from .pqc_blockchain.wallet import SIG_NAME
from .main import build_demo

def median_ms(fn: Callable[[], object], repeats: int = 10) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)

def serialized_ledger_size(ledger: Ledger) -> int:
    """Estimate ledger size as compact JSON blocks, including each stored hash and validator signature."""
    return sum(
        len(canonical_json({
            **block.body(),
            "block_hash": block.block_hash,
            "validator_signature": block.validator_signature.hex(),
        }))
        for block in ledger.blocks
    )

def measure_transaction_workload(transaction_count: int, validation_repeats: int):
    alice, bob, registry, ledger, _, node = build_demo()
    ledger.set_initial_balance(alice.address, transaction_count)
    initial_size = serialized_ledger_size(ledger)
    latencies_ms = []

    workload_start = time.perf_counter()
    for nonce in range(transaction_count):
        transaction_start = time.perf_counter()
        tx = alice.create_transaction(bob.address, 1, nonce)
        envelope = encrypt_submission(
            registry.validator_kem_key(),
            tx.to_bytes(),
            registry.validator_kem_fingerprint(),
        )
        accepted, reason = node.receive(envelope)
        latencies_ms.append((time.perf_counter() - transaction_start) * 1000)
    workload_seconds = time.perf_counter() - workload_start

    final_size = serialized_ledger_size(ledger)
    validation_ms = median_ms(ledger.validate_chain, validation_repeats)

    return {
        "median_latency_ms": statistics.median(latencies_ms),
        "throughput_tps": transaction_count / workload_seconds,
        "ledger_growth_bytes": final_size - initial_size,
        "ledger_growth_bytes_per_transaction": (final_size - initial_size) / transaction_count,
        "ledger_size_bytes": final_size,
        "validation_median_ms": validation_ms,
    }

def run(repeats: int = 10, transactions: int = 50):
    message = b"evaluation transaction payload"

    signer = PQCSigner(SIG_NAME)
    recipient = PQCKEMRecipient(KEM_NAME)
    signature = signer.sign(message)
    kem_ct, shared_secret = kem_encapsulate(recipient.public_key, KEM_NAME)
    key = derive_aes_key(shared_secret, kem_ct, b"eval")
    _, ciphertext = aes_gcm_encrypt(key, message)

    print(f"{SIG_NAME} signature bytes:", len(signature))
    print(f"{KEM_NAME} ciphertext bytes:", len(kem_ct))
    print("AES-GCM ciphertext+tag bytes:", len(ciphertext))
    print(f"{SIG_NAME} key generation median ms:", f"{median_ms(lambda: PQCSigner(SIG_NAME), repeats):.3f}")
    print(f"{SIG_NAME} signing median ms:", f"{median_ms(lambda: signer.sign(message), repeats):.3f}")
    print(f"{SIG_NAME} verification median ms:", f"{median_ms(lambda: PQCSigner.verify(signer.public_key, message, signature, SIG_NAME), repeats):.3f}")
    print(f"{KEM_NAME} key generation median ms:", f"{median_ms(lambda: PQCKEMRecipient(KEM_NAME), repeats):.3f}")
    print(f"{KEM_NAME} encapsulation median ms:", f"{median_ms(lambda: kem_encapsulate(recipient.public_key, KEM_NAME), repeats):.3f}")
    print(f"{KEM_NAME} decapsulation median ms:", f"{median_ms(lambda: recipient.decapsulate(kem_ct), repeats):.3f}")
    print("AES-GCM encryption median ms:", f"{median_ms(lambda: aes_gcm_encrypt(key, message), repeats):.3f}")

    workload = measure_transaction_workload(transactions, repeats)
    print(f"Transactions measured: {transactions}")
    print("Complete transaction end-to-end median latency ms:", f"{workload['median_latency_ms']:.3f}")
    print("Transaction throughput transactions/second:", f"{workload['throughput_tps']:.3f}")
    print("Ledger growth bytes:", workload["ledger_growth_bytes"])
    print("Ledger growth bytes/transaction:", f"{workload['ledger_growth_bytes_per_transaction']:.1f}")
    print("Final serialized ledger size bytes:", workload["ledger_size_bytes"])
    print("Full-chain validation median ms:", f"{workload['validation_median_ms']:.3f}")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repeats", type=int, default=10,
        help="number of samples for median cryptographic/validation timings",
    )
    parser.add_argument(
        "--transactions", type=int, default=50,
        help="number of complete transactions in the throughput/ledger workload",
    )
    args = parser.parse_args()
    run(repeats=args.repeats, transactions=args.transactions)

if __name__ == "__main__":
    main()
