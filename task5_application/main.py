"""CLI demo for the post-quantum permissioned blockchain PoC."""
import argparse
from common.pqc import PQCKEMRecipient, kem_encapsulate
from .pqc_blockchain.wallet import Wallet
from .pqc_blockchain.registry import Registry
from .pqc_blockchain.ledger import Ledger
from .pqc_blockchain.validator import Validator
from .pqc_blockchain.node import ValidatorNode
from .pqc_blockchain.secure_channel import encrypt_submission

def build_demo():
    alice = Wallet("Alice")
    bob = Wallet("Bob")
    validator_kem = PQCKEMRecipient()
    registry = Registry()
    alice_address = registry.register_wallet(alice.public_key)
    bob_address = registry.register_wallet(bob.public_key)
    assert alice_address == alice.address
    assert bob_address == bob.address
    registry.register_validator_kem_key(validator_kem.public_key)

    ledger = Ledger()
    ledger.set_initial_balance(alice.address, 100)
    ledger.set_initial_balance(bob.address, 0)
    validator = Validator(registry, ledger)
    node = ValidatorNode(validator_kem, registry, validator)
    return alice, bob, registry, ledger, validator, node, validator_kem

def normal_demo():
    alice, bob, registry, ledger, validator, node, kem = build_demo()
    tx = alice.create_transaction("Bob", 25, nonce=0)
    
    # In a real deployment, the sender would obtain this public key through
    # an authenticated registry/PKI, not trust an arbitrary network response.
    trusted_kem_pk = registry.validator_kem_key()
    trusted_fingerprint = registry.validator_kem_fingerprint()

    # Demonstrate KEM agreement without displaying the secret itself.
    demo_ct, sender_ss = kem_encapsulate(trusted_kem_pk)
    validator_ss = kem.decapsulate(demo_ct)
    print("ML-KEM shared-secret agreement:", sender_ss == validator_ss)

    # Encrypt the transaction payload to the validator's pinned KEM public key.
    envelope = encrypt_submission(trusted_kem_pk, tx.to_bytes(), trusted_fingerprint)

    # The validator node receives the encrypted envelope, decapsulates the KEM ciphertext,
    # decrypts the payload, and validates the transaction.
    ok, message = node.receive(envelope)
    print("[NORMAL]", ok, message)

    print("Balances:", {
        alice.label: ledger.balances.get(alice.address, 0),
        bob.label: ledger.balances.get(bob.address, 0),
    })
    print("Wallet addresses:", {alice.label: alice.address, bob.label: bob.address})
    print("Ledger valid:", ledger.validate_chain())

    return alice, ledger, validator, node, registry, kem, envelope, tx

def attack_demo():
    alice, ledger, validator, node, registry, kem, envelope, tx = normal_demo()

    # Replay: submit the exact same signed transaction a second time.
    replay_envelope = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
    replay_ok, replay_msg = node.receive(replay_envelope)
    print("[ATTACK: REPLAY]", replay_ok, replay_msg)

    # Ciphertext tampering: modify authenticated ciphertext bytes.
    bad = dict(envelope)
    bad["ciphertext"] = bytes([bad["ciphertext"][0] ^ 1]) + bad["ciphertext"][1:]
    try:
        node.receive(bad)
        print("[ATTACK: CIPHERTEXT TAMPER] ERROR: accepted unexpectedly")
    except Exception as exc:
        print("[ATTACK: CIPHERTEXT TAMPER] rejected:", type(exc).__name__)

    # Key substitution: sender encrypts to an attacker-controlled KEM public key
    # instead of the registry-pinned validator public key. The real validator
    # cannot decapsulate this envelope successfully.
    attacker_kem = PQCKEMRecipient()
    try:
        # The attacker's public key does not match the trusted validator pin.
        encrypt_submission(attacker_kem.public_key, tx.to_bytes(), registry.validator_kem_fingerprint())
        print("[ATTACK: KEM KEY SUBSTITUTION] ERROR: accepted unexpectedly")
    except Exception as exc:
        print("[ATTACK: KEM KEY SUBSTITUTION] rejected:", type(exc).__name__, str(exc))

    # Ledger tampering: modify a historical block's transaction data.
    if len(ledger.blocks) > 1:
        ledger.blocks[1].transactions[0]["amount"] = 999
    print("[ATTACK: LEDGER TAMPER] chain valid:", ledger.validate_chain())

def main():
    parser = argparse.ArgumentParser(description="PQC blockchain transaction PoC")
    parser.add_argument("--mode", choices=["normal", "attacks"], default="normal")
    args = parser.parse_args()
    if args.mode == "normal":
        normal_demo()
    else:
        attack_demo()

if __name__ == "__main__":
    main()
