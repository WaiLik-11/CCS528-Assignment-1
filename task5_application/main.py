"""CLI demo for the post-quantum permissioned blockchain PoC."""
import argparse

from cryptography.exceptions import InvalidTag

from common.display import boolean_colour, flip_bit, format_colour, preview, section
from common.pqc import PQCKEMRecipient, PQCSigner, sha256
from .pqc_blockchain.transaction import Transaction, canonical_json
from .pqc_blockchain.wallet import SIG_NAME, Wallet
from .pqc_blockchain.registry import Registry
from .pqc_blockchain.ledger import BLOCK_CONTEXT, Ledger
from .pqc_blockchain.validator import Validator
from .pqc_blockchain.node import ValidatorNode
from .pqc_blockchain.secure_channel import KEM_NAME, encrypt_submission

def build_demo(alice_balance: int = 100):
    alice = Wallet("Alice")
    bob = Wallet("Bob")
    validator_kem = PQCKEMRecipient(KEM_NAME)
    validator_signer = PQCSigner(SIG_NAME)
    registry = Registry()
    alice_address = registry.register_wallet(alice.public_key)
    bob_address = registry.register_wallet(bob.public_key)
    assert alice_address == alice.address
    assert bob_address == bob.address
    registry.register_validator_kem_key(validator_kem.public_key)
    registry.register_validator_signing_key(validator_signer.public_key)

    ledger = Ledger(registry.validator_signing_key())
    ledger.set_initial_balance(alice.address, alice_balance)
    ledger.set_initial_balance(bob.address, 0)
    validator = Validator(registry, ledger, validator_signer)
    node = ValidatorNode(validator_kem, validator)
    return alice, bob, registry, ledger, validator, node

def short(hex_string: str) -> str:
    return hex_string[:16] + "..."

def print_balances(ledger, wallets) -> None:
    print("  Balances: " + ", ".join(f"{w.label} = {ledger.balances.get(w.address, 0)}" for w in wallets))

# --------------------------------------------------------------------------
# Part 1: wallets, trusted registry and genesis ledger
# --------------------------------------------------------------------------
def show_setup(alice, bob, registry, ledger) -> None:
    section(f"PART 1: Permissioned network setup ({SIG_NAME} wallets, {KEM_NAME} validator)")

    print(f"\n[Step 1] Wallet key generation ({SIG_NAME})")
    for wallet in (alice, bob):
        print(f"  {wallet.label}: pk {preview(wallet.public_key)}")
        print(f"    address = SHA-256(pk) = {short(wallet.address)}")
    print(format_colour("  The private signing key never leaves each wallet's liboqs context."))

    print("\n[Step 2] Trusted registry")
    print("  Registered wallets: Alice, Bob (address -> ML-DSA public key)")
    print(f"  Validator {KEM_NAME} pk: {preview(registry.validator_kem_key())}")
    print(f"  Pinned fingerprint SHA-256(pk): {short(registry.validator_kem_fingerprint())}")
    print(f"  Validator {SIG_NAME} block-signing pk: {preview(registry.validator_signing_key())}")
    print(format_colour("  The validator has two key pairs: ML-KEM to receive submissions, ML-DSA to sign blocks."))
    print(format_colour("  Assumption: the registry is trusted, like a PKI. Senders and ledger readers use it to check the validator's keys."))

    print("\n[Step 3] Genesis block")
    print(f"  Block 0 hash: {short(ledger.blocks[0].block_hash)} (fixed and well known, so it is not signed)")
    print_balances(ledger, [alice, bob])

# --------------------------------------------------------------------------
# Part 2: one transaction from wallet to ledger
# --------------------------------------------------------------------------
def normal_demo():
    alice, bob, registry, ledger, validator, node = build_demo()
    show_setup(alice, bob, registry, ledger)
    section("PART 2: Normal operation (Alice pays Bob 25)")

    print(f"\n[Step 4] Alice creates and signs the transaction ({SIG_NAME})")
    tx = alice.create_transaction(bob.address, 25, nonce=0)
    print(f"  sender {short(tx.sender)}  recipient {short(tx.recipient)}  amount {tx.amount}  nonce {tx.nonce}")
    print(f"  Signed bytes: canonical JSON, {len(tx.signing_bytes())} bytes")
    print(f"  Signature: {preview(tx.signature)}")
    print(format_colour("  Authenticity: only Alice's sk can produce a signature that her registered pk accepts."))

    print("\n[Step 5] Alice checks the validator's KEM public key against the registry pin")
    # In a real deployment the key arrives over the network, so the sender must
    # compare it with a fingerprint obtained from a trusted source.
    trusted_kem_pk = registry.validator_kem_key()
    trusted_fingerprint = registry.validator_kem_fingerprint()
    print(f"  SHA-256(received pk): {short(sha256(trusted_kem_pk).hex())}")
    print(f"  Pinned fingerprint:   {short(trusted_fingerprint)}")

    print(f"\n[Step 6] Alice encrypts the submission ({KEM_NAME} -> HKDF-SHA-256 -> AES-256-GCM)")
    envelope = encrypt_submission(trusted_kem_pk, tx.to_bytes(), trusted_fingerprint)
    print(f"  KEM ciphertext (encapsulated shared secret): {preview(envelope['kem_ciphertext'])}")
    print(f"  AES-GCM nonce: {envelope['nonce'].hex()}")
    print(f"  AES-GCM ciphertext+tag: {len(tx.to_bytes())} B plaintext -> {preview(envelope['ciphertext'])}")
    print(f"  Envelope fields visible on the network: {', '.join(envelope)}")
    print(format_colour("  Sender, recipient, amount, nonce and signature are all inside the AES-GCM ciphertext."))
    print(format_colour("  Alice -> validator: the envelope travels over the untrusted network"))

    print("\n[Step 7] Validator node decapsulates, decrypts and validates")
    ok, message = node.receive(envelope)
    print(f"  Checks: registered sender, address = SHA-256(pk), {SIG_NAME} signature, nonce, balance")
    print(f"  Result: {boolean_colour(ok)} ({message})")

    print("\n[Step 8] Ledger append")
    block = ledger.blocks[-1]
    # In a real deployment, there will be multiple transactions and the block would be appended to the chain after consensus from multiple validators.
    print(f"  Block {block.index}: previous_hash {short(block.previous_hash)}  block_hash {short(block.block_hash)}")
    print(f"  Validator signature over block_hash ({SIG_NAME}, ctx '{BLOCK_CONTEXT.decode()}'): {preview(block.validator_signature)}")
    print_balances(ledger, [alice, bob])
    print(f"  Chain valid (hashes, links, validator signatures): {boolean_colour(ledger.validate_chain())}")

    return alice, ledger, validator, node, registry, envelope, tx

def attack_result(action) -> str:
    """Run one attack. action() returns (accepted, reason) or raises when a check rejects it."""
    try:
        accepted, reason = action()
    except (InvalidTag, ValueError) as exc:
        accepted, reason = False, type(exc).__name__ + (f": {exc}" if str(exc) else "")
    if accepted:
        return format_colour(f"ACCEPTED ({reason}), the attack worked", "yellow")
    return format_colour(f"REJECTED ({reason})", "red")

# --------------------------------------------------------------------------
# Part 3: attacks, in the order a transaction travels (network, sender, validator, storage)
# --------------------------------------------------------------------------
def attack_demo():
    alice, ledger, validator, node, registry, envelope, tx = normal_demo()
    validator_pk = registry.validator_kem_key()
    pin = registry.validator_kem_fingerprint()
    mallory = Wallet("Mallory")  # has her own ML-DSA key pair but is not in the registry

    def submit(transaction):
        # The validator's KEM public key is public, so Mallory can build a valid envelope herself.
        return node.receive(encrypt_submission(validator_pk, transaction.to_bytes(), pin))

    section("PART 3: Attack scenarios (every attempt must be rejected)")
    # Mallory can read the ledger, so she has Alice's signed transaction from block 1.
    copied = Transaction.from_bytes(canonical_json(ledger.blocks[1].transactions[0]))

    print("\n[Attack 1] Replay: Mallory resubmits Alice's transaction copied from block 1")
    print("  The ML-DSA signature is still valid: these are exactly the bytes Alice signed")
    print(f"  Expected: rejected by the nonce check (Alice's next nonce is {validator.next_nonce[alice.address]})")
    print(f"  Result: {attack_result(lambda: submit(copied))}")
    print(format_colour("  A signature proves who signed, not how often it may be used. The nonce makes each transfer single-use."))

    print("\n[Attack 2] Envelope tampering: Mallory flips one bit of Alice's envelope in transit")
    print("  Expected: rejected by AES-GCM, InvalidTag")
    for field in envelope:
        tampered = dict(envelope, **{field: flip_bit(envelope[field])})
        print(f"  {field:<15} {attack_result(lambda: node.receive(tampered))}")
    print(format_colour("""  The GCM tag covers the ciphertext and nonce, and HKDF ties the AES key to the KEM
  ciphertext. Mallory cannot compute a new tag without the key."""))

    print("\n[Attack 3] KEM key substitution: Mallory sends Alice her own ML-KEM public key")
    mallory_kem = PQCKEMRecipient(KEM_NAME)
    print(f"  SHA-256(Mallory's pk): {short(sha256(mallory_kem.public_key).hex())}")
    print(f"  Pinned fingerprint:    {short(pin)}")
    print("  Expected: Alice refuses to encapsulate, so Mallory never gets a ciphertext she can open")

    def encrypt_to_mallory():
        encrypt_submission(mallory_kem.public_key, tx.to_bytes(), pin)
        return True, "envelope encrypted to Mallory's key"
    print(f"  Result: {attack_result(encrypt_to_mallory)}")
    print(format_colour("  The pin is only as trustworthy as the registry it came from (our PKI assumption)."))

    print("\n[Attack 4] Modification after signing: Mallory redirects Alice's transaction to herself")
    modified = Transaction.from_bytes(copied.to_bytes())
    modified.recipient, modified.amount, modified.nonce = mallory.address, 75, 1
    print(f"  recipient -> Mallory {short(mallory.address)}, amount 25 -> 75, nonce 0 -> 1 (so the nonce check passes)")
    print("  Alice's original signature is kept")
    print(f"  Expected: rejected by {SIG_NAME} verification")
    print(f"  Result: {attack_result(lambda: submit(modified))}")
    print(format_colour("  The signature covers every field, so any change breaks it (integrity)."))

    print("\n[Attack 5] Impersonation: Mallory signs a transfer from Alice's address with her own key")
    forged = Transaction(sender=alice.address, recipient=mallory.address, amount=75, nonce=1, timestamp=tx.timestamp)
    forged.signature = mallory.signer.sign(forged.signing_bytes())
    print(f"  Signature by Mallory's sk: {preview(forged.signature)}")
    print(f"  Expected: rejected, because the registry returns Alice's pk and Mallory's signature does not verify")
    print(f"  Result: {attack_result(lambda: submit(forged))}")
    print(format_colour("  Only Alice's sk can sign for Alice's address (authenticity)."))

    print("\n  After attacks 1-5:")
    print_balances(ledger, [alice, mallory])
    print(f"  Blocks: {len(ledger.blocks)}  Chain valid: {boolean_colour(ledger.validate_chain())}")

    print("\n[Attack 6] Ledger tampering: Mallory edits block 1 in storage (amount 25 -> 999)")
    block = ledger.blocks[1]
    block.transactions[0]["amount"] = 999
    print(f"  Stored block_hash: {short(block.block_hash)}  recomputed: {short(block.calculate_hash())}")
    print("  (a) Edit only - Expected: hash mismatch")
    print(f"      Chain valid: {boolean_colour(ledger.validate_chain())}")

    block.seal()
    print("  (b) Also recompute block_hash - Expected: the validator's signature no longer matches the new hash")
    print(f"      Chain valid: {boolean_colour(ledger.validate_chain())}")

    block.validator_signature = mallory.signer.sign(bytes.fromhex(block.block_hash), BLOCK_CONTEXT)
    print("  (c) Also re-sign with her key - Expected: does not verify under the pinned validator pk")
    print(f"      Chain valid: {boolean_colour(ledger.validate_chain())}")
    print(format_colour("""  Hash links detect edits, and ML-DSA block signatures stop anyone without the validator's
  sk from rewriting history, even after recomputing every hash."""))
    print(format_colour("""  LIMITATION: the validator itself (or anyone who steals its sk) could still rewrite history.
  Real blockchains remove this single point of trust with consensus among many validators; this PoC has one.
  Balances are also not recomputed from the chain, so the edit did not move any funds.""", "yellow"))

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
