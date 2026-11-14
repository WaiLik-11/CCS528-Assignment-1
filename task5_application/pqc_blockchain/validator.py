"""Transaction validation: signature, address, nonce, balance and fields."""
from common.pqc import PQCSigner
from .wallet import SIG_NAME
from .ledger import Ledger
from .registry import Registry

class Validator:
    def __init__(self, registry: Registry, ledger: Ledger, signer: PQCSigner):
        self.registry = registry
        self.ledger = ledger
        self.signer = signer
        self.next_nonce: dict[str, int] = {}
        for block in ledger.blocks:
            for tx in block.transactions:
                sender = tx["sender"]
                nonce = tx["nonce"]
                expected_nonce = self.next_nonce.get(sender, 0)
                if nonce != expected_nonce:
                    raise ValueError(
                        f"Ledger contains invalid nonce sequence for {sender!r}"
                    )
                self.next_nonce[sender] = nonce + 1

    def validate_transaction(self, tx) -> tuple[bool, str]:
        # Validate basic transaction fields: amount, nonce, sender/recipient presence and uniqueness
        # Attacks stopped: invalid amounts, negative or non-integer nonces, missing or self-transfers
        if not isinstance(tx.amount, int) or isinstance(tx.amount, bool) or tx.amount <= 0:
            return False, "Amount must be a positive integer"
        if not isinstance(tx.nonce, int) or tx.nonce < 0:
            return False, "Invalid nonce"
        if not tx.sender or not tx.recipient or tx.sender == tx.recipient:
            return False, "Invalid sender/recipient"

        # Validate sender's registration against the registry
        # Attacks stopped: unregistered sender
        try:
            public_key = self.registry.get_wallet_key(tx.sender)
        except KeyError:
            return False, "Sender is not registered"

        # Validate the transaction's ML-DSA signature against the sender's registered public key
        # Attacks stopped: forged or tampered transactions
        if not PQCSigner.verify(public_key, tx.signing_bytes(), tx.signature, SIG_NAME):
            return False, "ML-DSA signature verification failed"

        # Validate the transaction's nonce against the expected sequence
        # Attacks stopped: replay attacks, out-of-order transactions
        expected_nonce = self.next_nonce.get(tx.sender, 0)
        if tx.nonce != expected_nonce:
            return False, f"Replay/nonce failure: expected {expected_nonce}, got {tx.nonce}"

        if self.ledger.balances.get(tx.sender, 0) < tx.amount:
            return False, "Insufficient balance"

        return True, "Accepted"

    def accept(self, tx) -> tuple[bool, str]:
        ok, reason = self.validate_transaction(tx)
        if not ok:
            return False, reason
        self.ledger.add_transaction(tx, self.signer)
        self.next_nonce[tx.sender] = tx.nonce + 1
        return True, "Accepted and appended to ledger"
