"""Transaction validation: signature, address, nonce, balance and fields."""
from common.pqc import PQCSigner
from .wallet import SIG_NAME, wallet_address

class Validator:
    def __init__(self, registry, ledger):
        self.registry = registry
        self.ledger = ledger
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
        if not isinstance(tx.amount, int) or isinstance(tx.amount, bool) or tx.amount <= 0:
            return False, "Amount must be a positive integer"
        if not isinstance(tx.nonce, int) or tx.nonce < 0:
            return False, "Invalid nonce"
        if not tx.sender or not tx.recipient or tx.sender == tx.recipient:
            return False, "Invalid sender/recipient"
        try:
            public_key = self.registry.get_wallet_key(tx.sender)
        except KeyError:
            return False, "Sender is not registered"

        if wallet_address(public_key) != tx.sender:
            return False, "Wallet address/public-key mismatch"

        if not PQCSigner.verify(public_key, tx.signing_bytes(), tx.signature, SIG_NAME):
            return False, "ML-DSA signature verification failed"

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
        self.ledger.add_transaction(tx)
        self.next_nonce[tx.sender] = tx.nonce + 1
        return True, "Accepted and appended to ledger"
