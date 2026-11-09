"""Wallet address is derived from its ML-DSA public key."""
import time
from common.pqc import PQCSigner, sha256
from .transaction import Transaction

SIG_NAME = "ML-DSA-65"

def wallet_address(public_key: bytes) -> str:
    """Derive a wallet address from an ML-DSA public key."""
    if not isinstance(public_key, bytes) or not public_key:
        raise ValueError("A non-empty ML-DSA public key is required")
    return sha256(public_key).hex()

class Wallet:
    def __init__(self, label: str):
        self.label = label  # Human-readable label for us to see in the demo; not part of the blockchain.
        self.signer = PQCSigner(SIG_NAME)
        self.public_key = self.signer.public_key
        self.address = wallet_address(self.public_key)

    def create_transaction(self, recipient: str, amount: int, nonce: int) -> Transaction:
        tx = Transaction(
            sender=self.address, recipient=recipient, amount=amount,
            nonce=nonce, timestamp=int(time.time())
        )
        tx.signature = self.signer.sign(tx.signing_bytes())
        return tx
