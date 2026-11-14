"""A tiny hash-linked permissioned ledger (not a consensus implementation)."""
from dataclasses import dataclass, field
import hashlib
from .transaction import canonical_json

GENESIS_PREVIOUS_HASH = "0" * 64


@dataclass
class Block:
    index: int
    timestamp: int
    transactions: list[dict]
    previous_hash: str
    block_hash: str = ""

    def body(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
        }

    def calculate_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.body())).hexdigest()

    def seal(self):
        self.block_hash = self.calculate_hash()


class Ledger:
    def __init__(self):
        genesis = Block(0, 0, [], GENESIS_PREVIOUS_HASH)
        genesis.seal()
        self.blocks = [genesis]
        self.balances: dict[str, int] = {}

    def set_initial_balance(self, address: str, amount: int):
        if amount < 0:
            raise ValueError("Initial balance cannot be negative")
        self.balances[address] = amount

    def add_transaction(self, tx):
        # Caller must validate signature, nonce, and balance before this method.
        new_balances = dict(self.balances)
        new_balances[tx.sender] = new_balances.get(tx.sender, 0) - tx.amount
        new_balances[tx.recipient] = new_balances.get(tx.recipient, 0) + tx.amount
        block = Block(
            index=len(self.blocks),
            timestamp=tx.timestamp,
            transactions=[tx.to_dict()],
            previous_hash=self.blocks[-1].block_hash,
        )
        block.seal()
        self.blocks.append(block)
        self.balances = new_balances

    def validate_chain(self) -> bool:
        # Detects edits unless the attacker recomputes every later hash (no block signatures)
        # Attacks stopped: tampered blocks, broken hash links
        if not self.blocks:
            return False
        for i, block in enumerate(self.blocks):
            if block.block_hash != block.calculate_hash():
                return False
            if i == 0:
                if block.previous_hash != GENESIS_PREVIOUS_HASH:
                    return False
            else:
                if block.previous_hash != self.blocks[i - 1].block_hash:
                    return False
                if block.index != i:
                    return False
        return True
