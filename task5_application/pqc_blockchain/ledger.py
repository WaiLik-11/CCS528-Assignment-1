"""A tiny hash-linked permissioned ledger with validator-signed blocks (not a consensus implementation)."""
from dataclasses import dataclass
import hashlib
from common.pqc import PQCSigner
from .transaction import canonical_json
from .wallet import SIG_NAME

GENESIS_PREVIOUS_HASH = "0" * 64
# ML-DSA context string: a block signature can never be mistaken for a signature made for another purpose.
BLOCK_CONTEXT = b"PQBlockchain-block"

@dataclass
class Block:
    index: int
    timestamp: int
    transactions: list[dict]
    previous_hash: str
    block_hash: str = ""
    validator_signature: bytes = b""  # ML-DSA signature over block_hash, so not part of the hashed body

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


def genesis_block() -> Block:
    genesis = Block(0, 0, [], GENESIS_PREVIOUS_HASH)
    genesis.seal()
    return genesis

# The genesis block is fixed and well known, so it is checked against this constant instead of a signature.
GENESIS_HASH = genesis_block().block_hash


class Ledger:
    def __init__(self, validator_public_key: bytes):
        # Pinned validator ML-DSA public key from the trusted registry; every block after genesis must verify under it.
        self.validator_public_key = validator_public_key
        self.blocks = [genesis_block()]
        self.balances: dict[str, int] = {}

    def set_initial_balance(self, address: str, amount: int):
        if amount < 0:
            raise ValueError("Initial balance cannot be negative")
        self.balances[address] = amount

    def add_transaction(self, tx, validator_signer: PQCSigner):
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
        block.validator_signature = validator_signer.sign(bytes.fromhex(block.block_hash), BLOCK_CONTEXT)
        self.blocks.append(block)
        self.balances = new_balances

    def validate_chain(self) -> bool:
        # Attacks stopped: edited blocks (hash mismatch), removed or reordered blocks (broken links),
        # and rewritten blocks with recomputed hashes (no valid validator signature)
        if not self.blocks or self.blocks[0].block_hash != GENESIS_HASH:
            return False
        for i, block in enumerate(self.blocks):
            if block.block_hash != block.calculate_hash():
                return False
            if i == 0:
                continue
            if block.previous_hash != self.blocks[i - 1].block_hash or block.index != i:
                return False
            if not PQCSigner.verify(
                self.validator_public_key, 
                bytes.fromhex(block.block_hash), 
                block.validator_signature, 
                SIG_NAME, 
                BLOCK_CONTEXT
            ):
                return False
        return True
