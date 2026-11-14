"""Canonical transaction representation and ML-DSA signing."""
from dataclasses import dataclass
import json
import hashlib
from typing import Any

def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")

@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    nonce: int
    timestamp: int
    signature: bytes = b""

    def unsigned_dict(self) -> dict:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json(self.unsigned_dict())

    def to_dict(self) -> dict:
        return {**self.unsigned_dict(), "signature": self.signature.hex()}

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Transaction":
        d = json.loads(raw.decode("utf-8"))
        return cls(
            sender=d["sender"], recipient=d["recipient"], amount=d["amount"],
            nonce=d["nonce"], timestamp=d["timestamp"],
            signature=bytes.fromhex(d["signature"])
        )
