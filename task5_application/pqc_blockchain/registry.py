"""Trusted permissioned registry."""
from dataclasses import dataclass
from common.pqc import sha256
from .wallet import wallet_address

@dataclass(frozen=True)
class IdentityRecord:
    mldsa_public_key: bytes

class Registry:
    def __init__(self):
        self._identities = {}
        self._validator_kem_public_key = None
        self._validator_kem_fingerprint = None

    def register_wallet(self, public_key: bytes) -> str:
        """Register a wallet under SHA-256(public_key); return its address."""
        address = wallet_address(public_key)
        if address in self._identities:
            raise ValueError(f"Wallet is already registered: {address}")
        self._identities[address] = IdentityRecord(bytes(public_key))
        return address

    def get_wallet_key(self, address: str) -> bytes:
        if address not in self._identities:
            raise KeyError(f"Unregistered wallet address: {address}")
        return self._identities[address].mldsa_public_key

    def register_validator_kem_key(self, public_key):
        self._validator_kem_public_key = bytes(public_key)
        self._validator_kem_fingerprint = sha256(public_key).hex()

    def validator_kem_key(self):
        if self._validator_kem_public_key is None:
            raise ValueError("Validator KEM key is not registered")
        return self._validator_kem_public_key

    def validator_kem_fingerprint(self):
        if self._validator_kem_fingerprint is None:
            raise ValueError("Validator KEM key is not registered")
        return self._validator_kem_fingerprint
