"""Validator node: receives encrypted transaction envelope."""
from .transaction import Transaction
from .secure_channel import decrypt_submission

class ValidatorNode:
    def __init__(self, kem_recipient, registry, validator):
        self.kem_recipient = kem_recipient
        self.registry = registry
        self.validator = validator

    def receive(self, envelope):
        plaintext = decrypt_submission(self.kem_recipient, envelope)
        tx = Transaction.from_bytes(plaintext)
        return self.validator.accept(tx)
