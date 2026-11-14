import unittest
from cryptography.exceptions import InvalidTag
from task5_application.main import build_demo
from task5_application.pqc_blockchain.secure_channel import KEM_NAME, encrypt_submission
from task5_application.pqc_blockchain.wallet import wallet_address
from common.pqc import PQCKEMRecipient

class PQCBlockchainTests(unittest.TestCase):
    def test_wallet_address_is_hash_of_public_key_and_registry_resolves_it(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        self.assertEqual(alice.address, wallet_address(alice.public_key))
        self.assertEqual(registry.get_wallet_key(alice.address), alice.public_key)
        self.assertEqual(len(bytes.fromhex(alice.address)), 32)
        self.assertNotEqual(alice.address, bob.address)
        self.assertFalse(hasattr(alice, "identity"))

    def test_normal_signed_secure_transaction(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        envelope = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        ok, msg = node.receive(envelope)
        self.assertTrue(ok, msg)
        self.assertEqual(ledger.balances[alice.address], 90)
        self.assertEqual(ledger.balances[bob.address], 10)
        self.assertTrue(ledger.validate_chain())

    def test_replay_rejected(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        env = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        self.assertTrue(node.receive(env)[0])
        env2 = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        self.assertFalse(node.receive(env2)[0])

    def test_replay_rejected_after_validator_recreation(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        env = encrypt_submission(
            registry.validator_kem_key(), tx.to_bytes(),
            registry.validator_kem_fingerprint(),
        )
        self.assertTrue(node.receive(env)[0])

        restarted_validator = type(validator)(registry, ledger)
        node.validator = restarted_validator
        ok, reason = node.receive(env)
        self.assertFalse(ok)
        self.assertIn("Replay/nonce failure", reason)

    def test_envelope_reveals_no_transaction_fields(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        envelope = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        self.assertEqual(set(envelope), {"kem_ciphertext", "nonce", "ciphertext"})
        for address in (alice.address, bob.address):
            self.assertNotIn(address.encode(), envelope["ciphertext"])

    def test_kem_ciphertext_or_nonce_tamper_rejected(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        envelope = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        for field in ("kem_ciphertext", "nonce"):
            with self.subTest(field=field):
                tampered_envelope = dict(envelope)
                tampered_envelope[field] = bytes([envelope[field][0] ^ 1]) + envelope[field][1:]
                with self.assertRaises(InvalidTag):
                    node.receive(tampered_envelope)

    def test_tampered_signature_or_message_rejected(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        tx.amount = 99  # Signature is now over different canonical bytes.
        env = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        self.assertFalse(node.receive(env)[0])


    def test_forged_signature_rejected(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        tx.signature = b"\x00" * len(tx.signature)  # attacker substitutes bogus signature
        env = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        self.assertFalse(node.receive(env)[0])

    def test_ciphertext_tamper_rejected(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        env = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        env["ciphertext"] = bytes([env["ciphertext"][0] ^ 1]) + env["ciphertext"][1:]
        with self.assertRaises(InvalidTag):
            node.receive(env)

    def test_validator_kem_key_substitution_rejected(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        attacker_kem = PQCKEMRecipient(KEM_NAME)
        tx = alice.create_transaction(bob.address, 10, 0)
        with self.assertRaises(ValueError):
            encrypt_submission(attacker_kem.public_key, tx.to_bytes(), registry.validator_kem_fingerprint())

    def test_ledger_tamper_detected(self):
        alice, bob, registry, ledger, validator, node = build_demo()
        tx = alice.create_transaction(bob.address, 10, 0)
        env = encrypt_submission(registry.validator_kem_key(), tx.to_bytes(), registry.validator_kem_fingerprint())
        self.assertTrue(node.receive(env)[0])
        ledger.blocks[1].transactions[0]["amount"] = 1234
        self.assertFalse(ledger.validate_chain())

if __name__ == "__main__":
    unittest.main()
