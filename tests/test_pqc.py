from common import pqc


def test_sign_verify_roundtrip():
    pk, sk = pqc.keygen_sig()
    sig = pqc.sign(sk, b"hello")
    assert pqc.verify(pk, b"hello", sig)


def test_tampered_message_fails():
    pk, sk = pqc.keygen_sig()
    sig = pqc.sign(sk, b"pay 10")
    assert not pqc.verify(pk, b"pay 100", sig)


def test_wrong_key_fails():
    _, sk = pqc.keygen_sig()
    other_pk, _ = pqc.keygen_sig()
    assert not pqc.verify(other_pk, b"m", pqc.sign(sk, b"m"))


def test_bad_signature_does_not_raise():
    pk, sk = pqc.keygen_sig()
    sig = pqc.sign(sk, b"m")
    assert not pqc.verify(pk, b"m", sig[:-1])
    assert not pqc.verify(pk, b"m", b"")


def test_kem_shared_secret_matches():
    pk, sk = pqc.keygen_kem()
    ct, ss = pqc.encaps(pk)
    assert pqc.decaps(sk, ct) == ss


def test_kem_tampered_ciphertext_gives_different_secret():
    pk, sk = pqc.keygen_kem()
    ct, ss = pqc.encaps(pk)
    bad = bytes([ct[0] ^ 1]) + ct[1:]
    assert pqc.decaps(sk, bad) != ss


def test_aead_roundtrip_and_tamper():
    key = pqc.derive_key(b"secret", b"ctx")
    assert len(key) == 32
    blob = pqc.aead_encrypt(key, b"payload", b"aad")
    assert pqc.aead_decrypt(key, blob, b"aad") == b"payload"
    assert pqc.aead_decrypt(key, blob[:-1] + bytes([blob[-1] ^ 1]), b"aad") is None
    assert pqc.aead_decrypt(key, blob, b"other-aad") is None


def test_kem_to_aead_end_to_end():
    pk, sk = pqc.keygen_kem()
    ct, ss_a = pqc.encaps(pk)
    blob = pqc.aead_encrypt(pqc.derive_key(ss_a, b"tx"), b"alice->bob 10")
    assert pqc.aead_decrypt(pqc.derive_key(pqc.decaps(sk, ct), b"tx"), blob) == b"alice->bob 10"