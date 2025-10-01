import pytest

from nudgepay.itsdangerous import BadSignature, TimestampSigner


@pytest.fixture
def fixed_time(monkeypatch):
    current = 1_700_000_000
    monkeypatch.setattr("nudgepay.itsdangerous.time.time", lambda: current)
    return current


def test_sign_and_unsign_round_trip(fixed_time, monkeypatch):
    signer = TimestampSigner("super-secret")
    signed = signer.sign("hello")

    # Advance time but keep within max_age to ensure successful validation.
    monkeypatch.setattr("nudgepay.itsdangerous.time.time", lambda: fixed_time + 10)
    assert signer.unsign(signed, max_age=30) == b"hello"


def test_unsign_rejects_tampered_payload(fixed_time):
    signer = TimestampSigner("super-secret")
    signed = bytearray(signer.sign("hello"))
    signed[-1] ^= 1  # flip last byte to corrupt the signature

    with pytest.raises(BadSignature):
        signer.unsign(bytes(signed))


def test_unsign_rejects_expired_signature(fixed_time, monkeypatch):
    signer = TimestampSigner("super-secret")
    signed = signer.sign("hello")

    # Move time well past the allowed max_age
    monkeypatch.setattr("nudgepay.itsdangerous.time.time", lambda: fixed_time + 100)
    with pytest.raises(BadSignature):
        signer.unsign(signed, max_age=60)
