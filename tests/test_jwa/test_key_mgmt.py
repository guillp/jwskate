"""Tests for jwskate.jwa.key_mgmt submodule."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519

from jwskate import BasePbes2, EcdhEs


@pytest.mark.parametrize(
    "key_gen",
    [
        lambda: ec.generate_private_key(ec.SECP256R1()),
        lambda: ec.generate_private_key(ec.SECP384R1()),
        lambda: ec.generate_private_key(ec.SECP521R1()),
        x25519.X25519PrivateKey.generate,
        x448.X448PrivateKey.generate,
    ],
)
def test_ecdhes(
    key_gen: (type[ec.EllipticCurvePrivateKey] | type[x25519.X25519PrivateKey] | type[x448.X448PrivateKey]),
) -> None:
    private_key = key_gen()
    sender_ecdhes = EcdhEs(private_key.public_key())
    epk = sender_ecdhes.generate_ephemeral_key()
    assert isinstance(epk, private_key.__class__)
    sender_key = sender_ecdhes.sender_key(epk, alg="A128GCM", key_size=128)

    recipient_ecdhes = EcdhEs(private_key)
    recipient_key = recipient_ecdhes.recipient_key(epk.public_key(), alg="A128GCM", key_size=128)

    assert sender_key == recipient_key

    with pytest.raises(TypeError):
        sender_ecdhes.ecdh(private_key, b"foo")  # type: ignore[arg-type]


def test_pbes2_salt() -> None:
    assert isinstance(BasePbes2.generate_salt(), bytes)
    assert len(BasePbes2.generate_salt()) == 12
    assert isinstance(BasePbes2.generate_salt(8), bytes)
    assert isinstance(BasePbes2.generate_salt(16), bytes)

    with pytest.raises(ValueError, match="at least 8 bytes long"):
        BasePbes2.generate_salt(7)
