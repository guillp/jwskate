"""Tests for jwskate.jwa.key_mgmt submodule."""
from typing import Type, Union

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519

from jwskate import EcdhEs


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
    key_gen: Union[
        Type[ec.EllipticCurvePrivateKey],
        Type[x25519.X25519PrivateKey],
        Type[x448.X448PrivateKey],
    ]
) -> None:
    private_key = key_gen()
    sender_ecdhes = EcdhEs(private_key.public_key())
    epk = sender_ecdhes.generate_ephemeral_key()
    assert isinstance(epk, private_key.__class__)
    sender_key = sender_ecdhes.sender_key(epk, alg="A128GCM", key_size=128)

    recipient_ecdhes = EcdhEs(private_key)
    recipient_key = recipient_ecdhes.recipient_key(
        epk.public_key(), alg="A128GCM", key_size=128
    )

    assert sender_key == recipient_key

    with pytest.raises(ValueError):
        sender_ecdhes.ecdh(private_key, b"foo")  # type: ignore[arg-type]
