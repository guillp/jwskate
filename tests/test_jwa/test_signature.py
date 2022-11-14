"""Tests for jwskate.jwa.signature submodule."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from jwskate import ES256


def test_ec_signature_invalid_size() -> None:
    es256 = ES256(ec.generate_private_key(ec.SECP256R1()).public_key())
    with pytest.raises(ValueError):
        es256.verify(b"foo", b"bar")
