"""Tests for jwskate.jwa.signature submodule."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from jwskate import ES256


def test_ec_signature_exceptions() -> None:
    es256 = ES256.with_random_key()
    with pytest.raises(ValueError):
        es256.verify(b"foo", b"bar")
