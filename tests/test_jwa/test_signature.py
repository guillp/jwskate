"""Tests for jwskate.jwa.signature submodule."""
from __future__ import annotations

import pytest

from jwskate import ES256


def test_ec_signature_exceptions() -> None:
    es256 = ES256.with_random_key()
    with pytest.raises(ValueError):
        es256.public_alg().verify(b"foo", b"bar")
