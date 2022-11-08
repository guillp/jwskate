"""Tests for jwskate.jwa.encryption submodule."""

import pytest

from jwskate import (
    A128CBC_HS256,
    A128GCM,
    A192CBC_HS384,
    A192GCM,
    A256CBC_HS512,
    A256GCM,
    BaseAESEncryptionAlg,
    MismatchingAuthTag,
)


class SupportsBytesTester:
    """A test class with a __bytes__ method to match SupportBytes interface."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __bytes__(self) -> bytes:  # noqa: D105
        return self.payload


@pytest.mark.parametrize(
    "alg", [A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512]
)
def test_encryption(alg: BaseAESEncryptionAlg) -> None:
    jwa = alg.init_random_key()
    plaintext = b"this is a test"
    iv = alg.generate_iv()
    assert len(iv) * 8 == alg.iv_size
    ciphertext, tag = jwa.encrypt(plaintext, iv=iv)
    assert (ciphertext, tag) == jwa.encrypt(
        SupportsBytesTester(plaintext), iv=SupportsBytesTester(iv)
    )
    assert (
        jwa.decrypt(ciphertext, iv=iv, auth_tag=tag)
        == jwa.decrypt(
            SupportsBytesTester(ciphertext),
            iv=SupportsBytesTester(iv),
            auth_tag=SupportsBytesTester(tag),
        )
        == plaintext
    )

    with pytest.raises(ValueError):
        jwa.encrypt(plaintext, iv=b"tooshort")
    with pytest.raises(ValueError):
        jwa.encrypt(plaintext, iv=b"toolong" * 50)
    with pytest.raises(ValueError):
        jwa.decrypt(ciphertext, iv=b"tooshort", auth_tag=tag)
    with pytest.raises(ValueError):
        jwa.decrypt(ciphertext, iv=b"toolong" * 50, auth_tag=tag)

    aad = b"this is an AAD"
    ciphertext_aad, tag_aad = jwa.encrypt(plaintext, iv=iv, aad=aad)
    assert (
        (ciphertext_aad, tag_aad)
        == jwa.encrypt(plaintext, iv=iv, aad=SupportsBytesTester(aad))
        != jwa.encrypt(plaintext, iv=iv)
    )
    assert jwa.decrypt(ciphertext_aad, auth_tag=tag_aad, iv=iv, aad=aad) == jwa.decrypt(
        ciphertext_aad, auth_tag=tag_aad, iv=iv, aad=SupportsBytesTester(aad)
    )

    with pytest.raises(MismatchingAuthTag):
        jwa.decrypt(ciphertext_aad, auth_tag=tag_aad, iv=iv)
