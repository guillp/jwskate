from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from jwskate import (
    A128CBC_HS256,
    A128GCM,
    A128GCMKW,
    A128KW,
    A192CBC_HS384,
    A192GCM,
    A192GCMKW,
    A192KW,
    A256CBC_HS512,
    A256GCM,
    A256GCMKW,
    A256KW,
    ES256,
    ES256K,
    ES384,
    ES512,
    HS256,
    HS384,
    HS512,
    PS256,
    PS384,
    PS512,
    RS256,
    RS384,
    RS512,
    BaseAlg,
    BaseAsymmetricAlg,
    EcdhEs,
    EcdhEs_A128KW,
    EcdhEs_A192KW,
    EcdhEs_A256KW,
    EdDsa,
    PrivateKeyRequired,
    PublicKeyRequired,
    RsaEsOaep,
    RsaEsOaepSha256,
    RsaEsOaepSha384,
    RsaEsOaepSha512,
    RsaEsPcks1v1_5,
)


def test_private_public_key_required() -> None:
    key = rsa.generate_private_key(65537, 2048)
    private_wrapper = RsaEsOaepSha256(key)

    with private_wrapper.private_key_required():
        assert True

    with pytest.raises(PublicKeyRequired):
        with private_wrapper.public_key_required():
            pass

    public_wrapper = RsaEsOaepSha256(key.public_key())
    with public_wrapper.public_key_required():
        assert True

    with pytest.raises(PrivateKeyRequired):
        with public_wrapper.private_key_required():
            pass


@pytest.mark.parametrize(
    "alg_class",
    (
        A128CBC_HS256,
        A128GCM,
        A128GCMKW,
        A128KW,
        A192CBC_HS384,
        A192GCM,
        A192GCMKW,
        A192KW,
        A256CBC_HS512,
        A256GCM,
        A256GCMKW,
        A256KW,
        ES256,
        ES256K,
        ES384,
        ES512,
        HS256,
        HS384,
        HS512,
        PS256,
        PS384,
        PS512,
        RS256,
        RS384,
        RS512,
        EcdhEs,
        EcdhEs_A128KW,
        EcdhEs_A192KW,
        EcdhEs_A256KW,
        EdDsa,
        RsaEsOaep,
        RsaEsOaepSha256,
        RsaEsOaepSha384,
        RsaEsOaepSha512,
        RsaEsPcks1v1_5,
    ),
)
def test_init_with_random_key(alg_class: type[BaseAlg]) -> None:
    alg = alg_class.with_random_key()
    assert isinstance(alg, alg_class)
    if issubclass(alg_class, BaseAsymmetricAlg):
        assert isinstance(alg, BaseAsymmetricAlg)
        assert isinstance(alg.public_key(), alg_class.public_key_class)
