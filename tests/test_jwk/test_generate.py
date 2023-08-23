from __future__ import annotations

import secrets
import warnings

import pytest

from jwskate import (
    P_521,
    EncryptionAlgs,
    ExpectedAlgRequired,
    Jwk,
    KeyManagementAlgs,
    KeyTypes,
    RSAJwk,
    SignatureAlgs,
    UnsupportedAlg,
)


@pytest.mark.parametrize("alg", SignatureAlgs.ALL | EncryptionAlgs.ALL | KeyManagementAlgs.ALL_KEY_BASED)
def test_generate_for_alg(alg: str) -> None:
    with warnings.catch_warnings():
        jwk = Jwk.generate(alg=alg).with_usage_parameters()
    assert jwk.is_private
    if alg in SignatureAlgs.ALL_SYMMETRIC:
        assert jwk.kty == "oct"
        assert jwk.use == "sig"
        assert jwk.key_ops == ("sign", "verify")
        assert jwk.is_symmetric
        keysize = {
            "HS256": 256,
            "HS384": 384,
            "HS512": 512,
            "A128CBC-HS256": 256,
            "A192CBC-HS384": 384,
            "A256CBC-HS512": 512,
            "A128GCM": 128,
            "A192GCM": 192,
            "A256GCM": 256,
        }.get(alg)
        if keysize:
            assert jwk.key_size == keysize
    elif alg in SignatureAlgs.ALL_ASYMMETRIC:
        assert jwk.kty in ("EC", "RSA", "OKP")
        assert jwk.use == "sig"
        assert jwk.key_ops == ("sign",)
        assert not jwk.is_symmetric
    elif alg in EncryptionAlgs.ALL:
        assert jwk.kty == "oct"
        assert jwk.use == "enc"
        assert jwk.key_ops == ("encrypt", "decrypt")
        assert jwk.is_symmetric
    elif alg in KeyManagementAlgs.ALL_SYMMETRIC:
        assert jwk.kty == "oct"
        assert jwk.use == "enc"
        assert jwk.key_ops == ("wrapKey", "unwrapKey")
        assert jwk.is_symmetric
    elif alg in KeyManagementAlgs.ALL_ASYMMETRIC:
        assert jwk.kty in ("EC", "RSA", "OKP")
        assert jwk.use == "enc"
        assert jwk.key_ops == ("unwrapKey",)
        assert not jwk.is_symmetric

    jwk_mini = jwk.minimize()
    assert "alg" not in jwk_mini
    assert "use" not in jwk_mini
    assert "key_ops" not in jwk_mini
    if isinstance(jwk_mini, RSAJwk):
        jwk_mini = jwk_mini.with_optional_private_parameters()

    assert jwk_mini.with_usage_parameters(alg) == jwk

    # cannot guess usage parameters if there is no 'alg' parameter in the Jwk
    with pytest.raises(ExpectedAlgRequired):
        jwk_mini.with_usage_parameters()

    # check to_pem() and from_pem(), to_der() and from_der()
    if not jwk.is_symmetric:
        assert Jwk.from_pem(jwk.to_pem()) == jwk
        assert Jwk.from_der(jwk.to_der()) == jwk

        password = secrets.token_urlsafe(16)
        assert Jwk.from_pem(jwk.to_pem(password), password=password) == jwk
        assert Jwk.from_der(jwk.to_der(password), password=password) == jwk

        assert Jwk.from_pem(jwk.public_jwk().to_pem()) == jwk.public_jwk()
        assert Jwk.from_der(jwk.public_jwk().to_der()) == jwk.public_jwk()


@pytest.mark.parametrize(
    "kty, kwargs",
    (
        (KeyTypes.EC, {"crv": "P-256"}),
        (KeyTypes.OCT, {}),
        (KeyTypes.RSA, {}),
        (KeyTypes.OKP, {"crv": "Ed25519"}),
    ),
)
def test_generate_for_kty(kty: str, kwargs: dict[str, str]) -> None:
    jwk = Jwk.generate_for_kty(kty, **kwargs)
    assert jwk.kty == kty


def test_generate() -> None:
    for alg in SignatureAlgs.ALL | KeyManagementAlgs.ALL_KEY_BASED | EncryptionAlgs.ALL:
        assert Jwk.generate(alg=alg).alg == alg

    ec_jwk = Jwk.generate(kty=KeyTypes.EC, crv="P-521")
    assert ec_jwk.kty == KeyTypes.EC
    assert ec_jwk.curve == P_521

    assert Jwk.generate(kty="RSA", alg="RS256")
    with pytest.raises(ValueError, match="Incompatible .* parameters"):
        Jwk.generate(kty="RSA", alg="ES512")

    with pytest.raises(ValueError, match="must provide a hint"):
        Jwk.generate()


def test_unsupported_alg() -> None:
    # trying to generate a Jwk with an unsupported alg raises a UnsupportedAlg
    with pytest.raises(UnsupportedAlg):
        Jwk.generate(alg="unknown_alg")


def test_symmetric_key_size() -> None:
    with pytest.warns():
        Jwk.generate(alg="HS256", key_size=64)

    # no warning when key_size > hash_size
    assert Jwk.generate(alg="HS256", key_size=384)

    # warn when keysize is not appropriate for a given alg
    with pytest.raises(ValueError):
        Jwk.generate(alg="A128GCM", key_size=100)
