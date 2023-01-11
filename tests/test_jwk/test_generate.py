import pytest

from jwskate import (
    EncryptionAlgs,
    ExpectedAlgRequired,
    Jwk,
    KeyManagementAlgs,
    RSAJwk,
    SignatureAlgs,
    UnsupportedAlg,
)


@pytest.mark.parametrize(
    "alg", SignatureAlgs.ALL + EncryptionAlgs.ALL + KeyManagementAlgs.ALL_KEY_BASED
)
def test_generate_for_alg(alg: str) -> None:
    jwk = Jwk.generate_for_alg(alg).with_usage_parameters()
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


def test_unsupported_alg() -> None:
    # trying to generate a Jwk with an unsupported alg raises a UnsupportedAlg
    with pytest.raises(UnsupportedAlg):
        Jwk.generate_for_alg("unknown_alg")


def test_symmetric_key_size() -> None:
    with pytest.warns():
        Jwk.generate_for_alg("HS256", key_size=64)

    assert Jwk.generate_for_alg(
        "HS256", key_size=384
    )  # no warning when key_size > hash_size

    with pytest.raises(ValueError):
        Jwk.generate_for_alg("A128GCM", key_size=100)
