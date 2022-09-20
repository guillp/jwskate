import pytest

from jwskate import EncryptionAlgs, Jwk, KeyManagementAlgs, SignatureAlgs


@pytest.mark.parametrize(
    "alg", SignatureAlgs.ALL + EncryptionAlgs.ALL + KeyManagementAlgs.ALL_KEY_BASED
)
def test_generate_for_alg(alg: str) -> None:
    jwk = Jwk.generate_for_alg(alg).with_usage_parameters()
    assert jwk.is_private
    if alg in SignatureAlgs.ALL_SYMMETRIC:
        assert jwk.kty == "oct"
        assert jwk.use == "sig"
        assert jwk.key_ops == ["sign", "verify"]
        assert jwk.is_symmetric
    elif alg in SignatureAlgs.ALL_ASYMMETRIC:
        assert jwk.kty in ("EC", "RSA", "OKP")
        assert jwk.use == "sig"
        assert jwk.key_ops == ["sign"]
        assert not jwk.is_symmetric
    elif alg in EncryptionAlgs.ALL:
        assert jwk.kty == "oct"
        assert jwk.use == "enc"
        assert jwk.key_ops == ["encrypt", "decrypt"]
        assert jwk.is_symmetric
    elif alg in KeyManagementAlgs.ALL_SYMMETRIC:
        assert jwk.kty == "oct"
        assert jwk.use == "enc"
        assert jwk.key_ops == ["wrapKey", "unwrapKey"]
        assert jwk.is_symmetric
    elif alg in KeyManagementAlgs.ALL_ASYMMETRIC:
        assert jwk.kty in ("EC", "RSA", "OKP")
        assert jwk.use == "enc"
        assert jwk.key_ops == ["unwrapKey"]
        assert not jwk.is_symmetric
