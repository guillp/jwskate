import pytest

from jwskate import Jwk, JwkSet


def test_jwks() -> None:
    keys = [Jwk.generate_for_kty("RSA"), Jwk.generate_for_kty("RSA")]
    jwks = JwkSet(keys=keys)
    assert jwks.jwks == keys

    jwk = Jwk.generate_for_kty("EC")
    keys.append(jwk)
    kid = jwks.add_jwk(jwk)
    assert kid == jwk.kid
    assert jwks.jwks == keys

    data = b"this is a test"
    signature = jwk.sign(data, "ES256")

    assert jwks.verify(data, signature, "ES256")

    jwks.remove_jwk(jwk.kid)

    jwks.remove_jwk("foo")

    assert jwks.is_private

    assert not jwks.verify(data, signature, "ES256")


def test_empty_jwks() -> None:
    jwks = JwkSet()
    assert len(jwks) == 0

    generated_jwk = Jwk.generate_for_kty("RSA")

    kid = jwks.add_jwk(generated_jwk)
    jwk = jwks.get_jwk_by_kid(kid)
    assert jwk.pop("kid") == jwk.thumbprint()
    assert jwk == generated_jwk

    with pytest.raises(KeyError):
        jwks.get_jwk_by_kid("foo")
