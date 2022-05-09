from typing import Any, Type

import pytest
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519

from jwskate import Jwk, JwsCompact, OKPJwk, UnsupportedOKPCurve


@pytest.mark.parametrize("curve", ["Ed25519", "Ed448", "X25519", "X448"])
def test_jwk_okp_generate(curve: str) -> None:
    jwk = OKPJwk.generate(crv=curve, kid="myokpkey")
    assert jwk.kty == "OKP"
    assert jwk.kid == "myokpkey"
    assert "x" in jwk
    assert "d" in jwk

    assert jwk.supported_encryption_algorithms() == []


def test_okp_ed25519_sign() -> None:
    jwk = Jwk(
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        }
    )
    assert isinstance(jwk, OKPJwk)
    assert jwk.is_private
    payload = "Example of Ed25519 signing".encode()

    jws = JwsCompact.sign(payload, jwk=jwk, alg="EdDSA")
    assert jws.alg == "EdDSA"
    assert jws.headers == {"alg": "EdDSA"}
    assert jws.payload == payload
    assert (
        jws
        == "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
    )

    assert jws.verify_signature(jwk=jwk.public_jwk(), alg="EdDSA")


def test_unknown_curve() -> None:
    with pytest.raises(UnsupportedOKPCurve):
        Jwk({"kty": "OKP", "crv": "foobar", "x": "abcd"})


@pytest.mark.parametrize(
    "crv,private_key_class,public_key_class",
    [
        ("Ed25519", ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey),
        ("Ed448", ed448.Ed448PrivateKey, ed448.Ed448PublicKey),
        ("X448", x448.X448PrivateKey, x448.X448PublicKey),
        ("X25519", x25519.X25519PrivateKey, x25519.X25519PublicKey),
    ],
)
def test_from_to_cryptography(
    crv: str, private_key_class: Type[Any], public_key_class: Type[Any]
) -> None:
    private_key = private_key_class.generate()
    private_jwk = Jwk(private_key)
    assert private_jwk.kty == "OKP"
    assert private_jwk.crv == crv
    assert private_jwk.is_private
    cryptography_private_key = private_jwk.cryptography_key
    assert isinstance(cryptography_private_key, private_key_class)

    public_jwk = Jwk(private_key.public_key())
    assert public_jwk.kty == "OKP"
    assert public_jwk.crv == crv
    assert not public_jwk.is_private
    cryptography_public_key = public_jwk.cryptography_key
    assert isinstance(cryptography_public_key, public_key_class)
