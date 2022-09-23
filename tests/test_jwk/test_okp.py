from typing import Any, Type

import pytest
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519

from jwskate import Jwk, JwsCompact, OKPJwk, UnsupportedAlg, UnsupportedOKPCurve


@pytest.mark.parametrize("crv", ["Ed25519", "Ed448", "X25519", "X448"])
def test_jwk_okp_generate_with_crv(crv: str) -> None:
    jwk = OKPJwk.generate(crv=crv, kid="myokpkey")
    assert jwk.kty == "OKP"
    assert jwk.crv == crv
    assert jwk.kid == "myokpkey"
    assert "x" in jwk
    assert "d" in jwk

    assert jwk.supported_encryption_algorithms() == []


@pytest.mark.parametrize(
    "alg", ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]
)
def test_jwk_okp_generate_with_alg(alg: str) -> None:
    jwk = OKPJwk.generate(alg=alg, kid="myokpkey")
    assert jwk.kty == "OKP"
    assert jwk.crv == "X25519"
    assert jwk.kid == "myokpkey"
    assert "x" in jwk
    assert "d" in jwk

    assert jwk.supported_encryption_algorithms() == []


def test_generate_no_crv_no_alg() -> None:
    with pytest.raises(ValueError):
        OKPJwk.generate()


def test_generate_unsuppored_alg() -> None:
    with pytest.raises(UnsupportedAlg):
        OKPJwk.generate(alg="foo")


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


@pytest.mark.parametrize("crv", ["Ed25519", "Ed448", "X25519", "X448"])
def test_pem_key(crv: str) -> None:
    private_jwk = OKPJwk.generate(crv=crv)
    private_pem = private_jwk.to_pem()
    assert Jwk.from_pem_key(private_pem) == private_jwk

    public_jwk = private_jwk.public_jwk()
    public_pem = public_jwk.to_pem()
    assert Jwk.from_pem_key(public_pem) == public_jwk

    # serialize private key with password
    password = b"th1s_i5_a_p4ssW0rd!"
    private_pem = private_jwk.to_pem(password)
    assert Jwk.from_pem_key(private_pem, password) == private_jwk

    # try to serialize the public key with password
    with pytest.raises(ValueError):
        public_jwk.to_pem(password)

    with pytest.raises(ValueError):
        assert Jwk.from_pem_key(public_pem, password) == public_jwk


def test_from_cryptography_key_unknown_type() -> None:
    with pytest.raises(TypeError):
        OKPJwk.from_cryptography_key("this is not a cryptography key")
