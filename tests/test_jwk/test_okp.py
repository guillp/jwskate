import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from jwskate import Jwk, JwsCompact, OKPJwk
from jwskate.jwk.okp import UnsupportedOKPCurve


@pytest.mark.parametrize("curve", ["Ed25519", "Ed448", "X25519", "X448"])
def test_jwk_okp_generate(curve: str) -> None:
    jwk = OKPJwk.generate(crv=curve, kid="myokpkey")
    assert jwk.kty == "OKP"
    assert jwk.kid == "myokpkey"
    assert "x" in jwk
    assert "d" in jwk


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


def test_from_to_cryptography() -> None:
    okp_key = ed25519.Ed25519PrivateKey.generate()
    jwk = Jwk.from_cryptography_key(okp_key)
    assert jwk.kty == "OKP"
