from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from jwskate import (
    A128CBC_HS256,
    EcdhEs,
    ECJwk,
    Jwk,
    UnsupportedAlg,
    UnsupportedEllipticCurve,
)


def test_ec_jwk() -> None:
    with pytest.raises(UnsupportedEllipticCurve):
        Jwk({"kty": "EC", "crv": "foo"})


def test_jwk_ec_generate() -> None:
    jwk = ECJwk.generate(kid="myeckey", crv="P-256")
    assert jwk.kty == "EC"
    assert jwk.kid == "myeckey"
    assert jwk.crv == "P-256"
    assert "x" in jwk
    assert "y" in jwk
    assert "d" in jwk
    assert jwk.coordinate_size == 32

    public_jwk = jwk.public_jwk()
    assert public_jwk.kty == "EC"
    assert public_jwk.kid == "myeckey"
    assert public_jwk.crv == "P-256"
    assert "x" in public_jwk
    assert "y" in public_jwk
    assert "d" not in public_jwk

    assert jwk.supported_encryption_algorithms() == []

    with pytest.raises(UnsupportedEllipticCurve):
        ECJwk.generate(crv="foo")

    with pytest.raises(UnsupportedAlg):
        ECJwk.generate(alg="foo")

    with pytest.raises(ValueError, match=r"No Curve identifier \(crv\) or Algorithm identifier \(alg\)"):
        ECJwk.generate()


def test_ecdh_es() -> None:
    alg = "ECDH-ES+A128KW"
    enc = "A128CBC-HS256"
    private_jwk = Jwk.generate(alg=alg, crv="P-256")
    assert private_jwk.crv == "P-256"
    public_jwk = private_jwk.public_jwk()
    sender_cek, wrapped_cek, headers = public_jwk.sender_key(enc)
    assert sender_cek
    assert wrapped_cek
    assert "epk" in headers
    epk = Jwk(headers["epk"])
    assert epk.crv == private_jwk.crv

    recipient_cek = private_jwk.recipient_key(wrapped_cek, enc, **headers)
    assert recipient_cek == sender_cek

    # no 'epk' in headers
    with pytest.raises(ValueError):
        private_jwk.recipient_key(wrapped_cek, enc)


def test_ecdh_es_with_controlled_cek_and_epk() -> None:
    # now try to generate the CEK and EPK ourselves, this should not be done outside of (pen)testing code!!!
    alg = "ECDH-ES+A128KW"
    enc = "A128CBC-HS256"
    private_jwk = ECJwk.generate(alg=alg, crv="P-256")
    public_jwk = private_jwk.public_jwk()
    cek = A128CBC_HS256.generate_key()
    epk = Jwk(EcdhEs(public_jwk.cryptography_key).generate_ephemeral_key())
    sender_cek, wrapped_cek, headers = public_jwk.sender_key(enc, cek=cek, epk=epk)
    assert sender_cek.cryptography_key == cek
    assert headers["epk"] == epk.public_jwk()

    recipient_cek = private_jwk.recipient_key(wrapped_cek, enc, **headers)
    assert recipient_cek == sender_cek

    # try passing the private EPK
    with pytest.raises(ValueError):
        private_jwk.recipient_key(wrapped_cek, enc, epk=epk)


@pytest.mark.parametrize("crv", ["P-256", "P-384", "P-521"])
def test_pem_key(crv: str) -> None:
    private_jwk = ECJwk.generate(crv=crv)
    private_pem = private_jwk.to_pem()
    assert Jwk.from_pem(private_pem) == private_jwk

    public_jwk = private_jwk.public_jwk()
    public_pem = public_jwk.to_pem()
    assert Jwk.from_pem(public_pem) == public_jwk

    # serialize private key with password
    password = b"th1s_i5_a_p4ssW0rd!"
    private_pem = private_jwk.to_pem(password)
    assert Jwk.from_pem(private_pem, password) == private_jwk

    # try to serialize the public key with password
    with pytest.raises(ValueError):
        public_jwk.to_pem(password)

    with pytest.raises(ValueError):
        assert Jwk.from_pem(public_pem, password) == public_jwk


def test_public_private() -> None:
    jwk = Jwk(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
            "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
            "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
        }
    )

    assert (
        ECJwk.public(
            crv="P-256",
            x=41091394722340406951651919287101979028566994134304719828008599584440827098914,
            y=5099336126642036233987555101153084413345413137896124327269101893088581300336,
        )
        == jwk.public_jwk()
    )

    assert (
        ECJwk.private(
            crv="P-256",
            x=41091394722340406951651919287101979028566994134304719828008599584440827098914,
            y=5099336126642036233987555101153084413345413137896124327269101893088581300336,
            d=8342345011805978907621665437908035545366143771247820774310445528411160853919,
        )
        == jwk
    )


def test_from_cryptography_key() -> None:
    key = ec.generate_private_key(curve=ec.SECP256R1())

    assert Jwk.from_cryptography_key(key) == Jwk(key)

    with pytest.raises(TypeError):
        ECJwk.from_cryptography_key(object())
