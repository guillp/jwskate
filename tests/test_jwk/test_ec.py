import pytest

from jwskate import A128CBC_HS256, EcdhEs, ECJwk, Jwk


def test_jwk_ec_generate() -> None:
    with pytest.warns():
        jwk = ECJwk.generate(kid="myeckey")
    assert jwk.kty == "EC"
    assert jwk.kid == "myeckey"
    assert jwk.crv == "P-256"
    assert "x" in jwk
    assert "y" in jwk
    assert "d" in jwk

    public_jwk = jwk.public_jwk()
    assert public_jwk.kty == "EC"
    assert public_jwk.kid == "myeckey"
    assert public_jwk.crv == "P-256"
    assert "x" in public_jwk
    assert "y" in public_jwk
    assert "d" not in public_jwk

    assert jwk.supported_encryption_algorithms() == []


def test_ecdh_es() -> None:
    alg = "ECDH-ES+A128KW"
    enc = "A128CBC-HS256"
    private_jwk = ECJwk.generate(alg=alg)
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

    # EPK is mandatory for recipient_key() to work
    with pytest.raises(ValueError):
        private_jwk.recipient_key(wrapped_cek, enc)
    # try passing the private EPK to recipient key
    with pytest.raises(ValueError):
        private_jwk.recipient_key(wrapped_cek, enc, epk=epk)


@pytest.mark.parametrize("crv", ["P-256", "P-384", "P-521"])
def test_pem_key(crv: str) -> None:
    private_jwk = ECJwk.generate(crv=crv)
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
