import pytest

from jwskate import Aes128CbcHmacSha256, EcdhEs, ECJwk, Jwk


def test_jwk_ec_generate() -> None:
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

    assert jwk.supported_encryption_algorithms() == []


def test_ecdh_es() -> None:
    alg = "ECDH-ES+A128KW"
    enc = "A128CBC-HS256"
    private_jwk = ECJwk.generate(alg=alg)
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
    cek = Aes128CbcHmacSha256.generate_key()
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


def test_pem_key() -> None:
    private_jwk = ECJwk.generate()
    private_pem = private_jwk.to_pem_key()
    assert Jwk.from_pem_key(private_pem) == private_jwk

    public_jwk = private_jwk.public_jwk()
    public_pem = public_jwk.to_pem_key()
    assert Jwk.from_pem_key(public_pem) == public_jwk

    # serialize private key with password
    password = b"th1s_i5_a_p4ssW0rd!"
    private_pem = private_jwk.to_pem_key(password)
    assert Jwk.from_pem_key(private_pem, password) == private_jwk

    # try to serialize the public key with password
    with pytest.raises(ValueError):
        public_jwk.to_pem_key(password)

    with pytest.raises(ValueError):
        assert Jwk.from_pem_key(public_pem, password) == public_jwk
