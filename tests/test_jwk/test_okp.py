from typing import Any, Type

import pytest
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519

from jwskate import EcdhEs, Jwk, JwsCompact, OKPJwk, UnsupportedAlg, UnsupportedOKPCurve


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


def test_rfc8037_ed25519() -> None:
    """Test from [RFC8037][https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A]."""
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
    assert jwk.private_key == bytes.fromhex(
        """9d 61 b1 9d ef fd 5a 60 ba 84 4a f4 92 ec 2c c4
   44 49 c5 69 7b 32 69 19 70 3b ac 03 1c ae 7f 60""".replace(
            " ", ""
        )
    )
    assert jwk.public_key == bytes.fromhex(
        """d7 5a 98 01 82 b1 0a b7 d5 4b fe d3 c9 64 07 3a
   0e e1 72 f3 da a6 23 25 af 02 1a 68 f7 07 51 1a""".replace(
            " ", ""
        )
    )
    assert jwk.public_jwk() == {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }

    assert jwk.thumbprint() == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

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


def test_rfc8037_x25519() -> None:
    """Test from [RFC8037 $A.6][https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.6]."""
    public_jwk = Jwk(
        {
            "kty": "OKP",
            "crv": "X25519",
            "kid": "Bob",
            "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08",
        }
    )
    assert isinstance(public_jwk, OKPJwk)
    assert public_jwk.public_key == bytes.fromhex(
        """de 9e db 7d 7b 7d c1 b4 d3 5b 61 c2 ec e4 35 37
   3f 83 43 c8 5b 78 67 4d ad fc 7e 14 6f 88 2b 4f"""
    )

    ephemeral_secret = bytes.fromhex(
        """77 07 6d 0a 73 18 a5 7d 3c 16 c1 72 51 b2 66 45
   df 4c 2f 87 eb c0 99 2a b1 77 fb a5 1d b9 2c 2a"""
    )

    ephemeral_private_key = OKPJwk.from_bytes(ephemeral_secret, use="enc")

    assert ephemeral_private_key.public_jwk() == Jwk(
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
        }
    )

    ephemeral_private_key["kid"] = "Bob"

    sender_shared_key = EcdhEs.ecdh(
        private_key=ephemeral_private_key.cryptography_key,
        public_key=public_jwk.cryptography_key,
    )
    assert sender_shared_key == bytes.fromhex(
        """4a 5d 9d 5b a4 ce 2d e1 72 8e 3b f4 80 35 0f 25
   e0 7e 21 c9 47 d1 9e 33 76 f0 9b 3c 1e 16 17 42"""
    )


def test_rfc8037_x448() -> None:
    """Test from [RFC8037 $A.7][https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.7]."""
    public_jwk = Jwk(
        {
            "kty": "OKP",
            "crv": "X448",
            "kid": "Dave",
            "x": "PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk",
        }
    )
    assert isinstance(public_jwk, OKPJwk)
    assert public_jwk.public_key == bytes.fromhex(
        """3e b7 a8 29 b0 cd 20 f5 bc fc 0b 59 9b 6f ec cf
   6d a4 62 71 07 bd b0 d4 f3 45 b4 30 27 d8 b9 72
   fc 3e 34 fb 42 32 a1 3c a7 06 dc b5 7a ec 3d ae
   07 bd c1 c6 7b f3 36 09"""
    )

    ephemeral_secret = bytes.fromhex(
        """9a 8f 49 25 d1 51 9f 57 75 cf 46 b0 4b 58 00 d4
   ee 9e e8 ba e8 bc 55 65 d4 98 c2 8d d9 c9 ba f5
   74 a9 41 97 44 89 73 91 00 63 82 a6 f1 27 ab 1d
   9a c2 d8 c0 a5 98 72 6b"""
    )

    ephemeral_private_key = OKPJwk.from_bytes(ephemeral_secret, use="enc")

    assert ephemeral_private_key.public_jwk() == Jwk(
        {
            "kty": "OKP",
            "crv": "X448",
            "x": "mwj3zDG34-Z9ItWuoSEHSic70rg94Jxj-qc9LCLF2bvINmRyQdlT1AxbEtqIEg1TF3-A5TLEH6A",
        }
    )

    ephemeral_private_key["kid"] = "Bob"

    sender_shared_key = EcdhEs.ecdh(
        private_key=ephemeral_private_key.cryptography_key,
        public_key=public_jwk.cryptography_key,
    )
    assert sender_shared_key == bytes.fromhex(
        """07 ff f4 18 1a c6 cc 95 ec 1c 16 a9 4a 0f 74 d1
   2d a2 32 ce 40 a7 75 52 28 1d 28 2b b6 0c 0b 56
   fd 24 64 c3 35 54 39 36 52 1c 24 40 30 85 d5 9a
   44 9a 50 37 51 4a 87 9d"""
    )


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


@pytest.mark.parametrize(
    "private_key, crv, use",
    [
        (b"a" * 32, "Ed25519", "sig"),
        (b"a" * 32, "X25519", "enc"),
        (b"a" * 57, "Ed448", "sig"),
        (b"a" * 56, "X448", "enc"),
    ],
)
def test_from_bytes(private_key: bytes, crv: str, use: str) -> None:
    # initializing an OKP with a private key of the appropriate length, and with 'crv' and 'use' parameters will always work
    jwk = OKPJwk.from_bytes(private_key, crv=crv, use=use)
    assert isinstance(jwk, OKPJwk)
    assert jwk.crv == crv
    assert jwk.use == use

    # initializing X448 and Ed448 keys with just a private key and no other hint will work
    if len(private_key) != 32:
        jwk = OKPJwk.from_bytes(private_key)
        assert isinstance(jwk, OKPJwk)
        assert jwk.crv == crv
        assert jwk.use == use
    else:
        # initializing a key with a 32 bytes key need a crv or use hint
        with pytest.raises(ValueError):
            OKPJwk.from_bytes(private_key)

        jwk = OKPJwk.from_bytes(private_key, crv=crv)
        assert isinstance(jwk, OKPJwk)
        assert jwk.crv == crv
        assert jwk.use == use

        jwk = OKPJwk.from_bytes(private_key, use=use)
        assert isinstance(jwk, OKPJwk)
        assert jwk.crv == crv
        assert jwk.use == use

    # trying to initialize an OKPJwk with inconsistent hints will not work
    with pytest.raises(ValueError):
        OKPJwk.from_bytes(private_key, crv=crv, use="sig" if use == "enc" else "enc")

    with pytest.raises(ValueError):
        OKPJwk.from_bytes(
            private_key,
            crv={
                "Ed25519": "X25519",
                "X25519": "Ed25519",
                "Ed448": "X448",
                "X448": "Ed448",
            }.get(crv),
            use=use,
        )

    # trying an unknown crv will raise an UnsupportedOKPCurve
    with pytest.raises(UnsupportedOKPCurve):
        OKPJwk.from_bytes(private_key, crv="foo")

    # trying an unknown use with raise a ValueError:
    with pytest.raises(ValueError):
        OKPJwk.from_bytes(private_key, use="foo")

    # trying to initialize an OKPJwk with a wrong key size will not work
    with pytest.raises(ValueError):
        OKPJwk.from_bytes(private_key + b"bb")
