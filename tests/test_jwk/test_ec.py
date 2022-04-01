from jwskate import ECJwk


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
