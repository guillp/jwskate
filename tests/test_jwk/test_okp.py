from jwskate import OKPJwk


def test_jwk_okp_generate():
    jwk = OKPJwk.generate(crv="Ed25519", kid="myokpkey")
    assert jwk.kty == "OKP"
    assert jwk.kid == "myokpkey"
