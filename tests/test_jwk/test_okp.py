import pytest

from jwskate import OKPJwk


@pytest.mark.parametrize("curve", ["Ed25519", "Ed448", "X25519", "X448"])
def test_jwk_okp_generate(curve: str) -> None:
    jwk = OKPJwk.generate(crv=curve, kid="myokpkey")
    assert jwk.kty == "OKP"
    assert jwk.kid == "myokpkey"
    assert "x" in jwk
    assert "d" in jwk
