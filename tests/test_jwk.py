import base64

import pytest

from jwskate import ECJwk, InvalidJwk, Jwk, JwkSet, OKPJwk, RSAJwk, SymetricJwk

RSA_PRIVATE_JWK = {
    "kty": "RSA",
    "n": "oRHn4oGv23ylRL3RSsL4p_e6Ywinnj2N2tT5OLe5pEZTg-LFBhjFxcJaB-p1dh6XX47EtSfa-JHffU0o5ZRK2ySyNDtlrFAkOpAHH6U83ayE2QPYGzrFrrvHDa8wIMUWymzxpPwGgKBwZZqtTT6d-iy4Ux3AWV-bUv6Z7WijHnOy7aVzZ4dFERLVf2FaaYXDET7GO4v-oQ5ss_guYdmewN039jxkjz_KrA-0Fyhalf9hL8IHfpdpSlHosrmjORG5y9LkYK0J6zxSBF5ZvLIBK33BTzPPiCMwKLyAcV6qdcAcvV4kthKO0iUKBK4eE8D0N8HcSPvA9F_PpLS_k5F2lw",
    "e": "AQAB",
    "d": "U-uiZ8-uMquU6GYF_-_p4ooeIK9HthjYKiZA255OKRtDNDoY8X5CvTDv-6PbI3n44J7gOorTeiN20DA9mLBU-Cz8dF5mMQtodOLJ82ECf3T9mpx4ImfSy6GmqqiWaNyHbVyp4o41TRtKtIWMuexgHxLhztx3dZlssidZR-r24kwON7_2JUeY-N6hwmKh3DlsmO9KyOAoTwNjyKxCIqbf7WnZ9gnavG_mLUeXeiHhSgASYMTUCCFm0KOhDWgvaddDKDMqcQUYPonaI19fW1eNtXfXRjFWwlGbqOnOo930yl1LG1CawI0rbxmkDoyjTHLDJlY7Go_gpHlP2maQRPiMcQ",
    "p": "0mzP9sbFxU5YxNNLgUEdRQSO-ojqWrzbI02PfQLGyzXumvOh_Qr73OpHStU8CAAcUBaQdRGidsVdb5cq6JG2zvbEEYiX-dCHqTJs8wfktGCL7eV-ZVh7fhJ1sYVBN20yv8aSH63uUPZnJXR1AUyrvRumuerdPxp8X951PESrJd0",
    "q": "w_SPRMeEtbEvsRcNfpmbRbpO368hcaLjB9Bb_IvxvoiI3aMTMZgwLSyx5hpuv6A86R3wFdRkh2JBKCzG4ItirUyTfVRUY9ItSNyMNplHxELA6I4JG0m6Rh-IO3wG8-h-U-NKllG4SCR8mS9Wvhg7eBZh_LXvKSgKLgalZSSUSQM",
    "dp": "ogg6B3u-VJVk04Mk1A3w3PGKq678Twy37bJOuGOH8njAGD9c0D5B_TXF2gDirgJvytflOtBueui1bzVHTDjQPQRVrG6zICGMJSR4Mpg0axUhCvo53w5IYacTS7QhqO2EM5pTcON87Ikgmf3YDz0bzY3aT7Vj0rCxbx0cx2DVLV0",
    "dq": "TwdPzJ5m4FwgbtxsPdW3cIyuCLp503ms9FbM8nKCQaSRBkohkIvfSijPaozYg4Idbqr7S-KH1K4Ety4v2xl754aNqSscidGXH96K0e5JqlZ9tIysEYxPir5m1A62QyJN6IkvaKZ2munUMneMFUhym4Dzbdb2KHQUfvGBPORexX8",
    "qi": "rymn9AZV0TshtAM32YLo2HNzOOXRVLbwMZUjOeViuUVSyPqtkKNYFHKBpg7QxuzGbl6w32xKLKoW7xmlQKsSCMtFyVFYtv5muRNlQMG79xxX2M65MhUesPoe7YMJR0fHSBQ6yDvOOdP35CEnABh7AiIIW_rs3ngyfIOyAm0XuiE",
}


def test_private_rsa_jwk():
    jwk = Jwk(RSA_PRIVATE_JWK)
    assert jwk.is_private
    assert jwk.kty == "RSA"
    assert type(jwk) == RSAJwk
    assert jwk.n == RSA_PRIVATE_JWK["n"]
    assert jwk.e == RSA_PRIVATE_JWK["e"]
    assert jwk.d == RSA_PRIVATE_JWK["d"]
    assert jwk.p == RSA_PRIVATE_JWK["p"]
    assert jwk.q == RSA_PRIVATE_JWK["q"]
    assert jwk.dp == RSA_PRIVATE_JWK["dp"]
    assert jwk.dq == RSA_PRIVATE_JWK["dq"]
    assert jwk.qi == RSA_PRIVATE_JWK["qi"]

    assert jwk.thumbprint() == "Qfq9DOLKNRyptzTJBhCFlzccbA0ac7Ag9GVFL11GAfM"

    signature = jwk.sign(b"Hello World!")
    assert (
        signature.hex()
        == "2eb2d1f5ef9a55403b7d09cca52955feea3ced6b948d311819ec976e4f40cb3cdf9718de38ecc53fd060e2994fab378cb64ebcecf1a6da1d5983af8b6d53c2830e0a4815863345ac72f9a6e7b6328f5678c1a3ed89074fa1e0526f261c5d969c0d059db94fedd51a705ae1870ef4c00cf89b5702c62f20fd1c3f13b94b15e529a9f6d86810788cf7d6d9e1e296d094af934931d6b845d2c93239943ca678b715310c2019ac1eca39dc1e8e67153342ab5d8d500ee07e438b316a1e6e2cd11191fb2ddf98ae2d9f62a6d50f74890d429af57946e744dda52f8341014a9bbc1b82bcaeae8d5458d3433140b88d6fc2c46af011c2189fdf6adc27b53e2ae90b6207"  # TODO: check this value
    )

    public_jwk = jwk.public_jwk()
    assert not public_jwk.is_private
    assert public_jwk.d is None
    assert public_jwk.p is None
    assert public_jwk.q is None
    assert public_jwk.dp is None
    assert public_jwk.dq is None
    assert public_jwk.qi is None

    assert public_jwk.thumbprint() == jwk.thumbprint()
    assert public_jwk.verify(b"Hello World!", signature, alg="RS256")


def test_public_rsa_jwk():
    public_jwk = {
        key: val for key, val in RSA_PRIVATE_JWK.items() if key in ("kty", "n", "e")
    }
    jwk = Jwk(public_jwk)
    assert jwk.is_private is False
    assert jwk.kty == "RSA"
    assert type(jwk) == RSAJwk
    assert jwk.n == RSA_PRIVATE_JWK["n"]
    assert jwk.e == RSA_PRIVATE_JWK["e"]

    assert jwk.thumbprint() == "Qfq9DOLKNRyptzTJBhCFlzccbA0ac7Ag9GVFL11GAfM"


def test_invalid_jwk():
    with pytest.raises(ValueError):
        Jwk({"kty": 1.5})

    with pytest.raises(ValueError):
        Jwk({"kty": "caesar13"})

    with pytest.raises(InvalidJwk):
        Jwk({"kty": "RSA"})

    with pytest.raises(InvalidJwk):
        Jwk({"kty": "RSA", "x": "$+!"})

    with pytest.raises(InvalidJwk):
        Jwk(
            {
                "kty": "RSA",
                "n": "oRHn4oGv23ylRL3RSsL4p_e6Ywinnj2N2tT5OLe5pEZTg-LFBhjFxcJaB-p1dh6XX47EtSfa-JHffU0o5ZRK2ySyNDtlrFAkOpAHH6U83ayE2QPYGzrFrrvHDa8wIMUWymzxpPwGgKBwZZqtTT6d-iy4Ux3AWV-bUv6Z7WijHnOy7aVzZ4dFERLVf2FaaYXDET7GO4v-oQ5ss_guYdmewN039jxkjz_KrA-0Fyhalf9hL8IHfpdpSlHosrmjORG5y9LkYK0J6zxSBF5ZvLIBK33BTzPPiCMwKLyAcV6qdcAcvV4kthKO0iUKBK4eE8D0N8HcSPvA9F_PpLS_k5F2lw",
                "e": "AQAB",
                "p": "0mzP9sbFxU5YxNNLgUEdRQSO-ojqWrzbI02PfQLGyzXumvOh_Qr73OpHStU8CAAcUBaQdRGidsVdb5cq6JG2zvbEEYiX-dCHqTJs8wfktGCL7eV-ZVh7fhJ1sYVBN20yv8aSH63uUPZnJXR1AUyrvRumuerdPxp8X951PESrJd0",
            }
        )


def test_jwk_symetric():
    jwk = SymetricJwk.generate(24, kid="myoctkey")
    assert jwk.kty == "oct"
    assert jwk.kid == "myoctkey"
    assert isinstance(jwk.k, str)
    assert len(base64.urlsafe_b64decode(jwk.k + "=")) == 24
    assert jwk.is_private


def test_jwk_rsa():
    jwk = RSAJwk.generate(kid="myrsakey")
    assert jwk.kty == "RSA"
    assert jwk.kid == "myrsakey"
    assert "n" in jwk
    assert "d" in jwk
    assert "p" in jwk
    assert "q" in jwk
    assert "dp" in jwk
    assert "dq" in jwk
    assert "qi" in jwk

    public_jwk = jwk.public_jwk()
    assert public_jwk.kty == "RSA"
    assert public_jwk.kid == "myrsakey"
    assert "d" not in public_jwk
    assert "p" not in public_jwk
    assert "q" not in public_jwk
    assert "dp" not in public_jwk
    assert "dq" not in public_jwk
    assert "qi" not in public_jwk


def test_jwk_ec():
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


def test_jwk_okp():
    jwk = OKPJwk.generate(crv="Ed25519", kid="myokpkey")
    assert jwk.kty == "OKP"
    assert jwk.kid == "myokpkey"


def test_jwks():
    jwks = JwkSet()
    assert len(jwks) == 0
    kid = jwks.add_jwk(RSA_PRIVATE_JWK)
    jwk = jwks.get_jwk_by_kid(kid)
    assert jwk.pop("kid") == jwk.thumbprint()
    assert jwk == RSA_PRIVATE_JWK
