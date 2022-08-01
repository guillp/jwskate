import pytest
from binapy import BinaPy

from jwskate import InvalidJwk, Jwk, RSAJwk


@pytest.fixture(scope="session")
def rsa_private_jwk() -> Jwk:
    d = {
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
    jwk = Jwk(d)
    assert jwk.is_private
    assert jwk.kty == "RSA"
    assert type(jwk) == RSAJwk
    assert jwk.n == d["n"]
    assert jwk.e == d["e"]
    assert jwk.d == d["d"]
    assert jwk.p == d["p"]
    assert jwk.q == d["q"]
    assert jwk.dp == d["dp"]
    assert jwk.dq == d["dq"]
    assert jwk.qi == d["qi"]

    assert jwk.thumbprint() == "Qfq9DOLKNRyptzTJBhCFlzccbA0ac7Ag9GVFL11GAfM"

    assert jwk.supported_encryption_algorithms() == []
    return jwk


@pytest.fixture(scope="session")
def rsa_public_jwk(rsa_private_jwk: Jwk) -> Jwk:
    public_jwk = rsa_private_jwk.public_jwk()

    assert not public_jwk.is_private

    assert public_jwk.n == rsa_private_jwk.n
    assert public_jwk.e == rsa_private_jwk.e
    assert public_jwk.get("d") is None
    assert public_jwk.get("p") is None
    assert public_jwk.get("q") is None
    assert public_jwk.get("dp") is None
    assert public_jwk.get("dq") is None
    assert public_jwk.get("qi") is None

    assert public_jwk.thumbprint() == rsa_private_jwk.thumbprint()

    return public_jwk


def test_sign(rsa_private_jwk: Jwk, rsa_public_jwk: Jwk) -> None:
    signature = rsa_private_jwk.sign(b"Hello World!", alg="RS256")
    assert (
        signature.hex()
        == "2eb2d1f5ef9a55403b7d09cca52955feea3ced6b948d311819ec976e4f40cb3cdf9718de38ecc53f"
        "d060e2994fab378cb64ebcecf1a6da1d5983af8b6d53c2830e0a4815863345ac72f9a6e7b6328f56"
        "78c1a3ed89074fa1e0526f261c5d969c0d059db94fedd51a705ae1870ef4c00cf89b5702c62f20fd"
        "1c3f13b94b15e529a9f6d86810788cf7d6d9e1e296d094af934931d6b845d2c93239943ca678b715"
        "310c2019ac1eca39dc1e8e67153342ab5d8d500ee07e438b316a1e6e2cd11191fb2ddf98ae2d9f62"
        "a6d50f74890d429af57946e744dda52f8341014a9bbc1b82bcaeae8d5458d3433140b88d6fc2c46a"
        "f011c2189fdf6adc27b53e2ae90b6207"
        # TODO: check this value
    )

    assert rsa_public_jwk.verify(b"Hello World!", signature, alg="RS256")


def test_public_jwk(rsa_private_jwk: Jwk) -> None:
    public_jwk = {
        key: val for key, val in rsa_private_jwk.items() if key in ("kty", "n", "e")
    }
    jwk = Jwk(public_jwk)
    assert jwk.is_private is False
    assert jwk.kty == "RSA"
    assert type(jwk) == RSAJwk
    assert jwk.n == rsa_private_jwk["n"]
    assert jwk.e == rsa_private_jwk["e"]

    assert jwk.thumbprint() == rsa_private_jwk.thumbprint()


def test_generate() -> None:
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


def test_invalid_rsa_jwk(rsa_private_jwk: Jwk) -> None:
    invalid_jwk = dict(rsa_private_jwk)
    invalid_jwk["d"] = BinaPy.from_int(rsa_private_jwk.private_exponent + 1).to("b64u")
    with pytest.raises(InvalidJwk):
        Jwk(invalid_jwk)


def test_thumbprint(rsa_private_jwk: Jwk) -> None:
    assert rsa_private_jwk.thumbprint() == "Qfq9DOLKNRyptzTJBhCFlzccbA0ac7Ag9GVFL11GAfM"
    assert (
        rsa_private_jwk.thumbprint_uri()
        == "urn:ietf:params:oauth:jwk-thumbprint:sha-256:Qfq9DOLKNRyptzTJBhCFlzccbA0ac7Ag9GVFL11GAfM"
    )
