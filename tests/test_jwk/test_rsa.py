import pytest
from binapy import BinaPy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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

    assert jwk.key_size == 2048

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
    jwk = RSAJwk.generate(kid="myrsakey", key_size=3096)
    assert jwk.kty == "RSA"
    assert jwk.kid == "myrsakey"
    assert "n" in jwk
    assert "d" in jwk
    assert "p" in jwk
    assert "q" in jwk
    assert "dp" in jwk
    assert "dq" in jwk
    assert "qi" in jwk
    assert jwk.key_size == 3096

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


@pytest.mark.parametrize("key_size", (1024, 2048, 4096, 1678))
def test_pem_key(key_size: int) -> None:
    private_jwk = RSAJwk.generate(key_size=key_size)
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


def test_optional_parameters() -> None:
    jwk = RSAJwk(
        {
            "kty": "RSA",
            "n": "vrTLXnpOv8Fe5stFYhmYrFKYUBcHpZU6GdtbXYRNPjBTAl2FMWE_chq5OMaM2QHBaAVLy62_xDV4AoUHydAlUoPtCtrxb9ViQnBpDytfXuhVEvAl0-K3zkWNVlOuLxDjp85cImbcPzmwrFADqAREPkCQh31V7tnlttlXlEYqDC_Cra8OnnPFwxRqcpcIWQmj2zy95TdJ1TQLv2HOYAbb1Ql1HhPhYJBFHcX4fhTVM0g-7JKOWRN7CBVudW3s5jqxgzykfkTopLDS0frP2ivz8p1vgHrXQKJr0M-dnj7FZzYiam8zBoTzOFRQ3-_QgWdu9Z9BCvJfpXhepZWu4Ryjiw",
            "e": "AQAB",
            "d": "AxJHWjivDwCOxjnM3sUZw-C6qkOMsHqESolRYeKxGcjOdXHLJN3zlyNeC0-LUi1oj4PSUi_0sDTKP4Qj-XicOUV9qliXXd06bWaBEqj4qr8kK59phI2Ytz5AhfzoB8MGX5v_uOAeOPh1Y3kQbgLPlI8WpM_8c9HXlMfQVMeCgtq08Vv15-eC6xeLqkNajQ8eEz3ZTt8eVuY5ElwiVAx8dl833_AV5E7s27mCoFWsd73zMk3ej1-eq0y4lwL7nHPPrM6JEdCrhMQgyR8BKmFZT14Ozm7W7p0W6llKY6SWV8VUEpnDbZrbm2Bpq_fvEptICE-byzIMVEN53KF9Mwo09Q",
        }
    )
    assert "qi" not in jwk
    assert "p" not in jwk
    assert "q" not in jwk
    assert "dp" not in jwk
    assert "dq" not in jwk

    assert (
        jwk.first_prime_factor
        == BinaPy(
            "1W78w6KeVoikPeFMH1E7ot6QzOmZEIv8DxYzJ440XIcY_6cvko34igTWS7x-XdapedbjeER1EBkR0_E_dUXos8HmRCTvO33SZ9R-w1HSm9VSx5JqHdBSbpDJtM2mbSKRaW7p_-KxJF2cvvnTyN8cawgDaPiEl8YpgGsize7MHvU"
        )
        .decode_from("b64u")
        .to_int()
    )
    assert (
        jwk.second_prime_factor
        == BinaPy(
            "5L1yUc691HaYvK6iohvlAzQ7RRcp_xKC0TntmwMaSUCtVkKiYOrkFxrJgtWlTx7p-M4ecdKaxO9njnRHDiMwXmDgiEhri5NellgfsXy0IQFugnW7BQBBEOkk5Y6CRvYE7WNd5sWnISO3b9nV7RDtHna6_CL1t8oDC1COU6kXKH8"
        )
        .decode_from("b64u")
        .to_int()
    )
    assert (
        jwk.first_factor_crt_exponent
        == BinaPy(
            "oCaf08x6M0RkuWoMzJMPxK5syNWf3SKtCEUILW4vLB7TS0IQGFAfZrEqe7n8uD0S_jGYje4QSPwGvJoRm9XRPtEID6oHOQS4lOCGHdmPxw7TBp1-stBWilBqihimAM4nfo2TWEap1TfJHiQoHloL4OQqauHP3HL9QTci7pN45uE"
        )
        .decode_from("b64u")
        .to_int()
    )
    assert (
        jwk.second_factor_crt_exponent
        == BinaPy(
            "BMK8ol8_LDDbtPGdiOoztgFcSm_U--4SsvAVteg2n9esw-LXJlU9Mg3oq8RukFsAW6FOmOfdOMQSz7Az2mN5Gj3B7pQzSNBkY5Sp9DO4PAefmS-CGPSMZiG0FuMEax2rtJUg2zC57cKkirtp7GkxxjSKZ70CiDS4I4AltjAKv1k"
        )
        .decode_from("b64u")
        .to_int()
    )
    assert (
        jwk.first_crt_coefficient
        == BinaPy(
            "1W3UxRlpxu2H4rcalHlQN0i5pq4Cei55CSjXkvewithAi_kmkcEaqzD07YKMdfjS9oKCKozzSklS_9XoeD-orPlszZ1dHwKbH8xn2_0QExazgvptSBF-br3xHoj9jbQ-4_DD1RQS1tXwA2nex5VAlvFGC-uHQhGRTnsmU3NNUcs"
        )
        .decode_from("b64u")
        .to_int()
    )

    jwk_with_opp = jwk.with_optional_private_parameters()
    assert jwk_with_opp == {
        "kty": "RSA",
        "n": "vrTLXnpOv8Fe5stFYhmYrFKYUBcHpZU6GdtbXYRNPjBTAl2FMWE_chq5OMaM2QHBaAVLy62_xDV4AoUHydAlUoPtCtrxb9ViQnBpDytfXuhVEvAl0-K3zkWNVlOuLxDjp85cImbcPzmwrFADqAREPkCQh31V7tnlttlXlEYqDC_Cra8OnnPFwxRqcpcIWQmj2zy95TdJ1TQLv2HOYAbb1Ql1HhPhYJBFHcX4fhTVM0g-7JKOWRN7CBVudW3s5jqxgzykfkTopLDS0frP2ivz8p1vgHrXQKJr0M-dnj7FZzYiam8zBoTzOFRQ3-_QgWdu9Z9BCvJfpXhepZWu4Ryjiw",
        "e": "AQAB",
        "d": "AxJHWjivDwCOxjnM3sUZw-C6qkOMsHqESolRYeKxGcjOdXHLJN3zlyNeC0-LUi1oj4PSUi_0sDTKP4Qj-XicOUV9qliXXd06bWaBEqj4qr8kK59phI2Ytz5AhfzoB8MGX5v_uOAeOPh1Y3kQbgLPlI8WpM_8c9HXlMfQVMeCgtq08Vv15-eC6xeLqkNajQ8eEz3ZTt8eVuY5ElwiVAx8dl833_AV5E7s27mCoFWsd73zMk3ej1-eq0y4lwL7nHPPrM6JEdCrhMQgyR8BKmFZT14Ozm7W7p0W6llKY6SWV8VUEpnDbZrbm2Bpq_fvEptICE-byzIMVEN53KF9Mwo09Q",
        "p": "1W78w6KeVoikPeFMH1E7ot6QzOmZEIv8DxYzJ440XIcY_6cvko34igTWS7x-XdapedbjeER1EBkR0_E_dUXos8HmRCTvO33SZ9R-w1HSm9VSx5JqHdBSbpDJtM2mbSKRaW7p_-KxJF2cvvnTyN8cawgDaPiEl8YpgGsize7MHvU",
        "q": "5L1yUc691HaYvK6iohvlAzQ7RRcp_xKC0TntmwMaSUCtVkKiYOrkFxrJgtWlTx7p-M4ecdKaxO9njnRHDiMwXmDgiEhri5NellgfsXy0IQFugnW7BQBBEOkk5Y6CRvYE7WNd5sWnISO3b9nV7RDtHna6_CL1t8oDC1COU6kXKH8",
        "dp": "oCaf08x6M0RkuWoMzJMPxK5syNWf3SKtCEUILW4vLB7TS0IQGFAfZrEqe7n8uD0S_jGYje4QSPwGvJoRm9XRPtEID6oHOQS4lOCGHdmPxw7TBp1-stBWilBqihimAM4nfo2TWEap1TfJHiQoHloL4OQqauHP3HL9QTci7pN45uE",
        "dq": "BMK8ol8_LDDbtPGdiOoztgFcSm_U--4SsvAVteg2n9esw-LXJlU9Mg3oq8RukFsAW6FOmOfdOMQSz7Az2mN5Gj3B7pQzSNBkY5Sp9DO4PAefmS-CGPSMZiG0FuMEax2rtJUg2zC57cKkirtp7GkxxjSKZ70CiDS4I4AltjAKv1k",
        "qi": "1W3UxRlpxu2H4rcalHlQN0i5pq4Cei55CSjXkvewithAi_kmkcEaqzD07YKMdfjS9oKCKozzSklS_9XoeD-orPlszZ1dHwKbH8xn2_0QExazgvptSBF-br3xHoj9jbQ-4_DD1RQS1tXwA2nex5VAlvFGC-uHQhGRTnsmU3NNUcs",
    }
    assert jwk_with_opp.without_optional_private_parameters() == jwk

    with pytest.raises(ValueError):
        jwk.public_jwk().with_optional_private_parameters()


def test_from_cryptography_key() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_jwk = RSAJwk.from_cryptography_key(private_key)
    assert private_jwk.is_private
    assert private_jwk.cryptography_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ) == private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    public_jwk = RSAJwk.from_cryptography_key(public_key)
    assert not public_jwk.is_private
    assert public_jwk.cryptography_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
    ) == public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
    )

    with pytest.raises(TypeError):
        RSAJwk.from_cryptography_key(b"foo")
