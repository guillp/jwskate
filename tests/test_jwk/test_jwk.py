import pytest

from jwskate import InvalidJwk, Jwk


def test_jwk_copy() -> None:
    jwk1 = Jwk.generate_for_kty("RSA")

    jwk2 = Jwk(jwk1)
    assert jwk1 is jwk2

    jwk3 = jwk1.copy()
    assert jwk1 == jwk3
    assert jwk1 is not jwk3


def test_invalid_jwk() -> None:
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
