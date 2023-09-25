from __future__ import annotations

from builtins import ValueError
from datetime import datetime, timezone

import pytest
from binapy import BinaPy
from freezegun.api import FrozenDateTimeFactory

from jwskate import (
    ExpectedAlgRequired,
    ExpiredJwt,
    InvalidClaim,
    InvalidJwt,
    InvalidSignature,
    JweCompact,
    Jwk,
    Jwt,
    JwtSigner,
    JwtVerifier,
    SignatureAlgs,
    SignedJwt,
    SymmetricJwk,
    UnsupportedAlg,
)


def test_signed_jwt() -> None:
    jwk = Jwk(
        {
            "kty": "EC",
            "alg": "ES256",
            "kid": "my_key",
            "crv": "P-256",
            "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
            "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
            "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
        }
    )

    jwt = Jwt(
        "eyJhbGciOiJFUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJuYmYiOjE2MjkyMDQ1NjAsImlzcyI6Imh0dHBzOi8vbXlhcy5sb2NhbCIsIm5vbmNlIjoibm9uY2UiLCJzdWIiOiIxMjM0NTYifQ.RhLqE8VGBjIRag4w9ps1oUQlxumma1fQzFH2UTrMDCjW2iTGdqhkOjpzb5bdI6tkQRRP64IGP4_CBa2BR7p26Q"
    )

    assert isinstance(jwt, SignedJwt)
    assert jwt.headers == {"alg": "ES256", "kid": "my_key"}
    assert jwt.claims == {
        "acr": "2",
        "amr": ["pwd", "otp"],
        "aud": "client_id",
        "auth_time": 1629204560,
        "exp": 1629204620,
        "iat": 1629204560,
        "nbf": 1629204560,
        "iss": "https://myas.local",
        "nonce": "nonce",
        "sub": "123456",
    }
    assert jwt.is_expired()
    assert jwt.sub == "123456"
    assert jwt.subject == "123456"
    assert jwt.audiences == ["client_id"]
    assert jwt.nonce == "nonce"
    assert jwt.amr == ["pwd", "otp"]
    assert jwt.exp == 1629204620
    assert jwt.expires_at == datetime.fromtimestamp(1629204620, tz=timezone.utc)
    assert jwt.issued_at == datetime.fromtimestamp(1629204560, tz=timezone.utc)
    assert jwt.not_before == datetime.fromtimestamp(1629204560, tz=timezone.utc)
    assert jwt.nonce == jwt["nonce"]

    # validating with the appropriate key must work

    jwt.validate(
        key=jwk.public_jwk(),
        issuer="https://myas.local",
        audience="client_id",
        check_exp=False,
    )

    # validating with another key must fail
    with pytest.raises(InvalidSignature):
        jwt.validate(Jwk.generate(alg="ES256").public_jwk())

    # invalid audience
    with pytest.raises(InvalidClaim, match="audience"):
        jwt.validate(
            jwk.public_jwk(),
            audience="foo",
        )


def test_unprotected() -> None:
    jwt = Jwt.unprotected({"foo": "bar"})
    assert jwt == "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ."
    assert jwt.alg == "none"
    assert jwt.signature == b""


def test_jwt_signer_and_verifier(issuer: str, freezer: FrozenDateTimeFactory) -> None:
    audience = "some_audience"
    signer = JwtSigner.with_random_key(issuer, alg="ES256")
    now = datetime.now(timezone.utc)
    jwt = signer.sign(subject="some_id", audience=audience, extra_claims={"foo": "bar"})
    assert isinstance(jwt, SignedJwt)
    assert jwt.subject == "some_id"
    assert jwt.audiences == [audience]
    assert jwt.iat == int(now.timestamp())
    assert jwt.expires_at is not None
    assert jwt.expires_at > now

    verifier = signer.verifier(audience=audience)

    @verifier.custom_verifier
    def foobar_verifier(j: SignedJwt) -> None:
        if j.foo != "bar":
            raise ValueError("This JWT is not FooBar compliant!")

    verifier.verify(jwt)

    @verifier.custom_verifier
    def failing_verifier(j: SignedJwt) -> None:
        raise ValueError("This token will never be valid")

    with pytest.raises(ValueError):
        verifier.verify(jwt)


def test_invalid_signed_jwt() -> None:
    with pytest.raises(InvalidJwt):
        SignedJwt("garbage")
    with pytest.raises(InvalidJwt):
        SignedJwt("garbage!.foo!.bar!")
    with pytest.raises(InvalidJwt):
        SignedJwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.garbage!.garbage!")
    with pytest.raises(InvalidJwt):
        SignedJwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.garbage!"
        )


def test_empty_jwt(private_jwk: Jwk) -> None:
    jwt = Jwt.sign({}, private_jwk)
    assert jwt.is_expired() is None
    assert jwt.issued_at is None
    assert jwt.expires_at is None
    assert jwt.not_before is None
    assert jwt.issuer is None
    assert jwt.audiences == []
    assert jwt.subject is None
    assert jwt.jwt_token_id is None
    assert jwt.kid == private_jwk.kid
    assert jwt.alg == private_jwk.alg

    with pytest.raises(AttributeError):
        jwt.foo

    with pytest.raises(KeyError):
        jwt["foo"]

    assert (
        str(jwt)
        == "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkpXSy1BQkNEIn0.e30.c_3ppMzgxnhn4CkLBCNNJ5_zdoS6S9P79cruukiuixMHoHIPF0_nzaj5LBRUXt3O47JiJyUzroi1MXNe_Kod9dqLRM8RJ9t3dbWJRNbPrgnCkqpUhNZ6frrc8jVs9Qu9xmXLDYEa4aSwPSkQTufWN1fC04Vzm8JUMVXM0AFeKjyEyUijEuqeBBFztDbIc2apyXWc5bZW7HEkhDNgKK0pWAVnXLwt4OwGQjd6ZOC5Hgx1wDbiam_abNWaDvR53JSCLM0wMpkYrONY_RPjWRycyeb9K5tHOcGbfRvQqpZGsRG-slf-bqwSOt-8G6Phc_YDv9Lw4NN-vqOxbo2lw-3Crw"
    )
    assert bytes(jwt) == str(jwt).encode()
    assert jwt.signed_part == b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkpXSy1BQkNEIn0.e30"

    jwt.validate(key=private_jwk.public_jwk(), check_exp=False)

    with pytest.raises(InvalidClaim):
        jwt.validate(key=private_jwk.public_jwk())


def test_validate() -> None:
    jwt = SignedJwt(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJhdWQiOiJodHRwczovL2F1ZGllbmNlLmxvY2FsIiwiZXhwIjoyMDAwMDAwMDAwLCJpYXQiOjE1MTYyMzkwMjIsImNsYWltMSI6IkkgaGF2ZSBhIDEifQ.bl5iNgXfkbmgDXItaUx7_1lUMNtOffihsShVP8MeE1g"
    )
    jwk = SymmetricJwk.from_bytes("your-256-bit-secret")

    jwt.validate(
        jwk,
        iss="https://issuer.local",
        audience="https://audience.local",
        sub="1234567890",
        name="John Doe",
        algs=SignatureAlgs.ALL_SYMMETRIC,
        claim1=lambda value: "1" in value,
    )

    with pytest.raises(ExpectedAlgRequired):
        # expected algs must be provided, unless jwk has an 'alg' parameter
        jwt.validate(jwk)

    with pytest.raises(UnsupportedAlg):
        # unsupported alg
        jwt.validate(jwk, alg="foobar")

    with pytest.raises(UnsupportedAlg):
        # unsupported alg
        jwt.validate(jwk, algs=SignatureAlgs.ALL_ASYMMETRIC)

    with pytest.raises(InvalidClaim):
        jwt.validate(jwk, sub="invalid_sub", algs=SignatureAlgs.ALL_SYMMETRIC)

    with pytest.raises(InvalidClaim):
        jwt.validate(jwk, issuer="invalid_iss", algs=SignatureAlgs.ALL_SYMMETRIC)

    with pytest.raises(InvalidClaim):
        jwt.validate(jwk, algs=SignatureAlgs.ALL_SYMMETRIC, claim1=lambda value: "2" in value)

    with pytest.raises(ExpiredJwt):
        SignedJwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJhdWQiOiJodHRwczovL2F1ZGllbmNlLmxvY2FsIiwiZXhwIjoxNTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjIsImNsYWltMSI6IkkgaGF2ZSBhIDEifQ.k4qhY14C0sJYTaUiAIc2kkybmaIxaUMkirIkln10SG4"
        ).validate(jwk, algs=SignatureAlgs.ALL_SYMMETRIC)


def test_encrypted_jwt() -> None:
    jwt = Jwt("""eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.
     QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM
     oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG
     TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima
     sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52
     YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a
     1rZgN5TiysnmzTROF869lQ.
     AxY8DCtDaGlsbGljb3RoZQ.
     MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM
     HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8.
     fiK51VwhsxJ-siBMR-YFiA""")

    assert isinstance(jwt, JweCompact)
    assert jwt.headers == {"alg": "RSA1_5", "enc": "A128CBC-HS256"}
    assert jwt.alg == "RSA1_5"
    assert jwt.enc == "A128CBC-HS256"
    assert (
        jwt.wrapped_cek.to("b64u")
        == b"QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtMoNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLGTkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26imasOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a1rZgN5TiysnmzTROF869lQ"
    )
    assert jwt.initialization_vector.to("b64u") == b"AxY8DCtDaGlsbGljb3RoZQ"
    assert (
        jwt.ciphertext.to("b64u")
        == b"MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaMHDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8"
    )
    assert jwt.authentication_tag.to("b64u") == b"fiK51VwhsxJ-siBMR-YFiA"

    jwk = Jwk(
        {
            "kty": "RSA",
            "n": (
                "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
                "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
                "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
                "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
                "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
                "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw"
            ),
            "e": "AQAB",
            "d": (
                "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
                "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
                "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
                "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
                "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
                "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"
            ),
            "p": (
                "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
                "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
                "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"
            ),
            "q": (
                "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
                "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
                "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"
            ),
            "dp": (
                "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
                "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
                "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"
            ),
            "dq": (
                "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
                "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
                "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"
            ),
            "qi": (
                "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
                "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
                "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
            ),
        }
    )

    assert jwt.decrypt(jwk).parse_from("json") == {
        "iss": "joe",
        "exp": 1300819380,
        "http://example.com/is_root": True,
    }


def test_audience() -> None:
    assert SignedJwt(
        "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJjbGllbnRfaWQifQ.S1FheqDgFtSCUg2YLvBjyTp7U_oTAdNeBU5DWJWG7nhdQ94kPEjz1aP8ALfHQI-V-SPA34FTm6a3NkG6C1opsg"
    ).audiences == ["client_id"]
    assert SignedJwt(
        "eyJhbGciOiJFUzI1NiJ9.eyJhdWQiOlsiY2xpZW50X2lkIl19.eLuTnfzUXE09-SwUfL70py-SlESZHom3SPK0deiy27QX5iCDjSk2rlSVAfcNpAO5DjnKKua3HHtAv6oE7Ox9vg"
    ).audiences == ["client_id"]
    assert (
        SignedJwt(
            "eyJhbGciOiJFUzI1NiJ9.e30.b7t6qRWXypeNf2GE2BnBqjfLbQ5FTcMFVGm6zjgbXSVZIKXNvkK-K4oRYurDD2YY8955JtnpajcVurns1PH-1Q"
        ).audiences
        == []
    )


def test_decrypt_nested_jwt() -> None:
    jwt = """
    eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0.
     g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M
     qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE
     b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh
     DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D
     YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq
     JGTO_z3Wfo5zsqwkxruxwA.
     UmVkbW9uZCBXQSA5ODA1Mg.
     VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB
     BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT
     -FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10
     l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY
     Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr
     ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2
     8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE
     l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U
     zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd
     _J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ.
     AVO9iT5AV4CzvDJCdhSFlQ"""

    jwk = {
        "kty": "RSA",
        "n": (
            "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
            "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
            "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
            "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
            "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
            "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw"
        ),
        "e": "AQAB",
        "d": (
            "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
            "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
            "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
            "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
            "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
            "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"
        ),
        "p": (
            "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
            "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
            "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"
        ),
        "q": (
            "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
            "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
            "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0"
        ),
        "dp": (
            "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
            "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
            "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs"
        ),
        "dq": (
            "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
            "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
            "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU"
        ),
        "qi": (
            "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
            "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
            "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
        ),
    }

    inner_jwt = Jwt.decrypt_nested_jwt(jwt, jwk)
    assert (
        inner_jwt
        == "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
    )


def test_sign_and_encrypt() -> None:
    sign_alg = "ES256"
    enc_alg = "RSA-OAEP-256"
    enc = "A128GCM"

    sign_jwk = Jwk.generate(alg=sign_alg).with_kid_thumbprint().with_usage_parameters()
    enc_jwk = Jwk.generate(alg=enc_alg).with_kid_thumbprint().with_usage_parameters()

    claims = {"iat": 1661759343, "exp": 1661759403, "nbf": 1661759323, "sub": "mysub"}
    enc_jwt = Jwt.sign_and_encrypt(claims, sign_jwk, enc_jwk.public_jwk(), enc)
    assert isinstance(enc_jwt, JweCompact)
    assert enc_jwt.cty == "JWT"
    assert enc_jwt.alg == enc_alg
    assert enc_jwt.enc == enc
    assert enc_jwt.kid == enc_jwk.kid

    inner_jwt = Jwt(enc_jwt.decrypt(enc_jwk))
    assert isinstance(inner_jwt, SignedJwt)
    assert inner_jwt.alg == sign_alg
    assert inner_jwt.claims == claims
    assert inner_jwt.verify_signature(sign_jwk.public_jwk())
    assert inner_jwt.kid == sign_jwk.kid

    verified_inner_jwt = Jwt.decrypt_and_verify(enc_jwt, enc_key=enc_jwk, sig_key=sign_jwk.public_jwk())
    assert isinstance(verified_inner_jwt, SignedJwt)

    # try to encrypt a JWT with an altered signature
    altered_inner_jwt = bytes(verified_inner_jwt)[:-4] + (
        b"aaaa" if not verified_inner_jwt.value.endswith(b"aaaa") else b"bbbb"
    )
    enc_altered_jwe = JweCompact.encrypt(altered_inner_jwt, key=enc_jwk.public_jwk(), enc=enc)
    with pytest.raises(InvalidSignature):
        Jwt.decrypt_and_verify(enc_altered_jwe, enc_key=enc_jwk, sig_key=sign_jwk.public_jwk())

    # trying to decrypt and verify a JWE nested in a JWE will raise a ValueError
    inner_jwe = JweCompact.encrypt(
        b"this_is_a_test",
        key=Jwk.generate(alg="ECDH-ES+A128KW", crv="P-256").public_jwk(),
        enc="A128GCM",
    )
    nested_inner_jwe = JweCompact.encrypt(inner_jwe, key=enc_jwk.public_jwk(), enc=enc)
    with pytest.raises(TypeError):
        Jwt.decrypt_and_verify(nested_inner_jwe, enc_key=enc_jwk, sig_key=sign_jwk.public_jwk())


def test_sign_without_alg() -> None:
    jwk = Jwk.generate_for_kty("EC", crv="P-256")
    with pytest.raises(ValueError, match="signing alg is required"):
        Jwt.sign({"foo": "bar"}, jwk)

    with pytest.raises(ValueError, match="signing alg is required"):
        Jwt.sign_arbitrary(claims={"foo": "bar"}, headers={}, key=jwk)


def test_large_jwt() -> None:
    with pytest.raises(ValueError, match="is abnormally big"):
        Jwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            f"{BinaPy.serialize_to('json', {f'claim{i}': f'value{i}' for i in range(16_000)}).ascii()}"
            ".bl5iNgXfkbmgDXItaUx7_1lUMNtOffihsShVP8MeE1g"
        )


def test_eq() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert Jwt(jwt) == Jwt(jwt)
    assert Jwt(jwt) == jwt
    assert Jwt(jwt) == jwt.encode()

    assert Jwt(jwt) != 1


def test_headers() -> None:
    jwt = Jwt(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im15X2tpZCIsImN0eSI6Im15X2N0eSJ9.e30.XYERQ3ODkqLEnQvcak8wHEVJMtEqNNUmzRGRtjmqcdE"
    )
    assert jwt.alg == "HS256"
    assert jwt.typ == "JWT"
    assert jwt.kid == "my_kid"
    assert jwt.cty == "my_cty"


def test_invalid_headers() -> None:
    jwt = Jwt(
        "eyJhbGciOjEsImtpZCI6MSwidHlwIjoxLCJjdHkiOjF9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cOUKU1ijv3KiN2KK_o50RU978I9MzQ4lNw2y7nOGAdM"
    )
    with pytest.raises(AttributeError):
        jwt.alg
    with pytest.raises(AttributeError):
        jwt.kid
    with pytest.raises(AttributeError):
        jwt.typ
    with pytest.raises(AttributeError):
        jwt.cty


def test_invalid_claims() -> None:
    jwt = SignedJwt(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsImlhdCI6ImZvbyIsImV4cCI6ImZvbyIsIm5iZiI6ImZvbyIsImlzcyI6MTExMSwiYXVkIjoxLCJqdGkiOjF9.XeKnvnirIE7LmkTVwVyWOVTKLawybdolAZTFtM4NfoI"
    )
    with pytest.raises(AttributeError):
        jwt.issuer
    with pytest.raises(AttributeError):
        jwt.subject
    with pytest.raises(AttributeError):
        jwt.issued_at
    with pytest.raises(AttributeError):
        jwt.expires_at
    with pytest.raises(AttributeError):
        jwt.not_before
    with pytest.raises(AttributeError):
        jwt.audiences
    with pytest.raises(AttributeError):
        jwt.jwt_token_id


def test_timestamp(freezer: FrozenDateTimeFactory) -> None:
    freezer.move_to("2022-10-07 10:40:15 UTC")
    now_ts = Jwt.timestamp()
    assert isinstance(now_ts, int)
    assert now_ts == 1665139215
    assert Jwt.timestamp_to_datetime(now_ts) == datetime(
        year=2022, month=10, day=7, hour=10, minute=40, second=15, tzinfo=timezone.utc
    )

    assert Jwt.timestamp(+60) == 1665139275
    assert Jwt.timestamp(-60) == 1665139155


def test_verifier(freezer: FrozenDateTimeFactory) -> None:
    freezer.move_to("2023-04-03 11:56:20 UTC")
    issuer = "https://my.issuer.local"
    audience = "myaudience"
    subject = "mysubject"
    private_jwk = Jwk(
        {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "kid": "MUBAl25sdPAIlnA_8-BnMcIe5e8LnlI5pHF6Zy-icvw",
            "x": "ftZqn6yrLR_4AytQz8Q_badHRTQ2Vc6Eg46ICsMuuMM",
            "y": "C4wIeHH0aIW5Tf1_EPnJkse-vcoDNd-kh8P6-Ci2MI8",
            "d": "3vyhseJLd51ZXdlrCHAPH1uv5Bp9IvnA8UB92ksu4MU",
        }
    )
    jwks = private_jwk.public_jwk().as_jwks()

    def suject_verifier(j: SignedJwt) -> None:
        if j.subject != subject:
            raise ValueError("Invalid Subject", jwt)

    def not_foo(j: SignedJwt) -> None:
        if "foo" in j.claims:
            raise ValueError("Token is foo!", jwt)

    verifier = JwtVerifier(
        jwks,
        issuer=issuer,
        audience=audience,
        alg="ES256",
        verifiers=[suject_verifier, not_foo],
    )

    verifier.verify(
        Jwt.sign(
            {
                "iss": "https://my.issuer.local",
                "aud": "myaudience",
                "iat": 1680523071,
                "exp": 1680523131,
                "sub": "mysubject",
            },
            private_jwk,
        )
    )

    with pytest.raises(InvalidClaim, match="issuer"):
        verifier.verify(
            Jwt.sign(
                {
                    "iss": "https://wrong.issuer.local",
                    "aud": "myaudience",
                    "iat": 1680522980,
                    "exp": 1680523040,
                    "sub": "mysubject",
                },
                private_jwk,
            )
        )

    with pytest.raises(InvalidClaim, match="audience"):
        verifier.verify(
            Jwt.sign(
                {
                    "iss": "https://my.issuer.local",
                    "aud": "wrong_audience",
                    "iat": 1680522980,
                    "exp": 1680523040,
                    "sub": "mysubject",
                },
                private_jwk,
            )
        )

    with pytest.raises(InvalidSignature):
        jwt = Jwt.sign(
            {
                "iss": "https://my.issuer.local",
                "aud": "myaudience",
                "iat": 1680523071,
                "exp": 1680523131,
                "sub": "mysubject",
            },
            private_jwk,
        )
        verifier.verify(str(jwt)[:-17] + "--wrong_signature")

    with pytest.raises(ExpiredJwt):
        verifier.verify(
            Jwt.sign(
                {
                    "iss": "https://my.issuer.local",
                    "aud": "myaudience",
                    "iat": 1680522860,  # expired
                    "exp": 1680522920,
                    "sub": "mysubject",
                },
                private_jwk,
            )
        )

    with pytest.raises(ValueError):
        verifier.verify(
            Jwt.sign(
                {
                    "iss": "https://my.issuer.local",
                    "aud": "wrong_audience",
                    "iat": 1680522980,
                    "exp": 1680523040,
                    "sub": "wrong_subject",
                },
                private_jwk,
            )
        )

    with pytest.raises(ValueError):
        verifier.verify(
            Jwt.sign(
                {
                    "iss": "https://my.issuer.local",
                    "aud": "myaudience",
                    "iat": 1680522860,
                    "exp": 1680522920,
                    "sub": "mysubject",
                    "foo": "bar",
                },
                private_jwk,
            )
        )

    valid_jwt_without_kid = Jwt.sign(
        {
            "iss": "https://my.issuer.local",
            "aud": "myaudience",
            "iat": 1680523071,
            "exp": 1680523131,
            "sub": "mysubject",
        },
        private_jwk.minimize(),
        alg="ES256",
    )

    verifier.verify(valid_jwt_without_kid)

    with pytest.raises(InvalidSignature):
        verifier.verify(str(valid_jwt_without_kid)[:-17] + "--wrong-signature")

    # init with a single Jwk
    JwtVerifier(
        private_jwk.public_jwk(),
        issuer=issuer,
        audience=audience,
        alg="ES256",
        verifiers=[suject_verifier, not_foo],
    ).verify(valid_jwt_without_kid)

    # init with a single Jwk as a dict
    JwtVerifier(
        dict(private_jwk.public_jwk()),
        issuer=issuer,
        audience=audience,
        alg="ES256",
        verifiers=[suject_verifier, not_foo],
    ).verify(valid_jwt_without_kid)

    # init with a JwkSet as a dict
    JwtVerifier(
        dict(private_jwk.public_jwk().as_jwks()),
        issuer=issuer,
        audience=audience,
        alg="ES256",
        verifiers=[suject_verifier, not_foo],
    ).verify(valid_jwt_without_kid)

    # init with a private key
    with pytest.raises(ValueError):
        JwtVerifier(
            dict(private_jwk),
            issuer=issuer,
            audience=audience,
            alg="ES256",
            verifiers=[suject_verifier, not_foo],
        ).verify(valid_jwt_without_kid)
