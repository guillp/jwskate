from datetime import datetime, timezone

import pytest
from freezegun import freeze_time  # type: ignore[import]

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
    SignatureAlgs,
    SignedJwt,
    SymmetricJwk,
    UnsupportedAlg,
)


def test_signed_jwt() -> None:
    jwt = Jwt(
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiwic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUnyTxl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCskqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f-azA"
    )

    assert isinstance(jwt, SignedJwt)
    assert jwt.headers == {"alg": "RS256", "kid": "my_key"}
    assert jwt.claims == {
        "acr": "2",
        "amr": ["pwd", "otp"],
        "aud": "client_id",
        "auth_time": 1629204560,
        "exp": 1629204620,
        "iat": 1629204560,
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
    assert jwt.nonce == jwt["nonce"]

    # validating with the appropriate key must work
    jwt.validate(
        jwk={
            "kty": "RSA",
            "alg": "RS256",
            "kid": "my_key",
            "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
            "e": "AQAB",
        },
        issuer="https://myas.local",
        audience="client_id",
        check_exp=False,
    )

    # validating with another key must fail
    with pytest.raises(InvalidSignature):
        jwt.validate(Jwk.generate_for_alg("RS256").public_jwk())


def test_unprotected() -> None:
    jwt = Jwt.unprotected({"foo": "bar"})
    assert jwt == "eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIifQ."


def test_jwt_signer(issuer: str, private_jwk: Jwk) -> None:
    signer = JwtSigner(issuer, private_jwk)
    now = datetime.now(timezone.utc)
    jwt = signer.sign(subject="some_id", audience="some_audience")
    assert isinstance(jwt, Jwt)
    assert jwt.subject == "some_id"
    assert jwt.audiences == ["some_audience"]
    assert jwt.iat == pytest.approx(now.timestamp())
    assert jwt.expires_at is not None
    assert jwt.expires_at > now


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
        == "eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXSy1BQkNEIn0.e30.iQ6eyP9QrNDQVfKYwHpIWvnTBb0SXNEItDxMQ0VmsB5CA5FaRYtGvj01VjoUAHEegGvwFI4YI35MDY_-DUR3UIXqxVMOe9Hk2hb9paTjJLpDIa7Ml6LKDh9-4xmAAPjZcra4IYrpDux8ohg0LUzgxHn0xnKDuxKmlh9shCyNWEOfN_i_JX4v8aSD-zDBteftrY9GzHU4Y0mlvlm4FaAwafPXovZilb_dTgTBkiFLmXY0y5ESurhQ4LrQqLzBz45lSONLElil5OQu0ySrrC72CBKp-HjdpCsLyG9F9p_X-1r9mmqlN38zIcgwkbhek04ieX-rumyzvHLO_UzttxDQOg"
    )
    assert bytes(jwt) == str(jwt).encode()
    assert jwt.signed_part == b"eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXSy1BQkNEIn0.e30"

    jwt.validate(jwk=private_jwk.public_jwk(), check_exp=False)

    with pytest.raises(InvalidClaim):
        jwt.validate(jwk=private_jwk.public_jwk())


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
        jwt.validate(
            jwk, algs=SignatureAlgs.ALL_SYMMETRIC, claim1=lambda value: "2" in value
        )

    with pytest.raises(ExpiredJwt):
        SignedJwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIubG9jYWwiLCJhdWQiOiJodHRwczovL2F1ZGllbmNlLmxvY2FsIiwiZXhwIjoxNTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjIsImNsYWltMSI6IkkgaGF2ZSBhIDEifQ.k4qhY14C0sJYTaUiAIc2kkybmaIxaUMkirIkln10SG4"
        ).validate(jwk, algs=SignatureAlgs.ALL_SYMMETRIC)


def test_encrypted_jwt() -> None:
    jwt = Jwt(
        """eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.
     QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM
     oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG
     TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima
     sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52
     YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a
     1rZgN5TiysnmzTROF869lQ.
     AxY8DCtDaGlsbGljb3RoZQ.
     MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM
     HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8.
     fiK51VwhsxJ-siBMR-YFiA"""
    )

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
            "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
            "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
            "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
            "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
            "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
            "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e": "AQAB",
            "d": "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
            "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
            "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
            "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
            "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
            "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            "p": "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
            "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
            "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
            "q": "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
            "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
            "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
            "dp": "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
            "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
            "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
            "dq": "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
            "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
            "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
            "qi": "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
            "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
            "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
        }
    )

    assert jwt.decrypt(jwk).parse_from("json") == {
        "iss": "joe",
        "exp": 1300819380,
        "http://example.com/is_root": True,
    }


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
        "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
        "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
        "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
        "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
        "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
        "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
        "e": "AQAB",
        "d": "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
        "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
        "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
        "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
        "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
        "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
        "p": "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
        "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
        "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
        "q": "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
        "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
        "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
        "dp": "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
        "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
        "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
        "dq": "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
        "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
        "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
        "qi": "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
        "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
        "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
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

    sign_jwk = (
        Jwk.generate_for_alg(sign_alg).with_kid_thumbprint().with_usage_parameters()
    )
    enc_jwk = (
        Jwk.generate_for_alg(enc_alg).with_kid_thumbprint().with_usage_parameters()
    )

    claims = {"iat": 1661759343, "exp": 1661759403, "sub": "mysub"}
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

    verified_inner_jwt = Jwt.decrypt_and_verify(
        enc_jwt, enc_jwk=enc_jwk, sig_jwk=sign_jwk.public_jwk()
    )
    assert isinstance(verified_inner_jwt, SignedJwt)

    # try to encrypt a JWT with an altered signature
    altered_inner_jwt = bytes(verified_inner_jwt)[:-4] + (
        b"aaaa" if not verified_inner_jwt.value.endswith(b"aaaa") else b"bbbb"
    )
    enc_altered_jwe = JweCompact.encrypt(
        altered_inner_jwt, jwk=enc_jwk.public_jwk(), enc=enc
    )
    with pytest.raises(InvalidSignature):
        Jwt.decrypt_and_verify(
            enc_altered_jwe, enc_jwk=enc_jwk, sig_jwk=sign_jwk.public_jwk()
        )

    # trying to decrypt and verify a JWE nested in a JWE will raise a ValueError
    inner_jwe = JweCompact.encrypt(
        b"this_is_a_test",
        jwk=Jwk.generate_for_alg("ECDH-ES+A128KW").public_jwk(),
        enc="A128GCM",
    )
    nested_inner_jwe = JweCompact.encrypt(inner_jwe, jwk=enc_jwk.public_jwk(), enc=enc)
    with pytest.raises(ValueError):
        Jwt.decrypt_and_verify(
            nested_inner_jwe, enc_jwk=enc_jwk, sig_jwk=sign_jwk.public_jwk()
        )


def test_sign_without_alg() -> None:
    jwk = Jwk.generate_for_kty("RSA")
    with pytest.raises(ValueError):
        Jwt.sign({"foo": "bar"}, jwk)


def test_large_jwt() -> None:
    with pytest.raises(ValueError):
        Jwt(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            f"{'alargevalue' * 16 * 1024}"
            "bl5iNgXfkbmgDXItaUx7_1lUMNtOffihsShVP8MeE1g"
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
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsImlhdCI6ImZvbyIsImV4cCI6ImZvbyIsIm5iZiI6ImZvbyIsImF1ZCI6MSwianRpIjoxfQ.lcNMSH9LNXbIpQUAqtbIjMv-kSWXeC0VamsrHNESTq0"
    )
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


@freeze_time("2022-10-07 10:40:15 UTC")  # type: ignore[misc]
def test_timestamp() -> None:
    now_ts = Jwt.timestamp()
    assert isinstance(now_ts, int)
    assert now_ts == 1665139215
    assert Jwt.timestamp_to_datetime(now_ts) == datetime(
        year=2022, month=10, day=7, hour=10, minute=40, second=15, tzinfo=timezone.utc
    )

    assert Jwt.timestamp(+60) == 1665139275
    assert Jwt.timestamp(-60) == 1665139155
