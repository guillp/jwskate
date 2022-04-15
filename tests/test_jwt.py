from datetime import datetime, timezone

import pytest

from jwskate import (
    ExpectedAlgRequired,
    ExpiredJwt,
    InvalidClaim,
    InvalidJwt,
    InvalidSignature,
    Jwk,
    Jwt,
    JwtSigner,
    SignatureAlgs,
    SignedJwt,
    SymmetricJwk,
    UnsupportedAlg,
)


def test_jwt() -> None:
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
    jwt.validate(
        jwk=Jwk(
            {
                "kty": "RSA",
                "alg": "RS256",
                "kid": "my_key",
                "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
                "e": "AQAB",
                "d": "RldleRTzwi8CRKB9CO4fsGNFxBCWJaWy8r2TIlBgYulZihPVwtLeVaIZ5dRrvxfcSNfuJ9CVJtm-1dI6ak71DJb6TvQYodFRm9uY6tNW5HRuZg_3_pLV8wqd7V1M8Zi-0gfnZZ5Q8vbgijeOyEQ54NLnVoTWO7M7nxqJjv6fk7Vd1vd6Gy8jI_soA6AMFCSAF-Vab07jGklBaLyow_TdczYufQ1737RNsFra2l43esAKeavxxkr7Js6OpgUkrXPEOc19GAwJLDdfkZ6yJLR8poWwX_OD-Opmvqmq6BT0s0mAyjBKZUxTGJuD3hm6mKOxXrbJOKY_UXRN7EAuH6U0gQ",
                "p": "9WQs9id-xB2AhrpHgyt4nfljXFXjaDqRHzUydw15HAOoSZzYMZJW-GT8g2hB3oH3EsSCuMh70eiE1ohTLeipYdJ-s7Gy5qTH5-CblT_OfLXxi2hIumdTx53w-AtDEWl2PRt_qGHZ0B83NjVU2fo96kp9bgJWYh_iWWtSJyabXbM",
                "q": "499_fCUhh5zL-3a4WGENy_yrsAa5C1sylZUtokyJNYBz68kWRFHFsArXnwZifBD_GWBgJQtldsouqvvPxzAlHQB9kfhxaRbaugwVePSjgHYmhd-NhAySq7rBURvRquAxJmoBmN2lS54YyN_X-VAKgfHDNsN7f7LIw9ISrLeR6EE",
                "dp": "Cfxwo_fJfduhfloYTOs49lzOwVQxc-1mOHnmuteOhShU8eHzHllRNryNVh-pBpANaPMcSr7F4y3uMfjMQcMFGZkCVPe3SxGLnRET48f79DFHSiANTaCk1SvFQaLbsNq02BnFYSnSPlj22zriYBiB6oXrgs2PjGC1ymPGrRcyHWc",
                "dq": "hL-4AfeTn_AtORJBdGMd6X8J-eMAu-fmARRF4G3b5Qou_eZIjYZhtxup31-V0hcItZzahdoswtYn9734nl6i0FFv1bC5SPJie838WFmUQosSCB1i0NGORHLombquG3C90VYiFg7Rc8rnP2Z_6CLD7E2OXwHkmVDq-oEQFgRfAME",
                "qi": "riPJlv9XNjdheryQWGr7Rhlvp9rxeNyWfVzj3y_IGh3tpe--Cd6-1GUrF00HLTTc-5iKVIa-FWOeMPTYc2_Uldi_0qWlrKjM5teIpUlDJbz7Ha-bfed9-eTbG8cI5F57KdDjbjB8YgqWYKz4YPMwqZFbWxZi4W_X79Bs3htXcXA",
            }
        ),
        issuer="https://myas.local",
        audience="client_id",
        check_exp=False,
    )

    with pytest.raises(InvalidSignature):
        jwt.validate(Jwk.generate_for_kty("RSA"), alg="RS256")


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
    assert jwt.audiences is None
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

    jwt.validate(jwk=private_jwk, check_exp=False)

    with pytest.raises(InvalidClaim):
        jwt.validate(jwk=private_jwk)


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
