from jwcrypto.jwa import JWAThis is a collection of recipes related to `jwskate` usage.

# JWK

## Generate private/public key pairs

```python
from jwskate import Jwk

private_jwk = (
    Jwk.generate(alg="ES256")  # select the signature or encryption alg here
    .with_kid_thumbprint()  # optionally, include a RFC7638 compliant thumbprint as kid
    .with_usage_parameters()  # optionally, include 'use' and 'key_ops'
)

print(private_jwk)
# {
#   "kty": "EC",
#   "crv": "P-256",
#   "x": "fYI3VbV5MYEu3TNGU4fgEr5re_Pq_PfexDYvDomK3SY",
#   "y": "BEe3LhDVW_MsFFwPeRxW_cnGLakXdE6cvLfSXwLe6Gk",
#   "d": "Lce_08inNOEe6Q9xEGrR9T0CJNQa1o4EhGtDQYAI0N8",
#   "alg": "ES256",
#   "kid": "CzCOqostujy4iT3B55dkYYrSusaFvYjbCotGvo-e2gA",
#   "use": "sig",
#   "key_ops": [
#     "sign"
#   ]
# }

public_jwk = private_jwk.public_jwk()
print(public_jwk.to_json(indent=2))
# {
#   "kty": "EC",
#   "kid": "CzCOqostujy4iT3B55dkYYrSusaFvYjbCotGvo-e2gA",
#   "alg": "ES256",
#   "use": "sig",
#   "key_ops": [
#     "verify"
#   ],
#   "crv": "P-256",
#   "x": "fYI3VbV5MYEu3TNGU4fgEr5re_Pq_PfexDYvDomK3SY",
#   "y": "BEe3LhDVW_MsFFwPeRxW_cnGLakXdE6cvLfSXwLe6Gk"
# }

# let's expose this public key as a JWKS:
print(public_jwk.as_jwks().to_json(indent=2))
# {
#   "keys": [
#     {
#       "kty": "EC",
#       "kid": "CzCOqostujy4iT3B55dkYYrSusaFvYjbCotGvo-e2gA",
#       "alg": "ES256",
#       "use": "sig",
#       "key_ops": [
#         "verify"
#       ],
#       "crv": "P-256",
#       "x": "fYI3VbV5MYEu3TNGU4fgEr5re_Pq_PfexDYvDomK3SY",
#       "y": "BEe3LhDVW_MsFFwPeRxW_cnGLakXdE6cvLfSXwLe6Gk"
#     }
#   ]
# }
```

## Fetching a JWKS from a remote endpoint

```python
from jwskate import JwkSet
import requests

raw_jwks = requests.get("https://www.googleapis.com/oauth2/v3/certs").json()
jwkset = JwkSet(raw_jwks)

print(jwkset)
# {
#  "keys": [
#      ...
#  ]
# }

# compared to a raw dict, a JwkSet offers convenience methods like:
if jwkset.is_private:  # returns True if the jwks contains at least one private key
    raise ValueError(
        "JWKS contains private keys!"
    )  # an exposed JWKS should only contain public keys

my_jwk = jwkset.get_jwk_by_kid("my_key_id")  # gets a key by key id (kid)
# select keys that is suitable for signature verification
verification_jwks = jwkset.verification_keys()
# select keys that are suitable for encryption
encryption_jwks = jwkset.encryption_keys()
```

## Converting between PEM, DER, JWK and `cryptography` keys

```python
from jwskate import Jwk

# generate a sample JWK, any asymmetric type will do:
private_jwk = (
    Jwk.generate(alg="ES256")  # generates the key
    .with_usage_parameters()  # adds use and key_ops
    .with_kid_thumbprint()  # adds the key thumbprint as kid
)
print(private_jwk.to_json(indent=2))
# {'kty': 'EC',
#  'crv': 'P-256',
#  'x': '8xX1CEhDNNjEySUKLw88YeiVwEOW34BWm0hBkAxqlVU',
#  'y': 'UfZ0JKT7MxdNMyqMKzKcAcYTcuqoXeplcJ3jNfnj3tM',
#  'd': 'T45KDokOKyuhEA92ri5a951c5kjmQfGyh1SrEkonb4s',
#  'alg': 'ES256',
#  'use': 'sig',
#  'key_ops': ['sign'],
#  'kid': '_E8_LoT4QEwctEkGNbiP9dogVDz6Lq9i8G_fj9nnEo0'}

# get the cryptography key that is wrapped in the Jwk:
cryptography_private_key = private_jwk.cryptography_key
print(type(cryptography_private_key))
# <class 'cryptography.hazmat.backends.openssl.ec._EllipticCurvePrivateKey'>

# create the PEM for the private key (encrypted with a password)
private_pem = private_jwk.to_pem("Th1s_P@ssW0rD_iS_5o_5tr0nG!")
print(private_pem.decode())
# -----BEGIN ENCRYPTED PRIVATE KEY-----
# MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAhFd4nINf0/8QICCAAw
# DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEJNdsyMjSx3d6RqBBTuI5LoEgZD4
# qdPHcTZhKAuzQ9mkM1SlaZfiydWM2KFqPCYPLwoX+3kuCHPanMLlDxwOGN9XMRYl
# hG3eO0Gu4eWdc/2QEcXIyBCbyKnSwhaHUSSfkhyK9eh8diHQw+blOIImIldLPxnp
# +ABOhO6pCjQxM7I5op7RZuxLNWGLyAlfOOvawLfnM/wKLW6GXmlywu7PZ5qk9Bk=
# -----END ENCRYPTED PRIVATE KEY-----

# write this private PEM to a file:
with open("my_private_key.pem", "wb") as foutput:
    foutput.write(private_pem)

# get the matching public key
public_jwk = private_jwk.public_jwk()
print(public_jwk)
# {
#   "kty": "EC",
#   "kid": "m-oFw9zA2YPFyqm265jbHnzXRa3SQ1ESdCE1AtAqO1U",
#   "alg": "ES256",
#   "use": "sig",
#   "key_ops": [
#     "verify"
#   ],
#   "crv": "P-256",
#   "x": "VVbLOXwIgIFsYQSpnbLm5hr-ibfnIK0EeWYj2HXWvks",
#   "y": "7f24WIqwHGr-jU9dH8GHpPEHMtAuXiwsedFnS6xayhk"
# }

# get the cryptography public key
cryptography_public_key = public_jwk.cryptography_key
print(type(cryptography_public_key))
# <class 'cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey'>

# get the public PEM
public_pem = public_jwk.to_pem()
print(public_pem.decode())
# -----BEGIN PUBLIC KEY-----
# MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8xX1CEhDNNjEySUKLw88YeiVwEOW
# 34BWm0hBkAxqlVVR9nQkpPszF00zKowrMpwBxhNy6qhd6mVwneM1+ePe0w==
# -----END PUBLIC KEY-----

# write this public PEM to a file:
with open("my_public_key.pem", "wb") as foutput:
    foutput.write(public_pem)

# read the private PEM from file and load it as a Jwk:
with open("my_private_key.pem", "rb") as finput:
    private_pem_from_file = finput.read()
private_jwk_from_file = (
    Jwk.from_pem(private_pem_from_file, password="Th1s_P@ssW0rD_iS_5o_5tr0nG!")
    .with_usage_parameters(alg="ES256")  # adds back the alg, use and key_ops parameters
    .with_kid_thumbprint()  # adds back the thumbprint as kid
)
assert private_jwk_from_file == private_jwk

# read the public PEM from file and load it as a Jwk:
with open("my_public_key.pem", "rb") as finput:
    public_pem_from_file = finput.read()
public_jwk_from_pem_file = (
    Jwk.from_pem(public_pem_from_file)
    .with_usage_parameters(
        alg="ES256"
    )  # alg is not part of the PEM, so you can add it back
    .with_kid_thumbprint()  # adds back the thumbprint as kid
)
assert public_jwk_from_pem_file == public_jwk

# get the public DER
public_der = public_jwk.to_der()
print(public_der.hex())
# 3059301306072a8648ce3d020106082a8648ce3d03010703420004f315f508484334d8c4c9250a2f0f3c61e895c04396df80569b4841900c6a955551f67424a4fb33174d332a8c2b329c01c61372eaa85dea65709de335f9e3ded3
# write DER to a file
with open("my_public_key.der", "wb") as foutput:
    foutput.write(public_der)

# read a DER and load it as a Jwk:
with open("my_public_key.pem", "rb") as finput:
    public_pem_from_file = finput.read()
public_jwk_from_der_file = (
    Jwk.from_pem(public_pem_from_file)
    .with_usage_parameters(
        alg="ES256"
    )  # alg is not part of the DER, so you can add it back
    .with_kid_thumbprint()  # adds back the thumbprint as kid
)
assert public_jwk_from_der_file == public_jwk
```

# JWT

## Parsing a JWT

```python
from jwskate import Jwt
from datetime import datetime, timezone

# you may recognize the default JWT value from https://jwt.io
jwt = Jwt(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
# access the parsed header, as a dict
print(jwt.headers)
# {'alg': 'HS256', 'typ': 'JWT'}
# access the parsed claims, as a dict
print(jwt.claims)
# {'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}
# access the signature, as bytes
print(jwt.signature.hex())
# 49f94ac7044948c78a285d904f87f0a4c7897f7e8f3a4eb2255fda750b2cc397

# alg and typ from the headers are accessible as attributes
assert jwt.alg == "HS256"
assert jwt.typ == "JWT"

# some registered claims are accessible, pre-parsed and validated according to RFC7519
assert jwt.issuer is None
assert jwt.subject == "1234567890"
assert jwt.audiences == []
# this would be a datetime if token had a valid 'exp' claim
assert jwt.expires_at is None
# this would be a datetime if token had a valid 'nbf' claim
assert jwt.not_before is None
assert jwt.issued_at == datetime(2018, 1, 18, 1, 30, 22, tzinfo=timezone.utc)
assert jwt.jwt_token_id is None

# checking the signature is as easy as
if jwt.verify_signature(b"your-256-bit-secret", alg="HS256"):  # this returns a bool
    print("signature is verified")

# or, if you prefer an exception
jwt.verify(
    b"your-256-bit-secret", alg="HS256"
)  # this raises an exception if the signature is invalid
```

# Signing an arbitrary JWT

To have full control over the claims that are signed, use the low-level `Jwt.sign()` method.
You provide the full set of claims to sign and those will be signed _exactly_ as-is:

```python
from jwskate import Jwk, Jwt

sign_key = Jwk.generate(
    alg="ES256"
)  # here we generate a key, but you usually want to load your own key

claims = {"iss": "my_issuer", "iat": 1695715510, "sub": "my_sub"}
jwt = Jwt.sign(claims, sign_key)

print(jwt)
# eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteV9pc3N1ZXIiLCJpYXQiOjE2OTU3MTUyOTgsInN1YiI6Im15X3N1YiJ9.OBfoh-9zRhHkAEQQbbopUrJ_eENTRgSmllC8r-sCCVrQ73a_F9QAoAX-ye1RUUqLDRoaiEkhJI2VmLVmEEqdaQ
```

# Signing a "proper" JWT

To have jwskate help you with the "standardized" claims such as `iat`, `exp`, `iss`, use a `JwtSigner`.
You pre-configure it with an issuer, a signing key and alg, and a default lifetime. You can then use it to sign
your claims:

```python
from jwskate import JwtSigner, Jwk

sign_key = Jwk.generate(alg="ES256")

signer = JwtSigner(
    issuer="my_issuer",
    key=sign_key,
    default_lifetime=600,
)

jwt = signer.sign(
    subject="my_sub",
    audience="my_audience",
    extra_claims={"my_custom_claim1": "my_custom_value1"},
)

print(jwt)
# eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJteV9jdXN0b21fY2xhaW0xIjoibXlfY3VzdG9tX3ZhbHVlMSIsImlzcyI6Im15X2lzc3VlciIsImF1ZCI6Im15X2F1ZGllbmNlIiwic3ViIjoibXlfc3ViIiwiaWF0IjoxNjk1NzE4NTQ3LCJleHAiOjE2OTU3MTkxNDcsImp0aSI6IjMxMzQ2NGI5LWMwOGMtNGE0ZS04NGE3LTlmMmVlYmE4ZjdkNCJ9.TBr-tjZd9m6Kyaa4OYiv9K6V_n5MAr1iMTOpZvl255TbN4Mk2XD6rd-9_UQdsViGHqeBPSzYFM-4nILPP2Tgyw
print(jwt.claims)
# {'my_custom_claim1': 'my_custom_value1',
# 'iss': 'my_issuer',
# 'aud': 'my_audience',
# 'sub': 'my_sub',
# 'iat': 1695718547, # iat and exp are auto-generated based on current time
# 'exp': 1695719147,
# 'jti': '313464b9-c08c-4a4e-84a7-9f2eeba8f7d4'} # a jti is autogenerated
```

# Signing and encrypting a nested JWT

It is trivial to sign then encrypt a JWT. You just need a signing key, an encryption key, and the claims you need to sign. `jwskate` handles everything else for you!

```python
from jwskate import Jwk, Jwt

enc_key = Jwk.generate(alg="ECDH-ES+A128KW")  # choose your own key management alg!
sig_key = Jwk.generate(alg="ES256")  # choose your own signature alg!

claims = {"iss": "my_issuer", "iat": 1695715510, "sub": "my_sub"}

signed_and_encryted_jwt = Jwt.sign(claims, key=sig_key).encrypt(  # this signs a JWT
    key=enc_key.public_jwk(), enc="A256GCM"
)  # this encrypts the signed JWT into a JWE. Choose your own encryption alg!

print(signed_and_encryted_jwt)
# eyJjdHkiOiJKV1QiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJSOS05eExHb052M3JhVGp6bUJndXFoZUU0NlBCbVB3VnVSc2lGVkllQnVZIiwieSI6Il8tS2txYXNtR0E1M2g5RTB4MTF2QmlEQ1g1M3M4Qi1TZTdvR0M4OW5yR0EifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0.KJSBiz5MkCy-YojozYgs5wn14T4llyI-MQBtkkzQpeHx7NPEhxUieA.x-flJmO6j5fX1ayE.LgpTlnZ6t01rO_ojhpep8RVxvI0ijdV_PbR6JcolTp7e327QpSsLgEA6_gllMO6_oxSPiqFwNgU-FkQhInT1FGZWKc04EA1coAsvmkDykshKWxiSC4LimYkqi-YOSQW7K9IBuMdMyEY6gYEj-znsY1HbYrh3nhS8_03QRbK56fJYIYcLUhkbcZBe3nHdD5kqNNigCuMW8ENo7M6jT53ZC__lYUyVIc-_JLZGUCGCEbJB--1ctFYDA4Iwyvxhk-wi.esupByQ5sWTq2lvzyNLi4w

print(
    signed_and_encryted_jwt.headers
)  # note that this header is generated automatically, including the ephemeral public key (epk)
# {'cty': 'JWT', # the inner content-type is JWT
# 'epk': {'kty': 'EC', 'crv': 'P-256', 'x': 'R9-9xLGoNv3raTjzmBguqheE46PBmPwVuRsiFVIeBuY', 'y': '_-KkqasmGA53h9E0x11vBiDCX53s8B-Se7oGC89nrGA'},
# 'alg': 'ECDH-ES+A128KW',
# 'enc': 'A256GCM'}

# to decode and verify the inner signed JWT:
inner_signed_jwt = signed_and_encryted_jwt.decrypt_jwt(enc_key).verify(
    sig_key.public_jwk()
)

print(inner_signed_jwt)
# eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteV9pc3N1ZXIiLCJpYXQiOjE2OTU3MTU1MTAsInN1YiI6Im15X3N1YiJ9.smfmqDYveE4TQboXhzxb7qddrITvU7JpWNwSfLj4XDOt8-tHe-pAuZ5EYJD0p4cynS1OwhT8LGSWnVpi7bPBCw
```
