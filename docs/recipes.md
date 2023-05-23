This is a collection of recipes related to `jwskate` usage.

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

## Converting between PEM key, JWK and `cryptography` keys

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

# create the PEM for the public key (unencrypted)
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
public_jwk_from_file = (
    Jwk.from_pem(public_pem_from_file)
    .with_usage_parameters(alg="ES256")  # adds back the alg, use and key_ops parameters
    .with_kid_thumbprint()  # adds back the thumbprint as kid
)
assert public_jwk_from_file == public_jwk
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
jwt.verify_signature(b"your-256-bit-secret", alg="HS256")
```
