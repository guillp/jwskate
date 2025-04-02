# ![jwskate](docs/logo.png)

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![PyPi](https://img.shields.io/pypi/v/jwskate.svg)](https://pypi.python.org/pypi/jwskate)
[![PyPi - License](https://img.shields.io/pypi/l/jwskate)](https://pypi.python.org/pypi/jwskate)
[![PyPI - Downloads](https://img.shields.io/pypi/dw/jwskate)](https://pypi.python.org/pypi/jwskate)
[![Supported Versions](https://img.shields.io/pypi/pyversions/jwskate.svg)](https://pypi.org/project/jwskate)
[![PyPI status](https://img.shields.io/pypi/status/jwskate.svg)](https://pypi.python.org/pypi/jwskate/)
[![GitHub commits](https://badgen.net/github/commits/guillp/jwskate)](https://github.com/guillp/jwskate/commit/)
[![GitHub latest commit](https://badgen.net/github/last-commit/guillp/jwskate)](https://github.com/guillp/jwskate/commit/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A Pythonic implementation of the JOSE set of IETF specifications: [Json Web Signature][rfc7515], [Keys][rfc7517],
[Algorithms][rfc7518], [Tokens][rfc7519] and [Encryption][rfc7516] (RFC7515 to 7519), hence the name **JWSKATE**, and
their extensions [ECDH Signatures][rfc8037] (RFC8037), [JWK Thumbprints][rfc7638] (RFC7638), and
[JWK Thumbprint URI][rfc9278] (RFC9278), with respects to [JWT Best Current Practices][rfc8725] (RFC8725).

- Free software: MIT
- Repository: https://github.com/guillp/jwskate/
- Documentation: https://guillp.github.io/jwskate/

Here is a quick usage example: generating a private RSA key, signing some data, then validating that signature with the
matching public key:

```python
from jwskate import Jwk

# Let's generate a random private key, to use with alg 'RS256'.
# Based on that alg, jwskate knows it must be an RSA key.
# RSA keys can be of any size, so let's pass the requested key size as parameter
rsa_private_jwk = Jwk.generate(alg="RS256", key_size=2048)

data = b"Signing is easy!"  # we will sign this
signature = rsa_private_jwk.sign(data)  # done!

print(signature)
# b'-\xe89\x81\xc4\xb9.G\x11\xa6\x93/dm\xf0\xc8\x0f\xd....'

# now extract the public key, and verify the signature with it
rsa_public_jwk = rsa_private_jwk.public_jwk()
assert rsa_public_jwk.verify(data, signature)

# let's see what a `Jwk` looks like:
from collections import UserDict

assert isinstance(rsa_private_jwk, UserDict)  # Jwk are UserDicts

print(rsa_private_jwk.with_usage_parameters())
```

The result of this print will look like this (with the random parts abbreviated to `...` for display purposes only):

```
{'kty': 'RSA',
 'n': '...',
 'e': 'AQAB',
 'd': '...',
 'p': '...',
 'q': '...',
 'dp': '...',
 'dq': '...',
 'qi': '...',
 'alg': 'RS256',
 'kid': '...',
 'use': 'sig',
 'key_ops': ['sign']}
```

Now let's sign a JWT containing arbitrary claims, this time using an Elliptic Curve (`EC`) key:

```python
from jwskate import Jwk, Jwt, InvalidSignature

# This time let's try to use the "ES256" alg, which is an ECDSA signature alg.
# Let's specify an arbitrary Key ID (kid).
private_jwk = Jwk.generate(alg="ES256", kid="my_key")
# Note that the appropriate key type and curve are determined automatically, based only on the `alg` value
print(private_jwk)
# {'kty': 'EC', 'crv': 'P-256', 'x': 'Ppe...', 'y': '9Si...', 'd': 'g09...', 'alg': 'ES256'}
assert private_jwk.kty == "EC"
assert private_jwk.crv == "P-256"
assert private_jwk.alg == "ES256"
# this is a private key and 'ES256' is a signature alg, so 'use' and 'key_ops' can also be deduced:
assert private_jwk.use == "sig"
assert private_jwk.key_ops == ("sign",)

# here are the claims to sign in a JWT:
claims = {"sub": "some_sub", "claim1": "value1"}

jwt = Jwt.sign(claims, private_jwk)
# that's it! we have a signed JWT.

# let's see what this looks like
assert isinstance(jwt, Jwt)  # Jwt are objects
print(jwt)  # they can be serialized to string with the `__str__` method
# eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzb21lX3N1YiIsImNsYWltMSI6InZhbHVlMSJ9.SBQIlGlFdwoEMViWUFsBmCsXShtOq4lnp3Im5ZVh1PFCGJFdW-dTG9qJjlFSAA_BkM5PF9u38PL7Ai9cC2_DJw
assert jwt.claims == claims  # claims can be accessed as a `dict`
assert jwt.headers == {"typ": "JWT", "alg": "ES256", "kid": "my_key"}  # headers too
assert jwt.sub == "some_sub"  # individual claims can be accessed as attributes
assert jwt["claim1"] == "value1"  # or as `dict` items (with "subscription")
assert jwt.alg == "ES256"  # alg and kid headers are also accessible as attributes
assert jwt.kid == private_jwk.kid
# notice that alg and kid are automatically set with appropriate values taken from our private jwk
assert isinstance(jwt.signature, bytes)  # signature is accessible too

# verifying the jwt signature is as easy as:
assert jwt.verify_signature(private_jwk.public_jwk())
# or, if you want an exception to be raised if the signature is invalid:
try:
    jwt.verify(private_jwk.public_jwk())
except InvalidSignature:
    print("Invalid signature!")  # this will not be printed, since the signature is valid
# since our jwk contains an 'alg' parameter (here 'ES256'), the signature is automatically verified using that alg
# you could also specify an alg manually, useful for keys with no "alg" hint:
assert jwt.verify_signature(private_jwk.public_jwk(), alg="ES256")
# note that jwskate will only trust the alg(s) you provide as parameter, either part of the JWK
# or with `alg` or `algs` params, and will ignore the 'alg' that is set in the JWT, for security reasons.
```

For most applications, you will often sign with the same key and issuer, and with a pre-determined token lifetime.
So you can create a `JwtSigner` object to simplify this for you:


```python
from jwskate import Jwk, JwtSigner

private_jwk = Jwk.generate(alg="ES256")
signer = JwtSigner(issuer="https://myissuer.com", key=private_jwk, default_lifetime=60)  # those values are pre-determined
jwt = signer.sign(  # so you only have to specify the variable claims when signing tokens
    subject="some_sub",
    audience="some_aud",
    extra_claims={"custom_claim1": "value1", "custom_claim2": "value2"},
)

print(jwt.claims)
```

The generated JWT will include the standardized claims (`iss`, `aud`, `sub`, `iat`, `exp` and `jti`), together with the
`extra_claims` provided to `.sign()`:

```
{
  'custom_claim1': 'value1',
  'custom_claim2': 'value2',
  'iss': 'https://myissuer.com',
  'aud': 'some_aud',
  'sub': 'some_sub',
  'iat': 1648823184,
  'exp': 1648823244,
  'jti': '3b400e27-c111-4013-84e0-714acd76bf3a'
}
```

## Features

- Simple, Clean, Pythonic interface
- Convenience wrappers around `cryptography` for all algorithms described in JWA
- Json Web Keys (JWK) loading, dumping and generation
- Arbitrary data signature and verification using Json Web Keys
- Json Web Signatures (JWS) signing and verification
- Json Web Encryption (JWE) encryption and decryption
- Json Web Tokens (JWT) signing, verification and validation
- 100% type annotated, verified with `mypy --strict`
- nearly 100% code coverage
- Relies on [cryptography](https://cryptography.io) for all cryptographic operations
- Relies on [BinaPy](https://guillp.github.io/binapy/) for binary data manipulations

### Supported Token Types


| Token Type                | Support                                                  |
| ------------------------- | -------------------------------------------------------- |
| Json Web Signature (JWS)  | ☑ Compact<br/> ☑ JSON Flat <br/> ☑ JSON General <br/> |
| Json Web Encryption (JWE) | ☑ Compact<br/> ☐ JSON Flat <br/> ☐ JSON General <br/> |
| Json Web Tokens (JWT)     | ☑ Signed<br/> ☑ Signed and Encrypted                   |

### Supported Signature algorithms


| Signature Alg   | Description                                      | Key Type | Reference                          | Note                           |
|-----------------|--------------------------------------------------|----------| ---------------------------------- | ------------------------------ |
| `HS256`         | HMAC using SHA-256                               | `oct`    | [RFC7518, Section 3.2]             |                                |
| `HS384`         | HMAC using SHA-384                               | `oct`    | [RFC7518, Section 3.2]             |                                |
| `HS512`         | HMAC using SHA-512                               | `oct`    | [RFC7518, Section 3.2]             |                                |
| `RS256`         | RSASSA-PKCS1-v1_5 using SHA-256                  | `RSA`    | [RFC7518, Section 3.3]             |                                |
| `RS384`         | RSASSA-PKCS1-v1_5 using SHA-384                  | `RSA`    | [RFC7518, Section 3.3]             |                                |
| `RS512`         | RSASSA-PKCS1-v1_5 using SHA-512                  | `RSA`    | [RFC7518, Section 3.3]             |                                |
| `PS256`         | RSASSA-PSS using SHA-256 and MGF1 with SHA-256   | `RSA`    | [RFC7518, Section 3.5]             |                                |
| `PS384`         | RSASSA-PSS using SHA-384 and MGF1 with SHA-384   | `RSA`    | [RFC7518, Section 3.5]             |                                |
| `PS512`         | RSASSA-PSS using SHA-512 and MGF1 with SHA-512   | `RSA`    | [RFC7518, Section 3.5]             |                                |
| `ES256`         | ECDSA using P-256 and SHA-256                    | `EC`     | [RFC7518, Section 3.4]             |                                |
| `ES384`         | ECDSA using P-384 and SHA-384                    | `EC`     | [RFC7518, Section 3.4]             |                                |
| `ES512`         | ECDSA using P-521 and SHA-512                    | `EC`     | [RFC7518, Section 3.4]             |                                |
| `ES256K`        | ECDSA using secp256k1 curve and SHA-256          | `EC`     | [RFC8812, Section 3.2]             |                                |
| `EdDSA`         | EdDSA signature algorithms                       | `OKP`    | [RFC8037, Section 3.1]             | Ed2219 and Ed448 are supported |
| `HS1`           | HMAC using SHA-1                                 | `oct`    | https://www.w3.org/TR/WebCryptoAPI | Validation Only                |
| `RS1`           | RSASSA-PKCS1-v1_5 with SHA-1                     | `RSA`    | https://www.w3.org/TR/WebCryptoAPI | Validation Only                |
| `none`          | No digital signature or MAC performed            |          | [RFC7518, Section 3.6]             | Not usable by mistake          |

### Supported Encryption algorithms


| Signature Alg   | Description                                                 | Reference                |
|-----------------|-------------------------------------------------------------|--------------------------|
| `A128CBC-HS256` | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm | [RFC7518, Section 5.2.3] |
| `A192CBC-HS384` | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm | [RFC7518, Section 5.2.4] |
| `A256CBC-HS512` | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm | [RFC7518, Section 5.2.5] |
| `A128GCM`       | AES GCM using 128-bit key                                   | [RFC7518, Section 5.3]   |
| `A192GCM`       | AES GCM using 192-bit key                                   | [RFC7518, Section 5.3]   |
| `A256GCM`       | AES GCM using 256-bit key                                   | [RFC7518, Section 5.3]   |

### Supported Key Management algorithms


| Signature Alg      | Description                                    | Key Type      | Reference                          | Note        |
| ------------------ | ---------------------------------------------- |---------------| ---------------------------------- | ----------- |
| `RSA1_5`             | RSAES-PKCS1-v1_5                               | `RSA`       | [RFC7518, Section 4.2]             | Unwrap Only |
| `RSA-OAEP`           | RSAES OAEP using default parameters            | `RSA`       | [RFC7518, Section 4.3]             |             |
| `RSA-OAEP-256`       | RSAES OAEP using SHA-256 and MGF1 with SHA-256 | `RSA`       | [RFC7518, Section 4.3]             |             |
| `RSA-OAEP-384`       | RSA-OAEP using SHA-384 and MGF1 with SHA-384   | `RSA`       | https://www.w3.org/TR/WebCryptoAPI |             |
| `RSA-OAEP-512`       | RSA-OAEP using SHA-512 and MGF1 with SHA-512   | `RSA`       | https://www.w3.org/TR/WebCryptoAPI |             |
| `A128KW`             | AES Key Wrap using 128-bit key                 | `oct`       | [RFC7518, Section 4.4]             |             |
| `A192KW`             | AES Key Wrap using 192-bit key                 | `oct`       | [RFC7518, Section 4.4]             |             |
| `A256KW`             | AES Key Wrap using 256-bit key                 | `oct`       | [RFC7518, Section 4.4]             |             |
| `A128GCMKW`          | Key wrapping with AES GCM using 128-bit key    | `oct`       | [RFC7518, Section 4.7]             |             |
| `A192GCMKW`          | Key wrapping with AES GCM using 192-bit key    | `oct`       | [RFC7518, Section 4.7]             |             |
| `A256GCMKW`          | Key wrapping with AES GCM using 256-bit key    | `oct`       | [RFC7518, Section 4.7]             |             |
| `dir`                | Direct use of a shared symmetric key           | `oct`       | [RFC7518, Section 4.5]             |             |
| `ECDH-ES`            | ECDH-ES using Concat KDF                       | `EC`        | [RFC7518, Section 4.6]             |             |
| `ECDH-ES+A128KW`     | ECDH-ES using Concat KDF and "A128KW" wrapping | `EC`        | [RFC7518, Section 4.6]             |             |
| `ECDH-ES+A192KW`     | ECDH-ES using Concat KDF and "A192KW" wrapping | `EC`        | [RFC7518, Section 4.6]             |             |
| `ECDH-ES+A256KW`     | ECDH-ES using Concat KDF and "A256KW" wrapping | `EC`        | [RFC7518, Section 4.6]             |             |
| `PBES2-HS256+A128KW` | PBES2 with HMAC SHA-256 and "A128KW" wrapping  | `password`  | [RFC7518, Section 4.8]             |             |
| `PBES2-HS384+A192KW` | PBES2 with HMAC SHA-384 and "A192KW" wrapping  | `password`  | [RFC7518, Section 4.8]             |             |
| `PBES2-HS512+A256KW` | PBES2 with HMAC SHA-512 and "A256KW" wrapping  | `password`  | [RFC7518, Section 4.8]             |             |



### Supported Elliptic Curves


| Curve       | Description                           | Key Type | Usage                 | Reference                  |
|-------------|---------------------------------------|----------| --------------------- | -------------------------- |
| `P-256`     | P-256 Curve                           | `EC`     | signature, encryption | [RFC7518, Section 6.2.1.1] |
| `P-384`     | P-384 Curve                           | `EC`     | signature, encryption | [RFC7518, Section 6.2.1.1] |
| `P-521`     | P-521 Curve                           | `EC`     | signature, encryption | [RFC7518, Section 6.2.1.1] |
| `secp256k1` | SECG secp256k1 curve                  | `EC`     | signature, encryption | [RFC8812, Section 3.1]     |
| `Ed25519`   | Ed25519 signature algorithm key pairs | `OKP`    | signature             | [RFC8037, Section 3.1]     |
| `Ed448`     | Ed448 signature algorithm key pairs   | `OKP`    | signature             | [RFC8037, Section 3.1]     |
| `X25519`    | X25519 function key pairs             | `OKP`    | encryption            | [RFC8037, Section 3.2]     |
| `X448`      | X448 function key pairs               | `OKP`    | encryption            | [RFC8037, Section 3.2]     |

## Why a new lib?

There are already multiple modules implementing JOSE and Json Web Crypto related specifications in Python. However, I
have been dissatisfied by all of them so far, so I decided to come up with my own module.

- [PyJWT](https://pyjwt.readthedocs.io)
- [JWCrypto](https://jwcrypto.readthedocs.io/)
- [Python-JOSE](https://python-jose.readthedocs.io/)
- [AuthLib](https://docs.authlib.org/en/latest/jose/)

Not to say that those are _bad_ libs (I actually use `jwcrypto` myself for `jwskate` unit tests), but they either don't
support some important features, lack documentation, or more generally have APIs that don't feel easy-enough,
Pythonic-enough to use. See [Design](#Design) below for some of the design decisions that lead to `jwskate`.

## Design

### Tokens are objects

Since JSON Web Tokens (JWT) are more and more used, JWT generation and validation must be as easy to do as possible. The
`Jwt` class wraps around a JWT value to allow easy access to its headers, claims and signature, and exposes methods to
easily verify the signature.

```python
from jwskate import Jwt

jwt = Jwt(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
assert jwt.headers == {"alg": "HS256", "typ": "JWT"}

assert jwt.claims == {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}

assert (
    jwt.signature
    == b"I\xf9J\xc7\x04IH\xc7\x8a(]\x90O\x87\xf0\xa4\xc7\x89\x7f~\x8f:N\xb2%_\xdau\x0b,\xc3\x97"
)
```

`Jwt` instances always represent a syntactically valid JWT. If you try to initialize one with a malformed value, you
will get a `InvalidJwt` exception, with an helpful error message:

```python
jwt = Jwt(
    "eyJhbGci-malformedheader.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
# jwskate.jwt.base.InvalidJwt: Invalid JWT header: it must be a Base64URL-encoded JSON object
```

`Jwt` may be objects, but they are easy to serialize into their representation. Use either `str()` or `bytes()`
depending on what type of value you need, or the `value` attribute:

```python
jwt = Jwt(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
str(jwt)
# 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
bytes(jwt)
# b'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
assert jwt.value == bytes(jwt)
```

The same is true for JWS and JWE tokens.

### Headers are auto-generated

When signing a JWS, JWE or JWT, the headers `alg`, `kid` and `typ` are autogenerated by default:
- `alg`: the signature or key-management alg
- `kid`: if the signature or key-management key has a `kid`, this will automatically be included in the headers.
- `typ`: will have value `"JWT"` by default.

You may add your own custom headers using the `extra_headers` parameter, and/or set a custom `typ` header with the
parameter of the same name:

```python
from jwskate import SymmetricJwk, Jwt

jwk = SymmetricJwk.from_bytes(b"T0t4llyR@nd0M", kid="symmetric_key1")
jwt = Jwt.sign(
    claims={"my": "claims"},
    key=jwk,
    alg="HS256",
    typ="CustomJWT",
    extra_headers={"custom_header": "custom_value"},
)
print(jwt)
# eyJhbGciOiJIUzI1NiIsImN1c3RvbV9oZWFkZXIiOiJjdXN0b21fdmFsdWUiLCJ0eXAiOiJDdXN0b21KV1QiLCJraWQiOiJzeW1tZXRyaWNfa2V5MSJ9.eyJteSI6ImNsYWltcyJ9.ZqCp8Crq-mdCXLoy5NiEdPTSUlIFEjrzexA6mKHrMAc
print(jwt.headers)
# {'alg': 'HS256', 'custom_header': 'custom_value', 'typ': 'CustomJWT', 'kid': 'symmetric_key1'}
```

If, for testing purposes, you need to fully control which headers are included in the JWT, even if they are inconsistent,
you can use `Jwt.sign_arbitrary()`:

```python
from jwskate import SymmetricJwk, Jwt

jwk = SymmetricJwk.from_bytes(b"T0t4llyR@nd0M", kid="symmetric_key1")
jwt = Jwt.sign_arbitrary(
    headers={
        "custom_header": "custom_value",
        "typ": "WeirdJWT",
        "kid": "R@nd0m_KID",
        "alg": "WeirdAlg",
    },
    claims={"my": "claims"},
    key=jwk,
    alg="HS256",
)
print(jwt)
# eyJjdXN0b21faGVhZGVyIjoiY3VzdG9tX3ZhbHVlIiwidHlwIjoiV2VpcmRKV1QiLCJraWQiOiJSQG5kMG1fS0lEIiwiYWxnIjoiV2VpcmRBbGcifQ.eyJteSI6ImNsYWltcyJ9.bcTFqCSiVIbyJhxClgsBDIyhbvLXTOXOV55QGqo2mhw
print(jwt.headers)  # you asked for inconsistent headers, you have them:
# {'custom_header': 'custom_value', 'typ': 'WeirdJWT', 'kid': 'R@nd0m_KID', 'alg': 'WeirdAlg'}
```

### `Jwk` as thin wrapper around `cryptography` keys

`Jwk` keys are just _thin_ wrappers around keys from the `cryptography` module, or, in the case of symmetric keys,
around `bytes`. But, unlike `cryptography` keys, they present a consistent interface for signature
creation/verification, key management, and encryption/decryption, regardless of the algorithm:

- For signature generation and verification, use `Jwk.sign()` and `Jwk.verify()` respectively
- For content encryption using a Key-Management alg and a symmetric Content-Encryption Key (CEK):
  - use `Jwk.sender_key()` to generate and wrap or otherwise derive a Content Encryption Key
  - use `Jwk.encrypt()` on that CEK to encrypt your data
- For decryption on the recipient side:
  - use `Jwk.recipient_key()` to unwrap or otherwise derive the CEK
  - use `Jwk.decrypt()` on that CEK to decrypt the encrypted data

Here is an example usage of signature and verification:

```python
from jwskate import Jwk, SignatureAlgs

# I'll use a symmetric key for this example, but the same applies to asymmetric keys
sig_key = Jwk.generate(alg=SignatureAlgs.HS256, kid="example_signature_key")  # symmetric key

# use `Jwk.sign()` and `Jwk.verify()` to sign and verify data
data = b"Something to sign"
signature = sig_key.sign(data)
if not sig_key.verify(data, signature[:-7] + b"altered"):
    print("Invalid signature!")

```

Here is an example of data encryption using a Key-Management alg and a Content-Encryption Key.
This example uses a Symmetric Key, but the interface is the same with private/public keys (excepted that encryption must be done with the public key).

```python
from jwskate import Jwk, EncryptionAlgs, KeyManagementAlgs
# generate a suitabe key
key_mgmt_key = Jwk.generate(alg=KeyManagementAlgs.A256KW, kid="example_key_management_key")
# First, choose your symmetric encryption alg
enc = EncryptionAlgs.A256GCM
# Use `Jwk.sender_key()` and `Jwk.recipient_key()` to generate or otherwise derive the CEK
# This will return a 3-tuple with the clear-text CEK, the wrapped CEK and extra headers to include in the token, if any
cek, wrapped_cek, headers = key_mgmt_key.sender_key(enc=enc)
# use the clear-text CEK to encrypt your data
secret_message = b"Encryption is easy!"
ciphertext, iv, tag = cek.encrypt(secret_message, enc=enc)
# you may also include Additional Authentication Data (AAD) with the `aad` parameter to `cek.encrypt()` above
# send the ciphertext, the wrapped CEK, IV, tag, AAD (if any) and extra headers to the recipient

recipient_cek = key_mgmt_key.recipient_key(wrapped_cek, enc=enc, **headers)
assert recipient_cek == cek  # the CEK is the same as the one we used to encrypt the data
cleartext = recipient_cek.decrypt(ciphertext, iv=iv, tag=tag, enc=enc) # if there is AAD, you must also include it here
assert cleartext == secret_message
```

All of the above is much easier if you use a JWE to encrypt your data:

```python
from jwskate import Jwk, JweCompact, EncryptionAlgs, KeyManagementAlgs

key = Jwk.generate(alg=KeyManagementAlgs.A256GCMKW)
jwe = JweCompact.encrypt(b"This is a secret message", key=key, enc=EncryptionAlgs.A256CBC_HS512)
print(jwe)

# the resulting JWE contains everything the recipient needs to be able to decrypt your message, excepted the key of course!
assert jwe.alg == "A256GCMKW" # key-management alg is part of the headers
assert jwe.enc == "A256CBC-HS512" # as well as content-encryption alg
assert isinstance(jwe.ciphertext, bytes) # the encrypted data
assert isinstance(jwe.wrapped_cek, bytes) # the CEK, if is it encrypted (empty if it is otherwise derived)
assert isinstance(jwe.initialization_vector, bytes) # the IV used for encryption
assert isinstance(jwe.authentication_tag, bytes) # the authentication tag
assert isinstance(jwe.additional_authenticated_data) # theJWE header part is used as AAD

# on recipient side, decryption is as easy as:
assert jwe.decrypt(key) == b"This is a secret message"
```

The `Jwk` layer is so thin, that everywhere a key is required as parameter, you may pass either:
- a `Jwk` instance,
- or a `Mapping` (typically a `dict`) representing the JWK key,
- a raw `cryptography` key instance, or a `bytes` if it is a symmetric key, but in that case, you must specify the `alg`
to use, since that is not part of the key.

As long as the provided key is suitable for the chosen algorithm, any of the above will work. Here is an example of
encrypting JWE tokens with raw `cryptography` keys:

```python
from jwskate import JweCompact
secret_message = b"my_very_secret_message"

# symmetric encryption with A128GCMKW and a 128 bit `bytes` key
aes_key = b"very_secret_key!"
jwe = JweCompact.encrypt(secret_message, key=aes_key, alg="A128GCMKW", enc="A128GCM")
assert jwe.decrypt(key=aes_key) == secret_message

# or, for asymmetric encryption with ECDH-ES+A256KW and a raw `cryptography` key (e.g. X25519):
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
eckey = X25519PrivateKey.generate()

jwe = JweCompact.encrypt(secret_message, key=eckey.public_key(), alg="ECDH-ES+A256KW", enc="A256GCM")
assert jwe.decrypt(key=eckey) == secret_message
```

### `Jwk` are `UserDict` instances

JWK are specified as JSON objects, which are parsed as `dict` in Python. The `Jwk` class in `jwskate` is actually a
`UserDict` subclass, which is very similar to a standard `dict`. So you can use it exactly like you would use a `dict`:
you can access its members, dump it back as JSON, etc. The same is true for Signed or Encrypted Json Web tokens in JSON
format. However, you cannot change the key cryptographic materials, since that would lead to unusable keys.

Unfortunately, `UserDict` is not natively serializable with the default JSON dump. To workaround that, you may either
use `Jwk.to_json()` / `JwkSet.to_json()` to get a JSON-serialized string, or `Jwk.to_dict()` / `JwkSet.to_dict()` to get
a standard `dict`, that is serializable by the standard `json` module.

### JWA Wrappers

You can use `cryptography` to do the cryptographic operations that are described in
[JWA](https://www.rfc-editor.org/info/rfc7518), but since `cryptography` is a general purpose library, its usage is not
straightforward and gives you plenty of options to carefully select and combine, leaving room for mistakes, errors and
confusion. It also has a quite inconsistent API to handle the different key types and algorithms. To work around this,
`jwskate` comes with a set of consistent wrappers that implement the exact JWA specifications, with minimum risk of
mistakes.

Here is an example of using raw JWA wrappers:

```python
from jwskate import A256KW, A256GCM  # pick any key-management and content-encryption algs

# on sender side, you have a message to encrypt and a pre-shared key with the recipient
secret_message = b"This is a secret message"

shared_key = A256KW.generate_key() # let's generate a suitable pre-shared key for this example, using this helper
a256kw = A256KW(shared_key) # you can initialize a JWA wrapper with a key of your choice this way

a256gcm = A256GCM.with_random_key() # or you can initialize them with a randomly generated key, as a one-liner
iv = A256GCM.generate_iv() # helper method for generating Initialisation Vectors of the appropriate size
ciphertext, tag = a256gcm.encrypt(secret_message, iv=iv) # use the Content-Encryption JWA wrapper to encrypt your message

wrapped_cek = a256kw.wrap_key(a256gcm.key) # and/or use the Key-Management JWA wrapper to wrap the CEK

# on recipient side, you receive ciphertext, iv, tag and wrapped_cek,
# and you are supposed to know the shared_key and algorithms to use
cek = A256KW(shared_key).unwrap_key(wrapped_cek) # so you can unwrap the CEK
cleartext = A256GCM(cek).decrypt(ciphertext, iv=iv, auth_tag=tag) # and decrypt the ciphertext and validating the tag

assert cleartext == secret_message
```

### Safe Signature Verification

As advised in [JWT Best Practices][rfc8725] $3.1:

For every signature verification method in `jwskate`, the expected signature(s) algorithm(s) must be specified. That is
to avoid a security flaw where your application accepts tokens with a weaker encryption scheme than what your security
policy mandates; or even worse, where it accepts unsigned tokens, or tokens that are symmetrically signed with an
improperly used public key, leaving your application exposed to exploitation by attackers.

To specify which signature algorithms are accepted, each signature verification method accepts, in order of preference:

- an `alg` parameter which contains the expected algorithm, or an `algs` parameter which contains a list of acceptable
  algorithms
- the `alg` parameter from the signature verification `Jwk`, if present. This `alg` is the algorithm intended for use
  with that key.

Note that you cannot use `alg` and `algs` at the same time. If your `Jwk` contains an `alg` parameter, and you provide
an `alg` or `algs` which does not match that value, a `Warning` will be emitted.

## TODO

- Complete/enhance/proof-read documentation
- Better exceptions (create dedicated exception classes, better messages, etc.)
- Support for JWE in JSON format
- Better tests
- Support for Selective-Disclosure JWT

## Credits

All cryptographic operations are handled by [cryptography](https://cryptography.io).

[rfc7515]: https://www.rfc-editor.org/rfc/rfc7515.html
[rfc7516]: https://www.rfc-editor.org/rfc/rfc7516.html
[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517.html
[rfc7518]: https://www.rfc-editor.org/rfc/rfc7518.html
[rfc7518, section 3.2]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2
[rfc7518, section 3.3]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3
[rfc7518, section 3.4]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4
[rfc7518, section 3.5]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5
[rfc7518, section 3.6]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6
[rfc7518, section 4.2]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4.2
[rfc7518, section 4.3]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3
[rfc7518, section 4.4]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4.4
[rfc7518, section 4.5]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4.5
[rfc7518, section 4.6]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6
[rfc7518, section 4.7]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4.7
[rfc7518, section 4.8]: https://www.rfc-editor.org/rfc/rfc7518.html#section-4.8
[rfc7518, section 5.2.3]: https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.3
[rfc7518, section 5.2.4]: https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.4
[rfc7518, section 5.2.5]: https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.5
[rfc7518, section 5.3]: https://www.rfc-editor.org/rfc/rfc7518.html#section-5.3
[rfc7518, section 6.2.1.1]: https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1
[rfc7519]: https://www.rfc-editor.org/rfc/rfc7519.html
[rfc7638]: https://www.rfc-editor.org/rfc/rfc7638.html
[rfc8037]: https://www.rfc-editor.org/rfc/rfc8037.html
[rfc8037, section 3.1]: https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1
[rfc8037, section 3.2]: https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2
[rfc8725]: https://www.rfc-editor.org/rfc/rfc8725
[rfc8812, section 3.1]: https://www.rfc-editor.org/rfc/rfc8812.html#section-3.1
[rfc8812, section 3.2]: https://www.rfc-editor.org/rfc/rfc8812.html#name-ecdsa-signature-with-secp25
[rfc9278]: https://www.rfc-editor.org/rfc/rfc9278.html
