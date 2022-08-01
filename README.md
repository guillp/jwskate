# JwSkate

[![PyPi](https://img.shields.io/pypi/v/jwskate.svg)](https://pypi.python.org/pypi/jwskate)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A Pythonic implementation of Json Web Signature, Keys, Algorithms, Tokens and Encryption (RFC7514 to 7519), and their
extensions ECDH Signatures (RFC8037), and JWK Thumbprints (RFC7638).

- Free software: MIT
- Documentation: <https://guillp.github.io/jwskate/>

A quick usage example, generating an RSA private key, signing some data, then validating that signature:

```python
from jwskate import Jwk

# generate a RSA Jwk and sign a plaintext with it
rsa_private_jwk = Jwk.generate_for_kty("RSA", key_size=2048, kid="my_key", alg="RS256")

data = b"Signing is easy!"
signature = rsa_private_jwk.sign(data)

# extract the public key, and verify the signature with it
rsa_public_jwk = rsa_private_jwk.public_jwk()
assert rsa_public_jwk.verify(data, signature)

# let's see what a Jwk looks like:
assert isinstance(rsa_private_jwk, dict)  # Jwk are dict

print(rsa_private_jwk)
```

The result of this print JWK will look like this:

```
{ 'kty': 'RSA',
  'n': '...',
  'e': 'AQAB',
  'd': '...',
  'p': '...',
  'q': '...',
  'dp': '...',
  'dq': '...',
  'qi': '...',
  'kid': 'my_key',
  'alg': 'RS256',
}
```

Now let's sign a JWT containing arbitrary claims:

```python
from jwskate import Jwk, Jwt

private_jwk = Jwk.generate_for_kty("EC", kid="my_key")
claims = {"sub": "some_sub", "claim1": "value1"}
sign_alg = "ES256"

jwt = Jwt.sign(claims, private_jwk, sign_alg)
# that's it! we have a signed JWT
assert jwt.claims == claims  # claims can be accessed as a dict
assert jwt.sub == "some_sub"  # or individual claims can be accessed as attributes
assert jwt["claim1"] == "value1"  # or as dict items
assert jwt.alg == sign_alg  # alg and kid headers are also accessible as attributes
assert jwt.kid == private_jwk.kid
assert jwt.verify_signature(private_jwk.public_jwk(), sign_alg)

print(jwt)
```

This will output the full JWT compact representation. You can inspect it for example at <https://jwt.io>

```
eyJhbGciOiJFUzI1NiIsImtpZCI6Im15a2V5In0.eyJzdWIiOiJzb21lX3N1YiIsImNsYWltMSI6InZhbHVlMSJ9.C1KcDyDT8qXwUqcWzPKkQD7f6xai-gCgaRFMdKPe80Vk7XeYNa8ovuLwvdXgGW4ZZ_lL73QIyncY7tHGXUthag
```

Or let's sign a JWT with the standardised lifetime, subject, audience and ID claims:

```python
from jwskate import Jwk, JwtSigner

private_jwk = Jwk.generate_for_kty("EC")
signer = JwtSigner(issuer="https://myissuer.com", jwk=private_jwk, alg="ES256")
jwt = signer.sign(
    subject="some_sub",
    audience="some_aud",
    extra_claims={"custom_claim1": "value1", "custom_claim2": "value2"},
)

print(jwt.claims)
```

The generated JWT claims will include the standardised claims:

```
{'custom_claim1': 'value1',
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
- Json Web Keys (JWK) loading and generation
- Arbitrary data signature and verification using Json Web Keys
- Json Web Signatures (JWS) signing and verification
- Json Web Encryption (JWE) encryption and decryption
- Json Web Tokens (JWT) signing, verification and validation
- 100% type annotated
- nearly 100% code coverage
- Relies on [cryptography](https://cryptography.io) for all cryptographic operations
- Relies on [BinaPy](https://guillp.github.io/binapy/) for binary data manipulations

### Supported Signature algorithms

`jwskate` supports the following signature algorithms:

| Signature Alg | Description                                    | Key Type | Reference                          | Note                  |
|---------------|------------------------------------------------|----------|------------------------------------|-----------------------|
| HS256         | HMAC using SHA-256                             | oct      | RFC7518, Section 3.2               |                       |
| HS384         | HMAC using SHA-384                             | oct      | RFC7518, Section 3.2               |                       |
| HS512         | HMAC using SHA-512                             | oct      | RFC7518, Section 3.2               |                       |
| RS256         | RSASSA-PKCS1-v1_5 using SHA-256                | RSA      | RFC7518, Section 3.3               |                       |
| RS384         | RSASSA-PKCS1-v1_5 using SHA-384                | RSA      | RFC7518, Section 3.3               |                       |
| RS512         | RSASSA-PKCS1-v1_5 using SHA-512                | RSA      | RFC7518, Section 3.3               |                       |
| ES256         | ECDSA using P-256 and SHA-256                  | EC       | RFC7518, Section 3.4               |                       |
| ES384         | ECDSA using P-384 and SHA-384                  | EC       | RFC7518, Section 3.4               |                       |
| ES512         | ECDSA using P-521 and SHA-512                  | EC       | RFC7518, Section 3.4               |                       |
| PS256         | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 | RSA      | RFC7518, Section 3.5               |                       |
| PS384         | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 | RSA      | RFC7518, Section 3.5               |                       |
| PS512         | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 | RSA      | RFC7518, Section 3.5               |                       |
| EdDSA         | EdDSA signature algorithms                     | OKP      | RFC8037, Section 3.1               |                       |
| ES256K        | ECDSA using secp256k1 curve and SHA-256        | EC       | RFC8812, Section 3.2               |                       |
| HS1           | HMAC using SHA-1                               | oct      | https://www.w3.org/TR/WebCryptoAPI | Validation Only       |
| RS1           | RSASSA-PKCS1-v1_5 with SHA-1                   | oct      | https://www.w3.org/TR/WebCryptoAPI | Validation Only       |
| none          | No digital signature or MAC performed          |          | RFC7518, Section 3.6               | Not usable by mistake |

### Supported Key Management algorithms

`jwskate` supports the following key management algorithms:

| Signature Alg      | Description                                     | Key Type | Reference                          | Note        |
|--------------------|-------------------------------------------------|----------|------------------------------------|-------------|
| RSA1_5             | RSAES-PKCS1-v1_5                                | RSA      | RFC7518, Section 4.2               | Unwrap Only |
| RSA-OAEP           | RSAES OAEP using default parameters             | RSA      | RFC7518, Section 4.3               |             |
| RSA-OAEP-256       | RSAES OAEP using SHA-256 and MGF1 with SHA-256  | RSA      | RFC7518, Section 4.3               |             |
| RSA-OAEP-384       | RSA-OAEP using SHA-384 and MGF1 with SHA-384    | RSA      | https://www.w3.org/TR/WebCryptoAPI |             |
| RSA-OAEP-512       | RSA-OAEP using SHA-512 and MGF1 with SHA-512    | RSA      | https://www.w3.org/TR/WebCryptoAPI |             |
| A128KW             | AES Key Wrap using 128-bit key                  | oct      | RFC7518, Section 4.4               |             |
| A192KW             | AES Key Wrap using 192-bit key                  | oct      | RFC7518, Section 4.4               |             |
| A256KW             | AES Key Wrap using 256-bit key                  | oct      | RFC7518, Section 4.4               |             |
| dir                | Direct use of a shared symmetric key            | oct      | RFC7518, Section 4.5               |             |
| ECDH-ES            | ECDH-ES using Concat KDF                        | EC       | RFC7518, Section 4.6               |             |
| ECDH-ES+A128KW     | ECDH-ES using Concat KDF and "A128KW" wrapping  | EC       | RFC7518, Section 4.6               |             |
| ECDH-ES+A192KW     | ECDH-ES using Concat KDF and "A192KW" wrapping  | EC       | RFC7518, Section 4.6               |             |
| ECDH-ES+A256KW     | ECDH-ES using Concat KDF and "A256KW" wrapping  | EC       | RFC7518, Section 4.6               |             |
| A128GCMKW          | Key wrapping with AES GCM using 128-bit key     | oct      | RFC7518, Section 4.7               |             |
| A192GCMKW          | Key wrapping with AES GCM using 192-bit key     | oct      | RFC7518, Section 4.7               |             |
| A256GCMKW          | Key wrapping with AES GCM using 256-bit key     | oct      | RFC7518, Section 4.7               |             |
| PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and "A128KW" wrapping   | password | RFC7518, Section 4.8               |             |
| PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and "A192KW" wrapping   | password | RFC7518, Section 4.8               |             |
| PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and "A256KW" wrapping   | password | RFC7518, Section 4.8               |             |

### Supported Encryption algorithms

`jwskate` supports the following encryption algorithms:

| Signature Alg  | Description                                                 | Reference               |
|----------------|-------------------------------------------------------------|-------------------------|
| A128CBC-HS256  | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm | RFC7518, Section 5.2.3  |
| A192CBC-HS384  | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm | RFC7518, Section 5.2.4  |
| A256CBC-HS512  | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm | RFC7518, Section 5.2.5  |
| A128GCM        | AES GCM using 128-bit key                                   | RFC7518, Section 5.3    |
| A192GCM        | AES GCM using 192-bit key                                   | RFC7518, Section 5.3    |
| A256GCM        | AES GCM using 256-bit key                                   | RFC7518, Section 5.3    |

### Supported Elliptic Curves

`jwskate` supports the following Elliptic Curves:

| Curve     | Description                           | Key Type | Usage                 | Reference                |
|-----------|---------------------------------------|----------|-----------------------|--------------------------|
| P-256     | P-256 Curve                           | EC       | signature, encryption | RFC7518, Section 6.2.1.1 |
| P-384     | P-384 Curve                           | EC       | signature, encryption | RFC7518, Section 6.2.1.1 |
| P-521     | P-521 Curve                           | EC       | signature, encryption | RFC7518, Section 6.2.1.1 |
| secp256k1 | SECG secp256k1 curve                  | EC       | signature, encryption | RFC8812, Section 3.1     |
| Ed25519   | Ed25519 signature algorithm key pairs | OKP      | signature             | RFC8037, Section 3.1     |
| Ed448     | Ed448 signature algorithm key pairs   | OKP      | signature             | RFC8037, Section 3.1     |
| X25519    | X25519 function key pairs             | OKP      | encryption            | RFC8037, Section 3.2     |
| X448      | X448 function key pairs               | OKP      | encryption            | RFC8037, Section 3.2     |

## Why a new lib ?

There are already multiple implementations of JOSE and Json Web Crypto related specifications in Python. However, I have
been dissatisfied by all of them so far, so I decided to come up with my own module.

- [PyJWT](https://pyjwt.readthedocs.io): lacks support for JWK, JWE, JWS, requires keys in PEM format.
- [JWCrypto](https://jwcrypto.readthedocs.io/): very inconsistent and complex API.
- [Python-JOSE](https://python-jose.readthedocs.io/): lacks easy support for JWT validation
  (checking the standard claims like iss, exp, etc.), lacks easy access to claims

Not to say that those are _bad_ libs (I actually use `jwcrypto` myself for `jwskate` unit tests), but they either don't
support some important features, or they just don't feel easy-enough, Pythonic-enough to use.

## Design

### JWK are dicts

JWK are specified as JSON objects, which are parsed as `dict` in Python. The `Jwk` class in `jwskate` is actually a
`dict` subclass, so you can use it exactly like you would use a dict: you can access its members, dump it back as JSON, etc.
The same is true for Json Web tokens in JSON format.

### JWA Wrappers

While you can directly use `cryptography` to do the cryptographic operations that are described in [JWA](https://www.rfc-editor.org/info/rfc7518),
its usage is not straightforward and gives you plenty of options to carefully select, leaving room for errors.
To work around this, `jwskate` comes with a set of wrappers that implement the exact JWA specification, with minimum
risk of mistakes.

### Safe Signature Verification

For every signature verification method in `jwskate`, you have to provide the expected signature(s) algorithm(s).
That is to avoid a security flaw where your application accepts tokens with a weaker encryption scheme than what
your security policy mandates; or even worse, where it accepts unsigned tokens, or tokens that are symmetrically signed
with an improperly used public key, leaving your application exposed to exploitation by attackers.

Each signature verification accepts 2 args `alg` and `algs`. If you always expect to verify tokens signed with a single
signature algorithm, pass that algorithm ID to alg. If you accept multiple algs (for example, any asymmetric alg that
you consider strong enough), you can instead pass an iterable of allowed algorithms with `algs`. The signature will be
validated as long as it is signed with one of the provided algs.

For verification methods that accept a `Jwk` key, you don't have to provide an `alg` or `algs` if that Jwk has the
appropriate `alg` member that define which algorithm is supposed to be used with that key.

## Credits

All cryptographic operations are handled by [cryptography](https://cryptography.io).
