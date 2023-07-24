# JwSkate

[![PyPi](https://img.shields.io/pypi/v/jwskate.svg)](https://pypi.python.org/pypi/jwskate)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A Pythonic implementation of the JOSE set of IETF specifications: [Json Web Signature][rfc7515], [Keys][rfc7517],
[Algorithms][rfc7518], [Tokens][rfc7519] and [Encryption][rfc7516] (RFC7515 to 7519), and their extensions
[ECDH Signatures][rfc8037] (RFC8037), [JWK Thumbprints][rfc7638] (RFC7638), and [JWK Thumbprint URI][rfc9278] (RFC9278),
and with respects to [JWT Best Current Practices][rfc8725] (RFC8725).

- Free software: MIT
- Documentation: [https://guillp.github.io/jwskate/](https://guillp.github.io/jwskate/)

Here is a quick usage example: generating a private RSA key, signing some data, then validating that signature with the matching public key:

```python
from jwskate import Jwk

# Let's generate a random private key, to use with alg 'RS256'.
# Based on that alg, jwskate knows it must be an RSA key.
# RSA keys can be of variable size, so let's pass the requested key size as parameter
rsa_private_jwk = Jwk.generate(alg="RS256", key_size=2048)

data = b"Signing is easy!"  # we will sign this
signature = rsa_private_jwk.sign(data)  # done!

# now extract the public key, and verify the signature with it
rsa_public_jwk = rsa_private_jwk.public_jwk()
assert rsa_public_jwk.verify(data, signature)

# let's see what a Jwk looks like:
assert isinstance(rsa_private_jwk, dict)  # Jwk are dict

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
from jwskate import Jwk, Jwt

# This time let's try an EC key, based on `alg` parameter,
# and let's specify an arbitrary Key ID (kid).
# additional args are either options (like 'key_size' above for RSA keys)
# or additional parameters to include in the JWK
private_jwk = Jwk.generate(alg="ES256", kid="my_key")
# note that based only on the `alg` value, the appropriate key type and curve
# are automatically deduced and included in the JWK
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
print(jwt)
# eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzb21lX3N1YiIsImNsYWltMSI6InZhbHVlMSJ9.SBQIlGlFdwoEMViWUFsBmCsXShtOq4lnp3Im5ZVh1PFCGJFdW-dTG9qJjlFSAA_BkM5PF9u38PL7Ai9cC2_DJw
assert isinstance(jwt, Jwt)  # Jwt are objects
assert jwt.claims == claims  # claims can be accessed as a dict
assert jwt.headers == {"typ": "JWT", "alg": "ES256", "kid": "my_key"}  # headers too
assert jwt.sub == "some_sub"  # individual claims can be accessed as attributes
assert jwt["claim1"] == "value1"  # or as dict items (with "subscription")
assert jwt.alg == "ES256"  # alg and kid headers are also accessible as attributes
assert jwt.kid == private_jwk.kid
# notice that alg and kid are automatically set with appropriate values taken from our private jwk
assert isinstance(jwt.signature, bytes)  # signature is accessible too
# verifying the jwt signature is as easy as:
assert jwt.verify_signature(private_jwk.public_jwk())
# since our jwk contains an 'alg' parameter (here 'ES256'), the signature is automatically verified using that alg
# you could also specify an alg manually, useful for keys with no "alg" hint:
assert jwt.verify_signature(private_jwk.public_jwk(), alg="ES256")
# note that jwskate will only trust the alg(s) you provide as parameter, either part of the JWK
# or with `alg` or `algs` params, and will ignore the 'alg' that is set in the JWT, for security reasons.
```

Now let's sign a JWT with the standardised lifetime, subject, audience and ID claims, plus arbitrary custom claims:

```python
from jwskate import Jwk, JwtSigner

private_jwk = Jwk.generate(alg="ES256")
signer = JwtSigner(issuer="https://myissuer.com", jwk=private_jwk)
jwt = signer.sign(
    subject="some_sub",
    audience="some_aud",
    extra_claims={"custom_claim1": "value1", "custom_claim2": "value2"},
)

print(jwt.claims)
```

The generated JWT will include the standardised claims (`iss`, `aud`, `sub`, `iat`, `exp` and `jti`),
together with the `extra_claims` provided to `.sign()`:

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
| `ES256`         | ECDSA using P-256 and SHA-256                    | `EC`     | [RFC7518, Section 3.4]             |                                |
| `ES384`         | ECDSA using P-384 and SHA-384                    | `EC`     | [RFC7518, Section 3.4]             |                                |
| `ES512`         | ECDSA using P-521 and SHA-512                    | `EC`     | [RFC7518, Section 3.4]             |                                |
| `PS256`         | RSASSA-PSS using SHA-256 and MGF1 with SHA-256   | `RSA`    | [RFC7518, Section 3.5]             |                                |
| `PS384`         | RSASSA-PSS using SHA-384 and MGF1 with SHA-384   | `RSA`    | [RFC7518, Section 3.5]             |                                |
| `PS512`         | RSASSA-PSS using SHA-512 and MGF1 with SHA-512   | `RSA`    | [RFC7518, Section 3.5]             |                                |
| `EdDSA`         | EdDSA signature algorithms                       | `OKP`    | [RFC8037, Section 3.1]             | Ed2219 and Ed448 are supported |
| `ES256K`        | ECDSA using secp256k1 curve and SHA-256          | `EC`     | [RFC8812, Section 3.2]             |                                |
| `HS1`           | HMAC using SHA-1                                 | `oct`    | https://www.w3.org/TR/WebCryptoAPI | Validation Only                |
| `RS1`           | RSASSA-PKCS1-v1_5 with SHA-1                     | `oct`    | https://www.w3.org/TR/WebCryptoAPI | Validation Only                |
| `none`          | No digital signature or MAC performed            |          | [RFC7518, Section 3.6]             | Not usable by mistake          |

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

### Supported Encryption algorithms


| Signature Alg | Description                                                 | Reference                |
| ------------- | ----------------------------------------------------------- | ------------------------ |
| `A128CBC-HS256` | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm | [RFC7518, Section 5.2.3] |
| `A192CBC-HS384` | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm | [RFC7518, Section 5.2.4] |
| `A256CBC-HS512` | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm | [RFC7518, Section 5.2.5] |
| `A128GCM`       | AES GCM using 128-bit key                                   | [RFC7518, Section 5.3]   |
| `A192GCM`       | AES GCM using 192-bit key                                   | [RFC7518, Section 5.3]   |
| `A256GCM`       | AES GCM using 256-bit key                                   | [RFC7518, Section 5.3]   |

### Supported Elliptic Curves


| Curve       | Description                           | Key Type | Usage                 | Reference                  |
|-------------|---------------------------------------|----------| --------------------- | -------------------------- |
| `P-256`     | P-256 Curve                           | `EC`     | signature, encryption | [RFC7518, Section 6.2.1.1] |
| `P-384`     | P-384 Curve                           | `EC`     | signature, encryption | [RFC7518, Section 6.2.1.1] |
| `P-521`     | P-521 Curve                           | `EC`     | signature, encryption | [RFC7518, Section 6.2.1.1] |
| `Ed25519`   | Ed25519 signature algorithm key pairs | `OKP`    | signature             | [RFC8037, Section 3.1]     |
| `Ed448`     | Ed448 signature algorithm key pairs   | `OKP`    | signature             | [RFC8037, Section 3.1]     |
| `X25519`    | X25519 function key pairs             | `OKP`    | encryption            | [RFC8037, Section 3.2]     |
| `X448`      | X448 function key pairs               | `OKP`    | encryption            | [RFC8037, Section 3.2]     |
| `secp256k1` | SECG secp256k1 curve                  | `EC`     | signature, encryption | [RFC8812, Section 3.1]     |

## Why a new lib ?

There are already multiple modules implementing JOSE and Json Web Crypto related specifications in Python. However, I
have been dissatisfied by all of them so far, so I decided to come up with my own module.

- [PyJWT](https://pyjwt.readthedocs.io)
- [JWCrypto](https://jwcrypto.readthedocs.io/)
- [Python-JOSE](https://python-jose.readthedocs.io/)
- [AuthLib](https://docs.authlib.org/en/latest/jose/)

Not to say that those are _bad_ libs (I actually use `jwcrypto` myself for `jwskate` unit tests), but they either don't
support some important features, lack documentation, or more generally have APIs that don't feel easy-enough, Pythonic-enough
to use.

## Design

### JWK are dicts

JWK are specified as JSON objects, which are parsed as `dict` in Python. The `Jwk` class in `jwskate` is actually a
`dict` subclass, so you can use it exactly like you would use a `dict`: you can access its members, dump it back as JSON,
etc. The same is true for Signed or Encrypted Json Web tokens in JSON format. However, you cannot change the key cryptographic
materials, since that would lead to unusable keys.

### JWA Wrappers

You can use `cryptography` to do the cryptographic operations that are described in
[JWA](https://www.rfc-editor.org/info/rfc7518), but since `cryptography` is a general purpose library, its usage is not
straightforward and gives you plenty of options to carefully select and combine, leaving room for mistakes, errors and
confusion. It has also a quite inconsistent API to handle the different type of keys and algorithms. To work around
this, `jwskate` comes with a set of consistent wrappers that implement the exact JWA specifications, with minimum risk
of mistakes.

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
