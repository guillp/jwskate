# JwSkate


<p align="center">
<a href="https://pypi.python.org/pypi/jwskate">
    <img src="https://img.shields.io/pypi/v/jwskate.svg"
        alt = "Release Status">
</a>

<a href="https://github.com/guillp/jwskate/actions">
    <img src="https://github.com/guillp/jwskate/actions/workflows/main.yml/badge.svg?branch=release" alt="CI Status">
</a>

<a href="https://jwskate.readthedocs.io/en/latest/?badge=latest">
    <img src="https://readthedocs.org/projects/jwskate/badge/?version=latest" alt="Documentation Status">
</a>

</p>


A Pythonic implementation of Json Web Signature, Keys, Algorithms, Tokens and Encryption (RFC7514 to 7519), and their
extensions ECDH Signatures (RFC8037), and JWK Thumbprints (RFC7638).

* Free software: MIT
* Documentation: <https://guillp.github.io/jwskate/>


A quick usage example, generating an RSA private key, signing some data, then validating that signature:

```python
from jwskate import Jwk

# generate a RSA Jwk and sign a plaintext with it
rsa_private_jwk = Jwk.generate_for_kty("RSA", key_size=2048, kid="my_key")

data = b"Signing is easy!"
alg = "RS256"
signature = rsa_private_jwk.sign(data, alg)

# extract the public key, and verify the signature with it
rsa_public_jwk = rsa_private_jwk.public_jwk()
assert rsa_public_jwk.verify(data, signature, alg)

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
  'kid': 'my_key'
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

* Simple, Clean, Pythonic interface
* Convenience wrappers around `cryptography` for all algorithms described in JWA
* Json Web Keys (JWK) loading and generation
* Arbitrary data signature and verification using Json Web Keys
* Json Web Signatures (JWS) signing and verification
* Json Web Encryption (JWE) encryption and decryption
* Json Web Tokens (JWT) signing, verification and validation
* 100% type annotated
* nearly 100% code coverage
* Relies on [cryptography](https://cryptography.io) for all cryptographic operations
* Relies on [BinaPy](https://guillp.github.io/binapy/) for binary data manipulations

## Why a new lib ?

There are already multiple implementations of JOSE and Json Web Crypto related specifications in Python. However, I have
been dissatisfied by all of them so far, so I decided to come up with my own module.

- [PyJWT](https://pyjwt.readthedocs.io): lacks support for JWK, JWE, JWS, requires keys in PEM format.
- [JWCrypto](https://jwcrypto.readthedocs.io/): very inconsistent and complex API.
- [Python-JOSE](https://python-jose.readthedocs.io/): lacks easy support for JWT validation
(checking the standard claims like iss, exp, etc.), lacks easy access to claims

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
