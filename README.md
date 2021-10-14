# JsonWebSkate


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


A Pythonic implementation of Json Web Signature, Keys, Algorithms, Tokens and Encryption (RFC7514 to 7519). It also
implements a few extensions like ECDH Signatures (RFC8037), and JWK Thumbprints (RFC7638).

* Free software: MIT
* Documentation: <https://jwskate.readthedocs.io>


A quick example of Json Web Keys (JWK) handling:

```python
from jwskate import Jwk

# generate a RSA Jwk and sign a plaintext with it
rsa_private_jwk = Jwk.generate_for_kty("RSA", key_size=2048)

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
  'kid': 'lfuHddfsvWsjLbMA4ZMCN0JD71RHmbKRCEo13tbyifY'
}
```

Now let's sign a JWT containing arbitrary claims:

```python
from jwskate import Jwk, Jwt

private_jwk = Jwk.generate_for_kty("RSA")
claims = {"sub": "some_sub", "claim1": "value1"}
sign_alg = "RS256"

jwt = Jwt.sign(claims, private_jwk, sign_alg)  # that's it! we have a signed JWT
assert jwt.claims == claims  # claims can be accessed as a dict
assert jwt.sub == "some_sub"  # or individual claims can be accessed as attributes
assert jwt["claim1"] == "value1"  # or as dict items
assert jwt.alg == sign_alg  # alg and kid headers are also accessible as attributes
assert jwt.kid == private_jwk.kid
assert jwt.verify_signature(private_jwk.public_jwk(), sign_alg)

print(jwt)
```
```
eyJhbGciOiJSUzI1NiIsImtpZCI6IkhyRnRZRk52U2g2WVp4WVpNY043XzM0dWNrN1hodTZFT2JoLWhkQVdqbHMifQ.eyJzdWIiOiJzb21lX3N1YiIsImNsYWltMSI6InZhbHVlMSJ9.RiBmKWC1Tu2IgUZNqSv84Gv1X-TttuKcUnee38Jn_KvRDjBw3ZQ1dEuG6hI8FVX4rDXmRMGNNsS51KL5BLTZNYd6Q34SJr_udIkwlW6xW-s39XzW1eMUSUkHa0p7CMpH32Vf-1ZPqnJMjMX6iq2nUOYxtPDZ5xdEjcTQhQf8llWunWhnTLLyMhY8Npz4c0veJkI9KxjM4_zLchpM0TR7OleBqflmbOzU14z2490K8VhHOfGxBr7Hj1WHvFMwC77qPU6jr6TSmHMFy5WvERfkbfpNgRQPFBWBDXT2uuWbFELUZHjfjaVA-uEy7SclDswTURKc-H-XWtdWKjb-tKKO5iNXd4qCeCakun5B3ykN7pE_u_bXO4fb5eSHWnBVByEa7UFBNLHIX2-aXOHZ95LpylDmXSpDTfHmpOGxxwT5SaRzosGH_cRbdmBKNEtTb0PG8tBQeq1uTpbhTL2u_H0KHUN8_C5GO5-5yelKhpMsHObFIcmy3WktRsgL98ATOXGYK0zShGeHc7JRHGJ5DQmU-FMK-eVe6J19LEpT0CgN4EljfsfSY7LBAFTE3yk3y95FDoYun7u_NcyZB5q_lhtHUKkTPqGLUEahNKCbn85AjMA8oLjlsAH123Hwz89NpxSY_FFWxSkUPAz477LWJUbgwGZhXUZYSFUQzk5DQ-0XMQU
```

Or let's sign a JWT with the standardised lifetime, subject, audience and ID claims:
```python
from jwskate import Jwk, JwtSigner

private_jwk = Jwk.generate_for_kty("RSA")
signer = JwtSigner(issuer="https://myissuer.com", jwk=private_jwk, alg="RS256")
jwt = signer.sign(
    subject="some_sub",
    audience="some_aud",
    extra_claims={"custom_claim1": "value1", "custom_claim2": "value2"},
)

print(jwt)
```

## Features

* Simple, Clean, Pythonic interface
* Json Web Keys (JWK) loading and generation
* Arbitrary data signature and verification using Json Web Keys
* Json Web Signatures (JWS) signing and verification
* Json Web Encryptions (JWE) encryption and decryption
* Json Web Tokens (JWT) signing, verification and validation
* 100% type annotated
* 100% code coverage
* Relies on [cryptography](https://cryptography.io)

## TODO
* Implement key loading and dumping to/from PEM or X509

## Credits

All cryptographic operations are handled by [cryptography](https://cryptography.io).

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [zillionare/cookiecutter-pypackage](https://github.com/zillionare/cookiecutter-pypackage) project template.
