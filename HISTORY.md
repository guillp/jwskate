# History
## 0.8.0 (2023-06-21)
- BREAKING CHANGE: all method parameters `jwk`, `sig_jwk`, `enc_jwk`, or `jwk_or_password`, accepting a `Jwk` instance
have been renamed to `key` or `sig_key`,`enc_key` or `key_or_password` respectively.
They now accept either a `Jwk` instance, or a dict containing a JWK, or a `cryptography` key instance directly.
- Added `Jwt.sign_arbitrary()` to sign JWT with arbitrary headers, for testing purposes only!
- Updated dev dependencies

## 0.1.0 (2021-11-15)

- First release on PyPI.
