"""Main module for `jwskate`.

The `jwskate` module implements the various Json Web Crypto-related
standards: JWA, JWK, JWKS, JWE, JWT. Each standard has its own submodule, but
for convenience, you can import any class or component directly from the root
`jwskate` module.

`jwskate` doesn't implement any actual cryptographic operation, it just
provides a set of convenient wrappers around the `cryptography` module.
"""

__author__ = """Guillaume Pujol"""
__email__ = "guill.p.linux@gmail.com"

from .enums import EncryptionAlgs, KeyManagementAlgs, SignatureAlgs
from .jwa import (
    A128GCM,
    A128GCMKW,
    A128KW,
    A192GCM,
    A192GCMKW,
    A192KW,
    A256GCM,
    A256GCMKW,
    A256KW,
    ES256,
    ES256K,
    ES384,
    ES512,
    HS256,
    HS384,
    HS512,
    P_256,
    P_384,
    P_521,
    PS256,
    PS384,
    PS512,
    RS256,
    RS384,
    RS512,
    X448,
    X25519,
    Aes128CbcHmacSha256,
    Aes192CbcHmacSha384,
    Aes256CbcHmacSha512,
    BaseAESEncryptionAlg,
    BaseAlg,
    BaseAsymmetricAlg,
    BaseEcdhEs_AesKw,
    BaseKeyManagementAlg,
    BasePbes2,
    BaseRsaKeyWrap,
    BaseSignatureAlg,
    BaseSymmetricAlg,
    DirectKeyUse,
    EcdhEs,
    EcdhEs_A128KW,
    EcdhEs_A192KW,
    EcdhEs_A256KW,
    Ed448,
    Ed25519,
    EdDsa,
    EllipticCurve,
    OKPCurve,
    Pbes2_HS256_A128KW,
    Pbes2_HS384_A192KW,
    Pbes2_HS512_A256KW,
    PrivateKeyRequired,
    PublicKeyRequired,
    RsaEsOaep,
    RsaEsOaepSha256,
    RsaEsOaepSha384,
    RsaEsOaepSha512,
    RsaEsPcks1v1_5,
    secp256k1,
)
from .jwe import InvalidJwe, JweCompact
from .jwk import (
    ECJwk,
    ExpectedAlgRequired,
    InvalidJwk,
    Jwk,
    JwkSet,
    OKPJwk,
    RSAJwk,
    SymmetricJwk,
    UnsupportedAlg,
    UnsupportedEllipticCurve,
    UnsupportedOKPCurve,
)
from .jws import InvalidJws, JwsCompact
from .jwt import (
    EncryptedJwt,
    ExpiredJwt,
    InvalidClaim,
    InvalidJwt,
    InvalidSignature,
    Jwt,
    JwtSigner,
    SignedJwt,
)
