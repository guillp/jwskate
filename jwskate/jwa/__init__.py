"""This module implements the Json Web Algorithms as defined in RFC7518.

Each algorithm is represented as a wrapper around a symmetric or
asymmetric key, and exposes the cryptographic operations as methods. The
cryptographic operations themselves are delegated to `cryptography`.
"""

from .base import (
    BaseAESEncryptionAlg,
    BaseAlg,
    BaseAsymmetricAlg,
    BaseKeyManagementAlg,
    BaseSignatureAlg,
    BaseSymmetricAlg,
    PrivateKeyRequired,
    PublicKeyRequired,
)
from .ec import P_256, P_384, P_521, EllipticCurve, secp256k1
from .encryption import (
    A128GCM,
    A192GCM,
    A256GCM,
    Aes128CbcHmacSha256,
    Aes192CbcHmacSha384,
    Aes256CbcHmacSha512,
)
from .key_mgmt import (
    A128GCMKW,
    A128KW,
    A192GCMKW,
    A192KW,
    A256GCMKW,
    A256KW,
    BaseAesGcmKeyWrap,
    BaseAesKeyWrap,
    BaseEcdhEs_AesKw,
    BasePbes2,
    BaseRsaKeyWrap,
    DirectKeyUse,
    EcdhEs,
    EcdhEs_A128KW,
    EcdhEs_A192KW,
    EcdhEs_A256KW,
    Pbes2_HS256_A128KW,
    Pbes2_HS384_A192KW,
    Pbes2_HS512_A256KW,
    RsaEsOaep,
    RsaEsOaepSha256,
    RsaEsOaepSha384,
    RsaEsOaepSha512,
    RsaEsPcks1v1_5,
)
from .okp import X448, X25519, Ed448, Ed25519, OKPCurve
from .signature import (
    ES256,
    ES256K,
    ES384,
    ES512,
    HS256,
    HS384,
    HS512,
    PS256,
    PS384,
    PS512,
    RS256,
    RS384,
    RS512,
    EdDsa,
)

__all__ = [
    "BaseAlg",
    "BaseAsymmetricAlg",
    "BaseSymmetricAlg",
    "BaseAESEncryptionAlg",
    "BaseKeyManagementAlg",
    "BaseSignatureAlg",
    "P_256",
    "P_384",
    "P_521",
    "EllipticCurve",
    "secp256k1",
    "Aes128CbcHmacSha256",
    "Aes192CbcHmacSha384",
    "Aes256CbcHmacSha512",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "BaseAesGcmKeyWrap",
    "A128GCM",
    "A192GCM",
    "A256GCM",
    "BaseAesKeyWrap",
    "A128KW",
    "A192KW",
    "A256KW",
    "DirectKeyUse",
    "EcdhEs",
    "BaseEcdhEs_AesKw",
    "EcdhEs_A128KW",
    "EcdhEs_A192KW",
    "EcdhEs_A256KW",
    "BasePbes2",
    "Pbes2_HS256_A128KW",
    "Pbes2_HS384_A192KW",
    "Pbes2_HS512_A256KW",
    "BaseRsaKeyWrap",
    "RsaEsOaep",
    "RsaEsOaepSha256",
    "RsaEsOaepSha384",
    "RsaEsOaepSha512",
    "RsaEsPcks1v1_5",
    "HS256",
    "HS384",
    "HS512",
    "EdDsa",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "RS256",
    "RS384",
    "RS512",
    "OKPCurve",
    "Ed25519",
    "Ed448",
    "X448",
    "X25519",
    "PrivateKeyRequired",
    "PublicKeyRequired",
]
