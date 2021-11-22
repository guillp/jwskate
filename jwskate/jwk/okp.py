from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Tuple

from binapy import BinaPy
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519

from .alg import SignatureAlg
from .base import Jwk, JwkParameter


@dataclass
class OKPSignatureAlg(SignatureAlg):
    pass


class OKPJwk(Jwk):
    """
    Represents an OKP Jwk (with `"kty": "OKP"`)
    """

    kty = "OKP"

    PARAMS = {
        "crv": JwkParameter("Curve", False, True, "name"),
        "x": JwkParameter("Public Key", False, True, "b64u"),
        "d": JwkParameter("Private Key", True, False, "b64u"),
    }

    CURVES: Mapping[str, Callable[[], Any]] = {
        # curve: generator
        "Ed25519": ed25519.Ed25519PrivateKey.generate,
        "Ed448": ed448.Ed448PrivateKey.generate,
        "X25519": x25519.X25519PrivateKey.generate,
        "X448": x448.X448PrivateKey.generate,
    }

    SIGNATURE_ALGORITHMS: Mapping[str, OKPSignatureAlg] = {
        # name : (description, hash_alg)
    }

    @classmethod
    def public(cls, crv: str, x: str, **params: str) -> "OKPJwk":
        return cls(dict(crv=crv, x=x, **params))

    @classmethod
    def private(cls, crv: str, x: bytes, d: bytes, **params: str) -> "OKPJwk":
        return cls(
            dict(
                crv=crv,
                x=BinaPy(x).encode_to("b64u").decode(),
                d=BinaPy(d).encode_to("b64u").decode(),
                **params
            )
        )

    @classmethod
    def generate(cls, crv: str = "Ed25519", **params: str) -> "OKPJwk":
        generator = cls.CURVES.get(crv)
        if generator is None:
            raise ValueError("Unsupported Curve", crv)
        key = generator()
        x = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        d = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return cls.private(crv=crv, x=x, d=d, **params)

    def to_cryptography_key(self) -> Any:
        if self.is_private:
            if self.curve == "Ed25519":
                return ed25519.Ed25519PrivateKey
