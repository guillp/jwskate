from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric, serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519

from ..algorithms import SignatureAlg
from .base import Jwk, JwkParameter


class PublicKeyProtocol(Protocol):
    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        ...


class PrivateKeyProtocol(Protocol):
    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        ...

    def public_key(self) -> PublicKeyProtocol:
        ...


@dataclass
class OKPCurve:
    name: str
    description: str
    generator: Callable[[], PrivateKeyProtocol]
    use: str


class OKPJwk(Jwk):
    """
    Represent an OKP Jwk, with `kty=OKP`.
    """

    kty = "OKP"

    PARAMS = {
        "crv": JwkParameter("Curve", is_private=False, is_required=True, kind="name"),
        "x": JwkParameter(
            "Public Key", is_private=False, is_required=True, kind="b64u"
        ),
        "d": JwkParameter(
            "Private Key", is_private=True, is_required=False, kind="b64u"
        ),
    }

    CURVES: Mapping[str, OKPCurve] = {
        "Ed25519": OKPCurve(
            name="Ed25519",
            description="Ed25519 signature algorithm key pairs",
            generator=ed25519.Ed25519PrivateKey.generate,
            use="sig",
        ),
        "Ed448": OKPCurve(
            name="Ed448",
            description="Ed448 signature algorithm key pairs",
            generator=ed448.Ed448PrivateKey.generate,
            use="sig",
        ),
        "X25519": OKPCurve(
            name="X25519",
            description="X25519 function key pairs",
            generator=x25519.X25519PrivateKey.generate,
            use="enc",
        ),
        "X448": OKPCurve(
            name="X448",
            description="X448 function key pairs",
            generator=x448.X448PrivateKey.generate,
            use="enc",
        ),
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
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise ValueError("Unsupported Curve", crv)
        key = curve.generator()
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
