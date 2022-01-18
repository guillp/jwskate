from __future__ import annotations

from typing import Any, Mapping

from binapy import BinaPy
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from jwskate.jwa import X448, X25519, Ed448, Ed25519, EdDsa, OKPCurve

from .base import Jwk, JwkParameter


class UnsupportedOKPCurve(KeyError):
    pass


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
        curve.name: curve for curve in [Ed25519, Ed448, X448, X25519]
    }

    SIGNATURE_ALGORITHMS = {alg.name: alg for alg in (EdDsa,)}

    @property
    def curve(self) -> OKPCurve:
        if not isinstance(self.crv, str) or self.crv not in self.CURVES:
            raise AttributeError("unsupported crv", self.crv)
        return self.CURVES[self.crv]

    @property
    def public_key(self) -> bytes:
        return BinaPy(self.x).decode_from("b64u")

    @property
    def private_key(self) -> bytes:
        return BinaPy(self.d).decode_from("b64u")

    @classmethod
    def from_cryptography_key(cls, key: Any) -> OKPJwk:
        if isinstance(key, ed25519.Ed25519PrivateKey):
            priv = key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            pub = key.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.private(
                crv="Ed25519",
                x=pub,
                d=priv,
            )
        elif isinstance(key, ed25519.Ed25519PublicKey):
            pub = key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
            return cls.public(
                crv="Ed25519",
                x=pub,
            )
        elif isinstance(key, ed448.Ed448PrivateKey):
            priv = key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            pub = key.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.private(
                crv="Ed448",
                x=pub,
                d=priv,
            )
        else:
            raise TypeError(
                "A Ed25519PrivateKey or a Ed25519PublicKey or a Ed448PrivateKey or a Ed448PrivateKey is required."
            )

    def to_cryptography_key(self) -> Any:
        if self.curve.name == "Ed25519":
            if self.is_private:
                return ed25519.Ed25519PrivateKey.from_private_bytes(self.private_key)
            else:
                return ed25519.Ed25519PublicKey.from_public_bytes(self.public_key)
        elif self.curve.name == "Ed448":
            if self.is_private:
                return ed448.Ed448PrivateKey.from_private_bytes(self.private_key)
            else:
                return ed448.Ed448PublicKey.from_public_bytes(self.public_key)
        else:
            return UnsupportedOKPCurve(self.curve)

    @classmethod
    def public(cls, crv: str, x: bytes, **params: Any) -> OKPJwk:
        return cls(dict(crv=crv, x=BinaPy(x).encode_to("b64u"), **params))

    @classmethod
    def private(cls, crv: str, x: bytes, d: bytes, **params: Any) -> OKPJwk:
        return cls(
            dict(
                crv=crv,
                x=BinaPy(x).encode_to("b64u").decode(),
                d=BinaPy(d).encode_to("b64u").decode(),
                **params
            )
        )

    @classmethod
    def generate(cls, crv: str = "Ed25519", **params: Any) -> OKPJwk:
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise ValueError("Unsupported Curve", crv)
        x, d = curve.generate()
        return cls.private(crv=crv, x=x, d=d, **params)
