from typing import Any, Mapping

from binapy import BinaPy

from jwskate.jwa.okp import X448, X25519, Ed448, Ed25519, OKPCurve

from .base import Jwk, JwkParameter


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
        x, d = curve.generate()
        return cls.private(crv=crv, x=x, d=d, **params)

    def to_cryptography_key(self) -> Any:
        pass
