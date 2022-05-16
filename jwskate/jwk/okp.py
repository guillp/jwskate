"""This module implements JWK representing Octet Key Pairs from [RFC8037](https://datatracker.ietf.org/doc/rfc8037/)."""

from __future__ import annotations

from typing import Any, Mapping

from backports.cached_property import cached_property
from binapy import BinaPy
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from jwskate.jwa import X448, X25519, Ed448, Ed25519, EdDsa, OKPCurve

from .. import EcdhEs, EcdhEs_A128KW, EcdhEs_A192KW, EcdhEs_A256KW
from .base import Jwk, JwkParameter


class UnsupportedOKPCurve(KeyError):
    """Raised when an unsupported OKP curve is requested."""


class OKPJwk(Jwk):
    """Represent an OKP Jwk, with `kty=OKP`."""

    KTY = "OKP"

    CRYPTOGRAPHY_KEY_CLASSES = (
        ed25519.Ed25519PrivateKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PrivateKey,
        ed448.Ed448PublicKey,
        x25519.X25519PrivateKey,
        x25519.X25519PublicKey,
        x448.X448PrivateKey,
        x448.X448PublicKey,
    )

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

    KEY_MANAGEMENT_ALGORITHMS = {
        keyalg.name: keyalg
        for keyalg in [EcdhEs, EcdhEs_A128KW, EcdhEs_A192KW, EcdhEs_A256KW]
    }

    @property
    def is_private(self) -> bool:  # noqa: D102
        return "d" in self

    def _validate(self) -> None:
        if not isinstance(self.crv, str) or self.crv not in self.CURVES:
            raise UnsupportedOKPCurve(self.crv)
        super()._validate()

    @classmethod
    def get_curve(cls, crv: str) -> OKPCurve:
        """Get the OKPCurve instance from a curve identifier.

        Args:
          crv: a crv identifier

        Returns:
            the matching OKPCurve instance

        Raises:
            UnsupportedOKPCurve: if the curve is not supported
        """
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise UnsupportedOKPCurve(crv)
        return curve

    @property
    def curve(self) -> OKPCurve:
        """Get the OKPCurve instance for this key.

        Returns:
            the OKPCurve for this key
        """
        return self.get_curve(self.crv)

    @cached_property
    def public_key(self) -> bytes:
        """Get the public key from this Jwk.

        Returns:
            the public key (from param `x`)
        """
        return BinaPy(self.x).decode_from("b64u")

    @cached_property
    def private_key(self) -> bytes:
        """Get the private key from this Jwk.

        Returns:
            the private key (from param `d`)
        """
        return BinaPy(self.d).decode_from("b64u")

    @classmethod
    def from_cryptography_key(cls, cryptography_key: Any, **kwargs: Any) -> OKPJwk:
        """Initialize a OKPJwk from a `cryptography` key.

        Args:
          cryptography_key: a `cryptography` key
          **kwargs: additional members to include in the Jwk

        Returns:
            the matching OKPJwk
        """
        if isinstance(cryptography_key, ed25519.Ed25519PrivateKey):
            priv = cryptography_key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            pub = cryptography_key.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.private(
                crv="Ed25519",
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, ed25519.Ed25519PublicKey):
            pub = cryptography_key.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.public(
                crv="Ed25519",
                x=pub,
            )
        elif isinstance(cryptography_key, ed448.Ed448PrivateKey):
            priv = cryptography_key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            pub = cryptography_key.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.private(
                crv="Ed448",
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, ed448.Ed448PublicKey):
            pub = cryptography_key.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.public(crv="Ed448", x=pub)
        elif isinstance(cryptography_key, x25519.X25519PrivateKey):
            priv = cryptography_key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            pub = cryptography_key.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.private(
                crv="X25519",
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, x25519.X25519PublicKey):
            pub = cryptography_key.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.public(crv="X25519", x=pub)
        elif isinstance(cryptography_key, x448.X448PrivateKey):
            priv = cryptography_key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            pub = cryptography_key.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.private(
                crv="X448",
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, x448.X448PublicKey):
            pub = cryptography_key.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )
            return cls.public(crv="X448", x=pub)
        else:
            raise TypeError(
                "Unsupported key type for OKP. Supported key types are: "
                + ", ".join(kls.__name__ for kls in cls.CRYPTOGRAPHY_KEY_CLASSES)
            )

    def _to_cryptography_key(self) -> Any:
        """Intialize a `cryptography` key based on this Jwk.

        Returns:
            a Ed25519PrivateKey or a Ed25519PublicKey or a Ed448PrivateKey or a Ed448PublicKey based on the current Jwk

        Raises:
            UnsupportedOKPCurve: if this Jwk curve is not supported.
        """
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
        elif self.curve.name == "X25519":
            if self.is_private:
                return x25519.X25519PrivateKey.from_private_bytes(self.private_key)
            else:
                return x25519.X25519PublicKey.from_public_bytes(self.public_key)
        elif self.curve.name == "X448":
            if self.is_private:
                return x448.X448PrivateKey.from_private_bytes(self.private_key)
            else:
                return x448.X448PublicKey.from_public_bytes(self.public_key)
        else:
            raise UnsupportedOKPCurve(self.curve)

    @classmethod
    def public(cls, crv: str, x: bytes, **params: Any) -> OKPJwk:
        """Initialize a public OKPJwk based on the provided parameters.

        Args:
          crv: the key curve
          x: the public key
          **params: additional members to include in the Jwk

        Returns:
            the resulting OKPJwk
        """
        return cls(dict(kty="OKP", crv=crv, x=BinaPy(x).to("b64u").ascii(), **params))

    @classmethod
    def private(cls, crv: str, x: bytes, d: bytes, **params: Any) -> OKPJwk:
        """Initialize a private OKPJwk based on the provided parameters.

        Args:
          crv: the OKP curve
          x: the public key
          d: the private key
          **params: additional members to include in the Jwk

        Returns:
            the resulting OKPJwk
        """
        return cls(
            dict(
                kty=cls.KTY,
                crv=crv,
                x=BinaPy(x).to("b64u").ascii(),
                d=BinaPy(d).to("b64u").ascii(),
                **params,
            )
        )

    @classmethod
    def generate(cls, crv: str = "Ed25519", **params: Any) -> OKPJwk:
        """Generate a private OKPJwk on a given curve.

        Args:
          crv: the curve to use
          **params: additional members to include in the Jwk

        Returns:
            the resulting OKPJwk
        """
        curve = cls.get_curve(crv)
        x, d = curve.generate()
        return cls.private(crv=crv, x=x, d=d, **params)
