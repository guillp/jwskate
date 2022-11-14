"""This module implements JWK representing Octet Key Pairs from [RFC8037].

[RFC8037]: https://www.rfc-editor.org/rfc/rfc8037.html
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from backports.cached_property import cached_property
from binapy import BinaPy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519

from jwskate.jwa import (
    X448,
    X25519,
    EcdhEs,
    EcdhEs_A128KW,
    EcdhEs_A192KW,
    EcdhEs_A256KW,
    Ed448,
    Ed25519,
    EdDsa,
    OKPCurve,
)

from .alg import UnsupportedAlg
from .base import Jwk, JwkParameter


class UnsupportedOKPCurve(KeyError):
    """Raised when an unsupported OKP curve is requested."""


class OKPJwk(Jwk):
    """Represent an OKP Jwk, with `kty=OKP`."""

    KTY = "OKP"

    CRYPTOGRAPHY_PRIVATE_KEY_CLASSES = (
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
        x25519.X25519PrivateKey,
        x448.X448PrivateKey,
    )

    CRYPTOGRAPHY_PUBLIC_KEY_CLASSES = (
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
        x25519.X25519PublicKey,
        x448.X448PublicKey,
    )

    PARAMS = {
        "crv": JwkParameter("Curve", is_private=False, is_required=True, kind="name"),
        "x": JwkParameter(
            "Public Key", is_private=False, is_required=True, kind="b64u"
        ),
        "d": JwkParameter(
            "Private Key", is_private=True, is_required=True, kind="b64u"
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
    def from_bytes(
        cls,
        private_key: bytes,
        crv: Optional[str] = None,
        use: Optional[str] = None,
        **kwargs: Any,
    ) -> OKPJwk:
        """Initialize an `OKPJwk` from its private key.

        The public key will be automatically derived from the supplied private key,

        The appropriate curve will be guessed based on the key length or supplied `crv`/`use` hints:
        - 56 bytes will use X448
        - 57 bytes will use Ed448
        - 32 bytes will use Ed25519 or X25519. Since there is no way to guess which one you want, it needs an hint with either a `crv` or `use` parameter.

        Args:
            private_key: the 32, 56 or 57 bytes private key, as raw bytes
            crv: the curve to use
            use: the key usage
            **kwargs: additional members to include in the Jwk

        Returns:
            the matching OKPJwk
        """
        if crv and use:
            if (crv in ("Ed25519", "Ed448") and use != "sig") or (
                crv in ("X25519", "X448") and use != "enc"
            ):
                raise ValueError(
                    f"Inconsistent `crv={crv}` and `use={use}` parameters."
                )
        elif crv:
            if crv in ("Ed25519", "Ed448"):
                use = "sig"
            elif crv in ("X25519", "X448"):
                use = "enc"
            else:
                raise UnsupportedOKPCurve(crv)
        elif use:
            if use not in ("sig", "enc"):
                raise ValueError(f"Invalid `use={use}` parameter, need 'sig' or 'enc'.")

        cryptography_key: Any
        if len(private_key) == 32:
            if use == "sig":
                cryptography_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                    private_key
                )
            elif use == "enc":
                cryptography_key = x25519.X25519PrivateKey.from_private_bytes(
                    private_key
                )
            else:
                raise ValueError(
                    "You need to specify either crv={'Ed25519', 'X25519'} or use={'sig', 'enc'} when providing a 32 bytes private key."
                )
        elif len(private_key) == 56:
            cryptography_key = x448.X448PrivateKey.from_private_bytes(private_key)
            if use and use != "enc":
                raise ValueError(
                    f"Invalid `use={use}` parameter. Keys of length 56 bytes are for curve X448."
                )
            use = "enc"
        elif len(private_key) == 57:
            cryptography_key = ed448.Ed448PrivateKey.from_private_bytes(private_key)
            if use and use != "sig":
                raise ValueError(
                    f"Invalid `use={use}` parameter. Keys of length 57 bytes are for curve Ed448."
                )
            use = "sig"
        else:
            raise ValueError(
                "Invalid private key. It must be bytes of length 32, 56 or 57."
            )

        return OKPJwk.from_cryptography_key(cryptography_key, use=use, **kwargs)

    @classmethod
    def from_cryptography_key(cls, cryptography_key: Any, **kwargs: Any) -> OKPJwk:
        """Initialize an `OKPJwk` from a `cryptography` key.

        Args:
          cryptography_key: a `cryptography` key
          **kwargs: additional members to include in the Jwk

        Returns:
            the matching OKPJwk
        """
        if isinstance(cryptography_key, ed25519.Ed25519PrivateKey):
            priv = cryptography_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub = cryptography_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.private(
                crv="Ed25519",
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, ed25519.Ed25519PublicKey):
            pub = cryptography_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.public(
                crv="Ed25519",
                x=pub,
            )
        elif isinstance(cryptography_key, ed448.Ed448PrivateKey):
            priv = cryptography_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub = cryptography_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.private(
                crv="Ed448",
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, ed448.Ed448PublicKey):
            pub = cryptography_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.public(crv="Ed448", x=pub)
        elif isinstance(cryptography_key, x25519.X25519PrivateKey):
            priv = cryptography_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub = cryptography_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.private(
                crv="X25519",
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, x25519.X25519PublicKey):
            pub = cryptography_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.public(crv="X25519", x=pub)
        elif isinstance(cryptography_key, x448.X448PrivateKey):
            priv = cryptography_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub = cryptography_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.private(
                crv="X448",
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, x448.X448PublicKey):
            pub = cryptography_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.public(crv="X448", x=pub)
        else:
            raise TypeError(
                "Unsupported key type for OKP. Supported key types are: "
                + ", ".join(
                    kls.__name__
                    for kls in (
                        cls.CRYPTOGRAPHY_PRIVATE_KEY_CLASSES
                        + cls.CRYPTOGRAPHY_PUBLIC_KEY_CLASSES
                    )
                )
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
            raise UnsupportedOKPCurve(self.curve)  # pragma: no cover

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
    def generate(
        cls, crv: Optional[str] = None, alg: Optional[str] = None, **params: Any
    ) -> OKPJwk:
        """Generate a private OKPJwk on a given curve.

        You can specify either a curve or an algorithm identifier, or both.
        If using an alg identifier, crv will default to Ed25519 for signature algs,
        or X25519 for encryption algs.

        Args:
          crv: the curve to use
          alg: algorithm to use
          **params: additional members to include in the Jwk

        Returns:
            the resulting OKPJwk
        """
        if crv:
            curve = cls.get_curve(crv)
        elif alg:
            if alg in cls.SIGNATURE_ALGORITHMS:
                curve = Ed25519
            elif alg in cls.KEY_MANAGEMENT_ALGORITHMS:
                curve = X25519
            else:
                raise UnsupportedAlg(alg)
        else:
            raise ValueError(
                "You must supply at least a Curve identifier (crv) or an Algorithm identifier (alg) "
                "in order to generate an OKP JWK."
            )

        x, d = curve.generate()
        return cls.private(crv=curve.name, x=x, d=d, alg=alg, **params)

    @cached_property
    def use(self) -> Optional[str]:
        """Return the key use.

        For OKP keys, this can be directly deduced from the curve.
        """
        if self.curve in (Ed25519, Ed448):
            return "sig"
        elif self.curve in (X25519, X448):
            return "enc"
        return None  # pragma: no cover
