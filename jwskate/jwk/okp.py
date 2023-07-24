"""This module implements JWK representing Octet Key Pairs from [RFC8037].

[RFC8037]
: https: //www.rfc-editor.org/rfc/rfc8037.html

"""
from __future__ import annotations

from functools import cached_property
from typing import Any, Mapping

from binapy import BinaPy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519
from typing_extensions import override

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

from .. import KeyTypes
from .alg import UnsupportedAlg
from .base import Jwk, JwkParameter


class UnsupportedOKPCurve(KeyError):
    """Raised when an unsupported OKP curve is requested."""


class OKPJwk(Jwk):
    """Represent an Octet Key Pair keys in JWK format.

    Octet Key Pair keys have Key Type `"OKP"`.

    """

    KTY = KeyTypes.OKP

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
    @override
    def is_private(self) -> bool:
        return "d" in self

    @override
    def _validate(self) -> None:
        if not isinstance(self.crv, str) or self.crv not in self.CURVES:
            raise UnsupportedOKPCurve(self.crv)
        super()._validate()

    @classmethod
    def get_curve(cls, crv: str) -> OKPCurve:
        """Get the `OKPCurve` instance from a curve identifier.

        Args:
          crv: a curve identifier

        Returns:
            the matching `OKPCurve` instance

        Raises:
            UnsupportedOKPCurve: if the curve is not supported

        """
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise UnsupportedOKPCurve(crv)
        return curve

    @property
    def curve(self) -> OKPCurve:
        """Get the `OKPCurve` instance for this key."""
        return self.get_curve(self.crv)

    @cached_property
    def public_key(self) -> bytes:
        """Get the public key from this `Jwk`, from param `x`, base64url-decoded."""
        return BinaPy(self.x).decode_from("b64u")

    @cached_property
    def private_key(self) -> bytes:
        """Get the private key from this `Jwk`, from param `d`, base64url-decoded."""
        return BinaPy(self.d).decode_from("b64u")

    @classmethod
    def from_bytes(
        cls,
        private_key: bytes,
        crv: str | None = None,
        use: str | None = None,
        **kwargs: Any,
    ) -> OKPJwk:
        """Initialize an `OKPJwk` from its private key, as `bytes`.

        The public key will be automatically derived from the supplied private key, according to the OKP curve.

        The appropriate curve will be guessed based on the key length or supplied `crv`/`use` hints:

        - 56 bytes will use `X448`
        - 57 bytes will use `Ed448`
        - 32 bytes will use `Ed25519` or `X25519`. Since there is no way to guess which one you want,
          it needs a hint with either a `crv` or `use` parameter.

        Args:
            private_key: the 32, 56 or 57 bytes private key, as raw `bytes`
            crv: the curve identifier to use
            use: the key usage
            **kwargs: additional members to include in the `Jwk`

        Returns:
            the matching `OKPJwk`

        """
        if crv and use:
            if (crv in ("Ed25519", "Ed448") and use != "sig") or (
                crv in ("X25519", "X448") and use != "enc"
            ):
                raise ValueError(
                    f"Inconsistent `crv={crv}` and `use={use}` parameters. "
                    "Ed25519 and Ed448 are used for signing (use='sig'). "
                    "X25519 and X448 are used for encryption (use='enc'). "
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
                raise ValueError(
                    f"Invalid `use={use}` parameter, it must be either 'sig' or 'enc'."
                )

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
                    "You provided a 32 bytes private key, which is appropriate for both Ed25519 and X25519 curves. "
                    "There is no way to guess which curve you need, "
                    "so please specify either `crv='Ed25519'` or `use='sig'` for an Ed25519 key, "
                    "or either `crv='X25519'` or `use='enc'` for a X25519 key."
                )
        elif len(private_key) == 56:
            cryptography_key = x448.X448PrivateKey.from_private_bytes(private_key)
            if use and use != "enc":
                raise ValueError(
                    f"Invalid `use='{use}'` parameter. Keys of length 56 bytes are only suitable for curve 'X448'."
                )
            use = "enc"
        elif len(private_key) == 57:
            cryptography_key = ed448.Ed448PrivateKey.from_private_bytes(private_key)
            if use and use != "sig":
                raise ValueError(
                    f"Invalid `use='{use}'` parameter. Keys of length 57 bytes are only suitable for curve 'Ed448'."
                )
            use = "sig"
        else:
            raise ValueError(
                "Invalid private key. It must be `bytes`, of length 32, 56 or 57 bytes."
            )

        return OKPJwk.from_cryptography_key(cryptography_key, use=use, **kwargs)

    @classmethod
    @override
    def from_cryptography_key(cls, cryptography_key: Any, **kwargs: Any) -> OKPJwk:
        crv = OKPCurve.get_curve(cryptography_key)
        if isinstance(cryptography_key, cls.CRYPTOGRAPHY_PRIVATE_KEY_CLASSES):
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
                crv=crv.name,
                x=pub,
                d=priv,
            )
        elif isinstance(cryptography_key, cls.CRYPTOGRAPHY_PUBLIC_KEY_CLASSES):
            pub = cryptography_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return cls.public(
                crv=crv.name,
                x=pub,
            )
        raise TypeError(
            "Unsupported key type", type(cryptography_key)
        )  # pragma: no-cover

    @override
    def _to_cryptography_key(self) -> Any:
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
    def public(cls, *, crv: str, x: bytes, **params: Any) -> OKPJwk:
        """Initialize a public `OKPJwk` based on the provided parameters.

        Args:
          crv: the key curve
          x: the public key
          **params: additional members to include in the `Jwk`

        Returns:
            the resulting `OKPJwk`

        """
        return cls(dict(kty=cls.KTY, crv=crv, x=BinaPy(x).to("b64u").ascii(), **params))

    @classmethod
    def private(cls, *, crv: str, x: bytes, d: bytes, **params: Any) -> OKPJwk:
        """Initialize a private `OKPJwk` based on the provided parameters.

        Args:
          crv: the OKP curve
          x: the public key
          d: the private key
          **params: additional members to include in the `Jwk`

        Returns:
            the resulting `OKPJwk`

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
    @override
    def generate(
        cls, *, crv: str | None = None, alg: str | None = None, **params: Any
    ) -> OKPJwk:
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
                "in order to generate an OKPJwk."
            )

        x, d = curve.generate()
        return cls.private(crv=curve.name, x=x, d=d, alg=alg, **params)

    @cached_property
    @override
    def use(self) -> str | None:
        if self.curve in (Ed25519, Ed448):
            return "sig"
        elif self.curve in (X25519, X448):
            return "enc"
        raise UnsupportedOKPCurve(self.curse)  # pragma: no-cover
