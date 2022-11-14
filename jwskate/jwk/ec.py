"""This module implements JWK representing Elliptic Curve keys."""

from __future__ import annotations

import warnings
from typing import Any, List, Mapping, Optional, Union

from backports.cached_property import cached_property
from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import ec

from jwskate.jwa import (
    ES256,
    ES256K,
    ES384,
    ES512,
    P_256,
    P_384,
    P_521,
    EcdhEs,
    EcdhEs_A128KW,
    EcdhEs_A192KW,
    EcdhEs_A256KW,
    EllipticCurve,
    secp256k1,
)

from .base import Jwk, JwkParameter


class UnsupportedEllipticCurve(KeyError):
    """Raised when an unsupported Elliptic curve is requested."""


class ECJwk(Jwk):
    """Represent an Elliptic Curve Jwk, with `kty=EC`."""

    KTY = "EC"

    CRYPTOGRAPHY_PRIVATE_KEY_CLASSES = (asymmetric.ec.EllipticCurvePrivateKey,)

    CRYPTOGRAPHY_PUBLIC_KEY_CLASSES = (asymmetric.ec.EllipticCurvePublicKey,)

    PARAMS: Mapping[str, JwkParameter] = {
        "crv": JwkParameter("Curve", is_private=False, is_required=True, kind="name"),
        "x": JwkParameter(
            "X Coordinate", is_private=False, is_required=True, kind="b64u"
        ),
        "y": JwkParameter(
            "Y Coordinate", is_private=False, is_required=True, kind="b64u"
        ),
        "d": JwkParameter(
            "ECC Private Key", is_private=True, is_required=True, kind="b64u"
        ),
    }

    CURVES: Mapping[str, EllipticCurve] = {
        curve.name: curve for curve in [P_256, P_384, P_521, secp256k1]
    }

    SIGNATURE_ALGORITHMS = {
        sigalg.name: sigalg for sigalg in [ES256, ES384, ES512, ES256K]
    }

    KEY_MANAGEMENT_ALGORITHMS = {
        keyalg.name: keyalg
        for keyalg in [EcdhEs, EcdhEs_A128KW, EcdhEs_A192KW, EcdhEs_A256KW]
    }

    @property
    def is_private(self) -> bool:  # noqa: D102
        return "d" in self

    def _validate(self) -> None:
        self.get_curve(self.crv)
        super()._validate()

    @classmethod
    def get_curve(cls, crv: str) -> EllipticCurve:
        """Get the EllipticCurve instance for a given curve identifier.

        Args:
          crv: the curve identifier

        Returns:
            the matching EllipticCurve instance

        Raises:
            UnsupportedEllipticCurve: if the curve identifier is not supported
        """
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise UnsupportedEllipticCurve(crv)
        return curve

    @property
    def curve(self) -> EllipticCurve:
        """Get the EllipticCurve instance for this key.

        Returns:
            the EllipticCurve instance
        """
        return self.get_curve(self.crv)

    @classmethod
    def public(cls, crv: str, x: int, y: int, **params: str) -> "ECJwk":
        """Initialize a public ECJwk from its public parameters.

        Args:
          crv: the curve to use
          x: the x coordinate
          y: the y coordinate
          **params: additional member to include in the Jwk

        Returns:
          an ECJwk initialized with the supplied parameters
        """
        coord_size = cls.get_curve(crv).coordinate_size
        return cls(
            dict(
                key="EC",
                crv=crv,
                x=BinaPy.from_int(x, length=coord_size).to("b64u"),
                y=BinaPy.from_int(y, length=coord_size).to("b64u"),
                **{k: v for k, v in params.items() if v is not None},
            )
        )

    @classmethod
    def private(cls, crv: str, x: int, y: int, d: int, **params: Any) -> "ECJwk":
        """Initialize a private ECJwk from its private parameters.

        Args:
          crv: the curve to use
          x: the x coordinate
          y: the y coordinate
          d: the elliptic curve private key
          **params: additional members to include in the JWK

        Returns:
          an ECJWk initialized with the supplied parameters
        """
        coord_size = cls.get_curve(crv).coordinate_size
        return cls(
            dict(
                kty="EC",
                crv=crv,
                x=BinaPy.from_int(x, coord_size).to("b64u").ascii(),
                y=BinaPy.from_int(y, coord_size).to("b64u").ascii(),
                d=BinaPy.from_int(d, coord_size).to("b64u").ascii(),
                **{k: v for k, v in params.items() if v is not None},
            )
        )

    @property
    def coordinate_size(self) -> int:
        """The coordinate size to use with the key curve.

        Returns:
          32, 48, or 66 (bits)
        """
        return self.curve.coordinate_size

    @classmethod
    def from_cryptography_key(cls, cryptography_key: Any, **kwargs: Any) -> ECJwk:
        """Initialize an ECJwk from a `cryptography` key.

        Args:
          cryptography_key: `cryptography` key
          **kwargs: additional members to include in the Jwk

        Returns:
            an ECJwk initialized from the provided `cryptography` key
        """
        parameters = EllipticCurve.get_jwk_parameters(cryptography_key)
        return cls(parameters)

    def _to_cryptography_key(
        self,
    ) -> Union[
        asymmetric.ec.EllipticCurvePrivateKey,
        asymmetric.ec.EllipticCurvePublicKey,
    ]:
        """Initialize a `cryptography` key based on this Jwk.

        Returns:
            an EllipticCurvePublicKey or EllipticCurvePrivateKey
        """
        if self.is_private:
            return asymmetric.ec.EllipticCurvePrivateNumbers(
                private_value=self.ecc_private_key,
                public_numbers=asymmetric.ec.EllipticCurvePublicNumbers(
                    x=self.x_coordinate,
                    y=self.y_coordinate,
                    curve=self.curve.cryptography_curve,
                ),
            ).private_key()
        else:
            return asymmetric.ec.EllipticCurvePublicNumbers(
                x=self.x_coordinate,
                y=self.y_coordinate,
                curve=self.curve.cryptography_curve,
            ).public_key()

    @classmethod
    def generate(
        cls, crv: Optional[str] = None, alg: Optional[str] = None, **params: str
    ) -> "ECJwk":
        """Generate a random ECJwk.

        Args:
          alg: the alg
          crv: the curve to use
          **params:

        Returns:
          a generated ECJwk

        Raises:
            UnsupportedEllipticCurve: if the provided curve identifier is not supported.
        """
        if crv is None and alg is None:
            warnings.warn(
                "No Curve identifier (crv) or an Algorithm identifier (alg) have been provided "
                "when generating an Elliptic Curve JWK. So there is no hint to determine which curve to use. "
                "Curve 'P-256' is used by default. You should explicitly pass an 'alg' or 'crv' parameter "
                "to explicitly select the appropriate Curve and avoid this warning."
            )
            crv = "P-256"
        curve: Optional[EllipticCurve] = None
        if crv:
            curve = cls.get_curve(crv)
        elif alg:
            if alg in cls.SIGNATURE_ALGORITHMS:
                curve = cls.SIGNATURE_ALGORITHMS[alg].curve
            elif alg in cls.KEY_MANAGEMENT_ALGORITHMS:
                curve = P_256

        if curve is None:
            raise UnsupportedEllipticCurve(crv)

        x, y, d = curve.generate()
        return cls.private(
            crv=curve.name,
            alg=alg,
            x=x,
            y=y,
            d=d,
            **params,
        )

    @cached_property
    def x_coordinate(self) -> int:
        """Return the x coordinate from this ECJwk.

        Returns:
         the x coordinate (from parameter `x`)
        """
        return BinaPy(self.x).decode_from("b64u").to_int()

    @cached_property
    def y_coordinate(self) -> int:
        """Return the y coordinate from this ECJwk.

        Returns:
            the y coordinate (from parameter `y`)
        """
        return BinaPy(self.y).decode_from("b64u").to_int()

    @cached_property
    def ecc_private_key(self) -> int:
        """Return the ECC private key from this ECJwk.

        Returns:
             the ECC private key (from parameter `d`)
        """
        return BinaPy(self.d).decode_from("b64u").to_int()

    def supported_signing_algorithms(self) -> List[str]:
        """Return the list of supported signature algorithms for this key.

        Returns:
            a list of supported algorithms identifiers
        """
        return [
            name
            for name, alg in self.SIGNATURE_ALGORITHMS.items()
            if alg.curve == self.curve
        ]

    def supported_key_management_algorithms(self) -> List[str]:
        """Return the list of supported Key Management algorithms for this key.

        Returns:
             a list of supported algorithms identifiers
        """
        return list(self.KEY_MANAGEMENT_ALGORITHMS)

    def supported_encryption_algorithms(self) -> List[str]:
        """Return the list of support Encryption algorithms for this key.

        Returns:
             a list of supported algorithms identifiers
        """
        return list(self.ENCRYPTION_ALGORITHMS)
