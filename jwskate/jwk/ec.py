from __future__ import annotations

from typing import Any, List, Mapping, Union

from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric

from jwskate.jwa import (
    ES256,
    ES256K,
    ES384,
    ES512,
    P_256,
    P_384,
    P_521,
    ECCurve,
    EcdhEs,
    EcdhEs_A128KW,
    EcdhEs_A192KW,
    EcdhEs_A256KW,
    secp256k1,
)

from .base import Jwk, JwkParameter


class UnsupportedEllipticCurve(KeyError):
    pass


class ECJwk(Jwk):
    """
    Represent an Elliptic Curve Jwk, with `kty=EC`.
    """

    kty = "EC"

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

    CURVES: Mapping[str, ECCurve] = {
        curve.name: curve for curve in [P_256, P_384, P_521, secp256k1]
    }

    SIGNATURE_ALGORITHMS = {
        sigalg.name: sigalg for sigalg in [ES256, ES384, ES512, ES256K]
    }
    KEY_MANAGEMENT_ALGORITHMS = {
        keyalg.name: keyalg
        for keyalg in [EcdhEs, EcdhEs_A128KW, EcdhEs_A192KW, EcdhEs_A256KW]
    }

    @classmethod
    def get_curve(cls, crv: str) -> ECCurve:
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise UnsupportedEllipticCurve(crv)
        return curve

    @classmethod
    def public(cls, crv: str, x: int, y: int, **params: str) -> "ECJwk":
        """
        Initialize a public ECJwk from its public parameters.
        :param crv: the curve to use
        :param x: the x coordinate
        :param y: the y coordinate
        :param params: additional parameters for the returned ECJwk
        :return: an ECJwk initialized with the supplied parameters
        """
        coord_size = cls.CURVES[crv].coordinate_size
        return cls(
            dict(
                key="EC",
                crv=crv,
                x=BinaPy.from_int(x, coord_size).encode_to("b64u"),
                y=BinaPy.from_int(y, coord_size).encode_to("b64u"),
                **params,
            )
        )

    @classmethod
    def private(cls, crv: str, x: int, y: int, d: int, **params: Any) -> "ECJwk":
        """
        Initialize a private ECJwk from its private parameters.
        :param crv: the curve to use
        :param x: the x coordinate
        :param y: the y coordinate
        :param d: the elliptic curve private key
        :param params: additional parameters for the returned ECJwk
        :return: an ECJWk initialized with the supplied parameters
        """
        coord_size = cls.CURVES[crv].coordinate_size
        return cls(
            dict(
                kty="EC",
                crv=crv,
                x=BinaPy.from_int(x, coord_size).encode_to("b64u").decode(),
                y=BinaPy.from_int(y, coord_size).encode_to("b64u").decode(),
                d=BinaPy.from_int(d, coord_size).encode_to("b64u").decode(),
                **params,
            )
        )

    @property
    def coordinate_size(self) -> int:
        """
        Return the coordinate size, in bytes, fitting for this key curve.
        :return: 32, 48, or 66
        """
        return self.curve.coordinate_size

    @classmethod
    def from_cryptography_key(cls, key: Any) -> ECJwk:
        if isinstance(key, asymmetric.ec.EllipticCurvePrivateKey):
            priv = key.private_numbers()  # type: ignore[attr-defined]
            pub = key.public_key().public_numbers()
            try:
                curve = next(
                    c
                    for c in cls.CURVES.values()
                    if c.cryptography_curve.name == pub.curve.name
                )
            except StopIteration:
                raise ValueError("Unsupported curve", pub.curve.name)
            return cls.private(
                crv=curve.name,
                x=pub.x,
                y=pub.y,
                d=priv.private_value,
            )
        elif isinstance(key, asymmetric.ec.EllipticCurvePublicKey):
            pub = key.public_numbers()
            try:
                curve = next(
                    c
                    for c in cls.CURVES.values()
                    if c.cryptography_curve.name == pub.curve.name
                )
            except StopIteration:
                raise ValueError("Unsupported curve", pub.curve.name)
            return cls.public(
                crv=curve.name,
                x=pub.x,
                y=pub.y,
            )
        else:
            raise TypeError(
                "A EllipticCurvePrivateKey or a EllipticCurvePublicKey is required."
            )

    def to_cryptography_key(
        self,
    ) -> Union[
        asymmetric.ec.EllipticCurvePrivateKey,
        asymmetric.ec.EllipticCurvePublicKey,
    ]:
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
    def generate(cls, crv: str = "P-256", **params: str) -> "ECJwk":
        """
        Generates a random ECJwk.
        :param crv: the curve to use
        :param params: additional parameters for the returned ECJwk
        :return: a generated ECJwk
        """
        curve = cls.get_curve(crv)
        if curve is None:
            raise ValueError("Unsupported curve", crv)
        key = asymmetric.ec.generate_private_key(curve.cryptography_curve)
        pn = key.private_numbers()  # type: ignore
        return cls.private(
            crv=crv,
            x=pn.public_numbers.x,
            y=pn.public_numbers.y,
            d=pn.private_value,
            **params,
        )

    @property
    def curve(self) -> ECCurve:
        if not isinstance(self.crv, str) or self.crv not in self.CURVES:
            raise AttributeError("unsupported crv", self.crv)
        return self.CURVES[self.crv]

    @property
    def x_coordinate(self) -> int:
        """
        Returns the x coordinate from this ECJwk
        :return: the x coordinate (from parameter `x`)
        """
        return BinaPy(self.x).decode_from("b64u").to_int()

    @property
    def y_coordinate(self) -> int:
        """
        Returns the y coordinate from this ECJwk
        :return: the y coordinate (from parameter `y`)
        """
        return BinaPy(self.y).decode_from("b64u").to_int()

    @property
    def ecc_private_key(self) -> int:
        """
        Returns the ECC private key from this ECJwk
        :return: the ECC private key (from parameter `d`)
        """
        return BinaPy(self.d).decode_from("b64u").to_int()

    def supported_signing_algorithms(self) -> List[str]:
        return [
            name
            for name, alg in self.SIGNATURE_ALGORITHMS.items()
            if alg.curve == self.curve
        ]

    def supported_key_management_algorithms(self) -> List[str]:
        return list(self.KEY_MANAGEMENT_ALGORITHMS)

    def supported_encryption_algorithms(self) -> List[str]:
        return list(self.ENCRYPTION_ALGORITHMS)
