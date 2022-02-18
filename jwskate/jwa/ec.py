"""
This module contains classes that describe Elliptic Curves as described in RFC7518.
"""

from dataclasses import dataclass
from typing import Any, ClassVar, Dict, Tuple, Union

from binapy import BinaPy
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass
class EllipticCurve:
    """
    A descriptive class for Elliptic Curves.

    Elliptic Curves have a name, a `cryptography.ec.EllipticCurve`, and a coordinate size.
    """

    name: str
    """
    Curve name as defined in [IANA JOSE](https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve).
    This name will appear in `alg` or `enc` fields in JOSE headers."""

    cryptography_curve: ec.EllipticCurve
    """`cryptography` curve instance."""

    coordinate_size: int
    """Coordinate size, in bytes."""

    instances: "ClassVar[Dict[str, EllipticCurve]]" = {}

    def __post_init__(self) -> None:
        self.instances[self.name] = self

    def generate(self) -> Tuple[int, int, int]:
        """
        Generate a new EC key on this curve.
        :return: A tuple of 4 `int`s: x and y coordinates (public) and d private key.
        """
        key = ec.generate_private_key(self.cryptography_curve)
        pn = key.private_numbers()  # type: ignore
        x = pn.public_numbers.x
        y = pn.public_numbers.y
        d = pn.private_value
        return x, y, d

    @classmethod
    def get_curve(
        cls, key: Union[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]
    ) -> "EllipticCurve":
        """
        Get the appropriate `EllipticCurve` instance for a given `cryptography` `EllipticCurvePublicKey`.
        :param key: an Elliptic Curve private or public key from `cryptography`.
        :return: the appropriate instance of EllipticCurve for the given key.
        """
        for c in cls.instances.values():
            if c.cryptography_curve.name == key.curve.name:
                return c
        raise NotImplementedError(f"Unsupported Curve {key.curve.name}")

    @classmethod
    def get_parameters(
        cls, key: Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]
    ) -> Dict[str, Any]:
        """
        Extract all private and public parameters from a given `cryptography` `EllipticCurvePrivateKey`.
        :param key: an Elliptic Curve public or private key from `cryptography`.
        :return: a tuple of `x`, `y` coordinates and `d` private key, as int
        """
        if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            raise TypeError(
                "A EllipticCurvePrivateKey or a EllipticCurvePublicKey is required."
            )
        crv = cls.get_curve(key)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            public_numbers = key.public_key().public_numbers()
        elif isinstance(key, ec.EllipticCurvePublicKey):
            public_numbers = key.public_numbers()
        x = (
            BinaPy.from_int(public_numbers.x, crv.coordinate_size)
            .encode_to("b64u")
            .ascii()
        )
        y = (
            BinaPy.from_int(public_numbers.y, crv.coordinate_size)
            .encode_to("b64u")
            .ascii()
        )
        parameters = {"kty": "EC", "crv": crv.name, "x": x, "y": y}
        if isinstance(key, ec.EllipticCurvePrivateKey):
            pn = key.private_numbers()  # type: ignore
            d = (
                BinaPy.from_int(pn.private_value, crv.coordinate_size)
                .encode_to("b64u")
                .ascii()
            )
            parameters["d"] = d
        return parameters


P_256 = EllipticCurve(
    name="P-256",
    cryptography_curve=ec.SECP256R1(),
    coordinate_size=32,
)
"""P-256 curve"""

P_384 = EllipticCurve(
    name="P-384",
    cryptography_curve=ec.SECP384R1(),
    coordinate_size=48,
)
"""P-384 curve"""

P_521 = EllipticCurve(
    name="P-521",
    cryptography_curve=ec.SECP521R1(),
    coordinate_size=66,
)
"""P-521 curve"""

secp256k1 = EllipticCurve(
    name="secp256k1",
    cryptography_curve=ec.SECP256K1(),
    coordinate_size=32,
)
"""[secp256k1 curve](https://www.rfc-editor.org/rfc/rfc8812.html)"""
