"""
This module contains classes that describe Elliptic Curves as described in RFC7518.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec


@dataclass
class EllipticCurve:
    """
    A descriptive class for Elliptic Curves.

    Elliptic Curves have a name, a `cryptography` ec.EllipticCurve, and a coordinate size.
    """

    name: str
    cryptography_curve: ec.EllipticCurve
    coordinate_size: int


P_256 = EllipticCurve(
    name="P-256",
    cryptography_curve=ec.SECP256R1(),
    coordinate_size=32,
)

P_384 = EllipticCurve(
    name="P-384",
    cryptography_curve=ec.SECP384R1(),
    coordinate_size=48,
)

P_521 = EllipticCurve(
    name="P-521",
    cryptography_curve=ec.SECP521R1(),
    coordinate_size=66,
)

secp256k1 = EllipticCurve(
    name="secp256k1",
    cryptography_curve=ec.SECP256K1(),
    coordinate_size=32,
)
