from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec


@dataclass
class ECCurve:
    name: str
    cryptography_curve: ec.EllipticCurve
    coordinate_size: int


P_256 = ECCurve(
    cryptography_curve=ec.SECP256R1(),
    name="P-256",
    coordinate_size=32,
)
P_384 = ECCurve(
    cryptography_curve=ec.SECP384R1(),
    name="P-384",
    coordinate_size=48,
)

P_521 = ECCurve(
    cryptography_curve=ec.SECP521R1(),
    name="P-521",
    coordinate_size=66,
)
secp256k1 = ECCurve(
    cryptography_curve=ec.SECP256K1(),
    name="secp256k1",
    coordinate_size=32,
)
