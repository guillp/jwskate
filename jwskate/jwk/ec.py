from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import asymmetric, hashes

from .alg import EncryptionAlg, KeyManagementAlg, SignatureAlg, get_alg, get_algs
from .base import Jwk, JwkParameter
from .exceptions import PrivateKeyRequired


@dataclass
class ECSignatureAlg(SignatureAlg):
    curve: str
    hashing_alg: hashes.HashAlgorithm


@dataclass
class ECKeyManagementAlg(KeyManagementAlg):
    pass


@dataclass
class ECEncryptionAlg(EncryptionAlg):
    pass


@dataclass
class ECCurve:
    cryptography_curve: asymmetric.ec.EllipticCurve
    name: str
    coordinate_size: int
    signature_algs: List[str]
    key_management_algs: List[str]
    encryption_algs: List[str]


class UnsupportedCurve(KeyError):
    pass


class ECJwk(Jwk):
    """
    Represents an Elliptic Curve Jwk, with `"kty": "EC"`.
    """

    kty = "EC"

    PARAMS: Mapping[str, JwkParameter] = {
        # name : ("description", is_private, is_required, "kind"),
        "crv": JwkParameter("Curve", False, True, "name"),
        "x": JwkParameter("X Coordinate", False, True, "b64u"),
        "y": JwkParameter("Y Coordinate", False, True, "b64u"),
        "d": JwkParameter("ECC Private Key", True, True, "b64u"),
    }

    CURVES: Mapping[str, ECCurve] = {
        "P-256": ECCurve(
            cryptography_curve=asymmetric.ec.SECP256R1(),
            name="P-256",
            coordinate_size=32,
            signature_algs=["ES256"],
            key_management_algs=[],
            encryption_algs=[],
        ),
        "P-384": ECCurve(
            cryptography_curve=asymmetric.ec.SECP384R1(),
            name="P-384",
            coordinate_size=48,
            signature_algs=["ES384"],
            key_management_algs=[],
            encryption_algs=[],
        ),
        "P-521": ECCurve(
            cryptography_curve=asymmetric.ec.SECP521R1(),
            name="P-521",
            coordinate_size=66,
            signature_algs=["ES512"],
            key_management_algs=[],
            encryption_algs=[],
        ),
        "secp256k1": ECCurve(
            cryptography_curve=asymmetric.ec.SECP256K1(),
            name="secp256k1",
            coordinate_size=32,
            signature_algs=["ES256K"],
            key_management_algs=[],
            encryption_algs=[],
        ),
    }

    SIGNATURE_ALGORITHMS: Mapping[str, ECSignatureAlg] = {
        "ES256": ECSignatureAlg(
            name="ES256",
            description="ECDSA using P-256 and SHA-256",
            curve="P-256",
            hashing_alg=hashes.SHA256(),
        ),
        "ES384": ECSignatureAlg(
            name="ES384",
            description="ECDSA using P-384 and SHA-384",
            curve="P-384",
            hashing_alg=hashes.SHA384(),
        ),
        "ES512": ECSignatureAlg(
            name="ES512",
            description="ECDSA using P-521 and SHA-512",
            curve="P-521",
            hashing_alg=hashes.SHA512(),
        ),
        "ES256K": ECSignatureAlg(
            name="ES256k",
            description="ECDSA using secp256k1 and SHA-256",
            curve="secp256k1",
            hashing_alg=hashes.SHA256(),
        ),
    }

    KEY_MANAGEMENT_ALGORITHMS: Mapping[str, ECKeyManagementAlg] = {
        "ECDH-ES": ECKeyManagementAlg(
            name="ECDH-ES",
            description="Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF",
        ),
        "ECDH-ES+A128KW": ECKeyManagementAlg(
            name="ECDH-ES+A128KW",
            description='ECDH-ES using Concat KDF and CEK wrapped with "A128KW"',
        ),
    }

    ENCRYPTION_ALGORITHMS: Mapping[str, ECEncryptionAlg] = {}

    @classmethod
    def get_curve(cls, crv: str) -> ECCurve:
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise UnsupportedCurve(crv)
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
    def private(cls, crv: str, x: int, y: int, d: int, **params: str) -> "ECJwk":
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
                key="EC",
                crv=crv,
                x=BinaPy.from_int(x, coord_size).encode_to("b64u").decode(),
                y=BinaPy.from_int(y, coord_size).encode_to("b64u").decode(),
                d=BinaPy.from_int(d, coord_size).encode_to("b64u").decode(),
                **params,
            )
        )

    @property
    def cryptography_curve(self) -> asymmetric.ec.EllipticCurve:
        """
        Return the `cryptography` curve for this key.
        :return: a subclass of EllipticCurve
        """
        return self.CURVES[self.curve].cryptography_curve

    @property
    def coordinate_size(self) -> int:
        """
        Return the coordinate size, in bytes, fitting for this key curve.
        :return: 32, 48, or 66
        """
        return self.CURVES[self.curve].coordinate_size

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
        asymmetric.ec.EllipticCurvePrivateKey, asymmetric.ec.EllipticCurvePublicKey
    ]:
        if self.is_private:
            return asymmetric.ec.EllipticCurvePrivateNumbers(
                private_value=self.ecc_private_key,
                public_numbers=asymmetric.ec.EllipticCurvePublicNumbers(
                    x=self.x_coordinate,
                    y=self.y_coordinate,
                    curve=self.cryptography_curve,
                ),
            ).private_key()
        else:
            return asymmetric.ec.EllipticCurvePublicNumbers(
                x=self.x_coordinate, y=self.y_coordinate, curve=self.cryptography_curve
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

    def sign(self, data: bytes, alg: Optional[str] = None) -> BinaPy:
        sigalg = get_alg(self.alg, alg, self.SIGNATURE_ALGORITHMS)

        if not self.is_private:
            raise PrivateKeyRequired("A private key is required for signing")

        if self.curve != sigalg.curve:
            raise UnsupportedCurve(
                f"Signing alg {sigalg.name} requires a curve {sigalg.curve}, which mismatch this Jwk curve {self.curve}"
            )

        key = asymmetric.ec.EllipticCurvePrivateNumbers(
            self.ecc_private_key,
            asymmetric.ec.EllipticCurvePublicNumbers(
                self.x_coordinate, self.y_coordinate, self.cryptography_curve
            ),
        ).private_key()

        dss_sig = key.sign(data, asymmetric.ec.ECDSA(sigalg.hashing_alg))
        r, s = asymmetric.utils.decode_dss_signature(dss_sig)
        return BinaPy.from_int(r, self.coordinate_size) + BinaPy.from_int(
            s, self.coordinate_size
        )

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        public_key = self.public_jwk().to_cryptography_key()

        if len(signature) != self.coordinate_size * 2:
            raise ValueError(
                f"Invalid signature length {len(signature)} bytes, expected {self.coordinate_size * 2} bytes"
            )

        r_bytes, s_bytes = (
            signature[: self.coordinate_size],
            signature[self.coordinate_size :],
        )
        r = int.from_bytes(r_bytes, "big", signed=False)
        s = int.from_bytes(s_bytes, "big", signed=False)
        dss_signature = asymmetric.utils.encode_dss_signature(r, s)

        for sigalg in get_algs(self.alg, alg, algs, self.SIGNATURE_ALGORITHMS):
            try:
                public_key.verify(
                    dss_signature,
                    data,
                    asymmetric.ec.ECDSA(sigalg.hashing_alg),
                )
                return True
            except exceptions.InvalidSignature:
                continue

        return False

    @property
    def curve(self) -> str:
        if not isinstance(self.crv, str) or self.crv not in self.CURVES:
            raise AttributeError("unsupported crv", self.crv)
        return self.crv

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
        return self.CURVES[self.curve].signature_algs

    def supported_key_management_algorithms(self) -> List[str]:
        return self.CURVES[self.curve].key_management_algs

    def supported_encryption_algorithms(self) -> List[str]:
        return self.CURVES[self.curve].encryption_algs
