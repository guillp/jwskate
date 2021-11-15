from __future__ import annotations

from typing import Any, Iterable, List, Optional, Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import asymmetric, hashes

from .alg import get_alg, get_algs
from .base import Jwk
from .exceptions import PrivateKeyRequired


class ECJwk(Jwk):
    """
    Represents an Elliptic Curve Jwk, with `"kty": "EC"`.
    """

    kty = "EC"

    PARAMS = {
        # name : ("description", is_private, is_required, "kind"),
        "crv": ("Curve", False, True, "name"),
        "x": ("X Coordinate", False, True, "b64u"),
        "y": ("Y Coordinate", False, True, "b64u"),
        "d": ("ECC Private Key", True, True, "b64u"),
    }

    CRYPTOGRAPHY_CURVES = {
        # name: curve
        "P-256": asymmetric.ec.SECP256R1(),
        "P-384": asymmetric.ec.SECP384R1(),
        "P-521": asymmetric.ec.SECP521R1(),
        "secp256k1": asymmetric.ec.SECP256K1(),
    }

    JWA_CURVE_NAMES = {
        curve.name: jwa_name for jwa_name, curve in CRYPTOGRAPHY_CURVES.items()
    }

    SIGNATURE_ALGORITHMS = {
        # name : (description, hash_alg)
        "ES256": ("ECDSA using P-256 and SHA-256", hashes.SHA256()),
        "ES384": ("ECDSA using P-384 and SHA-384", hashes.SHA384()),
        "ES512": ("ECDSA using P-521 and SHA-512", hashes.SHA512()),
    }

    KEY_MANAGEMENT_ALGORITHMS = {
        # name: ("description", alg)
        "ECDH-ES": (
            "Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF",
        ),
        "ECDH-ES+A128KW": ('ECDH-ES using Concat KDF and CEK wrapped with "A128KW"',),
    }

    COORDINATE_SIZES = {
        "P-256": 32,
        "P-384": 48,
        "P-521": 66,
    }

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
        coord_size = cls.COORDINATE_SIZES[crv]
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
        coord_size = cls.COORDINATE_SIZES[crv]
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
        return self.CRYPTOGRAPHY_CURVES[self.curve]

    @property
    def coordinate_size(self) -> int:
        """
        Return the coordinate size, in bytes, fitting for this key curve.
        :return: 32, 48, or 66
        """
        return self.COORDINATE_SIZES[self.curve]

    @classmethod
    def from_cryptography_key(cls, key: Any) -> ECJwk:
        if isinstance(key, asymmetric.ec.EllipticCurvePrivateKey):
            priv = key.private_numbers()  # type: ignore[attr-defined]
            pub = key.public_key().public_numbers()
            curve_name = cls.JWA_CURVE_NAMES[pub.curve.name]
            return cls.private(
                crv=curve_name,
                x=pub.x,
                y=pub.y,
                d=priv.private_value,
            )
        elif isinstance(key, asymmetric.ec.EllipticCurvePublicKey):
            pub = key.public_numbers()
            curve_name = cls.JWA_CURVE_NAMES[pub.curve.name]
            return cls.public(
                crv=curve_name,
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
        curve = cls.CRYPTOGRAPHY_CURVES.get(crv)
        if curve is None:
            raise ValueError("Unsupported curve", crv)
        key = asymmetric.ec.generate_private_key(curve)
        pn = key.private_numbers()  # type: ignore
        return cls.private(
            crv=crv,
            x=pn.public_numbers.x,
            y=pn.public_numbers.y,
            d=pn.private_value,
            **params,
        )

    def sign(self, data: bytes, alg: Optional[str] = None) -> BinaPy:
        alg = get_alg(self.alg, alg, self.supported_signing_algorithms)

        if not self.is_private:
            raise PrivateKeyRequired("A private key is required for signing")

        key = asymmetric.ec.EllipticCurvePrivateNumbers(
            self.ecc_private_key,
            asymmetric.ec.EllipticCurvePublicNumbers(
                self.x_coordinate, self.y_coordinate, self.cryptography_curve
            ),
        ).private_key()
        try:
            description, hashing = self.SIGNATURE_ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        dss_sig = key.sign(data, asymmetric.ec.ECDSA(hashing))
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

        for alg in get_algs(self.alg, alg, algs, self.supported_signing_algorithms):
            try:
                description, hashing = self.SIGNATURE_ALGORITHMS[alg]
            except KeyError:
                raise ValueError("Unsupported signing alg", alg)

            try:
                public_key.verify(
                    dss_signature,
                    data,
                    asymmetric.ec.ECDSA(hashing),
                )
                return True
            except exceptions.InvalidSignature:
                continue

        return False

    @property
    def curve(self) -> str:
        if not isinstance(self.crv, str) or self.crv not in self.CRYPTOGRAPHY_CURVES:
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

    @property
    def supported_signing_algorithms(self) -> List[str]:
        """
        Returns a list of signing algs that are compatible for use with this Jwk.
        :return: a list of signing algs
        """
        return {"P-256": ["ES256"], "P-384": ["ES384"], "P-521": ["ES512"]}[self.curve]
