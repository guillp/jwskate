from typing import Iterable, List, Optional, Union, cast

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..utils import b64u_to_int, int_to_b64u
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

    CURVES = {
        # name: curve
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
        "secp256k1": ec.SECP256K1(),
    }

    SIGNATURE_ALGORITHMS = {
        # name : (description, hash_alg)
        "ES256": ("ECDSA using P-256 and SHA-256", hashes.SHA256()),
        "ES384": ("ECDSA using P-384 and SHA-384", hashes.SHA384()),
        "ES512": ("ECDSA using P-521 and SHA-512", hashes.SHA512()),
    }

    @classmethod
    def public(cls, crv: str, x: str, y: str, **params: str) -> "ECJwk":
        """
        Initializes a public ECJwk from its public paramters.
        :param crv: the curve to use
        :param x: the x coordinate
        :param y: the y coordinate
        :param params: additional parameters for the returned ECJwk
        :return: an ECJwk initialized with the supplied parameters
        """
        return cls(dict(key="EC", crv=crv, x=x, y=y, **params))

    @classmethod
    def private(cls, crv: str, x: str, y: str, d: str, **params: str) -> "ECJwk":
        """
        Initializes a private ECJwk from its private parameters.
        :param crv: the curve to use
        :param x: the x coordinate
        :param y: the y coordinate
        :param d: the elliptic curve private key
        :param params: additional parameters for the returned ECJwk
        :return: an ECJWk initialized with the supplied parameters
        """
        return cls(dict(key="EC", crv=crv, x=x, y=y, d=d, **params))

    @classmethod
    def generate(cls, crv: str = "P-256", **params: str) -> "ECJwk":
        """
        Generates a random ECJwk.
        :param crv: the curve to use
        :param params: additional parameters for the returned ECJwk
        :return: a generated ECJwk
        """
        curve = cls.CURVES.get(crv)
        if curve is None:
            raise ValueError("Unsupported curve", crv)
        key = ec.generate_private_key(curve)
        pn = key.private_numbers()  # type: ignore
        # TODO: check why mypy complains that "EllipticCurvePrivateKey" has no attribute "private_numbers" while it does
        key_size = pn.public_numbers.curve.key_size
        x = int_to_b64u(pn.public_numbers.x, key_size)
        y = int_to_b64u(pn.public_numbers.y, key_size)
        d = int_to_b64u(pn.private_value, key_size)
        return cls.private(crv=crv, x=x, y=y, d=d, **params)

    def sign(self, data: bytes, alg: Optional[str] = "ES256") -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("a signing alg is required")

        if not self.is_private:
            raise PrivateKeyRequired("A private key is required for signing")

        key = ec.EllipticCurvePrivateNumbers(
            self.ecc_private_key,
            ec.EllipticCurvePublicNumbers(
                self.x_coordinate, self.y_coordinate, self.CURVES[self.curve]
            ),
        ).private_key()
        try:
            description, hashing = self.SIGNATURE_ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        return key.sign(data, ec.ECDSA(hashing))

    def verify(
        self, data: bytes, signature: bytes, alg: Union[str, Iterable[str], None]
    ) -> bool:
        if isinstance(alg, str):
            algs = [alg]
        elif alg is None:
            algs = [self.alg]
        else:
            algs = list(alg)

        public_key = ec.EllipticCurvePublicNumbers(
            self.x_coordinate, self.y_coordinate, self.CURVES[self.curve]
        ).public_key()

        for alg in algs:
            try:
                description, hashing = self.SIGNATURE_ALGORITHMS[alg]
            except KeyError:
                raise ValueError("Unsupported signing alg", alg)

            try:
                public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashing),
                )
                return True
            except cryptography.exceptions.InvalidSignature:
                continue

        return False

    @property
    def curve(self) -> str:
        if self.crv not in self.CURVES:
            raise AttributeError("unsupported crv", self.crv)
        return cast(str, self.crv)

    @property
    def x_coordinate(self) -> int:
        """
        Returns the x coordinate from this ECJwk
        :return: the x coordinate (from parameter `x`)
        """
        return b64u_to_int(self.x)

    @property
    def y_coordinate(self) -> int:
        """
        Returns the y coordinate from this ECJwk
        :return: the y coordinate (from parameter `y`)
        """
        return b64u_to_int(self.y)

    @property
    def ecc_private_key(self) -> int:
        """
        Returns the ECC private key from this ECJwk
        :return: the ECC private key (from parameter `d`)
        """
        return b64u_to_int(self.d)

    @property
    def supported_signing_algorithms(self) -> List[str]:
        return list(self.SIGNATURE_ALGORITHMS.keys())
