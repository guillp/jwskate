from __future__ import annotations

from typing import Any, Iterable, List, Mapping, Optional, Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import asymmetric, hashes, kdf

from ..algorithms import (
    ECDH_ES,
    ES256,
    ES256K,
    ES384,
    ES512,
    P256,
    P384,
    P521,
    ECCurve,
    EncryptionAlg,
    KeyAgreementAlg,
    KeyManagementAlg,
    SignatureAlg,
    secp256k1,
)
from .alg import select_alg, select_algs
from .base import Jwk, JwkParameter


class UnsupportedCurve(KeyError):
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
        curve.name: curve for curve in [P256, P384, P521, secp256k1]
    }

    SIGNATURE_ALGORITHMS = {
        sigalg.name: sigalg for sigalg in [ES256, ES384, ES512, ES256K]
    }
    KEY_MANAGEMENT_ALGORITHMS = {keyalg.name: keyalg for keyalg in [ECDH_ES]}

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
                kty="EC",
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
        return self.curve.cryptography_curve

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
                    curve=self.cryptography_curve,
                ),
            ).private_key()
        else:
            return asymmetric.ec.EllipticCurvePublicNumbers(
                x=self.x_coordinate,
                y=self.y_coordinate,
                curve=self.cryptography_curve,
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

    def sign(self, data: bytes, alg: Optional[str] = None) -> BinaPy:
        sigalg = select_alg(self.alg, alg, self.SIGNATURE_ALGORITHMS)
        wrapper = sigalg(self.to_cryptography_key())
        return BinaPy(wrapper.sign(data))

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

        for sigalg in select_algs(self.alg, alg, algs, self.SIGNATURE_ALGORITHMS):
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
