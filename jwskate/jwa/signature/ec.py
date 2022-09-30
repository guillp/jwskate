"""This module implement Elliptic Curve signature algorithms."""
from typing import SupportsBytes, Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..base import BaseAsymmetricAlg, BaseSignatureAlg
from ..ec import P_256, P_384, P_521, EllipticCurve, secp256k1


class BaseECSignatureAlg(
    BaseAsymmetricAlg[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey],
    BaseSignatureAlg,
):
    """Base class for Elliptic Curve signature algorithms."""

    curve: EllipticCurve
    hashing_alg: hashes.HashAlgorithm
    public_key_class = ec.EllipticCurvePublicKey
    private_key_class = ec.EllipticCurvePrivateKey

    @classmethod
    def check_key(
        cls, key: Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]
    ) -> None:  # noqa: D102
        if key.curve.name != cls.curve.cryptography_curve.name:
            raise ValueError(
                f"This key is on curve {key.curve.name}. An EC key on curve {cls.curve.name} is expected."
            )

    def sign(self, data: Union[bytes, SupportsBytes]) -> BinaPy:  # noqa: D102
        if not isinstance(data, bytes):
            data = bytes(data)

        with self.private_key_required() as key:
            dss_sig = key.sign(data, ec.ECDSA(self.hashing_alg))
            r, s = asymmetric.utils.decode_dss_signature(dss_sig)
            return BinaPy.from_int(r, self.curve.coordinate_size) + BinaPy.from_int(
                s, self.curve.coordinate_size
            )

    def verify(
        self, data: Union[bytes, SupportsBytes], signature: Union[bytes, SupportsBytes]
    ) -> bool:  # noqa: D102
        if not isinstance(data, bytes):
            data = bytes(data)

        if not isinstance(signature, bytes):
            signature = bytes(signature)

        with self.public_key_required() as key:
            if len(signature) != self.curve.coordinate_size * 2:
                raise ValueError(
                    f"Invalid signature length {len(signature)} bytes, expected {self.curve.coordinate_size * 2} bytes"
                )

            r_bytes, s_bytes = (
                signature[: self.curve.coordinate_size],
                signature[self.curve.coordinate_size :],
            )
            r = int.from_bytes(r_bytes, "big", signed=False)
            s = int.from_bytes(s_bytes, "big", signed=False)
            dss_signature = asymmetric.utils.encode_dss_signature(r, s)

            try:
                key.verify(
                    dss_signature,
                    data,
                    ec.ECDSA(self.hashing_alg),
                )
                return True
            except exceptions.InvalidSignature:
                return False


class ES256(BaseECSignatureAlg):  # noqa: D415
    """ECDSA using P-256 and SHA-256."""

    name = "ES256"
    description = __doc__
    curve = P_256
    hashing_alg = hashes.SHA256()


class ES384(BaseECSignatureAlg):  # noqa: D415
    """ECDSA using P-384 and SHA-384."""

    name = "ES384"
    description = __doc__
    curve = P_384
    hashing_alg = hashes.SHA384()


class ES512(BaseECSignatureAlg):  # noqa: D415
    """ECDSA using P-521 and SHA-512."""

    name = "ES512"
    description = __doc__
    curve = P_521
    hashing_alg = hashes.SHA512()


class ES256K(BaseECSignatureAlg):  # noqa: D415
    """ECDSA using secp256k1 and SHA-256."""

    name = "ES256k"
    description = __doc__
    curve = secp256k1
    hashing_alg = hashes.SHA256()
