from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import asymmetric, hashes

from ..base import AsymmetricAlg, SignatureAlg
from ..ec import P_256, P_384, P_521, ECCurve, secp256k1


class ECSignatureAlg(
    AsymmetricAlg[
        asymmetric.ec.EllipticCurvePrivateKey, asymmetric.ec.EllipticCurvePublicKey
    ],
    SignatureAlg,
):
    curve: ECCurve
    hashing_alg: hashes.HashAlgorithm
    public_key_class = asymmetric.ec.EllipticCurvePublicKey
    private_key_class = asymmetric.ec.EllipticCurvePrivateKey

    def sign(self, data: bytes) -> BinaPy:
        with self.private_key_required() as key:
            dss_sig = key.sign(data, asymmetric.ec.ECDSA(self.hashing_alg))
            r, s = asymmetric.utils.decode_dss_signature(dss_sig)
            return BinaPy.from_int(r, self.curve.coordinate_size) + BinaPy.from_int(
                s, self.curve.coordinate_size
            )

    def verify(self, data: bytes, signature: bytes) -> bool:
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
                    asymmetric.ec.ECDSA(self.hashing_alg),
                )
                return True
            except exceptions.InvalidSignature:
                return False


class ES256(ECSignatureAlg):
    name = "ES256"
    description = "ECDSA using P-256 and SHA-256"
    curve = P_256
    hashing_alg = hashes.SHA256()


class ES384(ECSignatureAlg):
    name = "ES384"
    description = "ECDSA using P-384 and SHA-384"
    curve = P_384
    hashing_alg = hashes.SHA384()


class ES512(ECSignatureAlg):
    name = "ES512"
    description = "ECDSA using P-521 and SHA-512"
    curve = P_521
    hashing_alg = hashes.SHA512()


class ES256K(ECSignatureAlg):
    name = "ES256k"
    description = "ECDSA using secp256k1 and SHA-256"
    curve = secp256k1
    hashing_alg = hashes.SHA256()
