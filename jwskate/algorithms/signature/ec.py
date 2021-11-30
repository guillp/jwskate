from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric, hashes

from jwskate.algorithms.base import SignatureAlg
from jwskate.algorithms.ec import P_256, P_384, P_521, ECCurve, secp256k1


class ECSignatureAlg(SignatureAlg):
    curve: ECCurve
    hashing_alg: hashes.HashAlgorithm

    def sign(self, data: bytes) -> BinaPy:
        dss_sig = self.key.sign(data, asymmetric.ec.ECDSA(self.hashing_alg))
        r, s = asymmetric.utils.decode_dss_signature(dss_sig)
        return BinaPy.from_int(r, self.curve.coordinate_size) + BinaPy.from_int(
            s, self.curve.coordinate_size
        )


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
