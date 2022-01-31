from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ..base import BaseAsymmetricAlg, BaseSignatureAlg


class RSASigAlg(
    BaseAsymmetricAlg[asymmetric.rsa.RSAPrivateKey, asymmetric.rsa.RSAPublicKey],
    BaseSignatureAlg,
):
    hashing_alg: hashes.HashAlgorithm
    padding_alg: padding.AsymmetricPadding = padding.PKCS1v15()
    min_key_size: int = 2048

    private_key_class = asymmetric.rsa.RSAPrivateKey
    public_key_class = asymmetric.rsa.RSAPublicKey

    def sign(self, data: bytes) -> BinaPy:
        if self.read_only:
            raise NotImplementedError
        with self.private_key_required() as key:
            return BinaPy(key.sign(data, self.padding_alg, self.hashing_alg))

    def verify(self, data: bytes, signature: bytes) -> bool:
        with self.public_key_required() as key:
            try:
                key.verify(
                    signature,
                    data,
                    self.padding_alg,
                    self.hashing_alg,
                )
                return True
            except exceptions.InvalidSignature:
                return False


class RS256(RSASigAlg):
    name = "RS256"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"
    hashing_alg = hashes.SHA256()


class RS384(RSASigAlg):
    name = "RS384"
    description = "RSASSA-PKCS1-v1_5 using SHA-384"
    hashing_alg = hashes.SHA384()


class RS512(RSASigAlg):
    name = "RS512"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"
    hashing_alg = hashes.SHA512()


class PS256(RSASigAlg):
    name = "PS256"
    description = "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"
    hashing_alg = hashes.SHA256()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=256 // 8)


class PS384(RSASigAlg):
    name = "PS384"
    description = "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"
    hashing_alg = hashes.SHA384()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=384 // 8)


class PS512(RSASigAlg):
    name = "PS512"
    description = "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"
    hashing_alg = hashes.SHA512()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=512 // 8)


class RS1(RSASigAlg):
    name = "RS1"
    description = "RSASSA-PKCS1-v1_5 with SHA-1"
    hashing_alg = hashes.SHA1()
    read_only = True
