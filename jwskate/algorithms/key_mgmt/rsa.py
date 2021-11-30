from typing import Any, Union

from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from jwskate.algorithms.base import KeyWrappingAlg


class RsaKeyWrap(KeyWrappingAlg):
    padding: Any

    name = "RSA1_5"
    description = "RSAES-PKCS1-v1_5"

    def __init__(
        self, key: Union[asymmetric.rsa.RSAPublicKey, asymmetric.rsa.RSAPrivateKey]
    ):
        self.key = key

    def wrap_key(self, plainkey: bytes) -> BinaPy:
        if not isinstance(self.key, asymmetric.rsa.RSAPublicKey):
            raise RuntimeError("A public key is required for key wrapping")
        return BinaPy(self.key.encrypt(plainkey, self.padding))

    def unwrap_key(self, cipherkey: bytes) -> BinaPy:
        if not isinstance(self.key, asymmetric.rsa.RSAPrivateKey):
            raise RuntimeError("A private key is required for key unwrapping")
        return BinaPy(self.key.decrypt(cipherkey, self.padding))


class RsaEsPcks1v1_5(RsaKeyWrap):
    name = "RSA1_5"
    description = "RSAES-PKCS1-v1_5"

    padding = padding.PKCS1v15()


class RsaEsOaep(RsaKeyWrap):
    name = "RSA-OAEP"
    description = "RSAES OAEP using default parameters"

    padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None,
    )


class RsaEsOaepSha256(RsaKeyWrap):
    name = "RSA-OAEP-256"
    description = "RSAES OAEP using SHA-256 and MGF1 with with SHA-256"

    padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
