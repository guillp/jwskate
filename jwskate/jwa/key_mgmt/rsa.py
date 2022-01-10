from typing import Any, Union

from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ..base import AsymmetricKeyWrappingAlg


class RsaKeyWrap(
    AsymmetricKeyWrappingAlg[asymmetric.rsa.RSAPrivateKey, asymmetric.rsa.RSAPublicKey]
):
    padding: Any

    name = "RSA1_5"
    description = "RSAES-PKCS1-v1_5"

    private_key_class = asymmetric.rsa.RSAPrivateKey
    public_key_class = asymmetric.rsa.RSAPublicKey

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