"""This module implements RSA based Key Management algorithms."""

from typing import Any, Union

from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ..base import BaseAsymmetricAlg, BaseKeyManagementAlg


class BaseRsaKeyWrap(
    BaseKeyManagementAlg,
    BaseAsymmetricAlg[asymmetric.rsa.RSAPrivateKey, asymmetric.rsa.RSAPublicKey],
):
    """Base class for RSA Key Wrapping algorithms.

    Args:
        key: the private or public key to use
    """

    padding: Any

    name: str
    description: str

    private_key_class = asymmetric.rsa.RSAPrivateKey
    public_key_class = asymmetric.rsa.RSAPublicKey

    def __init__(
        self, key: Union[asymmetric.rsa.RSAPublicKey, asymmetric.rsa.RSAPrivateKey]
    ):
        self.key = key

    def wrap_key(self, plainkey: bytes) -> BinaPy:
        """Wrap a symmetric key using this algorithm.

        Args:
          plainkey: the symmetric key to wrap

        Returns:
            the wrapped key

        Raises:
            PublicKeyRequired: if this algorithm is initialized with a private key instead of a public key
        """
        if self.read_only:
            raise NotImplementedError
        with self.public_key_required() as key:
            return BinaPy(key.encrypt(plainkey, self.padding))

    def unwrap_key(self, cipherkey: bytes) -> BinaPy:
        """Unwrap a symmetric key with this alg.

        Args:
          cipherkey: the wrapped key

        Returns:
            the unwrapped clear-text key
        Raises:
            PrivateKeyRequired: if this alg is initialized with a public key instead of a private key
        """
        with self.private_key_required() as key:
            return BinaPy(key.decrypt(cipherkey, self.padding))


class RsaEsPcks1v1_5(BaseRsaKeyWrap):  # noqa: D415
    """RSAES-PKCS1-v1_5"""

    name = "RSA1_5"
    description = __doc__
    read_only = True

    padding = padding.PKCS1v15()


class RsaEsOaep(BaseRsaKeyWrap):  # noqa: D415
    """RSAES OAEP using default parameters"""

    name = "RSA-OAEP"
    description = __doc__

    padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None,
    )


class RsaEsOaepSha256(BaseRsaKeyWrap):  # noqa: D415
    """RSAES OAEP using SHA-256 and MGF1 with SHA-256"""

    name = "RSA-OAEP-256"
    description = __doc__

    padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


class RsaEsOaepSha384(BaseRsaKeyWrap):  # noqa: D415
    """RSA-OAEP using SHA-384 and MGF1 with SHA-384"""

    name = "RSA-OAEP-384"
    description = __doc__

    padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA384()),
        algorithm=hashes.SHA384(),
        label=None,
    )


class RsaEsOaepSha512(BaseRsaKeyWrap):  # noqa: D415
    """RSA-OAEP using SHA-512 and MGF1 with SHA-512"""

    name = "RSA-OAEP-512"
    description = __doc__

    padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA512()),
        algorithm=hashes.SHA512(),
        label=None,
    )
