"""This module implements RSA signature algorithms."""
from typing import SupportsBytes, Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ..base import BaseAsymmetricAlg, BaseSignatureAlg


class BaseRSASigAlg(
    BaseAsymmetricAlg[asymmetric.rsa.RSAPrivateKey, asymmetric.rsa.RSAPublicKey],
    BaseSignatureAlg,
):
    """Base class for RSA based signature algorithms."""

    hashing_alg: hashes.HashAlgorithm
    padding_alg: padding.AsymmetricPadding = padding.PKCS1v15()
    min_key_size: int = 2048

    private_key_class = asymmetric.rsa.RSAPrivateKey
    public_key_class = asymmetric.rsa.RSAPublicKey

    def sign(self, data: Union[bytes, SupportsBytes]) -> BinaPy:
        """Sign arbitrary data.

        Args:
          data: the data to sign

        Returns:
            the generated signature

        Raises:
            NotImplementedError: for algorithms that are considered insecure, only signature verification is available
            PrivateKeyRequired: if the configured key is not private
        """
        if self.read_only:
            raise NotImplementedError

        if not isinstance(data, bytes):
            data = bytes(data)

        with self.private_key_required() as key:
            return BinaPy(key.sign(data, self.padding_alg, self.hashing_alg))

    def verify(
        self, data: Union[bytes, SupportsBytes], signature: Union[bytes, SupportsBytes]
    ) -> bool:
        """Verify a signature against some data.

        Args:
          data: the data to verify
          signature: the signature

        Returns:
            `True` if the signature is valid, `False` otherwise
        """
        if not isinstance(data, bytes):
            data = bytes(data)

        if not isinstance(signature, bytes):
            signature = bytes(signature)

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


class RS256(BaseRSASigAlg):  # noqa: D415
    """RSASSA-PKCS1-v1_5 using SHA-256."""

    name = "RS256"
    description = __doc__
    hashing_alg = hashes.SHA256()


class RS384(BaseRSASigAlg):  # noqa: D415
    """RSASSA-PKCS1-v1_5 using SHA-384."""

    name = "RS384"
    description = __doc__
    hashing_alg = hashes.SHA384()


class RS512(BaseRSASigAlg):  # noqa: D415
    """RSASSA-PKCS1-v1_5 using SHA-256."""

    name = "RS512"
    description = __doc__
    hashing_alg = hashes.SHA512()


class PS256(BaseRSASigAlg):  # noqa: D415
    """RSASSA-PSS using SHA-256 and MGF1 with SHA-256."""

    name = "PS256"
    description = __doc__
    hashing_alg = hashes.SHA256()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=256 // 8)


class PS384(BaseRSASigAlg):  # noqa: D415
    """RSASSA-PSS using SHA-384 and MGF1 with SHA-384."""

    name = "PS384"
    description = __doc__
    hashing_alg = hashes.SHA384()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=384 // 8)


class PS512(BaseRSASigAlg):  # noqa: D415
    """RSASSA-PSS using SHA-512 and MGF1 with SHA-512."""

    name = "PS512"
    description = __doc__
    hashing_alg = hashes.SHA512()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=512 // 8)


class RS1(BaseRSASigAlg):  # noqa: D415
    """RSASSA-PKCS1-v1_5 with SHA-1."""

    name = "RS1"
    description = __doc__
    hashing_alg = hashes.SHA1()
    read_only = True
