"""This module implements HMAC based signature algorithms."""

from typing import Type

from binapy import BinaPy
from cryptography.hazmat.primitives import hashes, hmac

from ..base import BaseSignatureAlg, BaseSymmetricAlg


class BaseHMACSigAlg(BaseSymmetricAlg, BaseSignatureAlg):
    """Base class for HMAC signature algorithms."""

    mac: Type[hmac.HMAC] = hmac.HMAC
    hash_alg: hashes.HashAlgorithm
    min_key_size: int

    def sign(self, data: bytes) -> BinaPy:  # noqa: D102
        if self.read_only:
            raise NotImplementedError
        m = self.mac(self.key, self.hash_alg)
        m.update(data)
        signature = m.finalize()
        return BinaPy(signature)

    def verify(self, data: bytes, signature: bytes) -> bool:  # noqa: D102
        candidate_signature = self.sign(data)
        return candidate_signature == signature


class HS256(BaseHMACSigAlg):  # noqa: D415
    """HMAC using SHA-256"""

    name = "HS256"
    description = __doc__
    hash_alg = hashes.SHA256()
    min_key_size = 256


class HS384(BaseHMACSigAlg):  # noqa: D415
    """HMAC using SHA-384"""

    name = "HS384"
    description = __doc__
    hash_alg = hashes.SHA384()
    min_key_size = 384


class HS512(BaseHMACSigAlg):  # noqa: D415
    """HMAC using SHA-512"""

    name = "HS512"
    description = __doc__
    hash_alg = hashes.SHA512()
    min_key_size = 512


class HS1(BaseHMACSigAlg):  # noqa: D415
    """HMAC using SHA-1"""

    name = "HS1"
    description = __doc__
    read_only = True
    min_key_size = 160
    hash_alg = hashes.SHA1()
