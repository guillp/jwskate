from typing import Type

from binapy import BinaPy
from cryptography.hazmat.primitives import hashes, hmac

from ..base import BaseSignatureAlg, BaseSymmetricAlg


class HMACSigAlg(BaseSymmetricAlg, BaseSignatureAlg):
    mac: Type[hmac.HMAC] = hmac.HMAC
    hash_alg: hashes.HashAlgorithm
    min_key_size: int

    def sign(self, data: bytes) -> BinaPy:
        if self.read_only:
            raise NotImplementedError
        m = self.mac(self.key, self.hash_alg)
        m.update(data)
        signature = m.finalize()
        return BinaPy(signature)

    def verify(self, data: bytes, signature: bytes) -> bool:
        candidate_signature = self.sign(data)
        return candidate_signature == signature


class HS256(HMACSigAlg):
    name = "HS256"
    description = "HMAC using SHA-256"
    hash_alg = hashes.SHA256()
    min_key_size = 256


class HS384(HMACSigAlg):
    name = "HS384"
    description = "HMAC using SHA-384"
    hash_alg = hashes.SHA384()
    min_key_size = 384


class HS512(HMACSigAlg):
    name = "HS512"
    description = "HMAC using SHA-512"
    hash_alg = hashes.SHA512()
    min_key_size = 512


class HS1(HMACSigAlg):
    name = "HS1"
    description = "HMAC using SHA-1"
    read_only = True
    min_key_size = 160
    hash_alg = hashes.SHA1()
