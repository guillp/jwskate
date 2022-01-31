import secrets
from typing import Tuple

from binapy import BinaPy
from cryptography.hazmat.primitives.ciphers import aead

from ..base import BaseKeyManagementAlg, BaseSymmetricAlg


class BaseAesGcmKeyWrap(BaseKeyManagementAlg, BaseSymmetricAlg):
    iv_size: int = 96
    key_size: int

    @classmethod
    def check_key(cls, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) * 8 != cls.key_size:
            raise ValueError(f"Key must be {cls.key_size} bits")

    def wrap_key(self, plainkey: bytes, iv: bytes) -> Tuple[BinaPy, BinaPy]:
        if len(iv) * 8 != self.iv_size:
            raise ValueError("Invalid IV size, must be {self.iv_size} bits")
        cipherkey, tag = BinaPy(
            aead.AESGCM(self.key).encrypt(iv, plainkey, b"")
        ).cut_at(-16)
        return cipherkey, tag

    def unwrap_key(self, cipherkey: bytes, tag: bytes, iv: bytes) -> BinaPy:
        return BinaPy(aead.AESGCM(self.key).decrypt(iv, cipherkey + tag, b""))

    def generate_iv(self) -> BinaPy:
        return BinaPy(secrets.token_bytes(self.iv_size // 8))


class A128GCMKW(BaseAesGcmKeyWrap):
    name = "A128GCMKW"
    key_size = 128


class A192GCMKW(BaseAesGcmKeyWrap):
    name = "A192GCMKW"
    key_size = 192


class A256GCMKW(BaseAesGcmKeyWrap):
    name = "A256GCMKW"
    key_size = 256
