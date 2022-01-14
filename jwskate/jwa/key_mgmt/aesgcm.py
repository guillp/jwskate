import secrets
from typing import Tuple

from binapy import BinaPy
from cryptography.hazmat.primitives.ciphers import aead

from ..base import KeyManagementAlg, SymmetricAlg


class AesGmcKeyWrap(KeyManagementAlg, SymmetricAlg):
    iv_size = 96

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


class A128GCMKW(AesGmcKeyWrap):
    name = "A128GCMKW"
    key_size = 128


class A192GCMKW(AesGmcKeyWrap):
    name = "A192GCMKW"
    key_size = 192


class A256GCMKW(AesGmcKeyWrap):
    name = "A256GCMKW"
    key_size = 256
