from binapy import BinaPy
from cryptography.hazmat.primitives import keywrap

from ..base import SymmetricKeyWrappingAlg


class AesKeyWrap(SymmetricKeyWrappingAlg):
    def wrap_key(self, plainkey: bytes) -> BinaPy:
        return BinaPy(keywrap.aes_key_wrap(self.key, plainkey))

    def unwrap_key(self, cipherkey: bytes) -> BinaPy:
        return BinaPy(keywrap.aes_key_unwrap(self.key, cipherkey))


class A128KW(AesKeyWrap):
    name = "A128KW"
    description = "AES Key Wrap with default initial value using 128-bit key"
    key_size = 128


class A192KW(AesKeyWrap):
    name = "A192KW"
    description = "AES Key Wrap with default initial value using 192-bit key"
    key_size = 192


class A256KW(AesKeyWrap):
    name = "A256KW"
    description = "AES Key Wrap with default initial value using 256-bit key"
    key_size = 256
