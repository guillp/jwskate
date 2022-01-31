from binapy import BinaPy
from cryptography.hazmat.primitives import keywrap

from ..base import BaseKeyManagementAlg, BaseSymmetricAlg


class BaseAesKeyWrap(BaseKeyManagementAlg, BaseSymmetricAlg):
    """
    Base class for AES KW algorithms.
    """

    key_size: int
    """Required AES key size in bits."""

    @classmethod
    def check_key(cls, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) * 8 != cls.key_size:
            raise ValueError(f"Key must be {cls.key_size} bits")

    def wrap_key(self, plainkey: bytes) -> BinaPy:
        """
        Wrap a key.
        :param plainkey: the key to wrap.
        :return: the wrapped key.
        """
        return BinaPy(keywrap.aes_key_wrap(self.key, plainkey))

    def unwrap_key(self, cipherkey: bytes) -> BinaPy:
        """
        Unwrap a key.
        :param cipherkey: the wrapped key.
        :return: the unwrapped key.
        """
        return BinaPy(keywrap.aes_key_unwrap(self.key, cipherkey))


class A128KW(BaseAesKeyWrap):
    """AES Key Wrap with default initial value using 128-bit key"""

    name = "A128KW"
    description = __doc__
    key_size = 128


class A192KW(BaseAesKeyWrap):
    """AES Key Wrap with default initial value using 192-bit key"""

    name = "A192KW"
    description = __doc__
    key_size = 192


class A256KW(BaseAesKeyWrap):
    """AES Key Wrap with default initial value using 256-bit key"""

    name = "A256KW"
    description = __doc__
    key_size = 256
