"""This module implements AES-GCM based Key Management algorithms."""

from typing import Tuple

from binapy import BinaPy

from ..base import BaseKeyManagementAlg
from ..encryption.aesgcm import BaseAESGCM


class BaseAesGcmKeyWrap(BaseAESGCM, BaseKeyManagementAlg):
    """Base class for AES-GCM Key wrapping algorithms."""

    key_size: int
    """Required key size, in bits."""
    tag_size: int = 16
    """Authentication tag size, in bits."""
    iv_size: int = 96
    """Initialisation Vector size, in bits."""

    def wrap_key(self, plainkey: bytes, *, iv: bytes) -> Tuple[BinaPy, BinaPy]:
        """Wrap a key using the given Initialisation Vector (`iv`).

        Args:
          plainkey: the key to wrap
          iv: the Initialisation Vector to use

        Returns:
          a tuple (wrapped_key, authentication_tag)
        """
        return self.encrypt(plainkey, iv=iv, aad=b"")

    def unwrap_key(self, cipherkey: bytes, *, tag: bytes, iv: bytes) -> BinaPy:
        """Unwrap a key and authenticates it with the authentication `tag`, using the given Initialisation Vector (`iv`).

        Args:
          cipherkey: the wrapped key
          tag: the authentication tag
          iv: the Initialisation Vector

        Returns:
          the unwrapped key.
        """
        return self.decrypt(cipherkey, auth_tag=tag, iv=iv, aad=b"")


class A128GCMKW(BaseAesGcmKeyWrap):
    """Key wrapping with AES GCM using 128-bit key."""

    name = "A128GCMKW"
    description = __doc__
    key_size = 128


class A192GCMKW(BaseAesGcmKeyWrap):
    """Key wrapping with AES GCM using 192-bit key."""

    name = "A192GCMKW"
    description = __doc__
    key_size = 192


class A256GCMKW(BaseAesGcmKeyWrap):
    """Key wrapping with AES GCM using 256-bit key."""

    name = "A256GCMKW"
    description = __doc__
    key_size = 256
