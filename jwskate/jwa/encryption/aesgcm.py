"""This module implements AES-GCM based encryption algorithms."""

from typing import Optional, SupportsBytes, Tuple, Union

from binapy import BinaPy
from cryptography.hazmat.primitives.ciphers import aead

from ..base import BaseAESEncryptionAlg


class BaseAESGCM(BaseAESEncryptionAlg):
    """Base class for AES-GCM encryption algorithms."""

    iv_size = 96
    tag_size = 16

    def encrypt(
        self, plaintext: Union[bytes, SupportsBytes], *, iv: bytes, aad: Optional[bytes]
    ) -> Tuple[BinaPy, BinaPy]:
        """Encrypt a plaintext, with the given IV and Additional Authenticated Data.".

        Args:
          plaintext: the data to encrypt
          iv: the IV to use
          aad: Additional Authenticated Data, if any

        Returns:
            a (ciphertext, authentication_tag) tuple

        Raises:
            ValueError: if the IV size is not appropriate
        """
        if len(iv) * 8 != self.iv_size:
            raise ValueError(f"Invalid IV size, must be {self.iv_size} bits")
        if not isinstance(plaintext, bytes):  # pragma: no branch
            plaintext = bytes(plaintext)
        ciphertext_with_tag = BinaPy(aead.AESGCM(self.key).encrypt(iv, plaintext, aad))
        ciphertext, tag = ciphertext_with_tag.cut_at(-self.tag_size)
        return ciphertext, tag

    def decrypt(
        self,
        ciphertext: Union[bytes, SupportsBytes],
        *,
        iv: bytes,
        auth_tag: bytes,
        aad: Optional[bytes],
    ) -> BinaPy:
        """Decrypt a ciphertext.

        Args:
          ciphertext: the data to decrypt
          auth_tag: the Authentication Tag
          iv: the Initialization Vector
          aad: the Additional Authentication Tag

        Returns:
            the decrypted data

        Raises:
            ValueError: if the IV size is not appropriate
        """
        if not isinstance(ciphertext, bytes):  # pragma: no branch
            ciphertext = bytes(ciphertext)

        if len(iv) * 8 != self.iv_size:
            raise ValueError(f"Invalid IV size, must be {self.iv_size} bits")
        ciphertext_with_tag = ciphertext + auth_tag
        return BinaPy(aead.AESGCM(self.key).decrypt(iv, ciphertext_with_tag, aad))


class A128GCM(BaseAESGCM):
    """AES GCM using 128-bit key."""

    name = "A128GCM"
    description = __doc__
    key_size = 128


class A192GCM(BaseAESGCM):
    """AES GCM using 192-bit key."""

    name = "A192GCM"
    description = __doc__
    key_size = 192


class A256GCM(BaseAESGCM):
    """AES GCM using 256-bit key."""

    name = "A256GCM"
    description = __doc__
    key_size = 256
