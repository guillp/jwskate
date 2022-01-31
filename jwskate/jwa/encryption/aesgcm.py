from typing import Optional, Tuple

from binapy import BinaPy
from cryptography.hazmat.primitives.ciphers import aead

from ..base import BaseAESEncryptionAlg


class BaseAESGCM(BaseAESEncryptionAlg):
    iv_size = 96
    tag_size = 16

    def encrypt(
        self, plaintext: bytes, iv: bytes, aad: Optional[bytes]
    ) -> Tuple[BinaPy, BinaPy]:
        if len(iv) * 8 != self.iv_size:
            raise ValueError(f"Invalid IV size, must be {self.iv_size} bits")
        ciphertext_with_tag = BinaPy(aead.AESGCM(self.key).encrypt(iv, plaintext, aad))
        ciphertext, tag = ciphertext_with_tag.cut_at(-self.tag_size)
        return ciphertext, tag

    def decrypt(
        self, ciphertext: bytes, auth_tag: bytes, iv: bytes, aad: Optional[bytes]
    ) -> BinaPy:
        if len(iv) * 8 != self.iv_size:
            raise ValueError(f"Invalid IV size, must be {self.iv_size} bits")
        ciphertext_with_tag = ciphertext + auth_tag
        return BinaPy(aead.AESGCM(self.key).decrypt(iv, ciphertext_with_tag, aad))


class A128GCM(BaseAESGCM):
    """AES GCM using 128-bit key"""

    name = "A128GCM"
    description = __doc__
    key_size = 128


class A192GCM(BaseAESGCM):
    """AES GCM using 192-bit key"""

    name = "A192GCM"
    description = __doc__
    key_size = 192


class A256GCM(BaseAESGCM):
    """AES GCM using 256-bit key"""

    name = "A256GCM"
    description = __doc__
    key_size = 256
