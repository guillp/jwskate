from typing import Optional, Tuple

from binapy import BinaPy
from cryptography.hazmat.primitives.ciphers import aead

from ..base import BaseAESAlg


class BaseAESGCM(BaseAESAlg):
    def encrypt(
        self, plaintext: bytes, iv: bytes, aad: Optional[bytes]
    ) -> Tuple[BinaPy, BinaPy]:
        ciphertext_with_tag = BinaPy(aead.AESGCM(self.key).encrypt(iv, plaintext, aad))
        ciphertext, tag = ciphertext_with_tag.cut_at(-self.tag_size)
        return ciphertext, tag

    def decrypt(
        self, ciphertext: bytes, auth_tag: bytes, iv: bytes, aad: Optional[bytes]
    ) -> BinaPy:
        ciphertext_with_tag = ciphertext + auth_tag
        return BinaPy(aead.AESGCM(self.key).decrypt(iv, ciphertext_with_tag, aad))


class A128GCM(BaseAESGCM):
    """AES GCM using 128-bit key"""

    name = "A128GCM"
    description = __doc__
    key_size = 128
    iv_size = 96
    tag_size = 16


class A192GCM(BaseAESGCM):
    """AES GCM using 192-bit key"""

    name = "A192GCM"
    description = __doc__
    key_size = 192
    iv_size = 96
    tag_size = 16


class A256GCM(BaseAESGCM):
    """AES GCM using 256-bit key"""

    name = "A256GCM"
    description = __doc__
    key_size = 256
    iv_size = 96
    tag_size = 16
