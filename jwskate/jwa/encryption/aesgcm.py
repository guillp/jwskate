from typing import Optional

from binapy import BinaPy
from cryptography.hazmat.primitives.ciphers import aead

from ..base import EncryptionAlg


class AESGCM(EncryptionAlg):
    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> BinaPy:
        return BinaPy(aead.AESGCM(self.key).encrypt(iv, plaintext, aad))

    def decrypt(self, iv: bytes, ciphertext: bytes, aad: Optional[bytes]) -> BinaPy:
        return BinaPy(aead.AESGCM(self.key).decrypt(iv, ciphertext, aad))


class A128GCM(AESGCM):
    name = "A128GCM"
    description = "AES GCM using 128-bit key"
    key_size = 128
    iv_size = 96
    tag_size = 16


class A192GCM(AESGCM):
    name = "A192GCM"
    description = "AES GCM using 192-bit key"
    key_size = 192
    iv_size = 96
    tag_size = 16


class A256GCM(AESGCM):
    name = "A256GCM"
    description = "AES GCM using 256-bit key"
    key_size = 256
    iv_size = 96
    tag_size = 16
