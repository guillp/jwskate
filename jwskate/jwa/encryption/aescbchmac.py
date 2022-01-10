from typing import Optional

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import ciphers, constant_time, hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from ..base import EncryptionAlg


class AesCbcHmacSha2(EncryptionAlg):
    mac_key_size: int
    aes_key_size: int
    iv_size: int = 16
    hash_alg: hashes.HashAlgorithm

    def __init_subclass__(cls) -> None:
        cls.key_size = cls.mac_key_size + cls.aes_key_size

    def __init__(self, key: bytes) -> None:
        super().__init__(key)
        self.mac_key = self.key[: self.mac_key_size // 8]
        self.aes_key = self.key[self.mac_key_size // 8 :]
        self.padding = padding.PKCS7(algorithms.AES.block_size)

    def mac(self, aad: Optional[bytes], iv: bytes, ciphertext: bytes) -> BinaPy:
        if aad is None:
            aad = b""
        al = BinaPy.from_int(len(aad) * 8, length=8, byteorder="big", signed=False)
        hasher = hmac.HMAC(self.mac_key, self.hash_alg)
        for param in (aad, iv, ciphertext, al):
            hasher.update(param)
        digest = hasher.finalize()
        mac = digest[: self.tag_size]
        return BinaPy(mac)

    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> BinaPy:
        cipher = ciphers.Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).encryptor()
        padder = self.padding.padder()
        padded_text = padder.update(plaintext) + padder.finalize()
        ciphertext = cipher.update(padded_text) + cipher.finalize()
        mac = self.mac(aad, iv, ciphertext)
        return BinaPy(ciphertext + mac)

    def decrypt(
        self, iv: bytes, ciphertext_with_tag: bytes, aad: Optional[bytes]
    ) -> BinaPy:
        ciphertext, tag = BinaPy(ciphertext_with_tag).cut_at(-self.tag_size)
        mac = self.mac(aad, iv, ciphertext)
        if not constant_time.bytes_eq(mac, tag):
            raise exceptions.InvalidSignature()

        cipher = ciphers.Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).decryptor()
        padded_text = cipher.update(ciphertext) + cipher.finalize()
        unpadder = self.padding.unpadder()
        return BinaPy(unpadder.update(padded_text) + unpadder.finalize())


class Aes128CbcHmacSha256(AesCbcHmacSha2):
    name = "A128CBC-HS256"
    description = "AES_128_CBC_HMAC_SHA_256"
    mac_key_size = 128
    aes_key_size = 128
    hash_alg = hashes.SHA256()
    tag_size = 16


class Aes192CbcHmacSha384(AesCbcHmacSha2):
    name = "A192CBC-HS384"
    description = "AES_192_CBC_HMAC_SHA_384"
    mac_key_size = 192
    aes_key_size = 192
    hash_alg = hashes.SHA384()
    tag_size = 24


class Aes256CbcHmacSha512(AesCbcHmacSha2):
    name = "A256CBC-HS512"
    description = "AES_256_CBC_HMAC_SHA_512"
    key_size = 512
    mac_key_size = 256
    aes_key_size = 256
    iv_size = 16
    tag_size = 32
    hash_alg = hashes.SHA512()
