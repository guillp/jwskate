from typing import Optional

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import ciphers, constant_time, hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes


class AesCbcHmacSha2:
    mac_key_size: int
    aes_key_size: int
    tag_size: int
    hash_alg: hashes.HashAlgorithm

    def __init_subclass__(
        cls,
        mac_key_size: int,
        aes_key_size: int,
        tag_size: int,
        hash_alg: hashes.HashAlgorithm,
    ):
        cls.mac_key_size = mac_key_size
        cls.aes_key_size = mac_key_size
        cls.tag_size = tag_size
        cls.hash_alg = hash_alg

    def __init__(self, key: bytes) -> None:
        if len(key) * 8 != self.mac_key_size + self.aes_key_size:
            raise ValueError(
                f"Invalid key length {len(key)*8} bits, expected {self.mac_key_size} + {self.aes_key_size} bits"
            )
        self.key = key
        self.mac_key = self.key[: self.mac_key_size // 8]
        self.aes_key = self.key[self.mac_key_size // 8 :]
        self.padding = padding.PKCS7(algorithms.AES.block_size)

    def mac(self, aad: Optional[bytes], iv: bytes, ciphertext: bytes) -> bytes:
        if aad is None:
            aad = b""
        al = BinaPy.from_int(len(aad) * 8, length=8, byteorder="big", signed=False)
        hasher = hmac.HMAC(self.mac_key, self.hash_alg)
        for param in (aad, iv, ciphertext, al):
            hasher.update(param)
        digest = hasher.finalize()
        mac = digest[: self.tag_size]
        return mac

    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> bytes:
        cipher = ciphers.Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).encryptor()
        padder = self.padding.padder()
        padded_text = padder.update(plaintext) + padder.finalize()
        ciphertext = cipher.update(padded_text) + cipher.finalize()
        mac = self.mac(aad, iv, ciphertext)
        return ciphertext + mac

    def decrypt(
        self, iv: bytes, ciphertext_with_tag: bytes, aad: Optional[bytes]
    ) -> bytes:
        ciphertext, tag = BinaPy(ciphertext_with_tag).cut_at(-self.tag_size)
        mac = self.mac(aad, iv, ciphertext)
        if not constant_time.bytes_eq(mac, tag):
            raise exceptions.InvalidSignature()

        cipher = ciphers.Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).decryptor()
        padded_text = cipher.update(ciphertext) + cipher.finalize()
        unpadder = self.padding.unpadder()
        return unpadder.update(padded_text) + unpadder.finalize()


class Aes128CbcHmacSha256(
    AesCbcHmacSha2,
    mac_key_size=128,
    aes_key_size=128,
    hash_alg=hashes.SHA256(),
    tag_size=16,
):
    pass


class Aes192CbcHmacSha384(
    AesCbcHmacSha2,
    mac_key_size=192,
    aes_key_size=192,
    hash_alg=hashes.SHA384(),
    tag_size=24,
):
    pass


class Aes256CbcHmacSha512(
    AesCbcHmacSha2,
    mac_key_size=256,
    aes_key_size=256,
    hash_alg=hashes.SHA512(),
    tag_size=32,
):
    pass
