from typing import Optional, Tuple

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import ciphers, constant_time, hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from ..base import BaseAESAlg


class BaseAesCbcHmacSha2(BaseAESAlg):
    """
    Implements the family of AES-CBC with HMAC-SHA encryption algorithms.
    """

    mac_key_size: int
    """Required key size for the Hash algorithm."""

    aes_key_size: int
    """Required key size for the AES algorithm."""

    iv_size: int = 16
    """Initialization Vector size for the AES algorithm."""

    hash_alg: hashes.HashAlgorithm
    """Hash algorithm to use."""

    def __init_subclass__(cls) -> None:
        cls.key_size = cls.mac_key_size + cls.aes_key_size

    def __init__(self, key: bytes) -> None:
        """
        Initialize this wrapper with the given key.
        :param key: the key to use for encryption and decryption.
        """
        super().__init__(key)
        self.mac_key = self.key[: self.mac_key_size // 8]
        self.aes_key = self.key[self.mac_key_size // 8 :]
        self.padding = padding.PKCS7(algorithms.AES.block_size)

    def mac(self, ciphertext: bytes, iv: bytes, aad: Optional[bytes] = None) -> BinaPy:
        """
        Produce a Message Authentication Code for the given `ciphertext`, `iv` and `aad`.
        :param ciphertext: the ciphertext.
        :param iv: the Initialization Vector.
        :param aad: the Additional Authenticated data.
        :return: the resulting MAC.
        """
        if aad is None:
            aad = b""
        al = BinaPy.from_int(len(aad) * 8, length=8, byteorder="big", signed=False)
        hasher = hmac.HMAC(self.mac_key, self.hash_alg)
        for param in (aad, iv, ciphertext, al):
            hasher.update(param)
        digest = hasher.finalize()
        mac = digest[: self.tag_size]
        return BinaPy(mac)

    def encrypt(
        self, plaintext: bytes, iv: bytes, aad: Optional[bytes] = None
    ) -> Tuple[BinaPy, BinaPy]:
        """
        Encrypt and MAC the given `plaintext`, using the given Initialization Vector (`iv`)
        and optional Additional Authenticated Data (`aad`).
        :param plaintext: the plain data to cipher.
        :param iv: the Initialization Vector.
        :param aad: the Additional Authenticated Data, if any.
        :return: the ciphered data and authentication tag.
        """
        cipher = ciphers.Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).encryptor()
        padder = self.padding.padder()
        padded_text = padder.update(plaintext) + padder.finalize()
        ciphertext = cipher.update(padded_text) + cipher.finalize()
        mac = self.mac(ciphertext, iv, aad)
        return BinaPy(ciphertext), BinaPy(mac)

    def decrypt(
        self, ciphertext: bytes, auth_tag: bytes, iv: bytes, aad: Optional[bytes]
    ) -> BinaPy:
        """
        Decrypt and authenticate the given ciphertext with authentication tag (`ciphertext_with_tag`), as produced by `encrypt()`.
        :param ciphertext: the ciphertext.
        :param auth_tag: the authentication tag.
        :param iv: the Initialization Vector.
        :param aad: the Additional Authenticated Data, if any.
        :return: the plain data.
        """
        mac = self.mac(ciphertext, iv, aad)
        if not constant_time.bytes_eq(mac, auth_tag):
            raise exceptions.InvalidSignature()

        cipher = ciphers.Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).decryptor()
        padded_text = cipher.update(ciphertext) + cipher.finalize()
        unpadder = self.padding.unpadder()
        return BinaPy(unpadder.update(padded_text) + unpadder.finalize())


class Aes128CbcHmacSha256(BaseAesCbcHmacSha2):
    """AES_128_CBC_HMAC_SHA_256"""

    name = "A128CBC-HS256"
    description = __doc__
    mac_key_size = 128
    aes_key_size = 128
    hash_alg = hashes.SHA256()
    tag_size = 16


class Aes192CbcHmacSha384(BaseAesCbcHmacSha2):
    """AES_192_CBC_HMAC_SHA_384"""

    name = "A192CBC-HS384"
    description = __doc__
    mac_key_size = 192
    aes_key_size = 192
    hash_alg = hashes.SHA384()
    tag_size = 24


class Aes256CbcHmacSha512(BaseAesCbcHmacSha2):
    """AES_256_CBC_HMAC_SHA_512"""

    name = "A256CBC-HS512"
    description = __doc__
    key_size = 512
    mac_key_size = 256
    aes_key_size = 256
    iv_size = 16
    tag_size = 32
    hash_alg = hashes.SHA512()
