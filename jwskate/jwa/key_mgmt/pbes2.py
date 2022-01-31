from typing import Type, Union

from binapy import BinaPy
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2

from ..base import BaseKeyManagementAlg
from .aeskw import A128KW, A192KW, A256KW, BaseAesKeyWrap


class Pbes2(BaseKeyManagementAlg):
    kwalg: Type[BaseAesKeyWrap]
    hash_alg: hashes.HashAlgorithm

    def __init__(self, password: Union[bytes, str]):
        if isinstance(password, str):
            password = password.encode("utf-8")
        self.password = password

    def generate_salt(self, size: int = 12) -> BinaPy:
        if size < 8:
            raise ValueError("salts used for PBES2 must be at least 8 bytes long")
        return BinaPy.random(size)

    def derive(self, salt_input: bytes, count: int) -> BinaPy:
        salt = self.name.encode() + b"\0" + salt_input
        pbkdf = pbkdf2.PBKDF2HMAC(
            algorithm=self.hash_alg,
            length=self.kwalg.key_size // 8,
            salt=salt,
            iterations=count,
        )
        return BinaPy(pbkdf.derive(self.password))

    def wrap_key(self, plainkey: bytes, salt_input: bytes, count: int) -> BinaPy:
        aes_key = self.derive(salt_input, count)
        return BinaPy(self.kwalg(aes_key).wrap_key(plainkey))

    def unwrap_key(self, cipherkey: bytes, salt_input: bytes, count: int) -> BinaPy:
        aes_key = self.derive(salt_input, count)
        return BinaPy(self.kwalg(aes_key).unwrap_key(cipherkey))


class Pbes2_HS256_A128KW(Pbes2):
    name = "PBES2-HS256+A128KW"
    kwalg = A128KW
    hash_alg = hashes.SHA256()


class Pbes2_HS384_A192KW(Pbes2):
    name = "PBES2-HS384+A192KW"
    kwalg = A192KW
    hash_alg = hashes.SHA384()


class Pbes2_HS512_A256KW(Pbes2):
    name = "PBES2-HS512+A256KW"
    kwalg = A256KW
    hash_alg = hashes.SHA512()
