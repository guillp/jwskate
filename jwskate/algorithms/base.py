from typing import Any, Generic, Mapping, Optional, Type, TypeVar

from binapy import BinaPy


class Alg:
    name: str
    description: str

    def __init__(self, key: Any):
        self.check_key(key)
        self.key = key

    @classmethod
    def check_key(cls, key: Any) -> None:
        ...

    @classmethod
    def supports_key(cls, key: Any) -> bool:
        try:
            cls.check_key(key)
            return True
        except Exception:
            return False

    def __str__(self) -> str:
        return self.name


class SignatureAlg(Alg):
    def sign(self, data: bytes) -> BinaPy:
        ...

    def verify(self, data: bytes) -> BinaPy:
        ...


class EncryptionAlg(Alg):
    key_size: int

    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> BinaPy:
        ...

    def decrypt(self, iv: bytes, ciphertext: bytes, aad: Optional[bytes]) -> BinaPy:
        ...


class AESEncryptionAlg(EncryptionAlg):
    iv_size: int
    tag_size: int

    @classmethod
    def supports_key(cls, key: Any) -> bool:
        return isinstance(key, bytes) and len(key) * 8 == cls.key_size


class KeyManagementAlg(Alg):
    pass


class WrappedContentEncryptionKeyAlg(KeyManagementAlg):
    def generate_cek(self, encalg: EncryptionAlg) -> BinaPy:
        ...

    def wrap_key(self, plainkey: bytes) -> BinaPy:
        ...

    def unwrap_key(self, cipherkey: bytes) -> BinaPy:
        ...


Kpriv = TypeVar("Kpriv")
Kpub = TypeVar("Kpub")


class DiffieHellmanAlg(KeyManagementAlg, Generic[Kpriv, Kpub]):
    def generate_ephemeral_key(self) -> Kpriv:
        ...

    def sender_key(
        self,
        ephemeral_private_key: Kpriv,
        headers: Mapping[str, Any],
        encalg: Type[EncryptionAlg],
    ) -> BinaPy:
        ...

    def recipient_key(
        self,
        ephemeral_public_key: Kpub,
        headers: Mapping[str, Any],
        encalg: Type[EncryptionAlg],
    ) -> BinaPy:
        ...
