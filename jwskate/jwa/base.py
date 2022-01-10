from contextlib import contextmanager
from typing import Any, Generic, Iterator, Optional, Type, TypeVar, Union

from binapy import BinaPy


class Alg:
    name: str
    description: str

    def __str__(self) -> str:
        return self.name


class SymmetricAlg(Alg):
    key_size: int

    def __init__(self, key: bytes):
        self.check_key(key)
        self.key = key

    @classmethod
    def check_key(cls, key: bytes) -> None:
        if len(key) * 8 != cls.key_size:
            raise ValueError(
                f"This key size of {len(key) * 8} bits doesn't match the expected keysize of {cls.key_size} bits"
            )

    @classmethod
    def supports_key(cls, key: bytes) -> bool:
        try:
            cls.check_key(key)
            return True
        except Exception:
            return False


Kpriv = TypeVar("Kpriv")
Kpub = TypeVar("Kpub")


class PrivateKeyRequired(AttributeError):
    pass


class PublicKeyRequired(AttributeError):
    pass


class AsymmetricAlg(Generic[Kpriv, Kpub], Alg):
    private_key_class: Type[Kpriv]
    public_key_class: Type[Kpub]

    def __init__(self, key: Union[Kpriv, Kpub]):
        self.check_key(key)
        self.key = key

    @classmethod
    def check_key(cls, key: Union[Kpriv, Kpub]) -> None:
        ...

    @classmethod
    def supports_key(cls, key: Union[Kpriv, Kpub]) -> bool:
        try:
            cls.check_key(key)
            return True
        except Exception:
            return False

    @contextmanager
    def private_key_required(self) -> Iterator[Kpriv]:
        if not isinstance(self.key, self.private_key_class):
            raise PrivateKeyRequired()
        yield self.key

    @contextmanager
    def public_key_required(self) -> Iterator[Kpub]:
        if not isinstance(self.key, self.public_key_class):
            raise PublicKeyRequired()
        yield self.key


class SignatureAlg(Alg):
    def sign(self, data: bytes) -> BinaPy:
        ...

    def verify(self, data: bytes, signature: bytes) -> bool:
        ...


class SymmetricSignatureAlg(SymmetricAlg, SignatureAlg):
    pass


class AsymmetricSignatureAlg(AsymmetricAlg[Kpriv, Kpub], SignatureAlg):
    pass


class EncryptionAlg(SymmetricAlg):
    tag_size: int
    iv_size: int

    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> BinaPy:
        ...

    def decrypt(self, iv: bytes, ciphertext: bytes, aad: Optional[bytes]) -> BinaPy:
        ...


class KeyManagementAlg(Alg):
    pass


class KeyWrappingAlg(KeyManagementAlg):
    def wrap_key(self, plainkey: bytes) -> BinaPy:
        ...

    def unwrap_key(self, cipherkey: bytes) -> BinaPy:
        ...


class SymmetricKeyWrappingAlg(KeyManagementAlg, SymmetricAlg):
    pass


class AsymmetricKeyWrappingAlg(KeyWrappingAlg, AsymmetricAlg[Kpriv, Kpub]):
    pass


class KeyGenerationAlg(KeyManagementAlg):
    def generate_cek(self) -> BinaPy:
        ...


class KeyDerivationAlg(KeyManagementAlg, AsymmetricAlg[Kpriv, Kpub]):
    def generate_ephemeral_key(self) -> Kpriv:
        ...

    def sender_key(
        self, ephemeral_private_key: Kpriv, aesalg: Type[SymmetricAlg], **headers: Any
    ) -> BinaPy:
        ...

    def recipient_key(
        self, ephemeral_public_key: Kpub, aesalg: Type[SymmetricAlg], **headers: Any
    ) -> BinaPy:
        ...
