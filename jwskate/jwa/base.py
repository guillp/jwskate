from contextlib import contextmanager
from typing import Generic, Iterator, Optional, Tuple, Type, TypeVar, Union

from binapy import BinaPy


class Alg:
    name: str
    description: str

    def __str__(self) -> str:
        return self.name


class SymmetricAlg(Alg):
    def __init__(self, key: bytes):
        self.check_key(key)
        self.key = key

    @classmethod
    def check_key(cls, key: bytes) -> None:
        pass

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
    private_key_class: Union[Type[Kpriv], Tuple[Type[Kpriv], ...]]
    public_key_class: Union[Type[Kpub], Tuple[Type[Kpub], ...]]

    use_epk: bool = False

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
        yield self.key  # type: ignore

    @contextmanager
    def public_key_required(self) -> Iterator[Kpub]:
        if not isinstance(self.key, self.public_key_class):
            raise PublicKeyRequired()
        yield self.key  # type: ignore

    def generate_ephemeral_key(self) -> Kpriv:
        ...


class SignatureAlg(Alg):
    def sign(self, data: bytes) -> BinaPy:
        ...

    def verify(self, data: bytes, signature: bytes) -> bool:
        ...


class EncryptionAlg(SymmetricAlg):
    key_size: int
    tag_size: int
    iv_size: int

    @classmethod
    def check_key(cls, key: bytes) -> None:
        if cls.key_size is not None and len(key) * 8 != cls.key_size:
            raise ValueError(
                f"This key size of {len(key) * 8} bits doesn't match the expected keysize of {cls.key_size} bits"
            )

    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> BinaPy:
        ...

    def decrypt(self, iv: bytes, ciphertext: bytes, aad: Optional[bytes]) -> BinaPy:
        ...


class KeyManagementAlg(Alg):
    pass
