import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple, Type, Union

from binapy import BinaPy
from cryptography.hazmat.primitives import hashes, hmac, keywrap
from cryptography.hazmat.primitives.ciphers import aead
from typing_extensions import Protocol

from ..algorithms import Aes128CbcHmacSha256, Aes192CbcHmacSha384, Aes256CbcHmacSha512
from .alg import (
    EncryptionAlg,
    KeyManagementAlg,
    SymetricSignatureAlg,
    select_alg,
    select_algs,
)
from .base import Jwk, JwkParameter


class EncryptionProtocol(Protocol):
    def __init__(self, key: bytes) -> None:
        ...

    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> bytes:
        ...

    def decrypt(self, iv: bytes, ciphertext: bytes, aad: Optional[bytes]) -> bytes:
        ...


@dataclass
class SymmetricKeyManagementAlg(KeyManagementAlg):
    wrap_method: Callable[[bytes, bytes], bytes]
    unwrap_method: Callable[[bytes, bytes], bytes]
    key_size: Optional[int] = None


@dataclass
class SymmetricEncryptionAlg(EncryptionAlg):
    enc_class: Type[EncryptionProtocol]
    key_size: int
    iv_size: int
    tag_size: int


class SymmetricJwk(Jwk):
    """
    Implement Symetric keys, with `kty=oct`.
    """

    kty = "oct"

    PARAMS = {
        "k": JwkParameter("Key Value", is_private=True, is_required=True, kind="b64u"),
    }

    SIGNATURE_ALGORITHMS = {
        "HS256": SymetricSignatureAlg(
            name="HS256",
            description="HMAC using SHA-256",
            mac=hmac.HMAC,
            hashing_alg=hashes.SHA256(),
            min_key_size=256,
        ),
        "HS384": SymetricSignatureAlg(
            name="HS384",
            description="HMAC using SHA-384",
            mac=hmac.HMAC,
            hashing_alg=hashes.SHA384(),
            min_key_size=384,
        ),
        "HS512": SymetricSignatureAlg(
            name="HS512",
            description="HMAC using SHA-512",
            mac=hmac.HMAC,
            hashing_alg=hashes.SHA512(),
            min_key_size=512,
        ),
    }

    KEY_MANAGEMENT_ALGORITHMS = {
        "A128KW": SymmetricKeyManagementAlg(
            name="A128KW",
            description="AES Key Wrap with default initial value using 128-bit key",
            wrap_method=keywrap.aes_key_wrap,
            unwrap_method=keywrap.aes_key_unwrap,
            key_size=128,
        ),
        "A192KW": SymmetricKeyManagementAlg(
            name="A192KW",
            description="AES Key Wrap with default initial value using 192-bit key",
            wrap_method=keywrap.aes_key_wrap,
            unwrap_method=keywrap.aes_key_unwrap,
            key_size=192,
        ),
        "A256KW": SymmetricKeyManagementAlg(
            name="A256KW",
            description="AES Key Wrap with default initial value using 256-bit key",
            wrap_method=keywrap.aes_key_wrap,
            unwrap_method=keywrap.aes_key_unwrap,
            key_size=256,
        ),
        "dir": SymmetricKeyManagementAlg(
            name="dir",
            description="Direct use of a shared symmetric key as the CEK",
            wrap_method=lambda self, key: self,
            unwrap_method=lambda self, key: self,
        ),
    }

    ENCRYPTION_ALGORITHMS = {
        "A128CBC-HS256": SymmetricEncryptionAlg(
            name="A128CBC-HS256",
            description="AES_128_CBC_HMAC_SHA_256",
            enc_class=Aes128CbcHmacSha256,
            key_size=256,
            iv_size=16,
            tag_size=16,
        ),
        "A192CBC-HS384": SymmetricEncryptionAlg(
            name="A192CBC-HS384",
            description="AES_192_CBC_HMAC_SHA_384",
            enc_class=Aes192CbcHmacSha384,
            key_size=384,
            iv_size=16,
            tag_size=24,
        ),
        "A256CBC-HS512": SymmetricEncryptionAlg(
            name="A256CBC-HS512",
            description="AES_256_CBC_HMAC_SHA_512",
            enc_class=Aes256CbcHmacSha512,
            key_size=512,
            iv_size=16,
            tag_size=32,
        ),
        "A128GCM": SymmetricEncryptionAlg(
            name="A128GCM",
            description="AES GCM using 128-bit key",
            enc_class=aead.AESGCM,
            key_size=128,
            iv_size=96,
            tag_size=16,
        ),
        "A192GCM": SymmetricEncryptionAlg(
            name="A192GCM",
            description="AES GCM using 192-bit key",
            enc_class=aead.AESGCM,
            key_size=192,
            iv_size=96,
            tag_size=16,
        ),
        "A256GCM": SymmetricEncryptionAlg(
            name="A256GCM",
            description="AES GCM using 256-bit key",
            enc_class=aead.AESGCM,
            key_size=256,
            iv_size=96,
            tag_size=16,
        ),
    }

    def public_jwk(self) -> "Jwk":
        raise ValueError("Symmetric keys don't have a public key")

    @classmethod
    def from_bytes(cls, k: Union[bytes, str], **params: str) -> "SymmetricJwk":
        """
        Initializes a SymmetricJwk from a raw secret key.
        The provided secret key is encoded and used as the `k` parameter for the returned SymetricKey.
        :param k: the key to use
        :param params: additional parameters for the returned Jwk
        :return: a SymmetricJwk
        """
        return cls(dict(kty="oct", k=BinaPy(k).encode_to("b64u").decode(), **params))

    @classmethod
    def generate(cls, size: int = 128, **params: str) -> "SymmetricJwk":
        """
        Generates a random SymmetricJwk, with a given key size.
        :param size: the size of the generated key, in bytes.
        :param params: additional parameters for the returned Jwk
        :return: a SymmetricJwk with a random key
        """
        key = secrets.token_bytes(size // 8)
        return cls.from_bytes(key, **params)

    @classmethod
    def generate_for_alg(cls, alg: str, **params: str) -> "SymmetricJwk":
        if alg in cls.SIGNATURE_ALGORITHMS:
            sigalg = cls.SIGNATURE_ALGORITHMS[alg]
            return cls.generate(sigalg.min_key_size, alg=alg, **params)
        if alg in cls.ENCRYPTION_ALGORITHMS:
            encalg = cls.ENCRYPTION_ALGORITHMS[alg]
            return cls.generate(encalg.key_size, alg=alg, **params)
        raise ValueError("Unsupported alg", alg)

    @property
    def key(self) -> bytes:
        """
        Returns the raw symmetric key.
        :return: the key from the `k` parameter, base64u-decoded.
        """
        return BinaPy(self.k).decode_from("b64u")

    @property
    def key_size(self) -> int:
        return len(self.key) * 8

    def sign(self, data: bytes, alg: Optional[str] = None) -> BinaPy:
        sigalg = select_alg(self.alg, alg, self.SIGNATURE_ALGORITHMS)

        m = sigalg.mac(self.key, sigalg.hashing_alg)
        m.update(data)
        signature = m.finalize()
        return BinaPy(signature)

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        for sigalg in select_algs(self.alg, alg, algs, self.SIGNATURE_ALGORITHMS):

            m = sigalg.mac(self.key, sigalg.hashing_alg)
            m.update(data)
            candidate_signature = m.finalize()
            if signature == candidate_signature:
                return True

        return False

    def encrypt(
        self,
        plaintext: bytes,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
        iv: Optional[bytes] = None,
    ) -> Tuple[BinaPy, BinaPy, BinaPy]:
        encalg = select_alg(self.alg, alg, self.ENCRYPTION_ALGORITHMS)

        if self.key_size != encalg.key_size:
            raise ValueError(
                f"This key size of {self.key_size} doesn't match the expected keysize for {encalg.name} of {encalg.key_size} bits"
            )

        if iv is None:
            iv = secrets.token_bytes(encalg.iv_size)

        encryptor = encalg.enc_class(self.key)
        cyphertext_with_tag = encryptor.encrypt(iv, plaintext, aad)
        cyphertext = cyphertext_with_tag[: -encalg.tag_size]
        tag = cyphertext_with_tag[-encalg.tag_size :]

        return BinaPy(cyphertext), BinaPy(tag), BinaPy(iv)

    def decrypt(
        self,
        cyphertext: bytes,
        tag: bytes,
        iv: bytes,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
    ) -> BinaPy:
        encalg = select_alg(self.alg, alg, self.ENCRYPTION_ALGORITHMS)

        if self.key_size != encalg.key_size:
            raise ValueError(
                f"This key size of {self.key_size} doesn't match the expected keysize for {encalg.name} of {encalg.key_size} bits"
            )

        decryptor = encalg.enc_class(self.key)
        cyphertext_with_tag = cyphertext + tag
        plaintext: bytes = decryptor.decrypt(iv, cyphertext_with_tag, aad)

        return BinaPy(plaintext)

    def wrap_key(self, key: bytes, alg: Optional[str] = None) -> BinaPy:
        keyalg = select_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)

        if keyalg.key_size is not None and self.key_size != keyalg.key_size:
            raise ValueError(
                f"This key size of {self.key_size} doesn't match the expected keysize for {keyalg.description} of {keyalg.key_size} bits"
            )

        cypherkey = keyalg.wrap_method(self.key, key)
        return BinaPy(cypherkey)

    def unwrap_key(self, cypherkey: bytes, alg: Optional[str] = None) -> BinaPy:
        keyalg = select_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)

        if keyalg.key_size is not None and self.key_size != keyalg.key_size:
            raise ValueError(
                f"This key size of {self.key_size} doesn't match the expected keysize for {keyalg.description} of {keyalg.key_size} bits"
            )

        plaintext = keyalg.unwrap_method(self.key, cypherkey)
        return BinaPy(plaintext)

    def supported_key_management_algorithms(self) -> List[str]:
        return [
            alg.name
            for alg in self.KEY_MANAGEMENT_ALGORITHMS.values()
            if alg.key_size is None or alg.key_size == self.key_size
        ]

    def supported_encryption_algorithms(self) -> List[str]:
        return [
            alg.name
            for alg in self.ENCRYPTION_ALGORITHMS.values()
            if alg.key_size is None or alg.key_size == self.key_size
        ]
