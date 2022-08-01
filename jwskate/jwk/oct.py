"""This module implements JWK representing Symmetric keys."""

from __future__ import annotations

from typing import Any, List, Optional, Tuple, Union

from binapy import BinaPy

from jwskate.jwa import (
    A128GCM,
    A128GCMKW,
    A128KW,
    A192GCM,
    A192GCMKW,
    A192KW,
    A256GCM,
    A256GCMKW,
    A256KW,
    HS256,
    HS384,
    HS512,
    Aes128CbcHmacSha256,
    Aes192CbcHmacSha384,
    Aes256CbcHmacSha512,
    BaseAESEncryptionAlg,
    DirectKeyUse,
)

from .alg import select_alg
from .base import Jwk, JwkParameter


class SymmetricJwk(Jwk):
    """Implement Symetric keys, with `kty=oct`."""

    KTY = "oct"
    CRYPTOGRAPHY_KEY_CLASSES = (bytes,)

    PARAMS = {
        "k": JwkParameter("Key Value", is_private=True, is_required=True, kind="b64u"),
    }

    SIGNATURE_ALGORITHMS = {sigalg.name: sigalg for sigalg in [HS256, HS384, HS512]}

    KEY_MANAGEMENT_ALGORITHMS = {
        keyalg.name: keyalg
        for keyalg in [
            A128KW,
            A192KW,
            A256KW,
            A128GCMKW,
            A192GCMKW,
            A256GCMKW,
            DirectKeyUse,
        ]
    }

    ENCRYPTION_ALGORITHMS = {
        keyalg.name: keyalg
        for keyalg in [
            Aes128CbcHmacSha256,
            Aes192CbcHmacSha384,
            Aes256CbcHmacSha512,
            A128GCM,
            A192GCM,
            A256GCM,
        ]
    }

    def public_jwk(self) -> Jwk:
        """This always raises a ValueError since SymmetricKeys are always private.

        Raises:
            ValueError: symmetric keys are always private, it makes no sense to use them as public keys
        """
        raise ValueError("Symmetric keys don't have a public key")

    @classmethod
    def from_bytes(cls, k: Union[bytes, str], **params: Any) -> SymmetricJwk:
        """Initializes a SymmetricJwk from a raw secret key. The provided secret key is encoded and used as the `k` parameter for the returned SymetricKey.

        Args:
          k: the key to use
          **params: additional members to include in the Jwk

        Returns:
          the resulting SymmetricJwk
        """
        return cls(dict(kty="oct", k=BinaPy(k).to("b64u").ascii(), **params))

    @classmethod
    def from_cryptography_key(
        cls, cryptography_key: Any, **kwargs: Any
    ) -> SymmetricJwk:
        """Alias for `from_bytes()` since symmetric keys are simply bytes.

        Args:
            cryptography_key: the key to use
            **kwargs: additional members to include in the Jwk

        Returns:
            the resulting SymmetricJwk
        """
        return cls.from_bytes(cryptography_key, **kwargs)

    @classmethod
    def generate(cls, key_size: int = 128, **params: str) -> SymmetricJwk:
        """Generate a random SymmetricJwk, with a given key size.

        Args:
          key_size: the size of the generated key, in bits
          **params: additional members to include in the Jwk

        Returns:
            a SymmetricJwk with a randomly generated key
        """
        key = BinaPy.random_bits(key_size)
        return cls.from_bytes(key, **params)

    @classmethod
    def generate_for_alg(cls, alg: str, **params: str) -> SymmetricJwk:
        """Generate a SymmetricJwk that is suitable for use with the given alg.

        Args:
          alg: the signing algorithm to use this key with
          **params: additional members to include in the Jwk

        Returns:
            the resulting Jwk

        Raises:
            ValueError: if the provided `alg` is not supported
        """
        if alg in cls.SIGNATURE_ALGORITHMS:
            sigalg = cls.SIGNATURE_ALGORITHMS[alg]
            return cls.generate(sigalg.min_key_size, alg=alg, **params)
        if alg in cls.ENCRYPTION_ALGORITHMS:
            encalg = cls.ENCRYPTION_ALGORITHMS[alg]
            return cls.generate(encalg.key_size, alg=alg, **params)
        raise ValueError("Unsupported alg", alg)

    def thumbprint(self, hashalg: str = "SHA256") -> str:
        """Return the key thumbprint as specified by RFC 7638.

        This is reimplemented for SymmetricJwk because the private parameter 'k' must be included.

        Args:
          hashalg: A hash function (defaults to SHA256)

        Returns:
            the calculated thumbprint
        """
        return (
            BinaPy.serialize_to("json", {"k": self.k, "kty": self.kty})
            .to("sha256")
            .to("b64u")
            .ascii()
        )

    def _to_cryptography_key(self) -> BinaPy:
        """Converts this Jwk into a key usable with `cryptography`.

        For SymmetricJwk instances, those are just `bytes` values.

        Returns:
            the raw private key, as `bytes`
        """
        return BinaPy(self.k).decode_from("b64u")

    @property
    def key(self) -> BinaPy:
        """Returns the raw symmetric key.

        Returns:
             the key from the `k` parameter, base64u-decoded
        """
        return self.cryptography_key  # type: ignore

    def encrypt(
        self,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
        iv: Optional[bytes] = None,
    ) -> Tuple[BinaPy, BinaPy, BinaPy]:
        """Encrypt arbitrary data using this key. Supports Authenticated Encryption with the Additional Authenticated Data (`aad`). An Initializatin Vector (IV) will be generated automatically. You can choose your own IV by providing the `iv` parameter (only use this if you know what you are doing).

        This return the ciphertext, the authentication tag, and the used IV (if an IV was provided as parameter, the same IV is returned).

        Args:
          plaintext: the plaintext to encrypt
          aad: the Additional Authentication Data, if any
          alg: the encryption alg to use
          iv: the IV to use, if you want a specific value

        Returns:
            a (ciphertext, authentication_tag, iv) tuple
        """
        encalg = select_alg(self.alg, alg, self.ENCRYPTION_ALGORITHMS)

        if iv is None:
            iv = encalg.generate_iv()

        wrapper: BaseAESEncryptionAlg = encalg(self.cryptography_key)
        ciphertext, tag = wrapper.encrypt(plaintext, iv=iv, aad=aad)
        return ciphertext, BinaPy(iv), tag

    @property
    def key_size(self) -> int:
        """The key size, in bits.

        Returns:
            the key size in bits
        """
        return len(self.key) * 8

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        iv: bytes,
        tag: bytes,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
    ) -> BinaPy:
        """Decrypt arbitrary data.

        Args:
          ciphertext: the encrypted data
          iv: the Initialization Vector (must be the same as used during encryption)
          tag: the authentication tag
          aad: the Additional Authenticated Data (must be the same as used during encryption)
          alg: the decryption alg (must be the same as used during encryption)

        Returns:
            the decrypted clear-text
        """
        encalg = select_alg(self.alg, alg, self.ENCRYPTION_ALGORITHMS)
        decryptor: BaseAESEncryptionAlg = encalg(self.cryptography_key)
        plaintext: bytes = decryptor.decrypt(ciphertext, auth_tag=tag, iv=iv, aad=aad)

        return BinaPy(plaintext)

    def supported_key_management_algorithms(self) -> List[str]:
        """Return the list of supported Key Management algorithms, usable for key (un)wrapping with this key.

        Returns:
            a list of supported algorithms identifiers
        """
        return [
            name
            for name, alg in self.KEY_MANAGEMENT_ALGORITHMS.items()
            if alg.supports_key(self.cryptography_key)  # type: ignore
        ]

    def supported_encryption_algorithms(self) -> List[str]:
        """Return the list of supported Encryption/Decryption algorithms with this key.

        Returns:
            a list of supported algorithms identifiers
        """
        return [
            name
            for name, alg in self.ENCRYPTION_ALGORITHMS.items()
            if alg.supports_key(self.cryptography_key)
        ]
