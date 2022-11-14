"""This module implements JWK representing Symmetric keys."""

from __future__ import annotations

from typing import Any, List, Optional, SupportsBytes, Tuple, Union

from binapy import BinaPy

from jwskate.jwa import (
    A128CBC_HS256,
    A128GCM,
    A128GCMKW,
    A128KW,
    A192CBC_HS384,
    A192GCM,
    A192GCMKW,
    A192KW,
    A256CBC_HS512,
    A256GCM,
    A256GCMKW,
    A256KW,
    HS256,
    HS384,
    HS512,
    BaseAESEncryptionAlg,
    BaseAesKeyWrap,
    BaseHMACSigAlg,
    DirectKeyUse,
)

from .base import Jwk, JwkParameter


class SymmetricJwk(Jwk):
    """Implement Symmetric keys, with `kty=oct`."""

    KTY = "oct"
    CRYPTOGRAPHY_PRIVATE_KEY_CLASSES = (bytes,)
    CRYPTOGRAPHY_PUBLIC_KEY_CLASSES = (bytes,)

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
            A128CBC_HS256,
            A192CBC_HS384,
            A256CBC_HS512,
            A128GCM,
            A192GCM,
            A256GCM,
        ]
    }

    @property
    def is_symmetric(self) -> bool:
        """Always returns `True`."""
        return True

    def public_jwk(self) -> Jwk:
        """This always raises a ValueError since SymmetricKeys are always private.

        Raises:
            ValueError: symmetric keys are always private, it makes no sense to use them as public keys
        """
        raise ValueError("Symmetric keys don't have a public key")

    @classmethod
    def from_bytes(cls, k: Union[bytes, str], **params: Any) -> SymmetricJwk:
        """Initialize a `SymmetricJwk` from a raw secret key.

        The provided secret key is encoded and used as the `k` parameter for the returned SymmetricKey.

        Args:
          k: the key to use
          **params: additional members to include in the Jwk

        Returns:
          the resulting SymmetricJwk
        """
        return cls(dict(kty="oct", k=BinaPy(k).to("b64u").ascii(), **params))

    @classmethod
    def from_cryptography_key(
        cls, cryptography_key: Any, **params: Any
    ) -> SymmetricJwk:
        """Alias for `from_bytes()` since symmetric keys are simply bytes.

        Args:
            cryptography_key: the key to use
            **kwargs: additional members to include in the Jwk

        Returns:
            the resulting SymmetricJwk
        """
        return cls.from_bytes(cryptography_key, **params)

    @classmethod
    def generate(cls, key_size: int = 128, **params: Any) -> SymmetricJwk:
        """Generate a random SymmetricJwk, with a given key size.

        Args:
          key_size: size of the generated key, in bits
          **params: additional members to include in the Jwk

        Returns:
            a SymmetricJwk with a randomly generated key
        """
        key = BinaPy.random_bits(key_size)
        return cls.from_bytes(key, **params)

    @classmethod
    def generate_for_alg(cls, alg: str, **params: Any) -> SymmetricJwk:
        """Generate a SymmetricJwk that is suitable for use with the given alg.

        Args:
          alg: the algorithm identifier
          **params: additional members to include in the Jwk

        Returns:
            the generated `Jwk`

        Raises:
            UnsupportedAlg: if the provided `alg` is not supported
        """
        alg_class = cls._get_alg_class(alg)
        if issubclass(alg_class, BaseHMACSigAlg):
            return cls.generate(key_size=alg_class.min_key_size, alg=alg, **params)
        elif issubclass(alg_class, (BaseAESEncryptionAlg, BaseAesKeyWrap)):
            return cls.generate(key_size=alg_class.key_size, alg=alg, **params)
        return cls.generate(alg=alg, **params)

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
        plaintext: Union[bytes, SupportsBytes],
        *,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
        iv: Optional[bytes] = None,
    ) -> Tuple[BinaPy, BinaPy, BinaPy]:
        """Encrypt arbitrary data using this key.

        Supports Authenticated Encryption with Additional Authenticated Data (`aad`).
        An Initialization Vector (IV) will be generated automatically. You can choose your own IV by providing the `iv` parameter (only use this if you know what you are doing).

        This returns the ciphertext, the authentication tag, and the used IV (if an IV was provided as parameter, the same IV is returned).

        Args:
          plaintext: the plaintext to encrypt
          aad: the Additional Authentication Data, if any
          alg: the encryption alg to use
          iv: the IV to use, if you want a specific value

        Returns:
            a (ciphertext, authentication_tag, iv) tuple
        """
        wrapper = self.encryption_wrapper(alg)
        if iv is None:
            iv = wrapper.generate_iv()

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
        ciphertext: Union[bytes, SupportsBytes],
        *,
        iv: Union[bytes, SupportsBytes],
        tag: Union[bytes, SupportsBytes],
        aad: Union[bytes, SupportsBytes, None] = None,
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
        aad = b"" if aad is None else aad
        if not isinstance(aad, bytes):
            aad = bytes(aad)
        if not isinstance(iv, bytes):
            iv = bytes(iv)
        if not isinstance(tag, bytes):
            tag = bytes(tag)

        wrapper = self.encryption_wrapper(alg)
        plaintext: bytes = wrapper.decrypt(ciphertext, auth_tag=tag, iv=iv, aad=aad)

        return BinaPy(plaintext)

    def supported_key_management_algorithms(self) -> List[str]:
        """Return the list of Key Management algorithms that this key supports.

        Key Management algorithms are used to generate or wrap Content Encryption Keys (CEK).

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

    def to_pem(self, password: Union[bytes, str, None] = None) -> bytes:
        """Serialize this key to PEM format.

        Symmetric keys are not serializable to PEM so this will raise a TypeError.

        Args:
          password: password to use to encrypt the PEM.

        Raises:
            TypeError: always
        """
        raise TypeError("Symmetric keys are not serializable to PEM.")
