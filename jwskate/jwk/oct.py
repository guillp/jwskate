"""This module implements JWK representing Symmetric keys."""
from __future__ import annotations

import warnings
from typing import Any, SupportsBytes

from binapy import BinaPy
from typing_extensions import override

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
    BaseAesKeyWrap,
    BaseHMACSigAlg,
    BaseSymmetricAlg,
    DirectKeyUse,
)

from .. import BaseAESEncryptionAlg, KeyTypes
from .base import Jwk, JwkParameter


class SymmetricJwk(Jwk):
    """Represent a Symmetric key in JWK format.

    Symmetric keys have key type `"oct"`.

    """

    KTY = KeyTypes.OCT
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
    @override
    def is_symmetric(self) -> bool:
        return True

    @override
    def public_jwk(self) -> Jwk:
        """Raise an error since Symmetric Keys are always private.

        Raises:
            ValueError: symmetric keys are always private, it makes no sense to use them as public keys

        """
        raise ValueError("Symmetric keys don't have a public key")

    @classmethod
    def from_bytes(cls, k: bytes | str, **params: Any) -> SymmetricJwk:
        """Initialize a `SymmetricJwk` from a raw secret key.

        The provided secret key is encoded and used as the `k` parameter for the returned `SymmetricKey`.

        Args:
          k: the key to use
          **params: additional members to include in the `Jwk`

        Returns:
          the resulting `SymmetricJwk`

        """
        return cls(dict(kty=cls.KTY, k=BinaPy(k).to("b64u").ascii(), **params))

    @classmethod
    @override
    def generate(
        cls, *, alg: str | None = None, key_size: int | None = None, **params: Any
    ) -> SymmetricJwk:
        if alg:
            alg_class = cls._get_alg_class(alg)
            # special cases for AES or HMAC based algs which require a specific key size
            if issubclass(alg_class, (BaseAESEncryptionAlg, BaseAesKeyWrap)):
                if key_size is not None and key_size != alg_class.key_size:
                    raise ValueError(
                        f"Key for {alg} must be exactly {alg_class.key_size} bits. "
                        "You should remove the `key_size` parameter to generate a key of the appropriate length."
                    )
                key_size = alg_class.key_size
            elif issubclass(alg_class, BaseHMACSigAlg):
                if key_size is not None and key_size < alg_class.min_key_size:
                    warnings.warn(
                        f"Symmetric keys to use with {alg} should be at least {alg_class.min_key_size} bits "
                        "in order to make the key at least as hard to brute-force as the signature. "
                        f"You requested a key size of {key_size} bits."
                    )
                else:
                    key_size = alg_class.min_key_size

        if key_size is None:
            warnings.warn(
                "Please provide a key_size or an alg parameter for jwskate to know the number of bits to generate. "
                "Defaulting to 128 bits."
            )
            key_size = 128

        key = BinaPy.random_bits(key_size)
        return cls.from_bytes(key, alg=alg, **params)

    @classmethod
    @override
    def from_cryptography_key(
        cls, cryptography_key: Any, **params: Any
    ) -> SymmetricJwk:
        return cls.from_bytes(cryptography_key, **params)

    @override
    def _to_cryptography_key(self) -> BinaPy:
        return BinaPy(self.k).decode_from("b64u")

    @override
    def thumbprint(self, hashalg: str = "SHA256") -> str:
        return (
            BinaPy.serialize_to("json", {"k": self.k, "kty": self.kty})
            .to("sha256")
            .to("b64u")
            .ascii()
        )

    @override
    def to_pem(self, password: bytes | str | None = None) -> str:
        raise TypeError("Symmetric keys are not serializable to PEM.")

    @property
    def key(self) -> BinaPy:
        """Returns the raw symmetric key, from the `k` parameter, base64u-decoded."""
        return self.cryptography_key  # type: ignore[no-any-return]

    @property
    def key_size(self) -> int:
        """The key size, in bits."""
        return len(self.key) * 8

    @override
    def encrypt(
        self,
        plaintext: bytes | SupportsBytes,
        *,
        aad: bytes | None = None,
        alg: str | None = None,
        iv: bytes | None = None,
    ) -> tuple[BinaPy, BinaPy, BinaPy]:
        """Encrypt arbitrary data using this key.

        Supports Authenticated Encryption with Additional Authenticated Data (use parameter `aad` for Additional
        Authenticated Data).

        An *Initialization Vector* (IV) will be generated automatically.
        You can choose your own IV by providing the `iv` parameter (only use this if you know what you are doing).

        This returns the ciphertext, the authentication tag, and the generated IV.
        If an IV was provided as parameter, the same IV is returned.

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

    @override
    def decrypt(
        self,
        ciphertext: bytes | SupportsBytes,
        *,
        iv: bytes | SupportsBytes,
        tag: bytes | SupportsBytes,
        aad: bytes | SupportsBytes | None = None,
        alg: str | None = None,
    ) -> BinaPy:
        """Decrypt arbitrary data, and verify Additional Authenticated Data.

        Args:
          ciphertext: the encrypted data
          iv: the Initialization Vector (must be the same as generated during encryption)
          tag: the authentication tag
          aad: the Additional Authenticated Data (must be the same data used during encryption)
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

    @override
    def supported_key_management_algorithms(self) -> list[str]:
        return [
            name
            for name, alg in self.KEY_MANAGEMENT_ALGORITHMS.items()
            if issubclass(alg, BaseSymmetricAlg)
            and alg.supports_key(self.cryptography_key)
        ]

    @override
    def supported_encryption_algorithms(self) -> list[str]:
        return [
            name
            for name, alg in self.ENCRYPTION_ALGORITHMS.items()
            if alg.supports_key(self.cryptography_key)
        ]
