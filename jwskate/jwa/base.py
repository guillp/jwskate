"""This module implement base classes used by Signature, Encryption and Key Management JWA algorithms."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generic, Iterator, SupportsBytes, Tuple, Type, TypeVar, Union

import cryptography.exceptions
from binapy import BinaPy


class PrivateKeyRequired(AttributeError):
    """Raised when a cryptographic operation requires a private key, and a public key has been provided instead."""


class PublicKeyRequired(AttributeError):
    """Raised when a cryptographic operation requires a public key, and a private key has been provided instead."""


class BaseAlg:
    """Base class for all algorithms.

    An algorithm has a `name` and a `description`, whose reference is found in [IANA JOSE registry][IANA].

    [IANA]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    """

    use: str
    """Alg use ('sig' or 'enc')"""

    name: str
    """Technical name of the algorithm"""
    description: str
    """Description of the algorithm (human readable)"""
    read_only: bool = False
    """For algs that are considered insecure, set to True to allow only signature verification
       or decryption of existing data, but don't allow new signatures or encryption."""

    def __repr__(self) -> str:
        """Use the name of the alg as repr."""
        return self.name


class BaseSymmetricAlg(BaseAlg):
    """Base class for Symmetric algorithms (using a raw bytes key).

    Args:
        key: the key to use for cryptographic operations
    """

    def __init__(self, key: bytes):
        self.check_key(key)
        self.key = key

    @classmethod
    def check_key(cls, key: bytes) -> None:
        """Check that a given key is suitable for this alg class.

        This raises an exception if the key is not suitable.
        This method must be implemented by subclasses as required.

        Args:
          key: the key to check for this alg class

        Returns:
          Returns `None`. Raises an exception if the key is not suitable
        """
        pass

    @classmethod
    def supports_key(cls, key: bytes) -> bool:
        """Return `True` if the given key is suitable for this alg class, or `False` otherwise.

        This is a convenience wrapper around `check_key(key)`.

        Args:
          key: the key to check for this alg class

        Returns:
          `True` if the key is suitable for this alg class, `False` otherwise
        """
        try:
            cls.check_key(key)
            return True
        except Exception:
            return False


Kpriv = TypeVar("Kpriv")
Kpub = TypeVar("Kpub")


class BaseAsymmetricAlg(Generic[Kpriv, Kpub], BaseAlg):
    """Base class for asymmetric algorithms. Those can be initialised with a private or public key.

    The available cryptographic operations will depend on the alg and
    the provided key type.

    Args:
        key: the key to use.
    """

    private_key_class: Union[Type[Kpriv], Tuple[Type[Kpriv], ...]]
    public_key_class: Union[Type[Kpub], Tuple[Type[Kpub], ...]]

    def __init__(self, key: Union[Kpriv, Kpub]):
        self.check_key(key)
        self.key = key

    @classmethod
    def check_key(cls, key: Union[Kpriv, Kpub]) -> None:
        """Check that a given key is suitable for this alg class.

        This must be implemented by subclasses as required.

        Args:
          key: the key to use.

        Returns:
          Returns None. Raises an exception if the key is not suitable.

        Raises:
            Exception: if the key is not suitable for use with this alg class
        """

    @contextmanager
    def private_key_required(self) -> Iterator[Kpriv]:
        """A context manager that checks if this alg is initialised with a private key.

        Yields:
            the private key

        Raises:
            PrivateKeyRequired: if the configured key is not private
        """
        if not isinstance(self.key, self.private_key_class):
            raise PrivateKeyRequired()
        yield self.key  # type: ignore

    @contextmanager
    def public_key_required(self) -> Iterator[Kpub]:
        """A context manager that checks if this alg is initialised with a public key.

        Yields:
            The public key

        Raises:
            PublicKeyRequired: if the configured key is private
        """
        if not isinstance(self.key, self.public_key_class):
            raise PublicKeyRequired()
        yield self.key  # type: ignore


class BaseSignatureAlg(BaseAlg):
    """Base class for signature algorithms."""

    use = "sig"

    def sign(self, data: Union[bytes, SupportsBytes]) -> BinaPy:
        """Sign arbitrary data, return the signature.

        Args:
          data: raw data to sign

        Returns:
          the raw signature
        """
        raise NotImplementedError

    def verify(
        self, data: Union[bytes, SupportsBytes], signature: Union[bytes, SupportsBytes]
    ) -> bool:
        """Verify a signature against some data.

        Args:
          data: the raw data to verify
          signature: the raw signature

        Returns:
          `True` if the signature matches, `False` otherwise.
        """
        raise NotImplementedError


class BaseAESEncryptionAlg(BaseSymmetricAlg):
    """Base class for AES encryption algorithms."""

    use = "enc"

    key_size: int
    tag_size: int
    iv_size: int

    @classmethod
    def check_key(cls, key: bytes) -> None:
        """Check that a key is suitable for this algorithm.

        Args:
          key: the key to check

        Raises:
            ValueError: if the key is not suitable
        """
        if len(key) * 8 != cls.key_size:
            raise ValueError(
                f"This key size of {len(key) * 8} bits doesn't match the expected key size of {cls.key_size} bits"
            )

    @classmethod
    def generate_key(cls) -> BinaPy:
        """Generate a key of an appropriate size for this AES alg subclass.

        Returns:
            a random AES key
        """
        return BinaPy.random_bits(cls.key_size)

    @classmethod
    def generate_iv(cls) -> BinaPy:
        """Generate an Initialisation Vector of the appropriate size.

        Returns:
            a random IV
        """
        return BinaPy.random_bits(cls.iv_size)

    def encrypt(
        self,
        plaintext: Union[bytes, SupportsBytes],
        *,
        iv: Union[bytes, SupportsBytes],
        aad: Union[bytes, SupportsBytes, None] = None,
    ) -> Tuple[BinaPy, BinaPy]:
        """Encrypt arbitrary data, with [Authenticated Encryption (with optional Associated Data)][AEAD].

        This needs:
        - the raw data to encrypt (`plaintext`)
        - a given random Initialisation Vector (`iv`) of the appropriate size
        - optional Additional Authentication Data (`aad`)
        And returns a tuple (ciphered_data, authentication_tag).

        Args:
          plaintext: the data to encrypt
          iv: the Initialisation Vector to use
          aad: the Additional Authentication Data

        Returns:
          a tuple of ciphered data and authentication tag

        [AEAD]: https://wikipedia.org/wiki/Authenticated_encryption
        """
        raise NotImplementedError

    def decrypt(
        self,
        ciphertext: Union[bytes, SupportsBytes],
        *,
        iv: Union[bytes, SupportsBytes],
        auth_tag: Union[bytes, SupportsBytes],
        aad: Union[bytes, SupportsBytes, None] = None,
    ) -> BinaPy:
        """Decrypt and verify a ciphertext with Authenticated Encryption.

        This needs:
        - the raw encrypted Data (`ciphertext`) and Authentication Tag (`auth_tag`) that were produced by encryption,
        - the same Initialisation Vector (`iv`) and optional Additional Authentication Data that were provided for encryption.
        and returns the resulting clear text data.

        Args:
          ciphertext: the data to decrypt
          iv: the Initialisation Vector to use. Must be the same one used during encryption
          auth_tag: the authentication tag
          aad: the Additional Authentication Data. Must be the same one used during encryption

        Returns:
          the deciphered data
        """
        raise NotImplementedError

    @classmethod
    def init_random_key(cls) -> BaseAESEncryptionAlg:
        """Initialize this alg with a random key.

        Returns:
            a subclass of BaseAESEncryptionAlg initialized with a randomly generated key
        """
        return cls(cls.generate_key())


class BaseKeyManagementAlg(BaseAlg):
    """Base class for Key Management algorithms."""

    use = "enc"


class MismatchingAuthTag(cryptography.exceptions.InvalidTag):
    """Raised when trying to decrypt with an Authentication Tag that doesn't match the expected value."""
