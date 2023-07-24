"""This module implements the JWE Compact format."""
from __future__ import annotations

import warnings
from functools import cached_property
from typing import Any, Iterable, Mapping, SupportsBytes

from binapy import BinaPy

from jwskate.jwa import (
    BasePbes2,
    Pbes2_HS256_A128KW,
    Pbes2_HS384_A192KW,
    Pbes2_HS512_A256KW,
)
from jwskate.jwk import Jwk, SymmetricJwk, to_jwk
from jwskate.jwk.alg import UnsupportedAlg, select_alg_class, select_alg_classes
from jwskate.token import BaseCompactToken


class InvalidJwe(ValueError):
    """Raised when an invalid JWE token is parsed."""


class JweCompact(BaseCompactToken):
    """Represents a Json Web Encryption object, in compact representation, as defined in RFC7516.

    Args:
        value: the compact representation for this Jwe

    """

    def __init__(self, value: bytes | str, max_size: int = 16 * 1024):
        super().__init__(value, max_size)

        if self.value.count(b".") != 4:
            raise InvalidJwe(
                "Invalid JWE: a JWE must contain a header, an encrypted key, an IV, a ciphertext and an authentication tag, separated by dots."
            )

        header, cek, iv, ciphertext, auth_tag = self.value.split(b".")
        try:
            headers = BinaPy(header).decode_from("b64u").parse_from("json")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE header: it must be a Base64URL-encoded JSON object."
            )
        enc = headers.get("enc")
        if enc is None or not isinstance(enc, str):
            raise InvalidJwe(
                "Invalid JWE header: this JWE doesn't have a valid 'enc' header."
            )
        self.headers = headers
        self.additional_authenticated_data = header

        try:
            self.wrapped_cek = BinaPy(cek).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE CEK: it must be a Base64URL-encoded binary data."
            )

        try:
            self.initialization_vector = BinaPy(iv).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE IV: it must be a Base64URL-encoded binary data."
            )

        try:
            self.ciphertext = BinaPy(ciphertext).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE ciphertext: it must be a Base64URL-encoded binary data."
            )

        try:
            self.authentication_tag = BinaPy(auth_tag).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE authentication tag: it must be a Base64URL-encoded binary data."
            )

    @classmethod
    def from_parts(
        cls,
        *,
        headers: Mapping[str, Any],
        cek: bytes,
        iv: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> JweCompact:
        """Initialize a `JweCompact` from its different parts (header, cek, iv, ciphertext, tag).

        Args:
          headers: the headers (as a mapping of name: value)
          cek: the raw CEK
          iv: the raw IV
          ciphertext: the raw ciphertext
          tag: the authentication tag

        Returns:
            the initialized `JweCompact` instance

        """
        return cls(
            b".".join(
                (
                    BinaPy.serialize_to("json", headers).to("b64u"),
                    BinaPy(cek).to("b64u"),
                    BinaPy(iv).to("b64u"),
                    BinaPy(ciphertext).to("b64u"),
                    BinaPy(tag).to("b64u"),
                )
            )
        )

    @cached_property
    def enc(self) -> str:
        """Return the `enc` from the JWE header.

        The `enc` header contains the identifier of the CEK encryption algorithm.

        Returns:
            the enc value

        Raises:
            AttributeError: if there is no enc header or it is not a string

        """
        return self.get_header("enc")  # type: ignore[no-any-return]
        # header has been checked at init time

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes | SupportsBytes,
        key: Jwk | dict[str, Any] | Any,
        *,
        enc: str,
        alg: str | None = None,
        extra_headers: dict[str, Any] | None = None,
        cek: bytes | None = None,
        iv: bytes | None = None,
        epk: Jwk | None = None,
    ) -> JweCompact:
        """Encrypt an arbitrary plaintext into a `JweCompact`.

        Args:
          plaintext: the raw plaintext to encrypt
          key: the public or symmetric key to use for encryption
          enc: the encryption algorithm to use
          alg: the Key Management algorithm to use, if there is no 'alg' header defined in the Jwk
          extra_headers: additional headers to include in the generated token
          cek: the CEK to force use, for algorithms relying on a random CEK. Leave `None` to have a safe value generated by `jwskate`.
          iv: the IV to force use. Leave `None` to have a safe value generated by `jwskate`.
          epk: the EPK to force use. Leave `None` to have a safe value generated by `jwskate`.

        Returns:
            the generated JweCompact instance

        """
        extra_headers = extra_headers or {}
        key = to_jwk(key)
        alg = select_alg_class(
            key.KEY_MANAGEMENT_ALGORITHMS, jwk_alg=key.alg, alg=alg
        ).name

        cek_jwk, wrapped_cek, cek_headers = key.sender_key(
            enc=enc, alg=alg, cek=cek, epk=epk, **extra_headers
        )

        headers = dict(extra_headers, **cek_headers, alg=alg, enc=enc)
        if key.kid is not None:
            headers["kid"] = key.kid

        aad = BinaPy.serialize_to("json", headers).to("b64u")

        ciphertext, iv, tag = cek_jwk.encrypt(plaintext, aad=aad, iv=iv, alg=enc)

        return cls.from_parts(
            headers=headers, cek=wrapped_cek, iv=iv, ciphertext=ciphertext, tag=tag
        )

    PBES2_ALGORITHMS: Mapping[str, type[BasePbes2]] = {
        alg.name: alg
        for alg in [Pbes2_HS256_A128KW, Pbes2_HS384_A192KW, Pbes2_HS512_A256KW]
    }

    def unwrap_cek(
        self,
        key_or_password: Jwk | dict[str, Any] | bytes | str,
        alg: str | None = None,
        algs: Iterable[str] | None = None,
    ) -> Jwk:
        """Unwrap the CEK from this `Jwe` using the provided key or password.

        Args:
          key_or_password: the decryption JWK or password
          alg: allowed key management algorithm, if there is only 1
          algs: allowed key managements algorithms, if there are several

        Returns:
            the unwrapped CEK, as a SymmetricJwk

        """
        if isinstance(key_or_password, (bytes, str)):
            password = key_or_password
            return self.unwrap_cek_with_password(password)

        jwk = to_jwk(key_or_password)
        select_alg_classes(
            jwk.KEY_MANAGEMENT_ALGORITHMS,
            jwk_alg=self.alg,
            alg=alg,
            algs=algs,
            strict=True,
        )
        cek = jwk.recipient_key(self.wrapped_cek, **self.headers)
        return cek

    def decrypt(
        self,
        key: Jwk | dict[str, Any] | Any,
        alg: str | None = None,
        algs: Iterable[str] | None = None,
    ) -> BinaPy:
        """Decrypts this `Jwe` payload using a `Jwk`.

        Args:
          key: the decryption key
          alg: allowed key management algorithm, if there is only 1
          algs: allowed keys management algorithms, if there are several

        Returns:
          the decrypted payload

        """
        cek_jwk = self.unwrap_cek(key, alg=alg, algs=algs)

        plaintext = cek_jwk.decrypt(
            ciphertext=self.ciphertext,
            iv=self.initialization_vector,
            tag=self.authentication_tag,
            aad=self.additional_authenticated_data,
            alg=self.enc,
        )
        return plaintext

    @classmethod
    def encrypt_with_password(
        cls,
        plaintext: SupportsBytes | bytes,
        password: SupportsBytes | bytes | str,
        *,
        alg: str,
        enc: str,
        salt: bytes | None = None,
        count: int = 2000,
        cek: bytes | None = None,
        iv: bytes | None = None,
    ) -> JweCompact:
        """Encrypt a payload with a password and return the resulting JweCompact.

        This performs symmetric encryption using PBES2.

        Args:
          plaintext: the data to encrypt
          password: the password to use
          alg: the Key Management alg to use
          enc: the Payload Encryption alg to use
          salt: the salt to use. Leave `None` (default) to have `jwskate` generate a safe random value
          count: the number of PBES2 iterations (recommended minimum 1000)
          cek: the CEK to force use. Leave `None` (default) to have `jwskate` generate a safe random value
          iv: the IV to force use. Leave `None` (default) to have `jwskate` generate a safe random value

        Returns:
            the resulting JweCompact

        Raises:
            UnsupportedAlg: if the key management alg is not supported
            ValueError: if the `count` parameter is not a positive integer

        """
        keyalg = cls.PBES2_ALGORITHMS.get(alg)
        if keyalg is None:
            raise UnsupportedAlg(
                f"Unsupported password-based encryption algorithm '{alg}'. "
                f"Value must be one of {list(cls.PBES2_ALGORITHMS.keys())}."
            )

        if cek is None:
            cek_jwk = SymmetricJwk.generate_for_alg(enc)
            cek = cek_jwk.key
        else:
            cek_jwk = SymmetricJwk.from_bytes(cek)

        wrapper = keyalg(password)
        if salt is None:
            salt = wrapper.generate_salt()

        if count < 1:
            raise ValueError(
                "PBES2 iteration count must be a positive integer, with a minimum recommended value of 1000."
            )
        if count < 1000:
            warnings.warn("PBES2 iteration count should be > 1000.")

        wrapped_cek = wrapper.wrap_key(cek, salt=salt, count=count)

        headers = dict(alg=alg, enc=enc, p2s=BinaPy(salt).to("b64u").ascii(), p2c=count)
        aad = BinaPy.serialize_to("json", headers).to("b64u")
        ciphertext, iv, tag = cek_jwk.encrypt(
            plaintext=plaintext, aad=aad, alg=enc, iv=iv
        )

        return cls.from_parts(
            headers=headers, cek=wrapped_cek, iv=iv, ciphertext=ciphertext, tag=tag
        )

    def unwrap_cek_with_password(self, password: bytes | str) -> Jwk:
        """Unwrap a CEK using a password. Works only for password-encrypted JWE Tokens.

        Args:
          password: the decryption password

        Returns:
            the CEK, as a SymmetricJwk instance

        Raises:
            UnsupportedAlg: if the token key management algorithm is not supported
            AttributeError: if the token misses the PBES2-related headers

        """
        keyalg = self.PBES2_ALGORITHMS.get(self.alg)
        if keyalg is None:
            raise UnsupportedAlg(
                f"Unsupported password-based encryption algorithm '{self.alg}'. "
                f"Value must be one of {list(self.PBES2_ALGORITHMS.keys())}."
            )
        p2s = self.headers.get("p2s")
        if p2s is None:
            raise InvalidJwe("Invalid JWE: a required 'p2s' header is missing.")
        salt = BinaPy(p2s).decode_from("b64u")
        p2c = self.headers.get("p2c")
        if p2c is None:
            raise InvalidJwe("Invalid JWE: a required 'p2c' header is missing.")
        if not isinstance(p2c, int) or p2c < 1:
            raise InvalidJwe(
                "Invalid JWE: invalid value for the 'p2c' header, must be a positive integer."
            )
        wrapper = keyalg(password)
        cek = wrapper.unwrap_key(self.wrapped_cek, salt=salt, count=p2c)
        return SymmetricJwk.from_bytes(cek)

    def decrypt_with_password(self, password: bytes | str) -> bytes:
        """Decrypt this JWE with a password.

        This only works for tokens encrypted with a password.

        Args:
          password: the password to use

        Returns:
            the unencrypted payload

        """
        cek_jwk = self.unwrap_cek_with_password(password)
        plaintext = cek_jwk.decrypt(
            ciphertext=self.ciphertext,
            iv=self.initialization_vector,
            tag=self.authentication_tag,
            aad=self.additional_authenticated_data,
            alg=self.enc,
        )
        return plaintext
