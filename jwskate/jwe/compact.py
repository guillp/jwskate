import warnings
from typing import Any, Dict, Mapping, Optional, Type, Union

from binapy import BinaPy

from jwskate.jwa import (
    Pbes2,
    Pbes2_HS256_A128KW,
    Pbes2_HS384_A192KW,
    Pbes2_HS512_A256KW,
)
from jwskate.jwk import Jwk, SymmetricJwk
from jwskate.token import BaseToken


class InvalidJwe(ValueError):
    """Raised when an invalid Jwe is parsed"""


class JweCompact(BaseToken):
    """
    Represents a Json Web Encryption object, as defined in RFC7516
    """

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes a Jwe based on its compact representation.
        :param value: the compact representation for this Jwe
        """
        super().__init__(value)

        if self.value.count(b".") != 4:
            raise InvalidJwe(
                "A JWE must contain a header, an encrypted key, an IV, a ciphertext and an authentication tag, separated by dots"
            )

        header, cek, iv, ciphertext, auth_tag = self.value.split(b".")
        try:
            self.headers = BinaPy(header).decode_from("b64u").parse_from("json")
            self.additional_authenticated_data = header
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.wrapped_cek = BinaPy(cek).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE cek: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.initialization_vector = BinaPy(iv).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE iv: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.ciphertext = BinaPy(ciphertext).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE ciphertext: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.authentication_tag = BinaPy(auth_tag).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE authentication tag: it must be a Base64URL-encoded binary data (bytes)"
            )

    @classmethod
    def from_parts(
        cls,
        headers: Dict[str, Any],
        cek: bytes,
        iv: bytes,
        ciphertext: bytes,
        tag: bytes,
    ) -> "JweCompact":
        return cls(
            b".".join(
                (
                    BinaPy.serialize_to("json", headers).encode_to("b64u"),
                    BinaPy(cek).encode_to("b64u"),
                    BinaPy(iv).encode_to("b64u"),
                    BinaPy(ciphertext).encode_to("b64u"),
                    BinaPy(tag).encode_to("b64u"),
                )
            )
        )

    @property
    def alg(self) -> str:
        alg = self.get_header("alg")
        if alg is None or not isinstance(alg, str):
            raise KeyError("This JWE doesn't have a valid 'alg' header")
        return alg

    @property
    def enc(self) -> str:
        enc = self.get_header("enc")
        if enc is None or not isinstance(enc, str):
            raise KeyError("This JWE doesn't have a valid 'enc' header")
        return enc

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        enc: str,
        alg: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
        cek: Optional[bytes] = None,
        iv: Optional[bytes] = None,
        epk: Optional[Jwk] = None,
    ) -> "JweCompact":
        jwk = Jwk(jwk)
        extra_headers = extra_headers or {}
        cek_jwk, cek_headers, wrapped_cek = jwk.sender_key(
            enc=enc, alg=alg, cek=cek, epk=epk, **extra_headers
        )

        headers = dict(extra_headers, **cek_headers, alg=alg, enc=enc)
        aad = BinaPy.serialize_to("json", headers).encode_to("b64u")

        ciphertext, tag, iv = cek_jwk.encrypt(
            plaintext=plaintext, aad=aad, iv=iv, alg=enc
        )

        return cls.from_parts(headers, wrapped_cek, iv, ciphertext, tag)

    PBES2_ALGORITHMS: Mapping[str, Type[Pbes2]] = {
        alg.name: alg
        for alg in [Pbes2_HS256_A128KW, Pbes2_HS384_A192KW, Pbes2_HS512_A256KW]
    }

    def unwrap_cek(
        self, jwk_or_password: Union[Jwk, Dict[str, Any], bytes, str]
    ) -> Jwk:
        if isinstance(jwk_or_password, (bytes, str)):
            password = jwk_or_password
            return self.unwrap_cek_with_password(password)

        jwk = Jwk(jwk_or_password)
        cek = jwk.recipient_key(self.wrapped_cek, **self.headers)
        return cek

    def decrypt(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
    ) -> bytes:
        """
        Decrypts this Jwe using a Jwk
        :param jwk: the Jwk to use to decrypt this Jwe
        :return: the decrypted payload
        """
        cek_jwk = self.unwrap_cek(jwk)

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
        plaintext: bytes,
        password: Union[bytes, str],
        alg: str,
        enc: str,
        salt: Optional[bytes] = None,
        count: int = 2000,
        cek: Optional[bytes] = None,
        iv: Optional[bytes] = None,
    ) -> "JweCompact":
        keyalg = cls.PBES2_ALGORITHMS.get(alg)
        if keyalg is None:
            raise ValueError(f"Unsupported password-based encryption algorithm '{alg}'")

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
                "PBES2 iteration count must be a positive integer, with a minimum recommended value of 1000"
            )
        if count < 1000:
            warnings.warn("PBES2 iteration count should be > 1000")

        wrapped_cek = wrapper.wrap_key(cek, salt, count)

        headers = dict(
            alg=alg, enc=enc, p2s=BinaPy(salt).encode_to("b64u").decode(), p2c=count
        )
        aad = BinaPy.serialize_to("json", headers).encode_to("b64u")
        ciphertext, tag, iv = cek_jwk.encrypt(
            plaintext=plaintext, aad=aad, alg=enc, iv=iv
        )

        return cls.from_parts(headers, wrapped_cek, iv, ciphertext, tag)

    def unwrap_cek_with_password(self, password: Union[bytes, str]) -> Jwk:
        keyalg = self.PBES2_ALGORITHMS.get(self.alg)
        if keyalg is None:
            raise ValueError(
                f"Unsupported password-based encryption algorithm '{self.alg}'"
            )
        p2s = self.headers.get("p2s")
        if p2s is None:
            raise ValueError("No 'p2s' in headers!")
        salt = BinaPy(p2s).decode_from("b64u")
        p2c = self.headers.get("p2c")
        if p2c is None:
            raise ValueError("No 'p2c' in headers!")
        if not isinstance(p2c, int) or p2c < 1:
            raise ValueError("Invalid value for p2c, must be a positive integer")
        wrapper = keyalg(password)
        cek = wrapper.unwrap_key(self.wrapped_cek, salt, p2c)
        return SymmetricJwk.from_bytes(cek)

    def decrypt_with_password(self, password: Union[bytes, str]) -> bytes:
        cek_jwk = self.unwrap_cek_with_password(password)
        plaintext = cek_jwk.decrypt(
            ciphertext=self.ciphertext,
            iv=self.initialization_vector,
            tag=self.authentication_tag,
            aad=self.additional_authenticated_data,
            alg=self.enc,
        )
        return plaintext
