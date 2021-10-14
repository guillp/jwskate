from typing import Any, Dict, Optional, Union

from jwskate.jwk.base import Jwk
from jwskate.jwk.symetric import SymmetricJwk
from jwskate.utils import b64u_decode, b64u_decode_json, b64u_encode, b64u_encode_json


class InvalidJwe(ValueError):
    """Raised when an invalid Jwe is parsed"""


class JweCompact:
    """
    Represents a Json Web Encryption object, as defined in RFC7516
    """

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes a Jwe based on its compact representation.
        :param value: the compact representation for this Jwe
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        value = b"".join(value.split())

        if value.count(b".") != 4:
            raise InvalidJwe(
                "A JWE must contain a header, an encrypted key, an IV, a cyphertext and an authentication tag, separated by dots"
            )

        header, key, iv, cyphertext, auth_tag = value.split(b".")
        try:
            self.headers = b64u_decode_json(header)
            self.additional_authenticated_data = header
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.content_encryption_key = b64u_decode(key)
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE cek: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.initialization_vector = b64u_decode(iv)
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE iv: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.cyphertext = b64u_decode(cyphertext)
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE cyphertext: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.authentication_tag = b64u_decode(auth_tag)
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE authentication tag: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    def get_header(self, name: str) -> Any:
        """
        Returns an header from this Jwe
        :param name: the header name
        :return: the header value
        """
        return self.headers.get(name)

    def __str__(self) -> str:
        return self.value.decode()

    def __bytes__(self) -> bytes:
        return self.value

    @classmethod
    def from_parts(
        cls,
        headers: Dict[str, Any],
        cek: bytes,
        iv: bytes,
        cyphertext: bytes,
        tag: bytes,
    ) -> "JweCompact":
        return cls(
            ".".join(
                (
                    b64u_encode_json(headers),
                    b64u_encode(cek),
                    b64u_encode(iv),
                    b64u_encode(cyphertext),
                    b64u_encode(tag),
                )
            )
        )

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        enc: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
        cek: Optional[bytes] = None,
        iv: Optional[bytes] = None,
    ) -> "JweCompact":
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        alg = jwk.alg or alg
        if alg is None:
            raise ValueError("A Key Management Alg is required (in parameter 'alg')")
        enc = jwk.enc or enc
        if enc is None:
            raise ValueError("An Encryption Alg is required (in parameter 'enc')")

        headers = dict(extra_headers or {}, alg=alg, enc=enc)

        if cek is None:
            cek_jwk = SymmetricJwk.generate_for_alg(enc)
        else:
            cek_jwk = SymmetricJwk.from_bytes(cek, alg=enc)

        enc_cek = jwk.encrypt_key(cek_jwk.key, alg)

        aad = b64u_encode_json(headers).encode()

        cyphertext, tag, iv = cek_jwk.encrypt(
            plaintext=plaintext, aad=aad, iv=iv, alg=enc
        )

        return cls.from_parts(headers, enc_cek, iv, cyphertext, tag)

    def decrypt(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        enc: Optional[str] = None,
    ) -> bytes:
        """
        Decrypts this Jwe using a Jwk
        :param jwk: the Jwk to use to decrypt this Jwe
        :param alg: the Key Management Algorithm to use to decrypt this Jwe
        :param enc: the Content Encryption Algorithm to use to decrypt this Jwe
        :return: the decrypted payload
        """
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        alg = jwk.alg or alg
        enc = jwk.enc or enc

        raw_cek = jwk.decrypt_key(self.content_encryption_key, alg)
        cek = SymmetricJwk.from_bytes(raw_cek)

        plaintext = cek.decrypt(
            cyphertext=self.cyphertext,
            iv=self.initialization_vector,
            tag=self.authentication_tag,
            aad=self.additional_authenticated_data,
            alg=enc,
        )
        return plaintext
