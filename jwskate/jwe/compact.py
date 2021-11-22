from typing import Any, Dict, Optional, Union

from binapy import BinaPy

from jwskate.jwk.alg import KeyManagementAlg, get_alg
from jwskate.jwk.base import Jwk
from jwskate.jwk.symetric import SymmetricJwk
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
                "A JWE must contain a header, an encrypted key, an IV, a cyphertext and an authentication tag, separated by dots"
            )

        header, key, iv, cyphertext, auth_tag = self.value.split(b".")
        try:
            self.headers = BinaPy(header).decode_from("b64u").parse_from("json")
            self.additional_authenticated_data = header
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.content_encryption_key = BinaPy(key).decode_from("b64u")
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
            self.cyphertext = BinaPy(cyphertext).decode_from("b64u")
        except ValueError:
            raise InvalidJwe(
                "Invalid JWE cyphertext: it must be a Base64URL-encoded binary data (bytes)"
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
        cyphertext: bytes,
        tag: bytes,
    ) -> "JweCompact":
        return cls(
            b".".join(
                (
                    BinaPy.serialize_to("json", headers).encode_to("b64u"),
                    BinaPy(cek).encode_to("b64u"),
                    BinaPy(iv).encode_to("b64u"),
                    BinaPy(cyphertext).encode_to("b64u"),
                    BinaPy(tag).encode_to("b64u"),
                )
            )
        )

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
    ) -> "JweCompact":
        jwk = Jwk(jwk)

        keyalg = get_alg(jwk.alg, alg, jwk.KEY_MANAGEMENT_ALGORITHMS)

        if cek is None:
            cek_jwk = SymmetricJwk.generate_for_alg(enc)
        else:
            cek_jwk = SymmetricJwk.from_bytes(cek, alg=enc)

        enc_cek = jwk.wrap_key(cek_jwk.key, keyalg.name)

        headers = dict(extra_headers or {}, alg=alg, enc=enc)
        aad = BinaPy.serialize_to("json", headers).encode_to("b64u")

        cyphertext, tag, iv = cek_jwk.encrypt(
            plaintext=plaintext, aad=aad, iv=iv, alg=enc
        )

        return cls.from_parts(headers, enc_cek, iv, cyphertext, tag)

    def decrypt(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        enc: str,
        alg: Optional[str] = None,
    ) -> bytes:
        """
        Decrypts this Jwe using a Jwk
        :param jwk: the Jwk to use to decrypt this Jwe
        :param alg: the Key Management Algorithm to use to decrypt this Jwe
        :param enc: the Content Encryption Algorithm to use to decrypt this Jwe
        :return: the decrypted payload
        """
        jwk = Jwk(jwk)

        keyalg = get_alg(jwk.alg, alg, jwk.KEY_MANAGEMENT_ALGORITHMS)

        raw_cek = jwk.unwrap_key(self.content_encryption_key, keyalg.name)
        cek = SymmetricJwk.from_bytes(raw_cek)

        plaintext = cek.decrypt(
            cyphertext=self.cyphertext,
            iv=self.initialization_vector,
            tag=self.authentication_tag,
            aad=self.additional_authenticated_data,
            alg=enc,
        )
        return plaintext
