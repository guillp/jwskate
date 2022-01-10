from typing import Any, Dict, Optional, Union

from binapy import BinaPy

from jwskate.jwa import DirectKeyUse, KeyDerivationAlg, KeyWrappingAlg
from jwskate.jwk.alg import select_alg
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
            self.content_encryption_key = BinaPy(cek).decode_from("b64u")
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

    @property
    def epk(self) -> Jwk:
        raw_epk = self.headers.get("epk")
        if raw_epk is None:
            raise RuntimeError(
                "CEK unwrapping requires an ephemeral key in header 'epk', which is missing."
            )
        jwk_epk = Jwk(raw_epk)
        if jwk_epk.is_private:
            raise RuntimeError(
                "EPK is supposed to be a public key, but this token contains a private key"
            )
        return jwk_epk

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
        keyalg = select_alg(jwk.alg, alg, jwk.KEY_MANAGEMENT_ALGORITHMS)
        extra_headers = extra_headers or {}

        if issubclass(keyalg, KeyDerivationAlg):
            cek_jwk, cek_headers = jwk.sender_key(keyalg.name, enc, **extra_headers)
            extra_headers.update(cek_headers)
            cek_part = b""
        elif issubclass(keyalg, KeyWrappingAlg):
            if cek is None:
                cek_jwk = SymmetricJwk.generate_for_alg(enc)
            else:
                cek_jwk = SymmetricJwk.from_bytes(cek, alg=enc)

            cek_part = jwk.wrap_key(cek_jwk, alg)
        elif issubclass(keyalg, DirectKeyUse):
            cek_part = b""
            cek_jwk = jwk
        else:
            raise RuntimeError(f"Unsupported Key Management method {keyalg}.")

        headers = dict(extra_headers or {}, alg=alg, enc=enc)
        aad = BinaPy.serialize_to("json", headers).encode_to("b64u")

        ciphertext, tag, iv = cek_jwk.encrypt(
            plaintext=plaintext, aad=aad, iv=iv, alg=enc
        )

        return cls.from_parts(headers, cek_part, iv, ciphertext, tag)

    def unwrap_cek(self, jwk: Union[Jwk, Dict[str, Any]]) -> Jwk:
        jwk = Jwk(jwk)
        keyalg = select_alg(None, self.alg, jwk.KEY_MANAGEMENT_ALGORITHMS)
        if issubclass(keyalg, KeyWrappingAlg):
            cek = jwk.unwrap_key(self.content_encryption_key, self.alg)
        elif issubclass(keyalg, KeyDerivationAlg):
            cek = jwk.recipient_key(**self.headers)
        elif issubclass(keyalg, DirectKeyUse):
            cek = jwk
        else:
            raise RuntimeError(f"Unsupported Key Management Algorithm {keyalg}")

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
