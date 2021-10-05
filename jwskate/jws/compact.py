from typing import Any, Dict, Optional, Union

from jwskate.jwk.base import Jwk
from jwskate.utils import b64u_decode, b64u_decode_json, b64u_encode, b64u_encode_json


class InvalidJws(ValueError):
    """Raised when an invalid Jws is parsed"""


class JwsCompact:
    """
    Represents a a Json Web Signature (JWS), using compact serialization, as defined in RFC7515.
    """

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes a Jws, from its compact representation.
        :param value: the Jws value
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        if value.count(b".") != 2:
            raise InvalidJws(
                "A JWS must contain a header, a payload and a signature, separated by dots"
            )

        header, payload, signature = value.split(b".")
        try:
            self.headers = b64u_decode_json(header)
        except ValueError:
            raise InvalidJws(
                "Invalid JWS header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.payload = b64u_decode(payload)
        except ValueError:
            raise InvalidJws(
                "Invalid JWS payload: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.signature = b64u_decode(signature)
        except ValueError:
            raise InvalidJws(
                "Invalid JWS signature: it must be a Base64URL-encoded binary data (bytes)"
            )

        self.value = value

    def get_header(self, name: str) -> Any:
        """
        Gets an header from this Jws
        :param name: the header name
        :return: the header value
        """
        return self.headers.get(name)

    @classmethod
    def sign(
        cls,
        payload: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> "JwsCompact":
        """
        Signs a payload into a Jws and returns the resulting JwsCompact
        :param payload: the payload to sign
        :param jwk: the jwk to use to sign this payload
        :param alg: the alg to use
        :param extra_headers: additional headers to add to the Jws Headers
        :return: a JwsCompact
        """
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        if not jwk.is_private:
            raise ValueError("Signing requires a private JWK")

        alg = alg or jwk.get("alg")
        kid = jwk.get("kid")

        if alg is None:
            raise ValueError("a signing alg is required")

        headers = dict(extra_headers or {}, alg=alg)
        if kid:
            headers["kid"] = kid

        signed_part = cls.assemble_signed_part(headers, payload)
        signature = jwk.sign(signed_part.encode(), alg=alg)
        return cls.from_parts(signed_part, signature)

    @classmethod
    def assemble_signed_part(
        cls, headers: Dict[str, Any], payload: Union[bytes, str]
    ) -> str:
        return ".".join((b64u_encode_json(headers), b64u_encode(payload)))

    @classmethod
    def from_parts(
        cls, signed_part: Union[bytes, str], signature: Union[bytes, str]
    ) -> "JwsCompact":
        if not isinstance(signed_part, bytes):
            signed_part = signed_part.encode("ascii")

        return cls(b".".join((signed_part, b64u_encode(signature).encode())))

    def __str__(self) -> str:
        """
        Returns the `str` representation of this JwsCompact
        :return: a `str`
        """
        return self.value.decode()

    def __bytes__(self) -> bytes:
        """
        Returns the `bytes` representation of this JwsCompact
        :return:
        """
        return self.value

    @property
    def signed_part(self) -> bytes:
        """
        Returns the signed part (header + payload) from this JwsCompact
        :return:
        """
        return b".".join(self.value.split(b".", 2)[:2])

    def verify_signature(self, jwk: Union[Jwk, Dict[str, Any]], alg: str) -> bool:
        """
        Verify the signature from this JwsCompact using a Jwk
        :param jwk: the Jwk to use to validate this signature
        :param alg: the alg to use
        :return: `True` if the signature matches, `False` otherwise
        """
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)
        return jwk.verify(self.signed_part, self.signature, alg)
