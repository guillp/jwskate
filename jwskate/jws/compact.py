from typing import Any, Dict, Iterable, Optional, Union

from binapy import BinaPy

from jwskate.jwk.alg import select_alg
from jwskate.jwk.base import Jwk
from jwskate.token import BaseToken


class InvalidJws(ValueError):
    """Raised when an invalid Jws is parsed"""


class JwsCompact(BaseToken):
    """
    Represents a a Json Web Signature (JWS), using compact serialization, as defined in RFC7515.
    """

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes a Jws, from its compact representation.
        :param value: the Jws value
        """
        super().__init__(value)

        if self.value.count(b".") != 2:
            raise InvalidJws(
                "A JWS must contain a header, a payload and a signature, separated by dots"
            )

        header, payload, signature = self.value.split(b".")
        try:
            self.headers = BinaPy(header).decode_from("b64u").parse_from("json")
        except ValueError:
            raise InvalidJws(
                "Invalid JWS header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.payload = BinaPy(payload).decode_from("b64u")
        except ValueError:
            raise InvalidJws(
                "Invalid JWS payload: it must be a Base64URL-encoded binary data (bytes)"
            )

        try:
            self.signature = BinaPy(signature).decode_from("b64u")
        except ValueError:
            raise InvalidJws(
                "Invalid JWS signature: it must be a Base64URL-encoded binary data (bytes)"
            )

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
        jwk = Jwk(jwk)

        if not jwk.is_private:
            raise ValueError("Signing requires a private JWK")

        sigalg = select_alg(jwk.alg, alg, jwk.SIGNATURE_ALGORITHMS)
        kid = jwk.get("kid")

        headers = dict(extra_headers or {}, alg=sigalg.name)
        if kid:
            headers["kid"] = kid

        signed_part = cls.assemble_signed_part(headers, payload)
        signature = jwk.sign(signed_part, alg=sigalg.name)
        return cls.from_parts(signed_part, signature)

    @classmethod
    def assemble_signed_part(
        cls, headers: Dict[str, Any], payload: Union[bytes, str]
    ) -> bytes:
        return b".".join(
            (
                BinaPy.serialize_to("json", headers).encode_to("b64u"),
                BinaPy(payload).encode_to("b64u"),
            )
        )

    @classmethod
    def from_parts(
        cls, signed_part: Union[bytes, str], signature: Union[bytes, str]
    ) -> "JwsCompact":
        if not isinstance(signed_part, bytes):
            signed_part = signed_part.encode("ascii")

        return cls(b".".join((signed_part, BinaPy(signature).encode_to("b64u"))))

    @property
    def signed_part(self) -> bytes:
        """
        Returns the signed part (header + payload) from this JwsCompact
        :return:
        """
        return b".".join(self.value.split(b".", 2)[:2])

    def verify_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        """
        Verify the signature from this JwsCompact using a Jwk
        :param jwk: the Jwk to use to validate this signature
        :param alg: the alg to use
        :return: `True` if the signature matches, `False` otherwise
        """
        jwk = Jwk(jwk)
        return jwk.verify(self.signed_part, self.signature, alg, algs)
