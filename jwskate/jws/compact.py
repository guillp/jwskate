from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Tuple, Union

from binapy import BinaPy

from jwskate.jwk.base import Jwk
from jwskate.token import BaseToken

from .signature import JwsSignature

if TYPE_CHECKING:
    from .json import JwsJsonFlat, JwsJsonGeneral


class InvalidJws(ValueError):
    """Raised when an invalid Jws is parsed"""


class JwsCompact(BaseToken):
    """
    Represents a Json Web Signature (JWS), using compact serialization, as defined in RFC7515.
    """

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes a Jws, from its compact representation.
        :param value: the Jws value
        """
        super().__init__(value)

        header, payload, signature = self.split(self.value)

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
    def split(cls, value: bytes) -> Tuple[BinaPy, BinaPy, BinaPy]:
        if value.count(b".") != 2:
            raise InvalidJws(
                "A JWS must contain a header, a payload and a signature, separated by dots"
            )

        header, payload, signature = value.split(b".")
        return BinaPy(header), BinaPy(payload), BinaPy(signature)

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

        headers = dict(extra_headers or {}, alg=alg)
        kid = jwk.get("kid")
        if kid:
            headers["kid"] = kid

        signed_part = JwsSignature.assemble_signed_part(headers, payload)
        signature = jwk.sign(signed_part, alg=alg)
        return cls.from_parts(signed_part, signature)

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

    @property
    def alg(self) -> str:
        alg = self.get_header("alg")
        if alg is None or not isinstance(alg, str):
            raise KeyError("This JWE doesn't have a valid 'alg' header")
        return alg

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

    def flat_json(self, unprotected_header: Any = None) -> JwsJsonFlat:
        from .json import JwsJsonFlat

        protected, payload, signature = self.split(self.value)
        content = {
            "payload": payload.ascii(),
            "protected": protected.ascii(),
            "signature": signature.ascii(),
        }
        if unprotected_header is not None:
            content["header"] = unprotected_header
        return JwsJsonFlat(content)

    def general_json(self) -> JwsJsonGeneral:
        jws = self.flat_json()
        return jws.generalize()
