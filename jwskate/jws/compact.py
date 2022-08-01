"""This module implements the JWS Compact format."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Tuple, Union

from backports.cached_property import cached_property
from binapy import BinaPy

from jwskate.jwk.base import Jwk
from jwskate.token import BaseCompactToken

from .signature import JwsSignature

if TYPE_CHECKING:
    from .json import JwsJsonFlat, JwsJsonGeneral  # pragma: no cover


class InvalidJws(ValueError):
    """Raised when an invalid Jws is parsed."""


class JwsCompact(BaseCompactToken):
    """Represents a Json Web Signature (JWS), using compact serialization, as defined in RFC7515.

    Args:
        value: the JWS token value
    """

    def __init__(self, value: Union[bytes, str]):
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
        """Splits a JWS token value into its (header, payload, signature) parts.

        Args:
          value: the JWS token value

        Returns:
            a (header, payload, signature)

        Raises:
            InvalidJws: if the provided value doesn't have 2 dots.
        """
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
        """Sign a payload and returns the resulting JwsCompact.

        Args:
          payload: the payload to sign
          jwk: the jwk to use to sign this payload
          alg: the alg to use
          extra_headers: additional headers to add to the Jws Headers

        Returns:
          the resulting token
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
        """Constructs a JWS token based on its signed part and signature values.

        Signed part is the concatenation of the header and payload, both encoded in Base64-Url, and joined by a dot.

        Args:
          signed_part: the signed part
          signature: the signature value

        Returns:
            the resulting token
        """
        if not isinstance(signed_part, bytes):
            signed_part = signed_part.encode("ascii")

        return cls(b".".join((signed_part, BinaPy(signature).to("b64u"))))

    @cached_property
    def signed_part(self) -> bytes:
        """Returns the signed part (header + payload) from this JwsCompact.

        Returns:
            the signed part
        """
        return b".".join(self.value.split(b".", 2)[:2])

    def verify_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        *,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        """Verify the signature from this JwsCompact using a Jwk.

        Args:
          jwk: the Jwk to use to validate this signature
          alg: the alg to use, if there is only 1 allowed
          algs: the allowed algs, if here are several

        Returns:
         `True` if the signature matches, `False` otherwise
        """
        jwk = Jwk(jwk)
        return jwk.verify(self.signed_part, self.signature, alg=alg, algs=algs)

    def flat_json(self, unprotected_header: Any = None) -> JwsJsonFlat:
        """Create a JWS in JSON flat format based on this Compact JWS.

        Args:
          unprotected_header: optional unprotected header to include in the JWS JSON

        Returns:
            the resulting token
        """
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

    def general_json(self, unprotected_header: Any = None) -> JwsJsonGeneral:
        """Create a JWS in JSON General format based on this JWS Compact.

        The resulting token will have a single signature which is the one from this token.

        Args:
            unprotected_header: optional unprotected header to include in the JWS JSON

        Returns:
            the resulting token
        """
        jws = self.flat_json(unprotected_header)
        return jws.generalize()
