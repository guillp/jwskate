"""This modules contains the `Jwt` base class."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from binapy import BinaPy

from jwskate.jwk import Jwk

from ..token import BaseCompactToken

if TYPE_CHECKING:
    from jwskate import EncryptedJwt, SignedJwt  # pragma: no cover


class InvalidJwt(ValueError):
    """Raised when an invalid Jwt is parsed."""


class Jwt(BaseCompactToken):
    """Represents a Json Web Token."""

    def __new__(cls, value: Union[bytes, str]):  # type: ignore
        """Allow parsing both Signed and Encrypted JWTs. Returns the appropriate subclass instance.

        Args:
            value: the token value
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        if cls == Jwt:
            if value.count(b".") == 2:
                from .signed import SignedJwt

                return super().__new__(SignedJwt)
            elif value.count(b".") == 3:
                from .encrypted import EncryptedJwt

                return super().__new__(EncryptedJwt)
        return super().__new__(cls)

    @classmethod
    def sign(
        cls,
        claims: Dict[str, Any],
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> "SignedJwt":
        """Sign a JSON payload with a `Jwk` and returns the resulting `SignedJwt`.

        This method cannot generate a token without a signature. If you want to use an unsigned token (with alg=none),
        use `.unprotected()` instead.

        Args:
          claims: the payload to sign
          jwk: the Jwk to use for signing
          alg: the alg to use for signing
          extra_headers: additional headers to include in the Jwt

        Returns:
          the resulting token
        """
        from .signed import SignedJwt

        jwk = Jwk(jwk)

        alg = alg or jwk.get("alg")
        kid = jwk.get("kid")

        if alg is None:
            raise ValueError("a signing alg is required")

        extra_headers = extra_headers or {}
        headers = dict(alg=alg, **extra_headers)
        if kid:
            headers["kid"] = kid

        headers_part = BinaPy.serialize_to("json", headers).to("b64u")
        claims_part = BinaPy.serialize_to("json", claims).to("b64u")
        signed_value = b".".join((headers_part, claims_part))
        signature = jwk.sign(signed_value, alg=alg).to("b64u")
        return SignedJwt(b".".join((signed_value, signature)))

    @classmethod
    def unprotected(
        cls,
        claims: Dict[str, Any],
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> "SignedJwt":
        """Generate a JWT that is not signed and not encrypted (with alg=none).

        Args:
          claims: the claims to set in the token.
          extra_headers: additional headers to insert in the token.

        Returns:
            the resulting token
        """
        from .signed import SignedJwt

        headers = dict(extra_headers or {}, alg="none")

        headers_part = BinaPy.serialize_to("json", headers).to("b64u")
        claims_part = BinaPy.serialize_to("json", claims).to("b64u")
        signed_value = b".".join((headers_part, claims_part))
        signature = b""
        return SignedJwt(b".".join((signed_value, signature)))

    @classmethod
    def sign_and_encrypt(
        cls,
        claims: Dict[str, Any],
        sign_jwk: Union[Jwk, Dict[str, Any]],
        sign_alg: Optional[str],
        enc_jwk: Union[Jwk, Dict[str, Any]],
        enc_alg: Optional[str],
        enc: Optional[str],
    ) -> "EncryptedJwt":
        """Sign then encrypt a payload with a `Jwk` and returns the resulting `EncryptedJwt`.

        NOT IMPLEMENTED YET.

        Args:
          claims: the payload to encrypt
          sign_jwk: the Jwk to use for signature
          sign_alg: the alg to use for signature
          enc_jwk: the Jwk to use for encryption
          enc_alg: the alg to use for CEK encryption
          enc: the alg to use for payload encryption

        Returns:
          the resulting JWE token, with signed JWT as payload
        """
        raise NotImplementedError
