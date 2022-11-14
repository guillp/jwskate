"""This modules contains the `Jwt` base class."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Union

from binapy import BinaPy

from jwskate.jwe import JweCompact
from jwskate.jwk import Jwk, to_jwk
from jwskate.token import BaseCompactToken

if TYPE_CHECKING:
    from jwskate import SignedJwt  # pragma: no cover


class InvalidJwt(ValueError):
    """Raised when an invalid Jwt is parsed."""


class Jwt(BaseCompactToken):
    """Represents a Json Web Token."""

    def __new__(cls, value: Union[bytes, str]):  # type: ignore
        """Allow parsing both Signed and Encrypted JWTs.

        This returns the appropriate subclass or instance depending on the number of dots (.) in the serialized JWT.

        Args:
            value: the token value
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        if cls == Jwt:
            if value.count(b".") == 2:
                from .signed import SignedJwt

                return super().__new__(SignedJwt)
            elif value.count(b".") == 4:
                from ..jwe import JweCompact

                return JweCompact(value)
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

        jwk = to_jwk(jwk)

        alg = alg or jwk.get("alg")

        if alg is None:
            raise ValueError("a signing alg is required")

        extra_headers = extra_headers or {}
        headers = dict(alg=alg, **extra_headers)
        if jwk.kid:
            headers["kid"] = jwk.kid

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
        enc_jwk: Union[Jwk, Dict[str, Any]],
        enc: str,
        *,
        sign_alg: Optional[str] = None,
        enc_alg: Optional[str] = None,
        sign_extra_headers: Optional[Dict[str, Any]] = None,
        enc_extra_headers: Optional[Dict[str, Any]] = None,
    ) -> JweCompact:
        """Sign a JWT, then encrypt it as JWE payload.

        This is a convenience method to do both the signing and encryption, in appropriate order.

        Args:
          claims: the payload to encrypt
          sign_jwk: the Jwk to use for signature
          sign_alg: the alg to use for signature
          sign_extra_headers: additional headers for the inner signed JWT
          enc_jwk: the Jwk to use for encryption
          enc_alg: the alg to use for CEK encryption
          enc: the alg to use for payload encryption
          enc_extra_headers: additional headers for the outer encrypted JWE

        Returns:
          the resulting JWE token, with the signed JWT as payload
        """
        enc_extra_headers = enc_extra_headers or {}
        enc_extra_headers.setdefault("cty", "JWT")

        inner_jwt = cls.sign(
            claims, jwk=sign_jwk, alg=sign_alg, extra_headers=sign_extra_headers
        )
        jwe = JweCompact.encrypt(
            inner_jwt, enc_jwk, enc=enc, alg=enc_alg, extra_headers=enc_extra_headers
        )
        return jwe

    @classmethod
    def decrypt_nested_jwt(
        cls, jwe: Union[str, JweCompact], jwk: Union[Jwk, Dict[str, Any]]
    ) -> Jwt:
        """Convenience method to decrypt a nested JWT.

        It will return a [Jwt] instance.

        Args:
            jwe: the JWE containing a nested Token
            jwk: the decryption key

        Returns:
            the inner token

        Raises:
            InvalidJwt: if the inner JWT is not valid
        """
        if not isinstance(jwe, JweCompact):
            jwe = JweCompact(jwe)
        cleartext = jwe.decrypt(jwk)
        return Jwt(cleartext)

    @classmethod
    def decrypt_and_verify(
        cls,
        jwt: Union[str, JweCompact],
        enc_jwk: Union[Jwk, Dict[str, Any]],
        sig_jwk: Union[Jwk, Dict[str, Any], None],
        sig_alg: Optional[str] = None,
        sig_algs: Optional[Iterable[str]] = None,
    ) -> SignedJwt:
        """Decrypt then verify the signature of a JWT nested in a JWE.

        This can only be used with signed then encrypted Jwt, such as those produce by `Jwt.sign_and_encrypt()`.

        Args:
            jwt: the JWE containing a nested signed JWT
            enc_jwk: the decryption key
            sig_jwk: the signature verification key
            sig_alg: the signature verification alg, if only 1 is allowed
            sig_algs: the signature verifications algs, if several are allowed

        Returns:
            the nested signed JWT, in clear-text, signature already verified

        Raises:
            InvalidJwt: if the JWT is not valid
            InvalidSignature: if the nested JWT signature is not valid
        """
        from .signed import InvalidSignature, SignedJwt

        nested_jwt = cls.decrypt_nested_jwt(jwt, enc_jwk)
        if not isinstance(nested_jwt, SignedJwt):
            raise ValueError("Nested JWT is not signed", nested_jwt)

        if sig_jwk:
            if nested_jwt.verify_signature(sig_jwk, sig_alg, sig_algs):
                return nested_jwt

        raise InvalidSignature()

    @classmethod
    def timestamp(cls, delta_seconds: int = 0) -> int:
        """Return an integer timestamp that is suitable for use in Jwt tokens `iat`, `exp` and `nbf` claims.

        A timestamp is a number of seconds since January 1st, 1970 00:00:00 UTC, ignoring leap seconds.

        By default, the current timestamp is returned. You can include `delta_seconds` to have a timestamp
        a number of seconds in the future (if positive) or in the past (if negative).

        Args:
            delta_seconds: number of seconds in the future or in the past compared to current time

        Returns:
            An integer timestamp
        """
        return int(datetime.now(timezone.utc).timestamp()) + delta_seconds

    @classmethod
    def timestamp_to_datetime(cls, timestamp: int) -> datetime:
        """Convert a JWT timestamp to a `datetime`.

        Returned datetime is always in the UTC timezone.

        Args:
            timestamp: a timestamp from a JWT token

        Returns:
            the corresponding `datetime` in UTC timezone
        """
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
