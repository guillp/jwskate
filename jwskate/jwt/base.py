"""This modules contains the `Jwt` base class."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterable

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

    def __new__(cls, value: bytes | str, max_size: int = 16 * 1024) -> SignedJwt | JweCompact | Jwt:  # type: ignore[misc]
        """Allow parsing both Signed and Encrypted JWTs.

        This returns the appropriate subclass or instance depending on the number of dots (.) in the serialized JWT.

        Args:
            value: the token value
            max_size: maximum allowed size for the token

        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        if cls == Jwt:
            if value.count(b".") == 2:
                from .signed import SignedJwt

                return super().__new__(SignedJwt)
            elif value.count(b".") == 4:
                from ..jwe import JweCompact

                return JweCompact(value, max_size)

        return super().__new__(cls)

    @classmethod
    def sign(
        cls,
        claims: dict[str, Any],
        key: Jwk | dict[str, Any] | Any,
        alg: str | None = None,
        typ: str | None = "JWT",
        extra_headers: dict[str, Any] | None = None,
    ) -> SignedJwt:
        """Sign a JSON payload with a private key and return the resulting `SignedJwt`.

        This method cannot generate a token without a signature. If you want to use an unsigned token (with alg=none),
        use `.unprotected()` instead.

        Args:
          claims: the payload to sign
          key: the key to use for signing
          alg: the alg to use for signing
          typ: typ (token type) header to include. If `None`, do not include this header.
          extra_headers: additional headers to include in the Jwt

        Returns:
          the resulting token

        """
        key = to_jwk(key)

        alg = alg or key.get("alg")

        if alg is None:
            raise ValueError("a signing alg is required")

        extra_headers = extra_headers or {}
        headers = dict(alg=alg, **extra_headers)
        if typ:
            headers["typ"] = typ
        if key.kid:
            headers["kid"] = key.kid

        return cls.sign_arbitrary(claims=claims, headers=headers, key=key, alg=alg)

    @classmethod
    def sign_arbitrary(
        self,
        claims: dict[str, Any],
        headers: dict[str, Any],
        key: Jwk | dict[str, Any] | Any,
        alg: str | None = None,
    ) -> SignedJwt:
        """Sign provided headers and claims with a private key and return the resulting `SignedJwt`.

        This does not check the consistency between headers, key, alg and kid.
        DO NOT USE THIS METHOD UNLESS YOU KNOW WHAT YOU ARE DOING!!!
        Use `Jwt.sign()` to make sure you are signing tokens properly.

        Args:
             claims: the payload to sign
             headers: the headers to sign
             key: the key to use for signing
             alg: the alg to use for signing

        """
        from .signed import SignedJwt

        key = to_jwk(key)

        alg = alg or key.get("alg")

        if alg is None:
            raise ValueError("a signing alg is required")

        headers_part = BinaPy.serialize_to("json", headers).to("b64u")
        claims_part = BinaPy.serialize_to("json", claims).to("b64u")
        signed_value = b".".join((headers_part, claims_part))
        signature = key.sign(signed_value, alg=alg).to("b64u")
        return SignedJwt(b".".join((signed_value, signature)))

    @classmethod
    def unprotected(
        cls,
        claims: dict[str, Any],
        typ: str | None = "JWT",
        extra_headers: dict[str, Any] | None = None,
    ) -> SignedJwt:
        """Generate a JWT that is not signed and not encrypted (with alg=none).

        Args:
          claims: the claims to set in the token.
          typ: typ (token type) header to include. If `None`, do not include this header.
          extra_headers: additional headers to insert in the token.

        Returns:
            the resulting token

        """
        from .signed import SignedJwt

        headers = dict(extra_headers or {}, alg="none")
        if typ:
            headers["typ"] = typ

        headers_part = BinaPy.serialize_to("json", headers).to("b64u")
        claims_part = BinaPy.serialize_to("json", claims).to("b64u")
        signed_value = b".".join((headers_part, claims_part))
        signature = b""
        return SignedJwt(b".".join((signed_value, signature)))

    @classmethod
    def sign_and_encrypt(
        cls,
        claims: dict[str, Any],
        sign_key: Jwk | dict[str, Any] | Any,
        enc_key: Jwk | dict[str, Any] | Any,
        enc: str,
        *,
        sign_alg: str | None = None,
        enc_alg: str | None = None,
        sign_extra_headers: dict[str, Any] | None = None,
        enc_extra_headers: dict[str, Any] | None = None,
    ) -> JweCompact:
        """Sign a JWT, then encrypt it as JWE payload.

        This is a convenience method to do both the signing and encryption, in appropriate order.

        Args:
          claims: the payload to encrypt
          sign_key: the Jwk to use for signature
          sign_alg: the alg to use for signature
          sign_extra_headers: additional headers for the inner signed JWT
          enc_key: the Jwk to use for encryption
          enc_alg: the alg to use for CEK encryption
          enc: the alg to use for payload encryption
          enc_extra_headers: additional headers for the outer encrypted JWE

        Returns:
          the resulting JWE token, with the signed JWT as payload

        """
        enc_extra_headers = enc_extra_headers or {}
        enc_extra_headers.setdefault("cty", "JWT")

        inner_jwt = cls.sign(
            claims, key=sign_key, alg=sign_alg, extra_headers=sign_extra_headers
        )
        jwe = JweCompact.encrypt(
            inner_jwt, enc_key, enc=enc, alg=enc_alg, extra_headers=enc_extra_headers
        )
        return jwe

    @classmethod
    def decrypt_nested_jwt(
        cls, jwe: str | JweCompact, key: Jwk | dict[str, Any] | Any
    ) -> Jwt:
        """Decrypt a JWE that contains a nested JWT.

        It will return a [Jwt] instance for the inner JWT.

        Args:
            jwe: the JWE containing a nested Token
            key: the decryption key

        Returns:
            the inner JWT

        Raises:
            InvalidJwt: if the inner JWT is not valid

        """
        if not isinstance(jwe, JweCompact):
            jwe = JweCompact(jwe)
        cleartext = jwe.decrypt(key)
        return Jwt(cleartext)

    @classmethod
    def decrypt_and_verify(
        cls,
        jwt: str | JweCompact,
        enc_key: Jwk | dict[str, Any] | Any,
        sig_key: Jwk | dict[str, Any] | None | Any,
        sig_alg: str | None = None,
        sig_algs: Iterable[str] | None = None,
    ) -> SignedJwt:
        """Decrypt then verify the signature of a JWT nested in a JWE.

        This can only be used with signed then encrypted Jwt, such as those produce by `Jwt.sign_and_encrypt()`.

        Args:
            jwt: the JWE containing a nested signed JWT
            enc_key: the decryption key
            sig_key: the signature verification key
            sig_alg: the signature verification alg, if only 1 is allowed
            sig_algs: the signature verifications algs, if several are allowed

        Returns:
            the nested signed JWT, in clear-text, signature already verified

        Raises:
            InvalidJwt: if the JWT is not valid
            InvalidSignature: if the nested JWT signature is not valid

        """
        from .signed import InvalidSignature, SignedJwt

        nested_jwt = cls.decrypt_nested_jwt(jwt, enc_key)
        if not isinstance(nested_jwt, SignedJwt):
            raise ValueError("Nested JWT is not signed", nested_jwt)

        if sig_key:
            if nested_jwt.verify_signature(sig_key, sig_alg, sig_algs):
                return nested_jwt

        raise InvalidSignature()

    @classmethod
    def timestamp(cls, delta_seconds: int = 0) -> int:
        """Return an integer timestamp that is suitable for use in Jwt tokens.

        Timestamps are used in particular for `iat`, `exp` and `nbf` claims.

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
