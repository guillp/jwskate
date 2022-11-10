"""This modules contains classes and utilities to generate and validate signed JWT."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Union

from backports.cached_property import cached_property
from binapy import BinaPy

from jwskate.jwk import Jwk, to_jwk

from .base import InvalidJwt, Jwt


class ExpiredJwt(ValueError):
    """Raised when trying to validate an expired JWT token."""


class InvalidSignature(ValueError):
    """Raised when trying to validate a JWT with an invalid signature."""


class InvalidClaim(ValueError):
    """Raised when trying to validate a JWT with unexpected claims."""


class SignedJwt(Jwt):
    """Represent a Signed Json Web Token (JWT), as defined in RFC7519.

    A signed JWT contains a JSON object as payload, which represents claims.

    To sign a JWT, use [Jwt.sign][jwskate.jwt.Jwt.sign].

    Args:
        value: the token value.
    """

    def __init__(self, value: Union[bytes, str]) -> None:
        super().__init__(value)

        if self.value.count(b".") != 2:
            raise InvalidJwt(
                "A JWT must contain a header, a payload and a signature, separated by dots",
                value,
            )

        header, payload, signature = self.value.split(b".")
        try:
            self.headers = BinaPy(header).decode_from("b64u").parse_from("json")
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.claims = BinaPy(payload).decode_from("b64u").parse_from("json")
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT payload: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.signature = BinaPy(signature).decode_from("b64u")
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT signature: it must be a Base64URL-encoded binary data (bytes)"
            )

    @cached_property
    def signed_part(self) -> bytes:
        """Return the actual signed data from this token.

        The signed part is composed of the header and payload, encoded in Base64-Url, joined by a dot.

        Returns:
          the signed part as bytes
        """
        return b".".join(self.value.split(b".", 2)[:2])

    def verify_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        """Verify this JWT signature using a given key and algorithm(s).

        Args:
          jwk: the private Jwk to use to verify the signature
          alg: the alg to use to verify the signature, if only 1 is allowed
          algs: the allowed signature algs, if there are several

        Returns:
            `True` if the token signature is verified, `False` otherwise
        """
        jwk = to_jwk(jwk)

        return jwk.verify(
            data=self.signed_part, signature=self.signature, alg=alg, algs=algs
        )

    def is_expired(self, leeway: int = 0) -> Optional[bool]:
        """Check if this token is expired, based on its `exp` claim.

        Args:
            leeway: additional number of seconds for leeway.

        Returns:
            `True` if the token is expired, `False` if it's not, `None` if there is no `exp` claim.
        """
        exp = self.expires_at
        if exp is None:
            return None
        return exp < (datetime.now(timezone.utc) + timedelta(seconds=leeway))

    @cached_property
    def expires_at(self) -> Optional[datetime]:
        """Get the "Expires At" (exp) date from this token.

        Returns:
          a `datetime` initialized from the `exp` claim, or `None` if there is no `exp` claim

        Raises:
            AttributeError: if the `exp` claim cannot be parsed to a date
        """
        exp = self.get_claim("exp")
        if not exp:
            return None
        try:
            exp_dt = Jwt.timestamp_to_datetime(exp)
            return exp_dt
        except (TypeError, OSError):
            raise AttributeError("invalid `exp `claim", exp)

    @cached_property
    def issued_at(self) -> Optional[datetime]:
        """Get the "Issued At" (iat) date from this token.

        Returns:
          a `datetime` initialized from the `iat` claim, or `None` if there is no `iat` claim

        Raises:
            AttributeError: if the `iss` claim cannot be parsed to a date
        """
        iat = self.get_claim("iat")
        if not iat:
            return None
        try:
            iat_dt = Jwt.timestamp_to_datetime(iat)
            return iat_dt
        except (TypeError, OSError):
            raise AttributeError("invalid `iat `claim", iat)

    @cached_property
    def not_before(self) -> Optional[datetime]:
        """Get the "Not Before" (nbf) date from this token.

        Returns:
          a `datetime` initialized from the `nbf` claim, or `None` if there is no `nbf` claim

        Raises:
            AttributeError: if the `nbf` claim cannot be parsed to a date
        """
        nbf = self.get_claim("nbf")
        if not nbf:
            return None
        try:
            nbf_dt = Jwt.timestamp_to_datetime(nbf)
            return nbf_dt
        except (TypeError, OSError):
            raise AttributeError("invalid `nbf `claim", nbf)

    @cached_property
    def issuer(self) -> Optional[str]:
        """Get the Issuer (iss) claim from this token.

        Returns:
          the issuer, as `str`, or `None` if there is no `ìss` claim

        Raises:
            AttributeError: if the `ìss` claim value is not a string
        """
        iss = self.get_claim("iss")
        if iss is None or isinstance(iss, str):
            return iss
        raise AttributeError("iss has an unexpected type", type(iss))

    @cached_property
    def audiences(self) -> List[str]:
        """Get the audience(s) (aud) claim from this token.

        If this token has a single audience, this will return a `list` anyway.

        Returns:
            the list of audiences from this token, from the `aud` claim.

        Raises:
            AttributeError: if the audience is an unexpected type
        """
        aud = self.get_claim("aud")
        if aud is None:
            return []
        if isinstance(aud, str):
            return [aud]
        if isinstance(aud, list):
            return aud
        raise AttributeError("aud has an unexpected type", type(aud))

    @cached_property
    def subject(self) -> Optional[str]:
        """Get the Subject (sub) from this token claims.

        Returns:
          the subject, as `str`, or `None` if there is no `sub` claim

        Raises:
            AttributeError: if the `sub` value is not a string
        """
        sub = self.get_claim("sub")
        if sub is None or isinstance(sub, str):
            return sub
        raise AttributeError("sub has an unexpected type", type(sub))

    @cached_property
    def jwt_token_id(self) -> Optional[str]:
        """Get the JWT Token ID (jti) from this token claims.

        Returns:
          the token identifier, as `str`, or `None` if there is no `jti` claim

        Raises:
          AttributeError: if the `jti` value is not a string
        """
        jti = self.get_claim("jti")
        if jti is None or isinstance(jti, str):
            return jti
        raise AttributeError("jti has an unexpected type", type(jti))

    def get_claim(self, key: str, default: Any = None) -> Any:
        """Get a claim from this Jwt.

        Args:
          key: the claim name.
          default: a default value if the claim is not found

        Returns:
          the claim value if found, or `default` if not found
        """
        return self.claims.get(key, default)

    def __getitem__(self, item: str) -> Any:
        """Allow claim access with subscription.

        Args:
          item: the claim name

        Returns:
         the claim value
        """
        value = self.get_claim(item)
        if value is None:
            raise KeyError(item)
        return value

    def __getattr__(self, item: str) -> Any:
        """Allow claim access as attributes.

        Args:
            item: the claim name

        Returns:
            the claim value
        """
        value = self.get_claim(item)
        if value is None:
            raise AttributeError(item)
        return value

    def __str__(self) -> str:
        """Return the Jwt serialized value, as `str`.

        Returns:
            the serialized token value.
        """
        return self.value.decode()

    def __bytes__(self) -> bytes:
        """Return the Jwt serialized value, as `bytes`.

        Returns:
            the serialized token value.
        """
        return self.value

    def validate(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        *,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
        issuer: Optional[str] = None,
        audience: Union[None, str] = None,
        check_exp: bool = True,
        **kwargs: Any,
    ) -> None:
        """Validate a `SignedJwt` signature and expected claims.

        This verifies the signature using the provided `jwk` and `alg`, then checks the token issuer, audience and expiration date.
        This can also check custom claims using extra `kwargs`, whose values can be:

        - a static value (`str`, `int`, etc.): the value from the token will be compared "as-is"
        - a callable, taking the claim value as parameter: if that callable returns `True`, the claim is considered as valid

        Args:
          jwk: the signing key to use to verify the signature.
          alg: the signature alg to use to verify the signature.
          algs: allowed signature algs, if several
          issuer: the expected issuer for this token.
          audience: the expected audience for this token.
          check_exp: ìf `True` (default), check that the token is not expired.
          **kwargs: additional claims to check

        Returns:
          Raises exceptions if any validation check fails.

        Raises:
          InvalidSignature: if the signature is not valid
          InvalidClaim: if a claim doesn't validate
          ExpiredJwt: if the expiration date is passed
        """
        if not self.verify_signature(jwk, alg, algs):
            raise InvalidSignature("Signature is not valid.")

        if issuer is not None:
            if self.issuer != issuer:
                raise InvalidClaim("iss", "Unexpected issuer", self.issuer)

        if audience is not None:
            if self.audiences is None or audience not in self.audiences:
                raise InvalidClaim("aud", "Unexpected audience", self.audiences)

        if check_exp:
            expired = self.is_expired()
            if expired is True:
                raise ExpiredJwt(f"This token expired at {self.expires_at}")
            elif expired is None:
                raise InvalidClaim("exp", "This token misses a 'exp' claim.")

        for key, value in kwargs.items():
            claim = self.get_claim(key)
            if callable(value):
                if not value(claim):
                    raise InvalidClaim(
                        key,
                        f"value of claim {key} doesn't validate with the provided validator",
                        claim,
                    )
            elif claim != value:
                raise InvalidClaim(key, f"unexpected value for claim {key}", claim)
