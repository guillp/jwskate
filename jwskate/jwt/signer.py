"""This module contains the `JwtSigner` class."""

import uuid
from typing import Any, Dict, Iterable, Optional, Union

from jwskate.jwk import Jwk

from .base import Jwt
from .signed import SignedJwt


class JwtSigner:
    """A helper class to easily sign JWTs with standardised claims.

    The standardised claims include:

       - `ìat`: issued at date
       - `exp`: expiration date
       - `nbf`: not before date:
       - `iss`: issuer identifier
       - `sub`: subject identifier
       - `aud`: audience identifier
       - `jti`: JWT token ID

    The issuer, signing keys, signing alg and default lifetime are
    defined at initialization time, so you only have to define the
    subject, audience and custom claims when calling `JwtSigner.sign()`.
    This can be used as an alternative to `Jwt.sign()` when a single
    issuer issues multiple tokens.

    Args:
        issuer: the issuer string to use as `ìss` claim for signed tokens.
        jwk: the private Jwk to use to sign tokens.
        alg: the signing alg to use to sign tokens.
        default_lifetime: the default lifetime, in seconds, to use for claim `exp`. This can be overridden
            when calling `.sign()`
        default_leeway: the default leeway, in seconds, to use for claim `nbf`. If None, no `nbf` claim is
            included. This can be overridden when calling `.sign()`
    """

    def __init__(
        self,
        issuer: str,
        jwk: Jwk,
        alg: Optional[str] = None,
        default_lifetime: int = 60,
        default_leeway: Optional[int] = None,
    ):
        self.issuer = issuer
        self.jwk = jwk
        self.alg = jwk.alg or alg
        self.default_lifetime = default_lifetime
        self.default_leeway = default_leeway

    def sign(
        self,
        subject: Optional[str] = None,
        audience: Union[str, Iterable[str], None] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
        lifetime: Optional[int] = None,
        leeway: Optional[int] = None,
    ) -> SignedJwt:
        """Sign a Jwt.

        Claim 'issuer' will have the value defined at initialization time. Claim `iat`, `nbf` and `exp` will reflect
        the current time when the token is signed. `exp` includes `lifetime` seconds in the future, and `nbf`
        includes `leeway` seconds in the past.

        Args:
          subject: the subject to include in claim `sub`. (Default value = None)
          audience: the audience identifier(s) to include in claim `aud`.
          extra_claims: additional claims to include in the signed token. (Default value = None)
          extra_headers: additional headers to include in the header part. (Default value = None)
          lifetime: lifetime, in seconds, to use for the `exp` claim. If None, use the default_lifetime defined at initialization time.
          leeway: leeway, in seconds, to use for the `nbf` claim. If None, use the default_leeway defined at initialization time.

        Returns:
          the resulting signed token.
        """
        now = Jwt.timestamp()
        lifetime = lifetime or self.default_lifetime
        exp = now + lifetime
        leeway = leeway or self.default_leeway
        nbf = (now - leeway) if leeway is not None else None
        jti = self.generate_jti()
        extra_claims = extra_claims or {}
        claims = {
            key: value
            for key, value in dict(
                extra_claims,
                iss=self.issuer,
                aud=audience,
                sub=subject,
                iat=now,
                exp=exp,
                nbf=nbf,
                jti=jti,
            ).items()
            if value is not None
        }
        return Jwt.sign(claims, jwk=self.jwk, alg=self.alg, extra_headers=extra_headers)

    def generate_jti(self) -> str:
        """Generate Jwt Token ID (jti) values.

        Default uses UUID4. Can be overridden in subclasses.

        Returns:
            A unique value suitable for use as JWT Token ID (jti) claim.
        """
        return str(uuid.uuid4())
