import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Union

from jwskate import Jwk

from .base import Jwt
from .signed import SignedJwt


class JwtSigner:
    """
    An helper class to easily sign JWTs containing the standardised claims `ìat`, `exp`, `nbf`, `iss`, `sub`, `aud`, and `jti`,
    along with your own custom claims.
    The issuer, signing keys, signing alg and default lifetime are defined at initialization time, so you only have
    to define the subject, audience and custom claims when calling `JwtSigner.sign()`.
    This can be used as an alternative to `Jwt.sign()`.
    """

    def __init__(
        self,
        issuer: str,
        jwk: Jwk,
        alg: Optional[str] = None,
        default_lifetime: int = 60,
        default_leeway: Optional[int] = None,
    ):
        """
        :param issuer: the issuer string to use as `ìss` claim for signed tokens.
        :param jwk: the private Jwk to use to sign tokens.
        :param alg: the signing alg to use to sign tokens.
        :param default_lifetime: the default lifetime, in seconds, to use for claim `exp`. This can be overridden
        when calling `.sign()`
        :param default_leeway: the default leeway, in seconds, to use for claim `nbf`. If None, no `nbf` claim is
        included. This can be overridden when calling `.sign()`
        """
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
        """
        Signs a Jwt.
        :param subject: the subject to include in claim `sub`.
        :param audience: the audience identifier(s) to include in claim `aud`.
        :param extra_claims: additional claims to include in the signed token.
        :param extra_headers: additional headers to include in the header part.
        :param lifetime: lifetime, in seconds, to use for the `exp` claim. If None, use the default_lifetime defined at
        initialization time.
        :param leeway: leeway, in seconds, to use for the `nbf` claim. If None, use the default_leeway defined at
        initialization time.
        """
        now = int(datetime.now().timestamp())
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
        """
        A generator for Jwt Token Ids (jti) claims. Default uses UUID4.
        Can be overridden in subclasses.
        """
        return str(uuid.uuid4())
