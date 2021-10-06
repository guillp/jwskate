from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

from jwskate import Jwk
from jwskate.utils import b64u_decode, b64u_decode_json

from .base import InvalidJwt, Jwt


class ExpiredJwt(ValueError):
    pass


class InvalidSignature(ValueError):
    pass


class InvalidClaim(ValueError):
    pass


class SignedJwt(Jwt):
    """
    Represents a Signed Json Web Token (JWT), as defined in RFC7519.
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
            self.headers = b64u_decode_json(header)
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT header: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.claims = b64u_decode_json(payload)
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT payload: it must be a Base64URL-encoded JSON object"
            )

        try:
            self.signature = b64u_decode(signature)
        except ValueError:
            raise InvalidJwt(
                "Invalid JWT signature: it must be a Base64URL-encoded binary data (bytes)"
            )

    @property
    def signed_part(self) -> bytes:
        return b".".join(self.value.split(b".", 2)[:2])

    def verify_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[Union[str, Iterable[str]]] = None,
    ) -> bool:
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        return jwk.verify(self.signed_part, self.signature, alg)

    def is_expired(self) -> Optional[bool]:
        exp = self.expires_at
        if exp is None:
            return None
        return exp < datetime.now()

    @property
    def expires_at(self) -> Optional[datetime]:
        exp = self.get_claim("exp")
        if not exp:
            return None
        exp_dt = datetime.fromtimestamp(exp)
        return exp_dt

    @property
    def issued_at(self) -> Optional[datetime]:
        iat = self.get_claim("iat")
        if not iat:
            return None
        iat_dt = datetime.fromtimestamp(iat)
        return iat_dt

    @property
    def not_before(self) -> Optional[datetime]:
        nbf = self.get_claim("nbf")
        if not nbf:
            return None
        nbf_dt = datetime.fromtimestamp(nbf)
        return nbf_dt

    @property
    def issuer(self) -> Optional[str]:
        try:
            iss = self.iss
            if isinstance(iss, str):
                return iss
            raise AttributeError("iss has an unexpected type", type(iss))
        except AttributeError:
            return None

    @property
    def audience(self) -> Optional[List[str]]:
        try:
            aud = self.aud
            if isinstance(aud, str):
                return [aud]
            elif isinstance(aud, list):
                return aud
            raise AttributeError("aud has an unexpected type", type(aud))
        except AttributeError:
            return None

    @property
    def subject(self) -> Optional[str]:
        try:
            sub = self.sub
            if isinstance(sub, str):
                return sub
            raise AttributeError("sub has an unexpected type", type(sub))
        except AttributeError:
            return None

    @property
    def jwt_token_id(self) -> Optional[str]:
        try:
            jti = self.jti
            if isinstance(jti, str):
                return jti
            raise AttributeError("jti has an unexpected type", type(jti))
        except AttributeError:
            return None

    @property
    def alg(self) -> str:
        return self.get_header("alg")  # type: ignore

    @property
    def kid(self) -> str:
        return self.get_header("kid")  # type: ignore

    def get_claim(self, key: str) -> Any:
        return self.claims.get(key)

    def __getattr__(self, item: str) -> Any:
        value = self.get_claim(item)
        if value is None:
            raise AttributeError(item)
        return value

    def __str__(self) -> str:
        return self.value.decode()

    def __bytes__(self) -> bytes:
        return self.value

    def validate(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        issuer: Optional[str] = None,
        audience: Union[None, str, List[str]] = None,
        check_exp: bool = True,
        **kwargs: Any,
    ) -> None:
        if not self.verify_signature(jwk):
            raise InvalidSignature("Signature is not valid.")

        if issuer is not None:
            if self.issuer != issuer:
                raise InvalidClaim("iss", "Unexpected issuer", self.issuer)

        if audience is not None:
            if isinstance(audience, str):
                audience = [audience]
            if self.audience != audience:
                raise InvalidClaim("aud", "Unexpected audience", self.audience)

        if check_exp:
            if self.is_expired():
                raise ExpiredJwt(f"This token expired at {self.expires_at}")

        for key, value in kwargs.items():
            if self.get_claim(key) != value:
                raise InvalidClaim(
                    key, f"unexpected value for claim {key}", self.get_claim(key)
                )
