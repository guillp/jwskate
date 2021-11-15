"""This modules contains classes and utilities to generate and validate signed JWT."""

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

from binapy import BinaPy

from jwskate import Jwk

from .base import InvalidJwt, Jwt


class ExpiredJwt(ValueError):
    """Raised when an expired JWT is validated."""


class InvalidSignature(ValueError):
    """Raised when a JWT signature doesn't match the expected value."""


class InvalidClaim(ValueError):
    """Raised a signed JWT contains an invalid claim."""


class SignedJwt(Jwt):
    """
    Represents a Signed Json Web Token (JWT), as defined in RFC7519.

    A signed JWT contains a JSON object as payload, which represents claims.

    To sign a JWT, use [Jwt.sign][jwskate.jwt.Jwt.sign].
    """

    def __init__(self, value: Union[bytes, str]) -> None:
        """
        Initialize a `SignedJwt`, from its compact serialized value.

        :param value: the token value.
        """
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

    @property
    def signed_part(self) -> bytes:
        """
        Return the signed part of this JWT.

        The signed part is composed of the header and payload, in their Base64-Url encoding, joined by a dot.
        :return: the signed part as bytes
        """
        return b".".join(self.value.split(b".", 2)[:2])

    def verify_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        """
        Verify this JWT signature using a given key and algorithm.

        :param jwk: the private Jwk to use to verify the signature.
        :param alg: the alg to use to verify the signature.
        """
        jwk = Jwk(jwk)

        return jwk.verify(
            data=self.signed_part, signature=self.signature, alg=alg, algs=algs
        )

    def is_expired(self) -> Optional[bool]:
        """
        Check if this token is expired, based on its `exp` claim.

        :return: `True` if the token is expired, `False` if it's not, `None` if there is no `exp` claim.
        """
        exp = self.expires_at
        if exp is None:
            return None
        return exp < datetime.now()

    @property
    def expires_at(self) -> Optional[datetime]:
        """
        Return the token expiration date, from the `exp` claim.

        :return: a `datetime` initialized from the `exp` claim, or `None` if there is no `exp` claim.
        """
        exp = self.get_claim("exp")
        if not exp:
            return None
        exp_dt = datetime.fromtimestamp(exp)
        return exp_dt

    @property
    def issued_at(self) -> Optional[datetime]:
        """
        Return the token "issued at" date, from the `iat` claim.

        :return: a `datetime` initialized from the `iat` claim, or `None` if there is no `iat` claim.
        """
        iat = self.get_claim("iat")
        if not iat:
            return None
        iat_dt = datetime.fromtimestamp(iat)
        return iat_dt

    @property
    def not_before(self) -> Optional[datetime]:
        """
        Return the token "not before" date, from the `nbf` claim.

        :return: a `datetime` initialized from the `nbf` claim, or `None` if there is no `nbf` claim.
        """
        nbf = self.get_claim("nbf")
        if not nbf:
            return None
        nbf_dt = datetime.fromtimestamp(nbf)
        return nbf_dt

    @property
    def issuer(self) -> Optional[str]:
        """
        Return the token issuer.

        This validates that the `iss` claim is a string.
        :return: the issuer, as `str`, or `None` if there is no `ìss` claim.
        """
        iss = self.get_claim("iss")
        if iss is None or isinstance(iss, str):
            return iss
        raise AttributeError("iss has an unexpected type", type(iss))

    @property
    def audience(self) -> Optional[str]:
        """
        Return the token single audience, from the `aud` claim.

        If this token has multiple audiences, this will raise an `InvalidClaim`. Use `.audiences()` instead to get those
        audiences as a list.

        :return: the single audience from this token, from the `aud` claim.
        """
        aud = self.get_claim("aud")
        if aud is None or isinstance(aud, str):
            return aud
        if isinstance(aud, list):
            raise InvalidClaim(
                "this token has multiple audiences. Use SignedJwt.audiences() to get them as a list."
            )
        raise AttributeError("aud has an unexpected type", type(aud))

    @property
    def audiences(self) -> Optional[List[str]]:
        """
        Return the token audiences, from the `aud` claim.

        If this token has a single audience, this will return a `list` anyway. If you intend to get tokens that always
        contain a signle audience, use `.audience()` instead.

        :return: a list of audiences from this token, from the `aud` claim.
        """
        aud = self.get_claim("aud")
        if aud is None:
            return None
        if isinstance(aud, str):
            return [aud]
        if isinstance(aud, list):
            return aud
        raise AttributeError("aud has an unexpected type", type(aud))

    @property
    def subject(self) -> Optional[str]:
        """
        Return the token subject, from the `sub` claim.

        This validates that the `sub` claim is a string.
        :return: the subject, as `str`, or `None` if there is no `sub` claim.
        """
        sub = self.get_claim("sub")
        if sub is None or isinstance(sub, str):
            return sub
        raise AttributeError("sub has an unexpected type", type(sub))

    @property
    def jwt_token_id(self) -> Optional[str]:
        """
        Return the token Identifier, from the `jti` claim.

        This validates that the `jti` claim is a string.
        :return: the token identifier, as `str`, or `None` if there is no `jti` claim.
        """
        jti = self.get_claim("jti")
        if jti is None or isinstance(jti, str):
            return jti
        raise AttributeError("jti has an unexpected type", type(jti))

    @property
    def alg(self) -> Optional[str]:
        """
        Return the signing alg from the JWT header.

        :return: the token signing alg, from the header `alg`.
        """
        alg = self.get_header("alg")
        if alg is None or isinstance(alg, str):
            return alg
        raise AttributeError("alg has an unexpected type", type(alg))

    @property
    def kid(self) -> Optional[str]:
        """
        Return the signing key id from the JWT header.

        :return: the token signing key id, from the header `kid`.
        """
        kid = self.get_header("kid")
        if kid is None or isinstance(kid, str):
            return kid
        raise AttributeError("kid has an unexpected type", type(kid))

    def get_claim(self, key: str, default: Any = None) -> Any:
        """
        Get a claim from this Jwt.

        :param key: the claim name.
        :param default: a default value if the claim is not found.
        :return: the claim value if found, or `default` if not found.
        """
        return self.claims.get(key, default)

    def __getitem__(self, item: str) -> Any:
        """
        Allow claim access with subscription.

        :param item: the claim name.
        :return: the claim value.
        """
        value = self.get_claim(item)
        if value is None:
            raise KeyError(item)
        return value

    def __getattr__(self, item: str) -> Any:
        """
        Allow claim access as attributes.

        :param item: the claim name.
        :return: the claim value
        """
        value = self.get_claim(item)
        if value is None:
            raise AttributeError(item)
        return value

    def __str__(self) -> str:
        """
        Return the Jwt serialized value, as `str`.

        :return: the serialized token value.
        """
        return self.value.decode()

    def __bytes__(self) -> bytes:
        """
        Return the Jwt serialized value, as `bytes`.

        :return: the serialized token value.
        """
        return self.value

    def validate(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        issuer: Optional[str] = None,
        audience: Union[None, str] = None,
        check_exp: bool = True,
        **kwargs: Any,
    ) -> None:
        """
        Validate a `SignedJwt` signature and expected claims.

        This verifies the signature using the provided `jwk` and `alg`, then checks the token issuer, audience and expiration date.
        This can also check custom claims using `kwargs`, ut

        :param jwk: the signing key to use to verify the signature.
        :param alg: the signing alg to use to verify the signature.
        :param issuer: the expected issuer for this token.
        :param audience: the expected audience for this token.
        :param check_exp: ìf `True` (default), check that the token is not expired.
        :param kwargs: additionnal claims to validate.
        :return: `None`. Raises exceptions if any validation check fails.
        """
        if not self.verify_signature(jwk, alg):
            raise InvalidSignature("Signature is not valid.")

        if issuer is not None:
            if self.issuer != issuer:
                raise InvalidClaim("iss", "Unexpected issuer", self.issuer)

        if audience is not None:
            if self.audiences is None or audience not in self.audiences:
                raise InvalidClaim("aud", "Unexpected audience", self.audience)

        if check_exp:
            if self.is_expired():
                raise ExpiredJwt(f"This token expired at {self.expires_at}")

        for key, value in kwargs.items():
            if self.get_claim(key) != value:
                raise InvalidClaim(
                    key, f"unexpected value for claim {key}", self.get_claim(key)
                )
