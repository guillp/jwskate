"""This modules contains the `Jwt` base class."""

from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from jwskate.jwk import Jwk

from ..jose import BaseJose
from ..utils import b64u_encode, b64u_encode_json

if TYPE_CHECKING:
    from jwskate import EncryptedJwt, SignedJwt


class InvalidJwt(ValueError):
    """Raised when an invalid Jwt is parsed."""


class Jwt(BaseJose):
    """Represents a Json Web Token."""

    def __new__(cls, value: Union[bytes, str]):  # type: ignore
        """
        Allow parsing both Signed and Encrypted Jwts. Returns the appropriate subclass.

        :param value: the token value
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
        """
        Sign a JSON payload with a `Jwk` and returns the resulting `SignedJwt`.

        :param claims: the payload to sign
        :param jwk: the Jwk to use for signing
        :param alg: the alg to use for signing
        :param extra_headers: additional headers to include in the Jwt
        :return: a `SignedJwt`
        """
        from .signed import SignedJwt

        jwk = Jwk(jwk)

        if not jwk.is_private:
            raise ValueError("Signing requires a private JWK")

        alg = alg or jwk.get("alg")
        kid = jwk.get("kid")

        if alg is None:
            raise ValueError("a signing alg is required")

        headers = dict(extra_headers or {}, alg=alg)
        if kid:
            headers["kid"] = kid

        headers_part = b64u_encode_json(headers)
        claims_part = b64u_encode_json(claims)
        signed_value = ".".join((headers_part, claims_part))
        signature = b64u_encode(jwk.sign(signed_value.encode(), alg=alg))
        return SignedJwt(".".join((signed_value, signature)))

    @classmethod
    def unprotected(
        cls,
        claims: Dict[str, Any],
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> "SignedJwt":
        """
        Generate a JWT that is not signed and not encrypted (with alg=none).

        :param claims: the claims to set in the token.
        :param extra_headers: additional headers to insert in the token.
        """
        from .signed import SignedJwt

        headers = dict(extra_headers or {}, alg="none")

        headers_part = b64u_encode_json(headers)
        claims_part = b64u_encode_json(claims)
        signed_value = ".".join((headers_part, claims_part))
        signature = ""
        return SignedJwt(".".join((signed_value, signature)))

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
        """
        Sign then encrypt a payload with a `Jwk` and returns the resulting `EncryptedJwt`.

        :param claims: the payload to encrypt
        :param sign_jwk: the Jwk to use for signature
        :param sign_alg: the alg to use for signature
        :param enc_jwk: the Jwk to use for encryption
        :param enc_alg: the alg to use for CEK encryption
        :param enc: the alg to use for payload encryption
        :return: an EncryptedJwt
        """
        from .encrypted import EncryptedJwt

        raise NotImplementedError
