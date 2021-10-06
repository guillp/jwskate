from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from jwskate.jwk import Jwk

from ..utils import b64u_encode, b64u_encode_json

if TYPE_CHECKING:
    from jwskate import SignedJwt, EncryptedJwt


class InvalidJwt(ValueError):
    """Raised when an invalid Jwt is parsed"""


class Jwt:
    """Represents a Json Web Token"""

    def __new__(cls, value: Union[bytes, str]):  # type: ignore
        """
        Allows parsing both Signed and Encrypted Jwts. Returns the appropriate subclass.
        :param value:
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

    def __init__(self, value: Union[bytes, str]):
        """
        Initializes an Jwt from its string representation.
        :param value: the string or bytes representation of this Jwt
        """
        if not isinstance(value, bytes):
            value = value.encode("ascii")

        self.value = value
        self.headers: Dict[str, Any]

    def __eq__(self, other: Any) -> bool:
        """
        Checks that a Jwt is equals to another. Works with other instances of Jwt, or with string or bytes.
        :param other: the other token to compare with
        :return: True if the other token has the same representation, False otherwise
        """
        if isinstance(other, Jwt):
            return self.value == other.value
        if isinstance(other, str):
            return self.value.decode() == other
        if isinstance(other, bytes):
            return self.value == other
        return super().__eq__(other)

    def get_header(self, name: str) -> Any:
        """
        Returns an header from this Jwt
        :param name: the header name
        :return: the header value
        """
        return self.headers.get(name)

    @classmethod
    def sign(
        cls,
        claims: Dict[str, Any],
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> "SignedJwt":
        """
        Signs a JSON payload with a Jwk and returns the resulting SignedJwt
        :param claims: the payload to sign
        :param jwk: the Jwk to use for signing
        :param alg: the alg to use for signing
        :param extra_headers: additional headers to include in the Jwt
        :return: a SignedJwt
        """
        from .signed import SignedJwt

        if not isinstance(jwk, Jwk):
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
        Generates a JWT that is not signed and not encrypted (with alg=none)
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
        Sign then encrypts a payload with a Jwk and returns the resulting EncryptedJwt
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

    def __bytes__(self) -> bytes:
        return self.value

    def __repr__(self) -> str:
        return self.value.decode()
