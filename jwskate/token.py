"""This module contains base classes for all tokens types handled by `jwskate`."""

from __future__ import annotations

from collections import UserDict
from functools import cached_property
from typing import Any

from binapy import BinaPy
from typing_extensions import Self

from jwskate.exceptions import JwskateError


class HeaderError(JwskateError):
    """Raised when a token header is missing, unexpected, or invalid."""

    def __init__(self, message: str, token: BaseCompactToken | BaseJsonDict, name: str, value: Any = None) -> None:
        super().__init__(message)
        self.token = token
        self.name = name
        self.value = value


class MissingHeader(HeaderError):
    """Raised when trying to access a header that is not present in a token."""

    def __init__(self, token: BaseCompactToken | BaseJsonDict, name: str) -> None:
        super().__init__(message=f"This token doesn't have a valid '{name}' claim.", token=token, name=name)


class InvalidHeader(HeaderError):
    """Raised when a header does not have the expected type in a token."""

    def __init__(self, token: BaseCompactToken | BaseJsonDict, name: str, value: Any) -> None:
        super().__init__(
            message=f"This token header '{name}'"
            " contains an unexpected value {claim_value}"
            " of type {type(claim_value)}",
            token=token,
            name=name,
            value=value,
        )


class MaximumTokenSizeExceeded(JwskateError):
    """Raised when a token value exceeds the maximum defined by `max_size`."""

    def __init__(self, token_size: int, max_size: int) -> None:
        super().__init__(
            f"This JWT size of {token_size} bytes exceeds {max_size} bytes, which is abnormally big. "
            "This size limit is made to avoid potential JSON deserialization vulnerabilities or issues. "
            "You can increase this limit by passing a different `max_size` value as parameter."
        )


class BaseCompactToken:
    """Base class for all tokens in Compact representation.

    This includes JWS, JWE, and JWT tokens.

    Args:
        value: the string or bytes representation of this JWS/JWE/JWT
        max_size: if the JWT length is larger than this value, raise a `MaximumTokenSizeExceeded`.
            This is to avoid JSON deserialization vulnerabilities.
            Set to 0 or negative value to accept a token of any size.

    Raises:
        MaximumTokenSizeExceeded: if the token size exceeds `max_size`.
    """

    def __init__(self, value: bytes | str, *, max_size: int = 16 * 1024) -> None:
        if isinstance(value, str):
            value = value.encode("ascii")

        if 0 < max_size < len(value):
            raise MaximumTokenSizeExceeded(token_size=len(value), max_size=max_size)

        value = b"".join(value.split())

        self.value = value
        self.headers: dict[str, Any]

    def __eq__(self, other: object) -> bool:
        """Check that a Jwt is equal to another.

        Works with other instances of `Jwt`, or with `str` or `bytes`.

        Args:
            other: the other token to compare with

        Returns:
            `True` if the other token has the same representation, `False` otherwise

        """
        if isinstance(other, BaseCompactToken):
            return self.value == other.value
        if isinstance(other, str):
            return self.value.decode() == other
        if isinstance(other, bytes):
            return self.value == other
        return super().__eq__(other)

    def get_header(self, name: str) -> Any:
        """Get a header from this Jwt.

        Args:
            name: the header name

        Returns:
            the header value

        """
        return self.headers.get(name)

    @cached_property
    def alg(self) -> str:
        """Get the signature algorithm (alg) from this token headers.

        Returns:
            the `alg` value
        Raises:
            MissingClaim: if the 'alg` header is missing
            InvalidClaim: if the `alg` header value is not a string

        """
        alg = self.get_header("alg")
        if alg is None:
            raise MissingHeader(self, "alg")
        if not isinstance(alg, str):
            raise InvalidHeader(self, "alg", alg)
        return alg

    @cached_property
    def kid(self) -> str:
        """Get the key id (kid) from this token headers.

        Returns:
            the `kid` value
        Raises:
            MissingClaim: if the `kid` header is missing
            InvalidClaim: if the `kid` header value is not a string

        """
        kid = self.get_header("kid")
        if kid is None:
            raise MissingHeader(self, "kid")
        if not isinstance(kid, str):
            raise InvalidHeader(self, "kid", kid)
        return kid

    @cached_property
    def typ(self) -> str:
        """Get the Type (typ) from this token headers.

        Returns:
            the `typ` value
        Raises:
            MissingClaim: if the `typ` header is missing
            InvalidClaim: if the `typ` header value is not a string

        """
        typ = self.get_header("typ")
        if typ is None:
            raise MissingHeader(self, "typ")
        if not isinstance(typ, str):
            raise InvalidHeader(self, "typ", typ)
        return typ

    @cached_property
    def cty(self) -> str:
        """Get the Content Type (typ) from this token's headers.

        Returns:
            the `cty` value
        Raises:
            MissingClaim: if the `cty` header is missing
            InvalidClaim: if the `cty` header value is not a string

        """
        cty = self.get_header("cty")
        if cty is None:
            raise MissingHeader(self, "cty")
        if not isinstance(cty, str):
            raise InvalidHeader(self, "cty", cty)
        return cty

    def __repr__(self) -> str:
        """Return the `str` representation of this token."""
        return self.value.decode()

    def __bytes__(self) -> bytes:
        """Return the `bytes` representation of this token."""
        return self.value


BaseUserDict = UserDict[str, Any]


class BaseJsonDict(BaseUserDict):
    """Base class Jwk and tokens in JSON representation."""

    @classmethod
    def from_json(cls, j: str) -> Self:
        """Initialize an object based on a string containing a JSON representation.

        Args:
          j: the JSON to parse, still serialized

        Returns:
            the resulting object

        """
        return cls(BinaPy(j).parse_from("json"))

    def to_json(self, *, compact: bool = True, **kwargs: Any) -> str:
        """Serialize the current object into a JSON representation.

        Args:
          compact: if True, don't include whitespaces or newlines in the result
          **kwargs: additional kwargs for json.dumps()

        Returns:
            a JSON representation of the current object

        """
        return BinaPy.serialize_to("json", self, compact=compact, **kwargs).decode()

    def to_dict(self) -> dict[str, Any]:
        """Transform this UserDict into an actual `dict`.

        This should only ever be required when serializing to JSON, since the default json
        serializer doesn't know how to handle UserDicts.

        """
        return {
            key: [
                dict(inner)
                if isinstance(inner, dict)
                else inner.to_dict()
                if isinstance(inner, BaseJsonDict)
                else inner
                for inner in val
            ]
            if isinstance(val, list)
            else dict(val)
            if isinstance(val, dict)
            else val.to_dict()
            if isinstance(val, BaseJsonDict)
            else val
            for key, val in self.data.items()
        }
