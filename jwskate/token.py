"""This module contains base classes for all tokens types handled by `jwskate`."""
import json
from typing import Any, Dict, Type, TypeVar, Union

from backports.cached_property import cached_property


class BaseCompactToken:
    """Base class for all tokens in Compact representation.

    This includes JWS, JWE, and JWT tokens.

    Args:
        value: the string or bytes representation of this JWS/JWE/JWT
        max_size: if the JWT length is larger than this value, raise a `ValueError`.
            This is to avoid JSON deserialization vulnerabilities.
    """

    def __init__(self, value: Union[bytes, str], max_size: int = 16 * 1024):
        if len(value) > max_size:
            raise ValueError(
                f"This JWT size exceeds {max_size} bytes, which is abnormally big. "
                "This size limit is made to avoid potential JSON deserialization vulnerabilities or issues. "
                "You can increase this limit by passing a different `max_size` value as parameter."
            )

        if isinstance(value, str):
            value = value.encode("ascii")

        value = b"".join(value.split())

        self.value = value
        self.headers: Dict[str, Any]

    def __eq__(self, other: Any) -> bool:
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
            AttributeError: if the `alg` header value is not a string
        """
        alg = self.get_header("alg")
        if alg is None or not isinstance(alg, str):  # pragma: no branch
            raise AttributeError("This token doesn't have a valid 'alg' header")
        return alg

    @cached_property
    def kid(self) -> str:
        """Get the key id (kid) from this token headers.

        Returns:
            the `kid` value
        Raises:
            AttributeError: if the `kid` header value is not a string
        """
        kid = self.get_header("kid")
        if kid is None or not isinstance(kid, str):
            raise AttributeError("This token doesn't have a valid 'kid' header")
        return kid

    @cached_property
    def typ(self) -> str:
        """Get the Type (typ) from this token headers.

        Returns:
            the `typ` value
        Raises:
            AttributeError: if the `typ` header value is not a string
        """
        typ = self.get_header("typ")
        if typ is None or not isinstance(typ, str):  # pragma: no branch
            raise AttributeError("This token doesn't have a valid 'typ' header")
        return typ

    @cached_property
    def cty(self) -> str:
        """Get the Type (typ) from this token headers.

        Returns:
            the `typ` value
        Raises:
            AttributeError: if the `typ` header value is not a string
        """
        cty = self.get_header("cty")
        if cty is None or not isinstance(cty, str):  # pragma: no branch
            raise AttributeError("This token doesn't have a valid 'cty' header")
        return cty

    def __repr__(self) -> str:
        """Returns the `str` representation of this token."""
        return self.value.decode()

    def __bytes__(self) -> bytes:
        """Return the `bytes` representation of this token."""
        return self.value


D = TypeVar("D", bound="BaseJsonDict")


class BaseJsonDict(Dict[str, Any]):
    """Base class Jwk and tokens in JSON representation."""

    @classmethod
    def from_json(cls: Type[D], j: str) -> D:
        """Initialize an object based on a string containing a JSON representation.

        Args:
          j: the JSON to parse, still serialized

        Returns:
            the resulting object
        """
        return cls(json.loads(j))

    def to_json(self, *args: Any, **kwargs: Any) -> str:
        """Serialize the current object into a JSON representation.

        Args:
          *args: additional args for json.dumps()
          **kwargs: additional kwargs for json.dumps()

        Returns:
            a JSON representation of the current object
        """
        return json.dumps(self, *args, **kwargs)
