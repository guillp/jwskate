"""This module contains base classes for all tokens types handled by `jwskate`."""
import json
from typing import Any, Dict, Type, TypeVar, Union


class BaseCompactToken:
    """Base class for all tokens in Compact representation.

    This includes JWS, JWE, and JWT tokens.
    """

    def __init__(self, value: Union[bytes, str], max_size: int = 16 * 1024):
        """Initialize a JW{S,E,T} from its string representation.

        Args:
            value: the string or bytes representation of this Jwt
            max_size: if the JWT length is larger than this value, raise a `ValueError`.
                This is to avoid JSON deserialization vulnerabilities.
        """
        if len(value) > max_size:
            raise ValueError(
                f"This JWT size exceeds {max_size} bytes, which is abnormally big. "
                "This size limit is made to avoid potential JSON deserialization vulnerabilities or issues. "
                "You can increase this limit by passing a different `max_size` value as parameter."
            )

        if not isinstance(value, bytes):
            value = value.encode("ascii")

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
