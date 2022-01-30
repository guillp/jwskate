from typing import Any, Dict, Union


class BaseToken:
    def __init__(self, value: Union[bytes, str], max_size: int = 16 * 1024):
        """
        Initialize a Jwt from its string representation.

        :param value: the string or bytes representation of this Jwt
        :param max_size: if the JWT length is larger than this value, raise a `ValueError`. This is to avoid JSON deserialization vulnerabilities.
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
        """
        Check that a Jwt is equals to another.

        Works with other instances of Jwt, or with string or bytes.
        :param other: the other token to compare with
        :return: True if the other token has the same representation, False otherwise
        """
        if isinstance(other, BaseToken):
            return self.value == other.value
        if isinstance(other, str):
            return self.value.decode() == other
        if isinstance(other, bytes):
            return self.value == other
        return super().__eq__(other)

    def get_header(self, name: str) -> Any:
        """
        Get a header from this Jwt.

        :param name: the header name
        :return: the header value
        """
        return self.headers.get(name)

    def __repr__(self) -> str:
        """
        Returns the `str` representation of this JwsCompact
        :return: a `str`
        """
        return self.value.decode()

    def __bytes__(self) -> bytes:
        """
        Returns the `bytes` representation of this JwsCompact
        :return:
        """
        return self.value
