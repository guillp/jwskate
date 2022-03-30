"""This module implements Encrypted JWT token handling."""

from typing import Union

from .base import Jwt


class EncryptedJwt(Jwt):
    """Represent an encrypted JWT."""

    def __init__(self, value: Union[bytes, str]):
        """Initialize an EncryptedJwt based on its serialized value."""
        raise NotImplementedError
