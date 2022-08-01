"""This module implements Encrypted JWT token handling."""

from typing import Union

from .base import Jwt


class EncryptedJwt(Jwt):
    """Represent an encrypted JWT.

    Args:
        value: the serialized JWT value
    """

    def __init__(self, value: Union[bytes, str]):
        raise NotImplementedError
