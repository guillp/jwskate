from typing import Union

from .base import Jwt


class EncryptedJwt(Jwt):
    def __init__(self, value: Union[bytes, str]):
        raise NotImplementedError
