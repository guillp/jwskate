from typing import Any

from jwskate.algorithms.base import KeyManagementAlg


class DirectKeyManagementAlg(KeyManagementAlg):
    name = "dir"
    description = "Direct use of a shared symmetric key as the CEK"

    @classmethod
    def check_key(cls, key: Any) -> None:
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")
