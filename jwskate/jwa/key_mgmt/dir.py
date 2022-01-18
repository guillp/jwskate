from typing import Any, Type

from binapy import BinaPy

from ..base import KeyManagementAlg, SymmetricAlg


class DirectKeyUse(KeyManagementAlg, SymmetricAlg):
    name = "dir"
    description = "Direct use of a shared symmetric key as the CEK"

    def sender_key(self, aesalg: Type[SymmetricAlg], **headers: Any) -> BinaPy:
        aesalg.check_key(self.key)
        return BinaPy(self.key)

    def recipient_key(self, aesalg: Type[SymmetricAlg], **headers: Any) -> BinaPy:
        aesalg.check_key(self.key)
        return BinaPy(self.key)
