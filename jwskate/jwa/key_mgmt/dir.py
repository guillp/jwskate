from typing import Any, Type

from binapy import BinaPy

from ..base import BaseKeyManagementAlg, BaseSymmetricAlg


class DirectKeyUse(BaseKeyManagementAlg, BaseSymmetricAlg):
    name = "dir"
    description = "Direct use of a shared symmetric key as the CEK"

    def sender_key(self, aesalg: Type[BaseSymmetricAlg], **headers: Any) -> BinaPy:
        aesalg.check_key(self.key)
        return BinaPy(self.key)

    def recipient_key(self, aesalg: Type[BaseSymmetricAlg], **headers: Any) -> BinaPy:
        aesalg.check_key(self.key)
        return BinaPy(self.key)
