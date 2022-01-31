from typing import Type

from binapy import BinaPy

from ..base import BaseKeyManagementAlg, BaseSymmetricAlg


class DirectKeyUse(BaseKeyManagementAlg, BaseSymmetricAlg):
    """Direct use of a shared symmetric key as the CEK"""

    name = "dir"
    description = __doc__

    def sender_key(self, aesalg: Type[BaseSymmetricAlg]) -> BinaPy:
        aesalg.check_key(self.key)
        return BinaPy(self.key)

    def recipient_key(self, aesalg: Type[BaseSymmetricAlg]) -> BinaPy:
        aesalg.check_key(self.key)
        return BinaPy(self.key)
