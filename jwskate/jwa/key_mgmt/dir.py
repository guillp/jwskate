"""This module implements direct use of a shared symmetric key as Key Management algorithm."""

from typing import Type

from binapy import BinaPy

from ..base import BaseKeyManagementAlg, BaseSymmetricAlg


class DirectKeyUse(BaseKeyManagementAlg, BaseSymmetricAlg):
    """Direct use of a shared symmetric key as the CEK."""

    name = "dir"
    description = __doc__

    def direct_key(self, aesalg: Type[BaseSymmetricAlg]) -> BinaPy:
        """Check that the current key is appropriate for a given alg and return that same key.

        Args:
          aesalg: the AES encryption alg to use

        Returns:
          the current configured key, as-is
        """
        aesalg.check_key(self.key)
        return BinaPy(self.key)
