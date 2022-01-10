from ..base import KeyGenerationAlg, SymmetricAlg


class DirectKeyUse(KeyGenerationAlg, SymmetricAlg):
    name = "dir"
    description = "Direct use of a shared symmetric key as the CEK"
