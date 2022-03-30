"""This module implements the Edwards-curve Digital Signature Algorithm (EdDSA)."""

from typing import Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519

from ..base import BaseAsymmetricAlg, BaseSignatureAlg


class EdDsa(
    BaseAsymmetricAlg[
        Union[ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey],
        Union[ed25519.Ed25519PublicKey, ed448.Ed448PublicKey],
    ],
    BaseSignatureAlg,
):
    """EdDSA signature algorithms."""

    private_key_class = (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)
    public_key_class = (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)

    name = "EdDSA"
    description = __doc__

    def sign(self, data: bytes) -> BinaPy:  # noqa: D102
        with self.private_key_required() as key:
            return BinaPy(key.sign(data))

    def verify(self, data: bytes, signature: bytes) -> bool:  # noqa: D102
        with self.public_key_required() as key:
            try:
                key.verify(signature, data)
                return True
            except exceptions.InvalidSignature:
                return False
