"""This module implements the Edwards-curve Digital Signature Algorithm (EdDSA)."""

from typing import SupportsBytes, Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
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

    def sign(self, data: Union[bytes, SupportsBytes]) -> BinaPy:  # noqa: D102
        if not isinstance(data, bytes):
            data = bytes(data)

        with self.private_key_required() as key:
            return BinaPy(key.sign(data))

    def verify(
        self, data: Union[bytes, SupportsBytes], signature: Union[bytes, SupportsBytes]
    ) -> bool:  # noqa: D102
        if not isinstance(data, bytes):
            data = bytes(data)
        if not isinstance(signature, bytes):
            signature = bytes(signature)

        with self.public_key_required() as key:
            try:
                key.verify(signature, data)
                return True
            except exceptions.InvalidSignature:
                return False


class Ed25519Dsa(
    BaseAsymmetricAlg[
        ed25519.Ed25519PrivateKey,
        ed25519.Ed25519PublicKey,
    ],
    BaseSignatureAlg,
):
    """EdDSA signature algorithm with Ed25519 curve."""

    description = __doc__
    hashing_alg = hashes.SHA256()

    private_key_class = ed25519.Ed25519PrivateKey
    public_key_class = ed25519.Ed25519PublicKey


class Ed448Dsa(
    BaseAsymmetricAlg[
        ed448.Ed448PrivateKey,
        ed448.Ed448PublicKey,
    ],
    BaseSignatureAlg,
):
    """EdDSA signature algorithm with Ed25519 curve."""

    description = __doc__
    hashing_alg = hashes.SHAKE256(114)

    private_key_class = ed448.Ed448PrivateKey
    public_key_class = ed448.Ed448PublicKey
