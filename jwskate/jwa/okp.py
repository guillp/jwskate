"""This module implements CFRG Elliptic Curve Diffie-Hellman algorithms as specified in [RFC8037].

[RFC8037]
: https: //www.rfc-editor.org/rfc/rfc8037.html

"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519
from typing_extensions import Protocol


@runtime_checkable
class PublicKeyProtocol(Protocol):
    """A protocol that each `cryptography` ECDH public key class implements."""

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:  # noqa: D102
        ...


@runtime_checkable
class PrivateKeyProtocol(Protocol):
    """A protocol that each `cryptography` ECDH private key class implements."""

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:  # noqa: D102
        ...

    def public_key(self) -> PublicKeyProtocol:  # noqa: D102
        ...

    @classmethod
    def generate(cls) -> PrivateKeyProtocol:  # noqa: D102
        ...


@dataclass
class OKPCurve:
    """Represent an Octet Key Pair (OKP) Curve."""

    name: str
    """Curve name as defined in [IANA JOSE](https://www.iana.org/assignments/jose/jose.xhtml#web-
    key-elliptic-curve).

    This name will appear in `crv` headers.
    """

    description: str
    """Curve description (human readable)."""

    cryptography_private_key_class: type[Any]
    """`cryptography` private key class."""

    cryptography_public_key_class: type[Any]
    """`cryptography` public key class."""

    use: str
    """Curve usage (`'sig'` or '`enc'`)."""

    instances: ClassVar[dict[str, OKPCurve]] = {}
    """Registry of subclasses, in a {name: instance} mapping."""

    def __post_init__(self) -> None:
        """Automatically registers subclasses in the instance registry."""
        self.instances[self.name] = self


Ed25519 = OKPCurve(
    name="Ed25519",
    description="Ed25519 signature algorithm key pairs",
    cryptography_private_key_class=ed25519.Ed25519PrivateKey,
    cryptography_public_key_class=ed25519.Ed25519PublicKey,
    use="sig",
)
"""Ed25519 curve."""

Ed448 = OKPCurve(
    name="Ed448",
    description="Ed448 signature algorithm key pairs",
    cryptography_private_key_class=ed448.Ed448PrivateKey,
    cryptography_public_key_class=ed448.Ed448PublicKey,
    use="sig",
)
"""Ed448 curve."""

X25519 = OKPCurve(
    name="X25519",
    description="X25519 function key pairs",
    cryptography_private_key_class=x25519.X25519PrivateKey,
    cryptography_public_key_class=x25519.X25519PublicKey,
    use="enc",
)
"""X25519 curve."""

X448 = OKPCurve(
    name="X448",
    description="X448 function key pairs",
    cryptography_private_key_class=x448.X448PrivateKey,
    cryptography_public_key_class=x448.X448PublicKey,
    use="enc",
)
"""X448 curve."""
