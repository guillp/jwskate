"""
This module contains classes that describe CFRG Elliptic Curve Diffie-Hellman algorithms as specified in RFC8037.
"""

from dataclasses import dataclass
from typing import Callable, Protocol, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519


class PublicKeyProtocol(Protocol):
    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        ...


class PrivateKeyProtocol(Protocol):
    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        ...

    def public_key(self) -> PublicKeyProtocol:
        ...


@dataclass
class OKPCurve:
    name: str
    description: str
    generator: Callable[[], PrivateKeyProtocol]
    use: str

    def generate(self) -> Tuple[bytes, bytes]:
        key = self.generator()
        x = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        d = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return x, d


Ed25519 = OKPCurve(
    name="Ed25519",
    description="Ed25519 signature algorithm key pairs",
    generator=ed25519.Ed25519PrivateKey.generate,
    use="sig",
)
Ed448 = OKPCurve(
    name="Ed448",
    description="Ed448 signature algorithm key pairs",
    generator=ed448.Ed448PrivateKey.generate,
    use="sig",
)
X25519 = OKPCurve(
    name="X25519",
    description="X25519 function key pairs",
    generator=x25519.X25519PrivateKey.generate,
    use="enc",
)
X448 = OKPCurve(
    name="X448",
    description="X448 function key pairs",
    generator=x448.X448PrivateKey.generate,
    use="enc",
)
