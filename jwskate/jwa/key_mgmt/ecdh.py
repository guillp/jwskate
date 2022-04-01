"""This module implements Elliptic Curve Diffie-Hellman based Key Management algorithms."""

from typing import Any, Type

from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from ..base import BaseAsymmetricAlg, BaseKeyManagementAlg
from .aeskw import A128KW, A192KW, A256KW, BaseAesKeyWrap


class EcdhEs(
    BaseKeyManagementAlg,
    BaseAsymmetricAlg[
        asymmetric.ec.EllipticCurvePrivateKey, asymmetric.ec.EllipticCurvePublicKey
    ],
):
    """Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF."""

    name = "ECDH-ES"
    description = __doc__
    public_key_class = asymmetric.ec.EllipticCurvePublicKey
    private_key_class = asymmetric.ec.EllipticCurvePrivateKey

    @classmethod
    def otherinfo(cls, alg: str, apu: bytes, apv: bytes, keysize: int) -> BinaPy:
        """Build the "otherinfo" parameter for Concat KDF Hash.

        Args:
          alg: identifier for the encryption alg
          apu: Agreement PartyUInfo
          apv: Agreement PartyVInfo
          keysize: length of the generated key

        Returns:
            the "otherinfo" value
        """
        algorithm_id = BinaPy.from_int(len(alg), length=4) + BinaPy(alg)
        partyuinfo = BinaPy.from_int(len(apu), length=4) + apu
        partyvinfo = BinaPy.from_int(len(apv), length=4) + apv
        supppubinfo = BinaPy.from_int(keysize or keysize, length=4)
        otherinfo = b"".join((algorithm_id, partyuinfo, partyvinfo, supppubinfo))
        return BinaPy(otherinfo)

    @classmethod
    def ecdh(
        cls,
        private_key: asymmetric.ec.EllipticCurvePrivateKey,
        public_key: asymmetric.ec.EllipticCurvePublicKey,
    ) -> BinaPy:
        """This does an Elliptic Curve Diffie Hellman key exchange.

        This derives a shared key between a sender and a receiver, based on a public and a private key from each side.
        ECDH exchange produces the same key with either a sender private key and a recipient public key,
        or the matching sender public key and recipient private key.

        Args:
          private_key: a private EC key
          public_key: a public EC key

        Returns:
          a shared key
        """
        shared_key = private_key.exchange(asymmetric.ec.ECDH(), public_key)
        return BinaPy(shared_key)

    @classmethod
    def derive(
        cls,
        private_key: asymmetric.ec.EllipticCurvePrivateKey,
        public_key: asymmetric.ec.EllipticCurvePublicKey,
        otherinfo: bytes,
        keysize: int,
    ) -> BinaPy:
        """Derive a key using ECDH and Concat KDF Hash.

        Args:
          private_key: the private key
          public_key: the public key
          otherinfo: the Concat KDF "otherinfo" parameter
          keysize: the expected CEK key size

        Returns:
            the derived key
        """
        shared_key = cls.ecdh(private_key, public_key)
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(), length=keysize // 8, otherinfo=otherinfo
        )
        return BinaPy(ckdf.derive(shared_key))

    def generate_ephemeral_key(self) -> asymmetric.ec.EllipticCurvePrivateKey:
        """Generate an ephemeral key that is suitable for use with this algorithm.

        Returns:
            a generated EllipticCurvePrivateKey, on the same curve as this algorithm key
        """
        return asymmetric.ec.generate_private_key(self.key.curve)

    def sender_key(
        self,
        ephemeral_private_key: asymmetric.ec.EllipticCurvePrivateKey,
        alg: str,
        key_size: int,
        **headers: Any,
    ) -> BinaPy:
        """Compute a CEK for encryption of a message. This method is meant for usage by a sender.

        Args:
          ephemeral_private_key: the EPK to use for this key
          alg: the content encryption algorithm identifier
          key_size: the expected CEK size
          **headers: additional headers to include for CEK derivation

        Returns:
            the CEK for encryption by the sender
        """
        with self.public_key_required() as key:
            apu = BinaPy(headers.get("apu", b"")).decode_from("b64u")
            apv = BinaPy(headers.get("apv", b"")).decode_from("b64u")
            otherinfo = self.otherinfo(alg, apu, apv, key_size)
            cek = self.derive(ephemeral_private_key, key, otherinfo, key_size)
            return cek

    def recipient_key(
        self,
        ephemeral_public_key: asymmetric.ec.EllipticCurvePublicKey,
        alg: str,
        key_size: int,
        **headers: Any,
    ) -> BinaPy:
        """Compute a shared key. This method is meant for use by the recipient of an encrypted message.

        Args:
          ephemeral_public_key: the EPK, as received from sender
          alg: the content encryption algorithm identifier
          key_size: the CEK size
          **headers: additional headers as received from sender

        Returns:
            the CEK for decryption by the recipient
        """
        with self.private_key_required() as key:
            apu = BinaPy(headers.get("apu", b"")).decode_from("b64u")
            apv = BinaPy(headers.get("apv", b"")).decode_from("b64u")
            otherinfo = self.otherinfo(alg, apu, apv, key_size)
            cek = self.derive(key, ephemeral_public_key, otherinfo, key_size)
            return cek


class BaseEcdhEs_AesKw(EcdhEs):
    """Base class for ECDH-ES+AESKW algorithms."""

    kwalg: Type[BaseAesKeyWrap]

    def wrap_key_with_epk(
        self,
        plainkey: bytes,
        ephemeral_private_key: asymmetric.ec.EllipticCurvePrivateKey,
        **headers: Any,
    ) -> BinaPy:
        """Wraps a key for content encryption.

        Args:
          plainkey: the key to wrap
          ephemeral_private_key: the EPK to use
          **headers: additional headers for CEK derivation

        Returns:
            the wrapped CEK
        """
        aes_key = self.sender_key(
            ephemeral_private_key, key_size=self.kwalg.key_size, **headers
        )
        return self.kwalg(aes_key).wrap_key(plainkey)

    def unwrap_key_with_epk(
        self,
        cipherkey: bytes,
        ephemeral_public_key: asymmetric.ec.EllipticCurvePublicKey,
        **headers: Any,
    ) -> BinaPy:
        """Unwrap a key for content decryption.

        Args:
          cipherkey: the wrapped key
          ephemeral_public_key: the EPK
          **headers: additional headers for CEK derivation

        Returns:
            the unwrapped key
        """
        aes_key = self.recipient_key(
            ephemeral_public_key, key_size=self.kwalg.key_size, **headers
        )
        return self.kwalg(aes_key).unwrap_key(cipherkey)


class EcdhEs_A128KW(BaseEcdhEs_AesKw):
    """ECDH-ES using Concat KDF and "A128KW" wrapping."""

    name = "ECDH-ES+A128KW"
    description = __doc__
    kwalg = A128KW


class EcdhEs_A192KW(BaseEcdhEs_AesKw):
    """ECDH-ES using Concat KDF and "A192KW" wrapping."""

    name = "ECDH-ES+A192KW"
    description = __doc__
    kwalg = A192KW


class EcdhEs_A256KW(BaseEcdhEs_AesKw):
    """ECDH-ES using Concat KDF and "A256KW" wrapping."""

    name = "ECDH-ES+A256KW"
    description = __doc__
    kwalg = A256KW