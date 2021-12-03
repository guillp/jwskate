from typing import Any, Mapping, Type

from binapy import BinaPy
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from jwskate.algorithms.base import DiffieHellmanAlg, EncryptionAlg


class ECDH_ES(
    DiffieHellmanAlg[
        asymmetric.ec.EllipticCurvePrivateKey, asymmetric.ec.EllipticCurvePublicKey
    ]
):
    name = "ECDH-ES"
    description = (
        "Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF"
    )

    def generate_ephemeral_key(self) -> asymmetric.ec.EllipticCurvePrivateKey:
        return asymmetric.ec.generate_private_key(self.key.curve)

    def sender_key(
        self,
        ephemeral_private_key: asymmetric.ec.EllipticCurvePrivateKey,
        headers: Mapping[str, Any],
        encalg: Type[EncryptionAlg],
    ) -> BinaPy:
        apu = BinaPy(headers.get("apu", b"")).decode_from("b64u")
        apv = BinaPy(headers.get("apv", b"")).decode_from("b64u")
        otherinfo = self.otherinfo(encalg.name, apu, apv, encalg.key_size)
        cek = self.derive(ephemeral_private_key, self.key, otherinfo, encalg.key_size)
        return cek

    def recipient_key(
        self,
        ephemeral_public_key: asymmetric.ec.EllipticCurvePublicKey,
        headers: Mapping[str, Any],
        encalg: Type[EncryptionAlg],
    ) -> BinaPy:
        apu = BinaPy(headers.get("apu", b"")).decode_from("b64u")
        apv = BinaPy(headers.get("apv", b"")).decode_from("b64u")
        otherinfo = self.otherinfo(encalg.name, apu, apv, encalg.key_size)
        cek = self.derive(self.key, ephemeral_public_key, otherinfo, encalg.key_size)
        return cek

    @classmethod
    def otherinfo(cls, alg: str, apu: bytes, apv: bytes, keysize: int) -> BinaPy:
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
        """
        This does an Elliptic Curve Diffie Hellman key exchange.

        This derive a shared key between a sender and a receiver, based on a public and a private key from each side.
        ECDH exchange produces the same key with either a sender private key and a recipient public key,
        or the matching sender public key and recipient private key.
        :param private_key: a private EC key
        :param public_key: a public EC key
        :return: a shared key
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
        shared_key = cls.ecdh(private_key, public_key)
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(), length=keysize // 8, otherinfo=otherinfo
        )
        return BinaPy(ckdf.derive(shared_key))


class ECDH_ES_AESKW(ECDH_ES):
    pass
