from dataclasses import dataclass
from typing import Any, Generic, Mapping, Optional, Type, TypeVar, Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import (
    asymmetric,
    ciphers,
    constant_time,
    hashes,
    hmac,
    keywrap,
    padding,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import aead, algorithms, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash


class Alg:
    name: str
    description: str

    def __init__(self, key: Any):
        self.check_key(key)
        self.key = key

    @classmethod
    def check_key(cls, key: Any) -> None:
        ...

    @classmethod
    def supports_key(cls, key: Any) -> bool:
        try:
            cls.check_key(key)
            return True
        except Exception:
            return False

    def __str__(self) -> str:
        return self.name


class SignatureAlg(Alg):
    def sign(self, data: bytes) -> bytes:
        ...

    def verify(self, data: bytes) -> bytes:
        ...


class EncryptionAlg(Alg):
    key_size: int

    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> bytes:
        ...

    def decrypt(self, iv: bytes, ciphertext: bytes, aad: Optional[bytes]) -> bytes:
        ...


class HMACSigAlg(SignatureAlg):
    mac: Type[hmac.HMAC] = hmac.HMAC
    hash_alg: hashes.HashAlgorithm
    min_key_size: int


class HS256(HMACSigAlg):
    name = "HS256"
    description = "HMAC using SHA-256"
    hash_alg = hashes.SHA256()
    min_key_size = 256


class HS384(HMACSigAlg):
    name = "HS384"
    description = "HMAC using SHA-384"
    hash_alg = hashes.SHA384()
    min_key_size = 384


class HS512(HMACSigAlg):
    name = "HS512"
    description = "HMAC using SHA-512"
    hash_alg = hashes.SHA512()
    min_key_size = 512


class KeyManagementAlg(Alg):
    pass


class KeyWrappingAlg(KeyManagementAlg):
    def wrap_key(self, plainkey: bytes) -> bytes:
        ...

    def unwrap_key(self, cipherkey: bytes) -> bytes:
        ...


Kpriv = TypeVar("Kpriv")
Kpub = TypeVar("Kpub")


class KeyAgreementAlg(KeyManagementAlg, Generic[Kpriv, Kpub]):
    def generate_ephemeral_key(self) -> Kpriv:
        ...

    def sender_key(
        self,
        ephemeral_key: Kpriv,
        headers: Mapping[str, Any],
        encalg: Type[EncryptionAlg],
    ) -> bytes:
        ...

    def recipient_key(
        self,
        ephemeral_public_key: Kpub,
        headers: Mapping[str, Any],
        encalg: Type[EncryptionAlg],
    ) -> bytes:
        ...


class DirectKeyManagementAlg(KeyManagementAlg):
    name = "dir"
    description = "Direct use of a shared symmetric key as the CEK"

    @classmethod
    def check_key(cls, key: Any) -> None:
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")


class AESEncryptionAlg(EncryptionAlg):
    iv_size: int
    tag_size: int

    @classmethod
    def supports_key(cls, key: Any) -> bool:
        return isinstance(key, bytes) and len(key) * 8 == cls.key_size


class AESGCM(AESEncryptionAlg):
    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> bytes:
        return aead.AESGCM(self.key).encrypt(iv, plaintext, aad)

    def decrypt(self, iv: bytes, ciphertext: bytes, aad: Optional[bytes]) -> bytes:
        return aead.AESGCM(self.key).decrypt(iv, ciphertext, aad)


class A128GCM(AESGCM):
    name = "A128GCM"
    description = "AES GCM using 128-bit key"
    key_size = 128
    iv_size = 96
    tag_size = 16


class A192GCM(AESGCM):
    name = "A192GCM"
    description = "AES GCM using 192-bit key"
    key_size = 192
    iv_size = 96
    tag_size = 16


class A256GCM(AESGCM):
    name = "A256GCM"
    description = "AES GCM using 256-bit key"
    key_size = 256
    iv_size = 96
    tag_size = 16


class AesCbcHmacSha2(AESEncryptionAlg):
    mac_key_size: int
    aes_key_size: int
    iv_size: int = 16
    hash_alg: hashes.HashAlgorithm

    def __init_subclass__(cls) -> None:
        cls.key_size = cls.mac_key_size + cls.aes_key_size

    @classmethod
    def supports_key(cls, key: Any) -> bool:
        return isinstance(key, bytes) and len(key) * 8 == cls.key_size

    def __init__(self, key: bytes) -> None:
        super().__init__(key)
        self.mac_key = self.key[: self.mac_key_size // 8]
        self.aes_key = self.key[self.mac_key_size // 8 :]
        self.padding = padding.PKCS7(algorithms.AES.block_size)

    def mac(self, aad: Optional[bytes], iv: bytes, ciphertext: bytes) -> bytes:
        if aad is None:
            aad = b""
        al = BinaPy.from_int(len(aad) * 8, length=8, byteorder="big", signed=False)
        hasher = hmac.HMAC(self.mac_key, self.hash_alg)
        for param in (aad, iv, ciphertext, al):
            hasher.update(param)
        digest = hasher.finalize()
        mac = digest[: self.tag_size]
        return mac

    def encrypt(self, iv: bytes, plaintext: bytes, aad: Optional[bytes]) -> bytes:
        cipher = ciphers.Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).encryptor()
        padder = self.padding.padder()
        padded_text = padder.update(plaintext) + padder.finalize()
        ciphertext = cipher.update(padded_text) + cipher.finalize()
        mac = self.mac(aad, iv, ciphertext)
        return ciphertext + mac

    def decrypt(
        self, iv: bytes, ciphertext_with_tag: bytes, aad: Optional[bytes]
    ) -> bytes:
        ciphertext, tag = BinaPy(ciphertext_with_tag).cut_at(-self.tag_size)
        mac = self.mac(aad, iv, ciphertext)
        if not constant_time.bytes_eq(mac, tag):
            raise exceptions.InvalidSignature()

        cipher = ciphers.Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).decryptor()
        padded_text = cipher.update(ciphertext) + cipher.finalize()
        unpadder = self.padding.unpadder()
        return unpadder.update(padded_text) + unpadder.finalize()


class Aes128CbcHmacSha256(AesCbcHmacSha2):
    name = "A128CBC-HS256"
    description = "AES_128_CBC_HMAC_SHA_256"
    mac_key_size = 128
    aes_key_size = 128
    hash_alg = hashes.SHA256()
    tag_size = 16


class Aes192CbcHmacSha384(AesCbcHmacSha2):
    name = "A192CBC-HS384"
    description = "AES_192_CBC_HMAC_SHA_384"
    mac_key_size = 192
    aes_key_size = 192
    hash_alg = hashes.SHA384()
    tag_size = 24


class Aes256CbcHmacSha512(AesCbcHmacSha2):
    name = "A256CBC-HS512"
    description = "AES_256_CBC_HMAC_SHA_512"
    key_size = 512
    mac_key_size = 256
    aes_key_size = 256
    iv_size = 16
    tag_size = 32
    hash_alg = hashes.SHA512()


class AesKeyWrap(KeyWrappingAlg):
    key_size: int

    def __init__(self, key: bytes):
        self.check_key(key)
        self.key = key

    @classmethod
    def check_key(cls, key: bytes) -> None:
        if len(key) * 8 != cls.key_size:
            raise ValueError(
                f"This key size of {len(key) * 8} bits doesn't match the expected keysize of {cls.key_size} bits"
            )

    def wrap_key(self, plainkey: bytes) -> bytes:
        return keywrap.aes_key_wrap(self.key, plainkey)

    def unwrap_key(self, cipherkey: bytes) -> bytes:
        return keywrap.aes_key_unwrap(self.key, cipherkey)


class A128KW(AesKeyWrap):
    name = "A128KW"
    description = "AES Key Wrap with default initial value using 128-bit key"
    key_size = 128


class A192KW(AesKeyWrap):
    name = "A192KW"
    description = "AES Key Wrap with default initial value using 192-bit key"
    key_size = 192


class A256KW(AesKeyWrap):
    name = "A256KW"
    description = "AES Key Wrap with default initial value using 256-bit key"
    key_size = 256


class RsaKeyWrap(KeyWrappingAlg):
    padding: Any

    name = "RSA1_5"
    name = "RSA1_5"
    description = "RSAES-PKCS1-v1_5"

    def __init__(
        self, key: Union[asymmetric.rsa.RSAPublicKey, asymmetric.rsa.RSAPrivateKey]
    ):
        self.key = key

    def wrap_key(self, plainkey: bytes) -> bytes:
        if not isinstance(self.key, asymmetric.rsa.RSAPublicKey):
            raise RuntimeError("A public key is required for key wrapping")
        return self.key.encrypt(plainkey, self.padding)

    def unwrap_key(self, cipherkey: bytes) -> bytes:
        if not isinstance(self.key, asymmetric.rsa.RSAPrivateKey):
            raise RuntimeError("A private key is required for key unwrapping")
        return self.key.decrypt(cipherkey, self.padding)


class RsaEsPcks1v1_5(RsaKeyWrap):
    name = "RSA1_5"
    description = "RSAES-PKCS1-v1_5"

    padding = asymmetric_padding.PKCS1v15()


class RsaEsOaep(RsaKeyWrap):
    name = "RSA-OAEP"
    description = "RSAES OAEP using default parameters"

    padding = asymmetric_padding.OAEP(
        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None,
    )


class RsaEsOaepSha256(RsaKeyWrap):
    name = "RSA-OAEP-256"
    description = "RSAES OAEP using SHA-256 and MGF1 with with SHA-256"

    padding = asymmetric_padding.OAEP(
        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


class RSASigAlg(SignatureAlg):
    hashing_alg: hashes.HashAlgorithm
    padding_alg: asymmetric_padding.AsymmetricPadding = asymmetric_padding.PKCS1v15()
    min_key_size: int = 2048


class RS256(RSASigAlg):
    name = "RS256"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"
    hashing_alg = hashes.SHA256()


class RS384(RSASigAlg):
    name = "RS384"
    description = "RSASSA-PKCS1-v1_5 using SHA-384"
    hashing_alg = hashes.SHA384()


class RS512(RSASigAlg):
    name = "RS512"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"
    hashing_alg = hashes.SHA512()


class PS256(RSASigAlg):
    name = "PS256"
    description = "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"
    hashing_alg = hashes.SHA256()
    padding_alg = asymmetric_padding.PSS(
        mgf=asymmetric_padding.MGF1(hashes.SHA256()), salt_length=256 // 8
    )


class PS384(RSASigAlg):
    name = "PS384"
    description = "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"
    hashing_alg = hashes.SHA384()
    padding_alg = asymmetric_padding.PSS(
        mgf=asymmetric_padding.MGF1(hashes.SHA384()), salt_length=384 // 8
    )


class PS512(RSASigAlg):
    name = "PS512"
    description = "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"
    hashing_alg = hashes.SHA512()
    padding_alg = asymmetric_padding.PSS(
        mgf=asymmetric_padding.MGF1(hashes.SHA512()), salt_length=512 // 8
    )


@dataclass
class ECCurve:
    name: str
    cryptography_curve: asymmetric.ec.EllipticCurve
    coordinate_size: int


P256 = ECCurve(
    cryptography_curve=asymmetric.ec.SECP256R1(),
    name="P-256",
    coordinate_size=32,
)
P384 = ECCurve(
    cryptography_curve=asymmetric.ec.SECP384R1(),
    name="P-384",
    coordinate_size=48,
)

P521 = ECCurve(
    cryptography_curve=asymmetric.ec.SECP521R1(),
    name="P-521",
    coordinate_size=66,
)
secp256k1 = ECCurve(
    cryptography_curve=asymmetric.ec.SECP256K1(),
    name="secp256k1",
    coordinate_size=32,
)


class ECSignatureAlg(SignatureAlg):
    curve: ECCurve
    hashing_alg: hashes.HashAlgorithm

    def sign(self, data: bytes) -> bytes:
        dss_sig = self.key.sign(data, asymmetric.ec.ECDSA(self.hashing_alg))
        r, s = asymmetric.utils.decode_dss_signature(dss_sig)
        return BinaPy.from_int(r, self.curve.coordinate_size) + BinaPy.from_int(
            s, self.curve.coordinate_size
        )


class ES256(ECSignatureAlg):
    name = "ES256"
    description = "ECDSA using P-256 and SHA-256"
    curve = P256
    hashing_alg = hashes.SHA256()


class ES384(ECSignatureAlg):
    name = "ES384"
    description = "ECDSA using P-384 and SHA-384"
    curve = P384
    hashing_alg = hashes.SHA384()


class ES512(ECSignatureAlg):
    name = "ES512"
    description = "ECDSA using P-521 and SHA-512"
    curve = P521
    hashing_alg = hashes.SHA512()


class ES256K(ECSignatureAlg):
    name = "ES256k"
    description = "ECDSA using secp256k1 and SHA-256"
    curve = secp256k1
    hashing_alg = hashes.SHA256()


class ECDH_ES(
    KeyAgreementAlg[
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
        ephemeral_key: asymmetric.ec.EllipticCurvePrivateKey,
        headers: Mapping[str, Any],
        encalg: Type[EncryptionAlg],
    ) -> bytes:
        apu = BinaPy(headers.get("apu", b"")).decode_from("b64u")
        apv = BinaPy(headers.get("apv", b"")).decode_from("b64u")
        otherinfo = self.otherinfo(encalg.name, apu, apv, encalg.key_size)
        cek = self.derive(ephemeral_key, self.key, otherinfo, encalg.key_size)
        return cek

    def recipient_key(
        self,
        epk: asymmetric.ec.EllipticCurvePublicKey,
        headers: Mapping[str, Any],
        encalg: Type[EncryptionAlg],
    ) -> bytes:
        apu = BinaPy(headers.get("apu", b"")).decode_from("b64u")
        apv = BinaPy(headers.get("apv", b"")).decode_from("b64u")
        otherinfo = self.otherinfo(encalg.name, apu, apv, encalg.key_size)
        cek = self.derive(self.key, epk, otherinfo, encalg.key_size)
        return cek

    @classmethod
    def otherinfo(cls, alg: str, apu: bytes, apv: bytes, keysize: int) -> bytes:
        algorithm_id = BinaPy.from_int(len(alg), length=4) + BinaPy(alg)
        partyuinfo = BinaPy.from_int(len(apu), length=4) + apu
        partyvinfo = BinaPy.from_int(len(apv), length=4) + apv
        supppubinfo = BinaPy.from_int(keysize or keysize, length=4)
        otherinfo = b"".join((algorithm_id, partyuinfo, partyvinfo, supppubinfo))
        return otherinfo

    @classmethod
    def ecdh(
        cls,
        private_key: asymmetric.ec.EllipticCurvePrivateKey,
        public_key: asymmetric.ec.EllipticCurvePublicKey,
    ) -> bytes:
        """
        This does an Elliptic Curve Diffie Hellman key exchange.

        This derive a shared key between a sender and a receiver, based on a public and a private key from each side.
        ECDH exchange produces the same key with either a sender private key and a recipient public key,
        or the matching sender public key and recipient private key.
        :param private_key: a private EC key
        :param public_key: a public EC key
        :return: a shared key
        """
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        return shared_key

    @classmethod
    def derive(
        cls,
        private_key: asymmetric.ec.EllipticCurvePrivateKey,
        public_key: asymmetric.ec.EllipticCurvePublicKey,
        otherinfo: bytes,
        keysize: int,
    ) -> bytes:
        shared_key = cls.ecdh(private_key, public_key)
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(), length=keysize // 8, otherinfo=otherinfo
        )
        return ckdf.derive(shared_key)
