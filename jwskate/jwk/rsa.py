from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Union

from binapy import BinaPy
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .alg import EncryptionAlg, KeyManagementAlg, SignatureAlg, get_alg, get_algs
from .base import Jwk, JwkParameter
from .exceptions import PrivateKeyRequired


@dataclass
class RSASignatureAlg(SignatureAlg):
    padding_alg: padding.AsymmetricPadding
    min_key_size: Optional[int]


@dataclass
class RSAKeyManagementAlg(KeyManagementAlg):
    padding_alg: padding.AsymmetricPadding


@dataclass
class RSAEncryptionAlg(EncryptionAlg):
    pass


class RSAJwk(Jwk):
    """
    Represents a RSA Jwk, with `"kid": "RSA"`.
    """

    kty = "RSA"

    PARAMS = {
        # name: ("Description", is_private, is_required, "kind"),
        "n": JwkParameter("Modulus", False, True, "b64u"),
        "e": JwkParameter("Exponent", False, True, "b64u"),
        "d": JwkParameter("Private Exponent", True, True, "b64u"),
        "p": JwkParameter("First Prime Factor", True, False, "b64u"),
        "q": JwkParameter("Second Prime Factor", True, False, "b64u"),
        "dp": JwkParameter("First Factor CRT Exponent", True, False, "b64u"),
        "dq": JwkParameter("Second Factor CRT Exponent", True, False, "b64u"),
        "qi": JwkParameter("First CRT Coefficient", True, False, "b64u"),
        "oth": JwkParameter("Other Primes Info", True, False, "unsupported"),
    }

    SIGNATURE_ALGORITHMS: Mapping[str, RSASignatureAlg] = {
        "RS256": RSASignatureAlg(
            name="RS256",
            description="RSASSA-PKCS1-v1_5 using SHA-256",
            hashing_alg=hashes.SHA256(),
            padding_alg=padding.PKCS1v15(),
            min_key_size=2048,
        ),
        "RS384": RSASignatureAlg(
            name="RS384",
            description="RSASSA-PKCS1-v1_5 using SHA-384",
            hashing_alg=hashes.SHA384(),
            padding_alg=padding.PKCS1v15(),
            min_key_size=2048,
        ),
        "RS512": RSASignatureAlg(
            name="RS512",
            description="RSASSA-PKCS1-v1_5 using SHA-256",
            hashing_alg=hashes.SHA512(),
            padding_alg=padding.PKCS1v15(),
            min_key_size=2048,
        ),
    }

    KEY_MANAGEMENT_ALGORITHMS: Mapping[str, RSAKeyManagementAlg] = {
        # name: ("description", alg)
        "RSA1_5": RSAKeyManagementAlg(
            name="RSA1_5",
            description="RSAES-PKCS1-v1_5",
            padding_alg=padding.PKCS1v15(),
        ),
        "RSA-OAEP": RSAKeyManagementAlg(
            name="RSA-OAEP",
            description="RSAES OAEP using default parameters",
            padding_alg=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        ),
        "RSA-OAEP-256": RSAKeyManagementAlg(
            name="RSA-OAEP-256",
            description="RSAES OAEP using SHA-256 and MGF1 with with SHA-256",
            padding_alg=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ),
    }

    ENCRYPTION_ALGORITHMS: Mapping[str, RSAEncryptionAlg] = {}

    @classmethod
    def from_cryptography_key(cls, key: Any) -> RSAJwk:
        if isinstance(key, rsa.RSAPrivateKey):
            priv = key.private_numbers()  # type: ignore[attr-defined]
            pub = key.public_key().public_numbers()
            return cls.private(
                n=pub.n,
                e=pub.e,
                d=priv.d,
                p=priv.p,
                q=priv.q,
                dp=priv.dmp1,
                dq=priv.dmq1,
                qi=priv.iqmp,
            )
        elif isinstance(key, rsa.RSAPublicKey):
            pub = key.public_numbers()
            return cls.public(
                n=pub.n,
                e=pub.e,
            )
        else:
            raise TypeError("A RSAPrivateKey or a RSAPublicKey is required.")

    def to_cryptography_key(self) -> Union[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        if self.is_private:
            return rsa.RSAPrivateNumbers(
                self.first_prime_factor,
                self.second_prime_factor,
                self.private_exponent,
                self.first_factor_crt_exponent,
                self.second_factor_crt_exponent,
                self.first_crt_coefficient,
                rsa.RSAPublicNumbers(self.exponent, self.modulus),
            ).private_key()
        else:
            return rsa.RSAPublicNumbers(e=self.exponent, n=self.modulus).public_key()

    @classmethod
    def public(cls, n: int, e: int, **params: str) -> RSAJwk:
        """
        Initialize a Public RsaJwk from a modulus and an exponent.
        :param n: the modulus
        :param e: the exponent
        :param params: additional parameters for the return RSAJwk
        :return: a RsaJwk
        """
        return cls(
            dict(
                kty="RSA",
                n=BinaPy.from_int(n).encode_to("b64u").decode(),
                e=BinaPy.from_int(e).encode_to("b64u").decode(),
                **params,
            )
        )

    @classmethod
    def private(
        cls,
        n: int,
        e: int,
        d: int,
        p: Optional[int] = None,
        q: Optional[int] = None,
        dp: Optional[int] = None,
        dq: Optional[int] = None,
        qi: Optional[int] = None,
        **params: str,
    ) -> RSAJwk:
        """
        Initializes a Private RsaJwk from its required parameters.
        :param n: the modulus
        :param e: the exponent
        :param d: the private exponent
        :param p: the first prime factor
        :param q: the second prime factor
        :param dp: the first factor CRT exponent
        :param dq: the second factor CRT exponent
        :param qi: the first CRT coefficient
        :param params: additional parameters for the return RSAJwk
        :return:
        """
        return cls(
            dict(
                kty="RSA",
                n=BinaPy.from_int(n).encode_to("b64u").decode(),
                e=BinaPy.from_int(e).encode_to("b64u").decode(),
                d=BinaPy.from_int(d).encode_to("b64u").decode(),
                p=BinaPy.from_int(p).encode_to("b64u").decode()
                if p is not None
                else None,
                q=BinaPy.from_int(q).encode_to("b64u").decode()
                if q is not None
                else None,
                dp=BinaPy.from_int(dp).encode_to("b64u").decode()
                if dp is not None
                else None,
                dq=BinaPy.from_int(dq).encode_to("b64u").decode()
                if dq is not None
                else None,
                qi=BinaPy.from_int(qi).encode_to("b64u").decode()
                if qi is not None
                else None,
                **params,
            )
        )

    @classmethod
    def generate(cls, key_size: int = 4096, **params: str) -> RSAJwk:
        """
        Generates a new random Private RSAJwk.
        :param key_size: the key size to use for the generated key.
        :param params: additional parameters for the generated RSAJwk
        :return: a generated RSAJwk
        """
        private_key = rsa.generate_private_key(65537, key_size=key_size)
        pn = private_key.private_numbers()
        return cls.private(
            n=pn.public_numbers.n,
            e=pn.public_numbers.e,
            d=pn.d,
            p=pn.p,
            q=pn.q,
            dp=pn.dmp1,
            dq=pn.dmq1,
            qi=pn.iqmp,
            **params,
        )

    @property
    def modulus(self) -> int:
        """
        Returns the modulus from this Jwk.
        :return: the key modulus (from parameter `n`)
        """
        return BinaPy(self.n).decode_from("b64u").to_int()

    @property
    def exponent(self) -> int:
        """
        Returns the exponent from this Jwk.
        :return: the key exponent (from parameter `e`)
        """
        return BinaPy(self.e).decode_from("b64u").to_int()

    @property
    def private_exponent(self) -> int:
        """
        Returns the private exponent from this Jwk.
        :return: the key private exponent (from parameter `d`)
        """
        return BinaPy(self.d).decode_from("b64u").to_int()

    @property
    def first_prime_factor(self) -> int:
        """
        Returns the first prime factor from this Jwk.
        :return: the first prime factor (from parameter `p`)
        """
        return BinaPy(self.p).decode_from("b64u").to_int()

    @property
    def second_prime_factor(self) -> int:
        """
        Returns the second prime factor from this Jwk.
        :return: the second prime factor (from parameter `q`)
        """
        return BinaPy(self.q).decode_from("b64u").to_int()

    @property
    def first_factor_crt_exponent(self) -> int:
        """
        Returns the first factor CRT exponent from this Jwk.
        :return: the first factor CRT coefficient (from parameter `dp`)
        """
        return BinaPy(self.dp).decode_from("b64u").to_int()

    @property
    def second_factor_crt_exponent(self) -> int:
        """
        Returns the second factor CRT exponent from this Jwk.
        :return: the second factor CRT coefficient (from parameter `dq`)
        """
        return BinaPy(self.dq).decode_from("b64u").to_int()

    @property
    def first_crt_coefficient(self) -> int:
        """
        Returns the first CRT coefficient from this Jwk
        :return: the first CRT coefficient (from parameter `qi`)
        """
        return BinaPy(self.qi).decode_from("b64u").to_int()

    def sign(self, data: bytes, alg: Optional[str] = None) -> BinaPy:
        sigalg = get_alg(self.alg, alg, self.SIGNATURE_ALGORITHMS)

        key = self.to_cryptography_key()
        if not isinstance(key, rsa.RSAPrivateKey):
            raise PrivateKeyRequired("A private key is required for signing")

        signature = BinaPy(key.sign(data, sigalg.padding_alg, sigalg.hashing_alg))
        return signature

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        public_key = rsa.RSAPublicNumbers(self.exponent, self.modulus).public_key()

        for sigalg in get_algs(self.alg, alg, algs, self.SIGNATURE_ALGORITHMS):
            try:
                public_key.verify(
                    signature,
                    data,
                    sigalg.padding_alg,
                    sigalg.hashing_alg,
                )
                return True
            except exceptions.InvalidSignature:
                continue

        return False

    def wrap_key(self, plaintext_key: bytes, alg: Optional[str] = None) -> BinaPy:
        keyalg = get_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)

        public_key = rsa.RSAPublicNumbers(e=self.exponent, n=self.modulus).public_key()

        cyphertext = public_key.encrypt(plaintext_key, keyalg.padding_alg)

        return BinaPy(cyphertext)

    def unwrap_key(self, cypherkey: bytes, alg: Optional[str] = None) -> BinaPy:
        keyalg = get_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)

        key = rsa.RSAPrivateNumbers(
            self.first_prime_factor,
            self.second_prime_factor,
            self.private_exponent,
            self.first_factor_crt_exponent,
            self.second_factor_crt_exponent,
            self.first_crt_coefficient,
            rsa.RSAPublicNumbers(self.exponent, self.modulus),
        ).private_key()

        plaintext = key.decrypt(cypherkey, keyalg.padding_alg)

        return BinaPy(plaintext)
