from __future__ import annotations

from typing import Any, Iterable, Optional, Union

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..utils import b64u_to_int, int_to_b64u
from .alg import get_alg, get_algs
from .base import Jwk
from .exceptions import PrivateKeyRequired


class RSAJwk(Jwk):
    """
    Represents a RSA Jwk, with `"kid": "RSA"`.
    """

    kty = "RSA"

    PARAMS = {
        # name: ("Description", is_private, is_required, "kind"),
        "n": ("Modulus", False, True, "b64u"),
        "e": ("Exponent", False, True, "b64u"),
        "d": ("Private Exponent", True, True, "b64u"),
        "p": ("First Prime Factor", True, False, "b64u"),
        "q": ("Second Prime Factor", True, False, "b64u"),
        "dp": ("First Factor CRT Exponent", True, False, "b64u"),
        "dq": ("Second Factor CRT Exponent", True, False, "b64u"),
        "qi": ("First CRT Coefficient", True, False, "b64u"),
        "oth": ("Other Primes Info", True, False, "unsupported"),
    }

    SIGNATURE_ALGORITHMS = {
        # name : (description, padding_alg, hash_alg)
        "RS256": (
            "RSASSA-PKCS1-v1_5 using SHA-256",
            padding.PKCS1v15(),
            hashes.SHA256(),
        ),
        "RS384": (
            "RSASSA-PKCS1-v1_5 using SHA-384",
            padding.PKCS1v15(),
            hashes.SHA384(),
        ),
        "RS512": (
            "RSASSA-PKCS1-v1_5 using SHA-256",
            padding.PKCS1v15(),
            hashes.SHA512(),
        ),
    }

    KEY_MANAGEMENT_ALGORITHMS = {
        # name: ("description", alg)
        "RSA1_5": ("RSAES-PKCS1-v1_5", padding.PKCS1v15()),
        "RSA-OAEP": (
            "RSAES OAEP using default parameters",
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        ),
        "RSA-OAEP-256": (
            "RSAES OAEP using SHA-256 and MGF1 with with SHA-256",
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ),
    }

    ENCRYPTION_ALGORITHMS = {"A256GCM": None}

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
        return cls(dict(kty="RSA", n=int_to_b64u(n), e=int_to_b64u(e), **params))

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
                n=int_to_b64u(n),
                e=int_to_b64u(e),
                d=int_to_b64u(d),
                p=int_to_b64u(p) if p is not None else None,
                q=int_to_b64u(q) if q is not None else None,
                dp=int_to_b64u(dp) if dp is not None else None,
                dq=int_to_b64u(dq) if dq is not None else None,
                qi=int_to_b64u(qi) if qi is not None else None,
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
        return b64u_to_int(self.n)

    @property
    def exponent(self) -> int:
        """
        Returns the exponent from this Jwk.
        :return: the key exponent (from parameter `e`)
        """
        return b64u_to_int(self.e)

    @property
    def private_exponent(self) -> int:
        """
        Returns the private exponent from this Jwk.
        :return: the key private exponent (from parameter `d`)
        """
        return b64u_to_int(self.d)

    @property
    def first_prime_factor(self) -> int:
        """
        Returns the first prime factor from this Jwk.
        :return: the first prime factor (from parameter `p`)
        """
        return b64u_to_int(self.p)

    @property
    def second_prime_factor(self) -> int:
        """
        Returns the second prime factor from this Jwk.
        :return: the second prime factor (from parameter `q`)
        """
        return b64u_to_int(self.q)

    @property
    def first_factor_crt_exponent(self) -> int:
        """
        Returns the first factor CRT exponent from this Jwk.
        :return: the first factor CRT coefficient (from parameter `dp`)
        """
        return b64u_to_int(self.dp)

    @property
    def second_factor_crt_exponent(self) -> int:
        """
        Returns the second factor CRT exponent from this Jwk.
        :return: the second factor CRT coefficient (from parameter `dq`)
        """
        return b64u_to_int(self.dq)

    @property
    def first_crt_coefficient(self) -> int:
        """
        Returns the first CRT coefficient from this Jwk
        :return: the first CRT coefficient (from parameter `qi`)
        """
        return b64u_to_int(self.qi)

    def sign(self, data: bytes, alg: Optional[str] = None) -> bytes:
        alg = self.get("alg", alg)
        if alg is None:
            raise ValueError("a signing alg is required")

        key = self.to_cryptography_key()
        if not isinstance(key, rsa.RSAPrivateKey):
            raise PrivateKeyRequired("A private key is required for signing")

        try:
            description, padding, hashing = self.SIGNATURE_ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        signature: bytes = key.sign(data, padding, hashing)
        return signature

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        public_key = rsa.RSAPublicNumbers(self.exponent, self.modulus).public_key()

        for alg in get_algs(self.alg, alg, algs, self.supported_signing_algorithms):
            try:
                description, padding, hashing = self.SIGNATURE_ALGORITHMS[alg]
            except KeyError:
                continue

            try:
                public_key.verify(
                    signature,
                    data,
                    padding,
                    hashing,
                )
                return True
            except exceptions.InvalidSignature:
                continue

        return False

    def wrap_key(self, plaintext_key: bytes, alg: Optional[str] = None) -> bytes:
        alg = get_alg(self.alg, alg, self.supported_key_management_algorithms)
        description, padding_alg = self.KEY_MANAGEMENT_ALGORITHMS[alg]

        public_key = rsa.RSAPublicNumbers(e=self.exponent, n=self.modulus).public_key()

        cyphertext = public_key.encrypt(plaintext_key, padding_alg)

        return cyphertext

    def unwrap_key(self, cypherkey: bytes, alg: Optional[str] = None) -> bytes:
        alg = get_alg(self.alg, alg, self.supported_key_management_algorithms)
        description, padding_alg = self.KEY_MANAGEMENT_ALGORITHMS[alg]

        key = rsa.RSAPrivateNumbers(
            self.first_prime_factor,
            self.second_prime_factor,
            self.private_exponent,
            self.first_factor_crt_exponent,
            self.second_factor_crt_exponent,
            self.first_crt_coefficient,
            rsa.RSAPublicNumbers(self.exponent, self.modulus),
        ).private_key()

        plaintext = key.decrypt(cypherkey, padding_alg)

        return plaintext
