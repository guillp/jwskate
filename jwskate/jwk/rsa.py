from typing import Iterable, List, Optional, Union

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..utils import b64u_to_int, int_to_b64u
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
        return b64u_to_int(self.dp)

    @property
    def second_factor_crt_exponent(self) -> int:
        return b64u_to_int(self.dq)

    @property
    def first_crt_coefficient(self) -> int:
        """
        Returns the first CRT coefficient from this Jwk
        :return: he first CRT coefficient (from parameter `qi`)
        """
        return b64u_to_int(self.qi)

    @classmethod
    def public(cls, n: int, e: int, **params: str) -> "RSAJwk":
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
        p: int,
        q: int,
        dp: int,
        dq: int,
        qi: int,
        **params: str,
    ) -> "RSAJwk":
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
                p=int_to_b64u(p),
                q=int_to_b64u(q),
                dp=int_to_b64u(dp),
                dq=int_to_b64u(dq),
                qi=int_to_b64u(qi),
                **params,
            )
        )

    @classmethod
    def generate(cls, key_size: int = 4096, **params: str) -> "RSAJwk":
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

    def sign(self, data: bytes, alg: Optional[str] = "RS256") -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("a signing alg is required")

        if not self.is_private:
            raise PrivateKeyRequired("A private key is required for signing")

        key = rsa.RSAPrivateNumbers(
            self.first_prime_factor,
            self.second_prime_factor,
            self.private_exponent,
            self.first_factor_crt_exponent,
            self.second_factor_crt_exponent,
            self.first_crt_coefficient,
            rsa.RSAPublicNumbers(self.exponent, self.modulus),
        ).private_key()
        try:
            description, padding, hashing = self.SIGNATURE_ALGORITHMS[alg]
        except KeyError:
            raise ValueError("Unsupported signing alg", alg)

        return key.sign(data, padding, hashing)

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Union[str, Iterable[str], None] = "RS256",
    ) -> bool:
        if isinstance(alg, str):
            algs = [alg]
        elif alg is None:
            algs = [self.alg]
        else:
            algs = list(alg)

        if not algs:
            raise ValueError("a signing alg is required")

        public_key = rsa.RSAPublicNumbers(self.exponent, self.modulus).public_key()

        for alg in algs:
            try:
                description, padding, hashing = self.SIGNATURE_ALGORITHMS[alg]
            except KeyError:
                raise ValueError("Unsupported signing alg", alg)

            try:
                public_key.verify(
                    signature,
                    data,
                    padding,
                    hashing,
                )
                return True
            except cryptography.exceptions.InvalidSignature:
                continue

        return False

    @property
    def supported_signing_algorithms(self) -> List[str]:
        return list(self.SIGNATURE_ALGORITHMS.keys())

    def encrypt_cek(self, cek: bytes, alg: Optional[str] = None) -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("an encryption alg is required")
        description, padding_alg = self.KEY_MANAGEMENT_ALGORITHMS[alg]

        public_key = rsa.RSAPublicNumbers(e=self.exponent, n=self.modulus).public_key()

        cyphertext = public_key.encrypt(cek, padding_alg)

        return cyphertext

    def decrypt_cek(self, enc_cek, alg: Optional[str] = None) -> bytes:
        alg = self.alg or alg
        if alg is None:
            raise ValueError("an encryption alg is required")
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

        plaintext = key.decrypt(enc_cek, padding_alg)

        return plaintext
