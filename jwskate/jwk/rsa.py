from __future__ import annotations

from typing import Any, Optional, Union

from binapy import BinaPy
from cryptography.hazmat.primitives.asymmetric import rsa

from jwskate.jwa import (
    PS256,
    PS384,
    PS512,
    RS256,
    RS384,
    RS512,
    RsaEsOaep,
    RsaEsOaepSha256,
    RsaEsOaepSha384,
    RsaEsOaepSha512,
    RsaEsPcks1v1_5,
)

from .alg import select_alg
from .base import Jwk, JwkParameter
from .symetric import SymmetricJwk


class RSAJwk(Jwk):
    """
    Represent a RSA Jwk, with `kty=RSA`.
    """

    kty = "RSA"

    PARAMS = {
        "n": JwkParameter("Modulus", is_private=False, is_required=True, kind="b64u"),
        "e": JwkParameter("Exponent", is_private=False, is_required=True, kind="b64u"),
        "d": JwkParameter(
            "Private Exponent", is_private=True, is_required=True, kind="b64u"
        ),
        "p": JwkParameter(
            "First Prime Factor", is_private=True, is_required=False, kind="b64u"
        ),
        "q": JwkParameter(
            "Second Prime Factor", is_private=True, is_required=False, kind="b64u"
        ),
        "dp": JwkParameter(
            "First Factor CRT Exponent", is_private=True, is_required=False, kind="b64u"
        ),
        "dq": JwkParameter(
            "Second Factor CRT Exponent",
            is_private=True,
            is_required=False,
            kind="b64u",
        ),
        "qi": JwkParameter(
            "First CRT Coefficient", is_private=True, is_required=False, kind="b64u"
        ),
        "oth": JwkParameter(
            "Other Primes Info", is_private=True, is_required=False, kind="unsupported"
        ),
    }

    SIGNATURE_ALGORITHMS = {
        sigalg.name: sigalg for sigalg in [RS256, RS384, RS512, PS256, PS384, PS512]
    }

    KEY_MANAGEMENT_ALGORITHMS = {
        keyalg.name: keyalg
        for keyalg in [
            RsaEsPcks1v1_5,
            RsaEsOaep,
            RsaEsOaepSha256,
            RsaEsOaepSha384,
            RsaEsOaepSha512,
        ]
    }

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
    def public(cls, n: int, e: int, **params: Any) -> RSAJwk:
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
        **params: Any,
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

    def wrap_key(self, plainkey: bytes, alg: Optional[str] = None) -> BinaPy:
        keyalg = select_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)
        wrapper = keyalg(self.public_jwk().to_cryptography_key())
        ciphertext = wrapper.wrap_key(plainkey)
        return BinaPy(ciphertext)

    def unwrap_key(
        self,
        cipherkey: bytes,
        alg: Optional[str] = None,
    ) -> Jwk:
        keyalg = select_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)
        wrapper = keyalg(self.to_cryptography_key())
        plaintext = wrapper.unwrap_key(cipherkey)
        return SymmetricJwk.from_bytes(plaintext)
