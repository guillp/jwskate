"""This module implements JWK representing RSA keys."""

from __future__ import annotations

from typing import Any, Optional, Union

from backports.cached_property import cached_property
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

from .base import Jwk, JwkParameter


class RSAJwk(Jwk):
    """Represent a RSA Jwk, with `kty=RSA`."""

    KTY = "RSA"
    CRYPTOGRAPHY_KEY_CLASSES = (rsa.RSAPrivateKey, rsa.RSAPublicKey)

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

    @property
    def is_private(self) -> bool:  # noqa: D102
        return "d" in self

    @classmethod
    def from_cryptography_key(cls, cryptography_key: Any, **kwargs: Any) -> RSAJwk:
        """Initialize a Jwk from a `cryptography` RSA key.

        Args:
          cryptography_key: a `cryptography` RSA key
          **kwargs: additional members to include in the Jwk

        Returns:
            a RSAJwk initialized with the given key

        Raises:
            TypeError: if the given key type is not supported
        """
        if isinstance(cryptography_key, rsa.RSAPrivateKey):
            priv = cryptography_key.private_numbers()  # type: ignore[attr-defined]
            pub = cryptography_key.public_key().public_numbers()
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
        elif isinstance(cryptography_key, rsa.RSAPublicKey):
            pub = cryptography_key.public_numbers()
            return cls.public(
                n=pub.n,
                e=pub.e,
            )
        else:
            raise TypeError("A RSAPrivateKey or a RSAPublicKey is required.")

    def _to_cryptography_key(self) -> Union[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Initialize a `cryptography` key based on this Jwk.

        Returns:
            a cryptography RSAPrivateKey or RSAPublicKey
        """
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
        """Initialize a public RsaJwk from a modulus and an exponent.

        Args:
          n: the modulus
          e: the exponent
          **params: additional members to include in the Jwk

        Returns:
          a RsaJwk initialized from the provided parameters
        """
        return cls(
            dict(
                kty="RSA",
                n=BinaPy.from_int(n).to("b64u").ascii(),
                e=BinaPy.from_int(e).to("b64u").ascii(),
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
        """Initializes a Private RsaJwk from its required parameters.

        Args:
          n: the modulus
          e: the exponent
          d: the private exponent
          p: the first prime factor
          q: the second prime factor
          dp: the first factor CRT exponent
          dq: the second factor CRT exponent
          qi: the first CRT coefficient
          **params: additional members to include in the Jwk

        Returns:
            a RSAJwk initialized from the given parameters
        """
        return cls(
            dict(
                kty="RSA",
                n=BinaPy.from_int(n).to("b64u").ascii(),
                e=BinaPy.from_int(e).to("b64u").ascii(),
                d=BinaPy.from_int(d).to("b64u").ascii(),
                p=BinaPy.from_int(p).to("b64u").ascii() if p is not None else None,
                q=BinaPy.from_int(q).to("b64u").ascii() if q is not None else None,
                dp=BinaPy.from_int(dp).to("b64u").ascii() if dp is not None else None,
                dq=BinaPy.from_int(dq).to("b64u").ascii() if dq is not None else None,
                qi=BinaPy.from_int(qi).to("b64u").ascii() if qi is not None else None,
                **params,
            )
        )

    @classmethod
    def generate(cls, key_size: int = 4096, **params: Any) -> RSAJwk:
        """Generates a new random private RSAJwk.

        Args:
          key_size: the key size to use for the generated key, in bits
          **params: additional members to include in the Jwk

        Returns:
          a generated RSAJwk
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

    @cached_property
    def modulus(self) -> int:
        """Returns the modulus from this Jwk.

        Returns:
            the key modulus (from parameter `n`)
        """
        return BinaPy(self.n).decode_from("b64u").to_int()

    @cached_property
    def exponent(self) -> int:
        """Returns the exponent from this Jwk.

        Returns:
            the key exponent (from parameter `e`)
        """
        return BinaPy(self.e).decode_from("b64u").to_int()

    @cached_property
    def private_exponent(self) -> int:
        """Returns the private exponent from this Jwk.

        Returns:
            the key private exponent (from parameter `d`)
        """
        return BinaPy(self.d).decode_from("b64u").to_int()

    @cached_property
    def first_prime_factor(self) -> int:
        """Returns the first prime factor from this Jwk.

        Returns:
            the first prime factor (from parameter `p`)
        """
        return BinaPy(self.p).decode_from("b64u").to_int()

    @cached_property
    def second_prime_factor(self) -> int:
        """Returns the second prime factor from this Jwk.

        Returns:
            the second prime factor (from parameter `q`)
        """
        return BinaPy(self.q).decode_from("b64u").to_int()

    @cached_property
    def first_factor_crt_exponent(self) -> int:
        """Returns the first factor CRT exponent from this Jwk.

        Returns:
            the first factor CRT coefficient (from parameter `dp`)
        """
        return BinaPy(self.dp).decode_from("b64u").to_int()

    @cached_property
    def second_factor_crt_exponent(self) -> int:
        """Returns the second factor CRT exponent from this Jwk.

        Returns:
            the second factor CRT coefficient (from parameter `dq`)
        """
        return BinaPy(self.dq).decode_from("b64u").to_int()

    @cached_property
    def first_crt_coefficient(self) -> int:
        """Returns the first CRT coefficient from this Jwk.

        Returns:
            the first CRT coefficient (from parameter `qi`)
        """
        return BinaPy(self.qi).decode_from("b64u").to_int()
