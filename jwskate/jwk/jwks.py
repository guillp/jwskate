"""This module implements Json Web Key Sets (JWKS)."""
from __future__ import annotations

from typing import Any, Iterable

from ..token import BaseJsonDict
from .base import Jwk, to_jwk


class JwkSet(BaseJsonDict):
    """A set of JWK keys, with methods for easy management of keys.

    A JwkSet is a dict subclass, so you can do anything with a JwkSet
    that you can do with a dict. In addition, it provides a few helpers
    methods to get the keys, add or remove keys, and verify signatures
    using keys from this set.

    - a `dict` from the parsed JSON object representing this JwkSet (in paramter `jwks`)
    - a list of `Jwk` (in parameter `keys`
    - nothing, to initialize an empty JwkSet

    Args:
        jwks: a dict, containing the JwkSet, parsed as a JSON object.
        keys: a list of `Jwk`, that will be added to this JwkSet

    """

    def __init__(
        self,
        jwks: dict[str, Any] | None = None,
        keys: Iterable[Jwk | dict[str, Any]] | None = None,
    ):
        if jwks is None and keys is None:
            keys = []

        if jwks is not None:
            keys = jwks.pop("keys", [])
            super().__init__(
                jwks
            )  # init the dict with all the dict content that is not keys
        else:
            super().__init__()

        if keys is not None:
            for jwk in keys:
                self.add_jwk(jwk)

    @property
    def jwks(self) -> list[Jwk]:
        """Return the list of keys from this JwkSet, as `Jwk` instances.

        Returns:
            a list of `Jwk`

        """
        return self.get("keys", [])

    def get_jwk_by_kid(self, kid: str) -> Jwk:
        """Return a Jwk from this JwkSet, based on its kid.

        Args:
          kid: the kid of the key to obtain

        Returns:
            the key with the matching Key ID

        Raises:
            KeyError: if no key matches

        """
        jwk = next(filter(lambda j: j.get("kid") == kid, self.jwks), None)
        if isinstance(jwk, Jwk):
            return jwk
        raise KeyError(kid)

    def __len__(self) -> int:
        """Return the number of Jwk in this JwkSet.

        Returns:
            the number of keys

        """
        return len(self.jwks)

    def add_jwk(
        self,
        key: Jwk | dict[str, Any] | Any,
        kid: str | None = None,
        use: str | None = None,
    ) -> str:
        """Add a Jwk in this JwkSet.

        Args:
          key: the Jwk to add (either a `Jwk` instance, or a dict containing the Jwk parameters)
          kid: the kid to use, if `jwk` doesn't contain one
          use: the defined use for the added Jwk

        Returns:
          the kid from the added Jwk (it may be generated if no kid is provided)

        """
        key = to_jwk(key)

        self.setdefault("keys", [])

        kid = key.get("kid", kid)
        if not kid:
            kid = key.thumbprint()
        key["kid"] = kid
        use = key.get("use", use)
        if use:
            key["use"] = use
        self.jwks.append(key)

        return kid

    def remove_jwk(self, kid: str) -> None:
        """Remove a Jwk from this JwkSet, based on a `kid`.

        Args:
          kid: the `kid` from the key to be removed.

        Raises:
            KeyError: if no key matches

        """
        try:
            jwk = self.get_jwk_by_kid(kid)
            self.jwks.remove(jwk)
        except KeyError:
            pass

    @property
    def is_private(self) -> bool:
        """True if the JwkSet contains at least one private key.

        Returns:
            `True` if this JwkSet contains at least one private key

        """
        return any(key.is_private for key in self.jwks)

    def public_jwks(self) -> JwkSet:
        """Return another JwkSet with the public keys associated with the current keys.

        Returns:
            a public JwkSet

        """
        return JwkSet(keys=(key.public_jwk() for key in self.jwks))

    def verification_keys(self) -> list[Jwk]:
        """Return the list of keys from this JWKS that are usable for signature verification.

        To be usable for signature verification, a key must:

        - be asymmetric
        - be public
        - be flagged for signature, either with `use=sig` or an `alg` that is compatible with signature

        Returns:
            a list of `Jwk` that are usable for signature verification

        """
        return [
            jwk
            for jwk in self.jwks
            if not jwk.is_symmetric and not jwk.is_private and jwk.use == "sig"
        ]

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: str | None = None,
        algs: Iterable[str] | None = None,
        kid: str | None = None,
    ) -> bool:
        """Verify a signature with the keys from this key set.

        If a `kid` is provided, only that Key ID will be tried. Otherwise, all keys that are compatible with the
        specified alg(s) will be tried.

        Args:
          data: the signed data to verify
          signature: the signature to verify against the signed data
          alg: alg to verify the signature, if there is only 1
          algs: list of allowed signature algs, if there are several
          kid: the kid of the Jwk that will be used to validate the signature. If no kid is provided, multiple keys
            from this key set may be tried.

        Returns:
          `True` if the signature validates with any of the tried keys, `False` otherwise

        """
        if not alg and not algs:
            raise ValueError("Please provide either 'alg' or 'algs' parameter")

        # if a kid is provided, try only the key matching `kid`
        if kid is not None:
            jwk = self.get_jwk_by_kid(kid)
            return jwk.verify(data, signature, alg=alg, algs=algs)

        # otherwise, try all keys which support the given alg(s)
        if algs is None:
            if alg is not None:
                algs = (alg,)
        else:
            algs = list(algs)

        for jwk in self.verification_keys():
            for alg in algs or (None,):
                if alg in jwk.supported_signing_algorithms():
                    if jwk.verify(data, signature, alg=alg):
                        return True

        # no key matches, so consider the signature invalid
        return False

    def encryption_keys(self) -> list[Jwk]:
        """Return the list of keys from this JWKS that are usable for encryption.

        To be usable for encryption, a key must:

        - be asymmetric
        - be public
        - be flagged for encryption, either with `use=enc` or an `alg` parameter that is an encryption alg

        Returns:
            a list of `Jwk` that are suitable for encryption

        """
        return [
            jwk
            for jwk in self.jwks
            if not jwk.is_symmetric and not jwk.is_private and jwk.use == "enc"
        ]
