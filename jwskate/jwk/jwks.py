"""This module implements Json Web Key Sets (JWKS)."""

from typing import Any, Dict, Iterable, List, Optional, Union

from ..token import BaseJsonDict
from .alg import UnsupportedAlg
from .base import Jwk


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
        jwks: Optional[Dict[str, Any]] = None,
        keys: Optional[Iterable[Jwk]] = None,
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
    def jwks(self) -> List[Jwk]:
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
        jwk = next(filter(lambda jwk: jwk.get("kid") == kid, self.jwks), None)
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
        jwk: Union[Jwk, Dict[str, Any]],
        kid: Optional[str] = None,
        use: Optional[str] = None,
    ) -> str:
        """Add a Jwk in this JwkSet.

        Args:
          jwk: the Jwk to add (either a `Jwk` instance, or a dict containing the Jwk parameters)
          kid: the kid to use, if `jwk` doesn't contain one
          use: the defined use for the added Jwk

        Returns:
          the kid from the added Jwk (it may be generated if no kid is provided)
        """
        if not isinstance(jwk, Jwk):
            jwk = Jwk(jwk)

        if "keys" not in self:
            self["keys"] = []

        kid = jwk.get("kid", kid)
        if not kid:
            kid = jwk.thumbprint()
        jwk["kid"] = kid
        use = jwk.get("use", use)
        if use:
            jwk["use"] = use
        self.jwks.append(jwk)

        return kid

    def remove_jwk(self, kid: str) -> None:
        """Removes a Jwk from this JwkSet, based on a `kid`.

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

    def public_jwks(self) -> "JwkSet":
        """Return another JwkSet with the public keys associated with the current keys.

        Returns:
            a public JwkSet
        """
        return JwkSet(keys=(key.public_jwk() for key in self.jwks))

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
        kid: Optional[str] = None,
    ) -> bool:
        """Verify a signature with the key from this key set.

        It implements multiple techniques to avoid trying all keys:
        If a `kid` is provided, only the key with this `kid` will be tried.
        Otherwise, if an `alg` or several `algs` are provided, only keys that are compatible with the supplied `alg` will be tried.
        Otherwise, keys that have use = signature will be tried.
        And if the signature is still not verified at that point, the keys with no specified alg and use will be tried.

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
        # if a kid is provided, try only the key matching `kid`
        if kid is not None:
            jwk = self.get_jwk_by_kid(kid)
            return jwk.verify(data, signature, alg=alg, algs=algs)

        # if one or several alg are provided, try only the keys that are compatible with one of the provided alg(s)
        if alg:
            for jwk in self.jwks:
                if jwk.get("alg") == alg:
                    if jwk.verify(data, signature, alg=alg):
                        return True

        if algs:
            for jwk in self.jwks:
                alg = jwk.get("alg")
                if alg is not None and alg in algs:
                    if jwk.verify(data, signature, algs=algs):
                        return True

        # if no kid and no alg are provided, try first the keys flagged for signature verification (`"use": "verify"`)
        for jwk in self.jwks:
            if jwk.get("use") == "verify":
                if jwk.verify(data, signature, alg=alg):
                    return True

        # then with the keys that have no defined `use`
        for jwk in self.jwks:
            if jwk.get("use") is None and jwk.get("alg") is None:
                try:
                    if jwk.verify(data, signature, alg=alg):
                        return True
                except UnsupportedAlg:
                    continue

        # no key matches, so consider the signature invalid
        return False
