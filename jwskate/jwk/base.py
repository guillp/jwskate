# see https://github.com/python/typing/issues/60#issuecomment-869757075
import hashlib
import json
from collections import UserDict
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    Union,
)

from ..utils import b64u_decode, b64u_encode
from .exceptions import InvalidJwk

if TYPE_CHECKING:  # pragma: no cover
    _BaseJwk = UserDict[str, Any]
else:
    _BaseJwk = UserDict


class Jwk(_BaseJwk):
    """
    Represents a Json Web Key (JWK), as specified in RFC7517.
    A JWK is a JSON object that represents a cryptographic key.  The members of the object
    represent properties of the key, including its value.
    Just like a parsed JSON object, a :class:`Jwk` is a dict, so you can do with a Jwk anything you can do with a `dict`.
    In addition, all keys parameters are exposed as attributes.
    There are subclasses of `Jwk` for each specific Key Type, but you shouldn't have to use the subclasses directly
    since they all present a common interface.
    """

    kty: str
    """The Key Type associated with this JWK."""

    subclasses: Dict[str, Type["Jwk"]] = {}
    """A dict of subclasses implementing each specific Key Type"""

    PARAMS: Dict[str, Tuple[str, bool, bool, str]]
    """A dict of parameters. Key is parameter name, value is a tuple (description, is_private, is_required, kind)"""

    def __init_subclass__(cls) -> None:
        """
        Automatically add subclasses to the registry.
        This allows __new__ to pick the appropriate subclass when creating a Jwk
        """
        Jwk.subclasses[cls.kty] = cls

    def __new__(cls, jwk: Dict[str, Any]):  # type: ignore
        """
        Overrided `__new__` to allow Jwk to accept a `dict` with the parsed Jwk content
        and return the appropriate subclass based on its `kty`.
        :param jwk:
        """
        if cls == Jwk:
            if jwk.get("keys"):  # if this is a JwkSet
                from .jwks import JwkSet

                jwks = JwkSet(jwk)
                return jwks
            kty: Optional[str] = jwk.get("kty")
            if kty is None:
                raise ValueError("A Json Web Key must have a Key Type (kty)")
            subclass = Jwk.subclasses.get(kty)
            if subclass is None:
                raise ValueError("Unsupported Key Type", kty)
            return super().__new__(subclass)
        return super().__new__(cls)

    def __init__(self, params: Dict[str, Any], kid: Optional[str] = None):
        """
        Initialize a Jwk. Accepts a `dict` with the parsed Jwk contents, and an optional kid if it isn't already part
        of the dict.
        If no `kid` is supplied either way, a default kid is generated based on the key thumbprint (defined in RFC7638)
        :param params: a dict with the parsed Jwk parameters.
        :param kid: a Key Id to use if no `kid` parameters is present in `params`.
        """
        self.data = dict(params)
        self.is_private = False
        self._validate()
        if self.kid is None:
            self.data["kid"] = kid or self.thumbprint()

    def __getattr__(self, item: str) -> Any:
        """
        Allows access to key parameters as attributes, like `jwk.kid`, `jwk.kty`, instead of `jwk['kid']`, `jwk['kty']`, etc.
        :param item:
        :return:
        """
        return self.data.get(item)

    def public_jwk(self) -> "Jwk":
        """
        Returns the public Jwk associated with this private Jwk.
        :return: a Jwk containing only the public parameters.
        """
        if not self.is_private:
            return self

        params = {
            name: self.data.get(name)
            for name, (description, private, required, kind) in self.PARAMS.items()
            if not private
        }
        return Jwk(
            dict(
                kty=self.kty,
                kid=self.kid,
                alg=self.alg,
                use=self.use,
                key_ops=self.key_ops,
                **params,
            )
        )

    def thumbprint(self, hashalg: str = "SHA256") -> str:
        """Returns the key thumbprint as specified by RFC 7638.

        :param hashalg: A hash function (defaults to SHA256)
        """

        digest = hashlib.new(hashalg)

        t = {"kty": self.get("kty")}
        for name, (description, private, required, kind) in self.PARAMS.items():
            if required and not private:
                t[name] = self.get(name)

        intermediary = json.dumps(t, separators=(",", ":"), sort_keys=True)
        digest.update(intermediary.encode("utf8"))
        return b64u_encode(digest.digest())

    def _validate(self) -> None:
        """
        Internal method used to validate a Jwk. It checks that all required parameters are present and well-formed.
        If the key is private, it sets the `is_private` flag to `True`.
        """
        is_private = False
        for name, (description, private, required, kind) in self.PARAMS.items():

            value = getattr(self, name)

            if private and value is not None:
                is_private = True

            if not private and required and value is None:
                raise InvalidJwk(
                    f"Missing required public param {description} ({name})"
                )

            if kind == "b64u":
                try:
                    b64u_decode(value)
                except ValueError:
                    InvalidJwk(
                        f"Parameter {description} ({name}) must be a Base64URL-encoded value"
                    )
            elif kind == "unsupported":
                if value is not None:
                    raise InvalidJwk(f"Unsupported JWK param {name}")
            elif kind == "name":
                pass
            else:
                assert False, f"Unsupported param {name} type {kind}"

        # if at least one of the supplied parameter was private, then all required private parameters must be provided
        if is_private:
            for name, (description, private, required, kind) in self.PARAMS.items():
                value = self.data.get(name)
                if private and required and value is None:
                    raise InvalidJwk(
                        f"Missing required private param {description} ({name})"
                    )

        self.is_private = is_private

    def sign(self, data: bytes, alg: Optional[str]) -> bytes:
        """
        Signs a data using this Jwk, and returns the signature.
        This is implemented by subclasses.
        :param data: the data to sign
        :param alg: the alg to use (if this key doesn't have an `alg` parameter).
        :return: the generated signature.
        """
        raise NotImplementedError  # pragma: no cover

    def verify(
        self, data: bytes, signature: bytes, alg: Union[str, Iterable[str], None]
    ) -> bool:
        """
        Verifies a signature using this Jwk, and returns `True` if valid.
        This is implemented by subclasses.
        :param data: the data to verify
        :param signature: the signature to verify
        :param alg: the alg to use to verify the signature (if this key doesn't have an `alg` parameter)
        :return: `True` if the signature matches, `False` otherwise
        """
        raise NotImplementedError  # pragma: no cover

    def encrypt(
        self,
        plaintext: bytes,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
        iv: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypts a plaintext, with an optional Additional Authenticated Data (AAD) using this JWK, and returns
        the Encrypted Data, the Authentication Tag and the used Initialization Vector.
        :param plaintext: the data to encrypt.
        :param aad: the Additional Authenticated Data (AAD) to include in the authentication tag
        :param alg: the alg to use to encrypt the data
        :param iv: the Initialization Vector that was used to encrypt the data. If `iv` is passed as parameter, this
        will return that same value. Otherwise, an IV is generated.
        :return: a tuple (cyphertext, authentication_tag, iv)
        """

        raise NotImplementedError  # pragma: no cover

    def decrypt(
        self,
        cyphertext: bytes,
        tag: bytes,
        iv: bytes,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
    ) -> bytes:
        """
        Decrypts an encrypted data using this Jwk, and returns the encrypted result.
        This is implemented by subclasses.
        :param cyphertext: the data to decrypt
        :param iv: the Initialization Vector (IV) that was used for encryption
        :param tag: the Authentication Tag that will be verified while decrypting data
        :param aad: the Additional Authentication Data (AAD) to verify the Tag against
        :param alg: the alg to use for decryption
        :return: the clear-text data
        """
        raise NotImplementedError  # pragma: no cover

    @property
    def supported_signing_algorithms(self) -> List[str]:
        """
        Returns a list of signing algs that are compatible for use with this Jwk.
        :return: a list of signing algs
        """
        raise NotImplementedError  # pragma: no cover
