from __future__ import annotations

import hashlib
import json
import warnings
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, Union

from binapy import BinaPy  # type: ignore[import]
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..utils import b64u_decode, b64u_encode
from .exceptions import InvalidJwk


class Jwk(Dict[str, Any]):
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

    SIGNATURE_ALGORITHMS: Dict[str, Any]
    KEY_MANAGEMENT_ALGORITHMS: Dict[str, Any]
    ENCRYPTION_ALGORITHMS: Dict[str, Any]

    def __init_subclass__(cls) -> None:
        """
        Automatically add subclasses to the registry.
        This allows __new__ to pick the appropriate subclass when creating a Jwk
        """
        if hasattr(cls, "kty"):
            Jwk.subclasses[cls.kty] = cls

    def __new__(cls, jwk: Union[Jwk, Dict[str, Any]]):  # type: ignore
        """
        Overrided `__new__` to allow Jwk to accept a `dict` with the parsed Jwk content
        and return the appropriate subclass based on its `kty`.
        :param jwk: a dict containing JWK parameters, or another Jwk instance.
        """
        if cls == Jwk:
            if isinstance(jwk, Jwk):
                return jwk

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
        super().__init__({key: val for key, val in params.items() if val is not None})
        self.is_private = False
        self._validate()
        if self.get("kid") is None:
            self["kid"] = kid or self.thumbprint()

    def __getattr__(self, item: str) -> Any:
        """
        Allows access to key parameters as attributes, like `jwk.kid`, `jwk.kty`, instead of `jwk['kid']`, `jwk['kty']`, etc.
        :param item:
        :return:
        """
        value = self.get(item)
        if value is None:
            raise AttributeError(item)
        return value

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

    @property
    def alg(self) -> Optional[str]:
        alg = self.get("alg")
        if alg is not None and not isinstance(alg, str):
            raise TypeError(f"Invalid alg type {type(str)}", alg)
        return alg

    @property
    def enc(self) -> Optional[str]:
        enc = self.get("enc")
        if enc is not None and not isinstance(enc, str):
            raise TypeError(f"Invalid enc type {type(str)}", enc)
        return enc

    def _validate(self) -> None:
        """
        Internal method used to validate a Jwk. It checks that all required parameters are present and well-formed.
        If the key is private, it sets the `is_private` flag to `True`.
        """
        jwk_is_private = False
        for name, (description, is_private, is_required, kind) in self.PARAMS.items():

            value = self.get(name)

            if is_private and value is not None:
                jwk_is_private = True

            if not is_private and is_required and value is None:
                raise InvalidJwk(
                    f"Missing required public param {description} ({name})"
                )

            if value is None:
                pass
            elif kind == "b64u":
                if not isinstance(value, str):
                    raise InvalidJwk(
                        f"Parameter {description} ({name}) must be a string with a Base64URL-encoded value"
                    )
                try:
                    b64u_decode(value)
                except ValueError:
                    raise InvalidJwk(
                        f"Parameter {description} ({name}) must be a Base64URL-encoded value"
                    )
            elif kind == "unsupported":
                if value is not None:
                    raise InvalidJwk(f"Unsupported JWK param '{name}'")
            elif kind == "name":
                pass
            else:
                assert False, f"Unsupported param '{name}' type '{kind}'"

        # if at least one of the supplied parameter was private, then all required private parameters must be provided
        if jwk_is_private:
            for name, (
                description,
                is_private,
                is_required,
                kind,
            ) in self.PARAMS.items():
                value = self.get(name)
                if is_private and is_required and value is None:
                    raise InvalidJwk(
                        f"Missing required private param {description} ({name})"
                    )

        # if key is used for signing, it must be private
        for op in self.get("key_ops", []):
            if op in ("sign", "decrypt", "unwrapKey") and not jwk_is_private:
                raise InvalidJwk(f"Key Operation is '{op}' but the key is public")

        self.is_private = jwk_is_private

    @property
    def supported_signing_algorithms(self) -> List[str]:
        """
        Return a list of signing algs that are compatible for use with this Jwk.
        :return: a list of signing algs
        """
        return list(self.SIGNATURE_ALGORITHMS.keys())

    @property
    def supported_key_management_algorithms(self) -> List[str]:
        """
        Return a list of key management algs that are compatible for use with this Jwk.
        :return: a list of key management algs
        """
        return list(self.KEY_MANAGEMENT_ALGORITHMS.keys())

    @property
    def supported_encryption_algorithms(self) -> List[str]:
        """
        Return a list of encryption algs that are compatible for use with this Jwk.
        :return: a list of encryption algs
        """
        return list(self.ENCRYPTION_ALGORITHMS.keys())

    def public_jwk(self) -> "Jwk":
        """
        Returns the public Jwk associated with this private Jwk.
        :return: a Jwk containing only the public parameters.
        """
        if not self.is_private:
            return self

        params = {
            name: self.get(name)
            for name, (description, private, required, kind) in self.PARAMS.items()
            if not private
        }

        key_ops = self.get("key_ops")
        if key_ops:
            if "sign" in key_ops:
                key_ops.remove("sign")
                key_ops.append("verify")
            if "decrypt" in key_ops:
                key_ops.remove("decrypt")
                key_ops.append("encrypt")
            if "unwrapKey" in key_ops:
                key_ops.remove("unwrapKey")
                key_ops.append("wrapKey")

        return Jwk(
            dict(
                kty=self.kty,
                kid=self.get("kid"),
                alg=self.get("alg"),
                use=self.get("use"),
                key_ops=key_ops,
                **params,
            )
        )

    def sign(self, data: bytes, alg: Optional[str]) -> BinaPy:
        """
        Signs a data using this Jwk, and returns the signature.
        This is implemented by subclasses.
        :param data: the data to sign
        :param alg: the alg to use (if this key doesn't have an `alg` parameter).
        :return: the generated signature.
        """
        raise NotImplementedError  # pragma: no cover

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
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
    ) -> Tuple[BinaPy, BinaPy, BinaPy]:
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
    ) -> BinaPy:
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

    def wrap_key(self, key: bytes, alg: Optional[str] = None) -> BinaPy:
        """
        Wraps a key using a Key Management Algorithm alg.
        """
        raise NotImplementedError

    def unwrap_key(self, cypherkey: bytes, alg: Optional[str] = None) -> BinaPy:
        """
        Unwraps a key using a Key Management Algorithm alg.
        """
        raise NotImplementedError

    CRYPTOGRAPHY_PRIVATE_KEY_TYPES = {
        rsa.RSAPrivateKey: "RSA",
        ec.EllipticCurvePrivateKey: "EC",
    }

    @classmethod
    def from_cryptography_key(cls, key: Any) -> Jwk:
        """
        Initializes a Jwk from a key from the `cryptography` library.

        `key` can be private or public.
        """
        raise NotImplementedError

    def to_cryptography_key(self) -> Any:
        """
        Returns a key from the `cryptography` library that matches this Jwk
        """
        raise NotImplementedError

    @classmethod
    def from_pem_private_key(cls, data: bytes, password: Optional[bytes] = None) -> Jwk:
        cryptography_key = serialization.load_pem_private_key(data, password)
        kty = cls.CRYPTOGRAPHY_PRIVATE_KEY_TYPES.get(type(cryptography_key))
        if kty is None:
            raise ValueError(
                f"Unsupported Key type for this key (cryptography type: {type(cryptography_key)}"
            )
        jwk_class = cls.subclasses.get(kty)
        if jwk_class is None:
            raise ValueError(f"Unimplemented Jwk class for this Key Type: {kty}")
        return jwk_class.from_cryptography_key(cryptography_key)

    def to_pem_private_key(cls, password: Optional[bytes] = None) -> str:
        raise NotImplementedError

    @classmethod
    def generate(self, **kwargs: Any) -> "Jwk":
        """
        Generates a Private Key. This method is implemented by subclasses for specific Key Types
        and returns an instance of that specific subclass.
        """
        raise NotImplementedError

    @classmethod
    def generate_for_kty(cls, kty: str, **kwargs: Any) -> "Jwk":
        jwk_class = cls.subclasses.get(kty)
        if jwk_class is None:
            raise ValueError("Unsupported Key Type:", kty)
        return jwk_class.generate(**kwargs)
