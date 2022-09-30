"""This module implements the `Jwk` base class, which provides most of the common features of all JWK types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    SupportsBytes,
    Tuple,
    Type,
    Union,
)

from backports.cached_property import cached_property
from binapy import BinaPy
from cryptography.hazmat.primitives import serialization

from jwskate.jwa import (
    BaseAESEncryptionAlg,
    BaseAesGcmKeyWrap,
    BaseAesKeyWrap,
    BaseAsymmetricAlg,
    BaseEcdhEs_AesKw,
    BaseKeyManagementAlg,
    BaseRsaKeyWrap,
    BaseSignatureAlg,
    BaseSymmetricAlg,
    DirectKeyUse,
    EcdhEs,
)

from .. import BaseAlg
from ..token import BaseJsonDict
from .alg import UnsupportedAlg, select_alg, select_algs

if TYPE_CHECKING:
    from .jwks import JwkSet  # pragma: no cover


class UnsupportedKeyType(ValueError):
    """Raised when an unsupported Key Type is requested."""


class InvalidJwk(ValueError):
    """Raised when an invalid JWK is encountered."""


@dataclass
class JwkParameter:  # noqa: D101
    description: str
    is_private: bool
    is_required: bool
    kind: str


class Jwk(BaseJsonDict):
    """Represents a Json Web Key (JWK), as specified in RFC7517.

    A JWK is a JSON object that represents a cryptographic key.  The
    members of the object represent properties of the key, including its
    value. Just like a parsed JSON object, a :class:`Jwk` is a dict, so
    you can do with a Jwk anything you can do with a `dict`. In
    addition, all keys parameters are exposed as attributes. There are
    subclasses of `Jwk` for each specific Key Type, but you shouldn't
    have to use the subclasses directly since they all present a common
    interface.

    Args:
        params: a dict with the parsed Jwk parameters, or a `cryptography key`, or another `Jwk`
        include_kid_thumbprint: if `True` (default), and there is no kid in the provided params, generate a kid based on the key thumbprint
    """

    subclasses: Dict[str, Type[Jwk]] = {}
    """A dict of 'kty' values to subclasses implementing each specific Key Type"""

    cryptography_key_types: Dict[Any, Type[Jwk]] = {}
    """A dict of cryptography key classes to its specific 'kty' value"""

    PARAMS: Mapping[str, JwkParameter]
    """A dict of parameters. Key is parameter name, value is a tuple (description, is_private, is_required, kind)"""

    KTY: ClassVar[str]
    """The Key Type associated with this JWK."""

    CRYPTOGRAPHY_PRIVATE_KEY_CLASSES: ClassVar[Iterable[Any]]
    CRYPTOGRAPHY_PUBLIC_KEY_CLASSES: ClassVar[Iterable[Any]]

    SIGNATURE_ALGORITHMS: Mapping[str, Type[BaseSignatureAlg]] = {}
    KEY_MANAGEMENT_ALGORITHMS: Mapping[str, Type[BaseKeyManagementAlg]] = {}
    ENCRYPTION_ALGORITHMS: Mapping[str, Type[BaseAESEncryptionAlg]] = {}

    IANA_HASH_FUNCTION_NAMES: Mapping[str, str] = {
        # IANA registered names to binapy hash name
        "sha-1": "sha1",
        "sha-224": "sha224",
        "sha-256": "sha256",
        "sha-384": "sha384",
        "sha-512": "sha512",
        "shake128": "shake128",
        "shake256": "shake256",
    }

    def __init_subclass__(cls) -> None:
        """Automatically add subclasses to the registry.

        This allows `__new__` to pick the appropriate subclass when creating a Jwk.
        """
        Jwk.subclasses[cls.KTY] = cls
        for klass in cls.CRYPTOGRAPHY_PRIVATE_KEY_CLASSES:
            Jwk.cryptography_key_types[klass] = cls
        for klass in cls.CRYPTOGRAPHY_PUBLIC_KEY_CLASSES:
            Jwk.cryptography_key_types[klass] = cls

    def __new__(cls, key: Union[Jwk, Dict[str, Any], Any], **kwargs: Any):  # type: ignore
        """Overridden `__new__` to make the Jwk constructor smarter.

        The Jwk constructor will accept:

            - a `dict` with the parsed Jwk content
            - another Jwk, which will be used as-is instead of creating a copy
            - an instance from a `cryptography` public or private key class

        Args:
            key: a dict containing JWK parameters, or another Jwk instance, or a `cryptography` key
            **kwargs: additional members to include in the Jwk
        """
        if cls == Jwk:
            if isinstance(key, Jwk):
                return cls.from_cryptography_key(key.cryptography_key, **kwargs)
            if isinstance(key, dict):
                kty: Optional[str] = key.get("kty")
                if kty is None:
                    raise InvalidJwk("A Json Web Key must have a Key Type (kty)")

                subclass = Jwk.subclasses.get(kty)
                if subclass is None:
                    raise InvalidJwk("Unsupported Key Type", kty)
                return super().__new__(subclass)
            elif isinstance(key, str):
                return cls.from_json(key)
            else:
                return cls.from_cryptography_key(key, **kwargs)
        return super().__new__(cls, key, **kwargs)

    def __init__(
        self, params: Union[Dict[str, Any], Any], include_kid_thumbprint: bool = False
    ):
        if isinstance(
            params, dict
        ):  # this is to avoid double init due to the __new__ above
            super().__init__(
                {key: val for key, val in params.items() if val is not None}
            )
            self._validate()
            if self.get("kid") is None and include_kid_thumbprint:
                self["kid"] = self.thumbprint()

        try:
            self.cryptography_key = self._to_cryptography_key()
        except AttributeError as exc:
            raise InvalidJwk() from exc

    @classmethod
    def _get_alg_class(cls, alg: str) -> Type[BaseAlg]:
        """Given an alg identifier, return the matching JWA wrapper.

        Args:
            alg: an alg identifier

        Returns:
            the matching JWA wrapper
        """
        alg_class: Optional[Type[BaseAlg]]

        alg_class = cls.SIGNATURE_ALGORITHMS.get(alg)
        if alg_class is not None:
            return alg_class

        alg_class = cls.KEY_MANAGEMENT_ALGORITHMS.get(alg)
        if alg_class is not None:
            return alg_class

        alg_class = cls.ENCRYPTION_ALGORITHMS.get(alg)
        if alg_class is not None:
            return alg_class

        raise UnsupportedAlg(alg)

    @property
    def is_private(self) -> bool:
        """Return `True` if the key is private, `False` otherwise.

        Returns:
            `True` if the key is private, `False` otherwise
        """
        return True

    @property
    def is_symmetric(self) -> bool:
        """Return `True` if the key is symmetric, `False` otherwise."""
        return False

    def __getattr__(self, param: str) -> Any:
        """Allow access to key parameters as attributes.

        This is a convenience to allow `jwk.param` instead of `jwk['param']`.

        Args:
            param: the parameter name to access

        Return:
            the param value

        Raises:
            AttributeError: if the param is not found
        """
        value = self.get(param)
        if value is None:
            raise AttributeError(param)
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        """Override base method to avoid modifying cryptographic key attributes.

        Args:
            key: name of the attribute to set
            value: value to set

        Raises:
            RuntimeError: when trying to modify cryptographic attributes
        """
        if key in self.PARAMS:
            raise RuntimeError("JWK key attributes cannot be modified.")
        super().__setitem__(key, value)

    def thumbprint(self, hashalg: str = "sha-256") -> str:
        """Return the key thumbprint as specified by RFC 7638.

        Args:
          hashalg: A hash function (defaults to SHA256)

        Returns:
            the calculated thumbprint
        """
        alg = self.IANA_HASH_FUNCTION_NAMES.get(hashalg)
        if not alg:
            raise ValueError(f"Unsupported hash alg {hashalg}")

        t = {"kty": self.get("kty")}
        for name, param in self.PARAMS.items():
            if param.is_required and not param.is_private:
                t[name] = self.get(name)

        return (
            BinaPy.serialize_to("json", t, separators=(",", ":"), sort_keys=True)
            .to(alg)
            .to("b64u")
            .ascii()
        )

    def thumbprint_uri(self, hashalg: str = "sha-256") -> str:
        """Returns the JWK thumbprint URI for this key.

        Args:
            hashalg: the IANA registered name for the hash alg to use

        Returns:
             the JWK thumbprint uri for this Jwk
        """
        return (
            f"urn:ietf:params:oauth:jwk-thumbprint:{hashalg}:{self.thumbprint(hashalg)}"
        )

    @property
    def kty(self) -> str:
        """Return the Key Type.

        Returns:
            the key type
        """
        return self.KTY

    @property
    def alg(self) -> Optional[str]:
        """Return the configured key alg, if any.

        Returns:
            the key alg
        """
        alg = self.get("alg")
        if alg is not None and not isinstance(alg, str):  # pragma: no branch
            raise TypeError(f"Invalid alg type {type(alg)}", alg)
        return alg

    @property
    def kid(self) -> Optional[str]:
        """Return the JWK key ID (kid), if present."""
        kid = self.get("kid")
        if kid is not None and not isinstance(kid, str):  # pragma: no branch
            raise TypeError(f"invalid kid type {type(kid)}", kid)
        return kid

    @cached_property
    def use(self) -> Optional[str]:
        """Return the key use.

        If no `alg` parameter is present, this returns the `use` parameter from this JWK. If an
        `alg` parameter is present, the use is deduced from this alg. To check for the presence of
        the `use` parameter, use `jwk.get('use')`.
        """
        if self.alg:
            return self._get_alg_class(self.alg).use
        else:
            return self.get("use")

    @cached_property
    def key_ops(self) -> List[str]:
        """Return the key operations.

        If no `alg` parameter is present, this returns the `key_ops` parameter from this JWK. If an
        `alg` parameter is present, the key operations are deduced from this alg. To check for the
        presence of the `key_ops` parameter, use `jwk.get('key_ops')`.
        """
        if self.use == "sig":
            if self.is_symmetric:
                key_ops = ["sign", "verify"]
            elif self.is_private:
                key_ops = ["sign"]
            else:
                key_ops = ["verify"]
        elif self.use == "enc":
            if self.is_symmetric:
                if self.alg:
                    alg_class = self._get_alg_class(self.alg)
                    if issubclass(alg_class, BaseKeyManagementAlg):
                        key_ops = ["wrapKey", "unwrapKey"]
                    elif issubclass(alg_class, BaseAESEncryptionAlg):
                        key_ops = ["encrypt", "decrypt"]
                else:
                    key_ops = ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
            elif self.is_private:
                key_ops = ["unwrapKey"]
            else:
                key_ops = ["wrapKey"]
        else:
            key_ops = self.get("key_ops", [])

        return key_ops

    def _validate(self) -> None:
        """Internal method used to validate a Jwk.

        It checks that all required parameters are present and well-formed. If the key is private, it sets the `is_private` flag to `True`.

        Raises:
            TypeError: if the key type doesn't match the subclass
            InvalidJwk: if the JWK misses required members or has invalid members
        """
        if self.get("kty") != self.KTY:
            raise TypeError(
                f"This key 'kty' {self.get('kty')} doesn't match this Jwk subclass intended 'kty' {self.KTY}!"
            )

        jwk_is_private = False
        for name, param in self.PARAMS.items():

            value = self.get(name)

            if param.is_private and value is not None:
                jwk_is_private = True

            if not param.is_private and param.is_required and value is None:
                raise InvalidJwk(
                    f"Missing required public param {param.description} ({name})"
                )

            if value is None:
                pass
            elif param.kind == "b64u":
                if not isinstance(value, str):
                    raise InvalidJwk(
                        f"Parameter {param.description} ({name}) must be a string with a Base64URL-encoded value"
                    )
                if not BinaPy(value).check("b64u"):
                    raise InvalidJwk(
                        f"Parameter {param.description} ({name}) must be a Base64URL-encoded value"
                    )
            elif param.kind == "unsupported":
                if value is not None:  # pragma: no cover
                    raise InvalidJwk(f"Unsupported JWK param '{name}'")
            elif param.kind == "name":
                pass
            else:
                assert (
                    False
                ), f"Unsupported param '{name}' type '{param.kind}'"  # pragma: no cover

        # if at least one of the supplied parameter was private, then all required private parameters must be provided
        if jwk_is_private:
            for name, param in self.PARAMS.items():
                value = self.get(name)
                if param.is_private and param.is_required and value is None:
                    raise InvalidJwk(
                        f"Missing required private param {param.description} ({name})"
                    )

        # if key is used for signing, it must be private
        for op in self.get("key_ops", []):
            if op in ("sign", "unwrapKey") and not self.is_private:
                raise InvalidJwk(f"Key Operation is '{op}' but the key is public")

    def supported_signing_algorithms(self) -> List[str]:
        """Return the list of Signature algorithms that can be used with this key.

        Returns:
          a list of supported algs
        """
        return list(self.SIGNATURE_ALGORITHMS)

    def supported_key_management_algorithms(self) -> List[str]:
        """Return the list of Key Management algorithms that can be used with this key.

        Returns:
            a list of supported algs
        """
        return list(self.KEY_MANAGEMENT_ALGORITHMS)

    def supported_encryption_algorithms(self) -> List[str]:
        """Return the list of Encryption algorithms that can be used with this key.

        Returns:
            a list of supported algs
        """
        return list(self.ENCRYPTION_ALGORITHMS)

    def public_jwk(self) -> Jwk:
        """Return the public Jwk associated with this key.

        Returns:
          a Jwk with the public key
        """
        if not self.is_private:
            return self

        params = {
            name: self.get(name)
            for name, param in self.PARAMS.items()
            if not param.is_private
        }

        if "key_ops" in self:
            key_ops = list(self.key_ops)
            if "sign" in key_ops:
                key_ops.remove("sign")
                key_ops.append("verify")
            if "unwrapKey" in key_ops:
                key_ops.remove("unwrapKey")
                key_ops.append("wrapKey")
        else:
            key_ops = None

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

    def as_jwks(self) -> JwkSet:
        """Return a JwkSet with this key as single element.

        Returns:
            a JwsSet with this single key
        """
        from .jwks import JwkSet

        return JwkSet(keys=(self,))

    def sign(
        self, data: Union[bytes, SupportsBytes], alg: Optional[str] = None
    ) -> BinaPy:
        """Sign a data using this Jwk, and return the generated signature.

        Args:
          data: the data to sign
          alg: the alg to use (if this key doesn't have an `alg` parameter)

        Returns:
          the generated signature
        """
        sigalg = select_alg(self.alg, alg, self.SIGNATURE_ALGORITHMS)
        wrapper: BaseSignatureAlg
        if issubclass(sigalg, BaseAsymmetricAlg):
            wrapper = sigalg(self.cryptography_key)

        elif issubclass(sigalg, BaseSymmetricAlg):
            wrapper = sigalg(self.key)

        signature = wrapper.sign(data)
        return BinaPy(signature)

    def verify(
        self,
        data: Union[bytes, SupportsBytes],
        signature: Union[bytes, SupportsBytes],
        *,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        """Verify a signature using this Jwk, and return `True` if valid.

        Args:
          data: the data to verify
          signature: the signature to verify
          alg: the allowed signature alg, if there is only one
          algs: the allowed signature algs, if there are several

        Returns:
          `True` if the signature matches, `False` otherwise
        """
        wrapper: BaseSignatureAlg
        for sigalg in select_algs(self.alg, alg, algs, self.SIGNATURE_ALGORITHMS):
            if issubclass(sigalg, BaseAsymmetricAlg):
                key = self.public_jwk().cryptography_key
                wrapper = sigalg(key)
            elif issubclass(sigalg, BaseSymmetricAlg):
                key = self.key
                wrapper = sigalg(key)
            if wrapper.verify(data, signature):
                return True

        return False

    def encrypt(
        self,
        plaintext: Union[bytes, SupportsBytes],
        *,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
        iv: Optional[bytes] = None,
    ) -> Tuple[BinaPy, BinaPy, BinaPy]:
        """Encrypt a plaintext with Authenticated Encryption using this key.

        Authenticated Encryption with Associated Data (AEAD) is supported, by passing Additional Authenticated Data (`aad`).
        This returns a tuple with 3 raw data, in order:
        - the encrypted Data
        - the Initialization Vector that was used to encrypt data
        - the generated Authentication Tag

        Args:
          plaintext: the data to encrypt.
          aad: the Additional Authenticated Data (AAD) to include in the authentication tag
          alg: the alg to use to encrypt the data
          iv: the Initialization Vector to use. If not provided, an IV is generated. If provided, the returned IV will be the same.

        Returns:
          a tuple (ciphertext, iv, authentication_tag), as raw data
        """
        raise NotImplementedError  # pragma: no cover

    def decrypt(
        self,
        ciphertext: Union[bytes, SupportsBytes],
        *,
        iv: Union[bytes, SupportsBytes],
        tag: Union[bytes, SupportsBytes],
        aad: Union[bytes, SupportsBytes, None] = None,
        alg: Optional[str] = None,
    ) -> BinaPy:
        """Decrypt an encrypted data using this Jwk, and return the encrypted result.

        This is implemented by subclasses.

        Args:
          ciphertext: the data to decrypt
          iv: the Initialization Vector (IV) that was used for encryption
          tag: the Authentication Tag that will be verified while decrypting data
          aad: the Additional Authentication Data (AAD) to verify the Tag against
          alg: the alg to use for decryption

        Returns:
          the clear-text data
        """
        raise NotImplementedError  # pragma: no cover

    def sender_key(
        self,
        enc: str,
        *,
        alg: Optional[str] = None,
        cek: Optional[bytes] = None,
        epk: Optional[Jwk] = None,
        **headers: Any,
    ) -> Tuple[Jwk, BinaPy, Mapping[str, Any]]:
        """Used by encrypted token senders to produce a Content Encryption Key.

        Returns a tuple with 3 items:

        - the clear text CEK, as a SymmetricJwk instance. Use this key to encrypt your message, but do not communicate this key to anyone!
        - the encrypted CEK, as bytes. You must send this to your recipient. This may be `None` for Key Management algs which derive a CEK instead of generating one.
        - extra headers depending on the Key Management algorithm, as a dict of name to values: you must send those to your recipient as well.

        For algorithms that rely on a randomly generated CEK, such as RSAES or AES, you can provide that CEK instead
        of letting `jwskate` generate a safe, unique random value for you.
        Likewise, for algorithms that rely on an ephemeral key, you can provide an EPK that you generated yourself,
        instead of letting `jwskate` generate an appropriate value for you.
        Only do this if you know what you are doing!

        Args:
          enc: the encryption algorithm to use with the CEK
          alg: the Key Management algorithm to use to produce the CEK
          cek: CEK to use (leave `None` to have an adequate random value generated automatically)
          epk: EPK to use (leave `None` to have an adequate ephemeral key generated automatically)
          **headers: additional headers to include for the CEK derivation

        Returns:
          Tuple[Jwk,BinaPy,Mapping[str,Any]]: a tuple (cek, wrapped_cek, additional_headers_map)

        Raises:
            UnsupportedAlg: if the requested alg identifier is not supported
        """
        from jwskate import SymmetricJwk

        keyalg = select_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)
        encalg = select_alg(None, enc, SymmetricJwk.ENCRYPTION_ALGORITHMS)

        cek_headers: Dict[str, Any] = {}

        if issubclass(keyalg, BaseRsaKeyWrap):
            rsa: BaseRsaKeyWrap = keyalg(self.public_jwk().cryptography_key)
            if cek:
                encalg.check_key(cek)
            else:
                cek = encalg.generate_key()
            assert cek
            wrapped_cek = rsa.wrap_key(cek)

        elif issubclass(keyalg, EcdhEs):
            ecdh: EcdhEs = keyalg(self.public_jwk().cryptography_key)
            epk = epk or Jwk.from_cryptography_key(ecdh.generate_ephemeral_key())
            cek_headers = {"epk": epk.public_jwk()}
            if isinstance(ecdh, BaseEcdhEs_AesKw):
                if cek:
                    encalg.check_key(cek)
                else:
                    cek = encalg.generate_key()
                assert cek
                wrapped_cek = ecdh.wrap_key_with_epk(
                    cek, epk.cryptography_key, alg=keyalg.name, **headers
                )
            else:
                cek = ecdh.sender_key(
                    epk.cryptography_key,
                    alg=encalg.name,
                    key_size=encalg.key_size,
                    **headers,
                )
                wrapped_cek = BinaPy(b"")
        elif issubclass(keyalg, BaseAesKeyWrap):
            aes: BaseAesKeyWrap = keyalg(self.cryptography_key)
            if cek:
                encalg.check_key(cek)
            else:
                cek = encalg.generate_key()
            assert cek
            wrapped_cek = aes.wrap_key(cek)

        elif issubclass(keyalg, BaseAesGcmKeyWrap):
            aesgcm: BaseAesGcmKeyWrap = keyalg(self.cryptography_key)
            if cek:
                encalg.check_key(cek)
            else:
                cek = encalg.generate_key()
            assert cek
            iv = aesgcm.generate_iv()
            wrapped_cek, tag = aesgcm.wrap_key(cek, iv=iv)
            cek_headers = {
                "iv": iv.to("b64u").ascii(),
                "tag": tag.to("b64u").ascii(),
            }

        elif issubclass(keyalg, DirectKeyUse):
            dir: DirectKeyUse = keyalg(self.key)
            cek = dir.direct_key(encalg)
            wrapped_cek = BinaPy(b"")
        else:
            raise UnsupportedAlg(f"Unsupported Key Management Alg {keyalg}")

        return SymmetricJwk.from_bytes(cek), wrapped_cek, cek_headers

    def recipient_key(
        self,
        wrapped_cek: Union[bytes, SupportsBytes],
        enc: str,
        *,
        alg: Optional[str] = None,
        **headers: Any,
    ) -> Jwk:
        """Used by token recipients to obtain the CEK, which then allows decryption of the payload.

        Args:
          wrapped_cek: the wrapped CEK
          enc: the encryption algorithm to use with the CEK
          alg: the Key Management algorithm to use to unwrap the CEK
          **headers: additional headers used to decrypt the CEK (e.g. "epk" for ECDH algs, "iv", "tag" for AES-GCM algs)

        Returns:
          the clear-text CEK, as a SymmetricJwk instance

        Raises:
            UnsupportedAlg: if the requested alg identifier is not supported
        """
        from jwskate import SymmetricJwk

        keyalg = select_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)
        encalg = select_alg(None, enc, SymmetricJwk.ENCRYPTION_ALGORITHMS)

        if issubclass(keyalg, BaseRsaKeyWrap):
            rsa = keyalg(self.cryptography_key)
            cek = rsa.unwrap_key(wrapped_cek)

        elif issubclass(keyalg, EcdhEs):
            ecdh = keyalg(self.cryptography_key)
            epk = headers.get("epk")
            if epk is None:
                raise ValueError("No EPK in the headers!")
            epk_jwk = Jwk(epk)
            if epk_jwk.is_private:
                raise ValueError("The EPK present in the header is private.")
            epk = epk_jwk.cryptography_key
            encalg = select_alg(None, enc, SymmetricJwk.ENCRYPTION_ALGORITHMS)
            if isinstance(ecdh, BaseEcdhEs_AesKw):
                cek = ecdh.unwrap_key_with_epk(wrapped_cek, epk, alg=keyalg.name)
            else:
                cek = ecdh.recipient_key(
                    epk, alg=encalg.name, key_size=encalg.key_size, **headers
                )

        elif issubclass(keyalg, BaseAesKeyWrap):
            aes = keyalg(self.cryptography_key)
            cek = aes.unwrap_key(wrapped_cek)

        elif issubclass(keyalg, BaseAesGcmKeyWrap):
            aesgcm = keyalg(self.cryptography_key)
            iv = headers.get("iv")
            if iv is None:
                raise ValueError("No 'iv' in headers!")
            iv = BinaPy(iv).decode_from("b64u")
            tag = headers.get("tag")
            if tag is None:
                raise ValueError("No 'tag' in headers!")
            tag = BinaPy(tag).decode_from("b64u")
            cek = aesgcm.unwrap_key(wrapped_cek, tag=tag, iv=iv)

        elif issubclass(keyalg, DirectKeyUse):
            dir_ = keyalg(self.key)
            cek = dir_.direct_key(encalg)
        else:
            raise UnsupportedAlg(f"Unsupported Key Management Alg {keyalg}")

        return SymmetricJwk.from_bytes(cek)

    @classmethod
    def from_cryptography_key(cls, cryptography_key: Any, **kwargs: Any) -> Jwk:
        """Initialize a Jwk from a key from the `cryptography` library.

        The input key can be any private or public key supported by cryptography.

        Args:
          cryptography_key: a `cryptography` key instance
          **kwargs: additional members to include in the Jwk (e.g. kid, use)

        Returns:
            the matching `Jwk` instance

        Raises:
            TypeError: if the key type is not supported
        """
        for klass in cryptography_key.__class__.mro():
            jwk_class = cls.cryptography_key_types.get(klass)
            if jwk_class:
                return jwk_class.from_cryptography_key(cryptography_key, **kwargs)

        raise TypeError(f"Unsupported Jwk class for this Key Type: {cryptography_key}")

    def _to_cryptography_key(self) -> Any:
        """Return a key from the `cryptography` library that matches this Jwk.

        This is implemented by subclasses.

        Returns:
            a `cryptography`key instance initialized from the current key
        """
        raise NotImplementedError

    @classmethod
    def from_pem_key(
        cls,
        data: Union[bytes, str],
        password: Union[bytes, str, None] = None,
        **kwargs: Any,
    ) -> Jwk:
        """Load a Jwk from a PEM encoded private or public key.

        Args:
          data: the PEM encoded data to load
          password: the password to decrypt the PEM, if required
          **kwargs: additional members to include in the Jwk (e.g. kid, use)

        Returns:
            a Jwk instance from the loaded key
        """
        if isinstance(data, str):
            data = data.encode()

        if isinstance(password, str):
            password = password.encode()

        try:
            cryptography_key = serialization.load_pem_private_key(data, password)
        except Exception as private_exc:
            try:
                cryptography_key = serialization.load_pem_public_key(data)
                if password is not None:
                    raise ValueError(
                        "A public key was loaded from PEM, while a password was provided for decryption."
                        "Only private keys are encrypted in PEM."
                    )
            except Exception:
                raise ValueError(
                    "The provided data is not a private or a public PEM encoded key."
                ) from private_exc

        return cls.from_cryptography_key(cryptography_key, **kwargs)

    def to_pem(self, password: Union[bytes, str, None] = None) -> bytes:
        """Serialize this key to PEM format.

        For private keys, you can provide a password for encryption. This password should be bytes. A `str` is also
        accepted, and will be encoded to `bytes` using UTF-8 before it is used as encryption key.

        Args:
          password: password to use to encrypt the PEM

        Returns:
            the PEM serialized key
        """
        if password is not None and not isinstance(password, bytes):
            password = str(password).encode("UTF-8")

        if self.is_private:
            encryption: serialization.KeySerializationEncryption
            if password:
                encryption = serialization.BestAvailableEncryption(password)
            else:
                encryption = serialization.NoEncryption()
            return self.cryptography_key.private_bytes(  # type: ignore[no-any-return]
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption,
            )
        else:
            if password:
                raise ValueError(
                    "Public keys cannot be encrypted when serialized in PEM format."
                )
            return self.cryptography_key.public_bytes(  # type: ignore[no-any-return]
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    @classmethod
    def generate(cls, **kwargs: Any) -> Jwk:
        """Generate a Private Key and return it as a `Jwk` instance.

        This method is implemented by subclasses for specific Key Types and returns an instance of that subclass.

        Args:
          **kwargs: specific parameters depending on the type of key, or additional members to include in the Jwk

        Returns:
            a Jwk instance with a generated key
        """
        raise NotImplementedError

    @classmethod
    def generate_for_kty(cls, kty: str, **kwargs: Any) -> Jwk:
        """Generate a key with a specific type and return the resulting Jwk.

        Args:
          kty: key type to generate
          **kwargs: specific parameters depending on the key type, or additional members to include in the Jwk

        Returns:
            the resulting Jwk

        Raises:
            UnsupportedKeyType: if the key type is not supported
        """
        jwk_class = cls.subclasses.get(kty)
        if jwk_class is None:
            raise UnsupportedKeyType("Unsupported Key Type:", kty)
        return jwk_class.generate(**kwargs)

    @classmethod
    def generate_for_alg(cls, alg: str, **kwargs: Any) -> Jwk:
        """Generate a key for usage with a specific alg and return the resulting Jwk.

        Args:
            alg: a signature or key management alg
            **kwargs: specific parameters depending on the key type, or additional members to include in the Jwk

        Returns:
            the resulting Jwk
        """
        for kty, jwk_class in cls.subclasses.items():
            alg_class: Optional[Type[BaseAlg]]
            try:
                alg_class = jwk_class._get_alg_class(alg)
                if isinstance(jwk_class, BaseAESEncryptionAlg):
                    kwargs.setdefault("key_size", alg_class.key_size)

                return jwk_class.generate(alg=alg, **kwargs)
            except UnsupportedAlg:
                continue

        raise UnsupportedAlg(alg)

    def copy(self) -> Jwk:
        """Creates a copy of this key.

        Returns:
            a copy of this key, with the same value
        """
        return Jwk(super().copy())

    def with_kid_thumbprint(self, force: bool = False) -> Jwk:
        """Includes the JWK thumbprint as "kid".

        If key already has a "kid":
        - if `force` is `True`, this erases the previous "kid".
        - if `force` is `False` (default), do nothing.

        Args:
            force: whether to overwrite a previously existing kid

        Returns:
            a copy of this key with a "kid" (either the previous one or the existing one, depending on `force`).
        """
        if self.get("kid") is not None and not force:
            return self
        jwk = self.copy()
        jwk["kid"] = self.thumbprint()
        return jwk

    def with_usage_parameters(
        self,
        alg: Optional[str] = None,
        with_alg: bool = True,
        with_use: bool = True,
        with_key_ops: bool = True,
    ) -> Jwk:
        """Copy this Jwk and add the `use` and `key_ops` parameters.

        The returned jwk `alg` parameter will be the one passed as parameter to this method, or as dfault the one declared as `alg` parameter in this Jwk.
        The `use` (Public Key Use) param is deduced based on this `alg` value.
        The `key_ops` (Key Operations) param is deduced based on the key `use` and if the key is public, private,
        or symmetric.

        Args:
            alg: the alg to use, if not present in this Jwk
            with_alg: whether to include an `alg` parameter
            with_use: whether to include a `use` parameter
            with_key_ops: whether to include a `key_ops` parameter

        Returns:
            a Jwk with the same key, with `alg`, `use` and `key_ops` parameters.
        """
        alg = alg or self.alg

        if not alg:
            raise ValueError("An algorithm is required to set the usage parameters")

        self._get_alg_class(alg)  # raises an exception if alg is not supported

        jwk = self.copy()
        if with_alg:
            jwk["alg"] = alg
        if with_use:
            jwk["use"] = jwk.use
        if with_key_ops:
            jwk["key_ops"] = jwk.key_ops

        return jwk

    def minimize(self) -> Jwk:
        """Strips out any optional or non-standard parameter from that key.

        This will remove `alg`, `use`, `key_ops`, optional parameters from RSA keys, and unknown
        parameters.
        """
        jwk = self.copy()
        for key in self.keys():
            if key == "kty" or key in self.PARAMS and self.PARAMS[key].is_required:
                continue
            del jwk[key]

        return jwk
