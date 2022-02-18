from __future__ import annotations

import hashlib
import json
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
    Tuple,
    Type,
    TypeVar,
    Union,
)

from binapy import BinaPy
from cryptography.hazmat.primitives import serialization

from jwskate.jwa import (
    BaseAESEncryptionAlg,
    BaseAesGcmKeyWrap,
    BaseAesKeyWrap,
    BaseAsymmetricAlg,
    BaseEcdhEs_AesKw,
    BaseKeyManagementAlg,
    BaseSignatureAlg,
    BaseSymmetricAlg,
    DirectKeyUse,
    EcdhEs,
    RsaKeyWrap,
)

from .alg import UnsupportedAlg, select_alg, select_algs

if TYPE_CHECKING:
    from .jwks import JwkSet


class InvalidJwk(ValueError):
    pass


@dataclass
class JwkParameter:
    description: str
    is_private: bool
    is_required: bool
    kind: str


D = TypeVar("D", bound="BaseJsonDict")


class BaseJsonDict(Dict[str, Any]):
    @classmethod
    def from_json(cls: Type[D], j: str) -> D:
        return cls(json.loads(j))

    def to_json(self, *args: Any, **kwargs: Any) -> str:
        return json.dumps(self, *args, **kwargs)


class Jwk(BaseJsonDict):
    """
    Represents a Json Web Key (JWK), as specified in RFC7517.
    A JWK is a JSON object that represents a cryptographic key.  The members of the object
    represent properties of the key, including its value.
    Just like a parsed JSON object, a :class:`Jwk` is a dict, so you can do with a Jwk anything you can do with a `dict`.
    In addition, all keys parameters are exposed as attributes.
    There are subclasses of `Jwk` for each specific Key Type, but you shouldn't have to use the subclasses directly
    since they all present a common interface.
    """

    subclasses: Dict[str, Type[Jwk]] = {}
    """A dict of 'kty' values to subclasses implementing each specific Key Type"""

    cryptography_key_types: Dict[Any, Type[Jwk]] = {}
    """A dict of cryptography key classes to its specific 'kty' value"""

    PARAMS: Mapping[str, JwkParameter]
    """A dict of parameters. Key is parameter name, value is a tuple (description, is_private, is_required, kind)"""

    KTY: ClassVar[str]
    """The Key Type associated with this JWK."""

    CRYPTOGRAPHY_KEY_CLASSES: ClassVar[Iterable[Any]]

    SIGNATURE_ALGORITHMS: Mapping[str, Type[BaseSignatureAlg]] = {}
    KEY_MANAGEMENT_ALGORITHMS: Mapping[str, Type[BaseKeyManagementAlg]] = {}
    ENCRYPTION_ALGORITHMS: Mapping[str, Type[BaseAESEncryptionAlg]] = {}

    def __init_subclass__(cls) -> None:
        """
        Automatically add subclasses to the registry.
        This allows __new__ to pick the appropriate subclass when creating a Jwk
        """
        Jwk.subclasses[cls.KTY] = cls
        for klass in cls.CRYPTOGRAPHY_KEY_CLASSES:
            Jwk.cryptography_key_types[klass] = cls

    def __new__(cls, jwk: Union[Jwk, Dict[str, Any]]):  # type: ignore
        """
        Overridden `__new__` to allow Jwk to accept:
        - a `dict` with the parsed Jwk content
        - another Jwk, which will be used as-is instead of creating a copy
        - an instance from a `cryptography` public or private key class
        :param jwk: a dict containing JWK parameters, or another Jwk instance, or a `cryptography` key.
        """
        if cls == Jwk:
            if isinstance(jwk, Jwk):
                return jwk
            elif isinstance(jwk, dict):
                kty: Optional[str] = jwk.get("kty")
                if kty is None:
                    raise ValueError("A Json Web Key must have a Key Type (kty)")

                subclass = Jwk.subclasses.get(kty)
                if subclass is None:
                    raise ValueError("Unsupported Key Type", kty)
                return super().__new__(subclass)

            return cls.from_cryptography_key(jwk)
        return super().__new__(cls)

    def __init__(self, params: Dict[str, Any], include_kid_thumbprint: bool = False):
        """
        Initialize a Jwk. Accepts a `dict` with the parsed Jwk contents, and an optional kid if it isn't already part
        of the dict.
        If no `kid` is supplied and `include_kid_thumbprint`, a default kid is generated based on the key thumbprint (defined in RFC7638)
        :param params: a dict with the parsed Jwk parameters.
        :param kid: a Key Id to use if no `kid` parameters is present in `params`.
        """
        super().__init__({key: val for key, val in params.items() if val is not None})
        self.is_private = False
        self._validate()
        if self.get("kid") is None and include_kid_thumbprint:
            self["kid"] = self.thumbprint()

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
        for name, param in self.PARAMS.items():
            if param.is_required and not param.is_private:
                t[name] = self.get(name)

        intermediary = json.dumps(t, separators=(",", ":"), sort_keys=True)
        digest.update(intermediary.encode("utf8"))
        return BinaPy(digest.digest()).encode_to("b64u").decode()

    @property
    def kty(self) -> str:
        return self.KTY

    @property
    def alg(self) -> Optional[str]:
        alg = self.get("alg")
        if alg is not None and not isinstance(alg, str):
            raise TypeError(f"Invalid alg type {type(str)}", alg)
        return alg

    def _validate(self) -> None:
        """
        Internal method used to validate a Jwk. It checks that all required parameters are present and well-formed.
        If the key is private, it sets the `is_private` flag to `True`.
        """
        if self.get("kty") != self.KTY:
            raise RuntimeError(
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
                if value is not None:
                    raise InvalidJwk(f"Unsupported JWK param '{name}'")
            elif param.kind == "name":
                pass
            else:
                assert False, f"Unsupported param '{name}' type '{param.kind}'"

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
            if op in ("sign", "decrypt", "unwrapKey") and not jwk_is_private:
                raise InvalidJwk(f"Key Operation is '{op}' but the key is public")

        self.is_private = jwk_is_private

    def supported_signing_algorithms(self) -> List[str]:
        """
        Return a dict of signing algs that are compatible for use with this Jwk.
        :return: a dict of signing algs
        """
        return list(self.SIGNATURE_ALGORITHMS)

    def supported_key_management_algorithms(self) -> List[str]:
        """
        Return a dict of key management algs that are compatible for use with this Jwk.
        :return: a dict of key management algs
        """
        return list(self.KEY_MANAGEMENT_ALGORITHMS)

    def supported_encryption_algorithms(self) -> List[str]:
        """
        Return a dict of encryption algs that are compatible for use with this Jwk.
        :return: a dict of encryption algs
        """
        return list(self.ENCRYPTION_ALGORITHMS)

    def public_jwk(self) -> Jwk:
        """
        Return the public Jwk associated with this private Jwk.
        :return: a Jwk containing only the public parameters.
        """
        if not self.is_private:
            return self

        params = {
            name: self.get(name)
            for name, param in self.PARAMS.items()
            if not param.is_private
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

    def as_jwks(self) -> JwkSet:
        """
        Return a JwkSet containing this single key.
        :return: a JwkSet
        """
        from .jwks import JwkSet

        return JwkSet(keys=(self,))

    def sign(self, data: bytes, alg: Optional[str] = None) -> BinaPy:
        """
        Signs a data using this Jwk, and returns the signature.
        :param data: the data to sign
        :param alg: the alg to use (if this key doesn't have an `alg` parameter).
        :return: the generated signature.
        """
        sigalg = select_alg(self.alg, alg, self.SIGNATURE_ALGORITHMS)
        wrapper: BaseSignatureAlg
        if issubclass(sigalg, BaseAsymmetricAlg):
            wrapper = sigalg(self.to_cryptography_key())

        elif issubclass(sigalg, BaseSymmetricAlg):
            wrapper = sigalg(self.key)

        signature = wrapper.sign(data)
        return BinaPy(signature)

    def verify(
        self,
        data: bytes,
        signature: bytes,
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        """
        Verifies a signature using this Jwk, and returns `True` if valid.
        :param data: the data to verify
        :param signature: the signature to verify
        :param alg: the alg to use to verify the signature (if this key doesn't have an `alg` parameter)
        :return: `True` if the signature matches, `False` otherwise
        """
        wrapper: BaseSignatureAlg
        for sigalg in select_algs(self.alg, alg, algs, self.SIGNATURE_ALGORITHMS):
            if issubclass(sigalg, BaseAsymmetricAlg):
                key = self.public_jwk().to_cryptography_key()
                wrapper = sigalg(key)
            elif issubclass(sigalg, BaseSymmetricAlg):
                key = self.key
                wrapper = sigalg(key)
            if wrapper.verify(data, signature):
                return True

        return False

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
        :return: a tuple (ciphertext, authentication_tag, iv)
        """

        raise NotImplementedError  # pragma: no cover

    def decrypt(
        self,
        ciphertext: bytes,
        tag: bytes,
        iv: bytes,
        aad: Optional[bytes] = None,
        alg: Optional[str] = None,
    ) -> BinaPy:
        """
        Decrypts an encrypted data using this Jwk, and returns the encrypted result.
        This is implemented by subclasses.
        :param ciphertext: the data to decrypt
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

    def unwrap_key(self, cipherkey: bytes, alg: Optional[str] = None) -> Jwk:
        """
        Unwraps a key using a Key Management Algorithm alg.
        """
        raise NotImplementedError

    def sender_key(
        self,
        enc: str,
        alg: Optional[str],
        cek: Optional[bytes] = None,
        epk: Optional[Jwk] = None,
        **headers: Any,
    ) -> Tuple[Jwk, Mapping[str, Any], BinaPy]:
        """
        For DH-based algs. As a token issuer, derive a EPK and CEK from the recipient public key.
        :param alg: the Key Management algorithm to use to produce the CEK
        :param enc: the encryption algorithm to use with the CEK
        :param extra_headers: additional headers that may be used to produce the CEK
        :return: a tuple (CEK, additional_headers_map, wrapped_cek)
        """
        from jwskate import SymmetricJwk

        keyalg = select_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)
        encalg = select_alg(None, enc, SymmetricJwk.ENCRYPTION_ALGORITHMS)

        cek_headers: Dict[str, Any] = {}

        if issubclass(keyalg, RsaKeyWrap):
            rsa = keyalg(self.public_jwk().to_cryptography_key())
            if cek:
                encalg.check_key(cek)
            else:
                cek = encalg.generate_key()
            wrapped_cek = rsa.wrap_key(cek)

        elif issubclass(keyalg, EcdhEs):
            ecdh: EcdhEs = keyalg(self.public_jwk().to_cryptography_key())
            epk = epk or Jwk.from_cryptography_key(ecdh.generate_ephemeral_key())
            cek_headers = {"epk": epk.public_jwk()}
            if isinstance(ecdh, BaseEcdhEs_AesKw):
                if cek:
                    encalg.check_key(cek)
                else:
                    cek = encalg.generate_key()
                wrapped_cek = ecdh.wrap_key_with_epk(
                    cek, epk.to_cryptography_key(), alg=alg, **headers
                )
            else:
                cek = ecdh.sender_key(
                    epk.to_cryptography_key(), encalg.name, encalg.key_size, **headers
                )
                wrapped_cek = BinaPy(b"")
        elif issubclass(keyalg, BaseAesKeyWrap):
            aes: BaseAesKeyWrap = keyalg(self.to_cryptography_key())
            if cek:
                encalg.check_key(cek)
            else:
                cek = encalg.generate_key()
            wrapped_cek = aes.wrap_key(cek)

        elif issubclass(keyalg, BaseAesGcmKeyWrap):
            aesgcm: BaseAesGcmKeyWrap = keyalg(self.to_cryptography_key())
            if cek:
                encalg.check_key(cek)
            else:
                cek = encalg.generate_key()
            iv = aesgcm.generate_iv()
            wrapped_cek, tag = aesgcm.wrap_key(cek, iv)
            cek_headers = {
                "iv": iv.encode_to("b64u").decode(),
                "tag": tag.encode_to("b64u").decode(),
            }

        elif issubclass(keyalg, DirectKeyUse):
            dir = keyalg(self.key)
            cek = dir.sender_key(encalg)
            wrapped_cek = BinaPy(b"")
        else:
            raise UnsupportedAlg(f"Unsupported Key Management Alg {keyalg}")

        return SymmetricJwk.from_bytes(cek), cek_headers, wrapped_cek

    def recipient_key(
        self, wrapped_cek: bytes, alg: str, enc: str, **headers: Any
    ) -> Jwk:
        """
        For DH-based algs. As a token recipient, derive the same CEK that was used for encryption, based on the
        recipient private key and the sender ephemeral public key.
        :param wrapped_cek: the wrapped cek
        :param alg: the Key Management algorithm to use to unwrap the CEK
        :param enc: the encryption algorithm to use with the CEK
        :param headers: additional headers that may be used to produce the CEK
        :return: the clear-text CEK
        """
        from jwskate import SymmetricJwk

        keyalg = select_alg(self.alg, alg, self.KEY_MANAGEMENT_ALGORITHMS)
        encalg = select_alg(None, enc, SymmetricJwk.ENCRYPTION_ALGORITHMS)

        if issubclass(keyalg, RsaKeyWrap):
            rsa = keyalg(self.to_cryptography_key())
            cek = rsa.unwrap_key(wrapped_cek)

        elif issubclass(keyalg, EcdhEs):
            ecdh = keyalg(self.to_cryptography_key())
            epk = headers.get("epk")
            if epk is None:
                raise ValueError("No EPK in the headers!")
            epk_jwk = Jwk(epk)
            if epk_jwk.is_private:
                raise ValueError("The EPK present in the header is private.")
            epk = epk_jwk.to_cryptography_key()
            encalg = select_alg(None, enc, SymmetricJwk.ENCRYPTION_ALGORITHMS)
            if isinstance(ecdh, BaseEcdhEs_AesKw):
                cek = ecdh.unwrap_key_with_epk(wrapped_cek, epk, alg=alg)
            else:
                cek = ecdh.recipient_key(
                    epk, alg=encalg.name, key_size=encalg.key_size, **headers
                )

        elif issubclass(keyalg, BaseAesKeyWrap):
            aes = keyalg(self.to_cryptography_key())
            cek = aes.unwrap_key(wrapped_cek)

        elif issubclass(keyalg, BaseAesGcmKeyWrap):
            aesgcm = keyalg(self.to_cryptography_key())
            iv = headers.get("iv")
            if iv is None:
                raise ValueError("No 'iv' in headers!")
            iv = BinaPy(iv).decode_from("b64u")
            tag = headers.get("tag")
            if tag is None:
                raise ValueError("No 'tag' in headers!")
            tag = BinaPy(tag).decode_from("b64u")
            cek = aesgcm.unwrap_key(wrapped_cek, tag, iv)

        elif issubclass(keyalg, DirectKeyUse):
            dir_ = keyalg(self.key)
            cek = dir_.recipient_key(encalg)
        else:
            raise UnsupportedAlg(f"Unsupported Key Management Alg {keyalg}")

        return SymmetricJwk.from_bytes(cek)

    @classmethod
    def from_cryptography_key(cls, cryptography_key: Any) -> Jwk:
        """
        Initializes a Jwk from a key from the `cryptography` library.

        `key` can be any private or public key supported by cryptography.
        """
        for klass in cryptography_key.__class__.mro():
            jwk_class = cls.cryptography_key_types.get(klass)
            if jwk_class:
                return jwk_class.from_cryptography_key(cryptography_key)

        raise ValueError(f"Unsupported Jwk class for this Key Type: {cryptography_key}")

    def to_cryptography_key(self) -> Any:
        """
        Returns a key from the `cryptography` library that matches this Jwk
        """
        raise NotImplementedError

    @classmethod
    def from_pem_private_key(cls, data: bytes, password: Optional[bytes] = None) -> Jwk:
        cryptography_key = serialization.load_pem_private_key(data, password)
        return cls.from_cryptography_key(cryptography_key)

    def to_pem_private_key(cls, password: Optional[bytes] = None) -> str:
        raise NotImplementedError

    @classmethod
    def generate(self, **kwargs: Any) -> Jwk:
        """
        Generates a Private Key. This method is implemented by subclasses for specific Key Types
        and returns an instance of that specific subclass.
        """
        raise NotImplementedError

    @classmethod
    def generate_for_kty(cls, kty: str, **kwargs: Any) -> Jwk:
        jwk_class = cls.subclasses.get(kty)
        if jwk_class is None:
            raise ValueError("Unsupported Key Type:", kty)
        return jwk_class.generate(**kwargs)
