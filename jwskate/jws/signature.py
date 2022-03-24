from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Optional, Type, TypeVar, Union

from binapy import BinaPy

from jwskate.jwk.base import BaseJsonDict, Jwk

S = TypeVar("S", bound="JwsSignature")


class JwsSignature(BaseJsonDict):
    @classmethod
    def from_parts(
        cls: Type[S],
        protected: Mapping[str, Any],
        signature: bytes,
        header: Optional[Any],
        **kwargs: Any,
    ) -> S:
        content = dict(
            kwargs,
            protected=BinaPy.serialize_to("json", protected).encode_to("b64u").ascii(),
            signature=BinaPy(signature).encode_to("b64u").ascii(),
        )
        if header is not None:
            content["header"] = header
        return cls(content)

    @property
    def protected(self) -> Dict[str, Any]:
        protected = self.get("protected")
        if protected is None:
            raise AttributeError("This Jws JSON does not contain a 'protected' member")
        return BinaPy(protected).decode_from("b64u").parse_from("json")  # type: ignore

    @property
    def header(self) -> Any:
        return self.get("header")

    @property
    def signature(self) -> bytes:
        signature = self.get("signature")
        if signature is None:
            raise AttributeError("This Jws JSON does not contain a 'signature' member")
        return BinaPy(signature).decode_from("b64u")

    @classmethod
    def sign(
        cls: Type[S],
        payload: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        extra_protected_headers: Optional[Mapping[str, Any]] = None,
        header: Optional[Any] = None,
        **kwargs: Any,
    ) -> S:
        jwk = Jwk(jwk)

        headers = dict(extra_protected_headers or {}, alg=alg)
        kid = jwk.get("kid")
        if kid:
            headers["kid"] = kid

        signed_part = JwsSignature.assemble_signed_part(headers, payload)
        signature = jwk.sign(signed_part, alg=alg)
        return cls.from_parts(
            protected=headers, signature=signature, header=header, **kwargs
        )

    @classmethod
    def assemble_signed_part(
        cls, headers: Dict[str, Any], payload: Union[bytes, str]
    ) -> bytes:
        return b".".join(
            (
                BinaPy.serialize_to("json", headers).encode_to("b64u"),
                BinaPy(payload).encode_to("b64u"),
            )
        )

    def verify(
        self,
        payload: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        jwk = Jwk(jwk)
        signed_part = self.assemble_signed_part(self.protected, payload)
        return jwk.verify(signed_part, self.signature, alg, algs)
