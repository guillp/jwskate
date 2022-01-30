from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from binapy import BinaPy

from jwskate.jwk.base import BaseJsonDict, Jwk

from .compact import JwsCompact
from .signature import JwsSignature


class JwsJsonFlat(JwsSignature):
    @property
    def payload(self) -> bytes:
        payload = self.get("payload")
        if payload is None:
            raise AttributeError("This Jws JSON does not contain a 'payload' member")
        return BinaPy(payload).decode_from("b64u")

    @property
    def jws_signature(self) -> JwsSignature:
        content = {
            "protected": self["protected"],
            "signature": self["signature"],
        }
        header = self.get("header")
        if header:
            content["header"] = self.header
        return JwsSignature(content)

    @classmethod
    def sign(
        cls,
        payload: bytes,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        extra_protected_headers: Optional[Mapping[str, Any]] = None,
        header: Optional[Any] = None,
        **kwargs: Any,
    ) -> JwsJsonFlat:
        signature = super().sign(
            payload, jwk, alg, extra_protected_headers, header, **kwargs
        )
        signature["payload"] = BinaPy(payload).encode_to("b64u").ascii()
        return cls(signature)

    def generalize(self) -> JwsJsonGeneral:
        content = self.copy()
        protected = content.pop("protected")
        header = content.pop("header", None)
        signature = content.pop("signature")
        jws_signature = {"protected": protected, "signature": signature}
        if header is not None:
            jws_signature["header"] = header
        content["signatures"] = [jws_signature]
        return JwsJsonGeneral(content)

    def signed_part(self) -> bytes:
        return JwsSignature.assemble_signed_part(self.protected, self.payload)

    def compact(self) -> JwsCompact:
        return JwsCompact.from_parts(self.signed_part(), self.signature)

    def verify_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        return self.jws_signature.verify(self.payload, jwk, alg, algs)


class JwsJsonGeneral(BaseJsonDict):
    @property
    def payload(self) -> bytes:
        payload = self.get("payload")
        if payload is None:
            raise AttributeError("This Jws JSON does not contain a 'payload' member")
        return BinaPy(payload).decode_from("b64u")

    @classmethod
    def sign(
        cls,
        payload: bytes,
        *signature_parameters: Union[
            Tuple[
                Union[Jwk, Mapping[str, Any]],
                str,
                Optional[Mapping[str, Any]],
                Optional[Mapping[str, Any]],
            ],
            Tuple[
                Union[Jwk, Mapping[str, Any]],
                str,
                Optional[Mapping[str, Any]],
            ],
            Tuple[
                Union[Jwk, Mapping[str, Any]],
                str,
            ],
            Union[Jwk, Mapping[str, Any]],
        ],
    ) -> JwsJsonGeneral:
        jws = cls({"payload": BinaPy(payload).encode_to("b64u").ascii()})
        for parameters in signature_parameters:
            jws.add_signature(*parameters)
        return jws

    @property
    def signatures(self) -> List[JwsSignature]:
        signatures = self.get("signatures")
        if signatures is None:
            raise AttributeError("This Jws JSON does not contain a 'signatures' member")
        return [JwsSignature(sig) for sig in signatures]

    def add_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        extra_protected_headers: Optional[Mapping[str, Any]] = None,
        header: Optional[Mapping[str, Any]] = None,
    ) -> JwsJsonGeneral:
        self.setdefault("signatures", [])
        self["signatures"].append(
            JwsSignature.sign(self.payload, jwk, alg, extra_protected_headers, header)
        )
        return self

    def signed_part(
        self,
        signature_chooser: Callable[
            [List[JwsSignature]], JwsSignature
        ] = lambda sigs: sigs[0],
    ) -> bytes:
        signature = signature_chooser(self.signatures)
        return JwsSignature.assemble_signed_part(signature.protected, self.payload)

    def compact(
        self,
        signature_chooser: Callable[
            [List[JwsSignature]], JwsSignature
        ] = lambda sigs: sigs[0],
    ) -> JwsCompact:
        return JwsCompact.from_parts(self.signed_part(signature_chooser), self.payload)

    def flatten(
        self,
        signature_chooser: Callable[
            [List[JwsSignature]], JwsSignature
        ] = lambda sigs: sigs[0],
    ) -> JwsJsonFlat:
        signature = signature_chooser(self.signatures)
        return JwsJsonFlat.from_parts(
            payload=self["payload"],
            protected=signature.protected,
            header=signature.header,
            signature=signature.signature,
        )

    def verify_signature(
        self,
        jwk: Union[Jwk, Dict[str, Any]],
        alg: Optional[str] = None,
        algs: Optional[Iterable[str]] = None,
    ) -> bool:
        for signature in self.signatures:
            if signature.verify(self.payload, jwk, alg, algs):
                return True
        return False
