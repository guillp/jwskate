"""This module contains several utilities for algorithmic agility."""

import warnings
from typing import Any, Iterable, List, Mapping, Optional, Type, TypeVar

from jwskate.jwa import BaseAlg


class UnsupportedAlg(ValueError):
    """Raised when an UnsupportedAlg is requested."""


class ExpectedAlgRequired(ValueError):
    """Raised when the expected signature alg(s) must be provided."""


T = TypeVar("T", bound=Type[BaseAlg])


def select_alg(
    jwk_alg: Optional[str], alg: Optional[str], supported_algs: Mapping[str, T]
) -> T:
    """Given an alg parameter from a JWK, and/or a user-specified alg, return the alg to use.

    This checks the coherency between the user specified `alg` and the `jwk_alg`, and will emit a warning
    if the user specified alg is different from the `jwk_alg`.

    Args:
      jwk_alg: the alg from the JWK, if any
      alg: a user specified alg
      supported_algs: a mapping of supported alg names to alg wrapper

    Returns:
      the alg to use

    Raises:
        UnsupportedAlg: if the requested alg is not supported
    """
    choosen_alg: str
    if jwk_alg is not None:
        if alg is not None:
            if jwk_alg != alg:
                warnings.warn(
                    "This key has an 'alg' parameter, you should use that alg for each operation."
                )
            choosen_alg = alg
        else:
            choosen_alg = jwk_alg
    elif alg is not None:
        choosen_alg = alg
    else:
        raise ExpectedAlgRequired(
            "This key doesn't have an 'alg' parameter, so you need to provide the expected signing alg(s) for each operation."
        )

    try:
        return supported_algs[choosen_alg]
    except KeyError:
        raise UnsupportedAlg(
            f"Alg {choosen_alg} is not supported. Supported algs: {list(supported_algs)}."
        )


def select_algs(
    jwk_alg: Optional[str],
    alg: Optional[str],
    algs: Optional[Iterable[str]],
    supported_algs: Mapping[str, T],
) -> List[T]:
    """Given an alg parameter from a JWK, and/or a user-specified alg, and/or a user specified list of useable algs, return a list of algorithms.

    This method is typically used to get the list of possible algs when checking a signature.

    Args:
      jwk_alg: the alg from the JWK, if any
      alg: a user specified alg to use
      algs: a user specified list of algs to use, if several are allowed
      supported_algs: a mapping of alg names to alg wrappers

    Returns:
      a list of possible algs to check

    Raises:
        ValueError: if both 'alg' and 'algs' parameters are used
        UnsupportedAlg: if none of the requested alg are supported

    Warnings:
        if the requested 'alg' is different that the 'jwk_alg', or the 'jwk_alg' is not in the 'algs'
    """
    if alg and algs:
        raise ValueError("Please use either parameter 'alg' or 'algs', not both.")

    if jwk_alg is not None:
        if alg and alg != jwk_alg:
            warnings.warn(
                "This key has an 'alg' parameter, you should use that alg for each operation."
            )
        if algs and jwk_alg not in algs:
            warnings.warn(
                "This key has an 'alg' parameter, you should use that alg for each operation."
            )

    possible_algs: List[str] = []
    if alg:
        possible_algs = [alg]
    elif algs:
        possible_algs = list(algs)
    elif jwk_alg:
        possible_algs = [jwk_alg]

    if possible_algs:
        possible_supported_algs = [
            supported_algs[alg] for alg in possible_algs if alg in supported_algs
        ]
        if possible_supported_algs:
            return possible_supported_algs
        else:
            raise UnsupportedAlg(
                f"None of the user-specified alg(s) are supported. {possible_algs}"
            )

    raise ExpectedAlgRequired(
        "This key doesn't have an 'alg' parameter, so you need to provide the expected signing alg(s) for each operation."
    )


KEY_PARAMS_FOR_ALG: Mapping[str, Mapping[str, Any]] = {
    "HS256": {"kty": "oct", "key_size": 256, "use": "sig", "key_ops": ["sign"]},
    "HS384": {"kty": "oct", "key_size": 384, "use": "sig", "key_ops": ["sign"]},
    "HS512": {"kty": "oct", "key_size": 512, "use": "sig", "key_ops": ["sign"]},
    "RS256": {"kty": "RSA", "key_size": 2048, "use": "sig", "key_ops": ["sign"]},
    "RS384": {"kty": "RSA", "key_size": 3064, "use": "sig", "key_ops": ["sign"]},
    "RS512": {"kty": "RSA", "key_size": 4096, "use": "sig", "key_ops": ["sign"]},
    "PS256": {"kty": "RSA", "key_size": 2048, "use": "sig", "key_ops": ["sign"]},
    "PS384": {"kty": "RSA", "key_size": 3064, "use": "sig", "key_ops": ["sign"]},
    "PS512": {"kty": "RSA", "key_size": 4096, "use": "sig", "key_ops": ["sign"]},
    "ES256": {"kty": "EC", "crv": "P-256", "use": "sig", "key_ops": ["sign"]},
    "ES384": {"kty": "EC", "crv": "P-384", "use": "sig", "key_ops": ["sign"]},
    "ES512": {"kty": "EC", "crv": "P-521", "use": "sig", "key_ops": ["sign"]},
    "RSA1_5": {
        "kty": "RSA",
        "key_size": 2048,
        "use": "enc",
        "key_ops": ["wrapKey"],
    },
    "RSA-OAEP": {
        "kty": "RSA",
        "key_size": 3064,
        "use": "enc",
        "key_ops": ["wrapKey"],
    },
    "RSA-OAEP-256": {
        "kty": "RSA",
        "key_size": 4096,
        "use": "enc",
        "key_ops": ["wrapKey"],
    },
    "RSA-OAEP-384": {
        "kty": "RSA",
        "key_size": 4096,
        "use": "enc",
        "key_ops": ["wrapKey"],
    },
    "RSA-OAEP-512": {
        "kty": "RSA",
        "key_size": 4096,
        "use": "enc",
        "key_ops": ["wrapKey"],
    },
    "A128KW": {"kty": "oct", "key_size": 128, "use": "enc", "key_ops": ["wrapKey"]},
    "A192KW": {"kty": "oct", "key_size": 192, "use": "enc", "key_ops": ["wrapKey"]},
    "A256KW": {"kty": "oct", "key_size": 256, "use": "enc", "key_ops": ["wrapKey"]},
    "A128GCMKW": {
        "kty": "oct",
        "key_size": 128,
        "use": "enc",
        "key_ops": ["wrapKey"],
    },
    "A192GCMKW": {
        "kty": "oct",
        "key_size": 192,
        "use": "enc",
        "key_ops": ["wrapKey"],
    },
    "A256GCMKW": {
        "kty": "oct",
        "key_size": 256,
        "use": "enc",
        "key_ops": ["wrapKey"],
    },
    "ECDH-ES": {"kty": "EC", "crv": "X25519", "use": "enc", "key_ops": ["wrapKey"]},
    "A128CBC-HS256": {
        "kty": "oct",
        "key_size": 256,
        "use": "enc",
        "key_ops": ["encrypt"],
    },
    "A192CBC-HS384": {
        "kty": "oct",
        "key_size": 384,
        "use": "enc",
        "key_ops": ["encrypt"],
    },
    "A256CBC-HS512": {
        "kty": "oct",
        "key_size": 512,
        "use": "enc",
        "key_ops": ["encrypt"],
    },
    "A128GCM": {
        "kty": "oct",
        "key_size": 128,
        "use": "enc",
        "key_ops": ["encrypt"],
    },
    "A192GCM": {
        "kty": "oct",
        "key_size": 192,
        "use": "enc",
        "key_ops": ["encrypt"],
    },
    "A256GCM": {
        "kty": "oct",
        "key_size": 256,
        "use": "enc",
        "key_ops": ["encrypt"],
    },
}


def get_kty_for_alg(alg: str) -> Mapping[str, Any]:
    """Given an alg identifier, return key parameters for a key that is suitable for use with that alg.

    Args:
        alg: a signature or keymanagement or encryption alg identifier

    Returns:
        a dict of key parameters
    """
    return KEY_PARAMS_FOR_ALG[alg]
