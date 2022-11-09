"""This module contains several utilities for algorithmic agility."""

import warnings
from typing import Iterable, List, Mapping, Optional, Type, TypeVar

from jwskate.jwa import BaseAlg


class UnsupportedAlg(ValueError):
    """Raised when a unsupported alg is requested."""


class ExpectedAlgRequired(ValueError):
    """Raised when the expected signature alg(s) must be provided."""


T = TypeVar("T", bound=Type[BaseAlg])


def select_alg_class(
    supported_algs: Mapping[str, T],
    *,
    jwk_alg: Optional[str] = None,
    alg: Optional[str] = None,
) -> T:
    """Internal helper method to choose the appropriate alg class to use for cryptographic operations.

    Given:
    - a mapping of supported algs names to wrapper classes
    - a preferred alg name (usually the one mentioned in a JWK)
    - and/or a user-specified alg
    this returns the wrapper class to use.

    This checks the coherency between the user specified `alg` and the `jwk_alg`, and will emit a warning
    if the user specified alg is different from the `jwk_alg`.

    Args:
      supported_algs: a mapping of supported alg names to alg wrapper
      jwk_alg: the alg from the JWK, if any
      alg: a user specified alg

    Returns:
      the alg to use

    Warnings:
        A warning is emitted if `jwk_alg` is supplied and `alg` doesn't match its value.

    Raises:
        UnsupportedAlg: if the requested alg is not supported
        ValueError: if supported_algs is empty
    """
    if not supported_algs:
        raise ValueError("No possible algorithms to choose from!")

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


def select_alg_classes(
    supported_algs: Mapping[str, T],
    *,
    jwk_alg: Optional[str] = None,
    alg: Optional[str] = None,
    algs: Optional[Iterable[str]] = None,
) -> List[T]:
    """Internal helper method to select several appropriate algs classes to use on cryptographic operations.

    This method is typically used to get the list of valid algorithms when checking a signature, when several algorithms are allowed.

    Given:
    - a mapping of supported algorithms name to wrapper classes
    - an alg parameter from a JWK
    - and/or a user-specified alg
    - and/or a user specified list of usable algs
    this returns a list of supported alg wrapper classes that matches what the user specified, or, as default, the alg parameter from the JWK.

    This checks the coherency between the user specified `alg` and the `jwk_alg`, and will emit a warning
    if the user specified alg is different from the `jwk_alg`.

    Args:
      supported_algs: a mapping of alg names to alg wrappers
      jwk_alg: the alg from the JWK, if any
      alg: a user specified alg to use, if any
      algs: a user specified list of algs to use, if several are allowed

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

    if not supported_algs:
        raise ValueError("No possible algorithms to choose from!")

    if jwk_alg is not None:
        if (alg and alg != jwk_alg) or (algs and jwk_alg not in algs):
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
