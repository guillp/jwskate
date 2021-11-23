import warnings
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional, Type, TypeVar

from cryptography.hazmat.primitives import hashes, hmac

from .exceptions import UnsupportedAlg


@dataclass
class Alg:
    name: str
    description: str


@dataclass
class SignatureAlg(Alg):
    hashing_alg: hashes.HashAlgorithm


@dataclass
class SymetricSignatureAlg(SignatureAlg):
    mac: Type[hmac.HMAC]
    min_key_size: int


@dataclass
class KeyManagementAlg(Alg):
    pass


@dataclass
class EncryptionAlg(Alg):
    pass


T = TypeVar("T")


def select_alg(
    jwk_alg: Optional[str], alg: Optional[str], supported_algs: Mapping[str, T]
) -> T:
    """
    Given an alg parameter from a JWK, and/or a user-specified alg, return the alg to use.

    This checks the coherency between the user specified `alg` and the `jwk_alg`, and will emit a warning
    if the user specified alg is different from the `jwk_alg`.
    :param jwk_alg: the alg from the JWK, if any
    :param alg: a user specified alg
    :return: the alg to use
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

    try:
        return supported_algs[choosen_alg]
    except KeyError:
        raise ValueError(
            f"Alg {choosen_alg} is not supported. Supported algs: {supported_algs}."
        )

    raise ValueError(
        "This key doesn't have an 'alg' parameter, you need to provide the signing alg for each operation."
    )


def select_algs(
    jwk_alg: Optional[str],
    alg: Optional[str],
    algs: Optional[Iterable[str]],
    supported_algs: Mapping[str, T],
) -> List[T]:
    """
    Given an alg parameter from a JWK, and/or a user-specified alg, and/or a user specified list of useable algs,
    return a list of algorithms.

    This method is typically used to get the list of possible algs when checking a signature.
    :param jwk_alg: the alg from the JWK, if any
    :param alg: a user specified alg to use
    :param algs: a user specified list of algs to use
    :param supported_algs: a mapping of alg names to alg description
    :return: a list of possible algs to check
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

    possible_algs: List[str]
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

    raise ValueError(
        "This key doesn't have an 'alg' parameter, you need to provide the signing alg for each operation."
    )
