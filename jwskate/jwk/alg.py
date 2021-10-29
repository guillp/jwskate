import warnings
from typing import Iterable, List, Optional

from jwskate.jwk.exceptions import UnsupportedAlg


def get_alg(
    jwk_alg: Optional[str], alg: Optional[str], supported_algs: List[str]
) -> str:
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

    if choosen_alg not in supported_algs:
        raise ValueError(
            f"Alg {choosen_alg} is not supported. Supported algs: {supported_algs}."
        )
    if choosen_alg:
        return choosen_alg

    raise ValueError(
        "This key doesn't have an 'alg' parameter, you need to provide the signing alg for each operation."
    )


def get_algs(
    jwk_alg: Optional[str],
    alg: Optional[str],
    algs: Optional[Iterable[str]],
    supported_algs: List[str],
) -> List[str]:
    """
    Given an alg parameter from a JWK, and/or a user-specified alg, and/or a user specified list of useable algs,
    return a list of algorithms.

    This method is typically used to get the list of possible algs when checking a signature.
    :param jwk_alg: the alg from the JWK, if any
    :param alg: a user specified alg to use
    :param algs: a user specified list of algs to use
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
            alg for alg in possible_algs if alg in supported_algs
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
