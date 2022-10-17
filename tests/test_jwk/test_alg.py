import pytest

from jwskate import ExpectedAlgRequired, RSAJwk, UnsupportedAlg
from jwskate.jwk.alg import select_alg_class, select_alg_classes


def test_select_alg() -> None:
    assert (
        select_alg_class(
            jwk_alg=None, alg="RS256", supported_algs=RSAJwk.SIGNATURE_ALGORITHMS
        )
        == RSAJwk.SIGNATURE_ALGORITHMS["RS256"]
    )

    with pytest.warns():
        assert (
            select_alg_class(
                jwk_alg="RS256", alg="RS512", supported_algs=RSAJwk.SIGNATURE_ALGORITHMS
            )
            == RSAJwk.SIGNATURE_ALGORITHMS["RS512"]
        )

    with pytest.raises(ExpectedAlgRequired):
        select_alg_class(
            jwk_alg=None, alg=None, supported_algs=RSAJwk.SIGNATURE_ALGORITHMS
        )

    with pytest.raises(UnsupportedAlg):
        select_alg_class(
            jwk_alg=None, alg="HS256", supported_algs=RSAJwk.KEY_MANAGEMENT_ALGORITHMS
        )

    with pytest.raises(ValueError):
        select_alg_class(jwk_alg=None, alg="HS256", supported_algs={})


def test_select_algs() -> None:
    assert select_alg_classes(
        jwk_alg=None, alg="RS256", algs=None, supported_algs=RSAJwk.SIGNATURE_ALGORITHMS
    ) == [RSAJwk.SIGNATURE_ALGORITHMS["RS256"]]

    with pytest.warns():
        assert select_alg_classes(
            jwk_alg="RS256",
            alg="RS512",
            algs=None,
            supported_algs=RSAJwk.SIGNATURE_ALGORITHMS,
        ) == [RSAJwk.SIGNATURE_ALGORITHMS["RS512"]]

    with pytest.raises(ValueError):
        select_alg_classes(
            jwk_alg=None,
            alg="RS256",
            algs=["RS256", "RS512"],
            supported_algs=RSAJwk.SIGNATURE_ALGORITHMS,
        )

    with pytest.raises(ValueError):
        select_alg_classes(jwk_alg=None, alg="HS256", algs=None, supported_algs={})
