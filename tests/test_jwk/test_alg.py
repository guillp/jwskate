import pytest

from jwskate import (
    ExpectedAlgRequired,
    RSAJwk,
    UnsupportedAlg,
    select_alg_class,
    select_alg_classes,
)


def test_select_alg_class() -> None:
    # select a supported alg of choice
    assert (
        select_alg_class(
            RSAJwk.SIGNATURE_ALGORITHMS,
            alg="RS256",
        )
        == RSAJwk.SIGNATURE_ALGORITHMS["RS256"]
    )

    # select a supported alg based on a JWK alg parameter
    assert (
        select_alg_class(
            RSAJwk.SIGNATURE_ALGORITHMS,
            jwk_alg="RS256",
        )
        == RSAJwk.SIGNATURE_ALGORITHMS["RS256"]
    )

    # if alg and jwk_alg are inconsistent, a warning is raised, value from alg is selected
    with pytest.warns():
        assert (
            select_alg_class(RSAJwk.SIGNATURE_ALGORITHMS, jwk_alg="RS256", alg="RS512")
            == RSAJwk.SIGNATURE_ALGORITHMS["RS512"]
        )

    # if no jwk_alg or alg are passed as parameter, raise an ExpectedAlgRequired
    with pytest.raises(ExpectedAlgRequired):
        select_alg_class(RSAJwk.SIGNATURE_ALGORITHMS)

    # if the requested alg is not supported, raise UnsupportedAlg
    with pytest.raises(UnsupportedAlg):
        select_alg_class(
            RSAJwk.KEY_MANAGEMENT_ALGORITHMS,
            alg="HS256",
        )

    with pytest.raises(UnsupportedAlg):
        select_alg_class(
            RSAJwk.KEY_MANAGEMENT_ALGORITHMS,
            jwk_alg="HS256",
        )

    # no supported algs: raise a ValueError
    with pytest.raises(ValueError):
        select_alg_class({}, alg="HS256")


def test_select_alg_classes() -> None:
    # selecting a single alg from the supported algs
    assert select_alg_classes(
        RSAJwk.SIGNATURE_ALGORITHMS,
        alg="RS256",
    ) == [RSAJwk.SIGNATURE_ALGORITHMS["RS256"]]

    # selecting multiple algs from the supported algs
    assert select_alg_classes(
        RSAJwk.SIGNATURE_ALGORITHMS,
        algs=["RS256", "ES256", "ES512", "PS384", "HS512"],
    ) == [RSAJwk.SIGNATURE_ALGORITHMS["RS256"], RSAJwk.SIGNATURE_ALGORITHMS["PS384"]]

    # selecting based on the JWK alg parameter
    assert select_alg_classes(
        RSAJwk.SIGNATURE_ALGORITHMS,
        jwk_alg="RS256",
    ) == [RSAJwk.SIGNATURE_ALGORITHMS["RS256"]]

    # selecting an unsupported alg
    with pytest.raises(UnsupportedAlg):
        select_alg_classes(RSAJwk.SIGNATURE_ALGORITHMS, alg="ES256")

    # you need to specify at least one of jwk_alg, alg or algs
    with pytest.raises(ExpectedAlgRequired):
        select_alg_classes(RSAJwk.SIGNATURE_ALGORITHMS)

    # if jwk_alg and alg/algs is inconsistent, a warning is fired
    with pytest.warns():
        assert select_alg_classes(
            RSAJwk.SIGNATURE_ALGORITHMS,
            jwk_alg="RS256",
            alg="RS512",
        ) == [RSAJwk.SIGNATURE_ALGORITHMS["RS512"]]

    with pytest.warns():
        assert select_alg_classes(
            RSAJwk.SIGNATURE_ALGORITHMS,
            jwk_alg="RS256",
            algs=["RS512", "PS512"],
        ) == [
            RSAJwk.SIGNATURE_ALGORITHMS["RS512"],
            RSAJwk.SIGNATURE_ALGORITHMS["PS512"],
        ]

    # you cannot use both 'alg' and 'algs' at the same time (raises ValueError)
    with pytest.raises(ValueError):
        select_alg_classes(
            RSAJwk.SIGNATURE_ALGORITHMS,
            alg="RS256",
            algs=["RS256", "RS512"],
        )

    # if no algs are supported, a ValueError is raised
    with pytest.raises(ValueError):
        select_alg_classes({}, alg="HS256")
