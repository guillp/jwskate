import pytest

from jwskate import SymmetricJwk


@pytest.fixture(
    scope="module",
    params=(
        ("HS256", 256),
        ("HS384", 384),
        ("HS512", 512),
    ),
)
def symmetric_jwk(request: pytest.FixtureRequest) -> SymmetricJwk:
    alg, key_size = request.param  # type: ignore
    kid = f"my_{alg}_jwk"
    jwk = SymmetricJwk.generate_for_alg(alg, kid=kid)
    assert jwk.kty == "oct"
    assert jwk.alg == alg
    assert jwk.kid == kid
    assert isinstance(jwk.k, str)
    assert jwk.key_size >= key_size

    with pytest.raises(ValueError):
        jwk.public_jwk()

    return jwk


def test_jwk_symmetric_sign(symmetric_jwk: SymmetricJwk) -> None:
    data = b"The true sign of intelligence is not knowledge but imagination."
    signature = symmetric_jwk.sign(data)
    assert symmetric_jwk.verify(data, signature)
