import pytest

from jwskate import SymmetricJwk


@pytest.fixture(scope="module", params=["HS256", "HS384", "HS512"])
def alg(request) -> str:
    return request.param


@pytest.fixture(scope="module")
def key_size(alg) -> int:
    return {
        "HS256": 256 * 8,
        "HS384": 384 * 8,
        "HS512": 512 * 8,
    }[alg]


@pytest.fixture(scope="module")
def symmetric_jwk(alg, key_size) -> SymmetricJwk:
    kid = f"my_{alg}_jwk"
    jwk = SymmetricJwk.generate_for_alg(alg, kid=kid)
    assert jwk.kty == "oct"
    assert jwk.kid == kid
    assert isinstance(jwk.k, str)
    assert jwk.key_size == key_size
    return jwk


def test_jwk_symetric_generate_for_alg(alg, key_size):
    jwk = SymmetricJwk.generate_for_alg(alg)
    assert jwk.kty == "oct"
    assert jwk.alg == alg
    assert jwk.key_size == key_size


def test_jwk_symetric_sign(symmetric_jwk):
    data = b"The true sign of intelligence is not knowledge but imagination."
    signature = symmetric_jwk.sign(data)
    assert symmetric_jwk.verify(data, signature)
