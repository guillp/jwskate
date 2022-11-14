import pytest

from jwskate import Jwk, SymmetricJwk


@pytest.fixture(
    scope="module",
    params=(
        ("HS256", 256),
        ("HS384", 384),
        ("HS512", 512),
    ),
    ids=("256bits", "384bits", "512bits"),
)
def symmetric_jwk(request: pytest.FixtureRequest) -> SymmetricJwk:
    alg, min_key_size = request.param
    kid = f"my_{alg}_jwk"
    jwk = SymmetricJwk.generate_for_alg(alg, kid=kid)
    assert jwk.kty == "oct"
    assert jwk.alg == alg
    assert jwk.kid == kid
    assert isinstance(jwk.k, str)
    assert jwk.key_size >= min_key_size

    with pytest.raises(ValueError):
        jwk.public_jwk()

    return jwk


def test_jwk_symmetric_sign(symmetric_jwk: SymmetricJwk) -> None:
    data = b"The true sign of intelligence is not knowledge but imagination."
    signature = symmetric_jwk.sign(data)
    assert symmetric_jwk.verify(data, signature)


def test_dir_alg(symmetric_jwk: SymmetricJwk) -> None:
    assert "dir" in symmetric_jwk.supported_key_management_algorithms()


def test_pem_key() -> None:
    private_jwk = SymmetricJwk.generate(key_size=128)
    with pytest.raises(TypeError):
        private_jwk.to_pem()


def test_aesgcmkw() -> None:
    alg = "A128GCMKW"
    enc = "A128GCM"
    jwk = Jwk.generate_for_alg(alg)
    sender_cek, wrapped_cek, headers = jwk.sender_key(enc)
    assert sender_cek
    assert wrapped_cek
    assert "iv" in headers
    assert "tag" in headers

    recipient_cek = jwk.recipient_key(wrapped_cek, enc, **headers)
    assert recipient_cek == sender_cek

    # missing 'iv' in headers
    with pytest.raises(ValueError):
        jwk.recipient_key(wrapped_cek, enc, **{"tag": headers["tag"]})

    # missing 'tag' in headers
    with pytest.raises(ValueError):
        jwk.recipient_key(wrapped_cek, enc, **{"iv": headers["iv"]})


@pytest.mark.parametrize(
    "alg, key_size",
    [
        ("HS256", 256),
        ("HS384", 384),
        ("HS512", 512),
        ("A128CBC-HS256", 256),
        ("A192CBC-HS384", 384),
        ("A256CBC-HS512", 512),
        ("A128GCM", 128),
        ("A192GCM", 192),
        ("A256GCM", 256),
        ("A128KW", 128),
        ("A192KW", 192),
        ("A256KW", 256),
        ("A128GCMKW", 128),
        ("A192GCMKW", 192),
        ("A256GCMKW", 256),
    ],
)
def test_generate_for_alg(alg: str, key_size: int) -> None:
    assert SymmetricJwk.generate_for_alg(alg).key_size == key_size
