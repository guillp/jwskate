import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from jwskate import PrivateKeyRequired, PublicKeyRequired, RsaEsOaepSha256


def test_private_public_key_required() -> None:
    key = rsa.generate_private_key(65537, 2048)
    private_wrapper = RsaEsOaepSha256(key)

    with private_wrapper.private_key_required():
        assert True

    with pytest.raises(PublicKeyRequired):
        with private_wrapper.public_key_required():
            pass

    public_wrapper = RsaEsOaepSha256(key.public_key())
    with public_wrapper.public_key_required():
        assert True

    with pytest.raises(PrivateKeyRequired):
        with public_wrapper.private_key_required():
            pass
