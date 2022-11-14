"""Tests for the jwkskate.jwa submodule."""
from binapy import BinaPy

from jwskate import A128CBC_HS256, A192CBC_HS384, EcdhEs, Jwk


def test_aes_128_hmac_sha256() -> None:
    """Test derived from [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#appendix-B.1)."""
    key = bytes.fromhex(
        (
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
            "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
        ).replace(" ", "")
    )
    mac_key = bytes.fromhex(
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f".replace(" ", "")
    )
    enc_key = bytes.fromhex(
        "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f".replace(" ", "")
    )
    plaintext = bytes.fromhex(
        (
            "41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20"
            "6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75"
            "69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65"
            "74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62"
            "65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69"
            "6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66"
            "20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f"
            "75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65"
        ).replace(" ", "")
    )
    iv = bytes.fromhex(
        "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04".replace(" ", "")
    )
    aad = bytes.fromhex(
        (
            "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63"
            "69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20"
            "4b 65 72 63 6b 68 6f 66 66 73"
        ).replace(" ", "")
    )
    al = bytes.fromhex("00 00 00 00 00 00 01 50".replace(" ", ""))  # noqa
    ciphertext = bytes.fromhex(
        (
            "c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79"
            "a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9"
            "a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2"
            "fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36"
            "09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8"
            "6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b"
            "38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f"
            "bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5"
            "4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db"
        ).replace(" ", "")
    )

    mac = bytes.fromhex(  # noqa
        (
            "65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4"
            "e6 e5 45 82 47 65 15 f0 ad 9f 75 a2 b7 1c 73 ef"
        ).replace(" ", "")
    )

    tag = bytes.fromhex(
        "65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4".replace(" ", "")
    )

    cipher = A128CBC_HS256(key)
    assert cipher.aes_key == enc_key
    assert cipher.mac_key == mac_key
    result_ciphertext, result_tag = cipher.encrypt(plaintext, iv=iv, aad=aad)
    assert result_ciphertext == ciphertext
    assert result_tag == tag


def test_aes_192_hmac_sha384() -> None:
    """Test derived from [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#appendix-B.2)."""
    key = bytes.fromhex(
        (
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
            "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
            "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f"
        ).replace(" ", "")
    )
    mac_key = bytes.fromhex(
        (
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" "10 11 12 13 14 15 16 17"
        ).replace(" ", "")
    )
    enc_key = bytes.fromhex(
        (
            "18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27" "28 29 2a 2b 2c 2d 2e 2f"
        ).replace(" ", "")
    )
    plaintext = bytes.fromhex(
        (
            "41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20"
            "6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75"
            "69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65"
            "74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62"
            "65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69"
            "6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66"
            "20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f"
            "75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65"
        ).replace(" ", "")
    )
    iv = bytes.fromhex(
        "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04".replace(" ", "")
    )
    aad = bytes.fromhex(
        (
            "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63"
            "69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20"
            "4b 65 72 63 6b 68 6f 66 66 73"
        ).replace(" ", "")
    )
    al = bytes.fromhex("00 00 00 00 00 00 01 50".replace(" ", ""))  # noqa
    ciphertext = bytes.fromhex(
        (
            "ea 65 da 6b 59 e6 1e db 41 9b e6 2d 19 71 2a e5"
            "d3 03 ee b5 00 52 d0 df d6 69 7f 77 22 4c 8e db"
            "00 0d 27 9b dc 14 c1 07 26 54 bd 30 94 42 30 c6"
            "57 be d4 ca 0c 9f 4a 84 66 f2 2b 22 6d 17 46 21"
            "4b f8 cf c2 40 0a dd 9f 51 26 e4 79 66 3f c9 0b"
            "3b ed 78 7a 2f 0f fc bf 39 04 be 2a 64 1d 5c 21"
            "05 bf e5 91 ba e2 3b 1d 74 49 e5 32 ee f6 0a 9a"
            "c8 bb 6c 6b 01 d3 5d 49 78 7b cd 57 ef 48 49 27"
            "f2 80 ad c9 1a c0 c4 e7 9c 7b 11 ef c6 00 54 e3"
        ).replace(" ", "")
    )

    mac = bytes.fromhex(  # noqa
        (
            "84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20"
            "75 16 80 39 cc c7 33 d7 45 94 f8 86 b3 fa af d4"
            "86 f2 5c 71 31 e3 28 1e 36 c7 a2 d1 30 af de 57"
        ).replace(" ", "")
    )

    tag = bytes.fromhex(
        (
            "84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20" "75 16 80 39 cc c7 33 d7"
        ).replace(" ", "")
    )

    cipher = A192CBC_HS384(key)
    assert cipher.aes_key == enc_key
    assert cipher.mac_key == mac_key
    result_ciphertext, result_tag = cipher.encrypt(plaintext, iv=iv, aad=aad)
    assert result_ciphertext == ciphertext
    assert result_tag == tag


def test_ecdhes() -> None:
    """Test derived from [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518#appendix-C)."""
    alice_ephemeral_key = Jwk(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
        }
    )
    bob_private_key = Jwk(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        }
    )

    otherinfo = EcdhEs.otherinfo(alg="A128GCM", apu=b"Alice", apv=b"Bob", key_size=128)
    alice_cek = EcdhEs.derive(
        private_key=alice_ephemeral_key.cryptography_key,
        public_key=bob_private_key.public_jwk().cryptography_key,
        otherinfo=otherinfo,
        key_size=128,
    )
    assert BinaPy(alice_cek).to("b64u") == b"VqqN6vgjbSBcIijNcacQGg"

    bob_cek = EcdhEs.derive(
        private_key=bob_private_key.cryptography_key,
        public_key=alice_ephemeral_key.public_jwk().cryptography_key,
        otherinfo=otherinfo,
        key_size=128,
    )
    assert BinaPy(bob_cek).to("b64u") == b"VqqN6vgjbSBcIijNcacQGg"
