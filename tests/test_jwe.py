from typing import SupportsBytes, Union

import pytest

import jwskate.jwa
from jwskate import (
    P_521,
    ECJwk,
    InvalidJwe,
    JweCompact,
    Jwk,
    RSAJwk,
    SymmetricJwk,
    UnsupportedAlg,
)

JWCRYPTO_UNSUPPORTED_ALGS = ["RSA-OAEP-384", "RSA-OAEP-512"]
jwskate.jwa.RsaEsPcks1v1_5.read_only = False  # turn off read only for that alg


def test_jwe() -> None:
    plaintext = b"The true sign of intelligence is not knowledge but imagination."
    alg = "RSA-OAEP"
    enc = "A256GCM"
    cek = bytes.fromhex(
        "b1a1f480548fe1733fb403ff6b9ad4f68a076e5b702e22692f82cb2e7aea40fc"
    )
    jwk = Jwk(
        {
            "kty": "RSA",
            "n": "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW"
            "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S"
            "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a"
            "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS"
            "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj"
            "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
            "e": "AQAB",
            "d": "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N"
            "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9"
            "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk"
            "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl"
            "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd"
            "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
            "p": "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-"
            "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf"
            "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
            "q": "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm"
            "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX"
            "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
            "dp": "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL"
            "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827"
            "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
            "dq": "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj"
            "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB"
            "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
            "qi": "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7"
            "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3"
            "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY",
        }
    )
    iv = bytes.fromhex("e3c575fc02dbe944b4e14ddb")

    jwe = JweCompact.encrypt(
        plaintext, jwk.public_jwk(), alg=alg, enc=enc, cek=cek, iv=iv
    )

    assert jwe.initialization_vector == bytes.fromhex("e3c575fc02dbe944b4e14ddb")

    assert jwe.alg == alg
    assert jwe.enc == enc
    assert jwe.decrypt(jwk) == plaintext

    assert jwe.get_header("foo") is None


def test_jwe_decrypt() -> None:
    jwe = (
        "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
        "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
        "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
        "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
        "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
        "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
        "6UklfCpIMfIjf7iGdXKHzg."
        "48V1_ALb6US04U3b."
        "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
        "SdiwkIr3ajwQzaBtQD_A."
        "XFBoMYUZodetZdvTiFvSkQ"
    )

    jwk = Jwk(
        {
            "kty": "RSA",
            "n": "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW"
            "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S"
            "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a"
            "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS"
            "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj"
            "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
            "e": "AQAB",
            "d": "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N"
            "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9"
            "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk"
            "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl"
            "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd"
            "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
            "p": "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-"
            "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf"
            "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
            "q": "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm"
            "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX"
            "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
            "dp": "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL"
            "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827"
            "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
            "dq": "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj"
            "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB"
            "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
            "qi": "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7"
            "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3"
            "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY",
        }
    )

    plaintext = b"The true sign of intelligence is not knowledge but imagination."
    alg = "RSA-OAEP"
    enc = "A256GCM"

    j = JweCompact(jwe)
    assert j.alg == alg
    assert j.enc == enc
    assert JweCompact(jwe).decrypt(jwk) == plaintext

    assert str(JweCompact(jwe)) == jwe
    assert bytes(JweCompact(jwe)) == jwe.encode()


def test_invalid_jwe() -> None:
    with pytest.raises(InvalidJwe, match="Invalid JWE: .*$"):
        JweCompact("foo")
    with pytest.raises(InvalidJwe, match="Invalid JWE header: .*$"):
        JweCompact("foo!.foo!.foo!.foo!.foo!")
    with pytest.raises(InvalidJwe, match="Invalid JWE CEK: .*$"):
        JweCompact("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.foo!.foo!.foo!.foo!")
    with pytest.raises(InvalidJwe, match="Invalid JWE IV: .*$"):
        JweCompact(
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
            "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
            "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
            "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
            "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
            "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
            "6UklfCpIMfIjf7iGdXKHzg."
            "foo!.foo!.foo!"
        )
    with pytest.raises(InvalidJwe, match="Invalid JWE ciphertext: .*$"):
        JweCompact(
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
            "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
            "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
            "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
            "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
            "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
            "6UklfCpIMfIjf7iGdXKHzg."
            "48V1_ALb6US04U3b."
            "foo!."
            "foo!"
        )
    with pytest.raises(InvalidJwe, match="Invalid JWE authentication tag: .*$"):
        JweCompact(
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
            "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
            "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
            "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
            "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
            "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
            "6UklfCpIMfIjf7iGdXKHzg."
            "48V1_ALb6US04U3b."
            "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
            "SdiwkIr3ajwQzaBtQD_A."
            "foo!"
        )


EC_P521_PRIVATE_KEY = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "enc",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"
    "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"
    "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
    "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"
    "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
}

RSA_PRIVATE_KEY = {
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "enc",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
    "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
    "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
    "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
    "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
    "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
    "HdrNP5zw",
    "e": "AQAB",
    "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e"
    "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld"
    "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b"
    "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU"
    "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj"
    "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc"
    "OpBrQzwQ",
    "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR"
    "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG"
    "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8"
    "bUq0k",
    "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT"
    "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an"
    "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0"
    "s7pFc",
    "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q"
    "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn"
    "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX"
    "59ehik",
    "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr"
    "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK"
    "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK"
    "T1cYF8",
    "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N"
    "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh"
    "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP"
    "z8aaI4",
}

SYMMETRIC_ENCRYPTION_KEY = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "enc",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
}


@pytest.fixture(scope="module")
def ec_p521_private_jwk() -> Jwk:
    """This is the key from [https://datatracker.ietf.org/doc/html/rfc7520#section-3.2]."""
    jwk = Jwk(EC_P521_PRIVATE_KEY)
    assert isinstance(jwk, ECJwk)
    assert jwk.is_private
    assert jwk.kty == "EC"
    assert jwk.kid == "bilbo.baggins@hobbiton.example"
    assert jwk.use == "enc"
    assert jwk.curve == P_521
    assert (
        jwk.x_coordinate
        == 1536512509633812701046363966946458604394346818697394258819956002474017850080242973018354677969345705661882653180474980600600249393774872942916765721086083757
    )
    assert (
        jwk.y_coordinate
        == 6390841077912737365653019441492828723058308087943275742908661475903115398365573971688270351422921162967673593344809147696590449694148618103053589689371825269
    )
    assert (
        jwk.ecc_private_key
        == 111516411687364059110290785888309499157003632541675704481981366909658327544236421609398595734137119337357107861242367481230550517706674527460992238934209133
    )
    return jwk


@pytest.fixture(scope="module")
def ec_p384_private_jwk() -> Jwk:
    return Jwk.generate_for_kty("EC", crv="P-384")


@pytest.fixture(scope="module")
def ec_p256_private_jwk() -> Jwk:
    return ECJwk.generate("P-256")


@pytest.fixture(scope="module")
def okp_x25519_private_jwk() -> Jwk:
    return Jwk.generate_for_kty("OKP", crv="X25519")


@pytest.fixture(scope="module")
def okp_x448_private_jwk() -> Jwk:
    return Jwk.generate_for_kty("OKP", crv="X448")


@pytest.fixture(scope="module")
def rsa_private_jwk() -> Jwk:
    """This is the key from [https://datatracker.ietf.org/doc/html/rfc7520#section-3.4]."""
    jwk = Jwk(RSA_PRIVATE_KEY)
    assert isinstance(jwk, RSAJwk)
    assert jwk.is_private
    assert jwk.kty == "RSA"
    assert jwk.kid == "bilbo.baggins@hobbiton.example"
    assert jwk.use == "enc"
    assert (
        jwk.modulus
        == 20135533008613362683983973718862990570890949482783547491074937566048838943004157274484500282679051238967930814182837332509745335321694730867914487474360313056717004122048241683576190451001206594369003880452220552186311851010130037332999299892700953157894377718386086768938058299374235398748350321163975673243254998238224668780038242796491971359194173117243083075284176788910883569789455869367283514387223800602948314723218768921623931105285092074647944930960873919066358313244754717122611255711161319444897038896496343014060976689972635082113758993979473481511550731351324005908071126862383299605264835961097030990287
    )
    assert jwk.exponent == 65537
    assert (
        jwk.private_exponent
        == 13809785886921180797407749068700942981528089435771470964933339849531763931979658226246689941649114165877756904281400924998825599768673188627050679509247407590724566295036763464811978094688530662125180988122227281988347728446577123121956338123153675672384095849459356212372062261627372823030362241721140402534827920608159114397698659666564432536888691574732214992533122683199444713216582417478411683595580959548347164585150169575401765252679902902625147728179779840007171037544685861186766305472768461620252400817122383292377247352244817836750259386865218586191336825522033117854784997616980884291365145982447543137217
    )
    assert (
        jwk.first_prime_factor
        == 155305159528675998315587554014523516083078608902053750652196202749677048642358299363759977556059891120561885641903854876605754500853726315968216134808579359395711784936178882676585818087673577574114127693348589707935410407050296794012012146664933439273320539907415872853360575628122941817407358922423140657993
    )
    assert (
        jwk.second_prime_factor
        == 129651410614568017951696388521026752738348674639303464401419464668770635900253174384526773731502315063946718183900420330879494363511129117909409612613133053606973655487402983938837056343590378935691659259752059752852280269661044647292328198275965901381648329420292300429253481090448036576608977166562458575959
    )
    assert (
        jwk.first_factor_crt_exponent
        == 5452754506240497308759433019323719585992094222860760795439270374399299463296556858507586681668276080205271813815413736836746282351411023590382002932611213604063854267637328669893708400136364221707380683009522939987478513612504889192694812845812469959990700860994002219137017021229395442602718050574418216489
    )
    assert (
        jwk.second_factor_crt_exponent
        == 6103034953475782159405883067387392346274709877813314428160871698478072108156934906636939392429995910283894984471867749832357906395346648896814450690625379104589983172538233447538219918824119490007305320907809395266022012480039103665056876141436971569684073061958920103517814199063615863387684736238234656863
    )
    assert (
        jwk.first_crt_coefficient
        == 155171362656114787674005338316026300971092335901511555016027916093530558354739494408751451514346305783601055276983183518496184496218932854791325892306914322459078533545141895619742270863660955772717492371592287055310307433879513025000807527757356866299049054535097378049521944951691464480088870568286553270414
    )
    return jwk


@pytest.fixture(scope="module")
def symmetric_128_encryption_jwk() -> Jwk:
    return Jwk.generate_for_kty("oct", key_size=128)


@pytest.fixture(scope="module")
def symmetric_192_encryption_jwk() -> Jwk:
    return Jwk.generate_for_kty("oct", key_size=192)


@pytest.fixture(scope="module")
def symmetric_256_encryption_jwk() -> Jwk:
    """This is the key from [https://datatracker.ietf.org/doc/html/rfc7520#section-3.5]."""
    jwk = Jwk(SYMMETRIC_ENCRYPTION_KEY)
    assert isinstance(jwk, SymmetricJwk)
    assert jwk.is_private
    assert jwk.kty == "oct"
    assert jwk.kid == "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
    assert jwk.use == "enc"
    assert (
        jwk.key.hex()
        == "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"
    )
    assert jwk.key_size == 32 * 8
    return jwk


@pytest.fixture(scope="module")
def symmetric_384_encryption_jwk() -> Jwk:
    return Jwk.generate_for_kty("oct", key_size=384)


@pytest.fixture(scope="module")
def symmetric_512_encryption_jwk() -> Jwk:
    return Jwk.generate_for_kty("oct", key_size=512)


@pytest.fixture(scope="module")
def encryption_plaintext() -> bytes:
    """This is the plaintext from [https://datatracker.ietf.org/doc/html/rfc7520#section-4]."""
    return (
        "It’s a dangerous business, Frodo, going out your door. "
        "You step onto the road, and if you don't keep your feet, "
        "there’s no knowing where you might be swept off to."
    ).encode()


@pytest.fixture(
    scope="module",
    params=[
        "RSA1_5",
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA-OAEP-384",
        "RSA-OAEP-512",
        "A128KW",
        "A192KW",
        "A256KW",
        "dir",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
        "A128GCMKW",
        "A192GCMKW",
        "A256GCMKW",
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    ],
)
def key_management_alg(request: pytest.FixtureRequest) -> str:
    return request.param  # type: ignore[no-any-return]


@pytest.fixture(
    scope="module",
    params=[
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    ],
)
def encryption_alg(request: pytest.FixtureRequest) -> str:
    alg: str = request.param
    if alg in SymmetricJwk.ENCRYPTION_ALGORITHMS:
        return alg
    pytest.skip(f"Encryption alg {alg} is not supported yet!")


@pytest.fixture(
    scope="module",
    params=[
        'pAvkcJv!$N8HtIuf3W@KaF&2Gv"EAD/BK[_FEoLIuvMS*aG0tm4,.?'.encode(),
    ],
)
def password(request: pytest.FixtureRequest) -> bytes:
    return request.param  # type: ignore


@pytest.fixture(scope="module")
def decryption_jwk(
    key_management_alg: str,
    encryption_alg: str,
    rsa_private_jwk: Jwk,
    ec_p256_private_jwk: Jwk,
    ec_p384_private_jwk: Jwk,
    ec_p521_private_jwk: Jwk,
    okp_x25519_private_jwk: Jwk,
    okp_x448_private_jwk: Jwk,
    symmetric_128_encryption_jwk: Jwk,
    symmetric_192_encryption_jwk: Jwk,
    symmetric_256_encryption_jwk: Jwk,
    symmetric_384_encryption_jwk: Jwk,
    symmetric_512_encryption_jwk: Jwk,
    password: bytes,
) -> Union[Jwk, bytes]:
    if key_management_alg == "dir":
        for key in (
            symmetric_128_encryption_jwk,
            symmetric_192_encryption_jwk,
            symmetric_256_encryption_jwk,
            symmetric_384_encryption_jwk,
            symmetric_512_encryption_jwk,
        ):
            if encryption_alg in key.supported_encryption_algorithms():
                return key
    elif key_management_alg in (
        "PBES2-HS256+A128KW",
        "PBES2-HS384+A192KW",
        "PBES2-HS512+A256KW",
    ):
        return password
    else:
        for key in (
            rsa_private_jwk,
            ec_p521_private_jwk,
            ec_p384_private_jwk,
            ec_p256_private_jwk,
            okp_x25519_private_jwk,
            okp_x448_private_jwk,
            symmetric_128_encryption_jwk,
            symmetric_192_encryption_jwk,
            symmetric_256_encryption_jwk,
        ):
            if key_management_alg in key.supported_key_management_algorithms():
                return key

    assert False, f"No key supports this Key Management alg: {key_management_alg}"


@pytest.fixture(scope="module")
def encryption_jwk(decryption_jwk: Union[Jwk, bytes]) -> Union[Jwk, bytes]:
    if isinstance(decryption_jwk, SymmetricJwk):
        return decryption_jwk
    elif isinstance(decryption_jwk, bytes):
        return decryption_jwk

    return decryption_jwk.public_jwk()


@pytest.fixture(scope="module")
def encrypted_jwe(
    encryption_plaintext: SupportsBytes,
    encryption_jwk: Union[Jwk, SupportsBytes],
    key_management_alg: str,
    encryption_alg: str,
) -> JweCompact:
    if isinstance(encryption_jwk, Jwk):
        jwe = JweCompact.encrypt(
            plaintext=encryption_plaintext,
            jwk=encryption_jwk,
            alg=key_management_alg,
            enc=encryption_alg,
        )
    else:
        password = bytes(encryption_jwk)
        jwe = JweCompact.encrypt_with_password(
            plaintext=encryption_plaintext,
            password=password,
            alg=key_management_alg,
            enc=encryption_alg,
        )
    assert isinstance(jwe, JweCompact)
    assert jwe.enc == encryption_alg
    return jwe


class SupportsBytesTester:
    """A test class with a __bytes__ method to match SupportBytes interface."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __bytes__(self) -> bytes:  # noqa: D105
        return self.payload


def test_supportsbytes(
    encryption_plaintext: bytes,
    encryption_jwk: Union[Jwk, SupportsBytes],
    key_management_alg: str,
    encryption_alg: str,
    encrypted_jwe: JweCompact,
    decryption_jwk: Jwk,
) -> None:
    if isinstance(encryption_jwk, Jwk):
        jwe = JweCompact.encrypt(
            plaintext=SupportsBytesTester(encryption_plaintext),
            jwk=encryption_jwk,
            alg=key_management_alg,
            enc=encryption_alg,
        )
    else:
        password = bytes(encryption_jwk)
        jwe = JweCompact.encrypt_with_password(
            plaintext=SupportsBytesTester(encryption_plaintext),
            password=password,
            alg=key_management_alg,
            enc=encryption_alg,
        )

    assert jwe.decrypt(decryption_jwk) == encrypted_jwe.decrypt(decryption_jwk)
    if not isinstance(decryption_jwk, bytes):
        cek = decryption_jwk.recipient_key(
            SupportsBytesTester(jwe.wrapped_cek), **jwe.headers
        )
        assert (
            cek.decrypt(
                SupportsBytesTester(jwe.ciphertext),
                iv=SupportsBytesTester(jwe.initialization_vector),
                tag=SupportsBytesTester(jwe.authentication_tag),
                aad=SupportsBytesTester(jwe.additional_authenticated_data),
                alg=encryption_alg,
            )
            == encryption_plaintext
        )


def test_decrypt(
    encryption_plaintext: bytes,
    encrypted_jwe: JweCompact,
    decryption_jwk: Union[Jwk, bytes],
    key_management_alg: str,
    encryption_alg: str,
) -> None:
    assert encrypted_jwe.alg == key_management_alg
    assert encrypted_jwe.enc == encryption_alg
    if isinstance(decryption_jwk, Jwk):
        assert encrypted_jwe.decrypt(decryption_jwk) == encryption_plaintext
    else:
        assert (
            encrypted_jwe.decrypt_with_password(decryption_jwk) == encryption_plaintext
        )


def test_decrypt_by_jwcrypto(
    encryption_plaintext: bytes,
    encrypted_jwe: JweCompact,
    decryption_jwk: Jwk,
    key_management_alg: str,
    encryption_alg: str,
) -> None:
    """This test decrypts tokens generated by `jwskate` using another lib `jwcrypto`.

    Args:
        encryption_plaintext: the expected plaintext
        encrypted_jwe: the Jwe encrypted by jwskate to decrypt
        decryption_jwk: the Jwk containing the decryption key
        key_management_alg: the key management alg
        encryption_alg: the encryption alg
    """
    import jwcrypto.jwe  # type: ignore[import]
    import jwcrypto.jwk  # type: ignore[import]
    from jwcrypto.common import InvalidJWEOperation, json_encode  # type: ignore[import]

    if key_management_alg in JWCRYPTO_UNSUPPORTED_ALGS:
        pytest.skip(f"jwcrypto doesn't support key management alg {key_management_alg}")

    jwe_algs_and_rsa1_5 = jwcrypto.jwe.default_allowed_algs + ["RSA1_5"]

    jwe = jwcrypto.jwe.JWE(algs=jwe_algs_and_rsa1_5)
    jwe.deserialize(str(encrypted_jwe))
    if isinstance(decryption_jwk, Jwk):
        jwk = jwcrypto.jwk.JWK(**decryption_jwk)
        jwe.decrypt(jwk)
    else:
        password = decryption_jwk
        jwe.decrypt(password)

    assert jwe.plaintext == encryption_plaintext


@pytest.fixture()
def jwcrypto_encrypted_jwe(
    encryption_plaintext: bytes,
    encryption_jwk: Jwk,
    key_management_alg: str,
    encryption_alg: str,
) -> str:
    """Encrypt a JWE using `jwcrypto`, to make sure it validates with `jwskate`.

    Args:
        encryption_plaintext: the plaintext to encrypt
        encryption_jwk: the Jwk to use to for encryption
        key_management_alg: the key management alg
        encryption_alg: the encryption alg

    Returns:
        a JWE token
    """
    import jwcrypto.jwe
    import jwcrypto.jwk
    from jwcrypto.common import json_encode

    if key_management_alg in JWCRYPTO_UNSUPPORTED_ALGS:
        pytest.skip(f"jwcrypto doesn't support key management alg {key_management_alg}")

    jwe_algs_and_rsa1_5 = jwcrypto.jwe.default_allowed_algs + ["RSA1_5"]
    jwe = jwcrypto.jwe.JWE(
        encryption_plaintext,
        protected=json_encode({"alg": key_management_alg, "enc": encryption_alg}),
        algs=jwe_algs_and_rsa1_5,
    )

    if isinstance(encryption_jwk, Jwk):
        jwk = jwcrypto.jwk.JWK(**encryption_jwk)
        jwe.add_recipient(jwk)
    else:
        password = encryption_jwk
        jwe.add_recipient(password)
    token: str = jwe.serialize(True)
    return token


def test_decrypt_from_jwcrypto(
    encryption_plaintext: bytes,
    jwcrypto_encrypted_jwe: str,
    decryption_jwk: Jwk,
    key_management_alg: str,
    encryption_alg: str,
) -> None:
    """Check that `jwskate` decrypts tokens encrypted by `jwcrypto`.

    Args:
        encryption_plaintext: the plaintext
        jwcrypto_encrypted_jwe: the JWE to validate
        decryption_jwk: the decryption key
        key_management_alg: the key management alg
        encryption_alg: the encryption alg
    """
    jwe = JweCompact(jwcrypto_encrypted_jwe)
    assert jwe.alg == key_management_alg
    assert jwe.enc == encryption_alg
    try:
        assert jwe.decrypt(decryption_jwk) == encryption_plaintext
    except Exception:
        cek = jwe.unwrap_cek(decryption_jwk)
        assert (
            False
        ), f"Decryption by JWSkate failed for {jwcrypto_encrypted_jwe}, CEK={cek}"


def test_invalid_enc_header() -> None:
    with pytest.raises(InvalidJwe, match="Invalid JWE header: .*enc.*$"):
        JweCompact(
            """eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6eyJmb28iOiJiYXIifX0.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"""
        )


def test_invalid_password_encryption() -> None:
    with pytest.raises(
        UnsupportedAlg,
        match=r"^Unsupported password-based encryption algorithm 'foo'\. Value must be one of \[.*\]\.$",
    ):
        JweCompact.encrypt_with_password(
            b"payload", "password", alg="foo", enc="A128GCM"
        )

    with pytest.raises(ValueError, match="must be a positive integer"):
        JweCompact.encrypt_with_password(
            b"payload", "password", alg="PBES2-HS256+A128KW", enc="A128GCM", count=-1
        )

    with pytest.warns(match="PBES2 iteration count should be > 1000"):
        assert isinstance(
            JweCompact.encrypt_with_password(
                b"payload",
                "password",
                alg="PBES2-HS256+A128KW",
                enc="A128GCM",
                count=50,
            ),
            JweCompact,
        )

    with pytest.raises(ValueError, match="key size"):
        JweCompact.encrypt_with_password(
            b"payload",
            "password",
            alg="PBES2-HS256+A128KW",
            enc="A128GCM",
            count=5000,
            cek=b"foo" * 8,
        )

    jwe_invalid_alg = JweCompact(
        "eyJhbGciOiJmb28iLCJlbmMiOiJBMTI4R0NNIiwicDJzIjoiZHR0Nlk0SE1DeC1DYWlFMyIsInAyYyI6NTB9.KB5nuVzZJ_DAw5VhvDjuvXMYe-tVDZC_.fQbPcHuNP68owByZ.ca5JnpoJVg.G1atlPo0sDP7E4VOR3dD5w"
    )
    assert jwe_invalid_alg.alg == "foo"
    with pytest.raises(
        UnsupportedAlg,
        match=r"^Unsupported password-based encryption algorithm 'foo'\. Value must be one of \[.*\]\.$",
    ):
        jwe_invalid_alg.decrypt_with_password("password")

    jwe_missing_p2s = JweCompact(
        "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjo1MH0.KB5nuVzZJ_DAw5VhvDjuvXMYe-tVDZC_.fQbPcHuNP68owByZ.ca5JnpoJVg.G1atlPo0sDP7E4VOR3dD5w"
    )
    assert jwe_missing_p2s.headers.get("p2s") is None
    with pytest.raises(
        InvalidJwe, match=r"Invalid JWE: a required 'p2s' header is missing."
    ):
        jwe_missing_p2s.decrypt_with_password("password")

    jwe_missing_p2c = JweCompact(
        "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJzIjoiZHR0Nlk0SE1DeC1DYWlFMyJ9.KB5nuVzZJ_DAw5VhvDjuvXMYe-tVDZC_.fQbPcHuNP68owByZ.ca5JnpoJVg.G1atlPo0sDP7E4VOR3dD5w"
    )
    assert jwe_missing_p2c.headers.get("p2c") is None
    with pytest.raises(
        InvalidJwe, match=r"Invalid JWE: a required 'p2c' header is missing."
    ):
        jwe_missing_p2c.decrypt_with_password("password")

    jwe_invalid_p2c = JweCompact(
        "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJzIjoiZHR0Nlk0SE1DeC1DYWlFMyIsInAyYyI6ImZvbyJ9.KB5nuVzZJ_DAw5VhvDjuvXMYe-tVDZC_.fQbPcHuNP68owByZ.ca5JnpoJVg.G1atlPo0sDP7E4VOR3dD5w"
    )
    assert jwe_invalid_p2c.headers.get("p2c") == "foo"
    with pytest.raises(
        InvalidJwe,
        match=r"Invalid JWE: invalid value for the 'p2c' header, must be a positive integer.",
    ):
        jwe_invalid_p2c.decrypt_with_password("password")
