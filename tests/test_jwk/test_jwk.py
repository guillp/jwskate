from __future__ import annotations

import secrets

import pytest
from binapy import BinaPy
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

from jwskate import (
    A128GCM,
    ES256,
    EcdhEs_A128KW,
    EncryptionAlgs,
    InvalidJwk,
    Jwk,
    KeyManagementAlgs,
    RSAJwk,
    SignatureAlgs,
    SymmetricJwk,
    UnsupportedKeyType,
    select_alg_class,
    to_jwk,
)


def test_public_jwk() -> None:
    private_jwk = Jwk.generate(alg="ES256")
    assert private_jwk.is_private
    public_jwk = private_jwk.public_jwk()
    assert not public_jwk.is_private
    assert public_jwk is public_jwk.public_jwk()


def test_jwk_copy() -> None:
    jwk1 = Jwk.generate(kty="RSA")

    jwk2 = Jwk(jwk1)
    assert jwk1 is not jwk2

    jwk3 = jwk1.copy()
    assert isinstance(jwk3, Jwk)
    assert jwk1 == jwk3
    assert jwk1 is not jwk3


def test_invalid_jwk() -> None:
    with pytest.raises(InvalidJwk):
        # kty is not str
        Jwk({"kty": 1.5})

    with pytest.raises(InvalidJwk):
        # kty is unknown
        Jwk({"kty": "caesar13"})

    with pytest.raises(InvalidJwk):
        # attributes are missing
        Jwk({"kty": "RSA"})

    with pytest.raises(InvalidJwk):
        # x is not a base64u
        Jwk({"kty": "RSA", "x": "$+!"})

    with pytest.raises(InvalidJwk):
        # attribute 'd' (private exponent) is missing
        Jwk(
            {
                "kty": "RSA",
                "n": "oRHn4oGv23ylRL3RSsL4p_e6Ywinnj2N2tT5OLe5pEZTg-LFBhjFxcJaB-p1dh6XX47EtSfa-JHffU0o5ZRK2ySyNDtlrFAkOpAHH6U83ayE2QPYGzrFrrvHDa8wIMUWymzxpPwGgKBwZZqtTT6d-iy4Ux3AWV-bUv6Z7WijHnOy7aVzZ4dFERLVf2FaaYXDET7GO4v-oQ5ss_guYdmewN039jxkjz_KrA-0Fyhalf9hL8IHfpdpSlHosrmjORG5y9LkYK0J6zxSBF5ZvLIBK33BTzPPiCMwKLyAcV6qdcAcvV4kthKO0iUKBK4eE8D0N8HcSPvA9F_PpLS_k5F2lw",
                "e": "AQAB",
                "p": "0mzP9sbFxU5YxNNLgUEdRQSO-ojqWrzbI02PfQLGyzXumvOh_Qr73OpHStU8CAAcUBaQdRGidsVdb5cq6JG2zvbEEYiX-dCHqTJs8wfktGCL7eV-ZVh7fhJ1sYVBN20yv8aSH63uUPZnJXR1AUyrvRumuerdPxp8X951PESrJd0",
            }
        )

    with pytest.raises(InvalidJwk):
        # k is not a str
        Jwk({"kty": "oct", "k": 1.23})

    with pytest.raises(InvalidJwk):
        # k is not a base64u
        Jwk({"kty": "oct", "k": "Foo****"})

    with pytest.raises(InvalidJwk):
        # oth is unsupported
        Jwk({"kty": "RSA", "oth": "foo"})

    with pytest.raises(InvalidJwk):
        # key is public and has key_ops: ["sign"]
        Jwk(
            {
                "kty": "EC",
                "key_ops": ["sign"],
                "crv": "P-256",
                "x": "vGVh-60pT34a0JLeiaers66I0JLRilpf5tbnZsa-q3U",
                "y": "y99gwPgQH1lrIBQPwgJoHCoeQjF96M7XfxGXu_Pjyzk",
            }
        )

    with pytest.raises(TypeError):
        Jwk.from_cryptography_key(object())


def test_json() -> None:
    j = (
        '{"kty": "RSA", "n":'
        ' "5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8",'
        ' "e": "AQAB", "d":'
        ' "QD----2gB03w9LwB6Zq5QXR-HmU2TfJKyml_LTxNufE8-es70Y1q8RVMYhX6CdgMliSmX_xwcicFOk06_5_hopKrDmiuHl8Z_DmqW6Zyc62H52CsTfmlTttI6cfV-ISlix1opAEebmusy9n3DZ1_2VtiAsylyHP0_BnWGS1rgzoHpLrRLHANK86SzV0NNBMd23cdhVdacBC7DLmpe9yO0-OuwxCwZ_qVe5OKBISiGkfIK08OWZCgO_t8NOHF6yYw8B2pv3wFEHllJHMR3R0akN6MMLmcIZ-qidbvXBgriRROYD3VZwVOgtrI8DlTdPVh3QnpMS3PekoczLgHx6oOhI0ytDvoQ0phZd1D4OJKpPtObBcaDiLcKqPJaV7cYBwHwV2D-DvMkvg9LG1fTZoCUZzVU8NBef8nX8tp3e5qJYYgusdexchdyDwxOigCKQcCSbFYk6cO0vy_XxwGGbqCKeaOxsC-laHR_wEIhrp_NNwVYfDVhvvj70TVNCvA5IWdIiNPaPYSH3klvNwdv6GRXn2RwYwReozgV9wG2dhaA0Sff0WXSgPRw_vF_cLoNIr59bS9X9jxp1-NcU2tei-VxC2g9U1RMFB09hbcXy8pBHoOsxA5UyDTDscZLFgxOiTr_D2GQBRvJch364p0RT0BHMak1Zkfq0LobAB9YWLwCAE",'
        ' "p":'
        ' "_AdO8_Y-mLzSnm65JI7Sleoxtf1Ex4LaJuNAzSlUdd5LQeUE-aAQ5qfdP_fjGFwY9uu2EQQ0n8jKKAxWT2z2sj4hEwPoT93SU-pZBA0zm0xeIo9QYPDgIw1ejPnAIdGzuW_F0Oh1ELdZ3XQGskNFywZXjoo4WtCbcwn5sLGlhZRfCFJ9dtJFB3OP3SbxKXWyWOcG6KIB2VivzH5NLz8-9sxiv4mJJj7AMvWA9gt0Qo1Alz_O6Xeg3iiV4qIzf0ioPJ7iy6UCVWpohdcwk2Cb6DHswICqlcOtKKRujLGhxtKJ98woSe-v76PuhZ7MWmS6GuF3iRud4AfsZGZWbue1oQ",'
        ' "q":'
        ' "6hN9GJygBBxjQxTLkZJZK3yS2GLJCWjNb5Egf6sWz3J-xvXBmBAszgC3C-OM7EMHr537nzxmLEN-wmIvx-U0OQrzqa5M9zCPdR2SMncRyQdw-nEBLcSqh9gocERjvdROrbZsCz_iLltNoCwCDlZQVE6HJkoVZ5AhAVhj50sQ9jlgWyhYnZMdDdKUfaJpfoADlsYmI49UZKCg2H5yJq1fws_Zh9Mi1z-we7rupOGp8rzgoQkzv68ljbY1yG-TF2Z_W99I32QseNzBRjFp99yXTgp3YcJxNtFnDBdvHLNnRHBwASlD_ZbDxg2p2xILVB_bUHZFW0W3CBzRNFi2bv3h_w",'
        ' "dp":'
        ' "aLsYwiSYCpyc4Z2dbmWzePzjP39J76aexP421YrRQFHp8C4djSZJH7CuLoDybBMJhMKa3CNlQukLqOzHiSX8tkE_OUmsZlQFrT17VEWwJl7r12y6uC4g1jAeFHNMtkEQcITULWYMD7BBtdcbWUS_Ygj2pZMmrAZ4Mqv4iMapxALOIwU0ggYLDXemVv5xxQrV3D_VDSMVpZ5HH7F0naeooKJ6fqHGzo_RCtwehSBpZaaRKsknULmXrfornwxMXh5xWw-jq4CcoaYgXU35L6U75JeqjKxrNuUjtfnuvqSqV5byInlCXMcv02PKINjGjuHAvJ7pL568Una4c1hbnqbHQQ",'
        ' "dq":'
        ' "RcEtBEqYfOEgy3rE90qPfCARep5lnoI2xkqPTrxjfcp28T-HQ5N-Zp1b7xUOh9Gp1rHTrC5JnGM4wSCVcJJjL6SN3EDu-rLj7Vi0molVKX0oM9m9KjBzSSwnUN1wg79i-u1j4S5Wbs4Soeq7ah5areUA7W4iVsxiqY33p5N9KIMMrd2mGr8eZ2Ibkhz2JxZq-2FtOCecVKhxhlKYHeKIqPtbrdhDh7WZGCYqu8Pr60RSBGtDmpnNLR_hgyuMv-pxhaVSiA_IGPRgPFS5aX25MS55SQ6ywk1A0h-howHrgj-ngREVC9sD2F92AKyt55Hev2mfXYW295nu1hShuQ27bQ",'
        ' "qi":'
        ' "ZzWzSSYiJHyLRpqUw-GDluHaIYgDV1w70yYtwl222tvJt0TCQkcZmc3tWmC6qYu_7UfFfVDoCVwBu592p6IC0ZD39_eilHaKbDMZ3dOIS9n9h4yfJvvY-4Jd7o5i_LyK5RktvdyZARKrKfL3mYlWCmHC7yYZC88hDh5qkehRT1d52QBKo928mmrkgJZcuuzEVTygTrnCiiFzcd6A7o8wLbtJPBg4WY793xLipiuSEZ8aWQ50hO98MauBO5MJl_C3kZOkEKiq8JYTU-cUHO6kMqlQ866MOccBsco__frxA8yZlZrfMIDOql8z6oS5tpxR5O_acl9fvJ_thwUAVTk3Ow",'
        ' "kid": "client_assertion_key"}'
    )
    jwk = Jwk.from_json(j)
    assert (
        jwk.public_jwk().as_jwks().to_json() == '{"keys":[{"kty":"RSA","kid":"client_assertion_key","n":'
        '"5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8",'
        '"e":"AQAB"}]}'
    )

    assert jwk.public_jwk().as_jwks().to_json(compact=False) == (
        "{\n"
        '  "keys": [\n'
        "    {\n"
        '      "kty": "RSA", \n'
        '      "kid": "client_assertion_key", \n'
        '      "n": '
        '"5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8", \n'
        '      "e": "AQAB"\n'
        "    }\n"
        "  ]\n"
        "}"
    )


def test_init_from_cryptography() -> None:
    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(65537, 2048)
    jwk = Jwk(private_key)
    assert jwk.kty == "RSA"


def test_init_from_json() -> None:
    j = """
    {
        "kty": "RSA",
        "n": "5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8",
        "e": "AQAB",
        "d": "QD----2gB03w9LwB6Zq5QXR-HmU2TfJKyml_LTxNufE8-es70Y1q8RVMYhX6CdgMliSmX_xwcicFOk06_5_hopKrDmiuHl8Z_DmqW6Zyc62H52CsTfmlTttI6cfV-ISlix1opAEebmusy9n3DZ1_2VtiAsylyHP0_BnWGS1rgzoHpLrRLHANK86SzV0NNBMd23cdhVdacBC7DLmpe9yO0-OuwxCwZ_qVe5OKBISiGkfIK08OWZCgO_t8NOHF6yYw8B2pv3wFEHllJHMR3R0akN6MMLmcIZ-qidbvXBgriRROYD3VZwVOgtrI8DlTdPVh3QnpMS3PekoczLgHx6oOhI0ytDvoQ0phZd1D4OJKpPtObBcaDiLcKqPJaV7cYBwHwV2D-DvMkvg9LG1fTZoCUZzVU8NBef8nX8tp3e5qJYYgusdexchdyDwxOigCKQcCSbFYk6cO0vy_XxwGGbqCKeaOxsC-laHR_wEIhrp_NNwVYfDVhvvj70TVNCvA5IWdIiNPaPYSH3klvNwdv6GRXn2RwYwReozgV9wG2dhaA0Sff0WXSgPRw_vF_cLoNIr59bS9X9jxp1-NcU2tei-VxC2g9U1RMFB09hbcXy8pBHoOsxA5UyDTDscZLFgxOiTr_D2GQBRvJch364p0RT0BHMak1Zkfq0LobAB9YWLwCAE",
        "p": "_AdO8_Y-mLzSnm65JI7Sleoxtf1Ex4LaJuNAzSlUdd5LQeUE-aAQ5qfdP_fjGFwY9uu2EQQ0n8jKKAxWT2z2sj4hEwPoT93SU-pZBA0zm0xeIo9QYPDgIw1ejPnAIdGzuW_F0Oh1ELdZ3XQGskNFywZXjoo4WtCbcwn5sLGlhZRfCFJ9dtJFB3OP3SbxKXWyWOcG6KIB2VivzH5NLz8-9sxiv4mJJj7AMvWA9gt0Qo1Alz_O6Xeg3iiV4qIzf0ioPJ7iy6UCVWpohdcwk2Cb6DHswICqlcOtKKRujLGhxtKJ98woSe-v76PuhZ7MWmS6GuF3iRud4AfsZGZWbue1oQ",
        "q": "6hN9GJygBBxjQxTLkZJZK3yS2GLJCWjNb5Egf6sWz3J-xvXBmBAszgC3C-OM7EMHr537nzxmLEN-wmIvx-U0OQrzqa5M9zCPdR2SMncRyQdw-nEBLcSqh9gocERjvdROrbZsCz_iLltNoCwCDlZQVE6HJkoVZ5AhAVhj50sQ9jlgWyhYnZMdDdKUfaJpfoADlsYmI49UZKCg2H5yJq1fws_Zh9Mi1z-we7rupOGp8rzgoQkzv68ljbY1yG-TF2Z_W99I32QseNzBRjFp99yXTgp3YcJxNtFnDBdvHLNnRHBwASlD_ZbDxg2p2xILVB_bUHZFW0W3CBzRNFi2bv3h_w",
        "dp": "aLsYwiSYCpyc4Z2dbmWzePzjP39J76aexP421YrRQFHp8C4djSZJH7CuLoDybBMJhMKa3CNlQukLqOzHiSX8tkE_OUmsZlQFrT17VEWwJl7r12y6uC4g1jAeFHNMtkEQcITULWYMD7BBtdcbWUS_Ygj2pZMmrAZ4Mqv4iMapxALOIwU0ggYLDXemVv5xxQrV3D_VDSMVpZ5HH7F0naeooKJ6fqHGzo_RCtwehSBpZaaRKsknULmXrfornwxMXh5xWw-jq4CcoaYgXU35L6U75JeqjKxrNuUjtfnuvqSqV5byInlCXMcv02PKINjGjuHAvJ7pL568Una4c1hbnqbHQQ",
        "dq": "RcEtBEqYfOEgy3rE90qPfCARep5lnoI2xkqPTrxjfcp28T-HQ5N-Zp1b7xUOh9Gp1rHTrC5JnGM4wSCVcJJjL6SN3EDu-rLj7Vi0molVKX0oM9m9KjBzSSwnUN1wg79i-u1j4S5Wbs4Soeq7ah5areUA7W4iVsxiqY33p5N9KIMMrd2mGr8eZ2Ibkhz2JxZq-2FtOCecVKhxhlKYHeKIqPtbrdhDh7WZGCYqu8Pr60RSBGtDmpnNLR_hgyuMv-pxhaVSiA_IGPRgPFS5aX25MS55SQ6ywk1A0h-howHrgj-ngREVC9sD2F92AKyt55Hev2mfXYW295nu1hShuQ27bQ",
        "qi": "ZzWzSSYiJHyLRpqUw-GDluHaIYgDV1w70yYtwl222tvJt0TCQkcZmc3tWmC6qYu_7UfFfVDoCVwBu592p6IC0ZD39_eilHaKbDMZ3dOIS9n9h4yfJvvY-4Jd7o5i_LyK5RktvdyZARKrKfL3mYlWCmHC7yYZC88hDh5qkehRT1d52QBKo928mmrkgJZcuuzEVTygTrnCiiFzcd6A7o8wLbtJPBg4WY793xLipiuSEZ8aWQ50hO98MauBO5MJl_C3kZOkEKiq8JYTU-cUHO6kMqlQ866MOccBsco__frxA8yZlZrfMIDOql8z6oS5tpxR5O_acl9fvJ_thwUAVTk3Ow",
        "kid": "client_assertion_key"
    }
    """
    jwk = Jwk(j)
    assert (
        jwk.public_jwk().as_jwks().to_json(compact=True) == '{"keys":[{"kty":"RSA","kid":"client_assertion_key","n":'
        '"5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8",'
        '"e":"AQAB"}]}'
    )
    assert jwk.public_jwk().as_jwks().to_json(compact=False) == (
        "{\n"
        '  "keys": [\n'
        "    {\n"
        '      "kty": "RSA", \n'
        '      "kid": "client_assertion_key", \n'
        '      "n": '
        '"5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8", \n'
        '      "e": "AQAB"\n'
        "    }\n"
        "  ]\n"
        "}"
    )


def test_missing_kty() -> None:
    with pytest.raises(InvalidJwk):
        Jwk({"foo": "kty_is_missing"})


def test_include_kid() -> None:
    jwk = Jwk({"kty": "oct", "k": "foobar"}, include_kid_thumbprint=True)
    assert jwk.kid == jwk.thumbprint() == "p91YUDdd513xDMIoKEJAySww4jB3hionP-1CUWx6b8g"


def test_getattr() -> None:
    jwk = Jwk.generate_for_kty("oct")
    with pytest.raises(AttributeError):
        jwk.foo


def test_setattr() -> None:
    jwk = Jwk.generate_for_kty("oct")
    with pytest.raises(RuntimeError):
        jwk["k"] = "foo"


def test_invalid_params() -> None:
    with pytest.raises(TypeError):
        Jwk({"kty": "oct", "k": "foobar", "alg": 1.34}).alg

    with pytest.raises(TypeError):
        Jwk({"kty": "oct", "k": "foobar", "kid": 1.34}).kid

    with pytest.raises(InvalidJwk):
        Jwk(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "SOlwe9_nRwz2f9Y2aSB9d7D-AXTSSBlAQd5HZUIEGLA",
                "y": "Pzk9Gd4wwbx9STkK_RfWqxnfU9AwpvWZzf_K0GpaQZo",
                "d": "Invalid-private-key--EHzgbRaNKRCMhk6jiCT-ZQ",
                "alg": "ES256",
            }
        )


def test_invalid_class_for_kty() -> None:
    with pytest.raises(TypeError):
        RSAJwk({"kty": "oct", "k": "foobar"})


@pytest.mark.parametrize(
    ("kty", "private_key_ops", "public_key_ops"),
    [
        ("RSA", ("sign",), ("verify",)),
        ("RSA", ("unwrapKey",), ("wrapKey",)),
        ("oct", ("sign",), ("verify",)),
        ("oct", ("unwrapKey",), ("wrapKey",)),
    ],
)
def test_key_ops_without_alg(kty: str, private_key_ops: tuple[str], public_key_ops: tuple[str]) -> None:
    # with a key with no alg or use, we can only trust the key_ops from the key
    private_jwk = Jwk.generate_for_kty("RSA", key_ops=private_key_ops)
    assert private_jwk.key_ops == private_key_ops

    public_jwk = private_jwk.public_jwk()
    assert public_key_ops == public_jwk.key_ops


@pytest.mark.parametrize(
    ("alg", "use", "private_key_ops", "public_key_ops"),
    [
        ("RS256", "sig", ("sign",), ("verify",)),
        ("HS256", "sig", ("sign", "verify"), ("sign", "verify")),
        ("A128GCMKW", "enc", ("wrapKey", "unwrapKey"), ("wrapKey", "unwrapKey")),
        ("A128GCM", "enc", ("encrypt", "decrypt"), ("encrypt", "decrypt")),
    ],
)
def test_use_key_ops_with_alg(alg: str, use: str, private_key_ops: tuple[str], public_key_ops: tuple[str]) -> None:
    # if key has an 'alg' parameter, we can deduce the use and key ops
    private_jwk = Jwk.generate(alg=alg)
    assert "use" not in private_jwk
    assert "key_ops" not in private_jwk
    assert private_jwk.use == use
    assert private_jwk.key_ops == private_key_ops

    public_jwk = private_jwk.public_jwk() if not private_jwk.is_symmetric else private_jwk
    assert "use" not in public_jwk
    assert "key_ops" not in public_jwk
    assert public_jwk.use == use
    assert public_jwk.key_ops == public_key_ops


def test_thumbprint() -> None:
    # key from https://www.rfc-editor.org/rfc/rfc7638.html#section-3.1
    jwk = Jwk(
        {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
                "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
                "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
                "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
                "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
                "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
            ),
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        }
    )

    assert jwk.thumbprint() == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    assert (
        jwk.thumbprint_uri()
        == "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    )

    jwk_with_thumbprint_kid = jwk.with_kid_thumbprint(force=True)
    assert jwk_with_thumbprint_kid.kid == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    assert isinstance(jwk_with_thumbprint_kid, Jwk)
    assert jwk_with_thumbprint_kid is not jwk
    assert jwk_with_thumbprint_kid.n == jwk.n

    jwk_with_initial_kid = jwk.with_kid_thumbprint(force=False)
    assert jwk_with_initial_kid.kid == "2011-04-29"
    assert isinstance(jwk_with_initial_kid, Jwk)
    assert jwk_with_initial_kid == jwk
    assert jwk_with_initial_kid.n == jwk.n


def test_invalid_thumbprint_hash() -> None:
    jwk = Jwk.generate(kty="EC", crv="P-256")
    with pytest.raises(ValueError):
        jwk.thumbprint(hashalg="foo")


def test_generate_invalid_kty() -> None:
    with pytest.raises(UnsupportedKeyType):
        Jwk.generate_for_kty("foobar")


def test_generate_for_alg() -> None:
    rsa15_jwk = Jwk.generate_for_alg("RSA1_5")
    assert isinstance(rsa15_jwk, RSAJwk)
    assert rsa15_jwk.alg == "RSA1_5"


def test_signature_wrapper() -> None:
    signature_jwk = Jwk.generate(alg="ES256")
    signature_wrapper = signature_jwk.signature_wrapper()
    assert isinstance(signature_wrapper, ES256)
    assert signature_wrapper.key == signature_jwk.cryptography_key


def test_encryption_wrapper() -> None:
    encryption_jwk = Jwk.generate(alg="A128GCM")
    encryption_wrapper = encryption_jwk.encryption_wrapper()
    assert isinstance(encryption_wrapper, A128GCM)
    assert encryption_wrapper.key == encryption_jwk.cryptography_key


def test_key_management_wrapper() -> None:
    key_mgmt_jwk = Jwk.generate(alg="ECDH-ES+A128KW")
    key_mgmt_wrapper = key_mgmt_jwk.key_management_wrapper()
    assert isinstance(key_mgmt_wrapper, EcdhEs_A128KW)
    assert key_mgmt_wrapper.key == key_mgmt_jwk.cryptography_key


def test_to_jwk() -> None:
    # symmetric key
    SYMMETRIC_KEY = b"this is a symmetric key"
    sym_key = to_jwk(SYMMETRIC_KEY, is_symmetric=True, kty="oct")
    assert isinstance(sym_key, SymmetricJwk)
    assert sym_key.key == b"this is a symmetric key"

    with pytest.raises(ValueError):
        to_jwk(SYMMETRIC_KEY, is_symmetric=False)

    with pytest.raises(ValueError):
        to_jwk(SYMMETRIC_KEY, is_private=False)

    # test using a Google public key
    GOOGLE_KEY = """{
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "f451345fad08101bfb345cf642a2da9267b9ebeb",
      "n": "ppFPAZUqIVqCf_SffT6xDCXu1R7aRoT6TNT5_Q8PKxkkqbOVysJPNwliF-486VeM8KNW8onFOv0GkP0lJ2ASrVgyMG1qmlGUlKug64dMQXPxSlVUCXCPN676W5IZTvT0tD2byM_29HZXnOifRg-d7PRRvIBLSUWe-fGb1-tP2w65SOW-W6LuOjGzLNPJFYQvHyUx_uXHOCfIoSb8kaMwx8bCWvKc76yT0DG1wcygGXKuFQHW-Sdi1j_6bF19lVu30DX-jhYsNMUnGUr6g2iycQ50pWMORZqvcHVOH1bbDrWuz0b564sK0ET2B3XDR37djNQ305PxiQZaBStm-hM8Aw",
      "alg": "RS256"
    }"""
    asym_key = to_jwk(GOOGLE_KEY, kty="RSA", is_private=False)
    assert not asym_key.is_private
    assert isinstance(asym_key, RSAJwk)

    with pytest.raises(ValueError):
        to_jwk(GOOGLE_KEY, kty="EC")

    with pytest.raises(ValueError):
        to_jwk(GOOGLE_KEY, is_private=True)

    with pytest.raises(ValueError):
        to_jwk(GOOGLE_KEY, is_symmetric=True)


@pytest.mark.parametrize("alg", SignatureAlgs.ALL)
def test_sign_verify(alg: str) -> None:
    payload = b"this_is_a_payload"
    jwk = Jwk.generate(alg=alg)
    signature = jwk.sign(payload)
    if not jwk.is_symmetric:
        assert jwk.public_jwk().verify(payload, signature)
        with pytest.warns(match="private key"):
            assert jwk.verify(payload, signature)
    else:
        assert jwk.verify(payload, signature)


@pytest.mark.parametrize(
    "alg",
    KeyManagementAlgs.ALL_KEY_BASED - {KeyManagementAlgs.RSA1_5, KeyManagementAlgs.dir},
)
@pytest.mark.parametrize("enc", EncryptionAlgs.ALL)
def test_sender_receiver_key(alg: str, enc: str) -> None:
    recipient_jwk = Jwk.generate(alg=alg)
    if recipient_jwk.is_symmetric:
        sender_cek, wrapped_cek, extra_headers = recipient_jwk.sender_key(enc=enc)
    else:
        sender_cek, wrapped_cek, extra_headers = recipient_jwk.public_jwk().sender_key(enc=enc)
        with pytest.warns(match="private key"):
            recipient_jwk.sender_key(enc=enc)

    if recipient_jwk.is_symmetric:
        recipient_cek = recipient_jwk.recipient_key(wrapped_cek, enc=enc, **extra_headers)
        assert sender_cek == recipient_cek
    else:
        with pytest.raises(ValueError):
            recipient_jwk.public_jwk().recipient_key(wrapped_cek, enc=enc, **extra_headers)


@pytest.mark.parametrize("alg", KeyManagementAlgs.ALL_AES | KeyManagementAlgs.ALL_AESGCM)
@pytest.mark.parametrize("enc", EncryptionAlgs.ALL)
def test_aeskw_with_choosen_cek(alg: str, enc: str) -> None:
    recipient_jwk = Jwk.generate(alg=alg)
    choosen_cek = select_alg_class(SymmetricJwk.ENCRYPTION_ALGORITHMS, alg=enc).generate_key()

    sender_cek, _, _ = recipient_jwk.sender_key(enc=enc, cek=choosen_cek)
    assert sender_cek.key == choosen_cek


def test_der_pem() -> None:
    jwk = Jwk.generate(alg="ES256")
    password = secrets.token_urlsafe(16)
    der = jwk.to_der(password)
    assert Jwk.from_der(der, password) == jwk

    pem = jwk.to_pem(password)
    assert Jwk.from_pem(pem, password) == jwk

    with pytest.raises(ValueError, match="public key was loaded"):
        Jwk.from_der(jwk.public_jwk().to_der(), password=password)
    with pytest.raises(ValueError, match="not a private or a public DER encoded key"):
        Jwk.from_der(secrets.token_bytes(512))

    with pytest.raises(ValueError, match="public key was loaded"):
        Jwk.from_pem(jwk.public_jwk().to_pem(), password=password)
    with pytest.raises(ValueError, match="not a private or a public PEM encoded key"):
        Jwk.from_pem("""\
-----BEGIN PRIVATE KEY-----
MIGHAgRandomGarbage/zrsfsdfsdfszer
lJPkaLBw
-----END PRIVATE KEY-----
""")


def test_from_x509() -> None:
    ms_cert = """-----BEGIN CERTIFICATE-----
MIII5TCCBs2gAwIBAgITMwAD4s0QZq2NuBwGCAAAAAPizTANBgkqhkiG9w0BAQwF
ADBdMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
MS4wLAYDVQQDEyVNaWNyb3NvZnQgQXp1cmUgUlNBIFRMUyBJc3N1aW5nIENBIDA3
MB4XDTIzMDkxNDE3MjQyMFoXDTI0MDkwODE3MjQyMFowaDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
ZnQgQ29ycG9yYXRpb24xGjAYBgNVBAMTEXd3dy5taWNyb3NvZnQuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsmbP4PGEgfIltEV/Wt6NFwC3OkbR
mtLc/+W9EsJUZNyQZLC5TlLOOy0ux67HPMoiSZrQRJLn99IQJbRXTTZbRR7jz4I9
e8qYO5VehFS0RHkT6M3XYeDTDQfQOAPO7jbZgMKP9XgGqZXsbqoBKyFRPrszVzZW
Zc+dGlZTQnMYkAhltEGgEL8+fN25Gquavt6WSY2vc9Li2Yj9Eoo4+Eo4zJMCKVPE
4bsyC40BBaJEyU5pTdaVMI8K0pyKkLvt2kklryXaamjU9K/zee1joPYGRqVr9fl3
+hJ1ia0VzdnFq3tP+wXFlEr+m8MtpQTwha1Elx1hnuRmFG/YPa9qj+RlNQIDAQAB
o4IEkTCCBI0wggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB3AHb/iD8KtvuVUcJh
zPWHujS0pM27KdxoQgqf5mdMWjp0AAABipTCG8UAAAQDAEgwRgIhAK9VBkhYoGD8
smdZpGblkGIxh+s76J9DIu2vylLOSX5DAiEAnW9VG6vFtyf+iv+LTiGE0ISGr0hh
itmTJxsgsbV2MQAAdQDatr9rP7W2Ip+bwrtca+hwkXFsu1GEhTS9pD0wSNf7qwAA
AYqUwhw0AAAEAwBGMEQCIGchMFlY/hrw6qyerVfS+IgchU160ugObUp6bbXLcU5x
AiBNOYgiepuAhstFR0OjvTwG0t2oRk8qr+S6/m6vFVAjTgB2AO7N0GTV2xrOxVy3
nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAABipTCG+0AAAQDAEcwRQIgdPH1Un+uZYyz
/miP1BfUdhmr7FxUSF64j76xNfBr+1ECIQCzUfOkMZuP6HwcBvqUKVnpgGrdGqRl
FWInDI0GIWts+DAnBgkrBgEEAYI3FQoEGjAYMAoGCCsGAQUFBwMCMAoGCCsGAQUF
BwMBMDwGCSsGAQQBgjcVBwQvMC0GJSsGAQQBgjcVCIe91xuB5+tGgoGdLo7QDIfw
2h1dgoTlaYLzpz4CAWQCASYwgbQGCCsGAQUFBwEBBIGnMIGkMHMGCCsGAQUFBzAC
hmdodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29m
dCUyMEF6dXJlJTIwUlNBJTIwVExTJTIwSXNzdWluZyUyMENBJTIwMDclMjAtJTIw
eHNpZ24uY3J0MC0GCCsGAQUFBzABhiFodHRwOi8vb25lb2NzcC5taWNyb3NvZnQu
Y29tL29jc3AwHQYDVR0OBBYEFJRG0f2FZsvVCZPogua5ie3N5ocKMA4GA1UdDwEB
/wQEAwIFoDCBmQYDVR0RBIGRMIGOghN3d3dxYS5taWNyb3NvZnQuY29tghF3d3cu
bWljcm9zb2Z0LmNvbYIYc3RhdGljdmlldy5taWNyb3NvZnQuY29tghFpLnMtbWlj
cm9zb2Z0LmNvbYINbWljcm9zb2Z0LmNvbYIRYy5zLW1pY3Jvc29mdC5jb22CFXBy
aXZhY3kubWljcm9zb2Z0LmNvbTAMBgNVHRMBAf8EAjAAMGoGA1UdHwRjMGEwX6Bd
oFuGWWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29m
dCUyMEF6dXJlJTIwUlNBJTIwVExTJTIwSXNzdWluZyUyMENBJTIwMDcuY3JsMGYG
A1UdIARfMF0wUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93
d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZn
gQwBAgIwHwYDVR0jBBgwFoAUzhUWO+oCo6Zr2tkr/eWMUr56UKgwHQYDVR0lBBYw
FAYIKwYBBQUHAwIGCCsGAQUFBwMBMA0GCSqGSIb3DQEBDAUAA4ICAQBuwQV+NfkB
BeNDMcuY1XwsnYhREpo03+hghAjMLwgY7HhwRD46jnTFdD+l9JUv4uXU5vy/UreZ
JbTia0mD76MWwrr70ntDum3nPRLyMDDtr3/n/ZnopCFMrk9WPiITOvcarpNznvaa
kbDWZccj4s6yHafKsruq2wDF5f/LtIRUt3D8pFLZ1nTmbLyiKcV7BKlaGUJyw83B
yCBj2ED0ynKqgssXfO8vdTDzBjMsiY1LtcW0AzlqA20o+7XUxCYmwVyx+3/TKSHs
elRE4hxEZ5lDHwnm2XLBls/BGA/bjIIMRwj+FqKax2jgNA0vBeeLeOt8d75LyupP
147snQDbauEeHRbrJKmDnpdE1JVsVWnYoEj5O39wQb4uBJ1e7SxDdkieydLQyNcJ
qJL/DDEtqlXn7BVunNNb6cPYH+d/KZYdF/Xgp9M0VepIvm8wgnnTNgW66RZTPwT2
7fbI+rnR8lrHSJcFmDPPC7j4IM0RNo2bmEGI4EX9GR7XZ5fuylS1NEIlrap9HIPq
TOR+MsPH4AeH9UyiYvOmxUNZIRTcQwxfWOEEZmvLpzVvROqIy7yxX5f3KGW4Cf45
Unyb2Oj6CDA9YFEcjRuaZBDtSKJ6AYOWFJO7CIHsjAZ0rBqfyfNdBd5DG4+ZJkD8
50WeBZCdbW0GmufXnB4Oa1oIOywDyOG6eQ==
-----END CERTIFICATE-----
"""
    # this is the https cert for www.microsoft.com on 06/10/23

    key = Jwk.from_x509_pem(ms_cert, include_x5t=True, include_x5t_s256=True)
    assert key.kty == "RSA"
    assert not key.is_private
    assert not key.is_symmetric
    assert key.is_public
    assert key.key_size == 2048
    assert key["x5t"] == "4VebpVElzsOnjjn1XPgdqL-pT4g"
    assert key["x5t#S256"] == "80gl5xzn_qHTiCyFX2TSvFv8RJCWgcm-nTNXvrKhrms"
    assert key == Jwk.from_x509_pem(ms_cert.encode())

    cert = x509.load_pem_x509_certificate(ms_cert.encode())
    assert key == Jwk.from_x509_cert(cert) == Jwk.from_x509_der(cert.public_bytes(Encoding.DER))


def test_from_pkcs12() -> None:
    p12 = BinaPy(
        """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"""
    ).decode_from("b64")

    jwk = Jwk.from_pkcs12(p12, "jwskate!")
    assert jwk.kty == "RSA"
    assert jwk.is_private
    assert not jwk.is_symmetric
    assert not jwk.is_public
    assert jwk == Jwk.from_pkcs12(p12, b"jwskate!")
