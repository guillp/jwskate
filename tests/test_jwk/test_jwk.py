from typing import Tuple

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from jwskate import (
    A128GCM,
    ES256,
    EcdhEs_A128KW,
    InvalidJwk,
    Jwk,
    RSAJwk,
    SymmetricJwk,
    UnsupportedKeyType,
    to_jwk,
)


def test_public_jwk() -> None:
    private_jwk = Jwk.generate_for_alg("RS256")
    assert private_jwk.is_private
    public_jwk = private_jwk.public_jwk()
    assert not public_jwk.is_private
    assert public_jwk is public_jwk.public_jwk()


def test_jwk_copy() -> None:
    jwk1 = Jwk.generate_for_kty("RSA")

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
    j = '{"kty": "RSA", "n": "5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8", "e": "AQAB", "d": "QD----2gB03w9LwB6Zq5QXR-HmU2TfJKyml_LTxNufE8-es70Y1q8RVMYhX6CdgMliSmX_xwcicFOk06_5_hopKrDmiuHl8Z_DmqW6Zyc62H52CsTfmlTttI6cfV-ISlix1opAEebmusy9n3DZ1_2VtiAsylyHP0_BnWGS1rgzoHpLrRLHANK86SzV0NNBMd23cdhVdacBC7DLmpe9yO0-OuwxCwZ_qVe5OKBISiGkfIK08OWZCgO_t8NOHF6yYw8B2pv3wFEHllJHMR3R0akN6MMLmcIZ-qidbvXBgriRROYD3VZwVOgtrI8DlTdPVh3QnpMS3PekoczLgHx6oOhI0ytDvoQ0phZd1D4OJKpPtObBcaDiLcKqPJaV7cYBwHwV2D-DvMkvg9LG1fTZoCUZzVU8NBef8nX8tp3e5qJYYgusdexchdyDwxOigCKQcCSbFYk6cO0vy_XxwGGbqCKeaOxsC-laHR_wEIhrp_NNwVYfDVhvvj70TVNCvA5IWdIiNPaPYSH3klvNwdv6GRXn2RwYwReozgV9wG2dhaA0Sff0WXSgPRw_vF_cLoNIr59bS9X9jxp1-NcU2tei-VxC2g9U1RMFB09hbcXy8pBHoOsxA5UyDTDscZLFgxOiTr_D2GQBRvJch364p0RT0BHMak1Zkfq0LobAB9YWLwCAE", "p": "_AdO8_Y-mLzSnm65JI7Sleoxtf1Ex4LaJuNAzSlUdd5LQeUE-aAQ5qfdP_fjGFwY9uu2EQQ0n8jKKAxWT2z2sj4hEwPoT93SU-pZBA0zm0xeIo9QYPDgIw1ejPnAIdGzuW_F0Oh1ELdZ3XQGskNFywZXjoo4WtCbcwn5sLGlhZRfCFJ9dtJFB3OP3SbxKXWyWOcG6KIB2VivzH5NLz8-9sxiv4mJJj7AMvWA9gt0Qo1Alz_O6Xeg3iiV4qIzf0ioPJ7iy6UCVWpohdcwk2Cb6DHswICqlcOtKKRujLGhxtKJ98woSe-v76PuhZ7MWmS6GuF3iRud4AfsZGZWbue1oQ", "q": "6hN9GJygBBxjQxTLkZJZK3yS2GLJCWjNb5Egf6sWz3J-xvXBmBAszgC3C-OM7EMHr537nzxmLEN-wmIvx-U0OQrzqa5M9zCPdR2SMncRyQdw-nEBLcSqh9gocERjvdROrbZsCz_iLltNoCwCDlZQVE6HJkoVZ5AhAVhj50sQ9jlgWyhYnZMdDdKUfaJpfoADlsYmI49UZKCg2H5yJq1fws_Zh9Mi1z-we7rupOGp8rzgoQkzv68ljbY1yG-TF2Z_W99I32QseNzBRjFp99yXTgp3YcJxNtFnDBdvHLNnRHBwASlD_ZbDxg2p2xILVB_bUHZFW0W3CBzRNFi2bv3h_w", "dp": "aLsYwiSYCpyc4Z2dbmWzePzjP39J76aexP421YrRQFHp8C4djSZJH7CuLoDybBMJhMKa3CNlQukLqOzHiSX8tkE_OUmsZlQFrT17VEWwJl7r12y6uC4g1jAeFHNMtkEQcITULWYMD7BBtdcbWUS_Ygj2pZMmrAZ4Mqv4iMapxALOIwU0ggYLDXemVv5xxQrV3D_VDSMVpZ5HH7F0naeooKJ6fqHGzo_RCtwehSBpZaaRKsknULmXrfornwxMXh5xWw-jq4CcoaYgXU35L6U75JeqjKxrNuUjtfnuvqSqV5byInlCXMcv02PKINjGjuHAvJ7pL568Una4c1hbnqbHQQ", "dq": "RcEtBEqYfOEgy3rE90qPfCARep5lnoI2xkqPTrxjfcp28T-HQ5N-Zp1b7xUOh9Gp1rHTrC5JnGM4wSCVcJJjL6SN3EDu-rLj7Vi0molVKX0oM9m9KjBzSSwnUN1wg79i-u1j4S5Wbs4Soeq7ah5areUA7W4iVsxiqY33p5N9KIMMrd2mGr8eZ2Ibkhz2JxZq-2FtOCecVKhxhlKYHeKIqPtbrdhDh7WZGCYqu8Pr60RSBGtDmpnNLR_hgyuMv-pxhaVSiA_IGPRgPFS5aX25MS55SQ6ywk1A0h-howHrgj-ngREVC9sD2F92AKyt55Hev2mfXYW295nu1hShuQ27bQ", "qi": "ZzWzSSYiJHyLRpqUw-GDluHaIYgDV1w70yYtwl222tvJt0TCQkcZmc3tWmC6qYu_7UfFfVDoCVwBu592p6IC0ZD39_eilHaKbDMZ3dOIS9n9h4yfJvvY-4Jd7o5i_LyK5RktvdyZARKrKfL3mYlWCmHC7yYZC88hDh5qkehRT1d52QBKo928mmrkgJZcuuzEVTygTrnCiiFzcd6A7o8wLbtJPBg4WY793xLipiuSEZ8aWQ50hO98MauBO5MJl_C3kZOkEKiq8JYTU-cUHO6kMqlQ866MOccBsco__frxA8yZlZrfMIDOql8z6oS5tpxR5O_acl9fvJ_thwUAVTk3Ow", "kid": "client_assertion_key"}'
    jwk = Jwk.from_json(j)
    assert jwk.public_jwk().as_jwks().to_json() == (
        '{"keys": [{"kty": "RSA", "kid": "client_assertion_key", "n": '
        '"5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8", '
        '"e": "AQAB"}]}'
    )


def test_init_from_cryptography() -> None:
    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(65537, 2048)
    jwk = Jwk(private_key)
    assert jwk.kty == "RSA"


def test_init_from_json() -> None:
    j = '{"kty": "RSA", "n": "5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8", "e": "AQAB", "d": "QD----2gB03w9LwB6Zq5QXR-HmU2TfJKyml_LTxNufE8-es70Y1q8RVMYhX6CdgMliSmX_xwcicFOk06_5_hopKrDmiuHl8Z_DmqW6Zyc62H52CsTfmlTttI6cfV-ISlix1opAEebmusy9n3DZ1_2VtiAsylyHP0_BnWGS1rgzoHpLrRLHANK86SzV0NNBMd23cdhVdacBC7DLmpe9yO0-OuwxCwZ_qVe5OKBISiGkfIK08OWZCgO_t8NOHF6yYw8B2pv3wFEHllJHMR3R0akN6MMLmcIZ-qidbvXBgriRROYD3VZwVOgtrI8DlTdPVh3QnpMS3PekoczLgHx6oOhI0ytDvoQ0phZd1D4OJKpPtObBcaDiLcKqPJaV7cYBwHwV2D-DvMkvg9LG1fTZoCUZzVU8NBef8nX8tp3e5qJYYgusdexchdyDwxOigCKQcCSbFYk6cO0vy_XxwGGbqCKeaOxsC-laHR_wEIhrp_NNwVYfDVhvvj70TVNCvA5IWdIiNPaPYSH3klvNwdv6GRXn2RwYwReozgV9wG2dhaA0Sff0WXSgPRw_vF_cLoNIr59bS9X9jxp1-NcU2tei-VxC2g9U1RMFB09hbcXy8pBHoOsxA5UyDTDscZLFgxOiTr_D2GQBRvJch364p0RT0BHMak1Zkfq0LobAB9YWLwCAE", "p": "_AdO8_Y-mLzSnm65JI7Sleoxtf1Ex4LaJuNAzSlUdd5LQeUE-aAQ5qfdP_fjGFwY9uu2EQQ0n8jKKAxWT2z2sj4hEwPoT93SU-pZBA0zm0xeIo9QYPDgIw1ejPnAIdGzuW_F0Oh1ELdZ3XQGskNFywZXjoo4WtCbcwn5sLGlhZRfCFJ9dtJFB3OP3SbxKXWyWOcG6KIB2VivzH5NLz8-9sxiv4mJJj7AMvWA9gt0Qo1Alz_O6Xeg3iiV4qIzf0ioPJ7iy6UCVWpohdcwk2Cb6DHswICqlcOtKKRujLGhxtKJ98woSe-v76PuhZ7MWmS6GuF3iRud4AfsZGZWbue1oQ", "q": "6hN9GJygBBxjQxTLkZJZK3yS2GLJCWjNb5Egf6sWz3J-xvXBmBAszgC3C-OM7EMHr537nzxmLEN-wmIvx-U0OQrzqa5M9zCPdR2SMncRyQdw-nEBLcSqh9gocERjvdROrbZsCz_iLltNoCwCDlZQVE6HJkoVZ5AhAVhj50sQ9jlgWyhYnZMdDdKUfaJpfoADlsYmI49UZKCg2H5yJq1fws_Zh9Mi1z-we7rupOGp8rzgoQkzv68ljbY1yG-TF2Z_W99I32QseNzBRjFp99yXTgp3YcJxNtFnDBdvHLNnRHBwASlD_ZbDxg2p2xILVB_bUHZFW0W3CBzRNFi2bv3h_w", "dp": "aLsYwiSYCpyc4Z2dbmWzePzjP39J76aexP421YrRQFHp8C4djSZJH7CuLoDybBMJhMKa3CNlQukLqOzHiSX8tkE_OUmsZlQFrT17VEWwJl7r12y6uC4g1jAeFHNMtkEQcITULWYMD7BBtdcbWUS_Ygj2pZMmrAZ4Mqv4iMapxALOIwU0ggYLDXemVv5xxQrV3D_VDSMVpZ5HH7F0naeooKJ6fqHGzo_RCtwehSBpZaaRKsknULmXrfornwxMXh5xWw-jq4CcoaYgXU35L6U75JeqjKxrNuUjtfnuvqSqV5byInlCXMcv02PKINjGjuHAvJ7pL568Una4c1hbnqbHQQ", "dq": "RcEtBEqYfOEgy3rE90qPfCARep5lnoI2xkqPTrxjfcp28T-HQ5N-Zp1b7xUOh9Gp1rHTrC5JnGM4wSCVcJJjL6SN3EDu-rLj7Vi0molVKX0oM9m9KjBzSSwnUN1wg79i-u1j4S5Wbs4Soeq7ah5areUA7W4iVsxiqY33p5N9KIMMrd2mGr8eZ2Ibkhz2JxZq-2FtOCecVKhxhlKYHeKIqPtbrdhDh7WZGCYqu8Pr60RSBGtDmpnNLR_hgyuMv-pxhaVSiA_IGPRgPFS5aX25MS55SQ6ywk1A0h-howHrgj-ngREVC9sD2F92AKyt55Hev2mfXYW295nu1hShuQ27bQ", "qi": "ZzWzSSYiJHyLRpqUw-GDluHaIYgDV1w70yYtwl222tvJt0TCQkcZmc3tWmC6qYu_7UfFfVDoCVwBu592p6IC0ZD39_eilHaKbDMZ3dOIS9n9h4yfJvvY-4Jd7o5i_LyK5RktvdyZARKrKfL3mYlWCmHC7yYZC88hDh5qkehRT1d52QBKo928mmrkgJZcuuzEVTygTrnCiiFzcd6A7o8wLbtJPBg4WY793xLipiuSEZ8aWQ50hO98MauBO5MJl_C3kZOkEKiq8JYTU-cUHO6kMqlQ866MOccBsco__frxA8yZlZrfMIDOql8z6oS5tpxR5O_acl9fvJ_thwUAVTk3Ow", "kid": "client_assertion_key"}'
    jwk = Jwk(j)
    assert jwk.public_jwk().as_jwks().to_json() == (
        '{"keys": [{"kty": "RSA", "kid": "client_assertion_key", "n": '
        '"5nHd3aefARenRFQn-wVrjBLS-5A0uUiHWfOUt8EpjwE3wADAvVPKLbvRQJfugyrn_RpnLqqZFkwYrVD_u1Uzl9J17XJG75jGjCf-gVs1t9FPpgEsJGYK4RK2_f40AxAc6hKomB9q6_dqIxChDxVCrIrrWd9kRk0T86d8Ade3J4f_iMbremm3woSwI6QD056DkRtAD_v2PZQbUBgSru-PsrJ5l_pxxlGPxzAM4_XH8VfogXI8pWv2UDE1IguVeh371ESCbQbJ7SX2jgNzcvvZMMWs0syfF7P0BzGrh_ONsRcxmtjZgtcOA0TCu2-v8qx7GisgqOWOrzWs7ej5RUsu1sxtT53JG2Y3lrPrgajXTB56mSUaL9ivxEfUD17X_cUznGDNoVqcRdfa27rCtWqd8gL-C7M9bYYgcfpCRPllRvGmWP9oarrG4XoIO17QuhZ5tAoz8oFLM9o6pzR2CeDvmSqFbbTHXYdcpCuvYukIimZP6RruMU9O9YQjgCEGWx06WoTnDqWWjbrId8VqP0xJ_6w0j6av3EWGKLETBbaYRXys4OOy-JZRRHydg-es4tkir4xkMvIG8plxoz_mZbTyO9GA5tMHWzbQciUQFf95Gpiwsa5RDdGZx-guBAN56mtKnUzVG_PmUJ8-pzTATkjVpThBRLWaVPFi0eWLEc2NbF8", '
        '"e": "AQAB"}]}'
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


def test_invalid_class_for_kty() -> None:
    with pytest.raises(TypeError):
        RSAJwk({"kty": "oct", "k": "foobar"})


@pytest.mark.parametrize(
    "kty, private_key_ops, public_key_ops",
    [
        ("RSA", ("sign",), ("verify",)),
        ("RSA", ("unwrapKey",), ("wrapKey",)),
        ("oct", ("sign",), ("verify",)),
        ("oct", ("unwrapKey",), ("wrapKey",)),
    ],
)
def test_key_ops_without_alg(
    kty: str, private_key_ops: Tuple[str], public_key_ops: Tuple[str]
) -> None:
    # with a key with no alg or use, we can only trust the key_ops from the key
    private_jwk = Jwk.generate_for_kty("RSA", key_ops=private_key_ops)
    assert private_jwk.key_ops == private_key_ops

    public_jwk = private_jwk.public_jwk()
    assert public_key_ops == public_jwk.key_ops


@pytest.mark.parametrize(
    "alg, use, private_key_ops, public_key_ops",
    [
        ("RS256", "sig", ("sign",), ("verify",)),
        ("HS256", "sig", ("sign", "verify"), ("sign", "verify")),
        ("A128GCMKW", "enc", ("wrapKey", "unwrapKey"), ("wrapKey", "unwrapKey")),
        ("A128GCM", "enc", ("encrypt", "decrypt"), ("encrypt", "decrypt")),
    ],
)
def test_use_key_ops_with_alg(
    alg: str, use: str, private_key_ops: Tuple[str], public_key_ops: Tuple[str]
) -> None:
    # if key has an 'alg' parameter, we can deduce the use and key ops
    private_jwk = Jwk.generate_for_alg(alg)
    assert "use" not in private_jwk
    assert "key_ops" not in private_jwk
    assert private_jwk.use == use
    assert private_jwk.key_ops == private_key_ops

    public_jwk = (
        private_jwk.public_jwk() if not private_jwk.is_symmetric else private_jwk
    )
    assert "use" not in public_jwk
    assert "key_ops" not in public_jwk
    assert public_jwk.use == use
    assert public_jwk.key_ops == public_key_ops


def test_thumbprint() -> None:
    # key from https://www.rfc-editor.org/rfc/rfc7638.html#section-3.1
    jwk = Jwk(
        {
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
            "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
            "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
            "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
            "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
            "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
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
    assert jwk_with_initial_kid is jwk
    assert jwk_with_initial_kid.n == jwk.n


def test_invalid_thumbprint_hash() -> None:
    jwk = Jwk.generate_for_kty("EC", crv="P-256")
    with pytest.raises(ValueError):
        jwk.thumbprint("foo")


def test_generate_invalid_kty() -> None:
    with pytest.raises(UnsupportedKeyType):
        Jwk.generate_for_kty("foobar")


def test_generate_for_alg() -> None:
    rsa15_jwk = Jwk.generate_for_alg("RSA1_5")
    assert isinstance(rsa15_jwk, RSAJwk)
    assert rsa15_jwk.alg == "RSA1_5"


def test_signature_wrapper() -> None:
    signature_jwk = Jwk.generate_for_alg("ES256")
    signature_wrapper = signature_jwk.signature_wrapper()
    assert isinstance(signature_wrapper, ES256)
    assert signature_wrapper.key == signature_jwk.cryptography_key


def test_encryption_wrapper() -> None:
    encryption_jwk = Jwk.generate_for_alg("A128GCM")
    encryption_wrapper = encryption_jwk.encryption_wrapper()
    assert isinstance(encryption_wrapper, A128GCM)
    assert encryption_wrapper.key == encryption_jwk.cryptography_key


def test_key_management_wrapper() -> None:
    key_mgmt_jwk = Jwk.generate_for_alg("ECDH-ES+A128KW")
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
