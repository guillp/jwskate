import pytest

from jwskate import Jwk, JwkSet


def test_jwkset() -> None:
    keys = [
        {
            "kty": "RSA",
            "n": "mUdmf5vJ3svsPSQ8BCOQVfwQdP8AmAEW21sYYUC5eSKR-pdwnRDBuFrIEjon2ry8cU-uaMjAoEZikPXcCTErye2Sj8fWQ8Wyo8DoGacJlFOJvs_18-CmNBc7oL8gBlYax3-feZZnaVIiJjvxQwUw5GQA6JTFnO8n2pnKMOOd8Gf6YrG-r0T6NXdviw0-2IW4f2UMJApqlu37yF8sgRNGZwDljNOkUtPK76Uz5T513Va4ckOqsVfnt4WoAkAkCl3eVBwGw3TJIbp_DaLUq53go0pXBCNxCHRD9mst69ZuknBLqn0SwKbQ9zJH9QvoqrEZ2q7GzkFzw70F6qH5MDEx2-dxQz_QccFV0XBpq4pkfuWzS8qKVO4QjyC7A0vIJUzrRHE2_moOtWvKTDsa7gfvK6kpnAW0iKnNchzBV0fzXWIIxRJ3_cc8Ue-KPRU9Wxm3heBOx_Qh-bKv9s9fVY9X6rimyX-pIwf-jkgWG8_FgTBuGkKTRcLi-XnwsCFIVNOtolmakbQHlin_lgDQm9s0nHoDJbZgAtzQfkIorclBJBzr2t__xgaZCfpSCLdwZFQvGEh1mK4WbSMMt5-L3zKsNLCBfdMbn2fS9n2hylfRwU_NZCY8f2RHAdP-z402Vq1c9-m2Ew3_695OmV5HoinJQPagY9hI-_EW8nhNWf8l4FE",
            "e": "AQAB",
            "d": "EGYw-3SrybxII3eBu1Chw-1Sxm20_s5ZB3GM33TZEzKFa0nyGL_e9g4yay7RLkg0oivsBVZ7M3qsV4WSe-JIpNNX862mCTy44ufD_WCfeADjEyj1T9kodxjIPqfMMZlbRp5rLctPd5d7w1r08l53D2x6o2etZ9-3hB4hoY7syjiZs58AP4jR-0_yvW4Wm_xck7a4MI_zvP-ryVGTdaDeDq2sIZ_QLDNwOikS7xM6cYqyc7k1JUG6Lyqr4cfCg2BtJdMUzysqzMLDDq6t8cmTq-zLeAwhrw2fatknQd0AmgbNNampjLacU2JMDBXw1_hYQ4shBpa-n8HUxPh87HDK_Gl4v7BZJHlzRQ73vkjHExcssZ3gkqEi90T4TNov-9uBXOtbVQCmut1IK6TnzBpaHepIqDovNmuzpc2gD3HFI78wdgHgzzV117lFgmLLIfg-mR9lj-qsJn-mdtKauXCXuZX24dBjGpknyBABx850px5nVQ2X9dWMFLxQomLhlxJAfhHQUsFlnpbw4StMDTz96zx9k_rgeNMTuj8VVTZ6DpOwhItYCvk41uIEbQTuehBRhOk7n6R8GELSizzLd6Yjw7FCxwWYavbnpx1sM9s3oOmxhQmm3BpcSRcochhPr14CA0SkTl1nQY3Z4Q_rIBTNtkDngrRBagjJGgtfN95cSIU",
            "kid": "uzPODAa44gSUXvSI6zilPwxMJCULUHm0FmXoqXRfYdI",
        },
        {
            "kty": "RSA",
            "n": "ycSaZ7HWpKCY4vfmoLWCxsg2KvpD-3dfFlz-2YsrfnMwpJF0nuRrceAxhFF34NlzwTn-JgVc8-lUrOJmcrBcxQNtr7eaJ0QhcRxu_Wre72QhqTddJgNt4V5Zn9P8l8CplSqiLruVI4nKGoiPFQ7mftGY39wxYiiFB6BMb04lAshvCuUOIP8WFFvCb5Afqpugl-NKpO2-C5vWeN_4xNkSO0fEq49Do01oUkMM5t1D4kvE6_BDVA2jxPHSSulXwcnwHmGuhXEfpVh-ME9MW0S0g7v-uNfpJmjVl7VDV87au6C9GKXHQ3NEXt8DWM8HXqRyRQ0XidJLymDOdUnF1_DMtS_wOCDrPFO-4rG_ZH3dwm-fBRSl_chu324OBi_ER6XIQpjkFiQo2pqbD8bI4X6kH8kUASq5gVsBU_hfQUZljSJoR2gQtorNw5EK4rlAQ5jS-ww16WiSna6jzgT_M4ZLr9IPCloe7isVxSk35-gD87xXtl8PzmE1vdpFC9aArkdFL_PK7MOqDvYIb6MRIOBvoxOV524tFKZhNrZUowTLH3a_-sWFLmdvd14iGxuv_DaC-hCmgI0eq7rzE2wUNP5IVmZASoI-3rKb22QdDlAPHNzdsyJCX4JVIPAJrpLOwptObN30404_C4UUD0IN9OXHD-16NaX5SY1thge94shJpTE",
            "e": "AQAB",
            "d": "1I1426RNKkDEztW477RHgIGKDtx2oYKveS-eii5CM4PFypgw8vJO_jff8jSgxQ5PE0-0nPkpYwp7WWVn54pDMIjcFDCnBJaRZEc_5VegYzBpBYp9Zn5WUwTCBc2cW4FrJOk00WZrRnTxo-IYWWbJCvBiy_F7VJy7B72mx9rawoPD9wY2TCxtZiUEP-LkeSZZl6iqCfUqL7CLz-qidzz2J90DInhaGL6DF6XrAYo26T5IxQTm6LU1wVO-5YvMFypU-qyM3aa-X8FJrjrbhYprYBu7y54oz33BBYC-4NHZO6-phT2fHT9g11C4heYTLXCvsG6KTXZswVYaKRT-hu31t0mgD8myErBQYcbityrKzdqKNdE9pBiaGMUngUMuaInLRbr2ihXeLSTzgQv6LrEOBxyDeyW43kPTzHtkFOoArOT_xpTjYobIYUTnFOer2rFpetG-B-yRMGSq5hMQ9067cBLfBoOAvJc9MrFTzM6ynPuTh2ZPRV7jZAR0cymtYb2CK_-6eKju2-bqQ0awjb9VkZolYgDccDZWJiM5TuiOBb-HRIdJSkI8KPGlWC-p14Eo3xeMFNjVJo_-lrT91IIaQC-WDSiRva3HZZGVjQPUiABji62wkC9QPD8VwLou044fnBqkiY7whAbDIGRQHpPiN5Co0_ZUEJdKFdVnncS74Q",
            "kid": "IYIB72QYGIUGP5lYlGmnrBeVOFOxTk9SO_5ajWBu1QE",
        },
    ]
    jwks = JwkSet(keys=keys)
    assert jwks.jwks == keys

    jwk = Jwk.generate_for_kty("EC", alg="ES256", kid="my_ec_key")
    keys.append(jwk.public_jwk())
    kid = jwks.add_jwk(jwk.public_jwk())
    assert kid == jwk.kid
    assert jwks.jwks == keys

    data = b"this is a test"
    signature = jwk.sign(data)

    assert jwks.verify(data, signature, kid="my_ec_key", alg="ES256")
    assert jwks.verify(data, signature, alg="ES256")
    assert jwks.verify(data, signature, algs=("ES256",))
    assert not jwks.verify(data, signature, algs=("HS256",))

    jwks.remove_jwk(jwk.kid)

    assert jwks.is_private

    assert not jwks.verify(data, signature, "ES256")
    assert not jwks.verify(data, signature, "ES256")

    assert jwks.public_jwks() == {
        "keys": [
            {
                "kty": "RSA",
                "n": "mUdmf5vJ3svsPSQ8BCOQVfwQdP8AmAEW21sYYUC5eSKR-pdwnRDBuFrIEjon2ry8cU-uaMjAoEZikPXcCTErye2Sj8fWQ8Wyo8DoGacJlFOJvs_18-CmNBc7oL8gBlYax3-feZZnaVIiJjvxQwUw5GQA6JTFnO8n2pnKMOOd8Gf6YrG-r0T6NXdviw0-2IW4f2UMJApqlu37yF8sgRNGZwDljNOkUtPK76Uz5T513Va4ckOqsVfnt4WoAkAkCl3eVBwGw3TJIbp_DaLUq53go0pXBCNxCHRD9mst69ZuknBLqn0SwKbQ9zJH9QvoqrEZ2q7GzkFzw70F6qH5MDEx2-dxQz_QccFV0XBpq4pkfuWzS8qKVO4QjyC7A0vIJUzrRHE2_moOtWvKTDsa7gfvK6kpnAW0iKnNchzBV0fzXWIIxRJ3_cc8Ue-KPRU9Wxm3heBOx_Qh-bKv9s9fVY9X6rimyX-pIwf-jkgWG8_FgTBuGkKTRcLi-XnwsCFIVNOtolmakbQHlin_lgDQm9s0nHoDJbZgAtzQfkIorclBJBzr2t__xgaZCfpSCLdwZFQvGEh1mK4WbSMMt5-L3zKsNLCBfdMbn2fS9n2hylfRwU_NZCY8f2RHAdP-z402Vq1c9-m2Ew3_695OmV5HoinJQPagY9hI-_EW8nhNWf8l4FE",
                "e": "AQAB",
                "kid": "uzPODAa44gSUXvSI6zilPwxMJCULUHm0FmXoqXRfYdI",
            },
            {
                "kty": "RSA",
                "n": "ycSaZ7HWpKCY4vfmoLWCxsg2KvpD-3dfFlz-2YsrfnMwpJF0nuRrceAxhFF34NlzwTn-JgVc8-lUrOJmcrBcxQNtr7eaJ0QhcRxu_Wre72QhqTddJgNt4V5Zn9P8l8CplSqiLruVI4nKGoiPFQ7mftGY39wxYiiFB6BMb04lAshvCuUOIP8WFFvCb5Afqpugl-NKpO2-C5vWeN_4xNkSO0fEq49Do01oUkMM5t1D4kvE6_BDVA2jxPHSSulXwcnwHmGuhXEfpVh-ME9MW0S0g7v-uNfpJmjVl7VDV87au6C9GKXHQ3NEXt8DWM8HXqRyRQ0XidJLymDOdUnF1_DMtS_wOCDrPFO-4rG_ZH3dwm-fBRSl_chu324OBi_ER6XIQpjkFiQo2pqbD8bI4X6kH8kUASq5gVsBU_hfQUZljSJoR2gQtorNw5EK4rlAQ5jS-ww16WiSna6jzgT_M4ZLr9IPCloe7isVxSk35-gD87xXtl8PzmE1vdpFC9aArkdFL_PK7MOqDvYIb6MRIOBvoxOV524tFKZhNrZUowTLH3a_-sWFLmdvd14iGxuv_DaC-hCmgI0eq7rzE2wUNP5IVmZASoI-3rKb22QdDlAPHNzdsyJCX4JVIPAJrpLOwptObN30404_C4UUD0IN9OXHD-16NaX5SY1thge94shJpTE",
                "e": "AQAB",
                "kid": "IYIB72QYGIUGP5lYlGmnrBeVOFOxTk9SO_5ajWBu1QE",
            },
        ]
    }

    jwks.remove_jwk("foo")  # this is a no op since there is not key 'foo'


def test_empty_jwkset() -> None:
    jwks = JwkSet()
    assert len(jwks) == 0

    generated_jwk = Jwk.generate_for_kty("RSA")

    kid = jwks.add_jwk(generated_jwk)
    jwk = jwks.get_jwk_by_kid(kid)
    assert jwk.pop("kid") == jwk.thumbprint()
    assert jwk == generated_jwk

    with pytest.raises(KeyError):
        jwks.get_jwk_by_kid("foo")


def test_public_jwkset() -> None:
    jwks = JwkSet(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "n": "iA7fKKnBz724Yqhe6ejEckSpqPCW0O1_3hUcW9GFC8OVgwWIG6Z6gwjLJFJPHQ7D-JT_Bc7UJ_3iBpUmEO_600SQu9jg8fVcf-OlDRvnMRuXMKYyyjWn50mfMZH9eHTBuw4h96rdIVm9N8ml0VsouJc59O7PjLi93HvzpV1PQM0m6it7oHfVPX_Gdm6cg6qWcc6yQ1jdW-YzkOp_nRCy81cVAvp_tKapaiXGIrpWipgBDObXSDeQ5qbArvL0P8N176g4Hia1WtpJoe7H1b_Km2e-gkl8UZVGN5-vSKryh1CKifD6uwLEvoHlHUvWdIqsSx7dPLchz07S81Qp2YpexulnfdA2VoZsH9AKrRtkf1_a3OSx0wFDxfOoRyTQblC1MZ8Dvf6PQ_stsc0-zBOjHa4jdunjneMUOuJmw3jaUl7MFAjcBS951mSqWoNUSOL8QgDEj3-jDghFGZmHZkjXfoflAmjbCUH6mRSTKgu9LzeKEWeKc9lSjwDRo9BNzq0X2qEzEqVexd96wJ7FkZ_zjyDWJlIElMy81fDcaX2Lh0AS0VOPDlAm6D5Py931V6jylI-Uz-3rQHuWiWUjZWp9ZB1OlYDC-nNFdJPqPxDQIgrODAvYMphK_R1NObdXjbwhr8qxZNRNXmqGB4FH-v6CGeNLOTB5FgmfndzX3utjk40",
                    "e": "AQAB",
                    "kid": "7KJgpwNvHJp_zb6SybahlC7506kvAm2cvMG_EY6jmx8",
                },
                {
                    "kty": "EC",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "Y3oM13zJ47UkSxuYRFP86cknI-JjMc9Nz39SA6R5EjQ",
                    "y": "pvA66-cfoNxK4TMTo3Wq-o7npJe5yRow9FPdP8N1s5Y",
                    "kid": "ojHE_6b7DXtOwLKYTmeao38CV_7P9F9rYTLGm8BuJnk",
                },
                {
                    "kty": "RSA",
                    "alg": "PS256",
                    "n": "rhvS1HWLDPKP2_I4a1_RhLwnRjVDT_0tGDScPO67fBH7ImzkK_BrDnBzY2Fsz9VozWrCh0G_SnAKimmIGcfLI-AL2lFX2413y28jfHf5uGGKSXnaYu1lUtX51MlvbbQnhEtsVkJUcBEFZgzl4EztZ1YeXGuY0gbeqBUOmudWA5yBHvB_wkMg4vNX4H6Aa7jRdfVA1xUM43BHl6zIXpjsxAlfmjCd7Ifh9gOxj5skDd1rYLBcQsaF2Qmh_KWYrWagQH_WN0JDF9vSBRK5nNSfyHSAv72WhL4p_2Jz1fkYUsIOcoaoP3JTjZYYH4ht2QpqjfYXB50rJlUwX-DQ7-SyclXJwf571gspv9aJ4ahnux1g-26ByXyasBGzrJfhbOUGN2QC7O1OWk903vV6VtqYZjxLuW5pi7GFTB1psROtgBCdX-2sXjAr_Up4DFwNWc4AwQqfuuXAIjc9NS7x66ar1Dsj32YsiowfwB-raLZYm4H8A1AuN7zOX6A0JosVENuJT9e7Fl3wermpIWx4QRN76WOLYba_8uyTP0-R2kmgoxI2Xzt1RqtRXnwqD6_dqnMRdyx2zSnBFU3y5ICtWqOCjM9bm2Orym3ZfPpBbpZkkMLXYik7oae0kpA6yJf3FMQSTY_-66sPWgeT9jgpwC_qFxDrBEy9hOCO5VJ6NUkmdnk",
                    "e": "AQAB",
                    "kid": "m7XoZRBgXXjEFxGhWvb_urskl4rCLmOhhPRdC6278-E",
                },
                {
                    "kty": "EC",
                    "alg": "ECDH-ES",
                    "crv": "P-256",
                    "x": "m98Qjjc1OlN1dVD0q7yetQfOVl0iHtcqHZpJ0ZeOkZQ",
                    "y": "g3PoI3YykxNj4H4Ffc8NF8Sf4MYXIkZzMN2wFBfD0fc",
                    "kid": "xAgzqjWdBD8cRifXbpmcv-9vIgjKHTdjelI-Vvu0K9Q",
                },
                {
                    "kty": "RSA",
                    "alg": "RSA-OAEP-256",
                    "n": "tGeChePEEOjo3j9SL15OjqL67w_SBaN4H5LxhXFMEcnIoAVpuGGwu18NuN2oRPabsuvJ3yDg0v4WZck5keftfs5cgal8P9J_MB8greSErmLRTDRmSqFlysEJaGuFABbbUXZZk1bO_Ea-dSKJgeNUEpJf4n_JiTtxEFgB8fTeh1RWsESOqB7tYaQNaSy4Ckt_0TF3000BL92SsvepFIyTKoL77ZnRxbAd0WQ-H7flIKbuyex_5JuTZ4amI2xJE-TThEU_KN-yVbLDWaIhUAEE-51bC2DtceyuWSBO4QmToLG9oefaF49VdxaKMWeUnrfJ9pfM2AM12S8G6k_fQPpyFflXrBlRvWEC769RECucBRDzkgBnLGQPeUKwsKfvjiQC-Eat_WFE5t3D7OiZISDEBjrW728PGMEKcHzQq1ut5Eu7BOpC95emJgattURmGSSI5988_6vebsD37iRdBlqQrcYAq7SUI9-aaPL0CEDCWZ_vC0Rnxx0BRHM32JwVb-Ac0gJcTo6WaL1NKzp1CdixXBXdVBFEyB1pGDfi9-bAcM1YMTLylmmkxUagSHVvQnPqbO2djwI2koFH305Oa5ABAlgenpNb8BSGnRC0h5yzaKn0D8e_JgNv--JIhGTOeMmIG69CMQwONdzEuhCy4wGBChhjEQaiI_pTKhah0U5hIHM",
                    "e": "AQAB",
                    "kid": "zjY2pjFnBc4rOHWEwfS5Cjyxsjo2aprsctM-4oS1r8I",
                },
            ]
        }
    )
    assert not jwks.is_private
    sig_keys = jwks.verification_keys()
    enc_keys = jwks.encryption_keys()

    sig_kids = set(jwk.kid for jwk in sig_keys)
    assert sig_kids == set(
        (
            "7KJgpwNvHJp_zb6SybahlC7506kvAm2cvMG_EY6jmx8",
            "ojHE_6b7DXtOwLKYTmeao38CV_7P9F9rYTLGm8BuJnk",
            "m7XoZRBgXXjEFxGhWvb_urskl4rCLmOhhPRdC6278-E",
        )
    )

    enc_kids = set(jwk.kid for jwk in enc_keys)
    assert enc_kids == set(
        (
            "xAgzqjWdBD8cRifXbpmcv-9vIgjKHTdjelI-Vvu0K9Q",
            "zjY2pjFnBc4rOHWEwfS5Cjyxsjo2aprsctM-4oS1r8I",
        )
    )
