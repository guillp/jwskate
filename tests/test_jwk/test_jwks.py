import pytest

from jwskate import Jwk, JwkSet


def test_jwkset() -> None:
    keys = [Jwk.generate_for_kty("RSA"), Jwk.generate_for_kty("RSA")]
    jwks = JwkSet(keys=keys)
    assert jwks.jwks == keys

    jwk = Jwk.generate_for_kty("EC", crv="P-256")
    keys.append(jwk)
    kid = jwks.add_jwk(jwk)
    assert kid == jwk.kid
    assert jwks.jwks == keys

    data = b"this is a test"
    signature = jwk.sign(data, "ES256")

    assert jwks.verify(data, signature, "ES256")

    jwks.remove_jwk(jwk.kid)

    jwks.remove_jwk("foo")

    assert jwks.is_private

    assert not jwks.verify(data, signature, "ES256")


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
