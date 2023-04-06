# Usage

To use `jwskate` in a project, you can import all exposed objects from the root module:

```
from jwskate import *
```

# Cheat Sheet

## Generating new keys

| Usage                    | Method                    |
|--------------------------|---------------------------|
| For a specific algorithm | Jwk.generate(alg='ES256') |
| For a specific key type  | Jwk.generate(kty='RSA')   |

## Loading keys

| From                           | Method                                                                                                                                                                               |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| A JWK in Python dict           | `jwk = Jwk({'kty': 'RSA', 'n': '...', ...})`                                                                                                                                         |
| A JWK in JSON formatted string | `jwk = Jwk('{"kty": "RSA", "n": "...", ...}')`                                                                                                                                       |
| A `cryptography` key           | `jwk = Jwk(cryptography_key, password='mypassword')`                                                                                                                                  |
| A PEM formatted string         | `jwk = Jwk.from_pem(<br/>'''-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp0VYc2zc/6yNzQUSFprv<br/> ... 3QIDAQAB<br/>-----END PUBLIC KEY----- '''<br/>)` |

## Saving keys

From an instance of a `Jwk` named `jwk`:

| To                             | Method                              | Note                             |
|--------------------------------|-------------------------------------|----------------------------------|
| A JWK in Python dict           | `jwk` # Jwk is a dict subclass      | you may also do `dict(jwk)`      |
| A JWK in JSON formatted string | `jwk.to_json()`                     |                                  |
| A cryptography key             | `jwk.cryptography_key`              |                                  |
| A PEM formatted string         | `jwk.to_pem(password="mypassword")` | password is optional             |
| A symmetric key, as bytes      | `jwk.key`                           | only works with kty=oct          |
| A JWKS                         | `jwk.as_jwks()`                     | will contain `jwk` as single key |

## Inspecting keys

| Usage                     | Method                                                                                                                  | Returns                                                                                             |
|---------------------------|-------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| Check privateness         | jwk.is_private()                                                                                                        | `bool`                                                                                              |
| Check symmetricness       | jwk.is_symmetric()                                                                                                      | `bool`                                                                                              |
| Get Key Type              | jwk.kty                                                                                                                 | key type, as `str`                                                                                  |
| Get Alg (if present)      | jwk.alg                                                                                                                 | intended algorithm identifier, as `str`                                                             |
| Get Use                   | jwk.use                                                                                                                 | intended key use, if present, or deduced from `alg`                                                 |
| Get Key Ops               | jwk.key_ops                                                                                                             | intended key operations, if present,<br>or deduced from `use`, `kty`, privateness and symmetricness |
| Get attributes            | jwk\['attribute'\]<br>jwk.attribute                                                                                      | attribute value                                                                                     |
| Get thumbprint            | jwk.thumbprint()<br>jwk.thumbprint_uri()                                                                                | Computed thumbprint or thumbprint URI                                                               |
| Get supported algorithms  | jwk.supported_signing_algorithms()<br>jwk.supported_key_management_algorithms()<br>jwk.supported_encryption_algorithms() | List of supported algorithms identifiers, as `str`.                                                 |

# JWK

## Loading keys

The `Jwk` class and its subclasses represent keys in JWK format. You can initialize a Jwk from:

- a dict representing the JWK content, already parsed from JSON:

```python
from jwskate import Jwk

jwk = Jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
        "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
        "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
    }
)
```

- a string containing a JSON representation of the JWK:

```python
from jwskate import Jwk

jwk = Jwk(
    '{"kty": "EC", "crv": "P-256",'
    'x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",'
    'y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",'
    'd": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8"}'
)
```

- a `cryptography` key:

```python
from jwskate import Jwk
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1)
jwk = Jwk(key)
```

- a public or private key in PEM format, optionally protected by a password:

```python
from jwskate import Jwk

public_jwk = Jwk.from_pem(
    b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjtGIk8SxD+OEiBpP2/T
JUAF0upwuKGMk6wH8Rwov88VvzJrVm2NCticTk5FUg+UG5r8JArrV4tJPRHQyvqK
wF4NiksuvOjv3HyIf4oaOhZjT8hDne1Bfv+cFqZJ61Gk0MjANh/T5q9vxER/7TdU
NHKpoRV+NVlKN5bEU/NQ5FQjVXicfswxh6Y6fl2PIFqT2CfjD+FkBPU1iT9qyJYH
A38IRvwNtcitFgCeZwdGPoxiPPh1WHY8VxpUVBv/2JsUtrB/rAIbGqZoxAIWvijJ
Pe9o1TY3VlOzk9ASZ1AeatvOir+iDVJ5OpKmLnzc46QgGPUsjIyo6Sje9dxpGtoG
QQIDAQAB
-----END PUBLIC KEY-----"""
)

private_jwk = Jwk.from_pem(
    b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAywYF71cKSo3xyi7/0S7N1blFCmBX4eZz0gXf+zyBfomuqhwr
....
daBAqhoDEr4SoKju8pagw6lqm65XeARyWkxqFqAZbb2K3bWY3x9qZT6oubLrCDGD
-----END RSA PRIVATE KEY-----""",
    "P@ssw0rd",
)
```

## Getting key parameters

Once you have a `Jwk` instance, you can get its parameters either with subscription or attribute access:

```python
from jwskate import Jwk

jwk = Jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
        "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
        "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
    }
)
assert jwk.kty == "EC"
assert jwk.crv == "P-256"
assert jwk.x == "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI"
assert jwk["x"] == jwk.x
```

Those will return the exact (usually base64url-encoded) value exactly as expressed in the JWK. You can also get the
real, decoded parameters with some special attributes:

```python
from jwskate import Jwk

jwk = Jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
        "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
        "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
    }
)
assert (
    jwk.x_coordinate
    == 41091394722340406951651919287101979028566994134304719828008599584440827098914
)
assert (
    jwk.y_coordinate
    == 5099336126642036233987555101153084413345413137896124327269101893088581300336
)
assert (
    jwk.ecc_private_key
    == 8342345011805978907621665437908035545366143771247820774310445528411160853919
)
```

The available special attributes vary depending on the key type.

## Generating keys

`jwskate` can generate private keys from any of it supported key types. To generate a key, use `Jwk.generate()`. It just
needs some hints to know what kind of key to generate, either an identifier for the algorithm that will be used with
that key (`alg`), or a key type (`kty`). An `alg` is preferred, since it gives more hints, like the Elliptic Curve to
use, or the key size to generate. The specified `alg` will be part of the generated key, and will avoid having to
specify the alg for every cryptographic operation you will perform with that key.

```python
from jwskate import Jwk

# specifying an alg:
rsa_jwk_RS256 = Jwk.generate(alg="RS256")
# 'kty': 'RSA', 'n': '0o-yPaR-e7yr3l3pA7CFwGpHu3QSGhEK50w_qeK0UGD2hmqNCRxD5cAYJ1JKltgcsmSQ4b94_DPdJjRaNdyJbX15cF25tVtoPRW6g5_kgiIpTzrDFcVTY0CJ0DHztnkG9IitC-xBRJSgJd2SPyL9j1bSfdWPjvaq1Z8LhxjUauUNaQmIkVw_ji-eGksClF-3Nv9l3s3V7sCbHaVLL6pQ1KV2SXW327xACHp5wbwtEociBRQWNMGoNpQz0k1dhTsfQTz2xOwKn-iETTySZSNnP6cvOjwlz2t5KjZNns3CBYKWw9z0AqLJ_99_y14q3krxpauuOQ_uh3Y_qPNSaFoUfjp5NuvAlVuptW3dzgf86Svb8KF7mmx0oC328FY_VCusUuKuis-lgX_P-_f-wTXEiXQkHjaekNDd8YFyssDu6NKWH8IfKR53NCtShLslNvifkQxIUOP6gVrMCvTr4oOAYQsw2K3C92CNfmavYsLtej0A-j7La-NeHuYX9UoWQimSefChw0LZ4unVahMqb6nb7C3_FVv7nLJzupahpmERTKDqv09Kw060KvMKv-OSd8sK_Zzfv5emjZmNaZTVBCAu5OVZBOVRKmzEPT9K0g-63DdLOlNmS_4Ns6qCzrFdc9Fy6HiJB60xOpZ-EBU7Ft_rr5YmtTrAW_oguHiN-hku0Vk', 'e': 'AQAB', 'd': 'INc-t_SRsbTsothyK8bQJaxYlyPJtafA0_CFjCFgJEVAo223pPBz-pU_xH-bmJ6zuHM3pwNugvoyh5nqFAqF-L4gPxFZ51pkDgWh5ej-AqSssr8khvRpnB-zHvYbip33zWi1LMM4LtJ2OVGvVLTyvUo6YbFPHGoxR55FywK-vBQQ8mKv7-lmaZktsfDPFzCSlTu3uiIlOCwcRWnEKfazeBHSkC88ckOQl9dFFEgdnjfWFjAFgqGjHdgho68ODhCkQFBE4NPmmFLzXPnnOhUP2SgMlVWk7rlW2D7zU6Md8YQRBb15kCEEcSnSdyKvJvqjaUaMpuPAPVUzz_hw0EvJyYSLYQMtI5gLhVZzKeTV_dsfB7QPJR9Q03lktwZOLzLqoRucC9nTiT_g7gsBUMBi6LRD34Krd_YGp4A24tynzMlD8KATO1oU4QSdVvxPGticKGUntEJcUAkq00aMKv9zrb1WBUDIIccf6UKbjj2tj3r9hUASg1xHrlZmIhXK9xe3FeNP34dp_5ACLfl9JQzorzoNsaNgf0swD2ww_-wSsUbxfpow1RYtfS9aKpbJGADx-gyGReRU8YVie3SJ1yfur90EvIbq4eIVdMFklQGbbMnR291DZNJM0e_RNzOSMj574rNaq_7Tq5uMNaoFfAc2rKZDdL-Ze9e6YD7UO10WpB0', 'p': '5MC2kUwy3I4hyQwk4ikh201IZEw_onOktcQAT3QSl6R_zlUMb8j9lR1-_7R5xNeQsUaN3gXuEzlAbuTAS7EgF_WcvEsYyi_Eqn2B_o2QAUUJXEtNqyeC5Q2bGLXM5Yl0nqaMOpI5lsoAK4CfTe0L6B3AeriFhlTPI-LY8_PrtbeSf06NHuJ2_1XqZVE-tQiDlKu29zWntOJ8L-0f9ABA1q6ixSX4hCa3QyE3_4hGgxH8pskQ8GSfUJ05KBu_bjlTghCvqGfoBQAxJSZJtmK71RNZ9zznDiwhJA0tGr1iZuAlsv3k_HRPbSuxPO1-XNWmyL9-66d05h7evurmLWnX3w', 'q': '66RGuDf9nqDBb1PNQy7EDldwDYdIU-1TzjcEjfBktI0powazWPS9d8DsnxRuL0IdEmS4QyZoNx7UnUjr7si4yDuzYkwo6DRsjWMkTjnSbzwd-2d55kU68qmloWc5t1fTWGslEVbDGX05bak2JfCqW87sycxfAFHANTwnIfTEbrVFiNb8FnRBA5dRGp-dyH6nSMzV5-V0d-CjJnil_TNwx6cOVJQgT40gJl-15jwpiHBGmTKUghHwspxVrrwH6sGr-eMfF2AaJplXbJCu1G_q494XGLwJvV_q6uTSTC6aU-eKlOwRJYFgSmkbHAuxdLfAmYHzjgMvoLQjE4tdJwRdxw', 'dp': 'DKx8sPomyz94sbnhhUJAJPVYMG5lDCwaERQF7GEC8rHjftwJb1wUaKGUurgWEwjadGfzTjzH3vrKDhrQaKEspQcvouMKQZF59PQ1MpRHSTq49QsbB4ON5gDl-e2Ap6sA8hVKKaiWVjtk3QQoT1n10etsEaCNjU6_lz5nRMTb51p_XFxOx0pGy4jIDsr8jW0mVSNaZMHtQ8FUnhcmMQ-eiAZu8DtVVIUMnESH5Ll5JqPlepwjOx5oEUBUvVskNQgqD0e7Y7o2CajkECnZ5af8viZvUppmNsvNHkE4oYWioQ6EKDGW8UHEcMj97eE-oggYUIEDmCzT9jf5oVxEWnnFww', 'dq': 'YSmgm29C3Xitqgjk91G-N6eoJXvlv-15A-u9rgU0kRov0-_8Xa60vT9IkiOrd0MMl7v-GnoouKm2w5AA8LnFL5MmWV7L80tCg14g5zyCX6lrN3GoWuGq98op6I6Wxtmo5KlxZF_hHI588pG2KRi-NhLxohfqCEitN4YxIJg7suZ94Hm9Akk3UZLAN3kfZz-KHMORZAhB6PgwbbmLwAbI9xoUF53oYMTxP8FxUJj4CzE4ewzXHXbmR8-cqOsRXKQ1FFmpRUs0HTxXRwW1gRUQxpqZ7XIDlhmJ1Qc7C3yf1_7-Ln_UZiGdobELI5pStqzZ9rIVyjXYGqyMVg-9_kuXmw', 'qi': 'HpqAlt1xp_to2iVqIfXh-CulsUgLupespF1lKdpzqLkApD1JVjxXm3dItI6wGewMgABdpE6WoiTqE-gyuMlgws-1vO6RnNpeT43p3pJfzKWaaC3v4agk1_xR6BZag2-dHPNBYED0nidS9HCZH7VsxbhIZ71vio7MGJbRJieDcF0Xpn5bZ5XBhbXvgo7tIySsIZ8U7DGs3PnDkDujJY1_11YMtUPW_zJmE1OJvoE3mroBoRwF2pjASmk3_WMmAyko79LoUCPWn-HI4dtjMV5YuUJ7S1OHrR7QoAWHThSCmc_Br5XHvMllcDjcvppFGfTNRNaADZ-eeygyA-Gxe6Hahg', 'alg': 'RS256'}
ec_jwk_ES512 = Jwk.generate(alg="ES256")
# {'kty': 'EC', 'crv': 'P-256', 'x': 'vYXg2w4d7qzhFl2BOleEfXTiUGjar9XZdNzL6WtQapA', 'y': 'QGfFxR3rOCPM4PXM6GgwwcEYHm42S-SYYRCWvbMIyko', 'd': '1E3PnLV9zAGbV8axbNm3kVykE-xhJbueYkIVcLC4t_g', 'alg': 'ES256'}
oct_jwk_HS256 = Jwk.generate(alg="HS256")
# {'kty': 'oct', 'k': 'EM4Yf0JLy5a6MoF0PIVhE51R4i-sPGXfiBg7Gyd7YzA', 'alg': 'HS256'}

# a few examples without specifying an alg, but passing a key type instead:
rsa_jwk = Jwk.generate(kty="RSA")
oct_jwk = Jwk.generate(kty="oct")

# you may combine both if needed:
rsa_jwk = Jwk.generate(kty="RSA", alg="RS256")
# alg takes precedence if it is inconsistent with kty:
rsa_jwk = Jwk.generate(kty="EC", alg="RS256")
```

You can include additional parameters such as "use" or "key_ops", or custom parameters which will be included in the
generated key:

```python
from jwskate import Jwk

jwk = Jwk.generate(alg="ES256", use="sig", custom_param="custom_value")

assert jwk.use == "sig"
assert jwk.custom_param == "custom_value"
```

For keys with a variable key size (such as RSA or oct), you may specify the key size:

```python
from jwskate import Jwk

jwk = Jwk.generate(kty="oct", key_size=512)
```

`jwskate` will warn you if the key size you specify is insufficient for the alg you are trying to use, or will raise an
exception if it is not the mandatory key size for the alg:

```python
from jwskate import Jwk

Jwk.generate(alg="HS256", key_size=40)
# UserWarning: Symmetric keys to use with HS256 should be at least 256 bits in order to make the key at least as hard to brute-force as the signature. You requested a key size of 40 bits.

Jwk.generate(alg="A128KW", key_size=40)
# ValueError: Key for A128KW must be exactly 128 bits. You should remove the `key_size` parameter to generate a key of the appropriate length.
```

Note that keys generated by jwskate are always private. You can get the matching public key as described below.

## Private and Public Keys

You can check if a key is public or private with the `is_private` property:

```python
from jwskate import Jwk

private_jwk = Jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
        "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
        "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
    }
)
assert private_jwk.is_private
```

You can get the public key that match a given private key with the `public_jwk()` method. It returns a new `Jwk`
instance that does not contain the private parameters:

```python
from jwskate import Jwk

private_jwk = Jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
        "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
        "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
    }
)
public_jwk = private_jwk.public_jwk()
assert "d" not in public_jwk  # "d" would contain the private key
assert not public_jwk.is_private
```

Note that Symmetric keys are always considered private, so calling `.public_jwk()` will raise a `ValueError`. You can
know if a key is symmetric with `.is_symmetric`:

```python
from jwskate import Jwk

jwk = Jwk.generate(kty="oct", key_size=128)
assert jwk.is_symmetric
assert jwk.is_private
```

## Dumping keys

### to JSON

`Jwk` instances are dicts, so you can serialize it to JSON in the usual ways (with Python `json` module or any other
means). You can also use the `to_json()` convenience method to serialize a `Jwk`:

```python
from jwskate import Jwk

jwk = Jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
        "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
        "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
    }
)
jwk.to_json()
# '{"kty": "EC", "crv": "P-256", "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI", "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA", "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8"}'
```

### to `cryptography` keys

You can access the `cryptography_key` attribute to get a `cryptography` key instance that matches a `Jwk`:

```python
from jwskate import Jwk

jwk = Jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "WtjnvHG9b_IKBLn4QYTHz-AdoAiO_ork5LH1BL_5tyI",
        "y": "C0YfOUDuCOvTCt7hAqO-f9z8_JdOnOPbfYmUk-RosHA",
        "d": "EnGZlkoa4VUsnl72LcRRychNJ2FFknm_ph855tNuPZ8",
    }
)
cryptography_key = jwk.cryptography_key
assert (
    str(cryptography_key.__class__)
    == "<class 'cryptography.hazmat.backends.openssl.ec._EllipticCurvePrivateKey'>"
)
```

## Signing and verifying data

You can sign arbitrary data, then validate the signature with a `Jwk` instance, using the `sign()` and `verify()`
methods:

```python
from jwskate import Jwk

data = b"Signing is easy!"
jwk = Jwk.generate_for_kty("EC", crv="P-256")

signature = jwk.sign(data, alg="ES256")
assert jwk.verify(data, signature, alg="ES256")
assert not jwk.verify(
    data,
    b"this_is_a_wrong_signature_value_12345678012345678012345678012345",
    alg="ES256",
)
```

## Encrypting and Decrypting data

Encryption or decryption require a symmetric key, which translates to an instance of `SymmetricJwk`, with `kty='oct'`.
You can encrypt and decrypt arbitrary data with a Jwk instance, using the `encrypt()` and `decrypt()` methods:

```python
from jwskate import Jwk

data = b"Encryption is easy!"
alg = "A256GCM"
jwk = Jwk.generate_for_kty("oct", key_size=256, alg=alg)

ciphertext, iv, tag = jwk.encrypt(data)

assert jwk.decrypt(ciphertext, iv=iv, tag=tag) == data
```

### Authenticated encryption

You can include Additional Authenticated Data (`aad`) in the `encrypt()` and `decrypt()` operations:

```python
from jwskate import Jwk

data = b"Authenticated Encryption is easy!"
alg = "A256GCM"
aad = b"This is my auth tag"
jwk = Jwk.generate_for_kty("oct", key_size=256, alg=alg)

ciphertext, iv, tag = jwk.encrypt(data, aad=aad)

assert jwk.decrypt(ciphertext, iv=iv, tag=tag, aad=aad) == data
```

## Key Management

Encrypting/decrypting arbitrary data is never done using asymmetric keys. But it is possible to use Key Management
algorithms with asymmetric keys to encrypt/decrypt or otherwise derive symmetric keys, which in turn can be used for
encryption/decryption using symmetric encryption algorithms.

Some of those Key Management algorithms rely on key wrapping, where a randomly-generated symmetric key (called a Content
Encryption Key or CEK) is itself encrypted with an asymmetric algorithm. Other algorithms rely on Diffie-Hellman, where
the CEK is derived from a pair of keys: one public and the other private. Sender will use a generated private key and
the recipient public key, while the recipient will use its private key and the sender public key. On both sides, the
resulting CEK will be the same. It is also possible to use a symmetric key to encrypt the CEK with a symmetric
algorithm, which is mostly used when the recipient is the same as the sender.

`jwskate` provides methods that make Key Management very easy. If you are the message sender, you must obtain the
recipient public key, as a `Jwk` instance. You can then use the `sender_key()` method on that instance to generate an
appropriate CEK. It needs the target encryption algorithm as parameter, and optionally the key management algorithm, if
it is not specified in the recipient public key. It will return a tuple
`(plaintext_message, encrypted_cek, extra_headers)`, with `plaintext_message` being the generated CEK (as an instance of
`SymmetricJwk`), `encrypted_cek` is the wrapped CEK value (which can be empty for Diffie-Hellman based algorithms), and
`extra_headers` a dict of extra headers that are required for the key management algorithm (for example, `epk` for
ECDH-ES based algorithms),

You can use `cleartext_cek` to encrypt your message with a given Encryption algorithm. You must then send
`encrypted_cek` and `extra_headers` to your recipient, along with the encrypted message, and both Key Management and
Encryption algorithms identifiers.

```python
from jwskate import Jwk

plaintext_message = b"Key Management and Encryption are easy!"
rcpt_private_jwk = Jwk.generate(alg="ECDH-ES", crv="P-256")
# {'kty': 'EC',
# 'crv': 'P-256',
# 'alg': 'ECDH-ES',
# 'x': '10QvcmuPmErnHHnrnQ7kVV-Mm_jA4QUG5W9t81jAVyE',
# 'y': 'Vk3Y4_qH09pm8rCLl_htf321fK62qbz6jxLlk0Y3Qe4',
# 'd': 'Y4vvC9He6beJi3lKYdVgvvUS9zUWz_YnV0xKT90-Z5E'}

rcpt_public_jwk = rcpt_private_jwk.public_jwk()
# {'kty': 'EC',
# 'crv': 'P-256',
# 'x': '10QvcmuPmErnHHnrnQ7kVV-Mm_jA4QUG5W9t81jAVyE',
# 'y': 'Vk3Y4_qH09pm8rCLl_htf321fK62qbz6jxLlk0Y3Qe4'}

enc_alg = "A256GCM"
km_alg = "ECDH-ES"
plaintext_cek, encrypted_cek, extra_headers = rcpt_public_jwk.sender_key(enc_alg)
# plaintext_cek: {'kty': 'oct', 'k': 'iUa0WAadkir02DrdapFGzPI-9q9xqP-JaU4M69euMvc'}
# encrypted_cek: b''
# extra_headers: {'epk': {'kty': 'EC',
#  'crv': 'P-256',
#  'x': '_26Ak6hccBPzFe2t2CYwFMH8jkKm-UWajOrci9KIPfg',
#  'y': 'nVXtV6YcU1IsT8qL9zAbvMrvXvhdEvMoeVfDeF-bsRs'}}

encrypted_message, iv, tag = plaintext_cek.encrypt(plaintext_message, alg=enc_alg)
# encrypted_message: b'\xb5J\x16\x08\x82Xp\x0f,\x0eu\xe5\xd6\xa6y\xe0J\xae\xcbu\xf8B\xbd'
# iv: b'K"H\xf3@\tt\\\xc78\xc2D'
# tag: b'\xc4\xee\xcf`\xfa\\\x8e\x9dn\xc4>D\xd8\x1d\x8c\x1a'
```

On recipient side, in order to decrypt the message, you will need to obtain the same symmetric CEK that was used to
encrypt the message. That is done with `recipient_key()` on the recipient private key. You need to provide it with the
`encrypted_cek` received from the sender (possibly empty for Diffie-Hellman based algorithms), the Key Management
algorithm that is used to wrap the CEK, the Encryption algorithm that is used to encrypt/decrypt the message, and the
eventual extra headers depending on the Key Management algorithm.

You can then use that CEK to decrypt the received message.

```python
from jwskate import Jwk

# reusing the variables from above
enc_alg = "A256GCM"
km_alg = "ECDH-ES"
plaintext_cek = {"kty": "oct", "k": "iUa0WAadkir02DrdapFGzPI-9q9xqP-JaU4M69euMvc"}
encrypted_cek = b""
extra_headers = {
    "epk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "_26Ak6hccBPzFe2t2CYwFMH8jkKm-UWajOrci9KIPfg",
        "y": "nVXtV6YcU1IsT8qL9zAbvMrvXvhdEvMoeVfDeF-bsRs",
    }
}
recipient_private_jwk = Jwk(
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "10QvcmuPmErnHHnrnQ7kVV-Mm_jA4QUG5W9t81jAVyE",
        "y": "Vk3Y4_qH09pm8rCLl_htf321fK62qbz6jxLlk0Y3Qe4",
        "d": "Y4vvC9He6beJi3lKYdVgvvUS9zUWz_YnV0xKT90-Z5E",
    }
)

encrypted_message = b"\xb5J\x16\x08\x82Xp\x0f,\x0eu\xe5\xd6\xa6y\xe0J\xae\xcbu\xf8B\xbd"
iv = b'K"H\xf3@\tt\\\xc78\xc2D'
tag = b"\xc4\xee\xcf`\xfa\\\x8e\x9dn\xc4>D\xd8\x1d\x8c\x1a"

# obtain the same CEK as the sender, based on our private key, and public data provided by sender
cek = recipient_private_jwk.recipient_key(
    encrypted_cek, enc="A256GCM", alg="ECDH-ES", **extra_headers
)
# and decrypt the message with that CEK (and the IV, Auth Tag and encryption alg identifier provided by sender)
plaintext_message = cek.decrypt(encrypted_message, iv=iv, tag=tag, alg=enc_alg)

assert plaintext_message == b"Key Management and Encryption are easy!"
```

# JWS

The `JwsCompact` class represents a syntactically valid JWS token in compact representation.

## Parsing tokens

To parse an existing Jws token and access its content (without validating the signature yet), you simply need to create
an instance of `JwsCompact` with the serialized token as value:

```python
from jwskate import JwsCompact

jws = JwsCompact(
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXSy1BQkNEIn0."
    "SGVsbG8gV29ybGQh."
    "1eucS9ZaTnAJyfVNhxLJ_phFN1rexm0l-nIXWBjUImdS29z55BuxH6NjGpltSXKrgYxYQxqGCs"
    "GIxlSVoIEhKVdhE1Vd9NPJRyw7I4zBRdwVvcqMRODMqDxCiqbDQ_5bI5jAqFEJAFCXZo2T4ixl"
    "xs-2eXtmSEp6vX51Tg1pvicM5_YrKfS8Jn3lt9xW5RaNKUJ94KVLlov_IncFsh2bg5jdo1SEoU"
    "xlB2II0JdlfCsgHohJd58eWjFToeNtH1eiXGeZOHblMLz5a5AhY8jY3C424-tggj6BK6fwpedd"
    "dFD3mtFFTNw6KT-2EgTeOlEA09pQqW5hosCj2duAlR-FQQ"
)

jws.payload
# b'Hello World!'
jws.headers
# {'alg': 'RS256', 'kid': 'JWK-ABCD'}
jws.alg
# 'RS256'
jws.kid
# 'JWK-ABCD'
jws.signature
# '\xd5\xeb\x9cK\xd6ZNp\t\xc9\xf5M\x87\x12\xc9\xfe\x98E7Z\xde\xc6m%\xfar\x17X\x18\xd4"gR\xdb\xdc\xf9\xe4\x1b\xb1\x1f\xa3c\x1a\x99mIr\xab\x81\x8cXC\x1a\x86\n\xc1\x88\xc6T\x95\xa0\x81!)Wa\x13U]\xf4\xd3\xc9G,;#\x8c\xc1E\xdc\x15\xbd\xca\x8cD\xe0\xcc\xa8<B\x8a\xa6\xc3C\xfe[#\x98\xc0\xa8Q\t\x00P\x97f\x8d\x93\xe2,e\xc6\xcf\xb6y{fHJz\xbd~uN\ri\xbe\'\x0c\xe7\xf6+)\xf4\xbc&}\xe5\xb7\xdcV\xe5\x16\x8d)B}\xe0\xa5K\x96\x8b\xff"w\x05\xb2\x1d\x9b\x83\x98\xdd\xa3T\x84\xa1Le\x07b\x08\xd0\x97e|+ \x1e\x88Iw\x9f\x1eZ1S\xa1\xe3m\x1fW\xa2\\g\x998v\xe50\xbc\xf9k\x90!c\xc8\xd8\xdc.6\xe3\xeb`\x82>\x81+\xa7\xf0\xa5\xe7]tP\xf7\x9a\xd1EL\xdc:)?\xb6\x12\x04\xde:Q\x00\xd3\xdaP\xa9na\xa2\xc0\xa3\xd9\xdb\x80\x95\x1f\x85A'
```

## Verifying tokens

To verify a Jws signature, you need the matching public key:

```python
from jwskate import JwsCompact

jws = JwsCompact(
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXSy1BQkNEIn0."
    "SGVsbG8gV29ybGQh."
    "1eucS9ZaTnAJyfVNhxLJ_phFN1rexm0l-nIXWBjUImdS29z55BuxH6NjGpltSXKrgYxYQxqGCs"
    "GIxlSVoIEhKVdhE1Vd9NPJRyw7I4zBRdwVvcqMRODMqDxCiqbDQ_5bI5jAqFEJAFCXZo2T4ixl"
    "xs-2eXtmSEp6vX51Tg1pvicM5_YrKfS8Jn3lt9xW5RaNKUJ94KVLlov_IncFsh2bg5jdo1SEoU"
    "xlB2II0JdlfCsgHohJd58eWjFToeNtH1eiXGeZOHblMLz5a5AhY8jY3C424-tggj6BK6fwpedd"
    "dFD3mtFFTNw6KT-2EgTeOlEA09pQqW5hosCj2duAlR-FQQ"
)
public_jwk = {
    "kty": "RSA",
    "kid": "JWK-ABCD",
    "alg": "RS256",
    "n": "2jgK-5aws3_fjllgnAacPkwjbz3RCeAHni1pcHvReuTgk9qEiTmXWJiSS_F20VeI1zEwFM36e836ROCyOQ8cjjaPWpdzCajWC0koY7X8MPhZbdoSptOmDBseRCyYqmeMCp8mTTOD6Cs43SiIYSMNlPuio89qjf_4u32eVF_5YqOGtwfzC4p2NUPPCxpljYpAcf2BBG1tRX1mY4WP_8zwmx3ZH7Sy0V_fXI46tzDqfRXdMhHW7ARJAnEr_EJhlMgUaM7FUQKUNpi1ZdeeLxYv44eRx9-Roy5zTG1b0yRuaKaAG3559572quOcxISZzK5Iy7BhE7zxVa9jabEl-Y1Daw",
    "e": "AQAB",
}
if jws.verify_signature(public_jwk):
    print("Signature is verified.")
else:
    print("Signature verification failed!")
```

## Signing tokens

To sign a Jws, you need its payload, the private key and alg to sign with, and provide those to `JwsCompact.sign()`:

```python
from jwskate import JwsCompact

payload = b"Hello World!"
private_jwk = {
    "kty": "RSA",
    "kid": "JWK-ABCD",
    "alg": "RS256",
    "n": "2jgK-5aws3_fjllgnAacPkwjbz3RCeAHni1pcHvReuTgk9qEiTmXWJiSS_F20VeI1zEwFM36e836ROCyOQ8cjjaPWpdzCajWC0koY7X8MPhZbdoSptOmDBseRCyYqmeMCp8mTTOD6Cs43SiIYSMNlPuio89qjf_4u32eVF_5YqOGtwfzC4p2NUPPCxpljYpAcf2BBG1tRX1mY4WP_8zwmx3ZH7Sy0V_fXI46tzDqfRXdMhHW7ARJAnEr_EJhlMgUaM7FUQKUNpi1ZdeeLxYv44eRx9-Roy5zTG1b0yRuaKaAG3559572quOcxISZzK5Iy7BhE7zxVa9jabEl-Y1Daw",
    "e": "AQAB",
    "d": "XCtpsCRQ1DBBm51yqdQ88C82lEjW30Xp0cy6iVEzBKZhmPGmI1PY8gnXWQ5PMlK3sLTM6yypDNvORoNlo6YXWJYA7LGlXEIczj2DOsJmF8T9-OEwGZixvNFDcmYnwWnlA6N_CQKmR0ziQr9ZAzZMCU5Tvr7f8cRZKdAALQEwk5FYpLnEbXOBduJtY9x2kddJSCJwRaEJhx0fG_pJAO3yLUZBY20dZK8UrxDoCgB9eiZV3N4uWGt367r1MDdaxGY6l6bC1HZCHkttBuTxfSUMCgooZevdU6ThQNpFrwZNY3KoP-OksEdqMs-neecfk_AQREkubDW2VPNFnaVEa38BKQ",
    "p": "8QNZGwUINpkuZi8l2ZfQzKVeOeNe3aQ7UW0wperM-63DFEJDRO1UyNC1n6yeo8_RxPZKSTlr6xZDoilQq23mopeF6O0ZmYz6E2VWJuma65V-A7tB-6xjqUXPlSkCNA6Ia8kMeCmNpKs0r0ijTBf_2y2GSsNH4EcP7XzcDEeJIh0",
    "q": "58nWgg-qRorRddwKM7qhLxJnEDsnCiYhbKJrP78OfBZ-839bNRvL5D5sfjJqxcKMQidgpYZVvVNL8oDEywcC5T7kKW0HK1JUdYiX9DuI40Mv9WzXQ8B8FBjp5wV4IX6_0KgyIiyoUiKpVHBvO0YFPUYuk0Ns4H9yEws93RWwhSc",
    "dp": "zFsLZcaphSnzVr9pd4urhqo9MBZjbMmBZnSQCE8ECe729ymMQlh-SFv3dHF4feuLsVcn-9iNceMJ6-jeNs1T_s89wxevWixYKrQFDa-MJW83T1CrDQvJ4VCJR69i5-Let43cXdLWACcO4AVWOQIsdpquQJw-SKPYlIUHS_4n_90",
    "dq": "fP79rNnhy3TlDBgDcG3-qjHUXo5nuTNi5wCXsaLInuZKw-k0OGmrBIUdYNizd744gRxXJCxTZGvdEwOaHJrFVvcZd7WSHiyh21g0CcNpSJVc8Y8mbyUIRJZC3RC3_egqbM2na4KFqvWCN0UC1wYloSuNxmCgAFj6HYb8b5NYxBU",
    "qi": "hxXfLYgwrfZBvZ27nrPsm6mLuoO-V2rKdOj3-YDJzf0gnVGBLl0DZbgydZ8WZmSLn2290mO_J8XY-Ss8PjLYbz3JXPDNLMJ-da3iEPKTvh6OfliM_dBxhaW8sq5afLMUR0H8NeabbWkfPz5h0W11CCBYxsyPC6CzniFYCYXfByU",
}

jws = JwsCompact.sign(payload, jwk=private_jwk, alg="RS256")
str(jws)
# 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXSy1BQkNEIn0.SGVsbG8gV29ybGQh.1eucS9ZaTnAJyfVNhxLJ_phFN1rexm0l-nIXWBjUImdS29z55BuxH6NjGpltSXKrgYxYQxqGCsGIxlSVoIEhKVdhE1Vd9NPJRyw7I4zBRdwVvcqMRODMqDxCiqbDQ_5bI5jAqFEJAFCXZo2T4ixlxs-2eXtmSEp6vX51Tg1pvicM5_YrKfS8Jn3lt9xW5RaNKUJ94KVLlov_IncFsh2bg5jdo1SEoUxlB2II0JdlfCsgHohJd58eWjFToeNtH1eiXGeZOHblMLz5a5AhY8jY3C424-tggj6BK6fwpedddFD3mtFFTNw6KT-2EgTeOlEA09pQqW5hosCj2duAlR-FQQ'
```

# JWE

The `JweCompact` class represents a syntactically valid JWE token.

## Parsing and decrypting JWE tokens

Provide the serialized token value to `JweCompact`, then use `.decrypt()` with the private key to decrypt the token
payload:

```python
from jwskate import JweCompact

jwe = JweCompact(
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

# all 'raw' attributes are accessible:
jwe.headers
# {'alg': 'RSA-OAEP', 'enc': 'A256GCM'}
jwe.alg
# 'RSA-OAEP'
jwe.enc
# 'A256GCM'
jwe.ciphertext
# b"\xe5\xec\xa6\xf15\xbfs\xc4\xae+Im'z\xe9`\x8c\xcex43\xed0\x0b\xbe\xdb\xbaPoh2\x8e/\xa7;=\xb5\x7f\xc4\x15(R\xf2 {\x8f\xa8\xe2I\xd8\xb0\x90\x8a\xf7j<\x10\xcd\xa0m@?\xc0"
jwe.wrapped_cek
# b'8\xa3\x9a\xc0:5\xde\x04i\xda\x88\xda\x1d^\xcb\x16\x96\\\x81^\xd3\xe85Y)<\x8a8\xc4\xd8Rb\xa8L%IF\x07$\x08\xbfd\x88\xc4\xf4\xdc\x91\x9e\x8a\x9b\x04u\x8d\xe6\xc7\xf7\xad-\xb6\xd6J\xb1k\xd3\x99\x0b\xcd\xc4\xab\xe2\xa2\x80\xab\xb6\r\xed\xefc\xc1\x04[\xdby\xdfk\xa7=w\xe4\xad\x9c\x89\x86\xc8P\xdbJ\xfd8\xb9[\xb1"\x9eY\x9a\xcd`7\x12\x8a+`\xda\xd7\x80|K\x8a\xf3U\x19mu\x8c\x1a\x9b\xf9C\xa7\x95\xe7d\x06)A\xd6\xfb\xe8WH(\xb6\x95\x9a\xa8\x1f\xc1~\xd7Y\x1co\xdb}\xb6\x8b\xeb\xc3\xc5\x17\xea7:?\xb4D\xca\xce\x95K\xcd\xf8\xb0C\'\xb2<b\xc1 \xeez`\x9e\xde9\xb7o\xd27\xbc\xd7\xce\xb4\xa6\x96\xa6j\xfa7\xe5H(E\xd6\xd8h\x17(\x87\xd4\x1c\x7f)P\xaf\xae\xa8s\xab\xc5Yt\\g\xf6S\xd8\xb6\xb0T%\x93#-\xdb\xacc\xe2\xe9I%|*H1\xf2#\x7f\xb8\x86ur\x87\xce'
jwe.initialization_vector
# b'\xe3\xc5u\xfc\x02\xdb\xe9D\xb4\xe1M\xdb'
jwe.authentication_tag
# b'\\Ph1\x85\x19\xa1\xd7\xade\xdb\xd3\x88[\xd2\x91'


private_jwk = {
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
payload = jwe.decrypt(private_jwk)
assert payload == b"The true sign of intelligence is not knowledge but imagination."

# you can also decrypt only the CEK (returned as SymmetricJwk instance):
cek = jwe.unwrap_cek(private_jwk)
assert cek == {"kty": "oct", "k": "saH0gFSP4XM_tAP_a5rU9ooHbltwLiJpL4LLLnrqQPw"}
```

## Encrypting JWE tokens

To encrypt a JWE token, use `JweCompact.encrypt()` with the plaintext, public key, key management alg (`alg`) and
encryption alg (`enc`):

```python
from jwskate import JweCompact, Jwk

plaintext = b"Encrypting JWE is easy!"
private_jwk = Jwk.generate_for_kty("EC")
public_jwk = private_jwk.public_jwk()

jwe = JweCompact.encrypt(plaintext, public_jwk, alg="ECDH-ES+A128KW", enc="A128GCM")
str(jwe)
# 'eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI3a2VIdGxXdnVQQWVfYzR3d1hsNXFBZENHYzNKSk9KX0c5WThWU29Cc0tBIiwieSI6ImlyVFpRVzFlckZUSGd4WG1nUVdpcTVBYXdNOXNtamxybE96X2RTMmpld1kifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.s7iUWLT2TG_kRnxuRvMxL5lY1oVRRVlI.kQaT5CM0HYfdwQ9H.49Trq2lpEtOEk8u_HP20TuJ80xpkqK8.RsQMBzvLj5i9bk4eew21gg'
```

# JWT

JWT tokens are JWS tokens which contain a JSON object as payload. Some attributes of this JSON object are standardised
to represent the token issuer, audience, and lifetime.

The `Jwt` class and its subclasses represent a syntactically valid Jwt token. It then allows to access the JWT content
and verify its signature.

Note that a JWT token can optionally be encrypted. In that case, the signed JWT content will be the plaintext of a JWE
token. Decrypting that JWE can then be achieved with the `JweCompact` class, then this plaintext can be manipulated with
the `Jwt` class.

## Parsing JWT tokens

To parse an existing JWT token, simply initialize a `Jwt` with the token value as parameter. An instance of `Jwt`
exposes all the JWT attributes, and a `verify_signature()` method just like `JwsCompact()`. Claims can be accessed
either:

- with the `claims` attribute, which is a dict of the parsed JSON content
- with subscription: `jwt['attribute']` does a key lookup inside the `claims` dict, just like `jwt.claims['attribute']`
- with attribute access: `jwt.attribute` does the same as `jwt.claims['attribute']`. Note that attribute names
  containing special characters are not accessible this way due to Python syntax for attribute names.
- for standardised attributes, with a dedicated special attribute, which will parse and validate the attribute value.
  Example: `jwt.expires_at` returns a `datetime` initialised from the `exp` claim.

```python
from jwskate import Jwt

jwt = Jwt(
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9.eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiwic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUnyTxl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCskqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f-azA"
)

jwt.claims
# {'acr': '2',
#  'amr': ['pwd', 'otp'],
#  'aud': 'client_id',
#  'auth_time': 1629204560,
#  'exp': 1629204620,
#  'iat': 1629204560,
#  'iss': 'https://myas.local',
#  'nonce': 'nonce',
#  'sub': '123456'}

# example claim access via subscription:
jwt["acr"]
# '2'

# example claim access via attribute:
jwt.sub
# '123456'

# example special claim access:
jwt.expires_at
# datetime.datetime(2021, 8, 17, 12, 50, 20, tzinfo=datetime.timezone.utc)

# the raw 'exp' value is still accessible with the other means:
jwt["exp"] == jwt.exp == 1629204620
# True

# other special attributes:
jwt.audiences  # always return a list
# ['client_id']
jwt.issued_at
# datetime.datetime(2021, 8, 17, 12, 49, 20, tzinfo=datetime.timezone.utc)
jwt.not_before  # this would be a datetime if there was a valid 'nbf' claim in the token
None
jwt.subject  # return the 'sub' claim, and makes sure it is a string
# '123456'
jwt.issuer  # return the 'iss' claim, and makes sure that it is a string
# 'https://myas.local'


jwt.headers
# {'alg': 'RS256', 'kid': 'my_key'}

jwt.signature
# b"\xc1G\xe33(\xe59'olQ\x85?\xc3\xbc\xc0g\r\x04\xae\xda\x91\xec\x8eP\x13/a\xc3YrQT\xb6\x89\x0e\xcb\x18KP\xfcf\xa3T\xc7\xa3P\xd5\xd4\x11\xd4U\xde\x80Y\xf7\x8aR|\x93\xc6_\xfc\xf8m\xc4\xfd\xafn\xe7\x02_\x0f'\xe0\x84\xf0\xe1\ng\xe4`\x04o\xa9\t\xe7W\xfd\xda!\xb7\xd3}@B\xe1\xfd\x1b\x1e\xbd<w\xfa\xb4|@\xfc\xf1\x12\xee\xef\xbc\x04H\x83\xc2V\xa4\x18\xcbf\xe4\xe0R\xeeq\xce\xb7\xc8`oh+$\xab;ag\xceCl\x12XX\xb9Q\xf2\xa0T\x93\xf3@\xf1\xb5\x80M\x81-\x8f\x04\xeb\xc6\x86^\xfa\xe0>\xbc\x1e\x8d\xc1K\xf5\x87\xc0\xcaF\xc0\xc5\xfb\xd1\xd2Tw\x96]p\x1e\xa0oT[\xbc\xe0\xc6\x867)\xb0\xc8W7\xa6\xbcl\xec\xd9\x1fN\x800QE\xa7\xc1\x05W\x80\x905z\t\xd6\xdd0\xd2C\x98|\xdc\x8d\xab\x1e\xe65\xfa,O\xb7`,\xbbs\xb0\x0c3[\x96D)\xca\xdd\xff\x9a\xcc"

# verifying the signature:
assert jwt.verify_signature(
    {
        "kty": "RSA",
        "kid": "my_key",
        "alg": "RS256",
        "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
        "e": "AQAB",
    }
)

# verifying expiration:
assert jwt.is_expired()
```

## Validating JWT tokens

To validate a JWT token, verifying the signature is usually not enough. You probably want to validate the issuer,
audience, expiration date, and other claims. To make things easier, use `SignedJwt.validate()`. It raises exceptions if
one of the check fails:

```python
from jwskate import Jwt

jwt = Jwt(
    "eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleSJ9."
    "eyJhY3IiOiIyIiwiYW1yIjpbInB3ZCIsIm90cCJdLCJhdWQiOiJjbGllbnRfaWQiLCJhdXRoX3RpbWUiOjE2MjkyMDQ1NjAsImV4cCI6MTYyOTIwNDYyMCwiaWF0IjoxNjI5MjA0NTYwLCJpc3MiOiJodHRwczovL215YXMubG9jYWwiLCJub25jZSI6Im5vbmNlIiwic3ViIjoiMTIzNDU2In0.wUfjMyjlOSdvbFGFP8O8wGcNBK7akeyOUBMvYcNZclFUtokOyxhLUPxmo1THo1DV1BHUVd6AWfeKUnyTxl_8-G3E_a9u5wJfDyfghPDhCmfkYARvqQnnV_3aIbfTfUBC4f0bHr08d_q0fED88RLu77wESIPCVqQYy2bk4FLucc63yGBvaCskqzthZ85DbBJYWLlR8qBUk_NA8bWATYEtjwTrxoZe-uA-vB6NwUv1h8DKRsDF-9HSVHeWXXAeoG9UW7zgxoY3KbDIVzemvGzs2R9OgDBRRafBBVeAkDV6CdbdMNJDmHzcjase5jX6LE-3YCy7c7AMM1uWRCnK3f-azA"
)
jwk = {
    "kty": "RSA",
    "kid": "my_key",
    "alg": "RS256",
    "n": "2m4QVSHdUo2DFSbGY24cJbxE10KbgdkSCtm0YZ1q0Zmna8pJg8YhaWCJHV7D5AxQ_L1b1PK0jsdpGYWc5-Pys0FB2hyABGPxXIdg1mjxn6geHLpWzsA3MHD29oqfl0Rt7g6AFc5St3lBgJCyWtci6QYBmBkX9oIMOx9pgv4BaT6y1DdrNh27-oSMXZ0a58KwnC6jbCpdA3V3Eume-Be1Tx9lJN3j6S8ydT7CGY1Xd-sc3oB8pXfkr1_EYf0Sgb9EwOJfqlNK_kVjT3GZ-1JJMKJ6zkU7H0yXe2SKXAzfayvJaIcYrk-sYwmf-u7yioOLLvjlGjysN7SOSM8socACcw",
    "e": "AQAB",
}

jwt.validate(jwk, issuer="https://myas.local", audience="client_id")
# at the time you run this, it will probably raise a `jwskate.ExpiredJwt` exception
```

## Signing JWT tokens

To sign a set of claims into a JWT, use `Jwt.sign()`. It takes the claims (as a dict), the signing key, and the
signature alg to use (if the key doesn't have an 'alg' parameter).

```python
from jwskate import Jwt, Jwk

claims = {"claim1": "value1", "claim2": "value2"}
jwk = Jwk.generate_for_kty("EC", crv="P-256")
jwt = Jwt.sign(claims, jwk, alg="ES256")

print(jwt)
# eyJhbGciOiJFUzI1NiJ9.eyJjbGFpbTEiOiJ2YWx1ZTEiLCJjbGFpbTIiOiJ2YWx1ZTIifQ.mqqXTljXQwNff0Sah88oFGBNWC9XpZxUj3WDa9-00UAyuEoL6cey-rHQNtmYgYgPRgI_HnWpRm5M4_a9qv9m0g
```

### JWT headers

The default header will contain the signing algorithm identifier (alg) and the JWK Key Identifier (kid), if there was
one in the used JWK. You can add additional headers by using the `extra_headers` parameter to `Jwt.sign()`:

```python
from jwskate import Jwt, Jwk

claims = {"claim1": "value1", "claim2": "value2"}
jwk = Jwk.generate_for_kty("EC", crv="P-256")
jwt = Jwt.sign(claims, jwk, alg="ES256", extra_headers={"header1": "value1"})

print(jwt)
# eyJoZWFkZXIxIjoidmFsdWUxIiwiYWxnIjoiRVMyNTYifQ.eyJjbGFpbTEiOiJ2YWx1ZTEiLCJjbGFpbTIiOiJ2YWx1ZTIifQ.m0Bi8D6Rdi6HeH4J45JPSaeGPxjboAf_-efQ3mUAi6Gs0ipC0MXg9rd727IIINUsVfU0geUn7IwA1HjoTOsHvg
print(jwt.headers)
# {'header1': 'value1', 'alg': 'ES256'}
```
