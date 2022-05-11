# Usage

To use `jwskate` in a project

```
from jwskate import *
```

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

Those will return the exact (usually base64url-encoded) value from the JWK.
You can also get the raw, decoded parameters with some special attributes:

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

## Generating keys

You can generate a Jwk with the class method `Jwk.generate_for_kty()`. It needs the key type as parameter, and type-specific parameters:

```python
from jwskate import Jwk

ec_jwk = Jwk.generate_for_kty("EC", crv="P-256")
rsa_jwk = Jwk.generate_for_kty("RSA", key_size=4096)
okp_jwk = Jwk.generate_for_kty("OKP", crv="Ed25519")
```

You can include additional parameters such as "use" or "key_ops", or custom parameters which will be included in the generated key:

```python
from jwskate import Jwk

jwk = Jwk.generate_for_kty("EC", crv="P-256", use="")
```

## Private and Public Keys

You can check if a key is public or private with the `is_private` property:

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
assert jwk.is_private
```

You can get the public key that match a given private key with the `public_jwk()` method. It returns a new `Jwk` instance that does not contain the private parameters:

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
public_jwk = jwk.public_jwk()
assert "d" not in public_jwk
assert not public_jwk.is_private
```

Note that Symmetric keys are always considered private, so calling `.public_jwk()` will raise a `ValueError`.

## Dumping keys

### to JSON

`Jwk` instances are dicts, so you can serialize it to JSON in the usual ways (with Python `json` module or any other means).
You can also use the `to_json()` convenience method to serialize a Jwk:

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

You can access the `cryptography_key` attribute to get a `cryptography` key instance that matches a Jwk:

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

You can sign arbitrary data, then validate the signature with a `Jwk` instance, using the `sign()` and `verify()` methods:

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

Encryption or decryption require a symmetric key, which translates to an instance of `SymmetricJwk`, with kty
You can encrypt and decrypt arbitrary data with a Jwk instance, using the `encrypt()` and `decrypt()` methods:

```python
from jwskate import Jwk

data = b"Encryption is easy!"
jwk = Jwk.generate_for_kty("oct", key_size=256)

ciphertext, tag, iv = jwk.encrypt(data, alg="A256GCM")

assert jwk.decrypt(ciphertext, tag, iv, alg="A256GCM") == data
```

## Key Management

Encrypting/decrypting arbitrary data requires a symmetric key. But it is possible to encrypt/decrypt or otherwise derive
symmetric keys from asymmetric keys, using Key Management algorithms.
