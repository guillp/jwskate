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
alg = "A256GCM"
jwk = Jwk.generate_for_kty("oct", key_size=256)

ciphertext, iv, tag = jwk.encrypt(data, alg=alg)

assert jwk.decrypt(ciphertext, iv=iv, alg=alg) == data
```

### Authenticated encryption

You can include Additional Authenticated Data (`aad`) in the `encrypt()` and `decrypt()` operations:

```python
from jwskate import Jwk

data = b"Authenticated Encryption is easy!"
alg = "A256GCM"
aad = b"This is my auth tag"
jwk = Jwk.generate_for_kty("oct", key_size=256)

ciphertext, iv, tag = jwk.encrypt(data, aad=aad, alg=alg)

assert jwk.decrypt(ciphertext, iv=iv, aad=aad, alg=alg) == data
```

## Key Management

Encrypting/decrypting arbitrary data requires a symmetric key. But it is possible to encrypt/decrypt or otherwise derive
symmetric keys from asymmetric keys, using Key Management algorithms.

Some of those Key Management algorithms rely on key wrapping, where a randomly-generated symmetric key (called a Content Encryption Key or CEK)
is itself asymetrically encrypted. It is also possible to use a symmetric key to "wrap" the CEK.
Other algorithms rely on Diffie-Hellman, where the CEK is derived from a pair of keys, one private, the other public.

You can use the methods `sender_key()` and `receiver_key()` to handle all the key management stuff for you.
For `sender_key()`, which the message sender will use get a CEK, you just need to specify which encryption algorithm you will use with the CEK, and the key management algorithm you want to wrap or derive that CEK.
It will return a tuple `(plaintext_message, encrypted_cek, extra_headers)`, with `plaintext_message` being the generated CEK (as an instance of `SymmetricJwk`),
`encrypted_cek` is the wrapped CEK value (which can be empty for Diffie-Hellman based algorithms),
and `extra_headers` a dict of extra headers that are required for the key management algorithm (for example, `epk` for ECDH-ES based algorithms),

You can use `cleartext_cek` to encrypt your message with a given Encryption algorithm. You must then send `encrypted_cek` and `extra_headers` to your recipient, along with the encrypted message, and both Key Management and Encryption algorithms identifiers.

```python
from jwskate import Jwk

plaintext_message = b"Key Management is easy!"
recipient_private_jwk = Jwk.generate_for_kty("EC", crv="P-256")
# {'kty': 'EC',
# 'crv': 'P-256',
# 'x': '10QvcmuPmErnHHnrnQ7kVV-Mm_jA4QUG5W9t81jAVyE',
# 'y': 'Vk3Y4_qH09pm8rCLl_htf321fK62qbz6jxLlk0Y3Qe4',
# 'd': 'Y4vvC9He6beJi3lKYdVgvvUS9zUWz_YnV0xKT90-Z5E'}

recipient_public_jwk = recipient_private_jwk.public_jwk()
# {'kty': 'EC',
# 'crv': 'P-256',
# 'x': '10QvcmuPmErnHHnrnQ7kVV-Mm_jA4QUG5W9t81jAVyE',
# 'y': 'Vk3Y4_qH09pm8rCLl_htf321fK62qbz6jxLlk0Y3Qe4'}

enc_alg = "A256GCM"
km_alg = "ECDH-ES"
plaintext_cek, encrypted_cek, extra_headers = recipient_public_jwk.sender_key(
    enc=enc_alg, alg=km_alg
)
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

On recipient side, in order to decrypt the message, you will need to obtain the same symmetric CEK that was used to encrypt the message. That is done with `recipient_key()`.
You need to provide it with the `encrypted_cek` received from the sender (possibly empty for Diffie-Hellman based algorithms),
the Key Management algorithm that is used to wrap the CEK, the Encryption algorithm that is used to encrypt/decrypt the message, and the eventual extra headers depending on the Key Management algorithm.

You can then use that CEK to decrypt the received message.

```python
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
recipient_private_jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": "10QvcmuPmErnHHnrnQ7kVV-Mm_jA4QUG5W9t81jAVyE",
    "y": "Vk3Y4_qH09pm8rCLl_htf321fK62qbz6jxLlk0Y3Qe4",
    "d": "Y4vvC9He6beJi3lKYdVgvvUS9zUWz_YnV0xKT90-Z5E",
}

encrypted_message = b"\xb5J\x16\x08\x82Xp\x0f,\x0eu\xe5\xd6\xa6y\xe0J\xae\xcbu\xf8B\xbd"
iv = b'K"H\xf3@\tt\\\xc78\xc2D'
tag = b"\xc4\xee\xcf`\xfa\\\x8e\x9dn\xc4>D\xd8\x1d\x8c\x1a"


# obtain the same CEK than the sender, based on our private key, and public data provided by sender
cek = recipient_private_jwk.recipient_key(
    encrypted_cek, enc="A256GCM", alg="ECDH-ES", **extra_headers
)
# and decrypt the message with that CEK (and the IV, Auth Tag and encryption alg identifier provided by sender)
plaintext_message = cek.decrypt(encrypted_message, iv=iv, tag=tag, alg=enc_alg)

assert plaintext_message == b"Key Management is easy!"
```
