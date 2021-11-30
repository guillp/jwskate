from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from jwskate.algorithms.base import SignatureAlg


class RSASigAlg(SignatureAlg):
    hashing_alg: hashes.HashAlgorithm
    padding_alg: padding.AsymmetricPadding = padding.PKCS1v15()
    min_key_size: int = 2048


class RS256(RSASigAlg):
    name = "RS256"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"
    hashing_alg = hashes.SHA256()


class RS384(RSASigAlg):
    name = "RS384"
    description = "RSASSA-PKCS1-v1_5 using SHA-384"
    hashing_alg = hashes.SHA384()


class RS512(RSASigAlg):
    name = "RS512"
    description = "RSASSA-PKCS1-v1_5 using SHA-256"
    hashing_alg = hashes.SHA512()


class PS256(RSASigAlg):
    name = "PS256"
    description = "RSASSA-PSS using SHA-256 and MGF1 with SHA-256"
    hashing_alg = hashes.SHA256()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=256 // 8)


class PS384(RSASigAlg):
    name = "PS384"
    description = "RSASSA-PSS using SHA-384 and MGF1 with SHA-384"
    hashing_alg = hashes.SHA384()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=384 // 8)


class PS512(RSASigAlg):
    name = "PS512"
    description = "RSASSA-PSS using SHA-512 and MGF1 with SHA-512"
    hashing_alg = hashes.SHA512()
    padding_alg = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=512 // 8)
