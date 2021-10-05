"""
Implements the various Json Web Crypto-related standards like JWA, JWK, JWKS, JWE, JWT.
This doesn't implement any actual cryptographic operations, it just provides a set of convenient wrappers
around the `cryptography` module.
"""

__author__ = """Guillaume Pujol"""
__email__ = "guill.p.linux@gmail.com"
__version__ = "0.1.0"

from .jwe import *
from .jwk import *
from .jws import *
from .jwt import *
