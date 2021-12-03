class InvalidJwk(ValueError):
    pass


class PrivateKeyRequired(AttributeError):
    pass


class PublicKeyRequired(AttributeError):
    pass


class UnsupportedAlg(ValueError):
    pass
