"""High-Level facility to verify JWT tokens signature, validity dates, issuer, audiences, etc."""
from __future__ import annotations

from typing import Any, Callable, Iterable

from jwskate import Jwk, JwkSet

from .signed import ExpiredJwt, InvalidClaim, InvalidSignature, SignedJwt


class JwtVerifier:
    """A helper class to validate JWTs tokens in a real application.

    Args:
        jwkset: a `JwkSet` or `Jwk` which will verify the token signatures
        issuer: expected issuer value
        audience: expected audience value
        alg: expected signature alg, if there is only one
        algs: expected signature algs, if there are several
        leeway: number of seconds to allow when verifying token validity period
        verifiers: additional verifiers to implement custom checks on the tokens

    Usage:
        ```python
        from jwskate import JwtVerifier

        # initialize a JwtVerifier based on its expected issuer, audience, JwkSet and allowed signature algs
        jwks = requests.get("https://myissuer.local/jwks").json()
        verifier = JwtVerifier(
            issuer="https://myissuer.local", jwkset=jwks, audience="myapp", alg="ES256"
        )

        # then verify tokens
        try:
            verifier.verify(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215aXNzdWVyLmxvY2FsIiwiYXVkIjoibXlhcHAiLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNjcyNzU5NjM0LCJleHAiOjE2NzI3NTk2OTR9.Uu5DtCnf9cwYtem8tQ4trHVgXyZBoa8fhFcGL87O2D4"
            )
            print("token is verified!")
        except ValueError:
            print("token failed verification :(")
        ```

    """

    def __init__(
        self,
        jwkset: JwkSet | Jwk | dict[str, Any],
        *,
        issuer: str | None,
        audience: str | None = None,
        alg: str | None = None,
        algs: Iterable[str] | None = None,
        leeway: int = 10,
        verifiers: Iterable[Callable[[SignedJwt], None]] | None = None,
    ) -> None:
        if isinstance(jwkset, Jwk):
            jwkset = jwkset.as_jwks()
        elif isinstance(jwkset, dict):
            if "keys" in jwkset:
                jwkset = JwkSet(jwkset)
            else:
                jwkset = Jwk(jwkset).as_jwks()

        if not isinstance(jwkset, JwkSet) or jwkset.is_private:
            raise ValueError(
                "Please provide either a `JwkSet` or a single `Jwk` for signature verification. "
                "Signature verification keys must be public."
            )

        self.issuer = issuer
        self.jwkset = jwkset
        self.audience = audience
        self.alg = alg
        self.algs = algs
        self.leeway = leeway
        self.verifiers = list(verifiers) if verifiers else []

    def verify(self, jwt: SignedJwt | str) -> None:
        """Verify a given JWT token.

        This checks the token signature, issuer, audience and expiration date, plus any custom verification,
        as configured at init time.

        Args:
            jwt: the JWT token to verify

        """
        if not isinstance(jwt, SignedJwt):
            jwt = SignedJwt(jwt)

        if self.issuer and jwt.issuer != self.issuer:
            raise InvalidClaim("Mismatching issuer", self.issuer, jwt.issuer)

        if self.audience and self.audience not in jwt.audiences:
            raise InvalidClaim("Mismatching audience", self.audience, jwt.audiences)

        if "kid" in jwt.headers:
            jwk = self.jwkset.get_jwk_by_kid(jwt.kid)
            if not jwt.verify_signature(jwk, alg=self.alg, algs=self.algs):
                raise InvalidSignature()
        else:
            for jwk in self.jwkset.verification_keys():
                if jwt.verify_signature(jwk, alg=self.alg, algs=self.algs):
                    break
            else:
                raise InvalidSignature()

        if jwt.is_expired(self.leeway):
            raise ExpiredJwt(f"Jwt token expired at {jwt.expires_at}")

        for verifier in self.verifiers:
            verifier(jwt)

    def custom_verifier(self, verifier: Callable[[SignedJwt], None]) -> None:
        """A decorator to add custom verification steps to this verifier.

        Usage:
            ```python
            from jwskate import Jwk, JwtVerifier

            verification_key = Jwk(
                {"kty": "oct", "k": "eW91ci0yNTYtYml0LXNlY3JldA", "alg": "HS256"}
            )
            verifier = JwtVerifier(verification_key.as_jwks(), issuer="https://foo.bar")


            @verifier.custom_verifier
            def must_contain_claim_foo(jwt):
                if "foo" not in jwt:
                    raise ValueError("No foo!")


            verifier.verify(
                "eyJhbGciOiJIUzI1NiIsImtpZCI6ImlfdXRLRXhBS05jXy1hd3FEUkFVYmFoTWd5RGFLREdfTTc1S01Cd2xBdkEifQ.eyJpc3MiOiJodHRwczovL2Zvby5iYXIiLCJmb28iOiJZRVMiLCJpYXQiOjE1MTYyMzkwMjJ9.hk2vnymjcww8K-OcOkNCPUiJK-8Rj--RKJqsHSKe4jM"
            )
            ```

        """
        self.verifiers.append(verifier)
