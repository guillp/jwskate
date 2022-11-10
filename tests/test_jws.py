import pytest
from binapy import BinaPy

from jwskate import (
    P_521,
    ECJwk,
    Jwk,
    JwsCompact,
    JwsJsonFlat,
    JwsJsonGeneral,
    OKPJwk,
    RSAJwk,
    SymmetricJwk,
)


def test_jws_compact(private_jwk: Jwk) -> None:
    jws = JwsCompact.sign(payload=b"Hello World!", jwk=private_jwk, alg="RS256")
    assert (
        str(jws)
        == "eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXSy1BQkNEIn0.SGVsbG8gV29ybGQh.1eucS9ZaTnAJyfVNhxLJ_phFN1rexm0l"
        "-nIXWBjUImdS29z55BuxH6NjGpltSXKrgYxYQxqGCsGIxlSVoIEhKVdhE1Vd9NPJRyw7I4zBRdwVvcqMRODMqDxCiqbDQ"
        "_5bI5jAqFEJAFCXZo2T4ixlxs-2eXtmSEp6vX51Tg1pvicM5_YrKfS8Jn3lt9xW5RaNKUJ94KVLlov_IncFsh2bg5jdo1"
        "SEoUxlB2II0JdlfCsgHohJd58eWjFToeNtH1eiXGeZOHblMLz5a5AhY8jY3C424-tggj6BK6fwpedddFD3mtFFTNw6KT-"
        "2EgTeOlEA09pQqW5hosCj2duAlR-FQQ"
    )
    public_jwk = private_jwk.public_jwk()
    assert jws.verify_signature(public_jwk, alg="RS256")


EC_P521_PRIVATE_KEY = {
    "kty": "EC",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "crv": "P-521",
    "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9"
    "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
    "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy"
    "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
    "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"
    "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
}

RSA_PRIVATE_KEY = {
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT"
    "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV"
    "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-"
    "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde"
    "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC"
    "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g"
    "HdrNP5zw",
    "e": "AQAB",
    "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e"
    "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld"
    "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b"
    "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU"
    "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj"
    "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc"
    "OpBrQzwQ",
    "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR"
    "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG"
    "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8"
    "bUq0k",
    "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT"
    "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an"
    "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0"
    "s7pFc",
    "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q"
    "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn"
    "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX"
    "59ehik",
    "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr"
    "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK"
    "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK"
    "T1cYF8",
    "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N"
    "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh"
    "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP"
    "z8aaI4",
}

OKP_ED25519_PRIVATE_KEY = {
    "kty": "OKP",
    "crv": "Ed25519",
    "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}

OKP_ED448_PRIVATE_KEY = {
    "kty": "OKP",
    "crv": "Ed448",
    "x": "Cg5TBDGx0VUzIsTBy7-1ipgpdbn1URt9Ahb4tKwzav788lold5nGfmuqMcdyBOBMnc-kVdtBew4A",
    "d": "8AW_tfr1kQkyMqOjoGzM3yiLgu6zbN2Nlcpc50b4lwh4bVE1b1EwyJJJqJ4J3zhXLRmUB3REz1y0",
}

SYMMETRIC_SIGNATURE_KEY = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "sig",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
}


@pytest.fixture(scope="session")
def ec_p521_private_jwk() -> Jwk:
    """This is the key from [https://datatracker.ietf.org/doc/html/rfc7520#section-3.2]."""
    jwk = Jwk(EC_P521_PRIVATE_KEY)
    assert isinstance(jwk, ECJwk)
    assert jwk.is_private
    assert jwk.kty == "EC"
    assert jwk.kid == "bilbo.baggins@hobbiton.example"
    assert jwk.use == "sig"
    assert jwk.curve == P_521
    assert (
        jwk.x_coordinate
        == 1536512509633812701046363966946458604394346818697394258819956002474017850080242973018354677969345705661882653180474980600600249393774872942916765721086083757
    )
    assert (
        jwk.y_coordinate
        == 6390841077912737365653019441492828723058308087943275742908661475903115398365573971688270351422921162967673593344809147696590449694148618103053589689371825269
    )
    assert (
        jwk.ecc_private_key
        == 111516411687364059110290785888309499157003632541675704481981366909658327544236421609398595734137119337357107861242367481230550517706674527460992238934209133
    )
    return jwk


@pytest.fixture(scope="session")
def ec_p256_private_jwk() -> Jwk:
    return ECJwk.generate("P-256")


@pytest.fixture(scope="session")
def ec_p384_private_jwk() -> Jwk:
    return Jwk.generate_for_kty("EC", crv="P-384")


@pytest.fixture(scope="session")
def rsa_private_jwk() -> Jwk:
    """This is the key from [https://datatracker.ietf.org/doc/html/rfc7520#section-3.4]."""
    jwk = Jwk(RSA_PRIVATE_KEY)
    assert isinstance(jwk, RSAJwk)
    assert jwk.is_private
    assert jwk.kty == "RSA"
    assert jwk.kid == "bilbo.baggins@hobbiton.example"
    assert jwk.use == "sig"
    assert (
        jwk.modulus
        == 20135533008613362683983973718862990570890949482783547491074937566048838943004157274484500282679051238967930814182837332509745335321694730867914487474360313056717004122048241683576190451001206594369003880452220552186311851010130037332999299892700953157894377718386086768938058299374235398748350321163975673243254998238224668780038242796491971359194173117243083075284176788910883569789455869367283514387223800602948314723218768921623931105285092074647944930960873919066358313244754717122611255711161319444897038896496343014060976689972635082113758993979473481511550731351324005908071126862383299605264835961097030990287
    )
    assert jwk.exponent == 65537
    assert (
        jwk.private_exponent
        == 13809785886921180797407749068700942981528089435771470964933339849531763931979658226246689941649114165877756904281400924998825599768673188627050679509247407590724566295036763464811978094688530662125180988122227281988347728446577123121956338123153675672384095849459356212372062261627372823030362241721140402534827920608159114397698659666564432536888691574732214992533122683199444713216582417478411683595580959548347164585150169575401765252679902902625147728179779840007171037544685861186766305472768461620252400817122383292377247352244817836750259386865218586191336825522033117854784997616980884291365145982447543137217
    )
    assert (
        jwk.first_prime_factor
        == 155305159528675998315587554014523516083078608902053750652196202749677048642358299363759977556059891120561885641903854876605754500853726315968216134808579359395711784936178882676585818087673577574114127693348589707935410407050296794012012146664933439273320539907415872853360575628122941817407358922423140657993
    )
    assert (
        jwk.second_prime_factor
        == 129651410614568017951696388521026752738348674639303464401419464668770635900253174384526773731502315063946718183900420330879494363511129117909409612613133053606973655487402983938837056343590378935691659259752059752852280269661044647292328198275965901381648329420292300429253481090448036576608977166562458575959
    )
    assert (
        jwk.first_factor_crt_exponent
        == 5452754506240497308759433019323719585992094222860760795439270374399299463296556858507586681668276080205271813815413736836746282351411023590382002932611213604063854267637328669893708400136364221707380683009522939987478513612504889192694812845812469959990700860994002219137017021229395442602718050574418216489
    )
    assert (
        jwk.second_factor_crt_exponent
        == 6103034953475782159405883067387392346274709877813314428160871698478072108156934906636939392429995910283894984471867749832357906395346648896814450690625379104589983172538233447538219918824119490007305320907809395266022012480039103665056876141436971569684073061958920103517814199063615863387684736238234656863
    )
    assert (
        jwk.first_crt_coefficient
        == 155171362656114787674005338316026300971092335901511555016027916093530558354739494408751451514346305783601055276983183518496184496218932854791325892306914322459078533545141895619742270863660955772717492371592287055310307433879513025000807527757356866299049054535097378049521944951691464480088870568286553270414
    )
    return jwk


@pytest.fixture(scope="module")
def okp_ed25519_signature_jwk() -> Jwk:
    jwk = Jwk(OKP_ED25519_PRIVATE_KEY)
    assert isinstance(jwk, OKPJwk)
    assert jwk.is_private
    assert jwk.kty == "OKP"
    assert (
        jwk.private_key.hex()
        == "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    assert (
        jwk.public_key.hex()
        == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    assert jwk.thumbprint() == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    return jwk


@pytest.fixture(scope="module")
def okp_ed448_signature_jwk() -> Jwk:
    jwk = Jwk(OKP_ED448_PRIVATE_KEY)
    assert isinstance(jwk, OKPJwk)
    assert jwk.is_private
    assert jwk.kty == "OKP"
    assert (
        jwk.private_key.hex()
        == "f005bfb5faf591093232a3a3a06cccdf288b82eeb36cdd8d95ca5ce746f89708786d51356f5130c89249a89e09df38572d1994077444cf5cb4"
    )
    assert (
        jwk.public_key.hex()
        == "0a0e530431b1d1553322c4c1cbbfb58a982975b9f5511b7d0216f8b4ac336afefcf25a257799c67e6baa31c77204e04c9dcfa455db417b0e00"
    )
    assert jwk.thumbprint() == "tNxVYGfEeBGXEG7N8YAvNhBlZ1mSKVjc3tMP_t_3-t0"
    return jwk


@pytest.fixture(scope="session")
def symmetric_signature_jwk() -> Jwk:
    """This is the key from [https://datatracker.ietf.org/doc/html/rfc7520#section-3.5]."""
    jwk = Jwk(SYMMETRIC_SIGNATURE_KEY)
    assert isinstance(jwk, SymmetricJwk)
    assert jwk.is_private
    assert jwk.kty == "oct"
    assert jwk.kid == "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
    assert jwk.use == "sig"
    assert (
        jwk.key.hex()
        == "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"
    )
    assert jwk.key_size == 32 * 8
    return jwk


@pytest.fixture(scope="module")
def signature_payload() -> bytes:
    """This is the payload from [https://datatracker.ietf.org/doc/html/rfc7520#section-4]."""
    return (
        "It’s a dangerous business, Frodo, going out your door. "
        "You step onto the road, and if you don't keep your feet, "
        "there’s no knowing where you might be swept off to."
    ).encode()


@pytest.fixture(
    params=[
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "HS256",
        "HS384",
        "HS512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    ]
)
def signature_alg(request: pytest.FixtureRequest) -> str:
    return request.param  # type: ignore[no-any-return]


@pytest.fixture()
def signature_jwk(
    signature_alg: str,
    rsa_private_jwk: Jwk,
    ec_p256_private_jwk: Jwk,
    ec_p384_private_jwk: Jwk,
    ec_p521_private_jwk: Jwk,
    okp_ed25519_signature_jwk: Jwk,
    okp_ed448_signature_jwk: Jwk,
    symmetric_signature_jwk: Jwk,
) -> Jwk:
    for key in (
        rsa_private_jwk,
        ec_p521_private_jwk,
        ec_p384_private_jwk,
        ec_p256_private_jwk,
        okp_ed25519_signature_jwk,
        okp_ed448_signature_jwk,
        symmetric_signature_jwk,
    ):
        if signature_alg in key.supported_signing_algorithms():
            return key

    pytest.skip(
        f"No key supports this signature alg: {signature_alg}"
    )  # pragma: no cover


@pytest.fixture()
def verification_jwk(signature_jwk: Jwk) -> Jwk:
    if isinstance(signature_jwk, SymmetricJwk):
        return signature_jwk
    public_jwk = signature_jwk.public_jwk()
    assert not public_jwk.is_private
    assert signature_jwk.kty == public_jwk.kty
    return public_jwk


@pytest.fixture()
def signed_jws_compact(
    signature_payload: bytes, signature_jwk: Jwk, signature_alg: str
) -> JwsCompact:
    jws = JwsCompact.sign(
        payload=signature_payload, jwk=signature_jwk, alg=signature_alg
    )
    assert isinstance(jws, JwsCompact)
    return jws


class SupportsBytesTester:
    """A test class with a __bytes__ method to match SupportBytes interface."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __bytes__(self) -> bytes:  # noqa: D105
        return self.payload


def test_supportsbytes(
    signature_payload: bytes,
    signature_jwk: Jwk,
    signature_alg: str,
    signed_jws_compact: JwsCompact,
    verification_jwk: Jwk,
) -> None:
    jws = JwsCompact.sign(
        payload=SupportsBytesTester(signature_payload),
        jwk=signature_jwk,
        alg=signature_alg,
    )
    if signature_alg not in ("ES256", "ES384", "ES512", "PS256", "PS384", "PS512"):
        # those algs have non deterministic signatures
        assert jws == signed_jws_compact

    assert jws.payload == signed_jws_compact.payload
    assert verification_jwk.verify(
        SupportsBytesTester(jws.signed_part),
        SupportsBytesTester(jws.signature),
        alg=signature_alg,
    )


@pytest.fixture()
def signed_jws_json_flat(
    signature_payload: bytes, signature_jwk: Jwk, signature_alg: str
) -> JwsJsonFlat:
    jws = JwsJsonFlat.sign(
        payload=signature_payload, jwk=signature_jwk, alg=signature_alg
    )
    assert isinstance(jws, JwsJsonFlat)
    return jws


@pytest.fixture()
def signed_jws_json_general(
    signature_payload: bytes, signature_jwk: Jwk, signature_alg: str
) -> JwsJsonGeneral:
    jws = JwsJsonGeneral.sign(signature_payload, (signature_jwk, signature_alg))
    assert isinstance(jws, JwsJsonGeneral)
    return jws


def test_verify_signature(
    signed_jws_compact: JwsCompact, verification_jwk: Jwk, signature_alg: str
) -> None:
    assert signed_jws_compact.verify_signature(verification_jwk, alg=signature_alg)
    altered_jws = bytes(signed_jws_compact)[:-4] + (
        b"aaaa" if not signed_jws_compact.value.endswith(b"aaaa") else b"bbbb"
    )
    assert not JwsCompact(altered_jws).verify_signature(
        verification_jwk, alg=signature_alg
    )


def test_verify_signature_json_flat(
    signed_jws_json_flat: JwsJsonFlat, verification_jwk: Jwk, signature_alg: str
) -> None:
    assert signed_jws_json_flat.verify_signature(verification_jwk, alg=signature_alg)
    altered_jws = dict(signed_jws_json_flat)
    altered_jws["signature"] = signed_jws_json_flat["signature"][:-4] + (
        "aaaa" if not signed_jws_json_flat["signature"].endswith("aaaa") else "bbbb"
    )
    assert not JwsJsonFlat(altered_jws).verify_signature(
        verification_jwk, alg=signature_alg
    )


def test_verify_signature_json_general(
    signed_jws_json_general: JwsJsonGeneral, verification_jwk: Jwk, signature_alg: str
) -> None:
    assert signed_jws_json_general.verify_signature(verification_jwk, alg=signature_alg)
    altered_jws = dict(signed_jws_json_general)
    altered_jws["signatures"][0]["signature"] = signed_jws_json_general["signatures"][
        0
    ]["signature"][:-4] + (
        "aaaa"
        if not signed_jws_json_general["signatures"][0]["signature"].endswith("aaaa")
        else "bbbb"
    )
    assert not JwsJsonGeneral(altered_jws).verify_signature(
        verification_jwk, alg=signature_alg
    )


def test_jws_format_transformation(
    signed_jws_compact: JwsCompact,
    signed_jws_json_flat: JwsJsonFlat,
    signed_jws_json_general: JwsJsonGeneral,
    signature_alg: str,
) -> None:
    # signature is not deterministic for those algs, so those comparisons will fail
    if signature_alg not in (
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
    ):
        assert signed_jws_compact.flat_json() == signed_jws_json_flat
        assert signed_jws_compact.general_json() == signed_jws_json_general
        assert signed_jws_json_flat.generalize() == signed_jws_json_general
        assert signed_jws_json_general.flatten() == signed_jws_json_flat
        assert signed_jws_json_flat.compact() == signed_jws_compact


def test_verify_signature_by_jwcrypto(
    signed_jws_compact: JwsCompact, verification_jwk: Jwk, signature_alg: str
) -> None:
    """This test verifies tokens generated by `jwskate` using another lib `jwcrypto`.

    Args:
        signed_jws_compact: the Jws signed by jwskate to verify
        verification_jwk: the Jwk containing the verification key
        signature_alg: the signature alg
    """
    import jwcrypto.jwk  # type: ignore[import]
    import jwcrypto.jws  # type: ignore[import]

    jwk = jwcrypto.jwk.JWK(**verification_jwk)
    jws = jwcrypto.jws.JWS()
    jws.deserialize(str(signed_jws_compact))
    jws.verify(jwk)


@pytest.fixture()
def jwcrypto_signed_jws(
    signature_payload: bytes, signature_jwk: Jwk, signature_alg: str
) -> str:
    """Sign a JWS using `jwcrypto`, to make sure it verifies with `jwskate`.

    Args:
        signature_payload: the payload to sign
        signature_jwk: the key to use
        signature_alg: the alg to use

    Returns:
        a JWS token
    """
    import jwcrypto.jwk
    import jwcrypto.jws

    jwk = jwcrypto.jwk.JWK(**signature_jwk)
    jws = jwcrypto.jws.JWS(signature_payload)

    jws.add_signature(
        jwk,
        alg=signature_alg,
        protected=BinaPy.serialize_to("json", {"alg": signature_alg}).decode(),
    )
    token: str = jws.serialize(True)
    return token


def test_verify_signature_from_jwcrypto(
    jwcrypto_signed_jws: str, verification_jwk: Jwk, signature_alg: str
) -> None:
    """Check that `jwskate` verifies tokens signed by `jwcrypto`.

    Args:
        jwcrypto_signed_jws: the JWS to verify
        verification_jwk: the public key to verify the signature
        signature_alg: the alg to use
    """
    assert JwsCompact(jwcrypto_signed_jws).verify_signature(
        verification_jwk, alg=signature_alg
    )


def test_invalid_jws_compact() -> None:
    with pytest.raises(ValueError):
        JwsCompact(
            "ey.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cOUKU1ijv3KiN2KK_o50RU978I9MzQ4lNw2y7nOGAdM"
        )
    with pytest.raises(ValueError):
        JwsCompact(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.!!.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
    with pytest.raises(ValueError):
        JwsCompact(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.!!"
        )


def test_invalid_jws_json() -> None:
    with pytest.raises(AttributeError):
        JwsJsonFlat({}).payload
    with pytest.raises(AttributeError):
        JwsJsonGeneral({}).payload
    with pytest.raises(AttributeError):
        JwsJsonGeneral({}).signatures
