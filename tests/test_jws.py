import pytest

from jwskate import ECJwk, Jwk, JwsCompact, RSAJwk, SymmetricJwk


def test_jws_compact(private_jwk: Jwk) -> None:
    jws = JwsCompact.sign(payload=b"Hello World!", jwk=private_jwk, alg="RS256")
    assert (
        str(jws)
        == "eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXSy1BQkNEIn0.SGVsbG8gV29ybGQh.1eucS9ZaTnAJyfVNhxLJ_phFN1rexm0l-nIXWBjUImdS29z55BuxH6NjGpltSXKrgYxYQxqGCsGIxlSVoIEhKVdhE1Vd9NPJRyw7I4zBRdwVvcqMRODMqDxCiqbDQ_5bI5jAqFEJAFCXZo2T4ixlxs-2eXtmSEp6vX51Tg1pvicM5_YrKfS8Jn3lt9xW5RaNKUJ94KVLlov_IncFsh2bg5jdo1SEoUxlB2II0JdlfCsgHohJd58eWjFToeNtH1eiXGeZOHblMLz5a5AhY8jY3C424-tggj6BK6fwpedddFD3mtFFTNw6KT-2EgTeOlEA09pQqW5hosCj2duAlR-FQQ"
    )
    assert jws.verify_signature(private_jwk, alg="RS256")


EC_PRIVATE_KEY = {
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

SYMMETRIC_SIGNATURE_KEY = {
    "kty": "oct",
    "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
    "use": "sig",
    "alg": "HS256",
    "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
}


@pytest.fixture
def ec_private_jwk() -> Jwk:
    """[https://datatracker.ietf.org/doc/html/rfc7520#section-3.2]"""
    jwk = Jwk(EC_PRIVATE_KEY)
    assert isinstance(jwk, ECJwk)
    assert jwk.is_private
    assert jwk.kty == "EC"
    assert jwk.kid == "bilbo.baggins@hobbiton.example"
    assert jwk.use == "sig"
    assert jwk.curve == "P-521"
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


@pytest.fixture
def rsa_private_jwk() -> Jwk:
    """[https://datatracker.ietf.org/doc/html/rfc7520#section-3.4]"""
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


@pytest.fixture()
def symmetric_signature_jwk() -> Jwk:
    """[https://datatracker.ietf.org/doc/html/rfc7520#section-3.5]"""
    jwk = Jwk(SYMMETRIC_SIGNATURE_KEY)
    assert isinstance(jwk, SymmetricJwk)
    assert jwk.is_private
    assert jwk.kty == "oct"
    assert jwk.kid == "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
    assert jwk.use == "sig"
    assert jwk.alg == "HS256"
    assert (
        jwk.key.hex()
        == "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"
    )
    assert jwk.key_size == 32 * 8
    return jwk


@pytest.fixture(scope="module")
def signature_payload() -> bytes:
    """[https://datatracker.ietf.org/doc/html/rfc7520#section-4]"""
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
    ]
)
def signature_alg(request: pytest.FixtureRequest) -> str:
    return request.param  # type: ignore[attr-defined,no-any-return]


@pytest.fixture()
@pytest.mark.parametrize("alg", [])
def signature_jwk(
    signature_alg: str,
    rsa_private_jwk: Jwk,
    ec_private_jwk: Jwk,
    symmetric_signature_jwk: Jwk,
) -> Jwk:
    if signature_alg in rsa_private_jwk.supported_signing_algorithms:
        return rsa_private_jwk
    if signature_alg in ec_private_jwk.supported_signing_algorithms:
        return ec_private_jwk
    if signature_alg in symmetric_signature_jwk.supported_signing_algorithms:
        return symmetric_signature_jwk

    pytest.skip("Unsupported signature alg: {signature_alg}")


@pytest.fixture()
def validation_jwk(signature_jwk: Jwk) -> Jwk:
    if isinstance(signature_jwk, SymmetricJwk):
        return signature_jwk
    public_jwk = signature_jwk.public_jwk()
    assert not public_jwk.is_private
    assert signature_jwk.kty == public_jwk.kty
    return public_jwk


@pytest.fixture()
def signed_jws(
    signature_payload: bytes, signature_jwk: Jwk, signature_alg: str
) -> JwsCompact:
    """[https://datatracker.ietf.org/doc/html/rfc7520#section-4]"""
    jws = JwsCompact.sign(
        payload=signature_payload, jwk=signature_jwk, alg=signature_alg
    )
    assert isinstance(jws, JwsCompact)
    return jws


def test_validate_signature(
    signed_jws: JwsCompact, validation_jwk: Jwk, signature_alg: str
) -> None:
    assert signed_jws.verify_signature(validation_jwk, signature_alg)


def test_validate_signature_by_jwcrypto(
    signed_jws: JwsCompact, validation_jwk: Jwk, signature_alg: str
) -> None:
    """
    This test verifies tokens generated by `jwskate` using another lib `jwcrypto`.
    :param signed_jws: the Jws signed by jwskate to verify
    :param validation_jwk: the Jwk containing the verification key
    :param signature_alg: the signature alg
    """
    import jwcrypto.jwk  # type: ignore[import]
    import jwcrypto.jws  # type: ignore[import]

    jwk = jwcrypto.jwk.JWK(**validation_jwk)
    jws = jwcrypto.jws.JWS()
    jws.deserialize(str(signed_jws))
    jws.verify(jwk)


@pytest.fixture()
def jwcrypto_signed_jws(
    signature_payload: bytes, signature_jwk: Jwk, signature_alg: str
) -> str:
    """
    Sign a JWS using `jwcrypto`, to make sure it validates with `jwskate`.
    :param signature_payload: the payload to sign
    :param signature_jwk: the key to use
    :param signature_alg: the alg to use
    :return: a JWS token
    """
    import jwcrypto.jwk
    import jwcrypto.jws

    jwk = jwcrypto.jwk.JWK(**signature_jwk)
    jws = jwcrypto.jws.JWS(signature_payload)
    from jwskate.utils import json_encode

    jws.add_signature(
        jwk, alg=signature_alg, protected=json_encode({"alg": signature_alg})
    )
    token: str = jws.serialize(True)
    return token


def test_validate_signature_from_jwcrypto(
    jwcrypto_signed_jws: str, validation_jwk: Jwk, signature_alg: str
) -> None:
    """
    Check that `jwskate`validates tokens signed by `jwcrypto`.
    :param jwcrypto_signed_jws: the JWS to validate
    :param validation_jwk: the public key to validate the signature
    :param signature_alg: the alg to use
    """
    assert JwsCompact(jwcrypto_signed_jws).verify_signature(
        validation_jwk, signature_alg
    )
