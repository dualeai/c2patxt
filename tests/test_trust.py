"""Certificate profile checks and the trust seam that ships empty."""

from __future__ import annotations

import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from c2patxt import verify
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from c2patxt.trust import (
    NoTrustEvaluator,
    ProfileError,
    TrustEvaluator,
    check_claim_signing_profile,
    load_anchors,
)
from c2patxt.verdict import Provenance
from tests.conftest import build_certificate


def test_a_conformant_certificate_passes(signing_certificate: x509.Certificate) -> None:
    check_claim_signing_profile(signing_certificate)


def test_a_default_openssl_style_certificate_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    """THE case to catch: cA asserted and no EKU.

    Terraform's tls_self_signed_cert produces exactly this by default. It yields
    signingCredential.INVALID -- a hard reject where the manifest is not even Valid
    -- rather than the signingCredential.untrusted a self-signed credential is
    supposed to produce. The difference is the whole point of the check.
    """
    certificate = build_certificate(signing_key, conformant=False)
    with pytest.raises(ProfileError, match="must not assert cA"):
        check_claim_signing_profile(certificate)


def test_a_certificate_without_an_eku_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    """14.5.1.1: the EKU extension shall be present and non-empty."""
    certificate = _build(signing_key, ca=False, ekus=None)
    with pytest.raises(ProfileError, match="non-empty EKU"):
        check_claim_signing_profile(certificate)


def test_any_extended_key_usage_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    """14.5.1.1: anyExtendedKeyUsage (2.5.29.37.0) shall not be present."""
    from cryptography.x509.oid import ExtendedKeyUsageOID

    certificate = _build(
        signing_key,
        ca=False,
        ekus=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE, x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")],
    )
    with pytest.raises(ProfileError, match="anyExtendedKeyUsage"):
        check_claim_signing_profile(certificate)


def test_the_claim_signing_eku_is_a_trust_input_not_a_profile_rule(signing_key: Ed25519PrivateKey) -> None:
    """THIS TEST USED TO ASSERT THE OPPOSITE, and the opposite was wrong.

    It required ``c2pa-kp-claimSigning`` and cited 14.4.1. 14.5.1.1 -- the clause that
    actually defines the profile -- names no required OID, and 14.4.1 is addressed to
    validators about their own trust-anchor configuration, explicitly anticipating
    ``id-kp-emailProtection`` and ``id-kp-documentSigning`` instead.

    So a leaf bearing the EKU passes, and so does one without it. What the OID governs is
    which trust anchors a deployment associates with the credential (14.5.1.2), which is
    the ``TrustEvaluator`` seam's question and not the profile's -- and with no anchors
    shipped, our accepted-EKU list is empty and the question decides nothing.

    Both rows are here because the change is easy to over-apply in the other direction:
    a certificate carrying claimSigning must still be accepted, and the EKU rules that
    ARE in 14.5.1.1 -- present, non-empty, no ``anyExtendedKeyUsage``, the exclusivity
    rule -- are all still enforced and tested above.
    """
    check_claim_signing_profile(_leaf(signing_key))
    check_claim_signing_profile(_leaf(signing_key, extended_key_usage=("1.3.6.1.5.5.7.3.4",)))


def test_unknown_ekus_do_not_cause_rejection(signing_key: Ed25519PrivateKey) -> None:
    """14.5.1.1 says so explicitly. Over-strictness is a conformance bug too."""
    from cryptography.x509.oid import ExtendedKeyUsageOID

    certificate = _build(
        signing_key,
        ca=False,
        ekus=[x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1"), ExtendedKeyUsageOID.EMAIL_PROTECTION],
    )
    check_claim_signing_profile(certificate)


def test_key_cert_sign_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    certificate = _build(
        signing_key, ca=False, ekus=[x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")], key_cert_sign=True
    )
    with pytest.raises(ProfileError, match="keyCertSign"):
        check_claim_signing_profile(certificate)


def test_the_default_evaluator_trusts_nothing(signing_certificate: x509.Certificate) -> None:
    """Not a stub: with no anchors bundled there is genuinely nothing to chain to."""
    evaluator = NoTrustEvaluator()
    assert isinstance(evaluator, TrustEvaluator)
    assert evaluator.is_trusted([signing_certificate], [signing_certificate]) is False


def test_no_anchors_ship_by_default() -> None:
    """The shipped default. Verification reaches Valid, never Trusted."""
    assert load_anchors() == []


def test_anchors_can_be_supplied_directly(signing_certificate: x509.Certificate) -> None:
    pem = signing_certificate.public_bytes(Encoding.PEM)
    anchors = load_anchors(pem)
    assert len(anchors) == 1
    assert anchors[0].public_bytes(Encoding.PEM) == pem


def test_an_explicit_empty_bundle_means_no_anchors() -> None:
    """ "No anchors" must be expressible without tripping the PEM parser."""
    assert load_anchors(b"") == []
    assert load_anchors(b"   \n  ") == []


def test_the_environment_cannot_supply_anchors(
    signing_certificate: x509.Certificate, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE ENVIRONMENT IS NOT A CHANNEL, and this pins it shut.

    A C2PATXT_TRUST_ANCHORS fallback existed until 2026-08-05. It falsified the "no
    ambient configuration" promise made in the package docstring, in VerifyContext
    and in SECURITY.md; a missing or malformed path raised straight out of verify(),
    which promises never to raise; and because the read happened only on the
    signature-valid path, unmarked and invalid text verified fine while VALID text
    crashed. A trust decision that depends on a process environment variable is also
    neither reproducible nor auditable.
    """
    bundle = tmp_path / "anchors.pem"
    bundle.write_bytes(signing_certificate.public_bytes(Encoding.PEM))
    monkeypatch.setenv("C2PATXT_TRUST_ANCHORS", str(bundle))

    assert load_anchors() == []


def test_a_hostile_anchors_variable_cannot_break_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact bomb that fires on the happy path only.

    Both of these raised -- FileNotFoundError and a PEM MalformedFraming ValueError --
    from inside verify(), and ONLY for text that was otherwise valid.
    """
    for value in ("/nonexistent/missing.pem", "not-a-path-at-all"):
        monkeypatch.setenv("C2PATXT_TRUST_ANCHORS", value)
        assert load_anchors() == []


def _build(
    key: Ed25519PrivateKey,
    *,
    ca: bool,
    ekus: list[x509.ObjectIdentifier] | None,
    key_cert_sign: bool = False,
) -> x509.Certificate:
    """Build a certificate with precise control over the profile-relevant extensions."""
    import datetime

    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "profile test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        # Pinned, like conftest's. A random serial makes every certificate in a run
        # differ, which is exactly the seed that turned the fixpoint's build count
        # into an intermittent failure. Nothing here compares serials.
        .serial_number(0xC2A7E47_7A057)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if ekus is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
    return builder.sign(key, None)


# --- C2PA 14.5.1.1, the parts we did not check until 2026-08-05 -----------------


def _leaf(signing_key: Ed25519PrivateKey, **kwargs: object) -> x509.Certificate:
    """A conformant leaf with one property varied. Keeps each case to its own line."""
    return build_certificate(signing_key, **kwargs)  # pyright: ignore[reportArgumentType] -- kwargs are the builder's


def test_the_key_usage_extension_must_be_present(signing_key: Ed25519PrivateKey) -> None:
    """14.5.1.1: "the Key Usage extension shall be present and should be marked as
    critical."

    We treated an absent KeyUsage as acceptable -- ``usage = None`` and carry on --
    because the only thing we read it for was the keyCertSign prohibition, and a
    certificate with no KeyUsage cannot assert keyCertSign. That reasoning is right
    about keyCertSign and wrong about the clause: presence is required in its own
    right.
    """
    certificate = _leaf(signing_key, key_usage=None)
    with pytest.raises(ProfileError, match="Key Usage extension"):
        check_claim_signing_profile(certificate)


def test_the_digital_signature_bit_must_be_asserted(signing_key: Ed25519PrivateKey) -> None:
    """14.5.1.1: "Certificates used to sign C2PA manifests shall assert the
    digitalSignature bit."

    A certificate asserting only, say, contentCommitment is one whose issuer did NOT
    authorize it to produce the signatures we are about to accept.
    """
    certificate = _leaf(signing_key, digital_signature=False)
    with pytest.raises(ProfileError, match="digitalSignature"):
        check_claim_signing_profile(certificate)


@pytest.mark.parametrize(
    "purpose",
    ["1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.9"],
    ids=["timeStamping", "OCSPSigning"],
)
def test_a_claim_signing_certificate_may_not_also_sign_timestamps_or_ocsp(
    signing_key: Ed25519PrivateKey, purpose: str
) -> None:
    """14.5.1.1: "If a certificate is valid for either id-kp-timeStamping or
    id-kp-OCSPSigning, it shall be valid for exactly one of those two purposes, and not
    valid for any other purpose." 14.5.1.2 restates it as a validator obligation: "a
    certificate being authorized for no more than one of the three purposes listed in
    this section: C2PA signing, time-stamp signing, or OCSP response signing."

    ``check_claim_signing_profile``'s docstring said these rules "govern certificate
    roles we never validate" and skipped them. THAT READING WAS BACKWARDS. The rule
    does not ask us to validate a time-stamping certificate; it constrains the
    claim-signing certificate IN OUR HANDS, and the certificate in our hands is
    exactly the one we are obliged to check. A credential that can both sign claims
    and mint the time-stamps attesting to when those claims were signed is the
    separation-of-duties failure the clause exists to prevent.
    """
    certificate = _leaf(signing_key, extra_ekus=(purpose,))
    with pytest.raises(ProfileError, match="exactly one"):
        check_claim_signing_profile(certificate)


def test_an_unrelated_extra_eku_is_still_accepted(signing_key: Ed25519PrivateKey) -> None:
    """The other half of the same clause, and the reason the check above is narrow.

    14.5.1.1: "the presence of any EKUs not mentioned in this profile and not in the
    list of EKUs in the configuration store shall not cause the certificate to be
    rejected."

    Over-strictness is as much a conformance bug as under-strictness -- it is the
    defect class docs/known-divergences.md catalogues in five other implementations,
    pointed at ourselves. ``emailProtection`` is unrelated to all three C2PA purposes
    and must pass.
    """
    check_claim_signing_profile(_leaf(signing_key, extra_ekus=("1.3.6.1.5.5.7.3.4",)))


def test_the_certificate_version_must_be_v3(signing_certificate: x509.Certificate) -> None:
    """14.5.1.1: "Version shall be v3 as per RFC 5280, section 4.1.2.1."

    ``cryptography``'s builder always emits v3, so v1 has to be produced by editing
    the DER -- and v1 is the one case that CANNOT be produced by an in-place byte
    swap. v1 is the field's DEFAULT, DER forbids encoding a default, so ``02 01 00``
    is not merely wrong but unparseable (``rust-asn1`` rejects it with ``ParseError {
    kind: EncodedDefault }``). v2 is no better: it encodes legally, but
    ``cryptography``'s ``Version`` enum has only v1 and v3 and raises ``InvalidVersion``
    before our code sees it.

    So the ``[0] EXPLICIT`` element is REMOVED and both enclosing SEQUENCE lengths are
    re-encoded, which is what a genuine v1 certificate looks like. The signature no
    longer verifies over the shortened bytes, which does not matter: profile checking
    is structural and runs before any chain is built.
    """
    version_field = b"\xa0\x03\x02\x01\x02"
    der = signing_certificate.public_bytes(Encoding.DER)
    assert der.count(version_field) == 1, "the version field must be uniquely locatable"

    tbs_start, outer_end = _der_contents(der, 0)
    body_start, tbs_end = _der_contents(der, tbs_start)
    assert der[body_start : body_start + len(version_field)] == version_field, "version is the first TBS member"

    tbs = _sequence(der[body_start + len(version_field) : tbs_end])
    downgraded = x509.load_der_x509_certificate(_sequence(tbs + der[tbs_end:outer_end]))

    assert downgraded.version is x509.Version.v1
    with pytest.raises(ProfileError, match="v3"):
        check_claim_signing_profile(downgraded)


@pytest.mark.parametrize(
    ("tag", "name"),
    [(0x81, "issuerUniqueID"), (0x82, "subjectUniqueID")],
    ids=["issuerUniqueID", "subjectUniqueID"],
)
def test_the_tbs_unique_id_fields_must_be_absent(signing_certificate: x509.Certificate, tag: int, name: str) -> None:
    """14.5.1.1: "The issuerUniqueID and subjectUniqueID optional fields of the
    TBSCertificate sequence shall not be present, as per RFC 5280, section 4.1.2.8."

    ``cryptography`` exposes no accessor for either field -- they are legacy v2
    syntax it declines to surface -- so this is the one profile rule that requires
    walking the DER ourselves. The walk stays at the TOP LEVEL of the TBSCertificate
    SEQUENCE, where the tags ``[1]`` and ``[2]`` are unambiguous; it never descends,
    so a ``0x81`` occurring as a length byte inside a nested structure cannot be
    mistaken for a field.

    The fixture is a genuine certificate with a genuine field spliced in and the outer
    SEQUENCE length corrected, not a hand-written stub, so the walk is exercised
    against real issuer, validity and SPKI encodings rather than a shape chosen to
    suit it.
    """
    from c2patxt.trust import (
        _tbs_carries_unique_ids,  # pyright: ignore[reportPrivateUsage] -- no public caller accepts raw TBS bytes
    )

    tbs = signing_certificate.tbs_certificate_bytes
    assert _tbs_carries_unique_ids(tbs) is False

    body_start, end = _der_contents(tbs, 0)
    extensions = tbs.index(b"\xa3", body_start)
    field = bytes([tag, 0x02, 0x00, 0xFF])
    spliced = _sequence(tbs[body_start:extensions] + field + tbs[extensions:end])

    assert len(spliced) == len(tbs) + len(field), f"only {name} was added"
    assert _tbs_carries_unique_ids(spliced) is True


def _der_contents(encoded: bytes, offset: int) -> tuple[int, int]:
    """``(contents_start, element_end)`` for the DER element at ``offset``.

    Deliberately a SECOND implementation, not an import of ``trust._der_contents``.
    Checking a parser against itself proves only that it is self-consistent, and these
    tests exist to hold that parser to the encoding rather than to its own habits.
    """
    length_start = offset + 2
    first = encoded[offset + 1]
    if first < 0x80:
        return length_start, length_start + first
    count = first & 0x7F
    length = int.from_bytes(encoded[length_start : length_start + count], "big")
    return length_start + count, length_start + count + length


def _der_length(length: int) -> bytes:
    """Encode a DER length, short form where it fits."""
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body), *body])


def _sequence(contents: bytes) -> bytes:
    """Wrap ``contents`` in a DER SEQUENCE header of the right length."""
    return bytes([0x30, *_der_length(len(contents))]) + contents


def test_the_authority_key_identifier_is_required_only_when_not_self_signed(
    signing_key: Ed25519PrivateKey,
) -> None:
    """14.5.1.1: "The Authority Key Identifier extension shall be present in any
    certificate that is not self-signed, as per RFC 5280, section 4.2.1.1."

    BOTH DIRECTIONS MATTER. Our own test credential is self-signed and carries no AKI,
    so a check that simply required the extension would reject the package's own
    fixture -- and, more to the point, would reject the self-signed credential C2PA
    expects to reach ``signingCredential.untrusted`` rather than
    ``signingCredential.invalid``.

    "Self-signed" is decided here by issuer == subject. That is self-ISSUED strictly
    speaking; a certificate self-issued but signed by a different key is pathological
    and, being a leaf, would fail chain building anyway.
    """
    check_claim_signing_profile(_leaf(signing_key))

    issued = _leaf(signing_key, issuer_name="some other issuer")
    with pytest.raises(ProfileError, match="Authority Key Identifier"):
        check_claim_signing_profile(issued)

    check_claim_signing_profile(_leaf(signing_key, issuer_name="some other issuer", authority_key_identifier=True))


def test_the_signature_algorithm_must_be_one_the_profile_lists(signing_certificate: x509.Certificate) -> None:
    """14.5.1.1 lists eight permitted values for "the algorithm field of the
    signatureAlgorithm field": three ECDSA, three PKCS#1 v1.5, RSASSA-PSS, and Ed25519.

    THIS IS THE ISSUER'S SIGNATURE, NOT OURS. 13.2.1 already restricts the key we
    verify the CLAIM with to Ed25519; this restricts the algorithm the CERTIFICATE was
    signed with by its issuer, which is a different signature made by a different key.
    A certificate signed with SHA-1 tells us about the issuer's practices no matter how
    strong the subject key is.

    THE CASE EXERCISED IS Ed448, and it is chosen to make the point that this is an
    ALLOWLIST rather than a weak-algorithm blocklist. Ed448 is stronger than Ed25519
    and the profile still does not list it, so it must be refused -- a check written as
    "reject SHA-1 and MD5" would pass this certificate and be wrong. It is also the
    only substitution available byte-for-byte: 1.3.101.113 encodes as ``2B 65 71``
    against Ed25519's ``2B 65 70``, so the edit disturbs no length header.

    The FIRST and LAST occurrences are rewritten -- ``TBSCertificate.signature`` and
    the outer ``signatureAlgorithm``, which RFC 5280 requires to agree. The middle one
    is left alone: it is the SubjectPublicKeyInfo algorithm, and rewriting it would
    relabel a 32-byte Ed25519 key as Ed448 and fail to parse at all.
    """
    from cryptography.x509.oid import SignatureAlgorithmOID

    from c2patxt.trust import PERMITTED_SIGNATURE_ALGORITHMS

    permitted = 8
    assert len(PERMITTED_SIGNATURE_ALGORITHMS) == permitted
    assert SignatureAlgorithmOID.ED25519 in PERMITTED_SIGNATURE_ALGORITHMS
    assert SignatureAlgorithmOID.RSA_WITH_SHA1 not in PERMITTED_SIGNATURE_ALGORITHMS

    der = signing_certificate.public_bytes(Encoding.DER)
    ed25519, ed448 = b"\x06\x03\x2b\x65\x70", b"\x06\x03\x2b\x65\x71"
    occurrences = 3
    assert der.count(ed25519) == occurrences, "expected TBS.signature, SPKI.algorithm and signatureAlgorithm"

    first = der.index(ed25519)
    last = der.rindex(ed25519)
    edited = der[:first] + ed448 + der[first + len(ed25519) : last] + ed448 + der[last + len(ed25519) :]
    assert len(edited) == len(der)

    certificate = x509.load_der_x509_certificate(edited)
    assert certificate.signature_algorithm_oid == SignatureAlgorithmOID.ED448
    with pytest.raises(ProfileError, match="signatureAlgorithm"):
        check_claim_signing_profile(certificate)


def test_a_certificate_carrying_a_unique_id_is_rejected(signing_certificate: x509.Certificate) -> None:
    """The same rule as above, driven end to end through the public entry point.

    Splicing ``issuerUniqueID`` into the TBSCertificate and re-encoding both enclosing
    SEQUENCE lengths produces a certificate ``cryptography`` parses without complaint
    -- it does not surface the field, so it does not object to it either -- which is
    precisely why the rejection has to be ours.
    """
    der = signing_certificate.public_bytes(Encoding.DER)
    tbs_start, outer_end = _der_contents(der, 0)
    body_start, tbs_end = _der_contents(der, tbs_start)
    extensions = der.index(b"\xa3", body_start)

    tbs = _sequence(der[body_start:extensions] + b"\x81\x02\x00\xff" + der[extensions:tbs_end])
    certificate = x509.load_der_x509_certificate(_sequence(tbs + der[tbs_end:outer_end]))

    with pytest.raises(ProfileError, match="issuerUniqueID"):
        check_claim_signing_profile(certificate)


@pytest.mark.parametrize(
    "tbs",
    [
        b"\x30\x80\x02\x01\x02",
        b"\x30\x06\x02\x7f\x00\x00",
        b"\x30\x03\x02\x01",
        b"\x30\x04\x02",
        b"\x30",
        b"",
    ],
    ids=[
        "indefinite-length",
        "length-past-end",
        "length-past-end-by-one",
        "truncated-member",
        "header-only",
        "empty",
    ],
)
def test_an_unwalkable_tbs_fails_closed(tbs: bytes) -> None:
    """A DER walk that cannot complete must REJECT, not shrug.

    ``cryptography``'s parser is DER-strict and has already accepted any certificate
    that reaches us, so a walk that fails means OUR reading of the encoding is wrong
    rather than the certificate's. For a function whose entire job is to reject, the
    safe direction is to reject: returning ``False`` on a confusing encoding would
    make "I could not tell" indistinguishable from "the field is absent", and would
    turn any parser disagreement into a bypass.

    ``indefinite-length`` is the case worth naming: BER permits ``0x80`` as a length
    and DER forbids it, so a walker that treated it as a long-form count would read
    zero length bytes, compute a zero-length element, and loop forever on the same
    offset.

    ``length-past-end-by-one`` exists because ``length-past-end`` alone did not hold the
    bound. That vector overruns by TWO bytes, so loosening ``end > len(encoded)`` to
    ``end > len(encoded) + 1`` -- an off-by-one, and the likeliest way to get a
    hand-rolled length check wrong -- still tripped it, and the mutation survived the
    whole suite. A one-byte overrun walks to completion under that mutant and returns
    "no unique identifiers", turning the one function here that is supposed to FAIL
    CLOSED into one that fails open. A boundary test that sits two units from the
    boundary is not a boundary test.
    """
    from c2patxt.trust import (
        _tbs_carries_unique_ids,  # pyright: ignore[reportPrivateUsage] -- no public caller accepts raw TBS bytes
    )

    with pytest.raises(ProfileError, match="could not be walked"):
        _tbs_carries_unique_ids(tbs)


def test_basic_constraints_may_be_absent_entirely(signing_key: Ed25519PrivateKey) -> None:
    """14.5.1.1 gates the EKU requirement on "any certificate where the Basic
    Constraints extension is ABSENT or the cA boolean is not asserted".

    Absent is one of the two legal ways of not being a CA, and treating it as a
    rejection would refuse a conforming leaf. This is the branch that reads the
    extension and, not finding it, concludes ``is_ca = False``.
    """
    check_claim_signing_profile(_leaf(signing_key, basic_constraints=False))


def test_an_unparseable_extension_set_is_a_profile_violation_not_a_crash(signing_key: Ed25519PrivateKey) -> None:
    """14.5.1.1 says the EKU extension "shall be present and NON-EMPTY". RFC 5280
    declares ``ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId``, so an
    empty one is legal to BUILD and illegal to READ.

    AN EARLIER VERSION OF THIS TEST ASSERTED THE CRASH AND CALLED IT SETTLED. It expected
    ``pytest.raises(ValueError, match="InvalidSize")`` and reasoned that the failure
    happens "before any of our code runs", so "a branch for it would be permanently
    unexecuted code". The reasoning was wrong about WHERE the failure lands.

    ``cryptography`` parses extensions LAZILY, so one malformed extension poisons the
    whole set: the first ``get_extension_for_class`` raises whichever extension it asks
    for. That call is inside ``check_claim_signing_profile``, which sits on the
    verification path, and the certificate arrives in the COSE ``x5chain`` -- from the
    wire. So ``verify()`` raised ``ValueError`` on attacker-controlled text, against a
    documented promise never to raise for absent, corrupt or invalid marks, and this test
    is what made that look intended.

    ``signingCredential.invalid`` is the honest answer: a credential we cannot parse is
    one we cannot accept, and the profile is exactly what it fails.
    """
    certificate = _leaf(signing_key, extended_key_usage=())

    with pytest.raises(ProfileError, match="could not be parsed"):
        check_claim_signing_profile(certificate)


@pytest.mark.parametrize(
    "ekus",
    [
        ("1.3.6.1.5.5.7.3.4",),
        ("1.3.6.1.5.5.7.3.36",),
        ("1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.36"),
    ],
    ids=["emailProtection", "documentSigning", "both-of-the-older-pair"],
)
def test_a_leaf_without_claim_signing_still_satisfies_the_profile(
    signing_key: Ed25519PrivateKey, ekus: tuple[str, ...]
) -> None:
    """14.5.1.1 names NO required EKU OID. Its rules are exhaustively: present and
    non-empty on a non-CA certificate, no ``anyExtendedKeyUsage``, the
    timeStamping/OCSPSigning exclusivity rule, and "the presence of any EKUs not
    mentioned in this profile ... shall not cause the certificate to be rejected".

    WE DEMANDED ``c2pa-kp-claimSigning`` AND CITED 14.4.1 FOR IT. That clause is
    addressed to validators, about their own configuration -- "For each accepted EKU
    value, a list of trust anchor configurations" -- and it explicitly anticipates
    others: a validator "should allow a user to configure additional trust anchor
    configurations for that EKU **and/or for other EKUs** (e.g., `id-kp-emailProtection`
    ... or `id-kp-documentSigning`)".

    THE INSTALLED BASE IS THE POINT, and the specification says so in the same paragraph:
    "Previous versions of this specification required the presence of
    `id-kp-emailProtection` or `id-kp-documentSigning` EKUs, so including at least one of
    those two EKUs in a signer's certificate ... can improve compatibility with older
    validators." `c2pa-kp-claimSigning` is new at 2.2. Every signing certificate issued
    before it carries the older pair alone, and we were answering
    ``signingCredential.invalid`` -- a HARD reject, where the manifest is not even
    Valid -- for all of them.

    The decisive argument is our own configuration rather than the wording. 14.5.1.2
    requires "at least one of the EKUs **for which the validator has an associated list
    of trust anchors**", and we ship none, so our accepted-EKU list is empty and the EKU
    question decides nothing about validity. It is a trust question, and the honest
    answer for a credential we cannot anchor is ``untrusted``.
    """
    check_claim_signing_profile(_leaf(signing_key, extended_key_usage=ekus))


def test_a_leaf_without_claim_signing_verifies_as_valid_but_untrusted(signing_key: Ed25519PrivateKey) -> None:
    """The end-to-end consequence, which is the whole reason the profile change matters.

    A certificate carrying only the pre-2.2 EKUs must reach C2PA state *Valid* with
    ``signingCredential.untrusted`` -- not ``signingCredential.invalid``. The difference
    is whether a third party's mark is readable at all.
    """
    from tests.conftest import build_certificate, mark

    certificate = build_certificate(signing_key, extended_key_usage=("1.3.6.1.5.5.7.3.4",))
    signer = Signer(private_key=signing_key, certificates=(certificate,))

    verdict = verify(mark("Hello world.", signer))

    assert verdict.state is Provenance.VALID
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED in verdict.codes()
    assert StatusCode.SIGNING_CREDENTIAL_INVALID not in verdict.codes()


def test_a_unique_id_tag_in_the_last_byte_is_still_seen() -> None:
    """The walk's loop bound, which ``while offset < end`` → ``< end - 1`` survived.

    Every well-formed DER element is at least two bytes, so the last member's offset is
    always at most ``end - 2`` and the two bounds agree -- EXCEPT when the SEQUENCE
    contents end in a lone one-byte remnant. ``30 04 | 02 01 00 | 81`` is that case: a
    complete INTEGER followed by a bare ``[1]`` tag byte.

    Not reachable through a certificate ``cryptography`` would parse. It is tested anyway
    because this function is ALREADY exercised on hand-built TBS bytes -- the fixture for
    ``test_the_tbs_unique_id_fields_must_be_absent`` splices bytes directly -- so the
    input class is one the suite already accepts, and an off-by-one in a hand-rolled
    parser is exactly what the neighbouring one-byte-overrun row exists for.
    """
    from c2patxt.trust import (
        _tbs_carries_unique_ids,  # pyright: ignore[reportPrivateUsage] -- no public caller accepts raw TBS bytes
    )

    assert _tbs_carries_unique_ids(b"\x30\x04\x02\x01\x00\x81") is True


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"conformant": False}, "must not assert cA"),
        ({"key_usage": False}, "Key Usage extension shall be present"),
        ({"digital_signature": False}, "shall assert the digitalSignature bit"),
        ({"extra_ekus": ("1.3.6.1.5.5.7.3.8",)}, "exactly one"),
    ],
    ids=["cA", "no-key-usage", "no-digital-signature", "timeStamping"],
)
def test_a_profile_violation_says_which_rule_failed(
    signing_key: Ed25519PrivateKey, kwargs: dict[str, object], expected: str
) -> None:
    """Every rule in ``_check_extensions`` must report ITSELF, not a parse failure.

    ``ProfileError`` subclasses ``ValueError``. When the extension accesses were wrapped
    in ``try/except ValueError`` -- so that a certificate ``cryptography`` cannot read
    becomes ``signingCredential.invalid`` instead of crashing ``verify()`` -- that
    handler also caught every GENUINE profile violation and re-labelled it "the
    certificate's extensions could not be parsed". For two hours a `cA` certificate, one
    with no Key Usage, and one without ``digitalSignature`` all reported as unparseable.

    THE EXISTING TESTS DID NOT NOTICE, and the reason is worth keeping: they assert with
    ``pytest.raises(..., match=...)`` on the inner text, and the wrapper PRESERVED the
    inner text by appending it. A substring match cannot see a wrong prefix. This test
    anchors the message start instead.

    ``ProfileError`` is now re-raised unchanged before the parse handler runs, and this
    is what holds that clause in place.
    """
    certificate = _leaf(signing_key, **kwargs)  # pyright: ignore[reportArgumentType] -- kwargs are build_certificate's

    with pytest.raises(ProfileError) as caught:
        check_claim_signing_profile(certificate)

    assert not str(caught.value).startswith("the certificate's extensions could not be parsed")
    assert expected in str(caught.value)
