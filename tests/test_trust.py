"""Certificate profile checks and the trust seam that ships empty."""

from __future__ import annotations

import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from c2patxt import verify
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from c2patxt.trust import (
    NoTrustEvaluator,
    ProfileError,
    TrustEvaluator,
    check_certificate_chain_profile,
    check_claim_signing_profile,
    load_anchors,
)
from c2patxt.verdict import Provenance
from tests.conftest import build_certificate

_PssHash = hashes.SHA224 | hashes.SHA256 | hashes.SHA384 | hashes.SHA512


def test_a_conformant_certificate_passes(signing_certificate: x509.Certificate) -> None:
    check_claim_signing_profile(signing_certificate)


def test_a_default_openssl_style_certificate_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    """THE case to catch: cA asserted and no EKU.

    A stock ``openssl req -x509`` certificate produces this shape. It yields
    signingCredential.INVALID -- a hard reject where the manifest is not even Valid
    -- rather than the signingCredential.untrusted a conformant self-signed credential
    produces. The difference is the whole point of the check.
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
    """14.5.1.1 names no single required claim-signing EKU OID.

    A leaf bearing the C2PA OID passes, and so does a leaf bearing an accepted legacy
    purpose. Trust-anchor association by EKU belongs to 14.5.1.2 and the
    ``TrustEvaluator`` seam. The profile still requires a present, non-empty EKU and
    enforces ``anyExtendedKeyUsage`` and purpose-separation rules.
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
    """Trust anchors come only from ``VerifyContext``, never the environment."""
    bundle = tmp_path / "anchors.pem"
    bundle.write_bytes(signing_certificate.public_bytes(Encoding.PEM))
    monkeypatch.setenv("C2PATXT_TRUST_ANCHORS", str(bundle))

    assert load_anchors() == []


def test_a_hostile_anchors_variable_cannot_break_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hostile ambient values do not enter the public trust path."""
    for value in ("/nonexistent/missing.pem", "not-a-path-at-all"):
        monkeypatch.setenv("C2PATXT_TRUST_ANCHORS", value)
        assert load_anchors() == []


def _build(
    key: Ed25519PrivateKey,
    *,
    ca: bool,
    ekus: list[x509.ObjectIdentifier] | None,
    key_cert_sign: bool = False,
    key_usage_critical: bool = True,
    authority_key_identifier: bool = False,
    authority_key_identifier_key: bool = True,
    authority_key_identifier_critical: bool = False,
    subject_key_identifier: bool = False,
    subject_key_identifier_critical: bool = False,
    issuer_key: Ed25519PrivateKey | None = None,
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
            critical=key_usage_critical,
        )
    )
    if authority_key_identifier:
        authority = (
            x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key())
            if authority_key_identifier_key
            else x509.AuthorityKeyIdentifier(
                key_identifier=None,
                authority_cert_issuer=[x509.DirectoryName(name)],
                authority_cert_serial_number=0xC2A7E47_1550,
            )
        )
        builder = builder.add_extension(
            authority,
            critical=authority_key_identifier_critical,
        )
    if subject_key_identifier:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=subject_key_identifier_critical,
        )
    if ekus is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
    return builder.sign(issuer_key or key, None)


# --- C2PA 14.5.1.1 certificate-profile rules ----------------------------------


def _leaf(signing_key: Ed25519PrivateKey, **kwargs: object) -> x509.Certificate:
    """A conformant leaf with one property varied. Keeps each case to its own line."""
    return build_certificate(signing_key, **kwargs)  # pyright: ignore[reportArgumentType] -- kwargs are the builder's


def test_the_key_usage_extension_must_be_present(signing_key: Ed25519PrivateKey) -> None:
    """14.5.1.1 requires a Key Usage extension."""
    certificate = _leaf(signing_key, key_usage=None)
    with pytest.raises(ProfileError, match="Key Usage extension"):
        check_claim_signing_profile(certificate)


def test_key_usage_need_not_be_critical(signing_key: Ed25519PrivateKey) -> None:
    """RFC 5280 says SHOULD, so making criticality a reject would be over-strict."""
    certificate = _build(
        signing_key,
        ca=False,
        ekus=[x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")],
        key_usage_critical=False,
    )

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

    Over-strictness is as much a conformance bug as under-strictness.
    ``emailProtection`` is unrelated to all three C2PA purposes and must pass.
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

    Equal issuer and subject names make a certificate self-issued, not self-signed.
    The signature must also verify under its own subject key before AKI may be absent.
    """
    check_claim_signing_profile(_leaf(signing_key))

    issued = _leaf(signing_key, issuer_name="some other issuer")
    with pytest.raises(ProfileError, match="Authority Key Identifier"):
        check_claim_signing_profile(issued)

    issuer_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    self_issued = _build(
        signing_key,
        ca=False,
        ekus=[x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")],
        issuer_key=issuer_key,
    )
    with pytest.raises(ProfileError, match="Authority Key Identifier"):
        check_claim_signing_profile(self_issued)

    check_claim_signing_profile(_leaf(signing_key, issuer_name="some other issuer", authority_key_identifier=True))


def test_authority_key_identifier_is_noncritical_even_on_a_self_signed_leaf(
    signing_key: Ed25519PrivateKey,
) -> None:
    certificate = _build(
        signing_key,
        ca=False,
        ekus=[x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")],
        authority_key_identifier=True,
        authority_key_identifier_critical=True,
    )

    with pytest.raises(ProfileError, match=r"Authority Key Identifier.*non-critical"):
        check_claim_signing_profile(certificate)


@pytest.mark.parametrize("role", ["issued-leaf", "carried-ca", "self-signed"], ids=str)
def test_a_present_authority_key_identifier_must_carry_key_identifier(
    signing_key: Ed25519PrivateKey,
    signing_certificate: x509.Certificate,
    role: str,
) -> None:
    """RFC 5280 permits a self-signed cert to omit AKI, not an empty keyIdentifier."""
    issuer_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    certificate = _build(
        signing_key,
        ca=role == "carried-ca",
        ekus=None if role == "carried-ca" else [x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")],
        key_cert_sign=role == "carried-ca",
        authority_key_identifier=True,
        authority_key_identifier_key=False,
        subject_key_identifier=role == "carried-ca",
        issuer_key=None if role == "self-signed" else issuer_key,
    )

    with pytest.raises(ProfileError, match="must include keyIdentifier"):
        if role == "carried-ca":
            check_certificate_chain_profile([signing_certificate, certificate])
        else:
            check_claim_signing_profile(certificate)


def test_a_lazy_carried_ca_parse_failure_is_indexed(
    signing_key: Ed25519PrivateKey,
    signing_certificate: x509.Certificate,
) -> None:
    """Malformed DER extensions must become ProfileError, not escape as ValueError."""
    ca = _build(
        signing_key,
        ca=True,
        ekus=[],
        key_cert_sign=True,
        subject_key_identifier=True,
    )
    loaded = x509.load_der_x509_certificate(ca.public_bytes(Encoding.DER))

    with pytest.raises(ProfileError, match=r"x5chain\[1\] carried CA could not be parsed"):
        check_certificate_chain_profile([signing_certificate, loaded])


@pytest.mark.parametrize(
    "patches",
    [
        [(39, 12, 0)],
        [(181, 0, 42), (188, 37, 15)],
        [(126, 43, 0)],
    ],
    ids=["issuer-key-error", "duplicate-extension", "unknown-spki"],
)
def test_lazy_leaf_parse_failures_are_translated_for_public_producer_apis(
    signing_key: Ed25519PrivateKey,
    signing_certificate: x509.Certificate,
    patches: list[tuple[int, int, int]],
) -> None:
    der = bytearray(signing_certificate.public_bytes(Encoding.DER))
    for offset, expected, replacement in patches:
        assert der[offset] == expected, "the fixed hostile-DER vector moved"
        der[offset] = replacement
    loaded = x509.load_der_x509_certificate(bytes(der))

    with pytest.raises(ProfileError, match="could not be parsed"):
        check_claim_signing_profile(loaded)
    with pytest.raises(ProfileError, match="could not be parsed"):
        Signer(private_key=signing_key, certificates=(loaded,))


def test_the_public_chain_profile_helper_rejects_an_empty_chain() -> None:
    with pytest.raises(ProfileError, match="no leaf certificate"):
        check_certificate_chain_profile([])


def test_an_unsupported_self_issued_key_becomes_a_profile_failure_not_type_error() -> None:
    """`verify_directly_issued_by` raises TypeError for a non-signing subject key."""
    import datetime

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    issuer_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    subject_key = X25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "self-issued, not self-signed")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(subject_key.public_key())
        .serial_number(0xC2A7E47_25519)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")]),
            critical=False,
        )
        .sign(issuer_key, None)
    )

    with pytest.raises(ProfileError, match="Authority Key Identifier"):
        check_claim_signing_profile(certificate)


def test_optional_leaf_subject_key_identifier_must_be_noncritical(
    signing_key: Ed25519PrivateKey,
) -> None:
    accepted = _build(
        signing_key,
        ca=False,
        ekus=[x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")],
        subject_key_identifier=True,
    )
    rejected = _build(
        signing_key,
        ca=False,
        ekus=[x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")],
        subject_key_identifier=True,
        subject_key_identifier_critical=True,
    )

    check_claim_signing_profile(accepted)
    with pytest.raises(ProfileError, match="Subject Key Identifier non-critical"):
        check_claim_signing_profile(rejected)


def test_the_signature_algorithm_must_be_one_the_profile_lists(signing_certificate: x509.Certificate) -> None:
    """14.5.1.1 lists eight permitted values for "the algorithm field of the
    signatureAlgorithm field": three ECDSA, three PKCS#1 v1.5, RSASSA-PSS, and Ed25519.

    THIS IS THE ISSUER'S SIGNATURE, NOT THE CLAIM'S. 13.2.1 governs the latter; this
    restricts the algorithm the CERTIFICATE was signed with by its issuer, which is a
    different signature made by a different key.
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

    assert (
        frozenset(
            {
                SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                SignatureAlgorithmOID.ECDSA_WITH_SHA384,
                SignatureAlgorithmOID.ECDSA_WITH_SHA512,
                SignatureAlgorithmOID.RSA_WITH_SHA256,
                SignatureAlgorithmOID.RSA_WITH_SHA384,
                SignatureAlgorithmOID.RSA_WITH_SHA512,
                SignatureAlgorithmOID.RSASSA_PSS,
                SignatureAlgorithmOID.ED25519,
            }
        )
        == PERMITTED_SIGNATURE_ALGORITHMS
    )

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


def _pss_signed_leaf(
    signing_key: Ed25519PrivateKey,
    hash_algorithm: _PssHash,
    mgf_hash_algorithm: _PssHash,
) -> x509.Certificate:
    """Build a profile-conforming leaf whose issuer signs it with RSASSA-PSS."""
    import datetime

    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "PSS leaf")])
    issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "PSS issuer")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(signing_key.public_key())
        .serial_number(0xC2A7E47_55)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.4.1.62558.2.1")]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .sign(
            issuer_key,
            hash_algorithm,
            rsa_padding=padding.PSS(
                mgf=padding.MGF1(mgf_hash_algorithm),
                salt_length=hash_algorithm.digest_size,
            ),
        )
    )


@pytest.mark.parametrize(
    "hash_algorithm",
    [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()],
    ids=["sha256", "sha384", "sha512"],
)
def test_permitted_matching_pss_hashes_are_accepted(
    signing_key: Ed25519PrivateKey,
    hash_algorithm: _PssHash,
) -> None:
    certificate = _pss_signed_leaf(signing_key, hash_algorithm, hash_algorithm)

    assert certificate.signature_algorithm_oid == x509.SignatureAlgorithmOID.RSASSA_PSS
    check_claim_signing_profile(certificate)


def test_a_pss_mgf_hash_must_match_the_signature_hash(signing_key: Ed25519PrivateKey) -> None:
    certificate = _pss_signed_leaf(signing_key, hashes.SHA256(), hashes.SHA384())

    with pytest.raises(ProfileError, match=r"MGF1 uses id-sha384, not hashAlgorithm id-sha256"):
        check_claim_signing_profile(certificate)


def test_a_pss_mask_generator_must_be_mgf1(signing_key: Ed25519PrivateKey) -> None:
    certificate = _pss_signed_leaf(signing_key, hashes.SHA256(), hashes.SHA256())
    encoded = certificate.public_bytes(Encoding.DER)
    mgf1 = bytes.fromhex("06092a864886f70d010108")
    other = bytes.fromhex("06092a864886f70d010109")
    assert encoded.count(mgf1) == 2, "fixture must carry MGF1 in both signatureAlgorithm fields"
    mutated = x509.load_der_x509_certificate(encoded.replace(mgf1, other))

    with pytest.raises(ProfileError, match="maskGenAlgorithm must be MGF1"):
        check_claim_signing_profile(mutated)


def test_a_pss_hash_outside_the_c2pa_allowlist_is_rejected(signing_key: Ed25519PrivateKey) -> None:
    certificate = _pss_signed_leaf(signing_key, hashes.SHA224(), hashes.SHA224())

    with pytest.raises(ProfileError, match=r"must be id-sha256, id-sha384, or id-sha512"):
        check_claim_signing_profile(certificate)


def _without_pss_parameter(certificate: x509.Certificate, field_tag: int) -> x509.Certificate:
    """Remove one explicit PSS field from both X.509 AlgorithmIdentifiers."""

    def strip(algorithm: bytes) -> bytes:
        algorithm_contents, algorithm_end = _der_contents(algorithm, 0)
        _, oid_end = _der_contents(algorithm, algorithm_contents)
        parameters_contents, parameters_end = _der_contents(algorithm, oid_end)
        assert algorithm_end == len(algorithm) and parameters_end == algorithm_end

        kept = bytearray()
        removed = False
        offset = parameters_contents
        while offset < parameters_end:
            _, field_end = _der_contents(algorithm, offset)
            if algorithm[offset] == field_tag:
                removed = True
            else:
                kept.extend(algorithm[offset:field_end])
            offset = field_end
        assert removed, f"fixture has no PSS field {field_tag:#x}"
        return _sequence(algorithm[algorithm_contents:oid_end] + _sequence(bytes(kept)))

    encoded = certificate.public_bytes(Encoding.DER)
    certificate_contents, certificate_end = _der_contents(encoded, 0)
    tbs_contents, tbs_end = _der_contents(encoded, certificate_contents)

    tbs_signature = tbs_contents
    for _ in range(2):  # version, then serialNumber
        _, tbs_signature = _der_contents(encoded, tbs_signature)
    _, tbs_signature_end = _der_contents(encoded, tbs_signature)
    _, outer_signature_algorithm_end = _der_contents(encoded, tbs_end)

    new_tbs = _sequence(
        encoded[tbs_contents:tbs_signature]
        + strip(encoded[tbs_signature:tbs_signature_end])
        + encoded[tbs_signature_end:tbs_end]
    )
    new_certificate = _sequence(
        new_tbs
        + strip(encoded[tbs_end:outer_signature_algorithm_end])
        + encoded[outer_signature_algorithm_end:certificate_end]
    )
    return x509.load_der_x509_certificate(new_certificate)


@pytest.mark.parametrize(
    ("field_tag", "field_name"),
    [(0xA0, "hashAlgorithm"), (0xA1, "maskGenAlgorithm")],
    ids=["missing-hash", "missing-mgf"],
)
def test_pss_hash_and_mask_fields_must_be_explicit(
    signing_key: Ed25519PrivateKey,
    field_tag: int,
    field_name: str,
) -> None:
    certificate = _without_pss_parameter(
        _pss_signed_leaf(signing_key, hashes.SHA256(), hashes.SHA256()),
        field_tag,
    )

    with pytest.raises(ProfileError, match=field_name):
        check_claim_signing_profile(certificate)


@pytest.mark.parametrize(
    ("tag", "name"),
    [(0x81, "issuerUniqueID"), (0x82, "subjectUniqueID")],
    ids=["issuerUniqueID", "subjectUniqueID"],
)
def test_a_certificate_carrying_a_unique_id_is_rejected(
    signing_certificate: x509.Certificate,
    tag: int,
    name: str,
) -> None:
    """14.5.1.1 rejects both legacy unique-ID fields on a real parsed certificate."""
    der = signing_certificate.public_bytes(Encoding.DER)
    tbs_start, outer_end = _der_contents(der, 0)
    body_start, tbs_end = _der_contents(der, tbs_start)
    extensions = der.index(b"\xa3", body_start)

    field = bytes([tag, 0x02, 0x00, 0xFF])
    tbs = _sequence(der[body_start:extensions] + field + der[extensions:tbs_end])
    certificate = x509.load_der_x509_certificate(_sequence(tbs + der[tbs_end:outer_end]))

    with pytest.raises(ProfileError, match=name):
        check_claim_signing_profile(certificate)


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

    ``cryptography`` parses extensions LAZILY, so one malformed extension poisons the
    whole set: the first ``get_extension_for_class`` raises whichever extension it asks
    for. ``check_claim_signing_profile`` must translate that dependency failure to
    ``ProfileError``.

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
    validators." `c2pa-kp-claimSigning` is new at 2.2. Older credentials may therefore
    carry one or both of the former EKUs without the new OID; rejecting those
    credentials as ``signingCredential.invalid`` would make the manifest not Valid.

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
    """A profile violation keeps its rule-specific explanation."""
    certificate = _leaf(signing_key, **kwargs)  # pyright: ignore[reportArgumentType] -- kwargs are build_certificate's

    with pytest.raises(ProfileError) as caught:
        check_claim_signing_profile(certificate)

    assert not str(caught.value).startswith("the certificate's extensions could not be parsed")
    assert expected in str(caught.value)
