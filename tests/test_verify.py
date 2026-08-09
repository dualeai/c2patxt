# pyright: reportPrivateUsage=false
# Reaches _verify._check_assertions directly only for states no producer can emit.
# Public signed-wire cases below hold every externally visible status mapping.
"""End-to-end tests for :func:`c2patxt.verify`.

The suite exercises selectors, JUMBF, CBOR, COSE, certificate profiles and hash binding
against signed text. Attack cases assert the exact status code, not merely ``INVALID``.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import unicodedata
import uuid
from collections.abc import Callable
from typing import TypeGuard

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from c2patxt import _cbor, _cose, _fixpoint, _jumbf, _verify
from c2patxt._jumbf import DescriptionBox, JumbfBox
from c2patxt._selectors import build_wrapper
from c2patxt.constants import MARKER
from c2patxt.manifest import (
    ASSERTION_ACTIONS,
    ASSERTION_ACTIONS_V1,
    ASSERTION_AI_DISCLOSURE,
    ASSERTION_HASH_DATA,
    ASSERTION_METADATA,
    ASSERTION_REPOSITORY_RECEIPT,
    DIGITAL_SOURCE_TYPE_TRAINED,
    LABEL_ASSERTION_STORE,
    LABEL_CLAIM,
    LABEL_CLAIM_SIGNATURE,
    LABEL_MANIFEST_STORE,
    UUID_ASSERTION_STORE,
    UUID_CLAIM,
    UUID_CLAIM_SIGNATURE,
    UUID_MANIFEST,
    UUID_MANIFEST_STORE,
    Assertion,
    ManifestStore,
)
from c2patxt.signing import C2PA_CLAIM_SIGNING_EKU, COSE_ALG_EDDSA, Signer
from c2patxt.status import StatusCode
from c2patxt.trust import ProfileError
from c2patxt.verdict import Provenance, Verdict
from tests.conftest import DISCLOSURE, WHEN, FloatingTimezone, RecordingTrustEvaluator, build_certificate, mark

from c2patxt import MarkCorruptError, VerifyContext, embed, extract, locate, verify  # isort: skip


#: This suite exercises the WHOLE stack -- selectors, JUMBF, CBOR, COSE, certificate
#: profile, hash binding -- against text that genuinely satisfies the binding, rather
#: than against hand-built fragments.


@pytest.fixture(scope="session")
def marked(signer: Signer) -> str:
    return mark("The quick brown fox jumps over the lazy dog.", signer)


def _test_wrapper(
    boxes: tuple[JumbfBox, ...],
    signature: bytes,
    *,
    manifest_label: str,
) -> str:
    """Assemble a hand-built test manifest around already chosen signed bytes."""
    signature_box = JumbfBox(
        description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
        content=((b"cbor", signature),),
    )
    manifest = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST, label=manifest_label),
        content=tuple((b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in (*boxes, signature_box)),
    )
    store = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label=LABEL_MANIFEST_STORE),
        content=((b"jumb", _jumbf.serialize_superbox(manifest)[8:]),),
    )
    return build_wrapper(_jumbf.serialize_superbox(store))


# --------------------------------------------------------------------------------
# The happy path, and what "happy" actually means here
# --------------------------------------------------------------------------------


def test_untouched_text_verifies_as_valid(marked: str) -> None:
    """The whole stack round-trips: sign, embed, locate, parse, verify.

    VALID rather than TRUSTED, and that is the correct answer: the credential is
    self-signed and no anchors were supplied, so there is nothing to chain to.

    ``at_least`` checks the aggregate verdict. Checking
    ``CLAIM_SIGNATURE_VALIDATED in verdict.codes()`` is not equivalent:
    ``codes()`` flattens all three buckets, and that code is genuinely PRESENT on a
    document whose text was rewritten -- the claim signature really is intact, only
    the binding broke. A service must therefore decide from the aggregate state.
    """
    verdict = verify(marked)
    assert verdict.at_least(Provenance.VALID)
    assert verdict.state is Provenance.VALID


def test_valid_carries_untrusted_and_that_is_not_an_error(marked: str) -> None:
    """14.3.5 defines Valid WITHOUT requiring signingCredential.trusted.

    Pinned because it is the single most likely thing for an integrator to misread:
    a failure-bucket code on a manifest that is entirely well-formed and honest.
    """
    verdict = verify(marked)
    assert verdict.state is Provenance.VALID
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED in verdict.codes()
    assert verdict.at_least(Provenance.VALID)
    assert not verdict.at_least(Provenance.TRUSTED)


@pytest.mark.parametrize(
    "part",
    ["claim-order", "assertion-order", "assertion-compound-key"],
)
def test_authenticated_manifest_cbor_outside_the_writer_subset_is_accepted(signer: Signer, part: str) -> None:
    """15.6.2 and 15.10.3.1 reject non-well-formed CBOR, not our writer subset.

    The generator rules in 10.1 and 18.1 still require deterministic bytes, and
    ``test_manifest`` checks ours. A validator applies different clauses. Two rows
    reverse a top-level map order. The third adds 18.3.3 custom assertion
    metadata whose value has an array map key, valid CBOR that Python cannot place
    directly in a dict. Every row recomputes each affected digest and signature.

    Each row passes through public verification so both extraction boundaries use the
    broader reader contract.
    """
    from c2patxt.manifest import (
        ASSERTION_URI_PREFIX,
        DEFAULT_HASH_ALGORITHM,
        _prepare_manifest,
        _serialize_prepared_manifest,
        hashed_uri,
    )

    text = "Hello world."
    normalized = unicodedata.normalize("NFC", text)
    start = len(normalized.encode("utf-8"))
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    manifest_uuid = uuid.UUID("00000000-0000-4000-8000-000000000013")

    def reversed_map(value: _cbor.CborValue) -> bytes:
        assert isinstance(value, dict)
        encoded = cbor2.dumps(dict(reversed(tuple(value.items()))))
        assert _cbor.loads(encoded, deterministic=False) == value
        with pytest.raises(_cbor.CborDecodeError, match="out-of-order"):
            _cbor.loads(encoded)
        return encoded

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        prepared = _prepare_manifest(
            disclosure=DISCLOSURE,
            digest=digest,
            exclusion_start=start,
            exclusion_length=exclusion_length,
            instance_id="xmp:iid:non-deterministic-reader",
            when=WHEN,
            generator_name="independent test producer",
        )
        claim = _cbor.loads(prepared.claim_bytes)
        assert isinstance(claim, dict)
        boxes = list(prepared.assertion_boxes)

        if part == "claim-order":
            claim_bytes = reversed_map(claim)
        else:
            target_label = ASSERTION_ACTIONS if part == "assertion-compound-key" else ASSERTION_HASH_DATA
            assertion_url = f"{ASSERTION_URI_PREFIX}{target_label}"
            changed = False
            for index, box in enumerate(boxes):
                if box.description.label != target_label:
                    continue
                assert len(box.content) == 1
                tbox, payload = box.content[0]
                assertion = _cbor.loads(payload)
                if part == "assertion-order":
                    assertion_bytes = reversed_map(assertion)
                else:
                    assert isinstance(assertion, dict)
                    # The prepared actions map has one `actions` pair. Preserve its
                    # exact tagged tdate bytes, widen the map to two pairs, and append
                    # `metadata` (which sorts after `actions`) from a separate encoder.
                    assert payload[:1] == b"\xa1"
                    custom_metadata = cbor2.dumps({"com.example:x": {(): 0}})
                    assertion_bytes = b"\xa2" + payload[1:] + _cbor.dumps("metadata") + custom_metadata
                    decoded = _cbor.loads(assertion_bytes)
                    assert isinstance(decoded, dict)
                    metadata = decoded.get("metadata")
                    assert isinstance(metadata, dict)
                    custom = metadata.get("com.example:x")
                    assert isinstance(custom, dict)
                    compound = next(iter(custom))
                    assert isinstance(compound, _cbor.MapKey)
                    assert compound.value == []
                replacement = dataclasses.replace(box, content=((tbox, assertion_bytes),))
                boxes[index] = replacement

                links = claim.get("created_assertions")
                assert isinstance(links, list)
                for link in links:
                    assert isinstance(link, dict)
                    if link.get("url") != assertion_url:
                        continue
                    new_digest = hashed_uri(replacement, assertion_url, DEFAULT_HASH_ALGORITHM)["hash"]
                    assert isinstance(new_digest, bytes)
                    link["hash"] = new_digest
                    changed = True
                    break
                break
            assert changed, "the target assertion and its claim link must both be replaced"
            claim_bytes = _cbor.dumps(claim)

        altered = dataclasses.replace(prepared, assertion_boxes=tuple(boxes), claim_bytes=claim_bytes)
        signed = _cose._prepare_signed_claim(signer, claim_bytes)

        def assemble(pad: int) -> str:
            signature = _cose._serialize_signed_claim(signed, pad=pad)
            raw = _serialize_prepared_manifest(altered, signature=signature, manifest_uuid=manifest_uuid)
            return build_wrapper(raw)

        return assemble

    wrapper, _ = _fixpoint.solve(prepare)
    verdict = verify(normalized + wrapper)

    assert verdict.state is Provenance.VALID
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()


def test_an_unprotected_x5chain_reaches_the_same_signature_checks(signer: Signer) -> None:
    """14.5 requires validators to accept the legacy unprotected placement."""

    def unprotected_chain(candidate: Signer, claim_bytes: bytes, pad: int) -> bytes:
        protected = _cbor.dumps({_cose.COSE_HEADER_ALG: COSE_ALG_EDDSA})
        signature = candidate.sign(_cose.sig_structure(protected, claim_bytes))
        return _cbor.dumps(
            _cbor.Tagged(
                _cbor.TAG_COSE_SIGN1,
                [
                    protected,
                    {_cose.COSE_HEADER_X5CHAIN: candidate.x5chain()[0], "pad": bytes(pad)},
                    None,
                    signature,
                ],
            )
        )

    verdict = verify(_resigned(signer, _unchanged, signature_serializer=unprotected_chain))

    assert verdict.state is Provenance.VALID
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()
    assert StatusCode.SIGNING_CREDENTIAL_INVALID not in verdict.codes()


def test_an_unknown_spki_is_an_invalid_credential_not_an_exception(signer: Signer) -> None:
    """Exercise the real hostile-DER boundary, not a certificate-shaped proxy."""
    der = signer.x5chain()[0]
    ed25519_oid = b"\x06\x03\x2b\x65\x70"
    positions = [index for index in range(len(der)) if der.startswith(ed25519_oid, index)]
    assert len(positions) == 3, "TBS signature, subjectPublicKeyInfo, outer signature"
    spki = positions[1]
    unknown_spki = der[: spki + 4] + b"\x72" + der[spki + 5 :]

    def hostile_certificate(candidate: Signer, claim_bytes: bytes, pad: int) -> bytes:
        protected = _cbor.dumps({_cose.COSE_HEADER_ALG: COSE_ALG_EDDSA, _cose.COSE_HEADER_X5CHAIN: unknown_spki})
        signature = candidate.sign(_cose.sig_structure(protected, claim_bytes))
        return _cbor.dumps(
            _cbor.Tagged(
                _cbor.TAG_COSE_SIGN1,
                [protected, {"pad": bytes(pad)}, None, signature],
            )
        )

    verdict = verify(_resigned(signer, _unchanged, signature_serializer=hostile_certificate))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()
    explanations = [status.explanation for status in verdict.failure if status.explanation]
    assert any("x5chain[0] leaf" in text and "not a readable certificate" in text for text in explanations)


@pytest.mark.parametrize("unreadable_index", [1, 2], ids=["intermediate", "third-slot"])
def test_an_unreadable_carried_certificate_reports_its_x5chain_index(unreadable_index: int) -> None:
    signer = _signer_with_carried_intermediate()
    chain: list[_cbor.CborValue] = [certificate for certificate in signer.x5chain()]
    if unreadable_index == len(chain):
        chain.append(b"not a DER certificate")
    else:
        chain[unreadable_index] = b"not a DER certificate"

    def unreadable_chain(candidate: Signer, claim_bytes: bytes, pad: int) -> bytes:
        protected = _cbor.dumps({_cose.COSE_HEADER_ALG: COSE_ALG_EDDSA, _cose.COSE_HEADER_X5CHAIN: chain})
        signature = candidate.sign(_cose.sig_structure(protected, claim_bytes))
        return _cbor.dumps(
            _cbor.Tagged(
                _cbor.TAG_COSE_SIGN1,
                [protected, {"pad": bytes(pad)}, None, signature],
            )
        )

    evaluator = RecordingTrustEvaluator(trusted=True)
    context = VerifyContext(
        anchors_pem=signer.certificates[-1].public_bytes(Encoding.PEM),
        trust_evaluator=evaluator,
        now=datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc),
    )

    verdict = verify(_resigned(signer, _unchanged, signature_serializer=unreadable_chain), context=context)

    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()
    explanations = [status.explanation for status in verdict.failure if status.explanation]
    assert any(f"x5chain[{unreadable_index}] carried CA" in text for text in explanations)
    assert not evaluator.calls


def test_unmarked_text_is_unmarked_not_invalid() -> None:
    """Absence of a mark is the absence of a finding, not a negative one."""
    verdict = verify("Just some ordinary prose with no mark at all.")
    assert verdict.state is Provenance.UNMARKED
    assert verdict.codes() == ()
    assert verdict.manifest is None


def test_empty_text_is_unmarked() -> None:
    verdict = verify("")
    assert verdict.state is Provenance.UNMARKED


def test_the_span_locates_the_wrapper_by_utf8_bytes(signer: Signer) -> None:
    """A non-ASCII prefix separates byte offsets from Python character indexes."""
    text = "café 漢字"
    marked = mark(text, signer)
    verdict = verify(marked)
    span = verdict.span
    assert span is not None
    encoded = marked.encode("utf-8")
    assert span.utf8_start == len(text.encode("utf-8"))
    assert encoded[span.utf8_start : span.utf8_stop].decode("utf-8").startswith(MARKER)
    stripped = encoded[: span.utf8_start] + encoded[span.utf8_stop :]
    assert stripped.decode("utf-8") == text


@pytest.mark.parametrize(
    "text",
    [
        "漢字テキスト",
        "مرحبا שלום",
        "é combining",
        "x" * 500,
        "line one\nline two\r\nline three\ttabbed",
        "emoji 👨‍👩‍👧‍👦 zwj sequence",
    ],
)
def test_verification_survives_unicode(text: str, signer: Signer) -> None:
    """Non-ASCII, bidirectional, combining, ZWJ and multi-line text all round-trip.

    Each of these stresses a different part of the offset arithmetic: multi-byte
    encodings make character and byte offsets diverge, combining marks make NFC do
    real work, and ZWJ sequences put format characters in the visible text.
    """
    assert verify(mark(text, signer)).state is Provenance.VALID


# --------------------------------------------------------------------------------
# Tampering: the hard binding
# --------------------------------------------------------------------------------


def test_altering_one_character_breaks_the_binding(signer: Signer) -> None:
    """ATTACK: edit the covered text. The single most important test in the suite."""
    marked = mark("Hello world.", signer)
    verdict = verify(marked.replace("Hello", "Hellp", 1))
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()


def test_appending_text_after_the_wrapper_breaks_the_binding(signer: Signer) -> None:
    """ATTACK: append after the mark, hoping the hash only covers the prefix.

    The signed exclusion still names the wrapper exactly, so validation removes that
    range and hashes every remaining byte. The appended text therefore produces the
    ordinary data-hash mismatch required by 15.12.1.3.1.
    """
    verdict = verify(mark("Hello world.", signer) + " and some appended lies")
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()


def test_replaying_a_wrapper_onto_same_length_text_fails(signer: Signer) -> None:
    """ATTACK: copy a valid wrapper onto another document.

    The replacement is deliberately the SAME byte length as the original, so the
    exclusion range still names the wrapper exactly and the only thing left to catch
    the swap is the hash itself. Without matching lengths this would fail one step
    earlier, on the exclusion check, and would not prove the binding works.
    """
    marked = mark("Original document", signer)
    wrapper = marked[marked.index(MARKER) :]
    verdict = verify("Different documnt" + wrapper)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()


def test_replaying_a_wrapper_onto_shifted_text_fails(signer: Signer) -> None:
    """ATTACK: replay onto text of a different length, moving the wrapper.

    Caught one step earlier than the hash: 15.12.1.3.1 step 3 requires the exclusion
    range to correspond to a located wrapper, and after the shift it names a range
    that is partly visible text. Malformed is the more precise answer than mismatch
    -- the assertion is wrong ABOUT the document, not merely disagreeing with it.
    """
    marked = mark("Original document.", signer)
    wrapper = marked[marked.index(MARKER) :]
    verdict = verify("Completely different text." + wrapper)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()


def test_an_appended_wrapper_is_covered_when_only_the_first_exclusion_matches(marked: str, signer: Signer) -> None:
    """15.12.1.3.1 selects the wrapper whose exclusion matches its exact range.

    The appended wrapper's own exclusion no longer names its shifted span, so the first
    mark remains authoritative and its digest covers the appended bytes.
    """
    second = mark("Something else entirely.", signer)
    verdict = verify(marked + second[second.index(MARKER) :])
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()


# --------------------------------------------------------------------------------
# Tampering: the signature and the credential
# --------------------------------------------------------------------------------


def _signer_with_carried_intermediate(
    *,
    intermediate_key: Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
    basic_constraints: bool = True,
    basic_constraints_critical: bool = True,
    ca: bool = True,
    authority_key_identifier: bool = True,
    authority_key_identifier_critical: bool = False,
    subject_key_identifier: bool = True,
    subject_key_identifier_critical: bool = False,
    key_usage: bool = True,
    key_usage_critical: bool = True,
    key_cert_sign: bool = True,
    ca_eku: bool = False,
    intermediate_not_after: datetime.datetime | None = None,
    allow_nonconformant: bool = False,
) -> Signer:
    """Build leaf -> carried intermediate -> omitted root test credentials."""
    leaf_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    issuer_key = intermediate_key or Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
    root_key = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2patxt chain leaf")])
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2patxt carried intermediate")])
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2patxt omitted root")])
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    not_after = datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc)

    issuer_builder = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(root_name)
        .public_key(issuer_key.public_key())
        .serial_number(0xC2A7E47_CAFE)
        .not_valid_before(not_before)
        .not_valid_after(intermediate_not_after or not_after)
    )
    if basic_constraints:
        issuer_builder = issuer_builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None),
            critical=basic_constraints_critical,
        )
    if authority_key_identifier:
        issuer_builder = issuer_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=authority_key_identifier_critical,
        )
    if subject_key_identifier:
        issuer_builder = issuer_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),
            critical=subject_key_identifier_critical,
        )
    if key_usage:
        issuer_builder = issuer_builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=key_usage_critical,
        )
    if ca_eku:
        # 14.5.1.1 says a CA's EKU does not take part in certificate acceptance.
        issuer_builder = issuer_builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=False,
        )
    issuer = issuer_builder.sign(root_key, None)

    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(0xC2A7E47_BEEF)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
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
        .add_extension(x509.ExtendedKeyUsage([C2PA_CLAIM_SIGNING_EKU]), critical=False)
        .sign(issuer_key, None if isinstance(issuer_key, Ed25519PrivateKey) else SHA256())
    )
    return Signer(
        private_key=leaf_key,
        certificates=(leaf, issuer),
        allow_nonconformant=allow_nonconformant,
    )


def test_a_conforming_carried_intermediate_with_an_eku_is_accepted() -> None:
    """A CA's EKU is ignored; applying the leaf rules to it would reject this chain."""
    verdict = verify(mark("Hello world.", _signer_with_carried_intermediate(ca_eku=True)))

    assert verdict.state is Provenance.VALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID not in verdict.codes()


def test_signer_refuses_an_unrelated_carried_certificate() -> None:
    first = _signer_with_carried_intermediate()
    second = _signer_with_carried_intermediate(
        intermediate_key=Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(64, 96))))
    )

    with pytest.raises(ValueError, match=r"x5chain\[0\].*not directly issued by x5chain\[1\]"):
        Signer(
            private_key=first.private_key,
            certificates=(first.certificates[0], second.certificates[1]),
        )


def test_a_noncritical_carried_ca_key_usage_is_accepted() -> None:
    """RFC 5280 recommends, but does not require, critical Key Usage."""
    verdict = verify(mark("Hello world.", _signer_with_carried_intermediate(key_usage_critical=False)))

    assert verdict.state is Provenance.VALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID not in verdict.codes()


@pytest.mark.parametrize(
    "intermediate_key",
    [
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        ec.derive_private_key(1, ec.SECP256R1()),
        ec.derive_private_key(1, ec.SECP384R1()),
        ec.derive_private_key(1, ec.SECP521R1()),
    ],
    ids=["rsa-2048", "p-256", "p-384", "p-521"],
)
def test_permitted_carried_ca_subject_keys_are_accepted(
    intermediate_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
) -> None:
    verdict = verify(mark("Hello world.", _signer_with_carried_intermediate(intermediate_key=intermediate_key)))

    assert verdict.state is Provenance.VALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID not in verdict.codes()


def test_signer_refuses_a_nonconforming_carried_intermediate() -> None:
    with pytest.raises(ProfileError, match=r"x5chain\[1\].*Subject Key Identifier"):
        _signer_with_carried_intermediate(subject_key_identifier=False)


def test_profile_validation_reaches_the_third_carried_certificate() -> None:
    base = _signer_with_carried_intermediate()
    root_key = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
    not_a_ca = build_certificate(root_key, common_name="c2patxt omitted root")
    certificates = (*base.certificates, not_a_ca)

    with pytest.raises(ProfileError, match=r"x5chain\[2\].*carried CA"):
        Signer(private_key=base.private_key, certificates=certificates)

    wire_signer = Signer(
        private_key=base.private_key,
        certificates=certificates,
        allow_nonconformant=True,
    )
    verdict = verify(mark("Hello world.", wire_signer))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()
    explanations = [status.explanation for status in verdict.failure if status.explanation]
    assert any("x5chain[2]" in text for text in explanations)


_INTERMEDIATE_PROFILE_VIOLATIONS: list[tuple[str, dict[str, bool]]] = [
    ("basic-constraints-absent", {"basic_constraints": False}),
    ("basic-constraints-not-critical", {"basic_constraints_critical": False}),
    ("ca-false", {"ca": False}),
    ("authority-key-identifier-absent", {"authority_key_identifier": False}),
    ("authority-key-identifier-critical", {"authority_key_identifier_critical": True}),
    ("subject-key-identifier-absent", {"subject_key_identifier": False}),
    ("subject-key-identifier-critical", {"subject_key_identifier_critical": True}),
    ("key-usage-absent", {"key_usage": False}),
    ("key-cert-sign-false", {"key_cert_sign": False}),
]


@pytest.mark.parametrize(
    ("label", "keywords"),
    _INTERMEDIATE_PROFILE_VIOLATIONS,
    ids=[case[0] for case in _INTERMEDIATE_PROFILE_VIOLATIONS],
)
def test_a_carried_intermediate_profile_violation_is_invalid(
    label: str,
    keywords: dict[str, bool],
) -> None:
    signer = _signer_with_carried_intermediate(
        **keywords,  # pyright: ignore[reportArgumentType] -- one bool-valued profile switch per row
        allow_nonconformant=True,
    )

    evaluator = RecordingTrustEvaluator(trusted=True)
    context = VerifyContext(
        anchors_pem=signer.certificates[-1].public_bytes(Encoding.PEM),
        trust_evaluator=evaluator,
    )
    verdict = verify(mark("Hello world.", signer), context=context)

    assert verdict.state is Provenance.INVALID, label
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes(), label
    assert not evaluator.calls, f"{label} reached the trust backend before its profile was accepted"
    explanations = [status.explanation for status in verdict.failure if status.explanation]
    assert any("x5chain[1]" in text for text in explanations), label


@pytest.mark.parametrize(
    "intermediate_key",
    [
        rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,  # noqa: S505 -- hostile fixture below the profile floor
        ),
        ec.derive_private_key(1, ec.SECP256K1()),
    ],
    ids=["rsa-1024", "secp256k1"],
)
def test_a_carried_intermediate_with_a_disallowed_subject_key_is_invalid(
    intermediate_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
) -> None:
    signer = _signer_with_carried_intermediate(
        intermediate_key=intermediate_key,
        allow_nonconformant=True,
    )

    verdict = verify(mark("Hello world.", signer))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()


def test_signer_refuses_a_key_that_does_not_match_the_certificate(
    signing_certificate: x509.Certificate,
) -> None:
    """The mismatch attack is unrepresentable through the public API.

    Signer pairs the key against the leaf's public key at construction, so a producer
    cannot emit a manifest nobody can verify. Verification must still catch it -- see
    the next test -- because a signature arriving over the wire never went through
    our constructor.
    """
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(100, 132)))
    with pytest.raises(ValueError, match="does not match"):
        Signer(private_key=other, certificates=(signing_certificate,))


def test_a_signature_from_a_key_not_in_the_chain_fails(signing_certificate: x509.Certificate) -> None:
    """ATTACK: sign with one key while presenting another key's certificate.

    The Signer guard is bypassed deliberately with ``object.__setattr__``, because
    the point is to test the VERIFIER against bytes an attacker could produce with
    any tooling they like. A verifier that leans on a producer-side check is not a
    verifier.
    """
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(100, 132)))
    mismatched = Signer(
        private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
        certificates=(signing_certificate,),
    )
    object.__setattr__(mismatched, "private_key", other)

    verdict = verify(mark("Hello world.", mismatched))
    assert verdict.state is Provenance.INVALID
    assert StatusCode.CLAIM_SIGNATURE_MISMATCH in verdict.codes()


def test_a_non_conformant_certificate_is_invalid_not_untrusted() -> None:
    """A profile violation is a HARD reject, distinct from an unreachable anchor.

    ``openssl req -x509`` defaults produce cA=TRUE and no EKU. Collapsing that into
    ``untrusted`` would let a CA certificate sign claims and still read as VALID.
    """
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    # allow_nonconformant is required to BUILD this attack at all: Signer now applies
    # the same 14.5.1.1 profile the verifier does, so the producer refuses it first.
    # The escape hatch exists precisely so a verifier test can still be written.
    signer = Signer(
        private_key=key,
        certificates=(build_certificate(key, conformant=False),),
        allow_nonconformant=True,
    )
    verdict = verify(mark("Hello world.", signer))
    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED not in verdict.codes()


def test_a_supplied_anchor_and_evaluator_reach_trusted(marked: str, signing_certificate: x509.Certificate) -> None:
    """TRUSTED is reachable, but only with BOTH an anchor and an evaluator.

    Proves the four-state model is not a three-state model with a decorative top.
    """
    evaluator = RecordingTrustEvaluator(trusted=True)
    context = VerifyContext(
        anchors_pem=signing_certificate.public_bytes(Encoding.PEM),
        trust_evaluator=evaluator,
    )
    verdict = verify(marked, context=context)
    assert verdict.state is Provenance.TRUSTED
    assert StatusCode.SIGNING_CREDENTIAL_TRUSTED in verdict.codes()
    certificate_der = signing_certificate.public_bytes(Encoding.DER)
    assert evaluator.calls == [((certificate_der,), (certificate_der,))]


def test_an_anchor_without_an_evaluator_stays_valid(marked: str, signing_certificate: x509.Certificate) -> None:
    """Anchors alone change nothing: the default evaluator trusts nothing.

    Fail-closed. Supplying a PEM bundle must never be mistaken for path validation
    the library does not perform.
    """
    context = VerifyContext(anchors_pem=signing_certificate.public_bytes(Encoding.PEM))
    assert verify(marked, context=context).state is Provenance.VALID


def test_an_evaluator_without_anchors_stays_valid(marked: str) -> None:
    """With no anchors there is nothing to chain to, so the evaluator is not asked."""
    evaluator = RecordingTrustEvaluator(trusted=True)
    context = VerifyContext(trust_evaluator=evaluator)
    assert verify(marked, context=context).state is Provenance.VALID
    assert not evaluator.calls


# --------------------------------------------------------------------------------
# Corruption, and what a caller still gets back
# --------------------------------------------------------------------------------


def test_a_corrupt_wrapper_reports_the_specification_code(marked: str) -> None:
    """Truncating the selector run must not raise; it must report a status code.

    verify() never raises for bad input -- every outcome is a Verdict. A library that
    raises here is one people wrap in a bare except, and a bare except is how a
    genuine corruption gets swallowed.
    """
    verdict = verify(marked[:-200])
    assert verdict.state is Provenance.INVALID
    # THE CODE, not merely "something failed". 15.12.1.3.2 names this one for a wrapper
    # whose "version, algorithm, or manifest length" does not survive: the run is intact
    # and its declared length overruns what is there. Asserting only that some code was
    # filed let this test pass for any of thirty reasons, in a file whose own docstring
    # says a test that checks only INVALID "passes just as happily when the mark fails
    # for the wrong reason".
    assert StatusCode.TEXT_CORRUPTED_WRAPPER in verdict.codes()


def test_a_success_code_survives_on_a_tampered_document(signer: Signer) -> None:
    """WHY ``codes()`` IS NOT A SUCCESS CHECK, pinned as executable documentation.

    Rewriting the covered text leaves ``claimSignature.validated`` in ``codes()``,
    because it is true: the signature over the claim verifies. Only the hard binding
    failed. Any integrator who reaches for ``in verdict.codes()`` as their pass
    condition ships this exact hole.
    """
    verdict = verify(mark("Hello world.", signer).replace("Hello", "Hellp", 1))

    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()
    assert verdict.state is Provenance.INVALID
    assert not verdict.at_least(Provenance.VALID)


def test_a_profile_violation_explains_which_rule_failed() -> None:
    """The diagnosis is carried into the Verdict, not computed and thrown away.

    ``check_claim_signing_profile`` already knows exactly which extension is wrong;
    returning a bare ``signingCredential.invalid`` leaves the caller with a code and
    no idea what to change on their certificate.
    """
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Signer(
        private_key=key,
        certificates=(build_certificate(key, conformant=False),),
        allow_nonconformant=True,
    )
    verdict = verify(mark("Hello world.", signer))

    explanations = [status.explanation for status in verdict.failure if status.explanation]
    assert explanations, "signingCredential.invalid arrived with no explanation"
    assert any("EKU" in text or "cA" in text or "keyCertSign" in text for text in explanations)


def test_an_unreadable_extension_set_becomes_a_public_status() -> None:
    """Lazy certificate parsing is contained at the public hostile-DER boundary.

    ``test_trust.py`` owns the full 14.5.1.1 rule matrix. This one distinct wire case
    proves that an extension which loads but fails when read becomes
    ``signingCredential.invalid`` rather than escaping ``verify``.
    """
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Signer(
        private_key=key,
        certificates=(build_certificate(key, extended_key_usage=()),),
        allow_nonconformant=True,
    )

    verdict = verify(mark("Hello world.", signer))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED not in verdict.codes()
    assert [status.explanation for status in verdict.failure if status.explanation]


def test_the_manifest_is_returned_even_when_validation_fails(signer: Signer) -> None:
    """A failed verification still hands back the manifest, so a caller can inspect it.

    Otherwise the only way to see which certificate signed a rejected mark is to
    bypass the library, and code that bypasses verification is what ships.
    """
    tampered = mark("Hello world.", signer).replace("Hello", "Hellp", 1)
    verdict = verify(tampered)
    assert verdict.state is Provenance.INVALID
    assert verdict.manifest is not None
    assert verdict.manifest.claim != {}


def test_the_verdict_refuses_to_be_a_boolean(marked: str) -> None:
    """bool(verdict) raises. Unmarked text rendered as "FAKE" is the worst collapse."""
    with pytest.raises(TypeError, match="not a boolean"):
        bool(verify(marked))


# --------------------------------------------------------------------------------
# The assertion store must be authenticated, not merely present
# --------------------------------------------------------------------------------


def _forge_assertion_swap(victim: str, attacker_text: str) -> str:
    """Keep the victim's signed claim fields verbatim; swap the assertion store.

    THE ATTACK THIS DEFENDS AGAINST. The COSE signature covers only the CLAIM. The
    claim commits to each assertion by a hashed-uri-map. If verify() does not
    recompute those digests over the assertion bytes that actually arrived, then one
    sample of marked text is enough to mint arbitrary text under the victim's
    credential -- escalating to TRUSTED wherever that credential chains to an anchor.

    Note what is NOT rebuilt: ``claim_bytes``, the protected header and the signature
    are copied byte for byte out of the victim's manifest. Only the unsigned COSE pad
    changes to satisfy the A.8 length equation. A forge that rebuilt the claim would
    fail on the signature and prove nothing about the assertion check.
    """
    victim_store = extract(victim)
    assert victim_store is not None

    normalized = unicodedata.normalize("NFC", attacker_text)
    start = len(normalized.encode("utf-8"))
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    parsed_signature = _cose.parse(victim_store.signature)
    signed = _cose._SignedClaim(
        protected=parsed_signature.protected,
        signature=parsed_signature.signature,
    )

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        forged = Assertion(
            label=ASSERTION_HASH_DATA,
            payload={
                "exclusions": [{"start": start, "length": exclusion_length}],
                "alg": "sha256",
                "hash": digest,
                "pad": b"",
            },
        )
        # Every OTHER assertion is copied byte for byte from the victim, so its
        # hashed-URI link still matches. Only c2pa.hash.data is replaced. This is the
        # tightest form of the attack: a store where exactly one link is wrong.
        children = [
            (b"jumb", raw) for label, raw in victim_store.assertion_bytes.items() if label != ASSERTION_HASH_DATA
        ]
        children.append((b"jumb", _jumbf.serialize_superbox(forged.to_box())[8:]))
        assertion_store = JumbfBox(
            description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
            content=tuple(children),
        )
        claim_box = JumbfBox(
            description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
            content=((b"cbor", victim_store.claim_bytes),),
        )
        boxes = (assertion_store, claim_box)

        def assemble(pad: int) -> str:
            signature = _cose._serialize_signed_claim(signed, pad=pad)
            return _test_wrapper(
                boxes,
                signature,
                manifest_label=victim_store.manifest_label,
            )

        return assemble

    wrapper, _ = _fixpoint.solve(prepare)
    return normalized + wrapper


def test_swapping_the_assertion_store_does_not_verify(signer: Signer) -> None:
    """ATTACK: reuse a captured claim and signature over a forged assertion store.

    The single most important test in this file. Before the hashed-URI check existed,
    this produced a full VALID verdict on attacker-chosen text, and TRUSTED wherever
    the victim's certificate reached an anchor.
    """
    victim = mark("The original, honest sentence.", signer)
    assert verify(victim).state is Provenance.VALID

    forged = _forge_assertion_swap(victim, "The quarterly revenue was 120 million euros.")

    verdict = verify(forged)
    assert verdict.state is Provenance.INVALID
    assert verdict.state is not Provenance.VALID
    assert not verdict.at_least(Provenance.VALID)
    # The claim signature is INTACT here -- that is the whole point of the attack --
    # so the only thing that can catch it is the hashed-URI link.
    assert StatusCode.ASSERTION_HASHED_URI_MISMATCH in verdict.codes()


def test_an_honest_mark_reports_its_assertions_as_linked(signer: Signer) -> None:
    """The positive half. Without it, the test above would pass just as well if
    verification had broken entirely and every input came back INVALID."""
    verdict = verify(mark("Hello world.", signer))
    assert verdict.state is Provenance.VALID
    assert StatusCode.ASSERTION_HASHED_URI_MATCH in verdict.codes()


def test_a_wrapper_that_is_not_a_suffix_is_validated_by_its_exact_range(signer: Signer) -> None:
    """A.8.4.1 makes suffix placement a producer SHOULD, not a validator condition.

    This mark keeps the signed UTF-8 range exact and hashes the text left after that
    range is removed, as 15.12.1.3.1 specifies. The public producer still emits only a
    suffix.
    """
    marked = embed("éé", signer, DISCLOSURE)
    assert verify(marked).state is Provenance.VALID

    wrapper = marked[marked.index(MARKER) :]
    # NFD "e" + combining acute, then "e", then a trailing combining acute. The prefix
    # is the same number of BYTES as the original "éé", so the declared exclusion
    # start still lands exactly on the marker.
    slid = "ée" + wrapper + "́"
    assert len("ée".encode()) == len("éé".encode())

    verdict = verify(slid)
    assert verdict.state is Provenance.VALID
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()


def test_a_hostile_trust_anchors_variable_does_not_affect_verify(marked: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Public verification reads no ambient trust-anchor configuration."""
    for value in ("/nonexistent/missing.pem", "", "not-a-path"):
        monkeypatch.setenv("C2PATXT_TRUST_ANCHORS", value)
        assert verify(marked).state is Provenance.VALID


def test_a_validation_time_with_tzinfo_but_no_offset_is_refused_at_construction() -> None:
    """A non-``None`` tzinfo does not make a datetime aware by itself."""
    floating = datetime.datetime(2026, 8, 5, tzinfo=FloatingTimezone())
    with pytest.raises(ValueError, match="timezone-aware"):
        VerifyContext(now=floating)


@pytest.mark.parametrize(
    ("not_before", "not_after", "expected_valid"),
    [
        ((2000, 1, 1), (2002, 1, 1), False),  # expired long ago
        ((2000, 1, 1), (2026, 8, 4), False),  # expired yesterday
        ((2026, 8, 6), (2040, 1, 1), False),  # not yet valid
        ((2026, 1, 1), (2040, 1, 1), True),  # live right now
    ],
    ids=["long-expired", "just-expired", "not-yet-valid", "live"],
)
def test_validity_is_judged_at_validation_time(
    signing_key: Ed25519PrivateKey,
    not_before: tuple[int, int, int],
    not_after: tuple[int, int, int],
    expected_valid: bool,
) -> None:
    """C2PA 15.8, verbatim:

        "If neither the sigTst nor the sigTst2 headers are present ... then the C2PA
        Manifest is valid if THE CURRENT TIME AT VALIDATION is within the validity
        period of the signer's certificate ... If it is, the validator shall return a
        success code of claimSignature.insideValidity. If it is not, the C2PA
        Manifest shall be rejected with a failure code of
        claimSignature.outsideValidity."

    ``VerifyContext.now`` supplies the validation instant for deterministic checks.
    """
    context = VerifyContext(now=datetime.datetime(2026, 8, 5, tzinfo=datetime.timezone.utc))
    certificate = build_certificate(
        signing_key,
        not_before=datetime.datetime(*not_before, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(*not_after, tzinfo=datetime.timezone.utc),
    )
    signer = Signer(private_key=signing_key, certificates=(certificate,))
    verdict = verify(mark("Hello world.", signer, when=certificate.not_valid_before_utc), context=context)

    if expected_valid:
        assert verdict.state is Provenance.VALID
        assert StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY in verdict.codes()
    else:
        assert verdict.state is Provenance.INVALID
        assert StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY in verdict.codes()
        assert StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY not in verdict.codes()


def test_an_expired_credential_cannot_hide_by_omitting_the_actions_assertion(
    signing_key: Ed25519PrivateKey,
) -> None:
    """Certificate validity uses the verifier clock, not an action's claimed time.

    Omitting the actions assertion cannot skip or backdate the validity check.
    """
    expired = build_certificate(
        signing_key,
        not_before=datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2002, 1, 1, tzinfo=datetime.timezone.utc),
    )
    signer = Signer(private_key=signing_key, certificates=(expired,))
    context = VerifyContext(now=datetime.datetime(2026, 8, 5, tzinfo=datetime.timezone.utc))

    creation_time = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
    verdict = verify(mark("Hello world.", signer, when=creation_time), context=context)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY in verdict.codes()


@pytest.mark.parametrize(
    "anchors",
    [b"not a pem at all", b"-----BEGIN CERTIFICATE-----\ntruncated", b"\x00\xff\x00\xff"],
    ids=["garbage", "truncated-pem", "binary"],
)
def test_a_malformed_anchor_bundle_is_rejected_when_the_context_is_built(anchors: bytes) -> None:
    """The context validates caller-owned trust material before any document is read."""
    with pytest.raises(ValueError):
        VerifyContext(anchors_pem=anchors)


@pytest.mark.parametrize("declared", [False, True], ids=["unlinked", "linked"])
@pytest.mark.parametrize("content_type", [b"cbor", b"json", b"xml ", b"uuid", b"zzzz"])
def test_an_unlinked_assertion_is_rejected_whatever_its_content_type(
    signer: Signer, content_type: bytes, declared: bool
) -> None:
    """C2PA 15.10.3.1: an assertion in the store the claim never linked is
    `assertion.undeclared`, whatever it contains.

    The claim commits to assertions by hashed URI, so a box it never named is
    unauthenticated and its content is irrelevant. Accepting one would let anyone append
    assertions to a signed manifest and have them read.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse, parse_manifest_store
    from c2patxt._jumbf import DescriptionBox, JumbfBox, parse_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE

    original = extract(mark("Hello world.", signer))
    assert original is not None

    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])

    smuggled = JumbfBox(
        description=DescriptionBox(uuid=_jumbf.UUID_CBOR, label="evil", requestable=True),
        content=((content_type, b"\xa1\x64evil\xf5"),),
    )

    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_ASSERTION_STORE:
            widened = JumbfBox(
                description=child.description,
                content=(*child.content, (_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(smuggled)[8:])),
            )
            rebuilt.append((tbox, _jumbf.serialize_superbox(widened)[8:]))
        else:
            rebuilt.append((tbox, payload))

    forged = _jumbf.serialize_superbox(
        JumbfBox(
            description=store.description,
            content=(
                (
                    _jumbf.TBOX_SUPERBOX,
                    _jumbf.serialize_superbox(JumbfBox(description=manifest.description, content=tuple(rebuilt)))[8:],
                ),
            ),
        )
    )

    parsed = parse_manifest_store(forged)
    claim = dict(parsed.claim)
    if declared:
        links = claim["created_assertions"]
        assert isinstance(links, list)
        claim["created_assertions"] = [
            *links,
            {
                "url": "self#jumbf=c2pa.assertions/evil",
                "hash": hashlib.sha256(parsed.assertion_bytes["evil"]).digest(),
                "alg": "sha256",
            },
        ]

    verdict, ok = _verify._check_assertions(dataclasses.replace(parsed, claim=claim), Verdict(state=Provenance.INVALID))

    assert ok is declared, f"a {content_type!r} assertion, declared={declared}, got the wrong answer"
    if not declared:
        assert StatusCode.ASSERTION_UNDECLARED in verdict.codes()


def test_the_exclusion_must_name_a_located_wrapper_not_merely_be_trailing(signer: Signer) -> None:
    """A trailing exclusion must also equal one exact located-wrapper span.

    Aligning the shift to a code-point boundary makes the test reach the intended
    distinction: with the exact-span check, ``assertion.dataHash.malformed``; without
    it, the input reaches the hash and reports ``assertion.dataHash.mismatch``. A
    one-byte shift is rejected by the same exact-span check before hashing.

    Both outcomes are invalid, but the exact-span failure has the clause-specific
    malformed status rather than a digest mismatch.
    """
    marked = mark("Hello world.", signer)
    encoded = marked.encode("utf-8")

    span = locate(marked)
    assert span is not None

    # Move the whole wrapper three bytes earlier, then re-pad the tail so the total
    # length is unchanged and the declared (start, length) still ends at the end.
    shifted = encoded[: span.utf8_start - 3] + encoded[span.utf8_start :] + b"..."
    tampered = shifted.decode("utf-8")

    assert locate(tampered) is not None
    verdict = verify(tampered)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()
    assert StatusCode.DATA_HASH_MISMATCH not in verdict.codes()


@pytest.mark.parametrize("omit", ["hash-data", "hashed-uri", "both"])
def test_a_manifest_that_inherits_its_algorithm_from_the_claim_verifies(signer: Signer, omit: str) -> None:
    """END TO END for 15.4.1 and 15.4.2: the common encoding must verify.

    Omitting the per-structure ``alg`` and inheriting the claim's is what a conforming
    producer typically emits -- both fields are optional in their CDDL -- and every
    such manifest read as INVALID here with ``algorithm.unsupported``.

    Built by re-signing a real claim with the ``alg`` fields stripped, so the
    signature is genuine and the only variable is the omission.
    """
    import hashlib

    from c2patxt import _cose, _fixpoint
    from c2patxt.manifest import (
        DEFAULT_HASH_ALGORITHM,
        Assertion,
        Claim,
        DescriptionBox,
        JumbfBox,
        hashed_uri,
    )

    text = "Hello world."
    normalized = unicodedata.normalize("NFC", text)
    start = len(normalized.encode("utf-8"))
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        payload: dict[str, object] = {
            "exclusions": [{"start": start, "length": exclusion_length}],
            "hash": digest,
            "pad": b"",
        }
        if omit not in {"hash-data", "both"}:
            payload["alg"] = DEFAULT_HASH_ALGORITHM
        hash_data = Assertion(label=ASSERTION_HASH_DATA, payload=payload)

        link = hashed_uri(hash_data.to_box(), f"self#jumbf=c2pa.assertions/{ASSERTION_HASH_DATA}")
        if omit in {"hashed-uri", "both"}:
            link = {key: value for key, value in link.items() if key != "alg"}

        claim = Claim(
            instance_id="xmp:iid:1",
            claim_generator_name="c2patxt",
            claim_generator_version=None,
            created_assertions=(link,),
            signature_url="self#jumbf=c2pa.signature",
        )
        claim_bytes = _cbor.dumps(claim.to_payload())

        boxes = (
            JumbfBox(
                description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
                content=((b"jumb", _jumbf.serialize_superbox(hash_data.to_box())[8:]),),
            ),
            JumbfBox(
                description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                content=((b"cbor", claim_bytes),),
            ),
        )
        signed = _cose._prepare_signed_claim(signer, claim_bytes)

        def assemble(pad: int) -> str:
            return _test_wrapper(
                boxes,
                _cose._serialize_signed_claim(signed, pad=pad),
                manifest_label="urn:c2pa:00000000-0000-4000-8000-000000000007",
            )

        return assemble

    wrapper, _ = _fixpoint.solve(prepare)
    verdict = verify(normalized + wrapper)

    # THE ASSERTION IS THE ABSENCE of algorithm.unsupported, plus a matching binding.
    # Both prove the resolution ran: _binding_status would have returned
    # algorithm.unsupported before hashing, and _link_status would have returned it
    # before comparing the digest.
    assert StatusCode.ALGORITHM_UNSUPPORTED not in verdict.codes()
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()

    # This hand-built manifest carries only the hard binding, so it is INVALID for a
    # different and correct reason: the required actions assertion is absent.
    assert StatusCode.ASSERTION_MISSING in verdict.codes()


@pytest.mark.parametrize(
    ("url", "state"),
    [
        ("self#jumbf=c2pa.signature", Provenance.TRUSTED),
        ("self#jumbf=/c2pa/{label}/c2pa.signature", Provenance.TRUSTED),
        ("https://evil.example/signature", Provenance.INVALID),
        ("self#jumbf=c2pa.claim", Provenance.INVALID),
        ("self#jumbf=c2pa.assertions/c2pa.actions.v2", Provenance.INVALID),
        ("self#jumbf=/c2pa/urn:c2pa:00000000-0000-0000-0000-000000000000/c2pa.signature", Provenance.INVALID),
        ("self#jumbf=/c2pa/{label}/c2pa.assertions/c2pa.signature", Provenance.INVALID),
        ("", Provenance.INVALID),
    ],
    ids=[
        "manifest-relative",
        "store-relative",
        "http",
        "the-claim-box",
        "an-assertion",
        "another-manifest",
        "too-many-segments",
        "empty",
    ],
)
def test_the_claims_signature_uri_is_resolved_not_assumed(
    signer: Signer, signing_certificate: x509.Certificate, monkeypatch: pytest.MonkeyPatch, url: str, state: Provenance
) -> None:
    """C2PA 15.7: "The validator shall retrieve the URI reference for the signature
    from the value of the claim's `signature` field and resolve the URI reference to
    obtain the COSE signature. If the signature field is not present, or the URI cannot
    be resolved, or the URI does not resolve to a location within the same C2PA
    Manifest box (as the claim), then the claim shall be rejected with a failure code
    of `claimSignature.missing`."

    The test changes the producer's signed URI and reruns the full mark pipeline. A URI
    that does not resolve to the carried signature box must yield
    ``claimSignature.missing``.

    THE TWO TRUSTED ROWS ARE THE CONTROL, and they are why this test can fail in both
    directions: 8.4.2.1 allows the store-relative form for this field exactly as it
    does for assertions, so a naive ``== "self#jumbf=c2pa.signature"`` would reject a
    conforming manifest. ``another-manifest`` and ``too-many-segments`` are the two
    ways a prefix test alone would wave through a URI pointing outside this manifest.
    """
    from c2patxt import manifest as manifest_module

    # conftest's producer pins the manifest UUID, which is what lets the
    # store-relative row name the manifest it belongs to. Every other row ignores it.
    monkeypatch.setattr(
        manifest_module,
        "CLAIM_SIGNATURE_URI",
        url.format(label="urn:c2pa:00000000-0000-4000-8000-000000000007"),
        raising=True,
    )
    marked = mark("Hello world.", signer)

    evaluator = RecordingTrustEvaluator(trusted=True)
    context = VerifyContext(
        anchors_pem=signing_certificate.public_bytes(Encoding.PEM),
        trust_evaluator=evaluator,
    )
    verdict = verify(marked, context=context)

    assert verdict.state is state
    if state is Provenance.INVALID:
        assert StatusCode.CLAIM_SIGNATURE_MISSING in verdict.codes()


def test_an_undeclared_assertion_gets_its_own_code(signer: Signer) -> None:
    """C2PA 15.10.3.1: "If an assertion that is present in the assertion store is not
    referenced by an element of either the created_assertions or gathered_assertions
    arrays in the claim (or the assertions array in the v1 claim), the claim shall be
    rejected with a failure code of `assertion.undeclared`."

    ``assertion.missing`` is the opposite condition: the claim names an assertion the
    store lacks. Here the store holds an assertion the claim never names.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse, parse_manifest_store
    from c2patxt._jumbf import DescriptionBox, JumbfBox, parse_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE

    original = extract(mark("Hello world.", signer))
    assert original is not None

    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])
    smuggled = JumbfBox(
        description=DescriptionBox(uuid=_jumbf.UUID_CBOR, label="c2patxt.extra", requestable=True),
        content=((b"cbor", b"\xa1\x64evil\xf5"),),
    )

    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_ASSERTION_STORE:
            widened = JumbfBox(
                description=child.description,
                content=(*child.content, (_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(smuggled)[8:])),
            )
            rebuilt.append((tbox, _jumbf.serialize_superbox(widened)[8:]))
        else:
            rebuilt.append((tbox, payload))

    forged = _jumbf.serialize_superbox(
        JumbfBox(
            description=store.description,
            content=(
                (
                    _jumbf.TBOX_SUPERBOX,
                    _jumbf.serialize_superbox(JumbfBox(description=manifest.description, content=tuple(rebuilt)))[8:],
                ),
            ),
        )
    )

    verdict, ok = _verify._check_assertions(parse_manifest_store(forged), Verdict(state=Provenance.INVALID))

    assert not ok
    assert StatusCode.ASSERTION_UNDECLARED in verdict.codes()
    assert StatusCode.ASSERTION_MISSING not in verdict.codes()


@pytest.mark.parametrize(
    ("hash_field", "expected"),
    [
        ({}, StatusCode.DATA_HASH_MISMATCH),
        ({"hash": None}, StatusCode.DATA_HASH_MALFORMED),
        ({"hash": "not bytes"}, StatusCode.DATA_HASH_MALFORMED),
        ({"hash": 12}, StatusCode.DATA_HASH_MALFORMED),
        ({"hash": []}, StatusCode.DATA_HASH_MALFORMED),
        ({"hash": {}}, StatusCode.DATA_HASH_MALFORMED),
        ({"hash": b""}, b""),
        ({"hash": b"\x00" * 32}, b"\x00" * 32),
    ],
    ids=["absent", "null", "text", "integer", "array", "map", "empty-bytes", "digest"],
)
def test_an_absent_hash_field_is_a_mismatch_and_a_malformed_one_is_not(
    hash_field: dict[str, object], expected: StatusCode | bytes
) -> None:
    """C2PA 15.12.1.1: "If the `hash` field is not present, then the manifest shall be
    rejected with a failure code of `assertion.dataHash.mismatch`."

    ABSENT AND MALFORMED ARE DIFFERENT CONDITIONS, and we collapsed them: any ``hash``
    that was not ``bytes`` -- including no ``hash`` at all -- produced
    ``assertion.dataHash.malformed``. The clause names ``mismatch`` for absence
    specifically, and says nothing that would license ``malformed`` there.

    The specification's choice is not arbitrary. An assertion with no ``hash`` is
    complete and well-formed and simply fails to bind anything, so the honest reading
    is that the binding did not hold. A ``hash`` present as a string, an integer, an
    array or a map is an assertion whose SYNTAX is wrong, which is what ``malformed``
    describes.

    ``empty-bytes`` and ``digest`` are the controls, and they are why this test can
    fail in both directions: both are present and well-typed, so both must be handed
    back for comparison rather than short-circuited. A branch keyed on emptiness or on
    truthiness instead of on PRESENCE would swallow the first of them.
    """
    # Built as object and narrowed at the call, because the whole point is to hand
    # _expected_digest values CborValue does not admit -- which is what an attacker
    # supplies and what the decoder will hand us.
    hash_data: dict[str, object] = {"exclusions": [{"start": 0, "length": 1}], "alg": "sha256", **hash_field}

    assert _verify._expected_digest(hash_data) == expected  # pyright: ignore[reportArgumentType] -- see above


@pytest.fixture(scope="session")
def store(signer: Signer) -> ManifestStore:
    """A genuine parsed manifest store, so reference targets are real boxes."""
    parsed = extract(mark("Hello world.", signer))
    assert parsed is not None
    return parsed


#: A CBOR map as the decoder produces one. Every CBOR item may be a key; ``MapKey``
#: preserves those Python cannot use directly in a dict.
CborMap = dict[_cbor.CborKey, _cbor.CborValue]


def _copy_cbor_map(
    mapping: dict[int | str | bytes, _cbor.CborValue] | dict[_cbor.CborKey, _cbor.CborValue],
) -> CborMap:
    """Copy either decoded-map branch into the generic key type."""
    return {key: value for key, value in mapping.items()}


def _widen(mapping: dict[str, _cbor.CborValue]) -> CborMap:
    """The same map, retyped for a ``CborValue`` slot.

    ``dict`` is invariant in its key type, so a ``dict[str, ...]`` is not a
    ``dict[int | str | bytes, ...]`` however obviously every key fits. Rebuilding is a
    real conversion rather than a cast, which is why it is allowed to be this dull.
    """
    return {key: value for key, value in mapping.items()}


def _is_string_cbor_map(value: object) -> TypeGuard[dict[str, _cbor.CborValue]]:
    """Recognize the string-keyed, writer-supported CBOR maps these mutators edit."""
    try:
        decoded = _cbor.loads(_cbor.dumps(value))
    except (TypeError, ValueError):
        return False
    return isinstance(decoded, dict) and all(isinstance(key, str) for key in decoded)


#: 8.4.2.1's store-relative form, naming THIS manifest: the shape of the spec's
#: own Example 1, naming the version-4 UUID pinned by conftest.
_STORE_RELATIVE = (
    f"self#jumbf=/c2pa/urn:c2pa:00000000-0000-4000-8000-000000000007/c2pa.assertions/{ASSERTION_AI_DISCLOSURE}"
)


def _icon(
    store: ManifestStore, *, drop: tuple[str, ...] = (), **overrides: _cbor.CborValue
) -> dict[str, _cbor.CborValue]:
    """A hashed-uri-map pointing at a real assertion, with fields replaced or removed.

    ``drop`` rather than a sentinel value: every ill-typed override a test wants to
    pass -- an integer URL, a string digest -- is itself a perfectly good
    ``CborValue``, so the only thing needing special handling is ABSENCE, and a
    sentinel would have to be smuggled through a slot typed to reject it.
    """
    label = ASSERTION_AI_DISCLOSURE
    reference: dict[str, _cbor.CborValue] = {
        "url": f"self#jumbf=c2pa.assertions/{label}",
        "hash": hashlib.sha256(store.assertion_bytes[label]).digest(),
        "alg": "sha256",
        **overrides,
    }
    return {key: value for key, value in reference.items() if key not in drop}


@pytest.mark.parametrize(
    ("drop", "overrides", "expected"),
    [
        ((), {}, None),
        (("alg",), {}, None),
        (("url",), {}, StatusCode.HASHED_URI_MISSING),
        ((), {"url": 7}, StatusCode.HASHED_URI_MISSING),
        ((), {"url": "self#jumbf=c2pa.assertions/c2pa.icon"}, StatusCode.HASHED_URI_MISSING),
        ((), {"url": "self#jumbf=/c2pa/urn:c2pa:other/c2pa.assertions/x"}, StatusCode.HASHED_URI_MISSING),
        (("hash",), {}, StatusCode.HASHED_URI_MISMATCH),
        ((), {"hash": "not bytes"}, StatusCode.HASHED_URI_MISMATCH),
        ((), {"hash": b"\x00" * 32}, StatusCode.HASHED_URI_MISMATCH),
        ((), {"alg": "md5"}, StatusCode.ALGORITHM_UNSUPPORTED),
        ((), {"url": "https://example.invalid/icon.svg"}, None),
        ((), {"url": "ipfs://bafy/icon.svg"}, None),
        ((), {"url": "view-source:https://x/i.svg"}, None),
        ((), {"url": "z39.50r://host/db"}, None),
        ((), {"url": "x-my+scheme:opaque"}, None),
        ((), {"url": "0x:icon.svg"}, StatusCode.HASHED_URI_MISSING),
        ((), {"url": "c2pa.assertions/icon:1"}, StatusCode.HASHED_URI_MISSING),
        (("hash",), {"url": _STORE_RELATIVE}, StatusCode.HASHED_URI_MISMATCH),
        ((), {"url": _STORE_RELATIVE}, None),
        ((), {"url": ""}, StatusCode.HASHED_URI_MISSING),
        ((), {"url": "c2pa.assertions/c2pa.icon"}, StatusCode.HASHED_URI_MISSING),
        ((), {"url": "jumbf=c2pa.assertions/c2pa.icon"}, StatusCode.HASHED_URI_MISSING),
        ((), {"url": "SELF#jumbf=c2pa.assertions/c2pa.icon"}, StatusCode.HASHED_URI_MISSING),
    ],
    ids=[
        "resolves",
        "alg-inherited-from-the-claim",
        "no-url",
        "url-not-a-string",
        "destination-absent",
        "another-manifest",
        "no-hash",
        "hash-not-bytes",
        "wrong-hash",
        "unsupported-alg",
        "external-not-retrieved",
        "external-non-http-scheme",
        "scheme-with-a-hyphen",
        "scheme-with-a-dot",
        "scheme-with-a-plus",
        "digit-initial-is-not-a-scheme",
        "colon-not-at-the-start",
        "store-relative-wrong-hash",
        "store-relative-resolves",
        "empty",
        "relative-without-the-prefix",
        "prefix-truncated",
        "prefix-miscased",
    ],
)
def test_a_hashed_uri_reference_follows_the_15_10_3_3_procedure(
    store: ManifestStore, drop: tuple[str, ...], overrides: dict[str, _cbor.CborValue], expected: StatusCode | None
) -> None:
    """C2PA 15.10.3.3, "Validation of References".

    A missing or unlocatable destination is ``hashedURI.missing``; a missing or
    mismatching ``hash`` is ``hashedURI.mismatch``. Those codes are deliberately NOT
    ``assertion.missing``/``assertion.hashedURI.mismatch`` -- a reference is a field
    inside a structure pointing elsewhere, so naming the assertion misnames the object.

    External references are passed over rather than failed: the clause scopes external
    validation to a resource "the validator chooses to retrieve", and this package
    retrieves none. An external reference is recognised by an RFC 3986 URI scheme;
    the rows cover its initial-letter and ``+.-`` rules.

    ``store-relative-resolves`` is 8.4.2.1's second URI shape, from the specification's
    Example 1. ``alg-inherited-from-the-claim`` is the 15.4.2 control.
    """
    reference = _icon(store, drop=drop, **overrides)

    assert _verify._reference_status(reference, store, {}) is expected


def _embedded_icon_box() -> JumbfBox:
    """A C2PA 18.12 embedded-data assertion carrying one SVG icon.

    ISO/IEC 19566-5 Annex B defines the ``bfdb`` payload as an eight-bit toggle
    followed by a NUL-terminated media type and an optional NUL-terminated file name.
    Zero means embedded, with no file name. ``bidb`` carries the file bytes.
    """
    return JumbfBox(
        description=DescriptionBox(
            uuid=bytes.fromhex("40CB0C32BB8A489DA70B2AD6F47F4369"),
            label="c2pa.icon",
            requestable=True,
        ),
        content=((b"bfdb", b"\x00image/svg+xml\x00"), (b"bidb", b"<svg/>")),
    )


@pytest.mark.parametrize("matches", [True, False], ids=["matching", "mismatching"])
def test_the_claim_generators_embedded_icon_is_validated_on_signed_wire(signer: Signer, matches: bool) -> None:
    """C2PA 15.6.2 routes a present generator icon through reference validation."""
    icon_box = _embedded_icon_box()
    digest = hashlib.sha256(_jumbf.serialize_superbox(icon_box)[8:]).digest()

    def add_icon(_items: list[Assertion], claim: dict[str, object]) -> None:
        generator = claim["claim_generator_info"]
        assert isinstance(generator, dict)
        claim["claim_generator_info"] = {
            **generator,
            "icon": _icon_reference(
                "self#jumbf=c2pa.assertions/c2pa.icon",
                digest if matches else b"\x00" * 32,
            ),
        }

    verdict = verify(_resigned(signer, add_icon, extra_assertions=(icon_box,)))

    assert verdict.state is (Provenance.VALID if matches else Provenance.INVALID)
    assert (StatusCode.HASHED_URI_MISMATCH in verdict.codes()) is not matches
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


@pytest.mark.parametrize("poisoned", [0, 1], ids=["first", "second"])
@pytest.mark.parametrize(
    "site",
    ["softwareAgent", "softwareAgents", "templates"],
    ids=["softwareAgent", "softwareAgents", "templates"],
)
def test_an_actions_assertion_icon_is_validated_too(signer: Signer, site: str, poisoned: int) -> None:
    """C2PA 15.10.3.2.3 routes three more icons through the same 15.10.3.3 procedure:

    > "If there is a `softwareAgent` field in the action-common-map-v2 or one or more
    > `softwareAgents` listed in the `softwareAgents` field of the actions-map-v2: If
    > there is an `icon` field in the generator-info-map, then it shall be validated as
    > described in Section 15.10.3.3."

    > "For each template in the `templates` list: If there is an `icon` field in the
    > action-template-map-v2, then it shall be validated as described in Section
    > 15.10.3.3."

    ``softwareAgents`` is the plural field on the ASSERTION, ``softwareAgent`` the
    singular field on one ACTION: different fields at different depths, which is why a
    single collector has to walk both.

    The second element is the discriminating input: every list member must be checked,
    not only the first.

    The actions assertion is otherwise conforming, ``digitalSourceType`` included, so
    the icon is the only defect and the test keeps discriminating as other rules tighten.
    """
    icon_box = _embedded_icon_box()
    digest = hashlib.sha256(_jumbf.serialize_superbox(icon_box)[8:]).digest()
    good = _icon_reference("self#jumbf=c2pa.assertions/c2pa.icon", digest)
    bad = _icon_reference("self#jumbf=c2pa.assertions/c2pa.icon", b"\x00" * 32)
    icons = [good, good]
    icons[poisoned] = bad

    agents: list[_cbor.CborValue] = [{"name": f"agent {n}", "icon": icon} for n, icon in enumerate(icons)]
    created: CborMap = {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED}
    payload: CborMap = {"actions": [created]}

    if site == "softwareAgent":
        payload["actions"] = [created, {"action": "c2pa.edited", "softwareAgent": agents[1]}]
        if poisoned == 0:
            payload["actions"] = [{**created, "softwareAgent": agents[0]}, {"action": "c2pa.edited"}]
    if site == "softwareAgents":
        payload["softwareAgents"] = agents
    if site == "templates":
        payload["templates"] = [{"action": "*", "icon": icons[0]}, {"action": "c2pa.edited", "icon": icons[1]}]

    def add_actions(items: list[Assertion], _claim: dict[str, object]) -> None:
        items[0] = Assertion(label=ASSERTION_ACTIONS, payload=payload)

    verdict = verify(_resigned(signer, add_actions, extra_assertions=(icon_box,)))

    assert verdict.state is Provenance.INVALID, f"a poisoned icon at index {poisoned} of {site} was accepted"
    assert StatusCode.HASHED_URI_MISMATCH in verdict.codes()


#: One actions assertion each, so a row reads as what it is: which assertion holds the
#: inception action, and which merely edits.
_SRC = DIGITAL_SOURCE_TYPE_TRAINED

_ACTIONS_CREATED: CborMap = {"actions": [{"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED}]}
_ACTIONS_OPENED: CborMap = {"actions": [{"action": "c2pa.opened"}]}
_ACTIONS_EDITED: CborMap = {"actions": [{"action": "c2pa.edited"}]}

#: Valid under no ordering. Named so the empty set reads as a claim, not an oversight.
_NEITHER: set[bool] = set()


@pytest.mark.parametrize(
    ("first", "second", "accepted_when"),
    [
        (_ACTIONS_CREATED, _ACTIONS_EDITED, {False}),
        (_ACTIONS_CREATED, _ACTIONS_OPENED, _NEITHER),
        (_ACTIONS_CREATED, _ACTIONS_CREATED, _NEITHER),
        (_ACTIONS_EDITED, _ACTIONS_CREATED, {True}),
        (_ACTIONS_EDITED, _ACTIONS_EDITED, _NEITHER),
    ],
    ids=["inception-in-the-first", "two-inceptions", "two-created", "inception-in-the-second", "no-inception"],
)
@pytest.mark.parametrize("reversed_order", [False, True], ids=["claim-order-matches", "claim-order-reversed"])
def test_only_the_first_actions_assertion_may_carry_the_inception(
    store: ManifestStore,
    first: CborMap,
    second: CborMap,
    accepted_when: set[bool],
    reversed_order: bool,
) -> None:
    """C2PA 15.10.3.2.3 and 15.10.1.2: the inception action belongs to the FIRST actions
    assertion, and to exactly one.

    WE INSPECTED ONE LABEL. `_store_shape_status` read `assertions.get("c2pa.actions.v2")`
    exactly, so a store carrying both `c2pa.actions.v2` and `c2pa.actions.v2__1` -- each
    declared, hash-matched, each with its own inception action -- was accepted. 6.4's
    `__N` convention is what makes the second label legal, which is why reading one label
    is not enough.
    """
    label, other = ASSERTION_ACTIONS, f"{ASSERTION_ACTIONS}__1"

    # BOTH assertions are real boxes under their OWN labels, built through the helper so
    # each one's bytes decode to its own payload. Mapping two labels to byte-identical
    # payloads is a state the parser refuses:
    # both would decode to the same label and _children_with_bytes rejects duplicates.
    tampered = _with_assertion(_with_assertion(store, label, first), other, second)

    # THE SECOND ASSERTION IS LINKED FIRST when reversed_order is set. That is the only
    # way to separate claim order from store order: the store's dict keeps `label` at
    # position 0 either way, so a version of _actions_labels walking
    # manifest.assertions.keys() instead of the claim's links passes every forward row.
    if reversed_order:
        ordered = tampered.claim["created_assertions"]
        assert isinstance(ordered, list)
        rotated: list[_cbor.CborValue] = [*ordered[-1:], *ordered[:-1]]
        tampered = dataclasses.replace(tampered, claim={**tampered.claim, "created_assertions": rotated})

    verdict, accepted = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert accepted is (reversed_order in accepted_when)
    # 15.10.3.2.3 names the code for every rejecting row here. A bare bool would accept
    # assertion.missing or claim.malformed just as readily, and a mutation that returned
    # the wrong one survived the whole suite until this line existed.
    if not accepted:
        assert StatusCode.ASSERTION_ACTION_MALFORMED in verdict.codes()


@pytest.mark.parametrize(
    ("gathered", "expected"),
    [
        ("declares-it", None),
        ("declares-nothing", StatusCode.ASSERTION_UNDECLARED),
        ("wrong-hash", StatusCode.ASSERTION_HASHED_URI_MISMATCH),
        ("empty-list", StatusCode.CLAIM_MALFORMED),
        ("not-a-list", StatusCode.CLAIM_MALFORMED),
    ],
    ids=["declares-it", "declares-nothing", "wrong-hash", "empty-list", "not-a-list"],
)
def test_an_assertion_declared_in_gathered_assertions_is_declared(
    store: ManifestStore, gathered: str, expected: StatusCode | None
) -> None:
    """C2PA 15.10.3.1: "Each assertion in the created_assertions **and
    gathered_assertions** fields of the claim (and in the assertions field of a v1
    claim) is a hashed_uri structure... Even though the assertions listed in the
    gathered_assertions field were not created by the claim generator, they are still
    part of the Claim and are therefore also validated according to this validation
    algorithm."

    And the rule #82 quotes: an assertion is undeclared only if it is "not referenced by
    an element of **either** the created_assertions **or** gathered_assertions arrays".

    ``claim-map-v2`` declares the field ``? "gathered_assertions": [1* $hashed-uri-map]``
    — optional, and non-empty **if present**, which is why ``empty-list`` is
    ``claim.malformed`` rather than simply ignored. ``wrong-hash`` is the control that
    matters: a gathered assertion is authenticated by the same hashed URI as a created
    one, so declaring it is not the same as trusting it.
    """
    label = "c2patxt.gathered"
    raw = b"\xa1\x64note\xf5"
    links: list[_cbor.CborValue] = [
        {
            "url": f"self#jumbf=c2pa.assertions/{label}",
            "hash": b"\x00" * 32 if gathered == "wrong-hash" else hashlib.sha256(raw).digest(),
            "alg": "sha256",
        }
    ]
    field: _cbor.CborValue = {
        "declares-it": links,
        "wrong-hash": links,
        "declares-nothing": None,
        "empty-list": [],
        "not-a-list": "nope",
    }[gathered]

    claim = dict(store.claim)
    if field is not None:
        claim["gathered_assertions"] = field
    tampered = dataclasses.replace(
        store,
        claim=claim,
        assertions={**store.assertions, label: {"note": True}},
        assertion_bytes={**store.assertion_bytes, label: raw},
    )

    verdict, ok = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert ok is (expected is None)
    if expected is not None:
        assert expected in verdict.codes()


def test_each_matched_claim_link_records_its_original_url_in_order(store: ManifestStore) -> None:
    """15.10.3.1 records one success per created or gathered hashed URI."""
    created = store.claim["created_assertions"]
    assert isinstance(created, list)
    duplicate = next(
        link
        for link in created
        if isinstance(link, dict) and str(link.get("url", "")).endswith(ASSERTION_AI_DISCLOSURE)
    )
    claim = {
        **store.claim,
        "created_assertions": [*created, duplicate],
        "gathered_assertions": [duplicate],
    }

    verdict, ok = _verify._check_assertions(dataclasses.replace(store, claim=claim), Verdict(state=Provenance.INVALID))

    assert ok
    expected = [link["url"] for link in [*created, duplicate, duplicate] if isinstance(link, dict)]
    actual = [status.url for status in verdict.success if status.code is StatusCode.ASSERTION_HASHED_URI_MATCH]
    assert actual == expected


def test_hash_matches_before_a_later_link_failure_are_not_discarded(store: ManifestStore) -> None:
    """A later mismatch invalidates the claim but not the matches already established."""
    created = store.claim["created_assertions"]
    assert isinstance(created, list)
    good: list[CborMap] = [_copy_cbor_map(link) for link in created if isinstance(link, dict)]
    assert len(good) == len(created)
    damaged = {**good[-1], "hash": b"\x00" * 32}
    claim = {**store.claim, "created_assertions": [*good[:-1], damaged]}

    verdict, ok = _verify._check_assertions(dataclasses.replace(store, claim=claim), Verdict(state=Provenance.INVALID))

    assert not ok
    actual = [status.url for status in verdict.success if status.code is StatusCode.ASSERTION_HASHED_URI_MATCH]
    assert actual == [link["url"] for link in good[:-1]]
    assert StatusCode.ASSERTION_HASHED_URI_MISMATCH in verdict.codes()


@pytest.mark.parametrize(
    ("offset", "inside"),
    [
        (datetime.timedelta(0), True),
        (datetime.timedelta(microseconds=-1), False),
    ],
    ids=["the-first-instant", "one-microsecond-before"],
)
def test_the_validity_window_includes_its_own_endpoints(
    signing_key: Ed25519PrivateKey,
    signing_certificate: x509.Certificate,
    offset: datetime.timedelta,
    inside: bool,
) -> None:
    """C2PA 15.8.2 includes both certificate-validity endpoints."""
    lower = signing_certificate.not_valid_before_utc
    upper = signing_certificate.not_valid_after_utc
    signer = Signer(private_key=signing_key, certificates=(signing_certificate,))
    marked = mark("Hello world.", signer, when=WHEN)

    for instant in (lower + offset, upper - offset):
        verdict = verify(marked, context=VerifyContext(now=instant))
        assert (verdict.state is Provenance.VALID) is inside
        assert (StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY in verdict.codes()) is not inside


def test_an_icon_in_a_second_actions_assertion_is_checked_too(store: ManifestStore) -> None:
    """6.4 lets a manifest carry ``c2pa.actions.v2`` and ``c2pa.actions.v2__1``, and
    15.10.3.2.3 obliges the icon check on each. We collected references from the base
    label alone, so a poisoned icon in the second instance was never looked at -- while
    ``_count_hard_bindings`` in the same file already counted ``__N`` instances. An
    inconsistency inside one module, which is the kind that survives review.

    The first assertion keeps the inception action so the manifest is otherwise sound
    and the only thing under test is whether the second one's icon was read.
    """
    label, other = ASSERTION_ACTIONS, f"{ASSERTION_ACTIONS}__1"
    digest = hashlib.sha256(store.assertion_bytes[label]).digest()
    links = store.claim["created_assertions"]
    assert isinstance(links, list)

    poisoned: CborMap = {"name": "x", "icon": _widen(_icon(store, hash=b"\x00" * 32))}
    claim = {
        **store.claim,
        "created_assertions": [*links, {"url": f"self#jumbf=c2pa.assertions/{other}", "hash": digest, "alg": "sha256"}],
    }
    tampered = dataclasses.replace(
        store,
        claim=claim,
        assertions={
            **store.assertions,
            label: {"actions": [{"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED}]},
            other: {"actions": [{"action": "c2pa.edited"}], "softwareAgents": [poisoned]},
        },
        assertion_bytes={**store.assertion_bytes, other: store.assertion_bytes[label]},
    )

    verdict, ok = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert not ok
    assert StatusCode.HASHED_URI_MISMATCH in verdict.codes()


def _restore_manifest(original: ManifestStore, rebuild: Callable[[JumbfBox], tuple[tuple[bytes, bytes], ...]]) -> str:
    """Re-wrap a manifest store whose boxes have been rebuilt by ``rebuild``.

    Returns marked text, so the result goes through the SELECTOR ENCODING and back --
    which is the part these tests are about. The hard binding will not match; it never
    gets that far, because the parse fails first and ``verify`` reports the parse's code.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import parse_superbox
    from c2patxt._selectors import build_wrapper

    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])
    content = rebuild(manifest)
    forged = _jumbf.serialize_superbox(
        JumbfBox(
            description=store.description,
            content=(
                (
                    _jumbf.TBOX_SUPERBOX,
                    _jumbf.serialize_superbox(JumbfBox(description=manifest.description, content=content))[8:],
                ),
            ),
        )
    )
    return "Hello world." + build_wrapper(forged)


@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        ("claim-cbor", StatusCode.CLAIM_CBOR_INVALID),
        ("no-claim-box", StatusCode.CLAIM_MISSING),
        ("claim-without-cbor", StatusCode.CLAIM_MISSING),
        ("assertion-cbor", StatusCode.ASSERTION_CBOR_INVALID),
        ("metadata-json", StatusCode.ASSERTION_JSON_INVALID),
        ("duplicate-label", StatusCode.ASSERTION_MISSING),
        ("duplicate-claim", StatusCode.CLAIM_MULTIPLE),
    ],
    ids=[
        "claim-cbor",
        "no-claim-box",
        "claim-without-cbor",
        "assertion-cbor",
        "metadata-json",
        "duplicate-label",
        "duplicate-claim",
    ],
)
def test_verify_reports_the_specific_parse_code(signer: Signer, damage: str, expected: StatusCode) -> None:
    """Every parse failure reaches public ``verify`` with its specific code.

    ``manifest.text.corruptedWrapper``
    is 15.12.1.3.2's code for a wrapper with an "invalid version, algorithm, or manifest
    length" -- damage to the selector run. Every case here is an intact wrapper around a
    manifest that is wrong INSIDE, and reporting the carrier's code sends an investigator
    hunting text corruption that is not there.

    Driven through the public entry point. The parse-level tests in
    ``test_extract.py`` assert ``MarkCorruptError.code`` and are right to; this asserts
    the one thing they cannot, which is that the code survives the trip into a
    ``Verdict``.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt.manifest import ASSERTION_METADATA, LABEL_ASSERTION_STORE, LABEL_CLAIM

    original = extract(mark("Hello world.", signer))
    assert original is not None

    def rebuild(manifest: JumbfBox) -> tuple[tuple[bytes, bytes], ...]:
        out: list[tuple[bytes, bytes]] = []
        for tbox, payload in manifest.content:
            child, _ = _reparse(payload)
            label = child.description.label
            if damage == "no-claim-box" and label == LABEL_CLAIM:
                continue
            if damage == "claim-cbor" and label == LABEL_CLAIM:
                child = JumbfBox(description=child.description, content=((b"cbor", b"\xff"),))
            if damage == "claim-without-cbor" and label == LABEL_CLAIM:
                child = JumbfBox(description=child.description, content=((b"json", b"{}"),))
            if damage in {"assertion-cbor", "metadata-json", "duplicate-label"} and label == LABEL_ASSERTION_STORE:
                child = _damage_store(child, damage, ASSERTION_METADATA)
            out.append((tbox, _jumbf.serialize_superbox(child)[8:]))
            if damage == "duplicate-claim" and label == LABEL_CLAIM:
                out.append((tbox, _jumbf.serialize_superbox(child)[8:]))
        return tuple(out)

    damaged = _restore_manifest(original, rebuild)
    with pytest.raises(MarkCorruptError) as caught:
        extract(damaged)
    assert caught.value.code is expected

    verdict = verify(damaged)

    assert verdict.state is Provenance.INVALID
    assert expected in verdict.codes()
    assert StatusCode.TEXT_CORRUPTED_WRAPPER not in verdict.codes(), "the carrier is intact; only the manifest is not"
    if expected is StatusCode.CLAIM_MULTIPLE:
        assert StatusCode.GENERAL_ERROR not in verdict.codes()


def _damage_store(store: JumbfBox, damage: str, metadata_label: str) -> JumbfBox:
    """Break one assertion inside the assertion store, in the way ``damage`` names."""
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse

    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in store.content:
        box, _ = _reparse(payload)
        if damage == "metadata-json" and box.description.label == metadata_label:
            box = JumbfBox(description=box.description, content=((b"json", b"{not json"),))
        if damage == "assertion-cbor" and box.description.label != metadata_label:
            box = JumbfBox(description=box.description, content=((b"cbor", b"\xff"),))
        rebuilt.append((tbox, _jumbf.serialize_superbox(box)[8:]))
        if damage == "duplicate-label":
            rebuilt.append((tbox, _jumbf.serialize_superbox(box)[8:]))
    return JumbfBox(description=store.description, content=tuple(rebuilt))


def test_a_second_hard_binding_is_rejected_by_the_store_check(store: ManifestStore) -> None:
    """C2PA 15.10.1.2: "If there is more than one such assertion, the manifest shall be
    rejected with a failure code of `assertion.multipleHardBindings`."

    The second box is relabelled and re-serialized so the parsed store contains two
    reachable hard bindings. The otherwise complete manifest isolates this rule from
    the earlier required-assertion check.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import DescriptionBox as Description
    from c2patxt._jumbf import parse_superbox

    label = ASSERTION_HASH_DATA
    second = f"{label}__1"

    original, _ = parse_superbox(store.raw)
    manifest, _ = _reparse(original.content[0][1])

    def labelled(payload: bytes, name: str) -> bool:
        return _reparse(payload)[0].description.label == name

    assertion_store, _ = _reparse(
        next(payload for _, payload in manifest.content if labelled(payload, LABEL_ASSERTION_STORE))
    )
    binding, _ = _reparse(next(p for _, p in assertion_store.content if labelled(p, label)))
    relabelled = _jumbf.serialize_superbox(
        JumbfBox(
            description=Description(uuid=binding.description.uuid, label=second, requestable=True),
            content=binding.content,
        )
    )[8:]

    links = store.claim["created_assertions"]
    assert isinstance(links, list)
    claim = {
        **store.claim,
        "created_assertions": [
            *links,
            {
                "url": f"self#jumbf=c2pa.assertions/{second}",
                "hash": hashlib.sha256(relabelled).digest(),
                "alg": "sha256",
            },
        ],
    }
    tampered = dataclasses.replace(
        store,
        claim=claim,
        assertions={**store.assertions, second: store.assertions[label]},
        assertion_bytes={**store.assertion_bytes, second: relabelled},
    )

    verdict, ok = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert not ok
    assert StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS in verdict.codes()


@pytest.mark.parametrize(
    ("when", "state"),
    [
        (datetime.datetime(2026, 1, 15, tzinfo=datetime.timezone.utc), Provenance.VALID),
        (datetime.datetime(2026, 3, 1, tzinfo=datetime.timezone.utc), Provenance.INVALID),
    ],
    ids=["before-the-ca-lapses", "after-the-ca-lapses"],
)
def test_an_expired_intermediate_invalidates_the_mark(
    when: datetime.datetime,
    state: Provenance,
) -> None:
    """C2PA 15.8.2: "the C2PA Manifest is valid if the current time at validation is
    within the validity period of the signer's certificate **and all CA certificates up
    to the trust anchor**."

    The same two-certificate mark is valid while both carried certificates are inside
    their windows and invalid after the intermediate expires. This drives the public
    verdict rather than only the validity helper.
    """
    signer = _signer_with_carried_intermediate(
        intermediate_not_after=datetime.datetime(2026, 2, 1, tzinfo=datetime.timezone.utc)
    )
    root_key = Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
    omitted_root = build_certificate(root_key, common_name="c2patxt omitted root", conformant=False)
    signer.certificates[-1].verify_directly_issued_by(omitted_root)
    assert omitted_root not in signer.certificates, "the external anchor must not be carried in x5chain"
    evaluator = RecordingTrustEvaluator(trusted=False)
    anchor_der = omitted_root.public_bytes(Encoding.DER)
    context = VerifyContext(
        now=when,
        anchors_pem=omitted_root.public_bytes(Encoding.PEM),
        trust_evaluator=evaluator,
    )

    creation_time = datetime.datetime(2026, 1, 15, tzinfo=datetime.timezone.utc)
    verdict = verify(mark("Hello world.", signer, when=creation_time), context=context)

    assert verdict.state is state
    assert (StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY in verdict.codes()) is (state is Provenance.INVALID)
    if state is Provenance.INVALID:
        assert not evaluator.calls, "the expired chain reached the trust backend"
        status = next(item for item in verdict.failure if item.code is StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY)
        assert status.explanation is not None
        assert "x5chain[1] carried CA" in status.explanation
    else:
        chain_der = tuple(certificate.public_bytes(Encoding.DER) for certificate in signer.certificates)
        assert evaluator.calls == [(chain_der, (anchor_der,))]


def test_one_assertion_can_be_authenticated_under_two_hash_algorithms(signer: Signer) -> None:
    """C2PA 15.4.2 permits each hashed-URI map to select its hash algorithm."""
    from c2patxt.manifest import hashed_uri

    url = f"self#jumbf=c2pa.assertions/{ASSERTION_AI_DISCLOSURE}"

    def add_sha384_link(items: list[Assertion], links: list[dict[str, object]]) -> None:
        assertion = next(item for item in items if item.label == ASSERTION_AI_DISCLOSURE)
        links.append(hashed_uri(assertion.to_box(), url, "sha384"))

    verdict = verify(_resigned(signer, _unchanged, mutate_links=add_sha384_link))

    assert verdict.state is Provenance.VALID
    matches = [
        status
        for status in verdict.success
        if status.code is StatusCode.ASSERTION_HASHED_URI_MATCH and status.url == url
    ]
    assert len(matches) == 2


def test_an_external_claim_link_reports_outside_manifest_through_public_verify(signer: Signer) -> None:
    """The 15.10.3.1 status survives serialized claim parsing and verdict assembly."""

    def point_outside(_items: list[Assertion], links: list[dict[str, object]]) -> None:
        links[0] = {**links[0], "url": "https://elsewhere.invalid/assertion"}

    verdict = verify(_resigned(signer, _unchanged, mutate_links=point_outside))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.ASSERTION_OUTSIDE_MANIFEST in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


@pytest.mark.parametrize(
    "damage",
    [
        "instanceID",
        "signature",
        "created_assertions",
        "claim_generator_info",
        "name",
        "array",
        "created-not-array",
        "created-empty",
        "created-item-not-map",
        "gathered-not-array",
    ],
    ids=[
        "instanceID",
        "signature",
        "created_assertions",
        "claim_generator_info",
        "generator-without-a-name",
        "generator-as-an-array",
        "created-not-an-array",
        "created-empty",
        "created-item-not-a-map",
        "gathered-not-an-array",
    ],
)
def test_a_claim_with_a_missing_or_malformed_required_field_is_rejected(signer: Signer, damage: str) -> None:
    """C2PA 15.6.2 names four fields -- ``instanceID``, ``signature``,
    ``created_assertions``, ``claim_generator_info`` -- and says "If any are absent, then
    the claim shall be rejected with a failure code of `claim.malformed`". It adds: "If
    the `claim_generator_info` field does not contain a `name` field, the claim shall be
    rejected with a failure code of `claim.malformed`."

    The claim is re-signed for each case rather than mutated after parsing, so
    ``claim_bytes`` and the decoded claim agree and the signature is genuine. A claim
    whose bytes and dict disagree is a state no producer can emit, and testing against
    one would prove the rule about an input the parser cannot deliver.

    ``generator-as-an-array`` is the subtle row: ``claim-map`` v1 declared
    ``claim_generator_info`` as an ARRAY of generator-info-maps and ``claim-map-v2``
    declares a single map. We emit ``c2pa.claim.v2``, so an array is malformed here --
    and it is exactly what a producer written against the older schema would send.
    """
    from c2patxt import _cose, _fixpoint
    from c2patxt.manifest import DEFAULT_HASH_ALGORITHM, hashed_uri

    text = "Hello world."
    normalized = unicodedata.normalize("NFC", text)
    start = len(normalized.encode("utf-8"))
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        hash_data = Assertion(
            label=ASSERTION_HASH_DATA,
            payload={
                "exclusions": [{"start": start, "length": exclusion_length}],
                "alg": DEFAULT_HASH_ALGORITHM,
                "hash": digest,
                "pad": b"",
            },
        )
        payload: dict[str, object] = {
            "instanceID": "xmp:iid:1",
            "claim_generator_info": {"name": "c2patxt"},
            "created_assertions": [hashed_uri(hash_data.to_box(), f"self#jumbf=c2pa.assertions/{ASSERTION_HASH_DATA}")],
            "signature": "self#jumbf=c2pa.signature",
            "alg": DEFAULT_HASH_ALGORITHM,
        }
        if damage == "name":
            payload["claim_generator_info"] = {"version": "1.0"}
        elif damage == "array":
            payload["claim_generator_info"] = [{"name": "c2patxt"}]
        elif damage == "created-not-array":
            payload["created_assertions"] = "not an array"
        elif damage == "created-empty":
            payload["created_assertions"] = []
        elif damage == "created-item-not-map":
            payload["created_assertions"] = [42]
        elif damage == "gathered-not-array":
            payload["gathered_assertions"] = "not an array"
        else:
            del payload[damage]

        claim_bytes = _cbor.dumps(payload)
        boxes = (
            JumbfBox(
                description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
                content=((b"jumb", _jumbf.serialize_superbox(hash_data.to_box())[8:]),),
            ),
            JumbfBox(
                description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                content=((b"cbor", claim_bytes),),
            ),
        )
        signed = _cose._prepare_signed_claim(signer, claim_bytes)

        def assemble(pad: int) -> str:
            return _test_wrapper(
                boxes,
                _cose._serialize_signed_claim(signed, pad=pad),
                manifest_label="urn:c2pa:00000000-0000-4000-8000-000000000007",
            )

        return assemble

    wrapper, _ = _fixpoint.solve(prepare)
    verdict = verify(normalized + wrapper)

    assert verdict.state is Provenance.INVALID
    assert StatusCode.CLAIM_MALFORMED in verdict.codes()


@pytest.mark.parametrize(
    ("declare", "state"),
    [("gathered", Provenance.VALID), ("nowhere", Provenance.INVALID)],
    ids=["declared-as-gathered", "declared-nowhere"],
)
def test_a_gathered_assertion_survives_the_wire(signer: Signer, declare: str, state: Provenance) -> None:
    """A signed gathered-assertion link survives parsing and validation.

    Both rows use the SAME assertion in the SAME store. Only the claim differs -- one
    declares it in ``gathered_assertions``, the other declares it nowhere. So the test
    isolates the field itself rather than the presence of an extra box, and a parse that
    drops the field turns the first row into the second.
    """
    from c2patxt import _cose, _fixpoint
    from c2patxt import manifest as manifest_module
    from c2patxt.manifest import DEFAULT_HASH_ALGORITHM, hashed_uri
    from tests.conftest import WHEN

    text = "Hello world."
    normalized = unicodedata.normalize("NFC", text)
    start = len(normalized.encode("utf-8"))
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    extra = Assertion(label="c2patxt.gathered", payload={"note": "from an ingredient"})

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        required = [
            manifest_module._actions_assertion(WHEN),
            manifest_module._ai_disclosure_assertion(DISCLOSURE),
            manifest_module._metadata_assertion(DISCLOSURE),
            manifest_module._hash_data_assertion(
                digest,
                start,
                exclusion_length,
                algorithm=DEFAULT_HASH_ALGORITHM,
                pad=b"",
            ),
        ]
        flat = [*required, extra]
        created = [hashed_uri(item.to_box(), f"self#jumbf=c2pa.assertions/{item.label}") for item in required]
        payload: dict[str, object] = {
            "instanceID": "xmp:iid:1",
            "claim_generator_info": {"name": "c2patxt"},
            "created_assertions": created,
            "signature": "self#jumbf=c2pa.signature",
            "alg": DEFAULT_HASH_ALGORITHM,
        }
        if declare == "gathered":
            payload["gathered_assertions"] = [hashed_uri(extra.to_box(), f"self#jumbf=c2pa.assertions/{extra.label}")]

        claim_bytes = _cbor.dumps(payload)
        boxes = (
            JumbfBox(
                description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
                content=tuple((b"jumb", _jumbf.serialize_superbox(item.to_box())[8:]) for item in flat),
            ),
            JumbfBox(
                description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                content=((b"cbor", claim_bytes),),
            ),
        )
        signed = _cose._prepare_signed_claim(signer, claim_bytes)

        def assemble(pad: int) -> str:
            return _test_wrapper(
                boxes,
                _cose._serialize_signed_claim(signed, pad=pad),
                manifest_label="urn:c2pa:00000000-0000-4000-8000-000000000007",
            )

        return assemble

    wrapper, _ = _fixpoint.solve(prepare)
    verdict = verify(normalized + wrapper)

    assert verdict.state is state
    assert (StatusCode.ASSERTION_UNDECLARED in verdict.codes()) is (state is Provenance.INVALID)


#: Each case re-signs a wire-legal manifest whose sole defect is the named rule; the
#: binding, signature and certificate-validity checks otherwise succeed.
_WIRE_DEFECTS = "wire defects"


def _resigned(
    signer: Signer,
    mutate: Callable[[list[Assertion], dict[str, object]], None],
    *,
    prefix: str = "Hello world.",
    suffix: str = "",
    excluded_prefix_ranges: tuple[tuple[int, int], ...] = (),
    gathered_labels: tuple[str, ...] = (),
    extra_assertions: tuple[JumbfBox, ...] = (),
    mutate_links: Callable[[list[Assertion], list[dict[str, object]]], None] | None = None,
    signature_serializer: Callable[[Signer, bytes, int], bytes] | None = None,
) -> str:
    """Marked text whose manifest is rebuilt, mutated and re-signed.

    ``mutate`` receives the assertion list and the claim payload BEFORE the claim is
    encoded, so a test can change either and still get a document that parses, links,
    hash-matches and verifies its signature. Everything else about the mark is correct.

    Built rather than embedded because ``embed()`` cannot emit any of these defects --
    which is the point: a rule reachable only from a third party's manifest still has to
    be driven from bytes.
    """
    import hashlib
    import unicodedata

    from c2patxt import _cose
    from c2patxt import manifest as manifest_module
    from c2patxt.manifest import DEFAULT_HASH_ALGORITHM, hashed_uri
    from tests.conftest import WHEN

    prefix_bytes = prefix.encode("utf-8")
    cursor = 0
    covered: list[bytes] = []
    for extra_start, extra_length in excluded_prefix_ranges:
        assert cursor <= extra_start <= extra_start + extra_length <= len(prefix_bytes)
        covered.append(prefix_bytes[cursor:extra_start])
        cursor = extra_start + extra_length
    covered.extend((prefix_bytes[cursor:], suffix.encode("utf-8")))
    normalized = unicodedata.normalize("NFC", b"".join(covered).decode("utf-8"))
    start = len(prefix_bytes)
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        binding = manifest_module._hash_data_assertion(
            digest,
            start,
            exclusion_length,
            algorithm=DEFAULT_HASH_ALGORITHM,
            pad=b"",
        )
        if excluded_prefix_ranges:
            binding = Assertion(
                label=binding.label,
                payload={
                    "alg": DEFAULT_HASH_ALGORITHM,
                    "hash": digest,
                    "exclusions": [
                        *(
                            {"start": extra_start, "length": extra_length}
                            for extra_start, extra_length in excluded_prefix_ranges
                        ),
                        {"start": start, "length": exclusion_length},
                    ],
                    "pad": b"",
                },
            )

        items = [
            manifest_module._actions_assertion(WHEN),
            manifest_module._ai_disclosure_assertion(DISCLOSURE),
            manifest_module._metadata_assertion(DISCLOSURE),
            binding,
        ]
        payload: dict[str, object] = {
            "instanceID": "xmp:iid:1",
            "claim_generator_info": {"name": "c2patxt"},
            "signature": "self#jumbf=c2pa.signature",
            "alg": DEFAULT_HASH_ALGORITHM,
        }
        mutate(items, payload)
        assertion_boxes = [item.to_box() for item in items]
        assertion_boxes.extend(extra_assertions)
        labels = [item.label for item in items]
        for box in extra_assertions:
            label = box.description.label
            assert label is not None, "a referenced assertion needs a JUMBF label"
            labels.append(label)
        links = [
            hashed_uri(box, f"self#jumbf=c2pa.assertions/{label}")
            for label, box in zip(labels, assertion_boxes, strict=True)
        ]
        if mutate_links is not None:
            mutate_links(items, links)
        assertion_links = links[: len(labels)]
        gathered = [link for label, link in zip(labels, assertion_links, strict=True) if label in gathered_labels]
        created = [link for label, link in zip(labels, assertion_links, strict=True) if label not in gathered_labels]
        created.extend(links[len(labels) :])
        payload["created_assertions"] = created
        if gathered:
            payload["gathered_assertions"] = gathered

        claim_bytes = _cbor.dumps(payload)  # pyright: ignore[reportArgumentType] -- hand-built claim, as the sibling e2e test
        boxes = (
            JumbfBox(
                description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
                content=tuple((b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in assertion_boxes),
            ),
            JumbfBox(
                description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                content=((b"cbor", claim_bytes),),
            ),
        )
        signed = _cose._prepare_signed_claim(signer, claim_bytes) if signature_serializer is None else None

        def assemble(pad: int) -> str:
            if signature_serializer is not None:
                signature = signature_serializer(signer, claim_bytes, pad)
            else:
                assert signed is not None
                signature = _cose._serialize_signed_claim(signed, pad=pad)
            return _test_wrapper(
                boxes,
                signature,
                manifest_label="urn:c2pa:00000000-0000-4000-8000-000000000007",
            )

        return assemble

    wrapper, _ = _fixpoint.solve(prepare)
    return prefix + wrapper + suffix


def _unchanged(_items: list[Assertion], _claim: dict[str, object]) -> None:
    """Leave a hand-built signed manifest conforming."""


def _without_ai_disclosure(items: list[Assertion], _claim: dict[str, object]) -> None:
    items[:] = [item for item in items if item.label != ASSERTION_AI_DISCLOSURE]


def _created_without_source_type(items: list[Assertion], _claim: dict[str, object]) -> None:
    items[0] = Assertion(label=items[0].label, payload={"actions": [{"action": "c2pa.created"}]})


def _assertion_link(assertion: Assertion) -> dict[str, object]:
    from c2patxt.manifest import hashed_uri

    return hashed_uri(assertion.to_box(), f"self#jumbf=c2pa.assertions/{assertion.label}")


def _set_actions(items: list[Assertion], actions: list[dict[str, object]]) -> None:
    items[0] = Assertion(label=ASSERTION_ACTIONS, payload={"actions": actions})


def _ingredient(label: str, relationship: str) -> Assertion:
    return Assertion(label=label, payload={"relationship": relationship})


def _append_assertion(items: list[Assertion], label: str, payload: dict[str, object]) -> None:
    items.append(Assertion(label=label, payload=payload))


def _cloud_data_missing_size(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(
        items,
        "c2pa.cloud-data",
        {"label": "c2patxt.remote", "location": {"url": "https://example.invalid/a", "alg": "sha256", "hash": b"x"}},
    )


def _cloud_data_names_hard_binding(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(
        items,
        "c2pa.cloud-data",
        {
            "label": "c2pa.hash.data",
            "size": 1,
            "location": {"url": "https://example.invalid/a", "alg": "sha256", "hash": b"x"},
        },
    )


def _valid_cloud_data(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(
        items,
        "c2pa.cloud-data",
        {
            "label": "c2patxt.remote",
            "size": 1,
            "location": {"url": "https://example.invalid/a", "alg": "sha256", "hash": b"x"},
        },
    )


def _external_reference_half_hash(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(
        items,
        "c2pa.external-reference",
        {"location": {"url": "https://example.invalid/a", "alg": "sha256"}},
    )


def _external_reference_names_hard_binding(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(
        items,
        "c2pa.external-reference",
        {"label": "c2pa.hash.data", "location": {"url": "https://example.invalid/a"}},
    )


def _valid_external_reference(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(
        items,
        "c2pa.external-reference",
        {"location": {"url": "https://example.invalid/a"}},
    )


def _empty_time_stamp(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(items, "c2pa.time-stamp", {})


def _unvalidated_time_stamp(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(items, "c2pa.time-stamp", {"tstToken": b"not an RFC 3161 token"})


def _session_keys(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(items, "c2pa.session-keys", {"keys": []})


def _alternative_content(items: list[Assertion], _claim: dict[str, object]) -> None:
    _append_assertion(items, "c2pa.alternative-content-representation", {"type": "exif.originalPreservationImage"})


def _opened_without_ingredient(items: list[Assertion], _claim: dict[str, object]) -> None:
    _set_actions(items, [{"action": "c2pa.opened"}])


def _opened_with_parent(items: list[Assertion], _claim: dict[str, object]) -> None:
    parent = _ingredient("c2pa.ingredient.v3", "parentOf")
    items.append(parent)
    _set_actions(
        items,
        [{"action": "c2pa.opened", "parameters": {"ingredients": [_assertion_link(parent)]}}],
    )


def _opened_with_component(items: list[Assertion], _claim: dict[str, object]) -> None:
    component = _ingredient("c2pa.ingredient.v3", "componentOf")
    items.append(component)
    _set_actions(
        items,
        [{"action": "c2pa.opened", "parameters": {"ingredients": [_assertion_link(component)]}}],
    )


def _placed_with_component(items: list[Assertion], _claim: dict[str, object]) -> None:
    component = _ingredient("c2pa.ingredient.v3", "componentOf")
    items.append(component)
    _set_actions(
        items,
        [
            {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
            {"action": "c2pa.placed", "parameters": {"ingredients": [_assertion_link(component)]}},
        ],
    )


def _v1_placed_with_singular_component(items: list[Assertion], _claim: dict[str, object]) -> None:
    component = _ingredient("c2pa.ingredient.v3", "componentOf")
    items.append(component)
    items[0] = Assertion(
        label=ASSERTION_ACTIONS_V1,
        payload={
            "actions": [
                {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
                {"action": "c2pa.placed", "parameters": {"ingredient": _assertion_link(component)}},
            ]
        },
    )


def _v1_placed_with_plural_component(items: list[Assertion], claim: dict[str, object]) -> None:
    _placed_with_component(items, claim)
    actions = items[0]
    items[0] = Assertion(label=ASSERTION_ACTIONS_V1, payload=actions.payload)


def _placed_without_ingredient(items: list[Assertion], _claim: dict[str, object]) -> None:
    _set_actions(
        items,
        [
            {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
            {"action": "c2pa.placed"},
        ],
    )


def _derived_with_relationship(items: list[Assertion], action: str, relationship: str) -> None:
    ingredient = _ingredient("c2pa.ingredient.v3", relationship)
    items.append(ingredient)
    _set_actions(
        items,
        [
            {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
            {"action": action, "parameters": {"ingredients": [_assertion_link(ingredient)]}},
        ],
    )


def _transcoded_with_parent(items: list[Assertion], _claim: dict[str, object]) -> None:
    _derived_with_relationship(items, "c2pa.transcoded", "parentOf")


def _transcoded_with_component(items: list[Assertion], _claim: dict[str, object]) -> None:
    _derived_with_relationship(items, "c2pa.transcoded", "componentOf")


def _repackaged_with_parent(items: list[Assertion], _claim: dict[str, object]) -> None:
    _derived_with_relationship(items, "c2pa.repackaged", "parentOf")


def _repackaged_with_component(items: list[Assertion], _claim: dict[str, object]) -> None:
    _derived_with_relationship(items, "c2pa.repackaged", "componentOf")


def _removed_with_current_component(items: list[Assertion], _claim: dict[str, object]) -> None:
    component = _ingredient("c2pa.ingredient.v3", "componentOf")
    items.append(component)
    _set_actions(
        items,
        [
            {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
            {"action": "c2pa.removed", "parameters": {"ingredients": [_assertion_link(component)]}},
        ],
    )


def _redacted_without_target(items: list[Assertion], _claim: dict[str, object]) -> None:
    _set_actions(
        items,
        [
            {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
            {"action": "c2pa.redacted", "parameters": {}},
        ],
    )


def _redacted_with_target(items: list[Assertion], _claim: dict[str, object]) -> None:
    _set_actions(
        items,
        [
            {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
            {
                "action": "c2pa.redacted",
                "parameters": {"redacted": f"self#jumbf=c2pa.assertions/{items[2].label}"},
            },
        ],
    )


def _watermarked_without_soft_binding(items: list[Assertion], _claim: dict[str, object]) -> None:
    _set_actions(
        items,
        [
            {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
            {"action": "c2pa.watermarked.bound"},
        ],
    )


def _watermarked_with_soft_binding(items: list[Assertion], _claim: dict[str, object]) -> None:
    payload: dict[str, _cbor.CborValue] = {
        "alg": "com.example.test-watermark",
        "blocks": [{"scope": {}, "value": b"test"}],
    }
    items.append(
        Assertion(
            label="c2pa.soft-binding",
            payload=payload,
        )
    )
    _set_actions(
        items,
        [
            {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED},
            {"action": "c2pa.watermarked"},
        ],
    )


def _related_assertion_is_an_action(items: list[Assertion], _claim: dict[str, object]) -> None:
    related = Assertion(label=f"{ASSERTION_ACTIONS}__1", payload={"actions": [{"action": "c2pa.edited"}]})
    items.append(related)
    _set_actions(
        items,
        [
            {
                "action": "c2pa.created",
                "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED,
                "parameters": {"relatedAssertions": [_assertion_link(related)]},
            }
        ],
    )


def _related_assertion_is_metadata(items: list[Assertion], _claim: dict[str, object]) -> None:
    _set_actions(
        items,
        [
            {
                "action": "c2pa.created",
                "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED,
                "parameters": {"relatedAssertions": [_assertion_link(items[2])]},
            }
        ],
    )


def _two_parent_ingredients(items: list[Assertion], _claim: dict[str, object]) -> None:
    first = _ingredient("c2pa.ingredient.v3", "parentOf")
    second = _ingredient("c2pa.ingredient.v3__1", "parentOf")
    items.extend((first, second))
    _set_actions(
        items,
        [{"action": "c2pa.opened", "parameters": {"ingredients": [_assertion_link(first)]}}],
    )


def _self_redacted(items: list[Assertion], claim: dict[str, object]) -> None:
    claim["redacted_assertions"] = [f"self#jumbf=c2pa.assertions/{items[1].label}"]


def _gathered_second_inception(items: list[Assertion], _claim: dict[str, object]) -> None:
    items.append(
        Assertion(
            label=f"{ASSERTION_ACTIONS}__1",
            payload={"actions": [{"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED}]},
        )
    )


def _gathered_placed_without_ingredient(items: list[Assertion], _claim: dict[str, object]) -> None:
    items.append(
        Assertion(
            label=f"{ASSERTION_ACTIONS}__1",
            payload={"actions": [{"action": "c2pa.placed"}]},
        )
    )


def _metadata_is_a_json_array(items: list[Assertion], _claim: dict[str, object]) -> None:
    items[2] = Assertion(
        label=ASSERTION_METADATA,
        payload={},
        json_ld=b'[{"@context":{"dc":"http://purl.org/dc/elements/1.1/"},"dc:format":"text/plain"}]',
    )


def _repository_receipt(items: list[Assertion], _claim: dict[str, object], *, malformed: bool) -> None:
    payload = (
        b"{not json"
        if malformed
        else b'{"@context":{},"@type":"org.c2pa.repository-receipt",'
        b'"repository":{"uri":"https://example.com","manifestId":"urn:example:1"},'
        b'"anchor":{"uri":"https://example.com/proof","proof":{}}}'
    )
    items.append(Assertion(label=ASSERTION_REPOSITORY_RECEIPT, payload={}, json_ld=payload))


def _malformed_repository_receipt(items: list[Assertion], claim: dict[str, object]) -> None:
    _repository_receipt(items, claim, malformed=True)


def _valid_repository_receipt(items: list[Assertion], claim: dict[str, object]) -> None:
    _repository_receipt(items, claim, malformed=False)


def test_generic_validation_does_not_require_an_ai_disclosure(signer: Signer) -> None:
    """18.28.2 constrains claim generators; 15.10.3 defines no matching validator failure."""
    verdict = verify(_resigned(signer, _without_ai_disclosure))
    assert verdict.state is Provenance.VALID
    assert StatusCode.GENERAL_ERROR not in verdict.codes()
    assert StatusCode.ASSERTION_MISSING not in verdict.codes()


def test_generic_validation_does_not_require_digital_source_type(signer: Signer) -> None:
    """18.15.2's producer field is not added to 15.10.3.2.3's validator conditions."""
    verdict = verify(_resigned(signer, _created_without_source_type))
    assert verdict.state is Provenance.VALID
    assert StatusCode.ASSERTION_ACTION_MALFORMED not in verdict.codes()


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (_opened_without_ingredient, StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH),
        (_opened_with_component, StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH),
        (_placed_without_ingredient, StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH),
        (_transcoded_with_component, StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH),
        (_repackaged_with_component, StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH),
        (_removed_with_current_component, StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH),
        (_redacted_without_target, StatusCode.ASSERTION_ACTION_REDACTION_MISMATCH),
        (_watermarked_without_soft_binding, StatusCode.ASSERTION_ACTION_SOFT_BINDING_MISSING),
        (_related_assertion_is_an_action, StatusCode.ASSERTION_ACTION_MALFORMED),
        (_two_parent_ingredients, StatusCode.MANIFEST_MULTIPLE_PARENTS),
        (_self_redacted, StatusCode.ASSERTION_SELF_REDACTED),
    ],
    ids=[
        "opened-needs-an-ingredient",
        "opened-needs-parentOf",
        "placed-needs-an-ingredient",
        "transcoded-ingredient-needs-parentOf",
        "repackaged-ingredient-needs-parentOf",
        "removed-needs-another-manifest",
        "redacted-needs-a-target",
        "watermarked-needs-a-soft-binding",
        "relatedAssertions-cannot-name-actions",
        "one-parentOf-at-most",
        "a-claim-cannot-redact-itself",
    ],
)
def test_signed_wire_enforces_action_and_manifest_relationship_rules(
    signer: Signer,
    mutate: Callable[[list[Assertion], dict[str, object]], None],
    expected: StatusCode,
) -> None:
    verdict = verify(_resigned(signer, mutate))

    assert verdict.state is Provenance.INVALID
    assert expected in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


@pytest.mark.parametrize(
    "mutate",
    [
        _redacted_with_target,
        _watermarked_with_soft_binding,
        _related_assertion_is_metadata,
    ],
    ids=[
        "redacted-target",
        "watermarked-soft-binding",
        "related-metadata",
    ],
)
def test_signed_wire_accepts_actions_whose_required_relationships_are_present(
    signer: Signer, mutate: Callable[[list[Assertion], dict[str, object]], None]
) -> None:
    verdict = verify(_resigned(signer, mutate))

    assert verdict.state is Provenance.VALID
    assert StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def test_repeated_links_to_one_actions_assertion_preserve_each_hash_result(signer: Signer) -> None:
    """Repeated hashed URIs authenticate repeatedly but name one actions assertion."""

    def repeat_actions(items: list[Assertion], links: list[dict[str, object]]) -> None:
        action_index = next(index for index, item in enumerate(items) if item.label == ASSERTION_ACTIONS)
        links.extend((links[action_index], links[action_index]))

    verdict = verify(_resigned(signer, _unchanged, mutate_links=repeat_actions))

    assert verdict.state is Provenance.VALID
    assert verdict.codes().count(StatusCode.ASSERTION_HASHED_URI_MATCH) == 6
    assert StatusCode.ASSERTION_ACTION_MALFORMED not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def test_repeated_links_to_one_parent_do_not_create_multiple_parents(signer: Signer) -> None:
    """15.10.1.2 counts parent assertions, not duplicate URIs to one assertion."""

    def repeat_parent(items: list[Assertion], links: list[dict[str, object]]) -> None:
        parent_index = next(index for index, item in enumerate(items) if item.label == "c2pa.ingredient.v3")
        links.extend((links[parent_index], links[parent_index]))

    verdict = verify(
        _resigned(
            signer,
            _opened_with_parent,
            mutate_links=repeat_parent,
        )
    )

    assert verdict.state is Provenance.INVALID
    assert verdict.codes().count(StatusCode.ASSERTION_HASHED_URI_MATCH) == 7
    assert StatusCode.MANIFEST_MULTIPLE_PARENTS not in verdict.codes()
    assert StatusCode.GENERAL_ERROR in verdict.codes(), "full ingredient-chain validation remains unsupported"


@pytest.mark.parametrize(
    "mutate",
    [_opened_with_parent, _placed_with_component, _transcoded_with_parent, _repackaged_with_parent],
    ids=["opened-parent", "placed-component", "transcoded-parent", "repackaged-parent"],
)
def test_an_ingredient_never_produces_valid_without_full_15_11_validation(
    signer: Signer,
    mutate: Callable[[list[Assertion], dict[str, object]], None],
) -> None:
    verdict = verify(_resigned(signer, mutate))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.GENERAL_ERROR in verdict.codes()
    assert StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH not in verdict.codes()


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (_cloud_data_missing_size, StatusCode.ASSERTION_CLOUD_DATA_MALFORMED),
        (_cloud_data_names_hard_binding, StatusCode.ASSERTION_CLOUD_DATA_HARD_BINDING),
        (_external_reference_half_hash, StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED),
        (_external_reference_names_hard_binding, StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED),
        (_empty_time_stamp, StatusCode.ASSERTION_TIMESTAMP_MALFORMED),
        (_unvalidated_time_stamp, StatusCode.GENERAL_ERROR),
        (_session_keys, StatusCode.GENERAL_ERROR),
        (_alternative_content, StatusCode.GENERAL_ERROR),
    ],
    ids=[
        "cloud-missing-field",
        "cloud-hard-binding",
        "external-half-hash",
        "external-forbidden-label",
        "empty-time-stamp",
        "unvalidated-time-stamp",
        "session-key-binding",
        "alternative-content",
    ],
)
def test_signed_wire_runs_every_mandatory_type_specific_validation(
    signer: Signer,
    mutate: Callable[[list[Assertion], dict[str, object]], None],
    expected: StatusCode,
) -> None:
    verdict = verify(_resigned(signer, mutate))

    assert verdict.state is Provenance.INVALID
    assert expected in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


@pytest.mark.parametrize("mutate", [_valid_cloud_data, _valid_external_reference], ids=["cloud", "external"])
def test_optional_remote_assertions_validate_without_network_retrieval(
    signer: Signer,
    mutate: Callable[[list[Assertion], dict[str, object]], None],
) -> None:
    verdict = verify(_resigned(signer, mutate))

    assert verdict.state is Provenance.VALID
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def test_related_assertions_can_name_a_hash_valid_opaque_assertion(signer: Signer) -> None:
    """15.10.3.2.3 resolves an assertion, not only a decoded CBOR or JSON value."""
    from c2patxt.manifest import hashed_uri

    label = "c2patxt.related"
    opaque = JumbfBox(
        description=DescriptionBox(uuid=_jumbf.content_type_uuid(b"uuid"), label=label),
        content=((b"uuid", bytes(16)),),
    )

    def relate(items: list[Assertion], _claim: dict[str, object]) -> None:
        reference = hashed_uri(opaque, f"self#jumbf=c2pa.assertions/{label}")
        _set_actions(
            items,
            [
                {
                    "action": "c2pa.created",
                    "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED,
                    "parameters": {"relatedAssertions": [reference]},
                }
            ],
        )

    verdict = verify(_resigned(signer, relate, extra_assertions=(opaque,)))

    assert verdict.state is Provenance.VALID
    assert StatusCode.HASHED_URI_MISSING not in verdict.codes()
    assert StatusCode.ASSERTION_ACTION_MALFORMED not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def test_gathered_actions_participate_in_the_full_inception_count(signer: Signer) -> None:
    gathered = f"{ASSERTION_ACTIONS}__1"
    verdict = verify(_resigned(signer, _gathered_second_inception, gathered_labels=(gathered,)))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.ASSERTION_ACTION_MALFORMED in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def test_gathered_actions_receive_the_same_per_action_validation(signer: Signer) -> None:
    gathered = f"{ASSERTION_ACTIONS}__1"
    verdict = verify(_resigned(signer, _gathered_placed_without_ingredient, gathered_labels=(gathered,)))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def test_a_json_ld_array_is_valid_json_on_the_signed_wire(signer: Signer) -> None:
    verdict = verify(_resigned(signer, _metadata_is_a_json_array))

    assert verdict.state is Provenance.VALID
    assert StatusCode.ASSERTION_JSON_INVALID not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


@pytest.mark.parametrize("payload", [b"NaN", b"Infinity", b"-Infinity"])
def test_non_finite_json_numbers_are_invalid_on_the_signed_wire(signer: Signer, payload: bytes) -> None:
    """RFC 8259 excludes non-finite numbers even though Python's decoder accepts them."""

    def metadata_constant(items: list[Assertion], _claim: dict[str, object]) -> None:
        items[2] = Assertion(label=ASSERTION_METADATA, payload={}, json_ld=payload)

    verdict = verify(_resigned(signer, metadata_constant))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.ASSERTION_JSON_INVALID in verdict.codes()


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (_malformed_repository_receipt, StatusCode.ASSERTION_JSON_INVALID),
        (_valid_repository_receipt, StatusCode.GENERAL_ERROR),
    ],
    ids=["malformed-json", "forbidden-in-a-standard-manifest"],
)
def test_repository_receipts_use_json_and_only_belong_to_update_manifests(
    signer: Signer,
    mutate: Callable[[list[Assertion], dict[str, object]], None],
    expected: StatusCode,
) -> None:
    verdict = verify(_resigned(signer, mutate))

    assert verdict.state is Provenance.INVALID
    assert expected in verdict.codes()


def test_plural_wrappers_use_the_one_whose_exclusion_matches(signer: Signer) -> None:
    """15.12.1.3.1 selects by an exact wrapper/exclusion-range match."""
    decoy_mark = mark("D", signer)
    decoy = decoy_mark[decoy_mark.index(MARKER) :]
    text = _resigned(signer, _unchanged, prefix="Visible" + decoy)

    assert text.count(MARKER) == 2
    verdict = verify(text)
    assert verdict.state is Provenance.VALID
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()
    assert StatusCode.TEXT_MULTIPLE_WRAPPERS not in verdict.codes()


def test_two_manifests_whose_own_wrapper_ranges_match_are_ambiguous(signer: Signer) -> None:
    """15.12.1.3.1 rejects before choosing between two matching candidates."""
    visible = "Visible"
    first = _resigned(signer, _unchanged, prefix=visible)
    text = _resigned(signer, _unchanged, prefix=first)

    encoded = text.encode("utf-8")
    first_span = (len(visible.encode("utf-8")), len(first.encode("utf-8")))
    second_span = (first_span[1], len(encoded))
    assert text.count(MARKER) == 2
    for start, stop in (first_span, second_span):
        assert encoded[start:stop].decode("utf-8").startswith(MARKER)

    verdict = verify(text)

    assert verdict.state is Provenance.INVALID
    assert verdict.manifest is None
    assert StatusCode.TEXT_MULTIPLE_WRAPPERS in verdict.codes()
    assert StatusCode.GENERAL_ERROR not in verdict.codes()


def test_two_wrapper_ranges_named_by_the_binding_are_reported_as_multiple(signer: Signer) -> None:
    """15.12.1.3.1 rejects only when more than one wrapper matches an exclusion."""
    visible = "Visible"
    decoy_mark = mark("D", signer)
    decoy = decoy_mark[decoy_mark.index(MARKER) :]
    decoy_start = len(visible.encode("utf-8"))
    text = _resigned(
        signer,
        _unchanged,
        prefix=visible + decoy,
        excluded_prefix_ranges=((decoy_start, len(decoy.encode("utf-8"))),),
    )

    assert text.count(MARKER) == 2
    verdict = verify(text)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.TEXT_MULTIPLE_WRAPPERS in verdict.codes()


def test_an_additional_exclusion_is_informational_and_is_applied(signer: Signer) -> None:
    """15.12.1.1 records extra ranges without turning a matching digest into failure."""
    text = _resigned(signer, _unchanged, prefix="XVisible", excluded_prefix_ranges=((0, 1),))

    verdict = verify(text)
    assert verdict.state is Provenance.VALID
    assert [status.code for status in verdict.informational] == [StatusCode.DATA_HASH_ADDITIONAL_EXCLUSIONS]
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()


def _binding_without_hash(items: list[Assertion], _claim: dict[str, object]) -> None:
    binding = items[3]
    assert binding.label == ASSERTION_HASH_DATA
    payload = binding.payload
    assert _is_string_cbor_map(payload)
    items[3] = Assertion(
        label=binding.label,
        payload={key: value for key, value in payload.items() if key != "hash"},
    )


def test_a_signed_data_hash_without_hash_reports_mismatch(signer: Signer) -> None:
    """15.12.1.1 gives an absent hash the mismatch code, not malformed."""
    verdict = verify(_resigned(signer, _binding_without_hash))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()
    assert StatusCode.DATA_HASH_MALFORMED not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def _binding_with_exclusion_past_eof(items: list[Assertion], _claim: dict[str, object]) -> None:
    binding = items[3]
    assert binding.label == ASSERTION_HASH_DATA
    payload = binding.payload
    assert _is_string_cbor_map(payload)
    exclusions = payload["exclusions"]
    assert isinstance(exclusions, list)
    overrun = _widen({"start": 10_000_000, "length": 1})
    items[3] = Assertion(
        label=binding.label,
        payload={
            **payload,
            "exclusions": [*exclusions, overrun],
        },
    )


def test_an_additional_exclusion_past_eof_reports_mismatch(signer: Signer) -> None:
    """The exact wrapper range matches before the later impossible range is checked."""
    verdict = verify(_resigned(signer, _binding_with_exclusion_past_eof))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()
    assert StatusCode.DATA_HASH_MALFORMED not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def _second_hard_binding(items: list[Assertion], _claim: dict[str, object]) -> None:
    items.append(Assertion(label=f"{items[3].label}__1", payload=items[3].payload))


def _unsupported_binding_algorithm(items: list[Assertion], _claim: dict[str, object]) -> None:
    binding = items[3].payload
    assert isinstance(binding, dict)
    replaced: CborMap = {**binding, "alg": "md5"}
    items[3] = Assertion(label=items[3].label, payload=replaced)


def _icon_reference(url: str, digest: bytes) -> CborMap:
    """A hashed-uri-map for a generator icon. Distinct from ``_icon`` below, which
    derives one from a real store; this one takes an arbitrary url and digest."""
    return {"url": url, "hash": digest, "alg": "sha256"}


def _icon_destination_absent(items: list[Assertion], claim: dict[str, object]) -> None:
    generator = claim["claim_generator_info"]
    assert isinstance(generator, dict)
    claim["claim_generator_info"] = {
        **generator,
        "icon": _icon_reference("self#jumbf=c2pa.assertions/c2pa.nonesuch", b"\x00" * 32),
    }


def _icon_is_not_a_reference(_items: list[Assertion], claim: dict[str, object]) -> None:
    generator = claim["claim_generator_info"]
    assert isinstance(generator, dict)
    claim["claim_generator_info"] = {**generator, "icon": "not a hashed URI"}


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (_second_hard_binding, StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS),
        (_unsupported_binding_algorithm, StatusCode.ALGORITHM_UNSUPPORTED),
        (_icon_destination_absent, StatusCode.HASHED_URI_MISSING),
        (_icon_is_not_a_reference, StatusCode.HASHED_URI_MISSING),
    ],
    ids=[
        "assertion.multipleHardBindings",
        "algorithm.unsupported",
        "hashedURI.missing",
        "malformed-icon",
    ],
)
def test_a_wire_legal_manifest_reports_its_defect_through_verify(
    signer: Signer, mutate: Callable[[list[Assertion], dict[str, object]], None], expected: StatusCode
) -> None:
    """Public verification reports each signed-wire defect through its exact code."""
    verdict = verify(_resigned(signer, mutate))

    assert verdict.state is Provenance.INVALID
    assert expected in verdict.codes(), [code.value for code in verdict.codes()]
    # The valid signature distinguishes the intended defect from unrelated wire damage.
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def test_supplying_anchors_directly_is_refused_rather_than_ignored() -> None:
    """Parsed anchors are derived state; callers supply ``anchors_pem`` instead."""
    with pytest.raises(TypeError, match="anchors"):
        VerifyContext(anchors=())  # pyright: ignore[reportCallIssue] -- that it is a call error IS the property


def _with_assertion(store: ManifestStore, label: str, payload: _cbor.CborValue) -> ManifestStore:
    """A store carrying ``label`` -> ``payload``, consistent the way a parse would leave it.

    ``dataclasses.replace(store, assertions=...)`` alone produces a state
    ``parse_manifest_store`` CANNOT: ``_parse_assertions`` derives ``assertions[label]``
    by decoding ``assertion_bytes[label]``, so a decoded payload that disagrees with the
    hashed bytes is unreachable from any input. Tests built that way prove a rule about
    a manifest nobody can send.

    This rebuilds three of them together -- the assertion superbox, its raw bytes, and
    the claim's hashed-uri link -- so those three agree with each other the way a parse
    would leave them. The link is added or replaced by label, so the caller does not have
    to know whether the assertion already existed.

    ``raw`` AND ``claim_bytes`` ARE LEFT STALE: ``raw`` still holds the untampered store and ``claim_bytes``
    still decodes to the ORIGINAL claim.

    That is safe for ``_check_assertions``, which reads ``claim``, ``assertions``,
    ``assertion_bytes`` and ``manifest_label`` and nothing else. It is NOT safe for
    ``verify()`` or ``_check_signature``, which read ``claim_bytes`` -- a store built here
    and routed through either would silently be checked against the original claim, and
    would pass. Use :func:`_resigned` when the property under test involves the
    signature or the wire.
    """
    from c2patxt import _jumbf
    from c2patxt.manifest import Assertion

    box = Assertion(label=label, payload=payload).to_box()
    raw = _jumbf.serialize_superbox(box)[8:]
    url = f"self#jumbf=c2pa.assertions/{label}"

    links = store.claim["created_assertions"]
    assert isinstance(links, list)
    kept = [link for link in links if not (isinstance(link, dict) and link.get("url") == url)]
    claim = {
        **store.claim,
        "created_assertions": [*kept, {"url": url, "hash": hashlib.sha256(raw).digest(), "alg": "sha256"}],
    }
    return dataclasses.replace(
        store,
        claim=claim,
        assertions={**store.assertions, label: payload},
        assertion_bytes={**store.assertion_bytes, label: raw},
    )


def _without_hard_binding(items: list[Assertion], _claim: dict[str, object]) -> None:
    items[:] = [item for item in items if item.label != ASSERTION_HASH_DATA]


def test_a_claim_with_no_hard_binding_uses_the_dedicated_claim_status(signer: Signer) -> None:
    """15.10.1.2 assigns absence to claim.hardBindings.missing, not assertion.missing."""
    verdict = verify(_resigned(signer, _without_hard_binding))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.CLAIM_HARD_BINDINGS_MISSING in verdict.codes()
    assert StatusCode.ASSERTION_MISSING not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


@pytest.mark.parametrize("url", ["self#jumbf=c2pa.databoxes/c2pa.icon", "self#jumbf=c2pa.databoxes/"])
def test_an_unresolved_data_box_icon_is_missing(store: ManifestStore, url: str) -> None:
    icon: CborMap = {"url": url, "hash": b"\x00" * 32, "alg": "sha256"}
    payload: CborMap = {
        "actions": [
            {"action": "c2pa.created", "digitalSourceType": _SRC, "softwareAgent": {"name": "agent", "icon": icon}}
        ]
    }

    verdict, accepted = _verify._check_assertions(
        _with_assertion(store, ASSERTION_ACTIONS, payload), Verdict(state=Provenance.INVALID)
    )

    assert not accepted
    assert StatusCode.HASHED_URI_MISSING in verdict.codes()


def test_a_second_actions_assertion_may_not_smuggle_another_inception(store: ManifestStore) -> None:
    """18.15.2: "The full set of actions assertions in a C2PA Manifest shall contain no
    more than one action whose type is either `c2pa.created` or `c2pa.opened`."

    The later assertion carries a second ``c2pa.created``. Its optional metadata does
    not change the rule: the full set of actions assertions may contain only one
    inception action.
    """
    good: CborMap = {"actions": [{"action": "c2pa.created", "digitalSourceType": _SRC}]}
    bare: CborMap = {"actions": [{"action": "c2pa.created"}]}

    tampered = _with_assertion(_with_assertion(store, ASSERTION_ACTIONS, good), f"{ASSERTION_ACTIONS}__1", bare)
    verdict, accepted = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert not accepted
    assert StatusCode.ASSERTION_ACTION_MALFORMED in verdict.codes()


def test_a_claim_missing_a_required_field_says_which_check_found_it(store: ManifestStore) -> None:
    """``_claim_malformed`` runs before ``_assertion_links``, and moving it after survived
    -- because BOTH paths return ``claim.malformed`` and no test read the EXPLANATION.

    The two are different diagnoses of the same code: 15.6.2's required-field check says
    a field the claim must carry is absent, while the link parse says
    ``created_assertions`` is not a non-empty list of maps. An operator handed the second
    for a claim that simply has no ``created_assertions`` key looks at the array's SHAPE
    rather than at its absence.

    ``Verdict`` carries the explanation precisely so a code can be narrowed in prose;
    asserting only the code leaves that channel untested.
    """
    broken = {key: value for key, value in store.claim.items() if key != "created_assertions"}

    verdict, ok = _verify._check_assertions(dataclasses.replace(store, claim=broken), Verdict(state=Provenance.INVALID))

    assert not ok
    explanations = [status.explanation for status in verdict.failure]
    assert "the claim is missing a field 15.6.2 requires" in explanations


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("anchor unreachable"), ValueError("bad path"), TypeError("wrong shape")],
    ids=["runtime", "value", "type"],
)
def test_a_trust_evaluator_that_raises_yields_untrusted_not_a_crash(
    signer: Signer, signing_certificate: x509.Certificate, failure: Exception
) -> None:
    """``verify`` promises: "Never raises for absent, corrupt or invalid marks."

    A trust evaluator is caller-supplied and may wrap a backend that raises. The seam
    must not break the package's central promise when that happens.

    IT FIRED ONLY ON THE SIGNATURE-VALID PATH WITH ANCHORS SUPPLIED, which is the exact
    asymmetry ``VerifyContext.anchors_pem`` was rewritten to remove -- "a bomb that fires
    only on the happy path". The same defect, one call deeper, reintroduced by the seam.

    AN UNREACHABLE ANCHOR IS A VERDICT, NOT AN ERROR. That is the whole point of the
    four-state model: ``signingCredential.untrusted`` is a normal answer, and a validator
    that cannot chain a credential has learned something rather than failed. So the
    exception is caught and mapped to untrusted.

    IT IS NOT SWALLOWED. The explanation carries the evaluator's exception, so a
    ``TypeError`` from a buggy evaluator appears in the verdict rather than vanishing
    into a bare "untrusted" -- which is why the parametrization includes one.
    """
    from cryptography.hazmat.primitives.serialization import Encoding

    class Raising:
        def is_trusted(self, chain: list[x509.Certificate], anchors: list[x509.Certificate]) -> bool:
            del chain, anchors
            raise failure

    context = VerifyContext(anchors_pem=signing_certificate.public_bytes(Encoding.PEM), trust_evaluator=Raising())
    verdict = verify(mark("Hello world.", signer), context=context)

    assert verdict.state is Provenance.VALID
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED in verdict.codes()
    explanations = " ".join(status.explanation or "" for status in verdict.failure)
    assert type(failure).__name__ in explanations, "the evaluator's failure must be visible, not swallowed"


def test_a_serialized_store_labelled_c2pa_actions_v1_is_accepted(signer: Signer) -> None:
    """Every clause names both action labels. 15.10.3.2.3 opens "If the assertion's label is
    c2pa.actions or c2pa.actions.v2"; Table 7 lists them as one row; 5.1 says a
    deprecated construct "can be read, but never written", and we still emit v2 only.

    The fixture is serialized and signed before public extraction and verification, so
    the parser cannot silently drop the deprecated label while private verifier tests
    remain green.
    """

    def relabel_actions(items: list[Assertion], _claim: dict[str, object]) -> None:
        actions = items[0]
        assert actions.label == ASSERTION_ACTIONS
        items[0] = Assertion(label=ASSERTION_ACTIONS_V1, payload=actions.payload)

    marked = _resigned(signer, relabel_actions)
    store = extract(marked)
    assert store is not None
    assert ASSERTION_ACTIONS_V1 in store.assertions
    assert ASSERTION_ACTIONS not in store.assertions

    verdict = verify(marked)

    assert verdict.state is Provenance.VALID
    assert StatusCode.ASSERTION_MISSING not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED in verdict.codes()


def test_actions_v1_resolves_its_singular_ingredient_field(signer: Signer) -> None:
    """The deprecated v1 shape uses ``ingredient``, not v2's ``ingredients`` array."""
    marked = _resigned(signer, _v1_placed_with_singular_component)
    store = extract(marked)
    assert store is not None
    actions = store.assertion(ASSERTION_ACTIONS_V1)
    assert isinstance(actions, dict)
    entries = actions["actions"]
    assert isinstance(entries, list)
    placed = entries[1]
    assert isinstance(placed, dict)
    parameters = placed["parameters"]
    assert isinstance(parameters, dict)
    assert "ingredient" in parameters
    assert "ingredients" not in parameters

    verdict = verify(marked)

    assert StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH not in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()
    assert StatusCode.GENERAL_ERROR in verdict.codes(), "full ingredient-manifest validation remains unsupported"


def test_actions_v1_rejects_the_v2_plural_ingredient_field(signer: Signer) -> None:
    """A valid component link under the wrong field proves the v1 check actually ran."""
    marked = _resigned(signer, _v1_placed_with_plural_component)
    store = extract(marked)
    assert store is not None
    actions = store.assertion(ASSERTION_ACTIONS_V1)
    assert isinstance(actions, dict)
    entries = actions["actions"]
    assert isinstance(entries, list)
    placed = entries[1]
    assert isinstance(placed, dict)
    parameters = placed["parameters"]
    assert isinstance(parameters, dict)
    assert "ingredient" not in parameters
    assert "ingredients" in parameters

    verdict = verify(marked)

    assert verdict.state is Provenance.INVALID
    assert StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


def test_an_unlinked_second_hard_binding_is_undeclared_not_multiple(store: ManifestStore) -> None:
    """C2PA 15.10.1.2 counts the hard bindings the claim links.

    An unlinked ``c2pa.hash.data__1`` is ``assertion.undeclared``. Two linked bindings
    are ``assertion.multipleHardBindings``.
    """
    smuggled = dataclasses.replace(
        store,
        assertion_bytes={**store.assertion_bytes, f"{ASSERTION_HASH_DATA}__1": b"not linked by the claim"},
    )
    verdict, accepted = _verify._check_assertions(smuggled, Verdict(state=Provenance.INVALID))

    assert not accepted
    assert StatusCode.ASSERTION_UNDECLARED in verdict.codes(), "an unlinked assertion is undeclared, whatever its type"
    assert StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS not in verdict.codes()


def _rfc9052_sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 4.4, encoded by the independent test-only CBOR implementation."""
    return cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)


def _mark_with_cose_algorithm(
    text: str,
    private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | Ed448PrivateKey,
    algorithm: int,
    hash_algorithm: hashes.HashAlgorithm | None,
    *,
    certificate: x509.Certificate | None = None,
) -> str:
    """Build a signed mark the deliberately Ed25519-only producer cannot emit."""
    from c2patxt.manifest import _prepare_manifest, _serialize_prepared_manifest

    normalized = unicodedata.normalize("NFC", text)
    encoded = normalized.encode("utf-8")
    if certificate is None:
        certificate = build_certificate(private_key)
    protected = _cbor.dumps(
        {
            _cose.COSE_HEADER_ALG: algorithm,
            _cose.COSE_HEADER_X5CHAIN: certificate.public_bytes(Encoding.DER),
        }
    )

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        prepared = _prepare_manifest(
            disclosure=DISCLOSURE,
            digest=hashlib.sha256(encoded).digest(),
            exclusion_start=len(encoded),
            exclusion_length=exclusion_length,
            instance_id="xmp:iid:mandatory-signature-algorithm",
            when=WHEN,
            generator_name="C2PA signature-algorithm test fixture",
        )
        # Do not sign the verifier's own Sig_structure implementation. If that helper
        # and verification share the same defect, a round trip stays green. RFC 9052's
        # literal four-element structure is encoded by cbor2 instead.
        to_be_signed = _rfc9052_sig_structure(protected, prepared.claim_bytes)
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            assert hash_algorithm is not None
            der_signature = private_key.sign(to_be_signed, ec.ECDSA(hash_algorithm))
            r, s = decode_dss_signature(der_signature)
            component_size = (private_key.curve.key_size + 7) // 8
            signature = r.to_bytes(component_size, "big") + s.to_bytes(component_size, "big")
        elif isinstance(private_key, rsa.RSAPrivateKey):
            assert hash_algorithm is not None
            signature = private_key.sign(
                to_be_signed,
                padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=hash_algorithm.digest_size),
                hash_algorithm,
            )
        else:
            signature = private_key.sign(to_be_signed)
        signed = _cose._SignedClaim(protected=protected, signature=signature)

        def assemble(pad_size: int) -> str:
            cose = _cose._serialize_signed_claim(signed, pad=pad_size)
            store = _serialize_prepared_manifest(
                prepared,
                signature=cose,
                manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000019"),
            )
            return build_wrapper(store)

        return assemble

    wrapper, _ = _fixpoint.solve(prepare)
    return normalized + wrapper


def _ed448_leaf_signed_by_ed25519(private_key: Ed448PrivateKey) -> x509.Certificate:
    """An Ed448 subject key under a profile-permitted Ed25519 issuer signature."""
    issuer_key = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ed448 C2PA test leaf")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ed25519 C2PA test issuer")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(0xED448)
        .not_valid_before(WHEN - datetime.timedelta(days=1))
        .not_valid_after(WHEN + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([C2PA_CLAIM_SIGNING_EKU]), critical=False)
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
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .sign(issuer_key, None)
    )


@pytest.mark.parametrize(
    ("algorithm", "curve", "hash_algorithm"),
    [
        (-7, ec.SECP256R1(), hashes.SHA256()),
        (-35, ec.SECP384R1(), hashes.SHA384()),
        (-36, ec.SECP521R1(), hashes.SHA512()),
        # RFC 9053 permits this polymorphic combination; pairing P-256 with
        # SHA-256 is recommended for interoperability, not required on read.
        (-7, ec.SECP521R1(), hashes.SHA256()),
    ],
    ids=["es256-p256", "es384-p384", "es512-p521", "es256-p521"],
)
def test_public_verify_accepts_every_required_ecdsa_shape(
    algorithm: int,
    curve: ec.EllipticCurve,
    hash_algorithm: hashes.HashAlgorithm,
) -> None:
    marked = _mark_with_cose_algorithm(
        "ECDSA C2PA mark.",
        ec.generate_private_key(curve),
        algorithm,
        hash_algorithm,
    )

    verdict = verify(marked)

    assert verdict.state is Provenance.VALID
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()
    assert StatusCode.ALGORITHM_UNSUPPORTED not in verdict.codes()


@pytest.mark.parametrize(
    ("algorithm", "hash_algorithm"),
    [
        (-37, hashes.SHA256()),
        (-38, hashes.SHA384()),
        (-39, hashes.SHA512()),
    ],
    ids=["ps256", "ps384", "ps512"],
)
def test_public_verify_accepts_every_required_rsa_pss_algorithm(
    algorithm: int,
    hash_algorithm: hashes.HashAlgorithm,
) -> None:
    marked = _mark_with_cose_algorithm(
        "RSA-PSS C2PA mark.",
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        algorithm,
        hash_algorithm,
    )

    verdict = verify(marked)

    assert verdict.state is Provenance.VALID
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()
    assert StatusCode.ALGORITHM_UNSUPPORTED not in verdict.codes()


@pytest.mark.parametrize("algorithm", [-7, -37], ids=["es256-with-ed25519-key", "ps256-with-ed25519-key"])
def test_public_verify_rejects_a_key_that_cannot_implement_the_declared_algorithm(algorithm: int) -> None:
    """C2PA 13.2.1: an allowed algorithm paired with the wrong key is a bad signature."""
    if algorithm == -7:
        private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = Ed25519PrivateKey.generate()
    marked = _mark_with_cose_algorithm(
        "C2PA algorithm and key mismatch.",
        private_key,
        algorithm,
        hashes.SHA256(),
        certificate=build_certificate(leaf_key),
    )

    verdict = verify(marked)

    assert verdict.state is Provenance.INVALID
    assert StatusCode.CLAIM_SIGNATURE_MISMATCH in verdict.codes()
    assert StatusCode.SIGNING_CREDENTIAL_INVALID not in verdict.codes()
    assert StatusCode.ALGORITHM_UNSUPPORTED not in verdict.codes()


def test_public_verify_rejects_ed448_as_the_forbidden_eddsa_instance() -> None:
    """C2PA 13.2.1 permits Ed25519 only within COSE EdDSA algorithm -8."""
    key = Ed448PrivateKey.generate()
    marked = _mark_with_cose_algorithm(
        "Ed448 C2PA mark.",
        key,
        COSE_ALG_EDDSA,
        None,
        certificate=_ed448_leaf_signed_by_ed25519(key),
    )

    verdict = verify(marked)

    assert verdict.state is Provenance.INVALID
    assert StatusCode.CLAIM_SIGNATURE_MISMATCH in verdict.codes()
    assert StatusCode.SIGNING_CREDENTIAL_INVALID not in verdict.codes()
    assert StatusCode.ALGORITHM_UNSUPPORTED not in verdict.codes()


@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        ("malformed-cose", StatusCode.GENERAL_ERROR),
        ("missing-credential", StatusCode.SIGNING_CREDENTIAL_INVALID),
        ("bad-credential-shape", StatusCode.SIGNING_CREDENTIAL_INVALID),
        ("unsupported-algorithm", StatusCode.ALGORITHM_UNSUPPORTED),
        ("float-alg", StatusCode.ALGORITHM_UNSUPPORTED),
        ("unknown-critical-header", StatusCode.GENERAL_ERROR),
        ("singleton-chain", StatusCode.SIGNING_CREDENTIAL_INVALID),
        ("bad-signature-shape", StatusCode.GENERAL_ERROR),
        ("short-signature", StatusCode.CLAIM_SIGNATURE_MISMATCH),
        ("long-signature", StatusCode.CLAIM_SIGNATURE_MISMATCH),
        ("bad-signature", StatusCode.CLAIM_SIGNATURE_MISMATCH),
    ],
)
# One table holds each public 15.7 category; splitting it would duplicate the wire rebuild.
def test_signature_failures_keep_their_15_7_categories(
    signer: Signer,
    damage: str,
    expected: StatusCode,
) -> None:
    """A present signature is not missing, and a bad algorithm is not a bad signature.

    C2PA 15.7 reserves ``claimSignature.missing`` for an absent field or a URI that
    cannot be resolved. It gives unsupported algorithms and unacceptable credentials
    their own codes. A structurally malformed, present COSE value has no dedicated
    code, so Table 4's ``general.error`` is the narrow fallback for an error not listed
    elsewhere.
    """
    from c2patxt import _cose
    from c2patxt._extract import _reparse

    original = extract(mark("Hello world.", signer))
    assert original is not None

    if damage == "malformed-cose":
        forged = b"\xff\xff not COSE at all"
    else:
        protected: dict[int, _cbor.CborValue] = {_cose.COSE_HEADER_ALG: COSE_ALG_EDDSA}
        signature: _cbor.CborValue = b"\x00" * 64
        if damage != "missing-credential":
            protected[_cose.COSE_HEADER_X5CHAIN] = signer.x5chain()[0]
        if damage == "bad-credential-shape":
            protected[_cose.COSE_HEADER_X5CHAIN] = 7
        elif damage == "unsupported-algorithm":
            protected[_cose.COSE_HEADER_ALG] = 999
        elif damage == "float-alg":
            protected[_cose.COSE_HEADER_ALG] = -8.0
        elif damage == "unknown-critical-header":
            protected[_cose.COSE_HEADER_CRIT] = [999]
            protected[999] = "must understand"
        elif damage == "singleton-chain":
            protected[_cose.COSE_HEADER_X5CHAIN] = [signer.x5chain()[0]]
        elif damage == "bad-signature-shape":
            signature = 7
        elif damage == "short-signature":
            signature = b"\x00" * 63
        elif damage == "long-signature":
            signature = b"\x00" * 65
        protected_bytes = cbor2.dumps(protected) if damage == "float-alg" else _cbor.dumps(protected)
        forged = _cbor.dumps(
            _cbor.Tagged(
                _cbor.TAG_COSE_SIGN1,
                [protected_bytes, {}, None, signature],
            )
        )

    def rebuild(manifest: JumbfBox) -> tuple[tuple[bytes, bytes], ...]:
        children: list[tuple[bytes, bytes]] = []
        for tbox, payload in manifest.content:
            child, _ = _reparse(payload)
            if child.description.label == LABEL_CLAIM_SIGNATURE:
                child = JumbfBox(description=child.description, content=((b"cbor", forged),))
            children.append((tbox, _jumbf.serialize_superbox(child)[8:]))
        return tuple(children)

    evaluator = RecordingTrustEvaluator(trusted=True)
    context = VerifyContext(
        anchors_pem=signer.certificates[0].public_bytes(Encoding.PEM),
        trust_evaluator=evaluator,
    )
    verdict = verify(_restore_manifest(original, rebuild), context=context)

    assert verdict.state is Provenance.INVALID
    assert expected in verdict.codes()
    assert not evaluator.calls, f"{damage} reached the trust backend before its signature was accepted"
    assert StatusCode.CLAIM_SIGNATURE_MISSING not in verdict.codes()
    if expected is not StatusCode.CLAIM_SIGNATURE_MISMATCH:
        assert StatusCode.CLAIM_SIGNATURE_MISMATCH not in verdict.codes()


def test_an_expired_credential_explains_which_rule_and_when(signing_key: Ed25519PrivateKey) -> None:
    """The failure explains the certificate index, validity window and validation time."""
    import datetime

    expired = build_certificate(
        signing_key,
        not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
    )
    signer = Signer(private_key=signing_key, certificates=(expired,), allow_nonconformant=True)
    creation_time = datetime.datetime(2020, 6, 1, tzinfo=datetime.timezone.utc)
    text = mark("Hello world.", signer, when=creation_time)

    verdict = verify(text, context=VerifyContext(now=datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc)))

    assert StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY in verdict.codes()
    explanations = [status.explanation for status in verdict.failure if status.explanation]
    assert any("validity period" in text for text in explanations), (
        f"the outsideValidity status carries no explanation: {explanations}"
    )
