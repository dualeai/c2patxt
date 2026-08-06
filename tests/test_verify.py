# pyright: reportPrivateUsage=false
# Reaches _verify._check_assertions directly: it is the unit that decides whether an
# assertion store is authentic, and driving it only through verify() would hide which
# of several rejection paths fired.
"""End-to-end tests for :func:`c2patxt.verify`.

This is the first suite that exercises the whole stack -- selectors, JUMBF, CBOR,
COSE, certificate profile, hash binding -- against text that genuinely satisfies the
binding, rather than against hand-built fragments. Every attack here is one the
threat model names, and each asserts the SPECIFIC status code, not merely that
something failed: a test that only checks ``INVALID`` passes just as happily when the
mark fails for the wrong reason.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import unicodedata
import uuid
from collections.abc import Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from c2patxt import _cbor, _fixpoint, _jumbf, _verify
from c2patxt._jumbf import DescriptionBox, JumbfBox
from c2patxt._selectors import build_wrapper
from c2patxt.constants import MARKER
from c2patxt.manifest import (
    ASSERTION_ACTIONS,
    ASSERTION_ACTIONS_V1,
    ASSERTION_AI_DISCLOSURE,
    ASSERTION_HASH_DATA,
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
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from c2patxt.trust import TrustEvaluator
from c2patxt.verdict import Provenance, Verdict
from tests.conftest import DISCLOSURE, build_certificate, mark

from c2patxt import VerifyContext, embed, extract, locate, verify  # isort: skip


#: This suite exercises the WHOLE stack -- selectors, JUMBF, CBOR, COSE, certificate
#: profile, hash binding -- against text that genuinely satisfies the binding, rather
#: than against hand-built fragments.


@pytest.fixture(scope="session")
def marked(signer: Signer) -> str:
    return mark("The quick brown fox jumps over the lazy dog.", signer)


class _AcceptAnchoredEvaluator:
    """Trusts a chain whose leaf appears verbatim among the anchors.

    Not a certificate path validator and not offered as one -- it exists so the
    TRUSTED state is reachable in a test. ``cryptography.x509.verification`` cannot
    validate Ed25519 chains, which is exactly why trust is a caller-supplied seam.
    """

    def is_trusted(self, chain: list[x509.Certificate], anchors: list[x509.Certificate]) -> bool:
        return bool(chain) and chain[0] in anchors


# --------------------------------------------------------------------------------
# The happy path, and what "happy" actually means here
# --------------------------------------------------------------------------------


def test_untouched_text_verifies_as_valid(marked: str) -> None:
    """The whole stack round-trips: sign, embed, locate, parse, verify.

    VALID rather than TRUSTED, and that is the correct answer: the credential is
    self-signed and no anchors were supplied, so there is nothing to chain to.

    THE ASSERTION IS ``at_least``, DELIBERATELY. This test file is where an
    integrator learns the idiom, so it must teach the safe one. Checking
    ``CLAIM_SIGNATURE_VALIDATED in verdict.codes()`` looks equivalent and is not:
    ``codes()`` flattens all three buckets, and that code is genuinely PRESENT on a
    document whose text was rewritten -- the claim signature really is intact, only
    the binding broke. Copy that idiom into a service and attacker-edited text
    passes. See the next test.
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


def test_unmarked_text_is_unmarked_not_invalid() -> None:
    """Absence of a mark is the absence of a finding, not a negative one."""
    verdict = verify("Just some ordinary prose with no mark at all.")
    assert verdict.state is Provenance.UNMARKED
    assert verdict.codes() == ()
    assert verdict.manifest is None


def test_empty_text_is_unmarked() -> None:
    verdict = verify("")
    assert verdict.state is Provenance.UNMARKED


def test_the_span_locates_the_wrapper(marked: str) -> None:
    """The reported span must name the wrapper exactly, so a caller can strip it."""
    verdict = verify(marked)
    span = verdict.span
    assert span is not None
    encoded = marked.encode("utf-8")
    stripped = encoded[: span.utf8_start] + encoded[span.utf8_stop :]
    assert stripped.decode("utf-8") == "The quick brown fox jumps over the lazy dog."


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

    Caught by the SUFFIX rule rather than by the hash: once bytes follow the wrapper
    it is no longer trailing, and the exclusion no longer describes this document.
    That is the more precise diagnosis -- "the assertion does not describe this text"
    rather than "the text was edited somewhere" -- and it fires one step earlier.
    """
    verdict = verify(mark("Hello world.", signer) + " and some appended lies")
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()


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


def test_a_second_wrapper_invalidates(marked: str, signer: Signer) -> None:
    """ATTACK: append a second wrapper so a consumer picks the wrong one.

    A.8.2.1 gives quantity "Zero or one"; 15.5.2.1 treats plural manifest stores as
    all invalid. A permissive reading would let an attacker choose which manifest a
    given consumer reads.
    """
    second = mark("Something else entirely.", signer)
    verdict = verify(marked + second[second.index(MARKER) :])
    assert verdict.state is Provenance.INVALID
    assert StatusCode.TEXT_MULTIPLE_WRAPPERS in verdict.codes()


# --------------------------------------------------------------------------------
# Tampering: the signature and the credential
# --------------------------------------------------------------------------------


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
    context = VerifyContext(
        anchors_pem=signing_certificate.public_bytes(Encoding.PEM),
        trust_evaluator=_AcceptAnchoredEvaluator(),
    )
    verdict = verify(marked, context=context)
    assert verdict.state is Provenance.TRUSTED
    assert StatusCode.SIGNING_CREDENTIAL_TRUSTED in verdict.codes()


def test_an_anchor_without_an_evaluator_stays_valid(marked: str, signing_certificate: x509.Certificate) -> None:
    """Anchors alone change nothing: the default evaluator trusts nothing.

    Fail-closed. Supplying a PEM bundle must never be mistaken for path validation
    the library does not perform.
    """
    context = VerifyContext(anchors_pem=signing_certificate.public_bytes(Encoding.PEM))
    assert verify(marked, context=context).state is Provenance.VALID


def test_an_evaluator_without_anchors_stays_valid(marked: str) -> None:
    """With no anchors there is nothing to chain to, so the evaluator is not asked."""
    context = VerifyContext(trust_evaluator=_AcceptAnchoredEvaluator())
    assert verify(marked, context=context).state is Provenance.VALID


def test_the_default_evaluator_satisfies_the_protocol() -> None:
    """The seam is a Protocol, so a caller's own evaluator needs no base class."""
    assert isinstance(_AcceptAnchoredEvaluator(), TrustEvaluator)


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
    """Keep the victim's claim bytes AND signature verbatim; swap the assertion store.

    THE ATTACK THIS DEFENDS AGAINST. The COSE signature covers only the CLAIM. The
    claim commits to each assertion by a hashed-uri-map. If verify() does not
    recompute those digests over the assertion bytes that actually arrived, then one
    sample of marked text is enough to mint arbitrary text under the victim's
    credential -- escalating to TRUSTED wherever that credential chains to an anchor.

    Note what is NOT rebuilt: ``claim_bytes`` and ``signature`` are copied byte for
    byte out of the victim's manifest. A forge that rebuilt the claim would fail on
    the signature and prove nothing about the assertion check.
    """
    victim_store = extract(victim)
    assert victim_store is not None

    normalized = unicodedata.normalize("NFC", attacker_text)
    start = len(normalized.encode("utf-8"))
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()

    def build(exclusion_length: int, pad: bytes) -> str:
        forged = Assertion(
            label=ASSERTION_HASH_DATA,
            payload={
                "exclusions": [{"start": start, "length": exclusion_length}],
                "alg": "sha256",
                "hash": digest,
                "pad": pad,
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
        signature_box = JumbfBox(
            description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
            content=((b"cbor", victim_store.signature),),
        )
        manifest = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST, label=victim_store.manifest_label),
            content=tuple(
                (b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in (assertion_store, claim_box, signature_box)
            ),
        )
        store = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label=LABEL_MANIFEST_STORE),
            content=((b"jumb", _jumbf.serialize_superbox(manifest)[8:]),),
        )
        return build_wrapper(_jumbf.serialize_superbox(store))

    wrapper, _ = _fixpoint.solve(build)
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


def test_a_wrapper_that_is_not_a_suffix_is_rejected(signer: Signer) -> None:
    """ATTACK: slide the wrapper into the middle of the text via canonical equivalence.

    The exact-span check alone does not stop this. Because the binding removes the
    wrapper BEFORE normalizing, composition runs across the removed gap, so a
    canonically-equivalent re-spelling whose prefix has the same byte length at a
    code-point boundary produces a mid-text wrapper that still matches the declared
    exclusion, and still hashes to the same bytes.

    Canonical equivalence bounds the visible damage, so this is not content forgery.
    What it breaks is the invariant the whole design rests on: with the wrapper as a
    suffix, the 15.12.1.3.1 and A.8.7.3 hash orderings agree BY CONSTRUCTION. Mid-text
    they do not, so an attacker could mint text this library calls VALID and a
    conforming peer calls INVALID.
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
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()


def test_a_hostile_trust_anchors_variable_does_not_affect_verify(marked: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """verify() consults NO ambient configuration, asserted end to end.

    The missing test that let a C2PATXT_TRUST_ANCHORS fallback survive: the old
    test only proved that IMPORTING the package ignored the variable, never that
    verify() did. Because the read sat on the signature-valid path, a bad value
    raised FileNotFoundError or a PEM ValueError for VALID text only -- fine in
    staging on unmarked inputs, fatal in production on the happy path.
    """
    for value in ("/nonexistent/missing.pem", "", "not-a-path"):
        monkeypatch.setenv("C2PATXT_TRUST_ANCHORS", value)
        assert verify(marked).state is Provenance.VALID


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

    The first implementation compared against the time the CLAIM asserted it was
    signed, reasoning that a mark signed while the credential was live should stay
    valid after expiry. That reasoning is appealing and is not what the specification
    says -- provenance across expiry is what sigTst2 time-stamping is for, and we do
    not implement it. Worse, the asserted time is attacker-supplied, so it made the
    check self-certifying: the holder of an expired key simply wrote a `when` inside
    the old window.

    Validation time is injected through VerifyContext so this stays deterministic.
    """
    context = VerifyContext(now=datetime.datetime(2026, 8, 5, tzinfo=datetime.timezone.utc))
    certificate = build_certificate(
        signing_key,
        not_before=datetime.datetime(*not_before, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(*not_after, tzinfo=datetime.timezone.utc),
    )
    signer = Signer(private_key=signing_key, certificates=(certificate,))
    verdict = verify(mark("Hello world.", signer), context=context)

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
    """ATTACK: make the validity check read its reference time out of the manifest.

    c2pa.actions is attacker-supplied, and when it (or its `when`) was absent the
    check was SKIPPED -- while still filing claimSignature.insideValidity as a
    SUCCESS code, affirmatively asserting a validity it had never checked. A
    certificate expired in 2002 verified VALID in 2026.

    Now the reference time comes from the verifier, so there is nothing in the
    document for an attacker to set.
    """
    expired = build_certificate(
        signing_key,
        not_before=datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2002, 1, 1, tzinfo=datetime.timezone.utc),
    )
    signer = Signer(private_key=signing_key, certificates=(expired,))
    context = VerifyContext(now=datetime.datetime(2026, 8, 5, tzinfo=datetime.timezone.utc))

    verdict = verify(mark("Hello world.", signer), context=context)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY in verdict.codes()


@pytest.mark.parametrize(
    "anchors",
    [b"not a pem at all", b"-----BEGIN CERTIFICATE-----\ntruncated", b"\x00\xff\x00\xff"],
    ids=["garbage", "truncated-pem", "binary"],
)
def test_a_malformed_anchor_bundle_fails_the_same_way_for_every_verdict(marked: str, anchors: bytes) -> None:
    """A malformed bundle must not be a bomb that fires only on the happy path.

    load_anchors is reached only AFTER claimSignature.validated, so an unparseable
    bundle raised for VALID text while unmarked and invalid text sailed through. That
    asymmetry is the worst shape a failure can take: it survives every staging test
    that uses unmarked input and detonates in production on the first good document.

    trust.py's own docstring cites this exact bug as the reason the environment-
    variable fallback was removed -- the fuse simply moved to anchors_pem.

    Whatever the behaviour is, it must be the SAME for all three states.
    """
    outcomes: list[tuple[str, str]] = []
    for text in (marked, "no mark here", marked.replace("quick", "slow", 1)):
        try:
            outcomes.append(("verdict", str(verify(text, context=VerifyContext(anchors_pem=anchors)).state)))
        except ValueError as exc:  # noqa: PERF203 - the asymmetry IS the thing under test
            outcomes.append(("raised", type(exc).__name__))

    kinds = {kind for kind, _ in outcomes}
    assert len(kinds) == 1, f"malformed anchors behaved differently per verdict: {outcomes}"


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


def test_a_claim_that_does_not_link_the_ai_disclosure_is_rejected(signer: Signer) -> None:
    """THE SINGLE FACT THIS ARTEFACT EXISTS TO CARRY, and nothing tested it.

    A mutation audit replaced ``if any(label not in seen for label in
    _REQUIRED_ASSERTIONS)`` with ``if False`` and the whole suite stayed green.
    c2pa.hash.data is caught separately by ``_check_binding``, so the only thing that
    line actually guards is c2pa.ai-disclosure -- and an EU AI Act Article 50(2) mark
    whose disclosure is absent has disclosed nothing while still reading as VALID.

    Built by re-signing a claim that links ONLY the hash assertion, so the signature
    is genuine and the sole defect is the missing commitment.
    """
    import hashlib
    import unicodedata

    from c2patxt import _cose, _fixpoint
    from c2patxt._selectors import build_wrapper
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

    def build(exclusion_length: int, pad: bytes) -> str:
        hash_data = Assertion(
            label=ASSERTION_HASH_DATA,
            payload={
                "exclusions": [{"start": start, "length": exclusion_length}],
                "alg": DEFAULT_HASH_ALGORITHM,
                "hash": digest,
                "pad": pad,
            },
        )
        # ONE created_assertion. No c2pa.ai-disclosure anywhere.
        claim = Claim(
            instance_id="xmp:iid:1",
            claim_generator_name="c2patxt",
            claim_generator_version=None,
            created_assertions=(hashed_uri(hash_data.to_box(), f"self#jumbf=c2pa.assertions/{ASSERTION_HASH_DATA}"),),
            signature_url="self#jumbf=c2pa.signature",
        )
        claim_bytes = _cbor.dumps(claim.to_payload())

        assertion_store = JumbfBox(
            description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
            content=((b"jumb", _jumbf.serialize_superbox(hash_data.to_box())[8:]),),
        )
        claim_box = JumbfBox(
            description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
            content=((b"cbor", claim_bytes),),
        )
        signature_box = JumbfBox(
            description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
            content=((b"cbor", _cose.sign_claim(signer, claim_bytes)),),
        )
        manifest = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST, label="urn:c2pa:" + str(uuid.UUID(int=7))),
            content=tuple(
                (b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in (assertion_store, claim_box, signature_box)
            ),
        )
        store = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label=LABEL_MANIFEST_STORE),
            content=((b"jumb", _jumbf.serialize_superbox(manifest)[8:]),),
        )
        return build_wrapper(_jumbf.serialize_superbox(store))

    wrapper, _ = _fixpoint.solve(build)
    verdict = verify(normalized + wrapper)

    assert verdict.state is Provenance.INVALID
    assert StatusCode.ASSERTION_MISSING in verdict.codes()


def test_the_exclusion_must_name_a_located_wrapper_not_merely_be_trailing(signer: Signer) -> None:
    """The membership test is NOT subsumed by the suffix rule. I claimed it was.

    docs/mutation-audit.md recorded ``(start, length) not in spans`` as an equivalent
    mutant -- "writing a test for it would mean writing a test that cannot fail" --
    and an audit disproved it in three lines. Slide the wrapper one WHOLE CODE POINT
    (3 bytes) earlier and pad the tail by 3: the signed ``start + length ==
    len(encoded)`` still holds, so the suffix rule passes, while the declared range no
    longer coincides with any located wrapper.

    A one-BYTE shift really is indistinguishable -- it splits U+FEFF, and
    ``_compare_digest`` catches the resulting UnicodeDecodeError and also returns
    ``malformed``. Aligning the shift to a code-point boundary is what separates them:
    with the check, ``assertion.dataHash.malformed``; without it, the input reaches
    the hash and reports ``assertion.dataHash.mismatch``.

    Both are failures, so this is not a forgery -- but this package treats status codes
    as load-bearing (vector rule 4: a validator "shall report exactly that code"), and
    a wrong code sends an investigator looking for a text edit that never happened.
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
    from c2patxt._selectors import build_wrapper
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

    def build(exclusion_length: int, pad: bytes) -> str:
        payload: dict[str, object] = {
            "exclusions": [{"start": start, "length": exclusion_length}],
            "hash": digest,
            "pad": pad,
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
            JumbfBox(
                description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
                content=((b"cbor", _cose.sign_claim(signer, claim_bytes)),),
            ),
        )
        manifest = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST, label="urn:c2pa:" + str(uuid.UUID(int=7))),
            content=tuple((b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in boxes),
        )
        store = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label=LABEL_MANIFEST_STORE),
            content=((b"jumb", _jumbf.serialize_superbox(manifest)[8:]),),
        )
        return build_wrapper(_jumbf.serialize_superbox(store))

    wrapper, _ = _fixpoint.solve(build)
    verdict = verify(normalized + wrapper)

    # THE ASSERTION IS THE ABSENCE of algorithm.unsupported, plus a matching binding.
    # Both prove the resolution ran: _binding_status would have returned
    # algorithm.unsupported before hashing, and _link_status would have returned it
    # before comparing the digest.
    assert StatusCode.ALGORITHM_UNSUPPORTED not in verdict.codes()
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()

    # This hand-built manifest carries only the hard binding, so it is INVALID for a
    # different and correct reason: _REQUIRED_ASSERTIONS also demands the AI
    # disclosure. Asserted so the test cannot quietly start passing for that reason.
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

    We resolved nothing. The parse found the signature box BY LABEL and verification
    used whatever it found, so the claim's own field was read once for presence
    (15.6.2) and never again. A claim naming an https URL verified happily against the
    box we happened to be holding.

    THE PRODUCER IS WHAT THIS PATCHES, deliberately. The URI lives inside the signed
    claim bytes, so the threat is not an outsider rewriting the field -- it is a
    producer, possibly a future version of us, emitting a claim that points somewhere
    else while a validator never checks. Patching the constant and re-running the real
    ``mark`` pipeline means the fixpoint re-solves the exclusion for each URL length
    and every other property of the mark stays genuine.

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
        manifest_module, "CLAIM_SIGNATURE_URI", url.format(label=f"urn:c2pa:{uuid.UUID(int=7)}"), raising=True
    )
    marked = mark("Hello world.", signer)

    context = VerifyContext(
        anchors_pem=signing_certificate.public_bytes(Encoding.PEM),
        trust_evaluator=_AcceptAnchoredEvaluator(),
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

    We rejected it -- ``test_an_unlinked_assertion_is_rejected_whatever_its_content_type``
    proves that, and it is the guard that closed a total break -- but we reported
    ``assertion.missing``, which is the code for the OPPOSITE condition: the claim
    names an assertion the store does not hold. Here the store holds one the claim
    never named.

    The distinction is diagnostic, and this package treats status codes as
    load-bearing (vector rule 4: a validator "shall report exactly that code"). Told
    ``assertion.missing``, an operator looks for a truncated store and finds nothing
    wrong with it. Told ``assertion.undeclared``, they look for the extra box -- which
    is the one an attacker put there.
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


#: A CBOR map as the decoder produces one. CBOR admits integer and byte-string keys,
#: so this is wider than ``dict[str, ...]`` and is what a ``CborValue`` slot accepts.
CborMap = dict[int | str | bytes, _cbor.CborValue]


def _widen(mapping: dict[str, _cbor.CborValue]) -> CborMap:
    """The same map, retyped for a ``CborValue`` slot.

    ``dict`` is invariant in its key type, so a ``dict[str, ...]`` is not a
    ``dict[int | str | bytes, ...]`` however obviously every key fits. Rebuilding is a
    real conversion rather than a cast, which is why it is allowed to be this dull.
    """
    return {key: value for key, value in mapping.items()}


#: 8.4.2.1's store-relative form, naming THIS manifest: the shape of the spec's
#: own Example 1, which conftest pins to uuid.UUID(int=7).
_STORE_RELATIVE = f"self#jumbf=/c2pa/urn:c2pa:{uuid.UUID(int=7)}/c2pa.assertions/{ASSERTION_AI_DISCLOSURE}"


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
    retrieves none. An external reference is recognised by having a URI SCHEME, matched
    against RFC 3986's production -- three mutations of which survived the whole suite:
    ``.match`` to ``.search``, ``[A-Za-z]`` to ``[A-Za-z0-9]``, and dropping ``+.-``
    from the trailing class. The rows pin the production, not the four strings the
    branch was originally written for.

    ``store-relative-resolves`` is 8.4.2.1's second URI shape, the specification's own
    Example 1; with only the negative row, sending every store-relative URL down the
    external branch survived. ``alg-inherited-from-the-claim`` is the 15.4.2 control.
    """
    reference = _icon(store, drop=drop, **overrides)

    assert _verify._reference_status(reference, store, {}) is expected


def test_the_claim_generators_icon_is_actually_validated(store: ManifestStore) -> None:
    """The wiring, not the procedure: 15.6.2 routes ``claim_generator_info.icon``
    through 15.10.3.3, and a procedure nothing calls validates nothing.

    The claim is rebuilt with an icon whose hash is wrong and the store re-checked.
    We do not EMIT an icon, so this is read-side only -- but a third party's claim may
    carry one, and a manifest we call VALID must not contain an unverified reference.
    """
    generator = store.claim["claim_generator_info"]
    assert isinstance(generator, dict)
    poisoned: CborMap = {**generator, "icon": _widen(_icon(store, hash=b"\x00" * 32))}
    broken = {**store.claim, "claim_generator_info": poisoned}

    verdict, ok = _verify._check_assertions(dataclasses.replace(store, claim=broken), Verdict(state=Provenance.INVALID))

    assert not ok
    assert StatusCode.HASHED_URI_MISMATCH in verdict.codes()


@pytest.mark.parametrize("poisoned", [0, 1], ids=["first", "second"])
@pytest.mark.parametrize(
    "site",
    ["softwareAgent", "softwareAgents", "templates"],
    ids=["softwareAgent", "softwareAgents", "templates"],
)
def test_an_actions_assertion_icon_is_validated_too(store: ManifestStore, site: str, poisoned: int) -> None:
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

    THE SECOND ELEMENT IS THE POINT OF THE ``poisoned`` PARAMETER. Every earlier version
    of this test used single-element lists, so each of the three loops ran exactly one
    iteration -- and truncating ``_as_list`` to ``value[:1]``, which would leave a
    poisoned icon anywhere past the first entry inside a manifest we call VALID, left
    the whole suite green. A loop exercised once is not a loop under test.

    The actions assertion is otherwise conforming, ``digitalSourceType`` included, so
    the icon is the only defect and the test keeps discriminating as other rules tighten.
    """
    good = _widen(_icon(store))
    bad = _widen(_icon(store, hash=b"\x00" * 32))
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

    verdict, ok = _verify._check_assertions(
        _with_assertion(store, ASSERTION_ACTIONS, payload), Verdict(state=Provenance.INVALID)
    )

    assert not ok, f"a poisoned icon at index {poisoned} of {site} was accepted"
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

    WE READ ONLY created_assertions, so a conforming manifest whose extra assertion was
    gathered rather than created was REJECTED. #82 made that worse rather than better:
    the same manifest previously failed as ``assertion.missing`` and now failed as
    ``assertion.undeclared`` — a code positively asserting the claim never named the
    box, when the claim named it in the other array. A more confident wrong answer.

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


def test_the_required_assertions_must_be_created_not_merely_gathered(store: ManifestStore) -> None:
    """18.15.2: "There shall be at least one actions assertion present in the
    **created_assertions** array", and the 2.4 change log: "Required that the mandatory
    actions assertion appear only in created_assertions (not gathered_assertions)."

    THE REASON GENERALISES TO ALL THREE REQUIRED ASSERTIONS. An AI disclosure a producer
    merely GATHERED from somewhere else is not that producer disclosing anything — it is
    them repeating someone else's disclosure — and an EU AI Act Article 50(2) mark that
    accepted a second-hand disclosure would attest to the wrong party. The same holds
    for the hard binding: a gathered binding binds another asset.

    So widening the undeclared check to gathered assertions must not widen the REQUIRED
    check with it, and this is the test that keeps the two apart.
    """
    links = store.claim["created_assertions"]
    assert isinstance(links, list)

    def names_the_disclosure(link: _cbor.CborValue) -> bool:
        return isinstance(link, dict) and ASSERTION_AI_DISCLOSURE in str(link.get("url", ""))

    moved = [link for link in links if not names_the_disclosure(link)]
    kept = [link for link in links if names_the_disclosure(link)]

    claim = {**store.claim, "created_assertions": moved, "gathered_assertions": kept}
    verdict, ok = _verify._check_assertions(dataclasses.replace(store, claim=claim), Verdict(state=Provenance.INVALID))

    assert not ok
    assert StatusCode.ASSERTION_MISSING in verdict.codes()


def test_a_generator_icon_can_now_actually_resolve(store: ManifestStore) -> None:
    """The match path of 15.10.3.3, which was unreachable when it was written.

    An icon is "a hashed URI ... to an embedded data assertion whose label is
    `c2pa.icon`" (10.2.3.2), and an embedded data assertion carries `bfdb`/`bidb`
    content boxes rather than `cbor`. Until the parse accepted those, every real icon
    resolved to ``hashedURI.missing`` and the success branch could not be reached by any
    input at all -- a check that only ever fails is not a check.

    THE FIXTURE IS A GENUINE `bfdb`/`bidb` SUPERBOX, serialized the way the assertion
    store carries one. A loose byte string leaves this green under a parse that rejects
    non-`cbor` assertions -- it would assert the match path over an input the parse can
    never deliver.

    Both directions are asserted from the same fixture: the right digest resolves, the
    wrong one is a mismatch. That is what makes this a test of the match path rather
    than of the parse.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import parse_manifest_store

    # A REAL EMBEDDED-DATA ASSERTION, not loose bytes. assertion_bytes values are
    # serialized superbox payloads -- a jumd description box followed by content boxes --
    # so a raw blob here would be a value no parse can produce, and this test would be
    # proving the match path reachable using an input that cannot reach it.
    label = "c2pa.icon"
    icon_box = JumbfBox(
        description=DescriptionBox(uuid=_jumbf.UUID_CBOR, label=label, requestable=True),
        content=((b"bfdb", b"image/svg+xml\x00"), (b"bidb", b"<svg/>")),
    )
    digest = hashlib.sha256(_jumbf.serialize_superbox(icon_box)[8:]).digest()
    generator = store.claim["claim_generator_info"]
    links = store.claim["created_assertions"]
    assert isinstance(generator, dict)
    assert isinstance(links, list)

    # PARSED FROM REAL BYTES, so the icon assertion has to survive _parse_assertions --
    # which is the change under test. Restoring the pre-#89 rejection of non-cbor
    # assertions now makes this raise during the parse rather than leaving the test green.
    parsed = parse_manifest_store(_store_with_box(store, icon_box))

    def build(icon_hash: bytes) -> ManifestStore:
        icon: CborMap = {"url": f"self#jumbf=c2pa.assertions/{label}", "hash": icon_hash, "alg": "sha256"}
        claim = {
            **parsed.claim,
            "claim_generator_info": {**generator, "icon": icon},
            "created_assertions": [*links, {"url": f"self#jumbf=c2pa.assertions/{label}", "hash": digest}],
        }
        return dataclasses.replace(parsed, claim=claim)

    _, resolved = _verify._check_assertions(build(digest), Verdict(state=Provenance.INVALID))
    verdict, rejected = _verify._check_assertions(build(b"\x00" * 32), Verdict(state=Provenance.INVALID))

    assert resolved, "an icon whose digest matches must verify"
    assert not rejected
    assert StatusCode.HASHED_URI_MISMATCH in verdict.codes()


@pytest.mark.parametrize(
    ("offset", "inside"),
    [
        (datetime.timedelta(0), True),
        (datetime.timedelta(microseconds=-1), False),
    ],
    ids=["the-first-instant", "one-microsecond-before"],
)
def test_the_validity_window_includes_its_own_endpoints(
    signing_certificate: x509.Certificate, offset: datetime.timedelta, inside: bool
) -> None:
    """Both comparisons in ``_chain_inside_validity`` are ``<=``, and no test used
    either endpoint EXACTLY -- so ``<=`` → ``<`` on the lower bound survived the whole
    suite.

    A certificate is valid at the first instant of its window and at the last. Judging
    the first as outside would reject a freshly issued credential during the second it
    becomes usable, which is a real operational failure and an invisible one: it would
    look like a clock problem.

    Both endpoints are checked, one microsecond either side, against the certificate's
    own ``not_valid_before_utc`` and ``not_valid_after_utc`` rather than against a
    literal, so the test follows the fixture if its dates ever move.
    """
    from c2patxt import _verify as verify_module

    chain = [signing_certificate]
    lower = signing_certificate.not_valid_before_utc
    upper = signing_certificate.not_valid_after_utc

    assert verify_module._chain_inside_validity(chain, lower + offset) is inside
    assert verify_module._chain_inside_validity(chain, upper - offset) is inside


@pytest.mark.parametrize("expired", ["leaf", "issuer"], ids=["leaf", "issuer"])
def test_the_whole_chain_must_be_inside_its_validity_period(
    signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate, expired: str
) -> None:
    """C2PA 15.8.2: "the C2PA Manifest is valid if the current time at validation is
    within the validity period of the signer's certificate **and all CA certificates up
    to the trust anchor**."

    WE CHECKED THE LEAF ONLY, and the docstring quoting this clause stopped at exactly
    the words it omitted -- a quotation that ends where it becomes inconvenient is worse
    than no quotation, because it reads as evidence.

    An expired intermediate is the realistic case, not a contrived one: leaves are
    short-lived and rotated, CAs are long-lived and forgotten. A chain whose CA lapsed
    is one nobody is maintaining, and RFC 5280 §6 path validation would reject it -- so
    accepting it here means we are more permissive than the chain builder we tell
    integrators to plug in.
    """
    from c2patxt import _verify as verify_module

    lapsed = datetime.datetime(2026, 2, 1, tzinfo=datetime.timezone.utc)
    stale = build_certificate(signing_key, common_name="c2patxt test ca", not_after=lapsed)
    chain = [stale if expired == "leaf" else signing_certificate, stale]

    after = datetime.datetime(2026, 3, 1, tzinfo=datetime.timezone.utc)
    inside = datetime.datetime(2026, 1, 15, tzinfo=datetime.timezone.utc)

    assert not verify_module._chain_inside_validity(chain, after)
    assert verify_module._chain_inside_validity(chain, inside), "the control: both are valid before the CA lapses"


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


@pytest.mark.parametrize(
    ("payload", "ok"),
    [
        ({"modelType": "c2pa.types.model"}, True),
        ({"modelType": "c2pa.types.model.pytorch", "modelName": "m"}, True),
        ({"modelType": "c2pa.types.model.openvino.topology"}, True),
        ({}, False),
        ({"modelType": ""}, False),
        ({"modelType": "c2pa.types.model.generative"}, True),
        ({"modelType": "ai.duale.types.model.generative"}, True),
        ({"modelType": "com.example.model"}, True),
        ({"modelType": 7}, False),
        ({"modelType": None}, False),
        ({"junk": 1}, False),
        (["not a map"], False),
        ("not a map either", False),
        (None, False),
    ],
    ids=[
        "generic",
        "a-real-framework",
        "a-value-we-never-emit",
        "no-modelType",
        "empty-modelType",
        "the-string-we-used-to-emit",
        "entity-namespaced",
        "a-vendor-value",
        "modelType-not-a-string",
        "modelType-null",
        "some-other-field",
        "an-array",
        "a-string",
        "absent-from-the-store",
    ],
)
def test_the_disclosure_must_actually_disclose(store: ManifestStore, payload: _cbor.CborValue, ok: bool) -> None:
    """C2PA 18.28.2: `modelType` "shall be present" in the ai-model-disclosure-map.

    WE CHECKED THE LABEL AND NEVER READ THE PAYLOAD. `_store_shape_status` required
    `c2pa.ai-disclosure` to appear in the claim's links and stopped, so a disclosure of
    `{}` -- or `{"junk": 1}`, or a CBOR array -- was linked, hash-matched and VALID.
    This artefact exists under EU AI Act Article 50(2) to carry one fact, and a mark
    carrying none of it was indistinguishable from one that did.

    Third occurrence of this shape: a required assertion whose PRESENCE was checked and
    whose CONTENT was not.
    """
    tampered = dataclasses.replace(store, assertions={**store.assertions, ASSERTION_AI_DISCLOSURE: payload})
    verdict, accepted = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert accepted is ok
    if not ok:
        assert StatusCode.GENERAL_ERROR in verdict.codes()


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
        ("duplicate-label", StatusCode.CLAIM_MULTIPLE),
    ],
    ids=["claim-cbor", "no-claim-box", "claim-without-cbor", "assertion-cbor", "metadata-json", "duplicate-label"],
)
def test_verify_reports_the_parse_code_a_third_party_would_see(
    signer: Signer, damage: str, expected: StatusCode
) -> None:
    """Every parse failure carries a specific code, and NOTHING checked that ``verify``
    passes it on.

    Replacing ``verify``'s ``return verdict._add(exc.code)`` with a fixed
    ``manifest.text.corruptedWrapper`` leaves the whole suite green. So the entire
    ``MarkCorruptError.code`` mechanism -- which ``exceptions.py`` justifies at length,
    and which two of today's tasks extended with four new codes -- was asserted only as
    an exception attribute, never as something a caller of ``verify`` receives.

    THE DISTINCTION IS THE WHOLE POINT OF THOSE CODES. ``manifest.text.corruptedWrapper``
    is 15.12.1.3.2's code for a wrapper with an "invalid version, algorithm, or manifest
    length" -- damage to the selector run. Every case here is an intact wrapper around a
    manifest that is wrong INSIDE, and reporting the carrier's code sends an investigator
    hunting text corruption that is not there.

    Driven through the PUBLIC entry point on purpose. The parse-level tests in
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
        return tuple(out)

    verdict = verify(_restore_manifest(original, rebuild))

    assert verdict.state is Provenance.INVALID
    assert expected in verdict.codes()
    assert StatusCode.TEXT_CORRUPTED_WRAPPER not in verdict.codes(), "the carrier is intact; only the manifest is not"


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

    ``StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS`` APPEARED IN NO TEST FILE AT ALL. The
    only coverage was ``test_hard_bindings_are_counted_across_the_instance_convention``,
    which asserts the COUNTER returns 2 and 3 for a hand-built dict of labels. Nothing
    ever drove a two-binding store through ``_check_assertions``, so the rule was proved
    only about arithmetic -- and both ``> 1`` → ``if False`` and ``> 1`` → ``> 2``
    survived the whole suite.

    WHAT THE RULE IS FOR, from ``_count_hard_bindings``' own docstring:
    ``ManifestStore.hash_data`` looks up the EXACT label, so a second binding under
    ``__N`` was invisible -- the verifier bound against the first and ignored the rest,
    "the 'different consumers read different claims' failure refused elsewhere in this
    package". That refusal is what had no test.

    THE SECOND BOX IS A REAL ONE, relabelled and re-serialized, not the first one's bytes
    under a second key. Two labels mapping to byte-identical payloads is a state the
    parser refuses outright -- both would decode to the same label and
    ``_children_with_bytes`` rejects duplicates -- so a fixture built that way would be
    testing a shape no input can reach.

    The manifest is otherwise COMPLETE. A minimal store reports ``assertion.missing``
    instead, because the required-assertion check runs first, so completeness is what
    makes the assertion about this rule rather than that one.
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
    signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate, when: datetime.datetime, state: Provenance
) -> None:
    """C2PA 15.8.2: "the C2PA Manifest is valid if the current time at validation is
    within the validity period of the signer's certificate **and all CA certificates up
    to the trust anchor**."

    NOTHING PROVES THE CHAIN CHECK IS WIRED THROUGH TO A VERDICT. Changing
    ``_chain_inside_validity(chain, ...)`` to ``(chain[:1], ...)`` -- undoing the whole
    change -- left the suite green, because the only test hand-built a two-certificate
    list and asserted a BOOL from the helper. It never touched ``Verdict.state`` and
    never called ``verify``.

    THE REASON IT WENT UNNOTICED WAS VISIBLE IN THE FIXTURES: until this test, every
    ``Signer`` that produced a MARK was built with exactly one certificate, so no test
    had ever verified text whose ``x5chain`` carried a CA at all. (``test_cose.py`` built
    a two-certificate ``Signer`` to check x5chain serialization, and never verified with
    it.) The sentence is past tense because the fixture below falsifies it. A rule about "all CA certificates" cannot be
    exercised by a corpus with no CAs in it.

    The expired intermediate is the realistic case rather than a contrived one: leaves
    are short-lived and rotated, CAs are long-lived and forgotten. RFC 5280 §6 path
    validation rejects such a chain, so checking the leaf alone made us more permissive
    than the chain builder we tell integrators to supply.

    ``before-the-ca-lapses`` is the control, and it is what makes this fail in both
    directions: the same two-certificate mark must still reach VALID while the CA is
    live, so the test cannot be satisfied by a verifier that rejects every chain.
    """
    lapsed = build_certificate(
        signing_key,
        common_name="c2patxt test ca",
        not_after=datetime.datetime(2026, 2, 1, tzinfo=datetime.timezone.utc),
    )
    signer = Signer(private_key=signing_key, certificates=(signing_certificate, lapsed))

    verdict = verify(mark("Hello world.", signer), context=VerifyContext(now=when))

    assert verdict.state is state
    assert (StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY in verdict.codes()) is (state is Provenance.INVALID)


def test_the_digest_cache_is_keyed_by_algorithm_as_well_as_label(store: ManifestStore) -> None:
    """The memoization added to stop pre-authentication hash amplification caches by
    ``(label, algorithm)``. Nothing checked the second element.

    Changing the key to ``(label, label)`` left the whole suite green. The existing
    counting test kills a mutation that DISABLES the cache, so it proves the cache is
    USED -- not that it is keyed correctly. Under the mutant, two references to one
    assertion under different algorithms both receive the FIRST algorithm's digest, so a
    sha384 reference is compared against a sha256 hash and either falsely matches or, as
    here, falsely fails.

    ``_assertion_digest``'s docstring rests the whole change on one claim -- that caching
    "accepts and rejects exactly what it did before". This is that claim's assertion.

    15.4.2 lets a hashed-uri-map carry its own ``alg``, so a manifest referencing one
    assertion under two algorithms is one a conforming producer can emit. Both digests
    are computed with ``hashlib`` directly rather than through ``HASH_ALGORITHMS``, so
    the expected values do not come from the mapping under test.
    """
    label = ASSERTION_AI_DISCLOSURE
    raw = store.assertion_bytes[label]
    url = f"self#jumbf=c2pa.assertions/{label}"
    cache: dict[tuple[str, str], bytes] = {}

    for algorithm, digest in (("sha256", hashlib.sha256(raw).digest()), ("sha384", hashlib.sha384(raw).digest())):
        code, resolved = _verify._link_status({"url": url, "hash": digest, "alg": algorithm}, store, cache)
        assert resolved == label, f"the {algorithm} reference did not resolve"
        assert code is StatusCode.ASSERTION_HASHED_URI_MATCH

    assert len(cache) == 2, "one entry per (label, algorithm), not one per label"


@pytest.mark.parametrize(
    "drop",
    ["instanceID", "signature", "created_assertions", "claim_generator_info", "name", "array"],
    ids=[
        "instanceID",
        "signature",
        "created_assertions",
        "claim_generator_info",
        "generator-without-a-name",
        "generator-as-an-array",
    ],
)
def test_a_claim_missing_a_required_field_is_malformed(signer: Signer, drop: str) -> None:
    """C2PA 15.6.2 names four fields -- ``instanceID``, ``signature``,
    ``created_assertions``, ``claim_generator_info`` -- and says "If any are absent, then
    the claim shall be rejected with a failure code of `claim.malformed`". It adds: "If
    the `claim_generator_info` field does not contain a `name` field, the claim shall be
    rejected with a failure code of `claim.malformed`."

    THE GUARD COULD BE DISCONNECTED TODAY AND NOTHING WOULD SAY SO. Changing
    ``if _claim_malformed(manifest.claim):`` to ``if False and ...`` left the whole suite
    green. ``_claim_malformed`` was tested only on hand-built dicts, and the one place
    ``claim.malformed`` reached a verdict came through a DIFFERENT branch.

    That is the same shape as the defect this check was added to fix. ``manifest.py``'s
    ``Claim`` docstring had always SAID these fields are "enforced on read by 15.6.2"
    while nothing enforced them, so "a claim with no instanceID verified happily". A fix
    whose only guard is a unit test on the helper can be undone by deleting one line.

    THE CLAIM IS RE-SIGNED for each case rather than mutated after parsing, so
    ``claim_bytes`` and the decoded claim agree and the signature is genuine. A claim
    whose bytes and dict disagree is a state no producer can emit, and testing against
    one would prove the rule about an input the parser cannot deliver.

    ``generator-as-an-array`` is the subtle row: ``claim-map`` v1 declared
    ``claim_generator_info`` as an ARRAY of generator-info-maps and ``claim-map-v2``
    declares a single map. We emit ``c2pa.claim.v2``, so an array is malformed here --
    and it is exactly what a producer written against the older schema would send.
    """
    from c2patxt import _cose, _fixpoint
    from c2patxt._selectors import build_wrapper
    from c2patxt.manifest import DEFAULT_HASH_ALGORITHM, hashed_uri

    text = "Hello world."
    normalized = unicodedata.normalize("NFC", text)
    start = len(normalized.encode("utf-8"))
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()

    def build(exclusion_length: int, pad: bytes) -> str:
        hash_data = Assertion(
            label=ASSERTION_HASH_DATA,
            payload={
                "exclusions": [{"start": start, "length": exclusion_length}],
                "alg": DEFAULT_HASH_ALGORITHM,
                "hash": digest,
                "pad": pad,
            },
        )
        payload: dict[str, object] = {
            "instanceID": "xmp:iid:1",
            "claim_generator_info": {"name": "c2patxt"},
            "created_assertions": [hashed_uri(hash_data.to_box(), f"self#jumbf=c2pa.assertions/{ASSERTION_HASH_DATA}")],
            "signature": "self#jumbf=c2pa.signature",
            "alg": DEFAULT_HASH_ALGORITHM,
        }
        if drop == "name":
            payload["claim_generator_info"] = {"version": "1.0"}
        elif drop == "array":
            payload["claim_generator_info"] = [{"name": "c2patxt"}]
        else:
            del payload[drop]

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
            JumbfBox(
                description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
                content=((b"cbor", _cose.sign_claim(signer, claim_bytes)),),
            ),
        )
        manifest = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST, label="urn:c2pa:" + str(uuid.UUID(int=7))),
            content=tuple((b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in boxes),
        )
        store = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label=LABEL_MANIFEST_STORE),
            content=((b"jumb", _jumbf.serialize_superbox(manifest)[8:]),),
        )
        return build_wrapper(_jumbf.serialize_superbox(store))

    wrapper, _ = _fixpoint.solve(build)
    verdict = verify(normalized + wrapper)

    assert verdict.state is Provenance.INVALID
    assert StatusCode.CLAIM_MALFORMED in verdict.codes()


@pytest.mark.parametrize(
    ("declare", "state"),
    [("gathered", Provenance.VALID), ("nowhere", Provenance.INVALID)],
    ids=["declared-as-gathered", "declared-nowhere"],
)
def test_a_gathered_assertion_survives_the_wire(signer: Signer, declare: str, state: Provenance) -> None:
    """``gathered_assertions`` had never been on the wire in any test.

    The four tests that established the rule inject the field into an ALREADY-PARSED
    store, so they exercise ``_assertion_links`` and nothing between the wire and it.
    Adding ``and key != "gathered_assertions"`` to the claim narrowing in ``_extract``
    -- a parse that silently deletes the field from every claim it reads -- left the
    whole suite green.

    OUR PRODUCER CANNOT EMIT THE FIELD, which is why the gap existed and why closing it
    means building the manifest by hand and re-signing. That is also what makes the test
    meaningful: 15.10.3.1 covers gathered assertions precisely because they come from
    somewhere else, so the only realistic manifest carrying one is a third party's.

    Both rows use the SAME assertion in the SAME store. Only the claim differs -- one
    declares it in ``gathered_assertions``, the other declares it nowhere. So the test
    isolates the field itself rather than the presence of an extra box, and a parse that
    drops the field turns the first row into the second.
    """
    from c2patxt import _cose, _fixpoint
    from c2patxt import manifest as manifest_module
    from c2patxt._selectors import build_wrapper
    from c2patxt.manifest import DEFAULT_HASH_ALGORITHM, hashed_uri
    from tests.conftest import WHEN

    text = "Hello world."
    normalized = unicodedata.normalize("NFC", text)
    start = len(normalized.encode("utf-8"))
    digest = hashlib.sha256(normalized.encode("utf-8")).digest()
    extra = Assertion(label="c2patxt.gathered", payload={"note": "from an ingredient"})

    def build(exclusion_length: int, pad: bytes) -> str:
        required = [
            manifest_module._actions_assertion(WHEN),
            manifest_module._ai_disclosure_assertion(DISCLOSURE),
            manifest_module._metadata_assertion(DISCLOSURE),
            manifest_module._hash_data_assertion(digest, start, exclusion_length, DEFAULT_HASH_ALGORITHM, pad),
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
            JumbfBox(
                description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
                content=((b"cbor", _cose.sign_claim(signer, claim_bytes)),),
            ),
        )
        manifest = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST, label="urn:c2pa:" + str(uuid.UUID(int=7))),
            content=tuple((b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in boxes),
        )
        store = JumbfBox(
            description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label=LABEL_MANIFEST_STORE),
            content=((b"jumb", _jumbf.serialize_superbox(manifest)[8:]),),
        )
        return build_wrapper(_jumbf.serialize_superbox(store))

    wrapper, _ = _fixpoint.solve(build)
    verdict = verify(normalized + wrapper)

    assert verdict.state is state
    assert (StatusCode.ASSERTION_UNDECLARED in verdict.codes()) is (state is Provenance.INVALID)


def _poisoned_generator(store: ManifestStore, generator: CborMap) -> CborMap:
    """A generator-info-map whose icon points at a real assertion with the wrong digest."""
    icon: CborMap = _widen(_icon(store, hash=b"\x00" * 32))
    return {**generator, "icon": icon}


def _store_with_box(store: ManifestStore, box: JumbfBox) -> bytes:
    """Serialized store bytes with ``box`` added to the assertion store.

    Returns BYTES rather than a ``ManifestStore``, so the caller has to parse them --
    which is the point wherever the property under test is about what the parse accepts.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import parse_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE

    original, _ = parse_superbox(store.raw)
    manifest, _ = _reparse(original.content[0][1])
    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_ASSERTION_STORE:
            child = JumbfBox(
                description=child.description,
                content=(*child.content, (_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(box)[8:])),
            )
        rebuilt.append((tbox, _jumbf.serialize_superbox(child)[8:]))
    return _jumbf.serialize_superbox(
        JumbfBox(
            description=original.description,
            content=(
                (
                    _jumbf.TBOX_SUPERBOX,
                    _jumbf.serialize_superbox(JumbfBox(description=manifest.description, content=tuple(rebuilt)))[8:],
                ),
            ),
        )
    )


def test_supplying_anchors_directly_is_refused_rather_than_ignored() -> None:
    """``VerifyContext(anchors=...)`` accepted the argument and threw it away.

    ``anchors`` is DERIVED from ``anchors_pem`` -- ``__post_init__`` overwrites it
    unconditionally -- so a caller who passed parsed certificates got a context with
    ``anchors == ()``, no error, and every mark reported ``signingCredential.untrusted``
    forever. Silent, and indistinguishable from having supplied nothing.

    THE README TOLD PEOPLE TO DO IT. "Supply anchors via ``VerifyContext(anchors=...)``
    and it becomes TRUSTED" shipped in the same document that states the correct form
    fifty lines later. A field that ignores its own keyword is a trap whether or not
    anything points at it, but a documented trap is one somebody will walk into.

    ``init=False`` is the fix and the refusal is the point: TypeError at the call site
    names the wrong keyword, where a silently empty tuple names nothing.
    """
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
    would pass. Use :func:`_store_with_box` and a real parse when the property under test
    involves the signature or the wire.
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


@pytest.mark.parametrize(
    ("payload", "ok"),
    [
        ({"actions": [{"action": "c2pa.created"}], "templates": [{"action": "*", "digitalSourceType": _SRC}]}, True),
        (
            {
                "actions": [{"action": "c2pa.created"}],
                "templates": [{"action": "c2pa.created", "digitalSourceType": _SRC}],
            },
            True,
        ),
        (
            {
                "actions": [{"action": "c2pa.created"}],
                "templates": [{"action": "c2pa.edited", "digitalSourceType": _SRC}],
            },
            False,
        ),
        ({"actions": [{"action": "c2pa.created"}], "templates": "not a list"}, False),
        ({"actions": [{"action": "c2pa.created", "digitalSourceType": _SRC}], "templates": [{"action": "*"}]}, True),
        # A NON-MAP TEMPLATE, ahead of a good one. `_overlaid_action` skips it with a
        # `continue`, and that line was reached only by a direct call to that helper --
        # so nothing checked that the skip survives the rules built on top of it. This
        # row drives it through `_check_assertions`, which is a layer up rather than the
        # public `verify()`: it is where the actions rules are decided, and it is the
        # layer the rest of this file uses. It must be skipped rather than raise, AND
        # it must not stop the template behind it applying, which is why the good one is
        # second and the row is expected to PASS.
        (
            {
                "actions": [{"action": "c2pa.created"}],
                "templates": [42, "not a map", {"action": "*", "digitalSourceType": _SRC}],
            },
            True,
        ),
    ],
    ids=[
        "star-template",
        "named-template",
        "template-for-another-action",
        "templates-not-a-list",
        "action-wins",
        "non-map-template-is-skipped",
    ],
)
def test_a_template_may_supply_the_digital_source_type(store: ManifestStore, payload: CborMap, ok: bool) -> None:
    """C2PA 18.15.6.1: "These values are combined by a C2PA Manifest Consumer with actions
    of the same name, or with all actions (if the value of the action field is the `*`
    special value), to get a full picture of an action... A C2PA Manifest Consumer
    **shall** take the values from the template and overlay the values from the action
    itself."

    WE REJECTED THE SPECIFICATION'S OWN EXAMPLE. Example 9 is, near verbatim, the first
    row here: actions carrying no ``digitalSourceType`` and a `*` template supplying it.
    Requiring the field on the action alone made a conforming manifest
    ``assertion.action.malformed`` -- and ``_action_references`` in the same module was
    already walking ``templates`` for icons, so the array was known about and not read.

    ``template-for-another-action`` is the control that keeps the overlay honest: a
    template naming ``c2pa.edited`` must NOT supply anything to ``c2pa.created``, or the
    rule degrades into "the field appears somewhere in the assertion".

    ``action-wins`` pins the direction of the overlay -- the template supplies defaults
    and the action overrides -- which is what "overlay the values from the action itself"
    means and is the opposite of what a naive ``dict.update`` order would produce.
    """
    tampered = _with_assertion(store, ASSERTION_ACTIONS, payload)
    verdict, accepted = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert accepted is ok
    if not ok:
        assert StatusCode.ASSERTION_ACTION_MALFORMED in verdict.codes()


def test_a_claim_that_never_links_its_hard_binding_says_the_assertion_is_missing(store: ManifestStore) -> None:
    """The one ``_REQUIRED_ASSERTIONS`` entry that had nothing of its own holding it.

    Dropping ``frozenset({ASSERTION_HASH_DATA})`` from the tuple left the whole suite
    green, because a store with no binding is INVALID anyway -- ``_binding_status``
    reports ``claim.hardBindings.missing`` from a different branch, and every existing
    test was satisfied by the state. Only the CODE changed, and the code is the entire
    output an integrator reads.

    THE TWO ARE NOT THE SAME FINDING. ``claim.hardBindings.missing`` says the claim
    carries no binding to evaluate; ``assertion.missing`` says the claim did not commit
    to one of the three assertions that make a mark mean anything. Kept as a distinct
    entry so a claim missing its binding is reported alongside a claim missing its
    disclosure, in the same words, rather than only through the binding evaluator.

    Driven through ``_check_assertions`` alone so the binding evaluator cannot supply
    the verdict: whatever fails here is this entry's doing.
    """
    url = f"self#jumbf=c2pa.assertions/{ASSERTION_HASH_DATA}"
    links = store.claim["created_assertions"]
    assert isinstance(links, list)
    kept = [link for link in links if not (isinstance(link, dict) and link.get("url") == url)]
    assert len(kept) == len(links) - 1, "the fixture must have linked its binding"

    unbound = dataclasses.replace(
        store,
        claim={**store.claim, "created_assertions": kept},
        assertions={k: v for k, v in store.assertions.items() if k != ASSERTION_HASH_DATA},
        assertion_bytes={k: v for k, v in store.assertion_bytes.items() if k != ASSERTION_HASH_DATA},
    )

    verdict, accepted = _verify._check_assertions(unbound, Verdict(state=Provenance.INVALID))
    assert not accepted
    assert StatusCode.ASSERTION_MISSING in verdict.codes()


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("self#jumbf=c2pa.databoxes/c2pa.icon", True),
        ("self#jumbf=c2pa.databoxes/", False),
    ],
    ids=["real-destination", "empty-tail"],
)
def test_a_data_box_icon_is_passed_over_only_when_it_names_something(store: ManifestStore, url: str, ok: bool) -> None:
    """The pass-over decided through a verdict rather than through the private helper.

    ``_reference_status``'s two branches are already tabulated in ``test_negative.py``
    against a direct call. What that cannot say is that the answer survives the trip:
    ``None`` has to mean the reference walk finds no failure and ``_check_assertions``
    accepts, and ``HASHED_URI_MISSING`` has to become a code on the verdict rather than
    being swallowed by the ``next(...)`` that consumes the walk.

    ``c2pa.databoxes/`` with nothing after it names no destination, so it is not a
    reference we DECLINED to resolve -- it is one that resolves to nothing, which is
    what hashedURI.missing is for. Passing it over would let any unresolvable icon be
    laundered through a trailing slash.
    """
    icon: CborMap = {"url": url, "hash": b"\x00" * 32, "alg": "sha256"}
    payload: CborMap = {
        "actions": [
            {"action": "c2pa.created", "digitalSourceType": _SRC, "softwareAgent": {"name": "agent", "icon": icon}}
        ]
    }

    verdict, accepted = _verify._check_assertions(
        _with_assertion(store, ASSERTION_ACTIONS, payload), Verdict(state=Provenance.INVALID)
    )

    assert accepted is ok
    if not ok:
        assert StatusCode.HASHED_URI_MISSING in verdict.codes()


def test_a_second_actions_assertion_may_not_smuggle_a_malformed_inception(store: ManifestStore) -> None:
    """18.15.2: "The full set of actions assertions in a C2PA Manifest shall contain no
    more than one action whose type is either `c2pa.created` or `c2pa.opened`."

    AN UNDER-REJECT, in the rule written to prevent exactly this. ``_actions_status``
    asked ``_has_single_inception_action`` of every assertion and read ``False`` as
    "carries no inception" -- but that function returns ``False`` for a dozen unrelated
    reasons. A second assertion holding a BARE ``c2pa.created``, with no
    ``digitalSourceType``, was malformed as an inception assertion and therefore counted
    as holding none, so two inception actions across two assertions verified clean.

    The fix is two predicates rather than one: ``_contains_inception`` asks only whether
    an inception action appears anywhere, and is what the positional sweep uses;
    ``_has_single_inception_action`` keeps answering the well-formedness question, and is
    asked only of the first.
    """
    good: CborMap = {"actions": [{"action": "c2pa.created", "digitalSourceType": _SRC}]}
    bare: CborMap = {"actions": [{"action": "c2pa.created"}]}

    tampered = _with_assertion(_with_assertion(store, ASSERTION_ACTIONS, good), f"{ASSERTION_ACTIONS}__1", bare)
    verdict, accepted = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert not accepted
    assert StatusCode.ASSERTION_ACTION_MALFORMED in verdict.codes()


@pytest.mark.parametrize(
    ("payload", "ok"),
    [({"modelType": "c2pa.types.model"}, True), ({}, False), ({"modelType": ""}, False)],
    ids=["conforming", "empty", "empty-modelType"],
)
def test_every_disclosure_instance_is_read_not_just_the_first(store: ManifestStore, payload: CborMap, ok: bool) -> None:
    """C2PA 6.4 lets a manifest carry ``c2pa.ai-disclosure`` and
    ``c2pa.ai-disclosure__1``. We read the base label only, so a SECOND disclosure
    asserting nothing was linked, hash-matched and never looked at -- verifying VALID.

    This is the un-swept remainder of a class already caught once: ``_count_hard_bindings``,
    ``_actions_labels`` and ``_action_references`` all honour ``__N``, and the disclosure
    did not. For a package whose stated purpose is carrying one disclosure fact, a
    second disclosure asserting nothing reaching VALID is that defect again, in the one
    assertion it matters most for.

    The ``__N`` grammar now lives in ONE helper rather than three copies, which is what
    stops the fourth site from being written wrong.
    """
    tampered = _with_assertion(store, f"{ASSERTION_AI_DISCLOSURE}__1", payload)
    verdict, accepted = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert accepted is ok
    if not ok:
        assert StatusCode.GENERAL_ERROR in verdict.codes()


def test_the_store_shape_is_reported_before_a_bad_reference(store: ManifestStore) -> None:
    """``_assertion_failure``'s docstring calls its check order "the contract... so a
    manifest missing its disclosure is reported as missing its disclosure rather than as
    having a bad generator icon". Swapping the two halves of that ``or`` survived the
    whole suite, because no test made both fail at once.

    An ordering claim needs an input where the two answers differ; with only one defect
    present, every order gives the same code. This is the third time a prose-only
    ordering claim has been found unheld in this file, which is why the two below it
    exist as well.

    The manifest here is broken twice over -- the disclosure link removed AND the
    generator icon poisoned -- and must report the missing disclosure, because that is
    what an operator has to fix first.
    """
    links = store.claim["created_assertions"]
    assert isinstance(links, list)

    def names_disclosure(link: _cbor.CborValue) -> bool:
        return isinstance(link, dict) and ASSERTION_AI_DISCLOSURE in str(link.get("url", ""))

    generator = store.claim["claim_generator_info"]
    assert isinstance(generator, dict)
    broken = {
        **store.claim,
        "created_assertions": [link for link in links if not names_disclosure(link)],
        "claim_generator_info": _poisoned_generator(store, generator),
    }

    verdict, ok = _verify._check_assertions(dataclasses.replace(store, claim=broken), Verdict(state=Provenance.INVALID))

    assert not ok
    assert StatusCode.ASSERTION_MISSING in verdict.codes()
    assert StatusCode.HASHED_URI_MISMATCH not in verdict.codes()


def test_a_malformed_actions_assertion_is_reported_before_an_empty_disclosure(store: ManifestStore) -> None:
    """The same class, one level down: ``_store_shape_status`` runs ``_actions_status``
    before the disclosure loop, and hoisting the disclosure above it survived.

    Both assertions are broken here -- the actions assertion carries no inception and the
    disclosure is empty -- so the two orders give different codes and the test can tell
    them apart.
    """
    tampered = _with_assertion(_with_assertion(store, ASSERTION_ACTIONS, _ACTIONS_EDITED), ASSERTION_AI_DISCLOSURE, {})

    verdict, ok = _verify._check_assertions(tampered, Verdict(state=Provenance.INVALID))

    assert not ok
    assert StatusCode.ASSERTION_ACTION_MALFORMED in verdict.codes()
    assert StatusCode.GENERAL_ERROR not in verdict.codes()


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

    THE TRUST EVALUATOR IS CALLER-SUPPLIED, AND THE RECOMMENDED ONE RAISES. `pyproject`
    ships `pyhanko-certvalidator` as the ``[trust]`` extra, and its path validation
    signals an unreachable anchor with ``PathBuildingError`` / ``PathValidationError`` --
    which is the single most likely outcome of asking it about a chain. So the natural
    implementation of the documented seam broke the package's central promise.

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


def test_a_store_labelled_c2pa_actions_v1_is_accepted(store: ManifestStore) -> None:
    """The v1 actions label reported ``assertion.missing`` -- naming a condition that
    was not the one that failed, for a store that plainly HAD an actions assertion and
    linked it.

    Every clause names both labels. 15.10.3.2.3 opens "If the assertion's label is
    c2pa.actions or c2pa.actions.v2"; Table 7 lists them as one row; 5.1 says a
    deprecated construct "can be read, but never written", and we still emit v2 only.

    DRIVEN THROUGH A RELABELLED STORE, not through the pure label function. The
    behaviour was correct when this was written and NOTHING HELD IT: reverting
    ``_REQUIRED_ASSERTIONS`` to v2-only left the entire suite green, so the false
    reject this fixes had no guard at all. Relabelling the assertion, its raw bytes and
    the claim's link together is what makes the store a genuine v1 manifest rather than
    a v2 one with a renamed key.
    """
    v1 = ASSERTION_ACTIONS_V1
    original = store.claim["created_assertions"]
    assert isinstance(original, list)

    links: list[_cbor.CborValue] = []
    for link in original:
        if isinstance(link, dict):
            url = link.get("url")
            if isinstance(url, str) and ASSERTION_ACTIONS in url:
                links.append({**link, "url": url.replace(ASSERTION_ACTIONS, v1)})
                continue
        links.append(link)
    relabelled = dataclasses.replace(
        store,
        claim={**store.claim, "created_assertions": links},
        assertions={
            (v1 if label == ASSERTION_ACTIONS else label): payload for label, payload in store.assertions.items()
        },
        assertion_bytes={
            (v1 if label == ASSERTION_ACTIONS else label): raw for label, raw in store.assertion_bytes.items()
        },
    )

    verdict, accepted = _verify._check_assertions(relabelled, Verdict(state=Provenance.INVALID))

    assert accepted, f"a v1 actions assertion was rejected: {verdict.failure}"
    assert StatusCode.ASSERTION_MISSING not in verdict.codes()


def test_an_unlinked_second_hard_binding_is_undeclared_not_multiple(store: ManifestStore) -> None:
    """An unlinked extra assertion reported the wrong condition when it happened to be
    a hard binding.

    ``_count_hard_bindings`` read the STORE while the undeclared check reads the CLAIM,
    so an unlinked ``c2pa.hash.data__1`` produced ``assertion.multipleHardBindings`` --
    sending an investigator to look for two bindings the claim never named -- where an
    unlinked assertion of any other type produces ``assertion.undeclared``.

    Both reject, so this is a naming defect rather than a hole. It still matters: the
    code is the first thing an operator reads, and 15.10.1.2's rule is about the
    bindings the claim VOUCHES for. Two LINKED bindings are still
    ``multipleHardBindings``, which the second half of this test pins.
    """
    smuggled = dataclasses.replace(
        store,
        assertion_bytes={**store.assertion_bytes, f"{ASSERTION_HASH_DATA}__1": b"not linked by the claim"},
    )
    verdict, accepted = _verify._check_assertions(smuggled, Verdict(state=Provenance.INVALID))

    assert not accepted
    assert StatusCode.ASSERTION_UNDECLARED in verdict.codes(), "an unlinked assertion is undeclared, whatever its type"
    assert StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS not in verdict.codes()


def test_an_unparseable_signature_box_reports_missing_not_mismatch(store: ManifestStore) -> None:
    """15.7's code for a signature box that will not parse is ``claimSignature.missing``.

    Every other code choice in ``_verify`` is pinned -- eleven were mutated and ten
    died -- and this one was not: swapping it to ``claimSignature.mismatch`` passed the
    whole suite. The distinction is what an operator acts on. MISSING says the
    credential is not there to check; MISMATCH says it is there and does not verify,
    which sends them looking for tampering that has not happened.
    """
    broken = dataclasses.replace(store, signature=b"\xff\xff not COSE at all")
    verdict, ok, _trusted = _verify._check_signature(broken, Verdict(state=Provenance.INVALID), VerifyContext())

    assert not ok
    assert StatusCode.CLAIM_SIGNATURE_MISSING in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_MISMATCH not in verdict.codes()


def test_an_expired_credential_explains_which_rule_and_when(signing_key: Ed25519PrivateKey) -> None:
    """``Verdict.explanation`` is a channel, and half of it was unasserted.

    The three explanations that ARE pinned all died under mutation; this one could be
    replaced with ``None`` and nothing noticed. An explanation that silently becomes
    absent is worse than one that was never promised: ``raise_for_state`` and every
    log line built from a verdict lose the only sentence saying WHY.
    """
    import datetime

    expired = build_certificate(
        signing_key,
        not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc),
    )
    signer = Signer(private_key=signing_key, certificates=(expired,), allow_nonconformant=True)
    text = mark("Hello world.", signer)

    verdict = verify(text, context=VerifyContext(now=datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc)))

    assert StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY in verdict.codes()
    explanations = [status.explanation for status in verdict.failure if status.explanation]
    assert any("validity period" in text for text in explanations), (
        f"the outsideValidity status carries no explanation: {explanations}"
    )
