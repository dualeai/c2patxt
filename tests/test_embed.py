"""Tests for :func:`c2patxt.embed`.

The round trip -- embed then verify -- is the only test that proves the producer and
the consumer agree, and it is the one a wrong constant fails first.
"""

from __future__ import annotations

import datetime
import unicodedata
import uuid
from collections.abc import Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt import (
    AlreadyMarkedError,
    EmbedContext,
    MarkCorruptError,
    Provenance,
    embed,
    extract,
    strip,
    verify,
)
from c2patxt.constants import MAGIC, MARKER
from c2patxt.signing import Signer
from tests.conftest import DISCLOSURE, WHEN, build_certificate

PINNED = EmbedContext(manifest_uuid=uuid.UUID(int=7), instance_id="xmp:iid:pinned", when=WHEN)


#: This suite exercises the WHOLE stack -- selectors, JUMBF, CBOR, COSE, certificate
#: profile, hash binding -- against text that genuinely satisfies the binding, rather
#: than against hand-built fragments.


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


# --------------------------------------------------------------------------------
# The round trip
# --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Hello world.",
        "",
        "a",
        "漢字テキスト",
        "مرحبا שלום",
        "x" * 4096,
        "line one\nline two\r\n\ttabbed",
        "emoji 👨‍👩‍👧‍👦 zwj",
        "markdown **bold** and `code`",
    ],
)
def test_embed_then_verify_round_trips(text: str, signer: Signer) -> None:
    """The one test that proves producer and consumer agree, across byte costs."""
    assert verify(embed(text, signer, DISCLOSURE, context=PINNED)).state is Provenance.VALID


def test_the_visible_text_is_unchanged(signer: Signer) -> None:
    """Marking must not alter what a reader sees.

    Variation selectors are zero-width and the mark is a suffix, so stripping from
    U+FEFF returns the original exactly. If this ever fails, the mark is corrupting
    documents, which is worse than failing to mark them.
    """
    text = "The quick brown fox."
    marked = embed(text, signer, DISCLOSURE, context=PINNED)
    assert marked[: marked.index(MARKER)] == text
    assert marked.startswith(text)


def test_the_mark_is_a_suffix_and_there_is_exactly_one(signer: Signer) -> None:
    """Suffix placement is what makes the two normalization orders agree."""
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    assert marked.count(MARKER) == 1
    assert marked.index(MARKER) == len("Hello world.")


def test_the_exclusion_names_the_wrapper_exactly(signer: Signer) -> None:
    """15.12.1.3.1 step 3: the exclusion must correspond to a located wrapper.

    Asserted directly rather than trusted via verify(), so an off-by-one shows up
    here as an offset rather than as an unexplained hash mismatch.
    """
    text = "Hello world."
    marked = embed(text, signer, DISCLOSURE, context=PINNED)
    manifest = extract(marked)
    assert manifest is not None
    hash_data = manifest.hash_data
    assert hash_data is not None

    exclusions = hash_data["exclusions"]
    assert isinstance(exclusions, list)
    entry = exclusions[0]
    assert isinstance(entry, dict)

    encoded = marked.encode("utf-8")
    assert entry["start"] == len(text.encode("utf-8"))
    assert entry["length"] == len(encoded) - len(text.encode("utf-8"))


def test_the_wrapper_carries_the_magic_number(signer: Signer) -> None:
    """A.8.2.2: the package name IS this constant."""
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    manifest = extract(marked)
    assert manifest is not None
    assert MAGIC == b"C2PATXT\x00"


# --------------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------------


def test_embedding_twice_with_a_pinned_context_is_byte_identical(signer: Signer) -> None:
    """The claim the whole EmbedContext design exists to make testable.

    Ed25519's deterministic nonce (RFC 8032 5.1.6) is what makes this reachable at
    all; every other varying input is pinned by the context.
    """
    first = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    second = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    assert first == second


def test_embedding_twice_without_a_context_differs(signer: Signer) -> None:
    """Unpinned marks differ, and MUST: a reused manifest UUID or instanceID across
    documents is a correctness error, not a tidiness one."""
    assert embed("Hello world.", signer, DISCLOSURE) != embed("Hello world.", signer, DISCLOSURE)


def test_an_unpinned_mark_still_verifies(signer: Signer) -> None:
    """The default path is the one users take; it must not be the untested one."""
    assert verify(embed("Hello world.", signer, DISCLOSURE)).state is Provenance.VALID


# --------------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------------


def test_nfd_input_is_normalized_before_marking(signer: Signer) -> None:
    """A.8.6.1 requires NFC for hashing; we normalize before marking so the
    producer's offsets and the verifier's are over the same bytes.

    The visible text therefore comes back as NFC, which for NFD input is a real
    change to the caller's bytes. That is deliberate and documented -- the
    alternative is a mark whose offsets no verifier can reproduce.
    """
    nfd = unicodedata.normalize("NFD", "café")
    assert nfd != "café"

    marked = embed(nfd, signer, DISCLOSURE, context=PINNED)
    assert marked[: marked.index(MARKER)] == "café"
    assert verify(marked).state is Provenance.VALID


def test_nfc_input_is_returned_byte_identical(signer: Signer) -> None:
    """The common case must be lossless. Effectively all real text is already NFC."""
    text = "café and 漢字"
    marked = embed(text, signer, DISCLOSURE, context=PINNED)
    assert marked[: marked.index(MARKER)] == text


# --------------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------------


def test_embedding_over_an_existing_mark_raises(signer: Signer) -> None:
    """Neither append nor replace: both fail somewhere the caller cannot see.

    A second wrapper is invalid per 15.5.2.1 and would only surface at the consumer;
    replacing would discard another producer's signed claim.
    """
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    with pytest.raises(AlreadyMarkedError, match="already carries") as excinfo:
        embed(marked, signer, DISCLOSURE, context=PINNED)

    start, stop = excinfo.value.span
    encoded = marked.encode("utf-8")
    assert encoded[:start].decode("utf-8") == "Hello world."
    assert stop == len(encoded)


def test_the_already_marked_span_is_enough_to_re_mark(signer: Signer) -> None:
    """The reported span must be actionable, not merely informative."""
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    with pytest.raises(AlreadyMarkedError) as excinfo:
        embed(marked, signer, DISCLOSURE, context=PINNED)

    start, stop = excinfo.value.span
    encoded = marked.encode("utf-8")
    # The span must name exactly what strip() removes, or the error is telling the
    # caller something the shipped helper contradicts.
    assert (encoded[:start] + encoded[stop:]).decode("utf-8") == strip(marked)
    assert verify(embed(strip(marked), signer, DISCLOSURE, context=PINNED)).state is Provenance.VALID


def test_embedding_over_a_corrupt_mark_raises(signer: Signer) -> None:
    """Marking on top of damage would bury it under a valid-looking signature."""
    corrupt = embed("Hello world.", signer, DISCLOSURE, context=PINNED)[:-400]
    with pytest.raises(MarkCorruptError):
        embed(corrupt, signer, DISCLOSURE, context=PINNED)


def test_an_unsupported_algorithm_is_refused(signer: Signer) -> None:
    """13.1 permits sha256/384/512 and says implementations "shall not support
    additional algorithms on an optional basis"."""
    context = EmbedContext(when=WHEN, algorithm="sha1")
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        embed("Hello world.", signer, DISCLOSURE, context=context)


@pytest.mark.parametrize("algorithm", ["sha256", "sha384", "sha512"])
def test_every_permitted_algorithm_round_trips(algorithm: str, signer: Signer) -> None:
    """All three permitted algorithms, not just the default."""
    context = EmbedContext(manifest_uuid=uuid.UUID(int=7), instance_id="x", when=WHEN, algorithm=algorithm)
    assert verify(embed("Hello world.", signer, DISCLOSURE, context=context)).state is Provenance.VALID


def test_a_naive_signing_time_is_refused(signer: Signer) -> None:
    """A naive datetime names no instant. Assuming UTC would silently misdate marks
    produced anywhere else."""
    context = EmbedContext(when=datetime.datetime(2026, 6, 1, 12, 0))  # noqa: DTZ001
    with pytest.raises(ValueError, match="timezone-aware"):
        embed("Hello world.", signer, DISCLOSURE, context=context)


# --------------------------------------------------------------------------------
# The payload prohibition
# --------------------------------------------------------------------------------


def test_the_manifest_carries_no_operator_identity(signer: Signer) -> None:
    """RFC-136 5: no tenant, agent, account, end-user, author, prompt or
    conversation content, ever.

    Asserted against the emitted BYTES rather than against the builder's inputs,
    because the prohibition is a property of what ships, not of what was intended.
    Signed bytes cannot be recalled once a document leaves the building.
    """
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    manifest = extract(marked)
    assert manifest is not None

    lowered = manifest.raw.lower()
    for forbidden in (b"tenant", b"agent", b"account", b"user", b"author", b"prompt", b"conversation", b"session"):
        assert forbidden not in lowered


def test_the_published_size_figures_are_still_true(signer: Signer) -> None:
    """The README, the release notes and the platform handoff all publish size numbers.

    They went stale once, silently: adding the `c2pa.metadata` assertion required by
    the text conformance rubric grew the manifest by ~570 bytes, and three documents
    kept quoting figures taken before it. Nothing noticed, because a number in prose
    has nothing checking it.

    Bounds are loose on purpose -- this guards against a SILENT DRIFT of the kind that
    already happened, not against a deliberate change. A deliberate change fails this
    test, which is the point: it forces the documents to be updated in the same commit.
    """
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    store = extract(marked)
    assert store is not None

    wrapper = marked[marked.index(MARKER) :]
    wrapper_bytes = len(wrapper.encode("utf-8"))
    inflation = wrapper_bytes / len(store.raw)

    # THE PUBLISHED NUMBERS, HELD TIGHTLY ENOUGH TO MEAN SOMETHING. The bounds were
    # 3.75-3.9375 and 6_000-8_000, which held NEITHER figure the documents print: 14%
    # growth passed, and a stale 6,872 B sat comfortably inside. A test that permits
    # every number the docs might have said does not hold the number they do say.
    #
    # 3.9375 is the THEORETICAL worst case (every byte a 4-byte selector); the observed
    # value is lower because 1 byte in 16 falls in the 3-byte plane. The band below is
    # narrow enough that an assertion or a field added to the manifest trips it, which
    # is the moment the documents need re-measuring.
    # THE STORE SIZE, EXACTLY. `constants.py` publishes 1,797 to the byte and said both
    # its figures were "held by tests/test_embed.py"; only the leaf+CA one was. The
    # bounds below admit any store from 1764.7 to 1825.2 B -- a 61-byte band around a
    # number printed to the byte, which is not holding it.
    assert len(store.raw) == 1_797, f"self-signed store is {len(store.raw)} B; the documents publish 1,797"
    assert 3.89 <= inflation <= 3.91, f"inflation {inflation:.3f}; README publishes 3.90"
    assert 6_900 <= wrapper_bytes <= 7_100, (
        f"{wrapper_bytes} B per mark under the pinned context; platform-handoff.md publishes 7,001"
    )

    # A.8.2.2: 13-byte header plus the marker, so the CHARACTER count is exact.
    assert len(wrapper) == len(store.raw) + 14


def test_the_published_leaf_and_ca_size_is_still_true(signing_key: Ed25519PrivateKey) -> None:
    """The second row of the same size table, which nothing held.

    ``constants.py`` published 2,102 B and ``docs/platform-handoff.md`` published
    2,090 B, re-measured a day apart, and both cannot be right. Neither reproduced: the
    chain CONSTRUCTION was pinned nowhere, so the number depended on how whoever took it
    happened to build the CA that day, and no assertion covered the row at all.

    The construction is now here, which is what makes the figure mean something: a leaf
    issued under a named CA and carrying an authority key identifier, with the CA's own
    certificate second in the chain. Change the construction and this fails, which is the
    moment the documents need re-measuring.
    """
    ca_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    ca = build_certificate(ca_key, common_name="c2patxt test CA")
    leaf = build_certificate(signing_key, issuer_name="c2patxt test CA", authority_key_identifier=True)
    signer = Signer(private_key=signing_key, certificates=(leaf, ca))

    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    store = extract(marked)
    assert store is not None
    wrapper_bytes = len(marked[marked.index(MARKER) :].encode("utf-8"))

    assert len(store.raw) == 2_120, f"leaf+CA store is {len(store.raw)} B; the documents publish 2,120"
    assert wrapper_bytes == 8_218, f"leaf+CA mark is {wrapper_bytes} B; the documents publish 8,218"


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("instanceID", "xmp:iid:pinned"),
        ("alg", "sha256"),
        ("signature", "self#jumbf=c2pa.signature"),
    ],
    ids=["instanceID", "alg", "signature"],
)
def test_the_claim_fields_survive_the_round_trip_to_the_wire(signer: Signer, field: str, expected: str) -> None:
    """NOTHING PINS THE MANIFEST CBOR, and CONTRIBUTING.md makes that a versioning
    matter: "Any change to the bytes we emit is a MAJOR version of both this package and
    the conformance vector file."

    The conformance vector file cannot help -- it treats the payload as opaque by
    design, "given text and an opaque manifest payload" -- and the byte-stability test
    compares two of our own runs, so it cannot tell a correct encoding from a
    consistently wrong one.

    These fields are read back out of the DECODED CBOR of a genuinely marked document,
    so each value has to survive ``_cbor.dumps``, the JUMBF serializer, the selector
    encoding, the parse and the CBOR decode. Asserting against ``to_payload()`` -- a
    plain dict -- proves none of that: a mutation that strips a field one line later,
    just before ``dumps``, leaves such a test green.
    """
    store = extract(embed("Hello world.", signer, DISCLOSURE, context=PINNED))
    assert store is not None
    assert store.claim[field] == expected


def test_the_spec_version_survives_the_round_trip_to_the_wire(signer: Signer) -> None:
    """The case that found the gap: stripping ``specVersion`` from the map just before
    ``_cbor.dumps`` left all 944 tests green -- the suite as it stood
    that morning, while removing it from ``to_payload()``
    killed two. The only guard sat exactly one line too early.

    10.2.3.2 puts the field in ``claim_generator_info``, and 2.4 deprecated the
    claim-level position -- "Moved the specVersion field from the claim to the
    claim_generator_info object" -- so ABSENCE at claim level is as much a wire property
    as presence inside the generator info, and both are asserted here where they are
    observable.

    ``manifest.py`` says changing this constant "is a claim about the WHOLE producer, not
    a version bump", because 5.1 makes setting it a declaration that the manifest
    "does not contain any constructs that are deprecated in that version". CLAUDE.md
    requires an assertion holding a claim like that; until now it had one that checked a
    dict.
    """
    store = extract(embed("Hello world.", signer, DISCLOSURE, context=PINNED))
    assert store is not None

    generator = store.claim["claim_generator_info"]
    assert isinstance(generator, dict)
    assert generator["specVersion"] == "2.4.0"
    assert "specVersion" not in store.claim, "the claim-level field is deprecated at 2.4"


def test_the_test_helper_produces_exactly_what_embed_produces(signer: Signer) -> None:
    """``mark()`` IS ``embed()`` REWRITTEN, and dozens of tests are built on it.

    ``tests/conftest.py``'s ``mark`` and ``wrapper_builder`` walk the same five steps as
    ``_embed.embed`` -- normalize, digest, build a closure, solve the fixpoint, append --
    and its own docstring says so: "embed() in miniature, so verify() can be tested
    against bytes that actually satisfy the binding". Nothing asserted the two agree.

    THAT IS THE LARGEST REIMPLEMENTATION IN THIS SUITE. If ``embed`` were to drop NFC
    normalization, change ``generator_name``, reorder the assertion store or gain a
    field, all 54 call sites would keep passing -- against bytes the shipped producer no
    longer emits. The tests would be verifying a producer that exists only in
    ``conftest``.

    A byte comparison is the whole guard, and it is available because both sides are pure
    functions of their inputs: ``EmbedContext`` takes the clock, the instance ID and the
    manifest UUID, and ``conftest`` pins all three to the values ``mark`` uses.

    If these two ever legitimately diverge, this assertion is where the divergence has to
    be justified in writing rather than discovered later by a failing conformance run.
    """
    from tests.conftest import DISCLOSURE, WHEN, mark

    context = EmbedContext(when=WHEN, instance_id="xmp:iid:1", manifest_uuid=uuid.UUID(int=7))

    assert mark("Hello world.", signer) == embed("Hello world.", signer, DISCLOSURE, context=context)


#: A moment expressed relative to the leaf whose window is under test, rather than as a
#: literal. The endpoint cases have to be EXACTLY ``notBefore`` and ``notAfter``, and a
#: literal date here would be this test reimplementing the fixture's constants -- it
#: would keep passing after the fixture moved, testing nothing.
_Moment = Callable[[x509.Certificate], datetime.datetime]

_TICK = datetime.timedelta(microseconds=1)


#: Annotated so pyright can type the lambdas: it does not infer a lambda's parameter
#: from the position it is passed into, and an unannotated list here is `Unknown`.
_WINDOW_CASES: list[tuple[_Moment, bool]] = [
    (lambda _leaf: WHEN, True),
    (lambda leaf: leaf.not_valid_before_utc, True),
    (lambda leaf: leaf.not_valid_after_utc, True),
    (lambda leaf: leaf.not_valid_before_utc - _TICK, False),
    (lambda leaf: leaf.not_valid_after_utc + _TICK, False),
    (lambda _leaf: datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc), False),
    (lambda _leaf: datetime.datetime(2047, 6, 1, tzinfo=datetime.timezone.utc), False),
]


@pytest.mark.parametrize(
    ("moment", "ok"),
    _WINDOW_CASES,
    ids=[
        "inside",
        "on-notBefore",
        "on-notAfter",
        "one-tick-before-notBefore",
        "one-tick-after-notAfter",
        "before-notBefore",
        "after-notAfter",
    ],
)
def test_embed_refuses_to_sign_with_a_credential_outside_its_validity(
    signer: Signer, moment: _Moment, ok: bool
) -> None:
    """A mark signed with an expired credential is BORN INVALID, and signed bytes cannot
    be recalled.

    Expiry is the one property of a credential that changes with time, so it is checked
    at SIGN TIME against ``EmbedContext.when`` rather than at ``Signer`` construction:
    nothing reconstructs a Signer, and a service holding one across its leaf's expiry
    emitted invalid marks silently. Judging against ``when`` also keeps ``embed`` a pure
    function of its arguments.

    THE ENDPOINTS ARE INCLUSIVE (RFC 5280 4.1.2.5), and the two ``on-`` rows hold that.
    This ran with 2025 and 2047 against a 2026-2046 leaf -- months clear of either edge
    -- so ``<=`` could become ``<`` and nothing failed. The verifier side is pinned by
    ``test_the_validity_window_includes_its_own_endpoints``; the two disagreeing about
    one instant would refuse to issue a mark that would have verified.
    """
    when = moment(signer.certificates[0])
    context = EmbedContext(manifest_uuid=uuid.UUID(int=7), instance_id="xmp:iid:pinned", when=when)

    if ok:
        assert extract(embed("Hello world.", signer, DISCLOSURE, context=context)) is not None
        return

    with pytest.raises(ValueError, match="validity"):
        embed("Hello world.", signer, DISCLOSURE, context=context)
