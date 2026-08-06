# pyright: reportPrivateUsage=false
# Drives the private units directly. A mutation audit showed several of these guards
# were only ever exercised through a public entry point that another check answered
# first, so the guard itself could be deleted unnoticed.
"""extract(): parses, never verifies, and never raises on absence."""

from __future__ import annotations

import datetime
import uuid

import pytest

from c2patxt import _cbor
from c2patxt._extract import extract, parse_manifest_store
from c2patxt._selectors import build_wrapper
from c2patxt.exceptions import C2paTextError, MarkCorruptError
from c2patxt.manifest import (
    ASSERTION_ACTIONS,
    ASSERTION_AI_DISCLOSURE,
    ASSERTION_HASH_DATA,
    ASSERTION_METADATA,
    UUID_MANIFEST,
    build_manifest_store,
    content_type_uuid,
)
from c2patxt.signing import Disclosure, ModelType, Signer
from c2patxt.status import StatusCode
from tests.conftest import mark

WHEN = datetime.datetime(2026, 8, 5, 12, 0, tzinfo=datetime.timezone.utc)


def _store() -> bytes:
    return build_manifest_store(
        disclosure=Disclosure(
            media_type="text/plain",
            model_type=ModelType.GENERIC,
            model_name="test-model",
            model_identifier="pkg:generic/test-model@1",
        ),
        digest=bytes(range(32)),
        exclusion_start=11,
        exclusion_length=74,
        signature=b"\xaa" * 64,
        instance_id="xmp:iid:00000000-0000-4000-8000-000000000002",
        manifest_uuid=uuid.UUID(int=1),
        when=WHEN,
        generator_name="c2patxt",
    )


def _marked(prefix: str = "Hello world.") -> str:
    return prefix + build_wrapper(_store())


def test_unmarked_text_returns_none_and_never_raises() -> None:
    """Absence is the common case. A library that raises on it gets wrapped in
    a bare except, and a bare except is how real corruption gets swallowed."""
    assert extract("Just ordinary prose.") is None
    assert extract("") is None
    assert extract("﻿") is None


def test_round_trip_recovers_the_manifest() -> None:
    manifest = extract(_marked())
    assert manifest is not None
    assert manifest.manifest_label == f"urn:c2pa:{uuid.UUID(int=1)}"
    assert manifest.signature == b"\xaa" * 64
    assert set(manifest.assertions) == {
        ASSERTION_ACTIONS,
        ASSERTION_AI_DISCLOSURE,
        ASSERTION_METADATA,
        ASSERTION_HASH_DATA,
    }


def test_the_claim_carries_the_required_fields() -> None:
    """15.6.2: instanceID, signature, created_assertions, claim_generator_info."""
    manifest = extract(_marked())
    assert manifest is not None
    assert {"instanceID", "signature", "created_assertions", "claim_generator_info"} <= set(manifest.claim)


def test_the_hard_binding_is_reachable() -> None:
    manifest = extract(_marked())
    assert manifest is not None
    hash_data = manifest.hash_data
    assert hash_data is not None
    assert hash_data["alg"] == "sha256"
    assert hash_data["exclusions"] == [{"start": 11, "length": 74}]
    assert hash_data["pad"] == b"", "18.5.2 requires pad to be present"


def test_extraction_does_not_depend_on_position_in_the_text() -> None:
    for prefix in ("", "a", "café ", "漢字 ", "x" * 1000):
        manifest = extract(_marked(prefix))
        assert manifest is not None, f"failed for prefix {prefix[:10]!r}"


def test_the_raw_bytes_are_preserved_for_re_verification() -> None:
    """Verification must not have to re-encode, which could change the bytes."""
    manifest = extract(_marked())
    assert manifest is not None
    assert manifest.raw == _store()


def test_extract_performs_no_verification() -> None:
    """A garbage signature must still parse. That is the whole point of the split.

    Someone inspecting a manifest that FAILED verification -- to see which
    certificate signed it -- must not have to bypass the library.
    """
    store = build_manifest_store(
        disclosure=Disclosure(media_type="text/plain", model_type=ModelType.GENERIC),
        digest=bytes(32),
        exclusion_start=0,
        exclusion_length=1,
        signature=b"\x00" * 64,
        instance_id="xmp:iid:1",
        manifest_uuid=uuid.UUID(int=2),
        when=WHEN,
        generator_name="c2patxt",
    )
    manifest = extract("x" + build_wrapper(store))
    assert manifest is not None
    assert manifest.signature == b"\x00" * 64


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not jumbf at all",
        b"\x00\x00\x00\x08jumb",
    ],
)
def test_a_malformed_manifest_raises_rather_than_returning_none(payload: bytes) -> None:
    """A matched magic asserts intent, so a broken manifest is a real failure --
    distinct from absence, which returns None."""
    with pytest.raises(MarkCorruptError):
        extract("x" + build_wrapper(payload))


def test_the_error_is_catchable_as_the_package_root() -> None:
    with pytest.raises(C2paTextError):
        parse_manifest_store(b"not jumbf")


def test_a_store_without_a_claim_is_rejected() -> None:
    """15.6: a manifest with no claim box cannot be validated."""
    from c2patxt._jumbf import DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import UUID_MANIFEST, UUID_MANIFEST_STORE

    manifest = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST, label="urn:uuid:x"),
        content=((b"cbor", b"\x01"),),
    )
    store = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label="c2pa"),
        content=((b"jumb", serialize_superbox(manifest)[8:]),),
    )
    with pytest.raises(MarkCorruptError, match=r"no c2pa\.claim\.v2 box"):
        parse_manifest_store(serialize_superbox(store))


def test_a_store_with_no_manifest_is_rejected() -> None:
    from c2patxt._jumbf import DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import UUID_MANIFEST_STORE

    store = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label="c2pa"),
        content=((b"cbor", b"\x01"),),
    )
    with pytest.raises(MarkCorruptError, match="no manifest"):
        parse_manifest_store(serialize_superbox(store))


def _store_with(*, claim: bytes | None, signature: bytes | None, extra: bytes | None = None) -> bytes:
    """Build a manifest with individual boxes present or absent, for the error paths."""
    from c2patxt._jumbf import DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import (
        LABEL_CLAIM,
        LABEL_CLAIM_SIGNATURE,
        UUID_CLAIM,
        UUID_CLAIM_SIGNATURE,
        UUID_MANIFEST,
        UUID_MANIFEST_STORE,
    )

    parts: list[tuple[bytes, bytes]] = []
    if claim is not None:
        box = JumbfBox(
            description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
            content=((b"cbor", claim) if extra is None else (b"json", extra),),
        )
        parts.append((b"jumb", serialize_superbox(box)[8:]))
    if signature is not None:
        box = JumbfBox(
            description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
            content=((b"cbor", signature),),
        )
        parts.append((b"jumb", serialize_superbox(box)[8:]))
    if not parts:
        parts.append((b"cbor", b"\x01"))

    manifest = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST, label="urn:uuid:x"),
        content=tuple(parts),
    )
    store = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label="c2pa"),
        content=((b"jumb", serialize_superbox(manifest)[8:]),),
    )
    return serialize_superbox(store)


def test_a_claim_box_without_cbor_content_is_rejected() -> None:
    """The claim is CBOR (10.1); a claim box holding something else is malformed."""
    with pytest.raises(MarkCorruptError, match="no cbor content box"):
        parse_manifest_store(_store_with(claim=b"", signature=b"\xaa" * 64, extra=b"{}"))


def test_a_manifest_without_a_signature_box_is_rejected() -> None:
    from c2patxt import _cbor

    with pytest.raises(MarkCorruptError, match=r"no c2pa\.signature box"):
        parse_manifest_store(_store_with(claim=_cbor.dumps({"a": 1}), signature=None))


def test_a_claim_that_is_not_a_map_is_rejected() -> None:
    """10.2.1 defines the claim as a CBOR map; an array is not a claim."""
    from c2patxt import _cbor

    with pytest.raises(MarkCorruptError, match="not a CBOR map"):
        parse_manifest_store(_store_with(claim=_cbor.dumps([1, 2, 3]), signature=b"\xaa" * 64))


def test_non_superbox_children_are_skipped_when_collecting_labels() -> None:
    """A manifest may carry plain content boxes alongside nested superboxes."""
    from c2patxt import _cbor

    manifest = extract("x" + build_wrapper(_store_with(claim=_cbor.dumps({"a": 1}), signature=b"\xbb" * 64)))
    assert manifest is not None
    assert manifest.signature == b"\xbb" * 64
    assert manifest.assertions == {}, "no assertion store present"


def test_the_last_manifest_in_the_store_is_the_active_one() -> None:
    """C2PA 15.5.2.1: "The last C2PA Manifest superbox in the C2PA Manifest Store
    superbox shall be considered the active manifest."

    A sixteen-line comment in ``_extract`` justifies following that rule, and a
    mutation audit changed ``list(manifests)[-1]`` to ``[0]`` without a single test
    noticing. The rule is what makes plural manifests DETERMINISTIC -- every
    conforming consumer picks the same one -- which is the entire argument for
    following it rather than rejecting.

    Two manifests under DIFFERENT labels, since duplicates are refused outright.
    """
    import dataclasses

    from c2patxt import _jumbf
    from c2patxt._extract import _reparse, parse_manifest_store
    from c2patxt._jumbf import JumbfBox, parse_superbox

    raw = _store()
    store, _ = parse_superbox(raw)
    first_payload = store.content[0][1]

    second, _ = _reparse(first_payload)
    renamed = dataclasses.replace(
        second, description=dataclasses.replace(second.description, label="urn:c2pa:" + "0" * 36)
    )

    doubled = _jumbf.serialize_superbox(
        JumbfBox(
            description=store.description,
            content=(
                *store.content,
                (_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(renamed)[8:]),
            ),
        )
    )

    assert parse_manifest_store(doubled).manifest_label == "urn:c2pa:" + "0" * 36
    assert parse_manifest_store(raw).manifest_label != "urn:c2pa:" + "0" * 36


@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        ("assertion-cbor", StatusCode.ASSERTION_CBOR_INVALID),
        ("no-claim-box", StatusCode.CLAIM_MISSING),
        ("claim-box-no-content", StatusCode.CLAIM_MISSING),
    ],
    ids=["assertion-cbor", "no-claim-box", "claim-box-no-content"],
)
def test_the_parse_reports_the_code_the_clause_names(signer: Signer, damage: str, expected: StatusCode) -> None:
    """Three parse failures that all reported ``manifest.text.corruptedWrapper``.

    15.10.3.1: "If the content of a standard assertion is not well-formed CBOR or is
    non-conforming JSON, the claim shall be rejected with a failure code of
    `assertion.cbor.invalid` or `assertion.json.invalid`."

    15.11.3.3: "Locate the claim, as described in Locating and Validating the Claim. If
    unable to, reject claim with a `claim.missing` failure code."

    ``manifest.text.corruptedWrapper`` is 15.12.1.3.2's code for a wrapper with an
    "invalid version, algorithm, or manifest length" -- damage to the SELECTOR RUN
    carrying the manifest. Every one of these three is a perfectly intact wrapper
    around a manifest that is wrong INSIDE. Reporting the carrier's code sends an
    investigator hunting for text corruption that is not there, which is exactly the
    substitution ``MarkCorruptError``'s overridable ``code`` parameter exists to
    prevent, and the same one already fixed for the claim's own CBOR.

    ``claim-box-no-content`` is the case a presence check alone would miss: the
    ``c2pa.claim`` box is right there, correctly labelled, and holds a ``json`` content
    box where the claim's CBOR should be. The claim still cannot be located, which is
    what 15.11.1 keys on. It carries SOMETHING because JUMBF requires a superbox to
    hold at least one content box, so a genuinely empty box cannot be built at all.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse, parse_manifest_store
    from c2patxt._jumbf import JumbfBox, parse_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE, LABEL_CLAIM

    original = extract(mark("Hello world.", signer))
    assert original is not None
    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])

    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        label = child.description.label
        if damage == "no-claim-box" and label == LABEL_CLAIM:
            continue
        if damage == "claim-box-no-content" and label == LABEL_CLAIM:
            # A json box rather than none at all: JUMBF requires a superbox to hold at
            # least one content box, so "carries no cbor" is the reachable shape.
            child = JumbfBox(description=child.description, content=((b"json", b"{}"),))
        if damage == "assertion-cbor" and label == LABEL_ASSERTION_STORE:
            first, _ = _reparse(child.content[0][1])
            # 0xff is the CBOR "break" byte: never a valid top-level item.
            broken = JumbfBox(description=first.description, content=((b"cbor", b"\xff"),))
            child = JumbfBox(
                description=child.description,
                content=((_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(broken)[8:]), *child.content[1:]),
            )
        rebuilt.append((tbox, _jumbf.serialize_superbox(child)[8:]))

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

    with pytest.raises(MarkCorruptError) as caught:
        parse_manifest_store(forged)
    assert caught.value.code is expected


@pytest.mark.parametrize("tag", [b"c2ma", b"c2md"], ids=["c2ma", "c2md"])
def test_a_standard_manifest_is_accepted_under_either_type_uuid(signer: Signer, tag: bytes) -> None:
    """C2PA 11.2.2: "Manifest Consumers **shall** also accept standard C2PA Manifests
    specified with JUMBF type UUID 63326D64-0011-0010-8000-00AA00389B71 (`c2md`), but
    claim generators shall not create manifests with this JUMBF type UUID."

    A `shall` on the CONSUMER and a prohibition on the PRODUCER, which is why the two
    halves are asserted separately: we accept both on read and continue to emit `c2ma`.
    Rejecting a `c2md` manifest would make us the implementation that breaks on valid
    input -- the defect class docs/known-divergences.md catalogues in five others.

    ``c2md`` is also one of the two box types docs/known-divergences.md records as
    MISSING from c2pa-rs. Being able to read it is the point of that entry.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import DescriptionBox, JumbfBox, parse_superbox

    original = extract(mark("Hello world.", signer))
    assert original is not None
    assert original.raw.count(UUID_MANIFEST) == 1, "the emitted manifest must be c2ma"

    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])
    retyped = JumbfBox(
        description=DescriptionBox(
            uuid=content_type_uuid(tag),
            label=manifest.description.label,
            requestable=manifest.description.requestable,
        ),
        content=manifest.content,
    )
    forged = _jumbf.serialize_superbox(
        JumbfBox(
            description=store.description,
            content=((_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(retyped)[8:]),),
        )
    )

    parsed = parse_manifest_store(forged)

    assert parsed.manifest_label == original.manifest_label
    assert parsed.claim_bytes == original.claim_bytes


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ((b"bfdb", b"image/svg+xml\x00"), None),
        ((b"bidb", b"<svg/>"), None),
        ((b"uuid", b"\x00" * 16), None),
        ((b"cbor", b"\xff"), StatusCode.ASSERTION_CBOR_INVALID),
    ],
    ids=["bfdb", "bidb", "uuid", "broken-cbor"],
)
def test_an_assertion_may_carry_a_content_type_other_than_cbor(
    signer: Signer, content: tuple[bytes, bytes], expected: StatusCode | None
) -> None:
    """C2PA 11.1.4: "The JUMBF Content Type ... box(es) contained in each assertion
    superbox **should be CBOR Content Type (`cbor`), JSON Content Type (`json`),
    Embedded File Content Type (`bfdb` & `bidb`) or UUID Content Type (`uuid`)** though
    any Content Type defined in JUMBF ... is permitted."

    WE REJECTED THE WHOLE STORE for anything but `cbor`, and at 2.4 that is not an edge
    case: the specification "replaced data boxes with embedded data assertions", so a
    claim generator's **icon** now lives in a `bfdb`/`bidb` assertion. The 15.10.3.3
    reference validation added for exactly that icon could therefore never reach its
    match path -- the box it points at was unparseable before verification began.

    THE #58 GUARD IS NOT REOPENED, and that is the whole design of this change. The
    smuggling hole it closed was that a non-`cbor` box vanished from
    ``assertion_bytes``, so the "every assertion is linked by the claim" comparison
    never saw it. Here every assertion keeps its RAW BYTES whatever its content type --
    so the undeclared check still sees it, and the hashed URI still authenticates it --
    and only the DECODED VALUE is omitted, because there is nothing generic to decode.
    Hashing operates on bytes and never needed the decode.

    ``broken-cbor`` is the control: a box that CLAIMS to be CBOR and is not stays a
    rejection, with 15.10.3.1's code.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import DescriptionBox, JumbfBox, parse_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE

    label = "c2patxt.embedded"
    original = extract(mark("Hello world.", signer))
    assert original is not None
    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])

    extra = JumbfBox(
        description=DescriptionBox(uuid=_jumbf.UUID_CBOR, label=label, requestable=True), content=(content,)
    )
    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_ASSERTION_STORE:
            child = JumbfBox(
                description=child.description,
                content=(*child.content, (_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(extra)[8:])),
            )
        rebuilt.append((tbox, _jumbf.serialize_superbox(child)[8:]))

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

    if expected is not None:
        with pytest.raises(MarkCorruptError) as caught:
            parse_manifest_store(forged)
        assert caught.value.code is expected
        return

    parsed = parse_manifest_store(forged)

    assert label in parsed.assertion_bytes, "an undecodable assertion must still be hashable and linkable"
    assert label not in parsed.assertions, "there is nothing generic to decode from a non-CBOR payload"


def test_malformed_json_in_a_metadata_assertion_gets_the_json_code(signer: Signer) -> None:
    """C2PA 15.10.3.1: "If the content of a standard assertion is not well-formed CBOR
    **or is non-conforming JSON**, the claim shall be rejected with a failure code of
    `assertion.cbor.invalid` **or `assertion.json.invalid`**."

    The CBOR half landed and the JSON half did not, so malformed JSON-LD in
    `c2pa.metadata` -- the one assertion 18.17.2 requires to be JSON rather than CBOR --
    reported `assertion.missing`, which says the store lacks an assertion the claim
    named. The store has it; it does not parse.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import JumbfBox, parse_superbox
    from c2patxt.manifest import ASSERTION_METADATA, LABEL_ASSERTION_STORE

    original = extract(mark("Hello world.", signer))
    assert original is not None
    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])

    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_ASSERTION_STORE:
            widened: list[tuple[bytes, bytes]] = []
            for inner_tbox, inner in child.content:
                box, _ = _reparse(inner)
                if box.description.label == ASSERTION_METADATA:
                    box = JumbfBox(description=box.description, content=((b"json", b"{not json"),))
                    widened.append((inner_tbox, _jumbf.serialize_superbox(box)[8:]))
                else:
                    widened.append((inner_tbox, inner))
            child = JumbfBox(description=child.description, content=tuple(widened))
        rebuilt.append((tbox, _jumbf.serialize_superbox(child)[8:]))

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

    with pytest.raises(MarkCorruptError) as caught:
        parse_manifest_store(forged)
    assert caught.value.code is StatusCode.ASSERTION_JSON_INVALID


@pytest.mark.parametrize(
    ("label", "payload", "expected"),
    [
        ("c2pa.metadata", b"[1, 2, 3]", StatusCode.ASSERTION_JSON_INVALID),
        ("c2pa.metadata", b'"a string"', StatusCode.ASSERTION_JSON_INVALID),
        ("c2pa.metadata", b"{not json", StatusCode.ASSERTION_JSON_INVALID),
        ("c2patxt.notes", b"{not json", None),
        ("c2patxt.notes", b"[1, 2, 3]", None),
    ],
    ids=["metadata-array", "metadata-string", "metadata-malformed", "other-malformed", "other-array"],
)
def test_json_decoding_is_scoped_to_metadata_labels(
    signer: Signer, label: str, payload: bytes, expected: StatusCode | None
) -> None:
    """Two rules in one table, because they are two halves of the same decision.

    C2PA 18.17.2 requires ``c2pa.metadata`` to carry JSON-LD, and 15.10.3.1 names
    ``assertion.json.invalid`` for content that "is non-conforming JSON". A payload that
    is well-formed JSON but not an OBJECT is non-conforming: the clause's CDDL and
    18.17.2's "JSON-LD serialization of one or more metadata values" both require a map.
    Returning ``None`` for it -- as the code did under mutation -- leaves the assertion
    with its raw bytes recorded, so the hashed URI still authenticates it and the
    undeclared check still clears it, and the manifest verifies with an assertion
    NOTHING DECODED. That mutation survived the whole suite.

    THE SCOPING IS THE OTHER HALF, and it was equally unheld. ``_json_ld_assertion``'s
    docstring calls the ``.metadata`` restriction deliberate and "NOT widened to 'any
    json box'", and dropping it also survived the whole suite -- a non-metadata
    assertion carrying malformed JSON would start being rejected as
    ``assertion.json.invalid`` where it should simply be an assertion we do not decode.
    11.1.4 permits any JUMBF content type in an assertion, and #89 made us record raw
    bytes for all of them; deciding that one of them must ALSO be valid JSON would
    re-narrow what that change deliberately widened.

    The two ``c2patxt.notes`` rows are what make this a scoping test rather than a JSON
    test: identical bytes, different label, opposite outcome.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import DescriptionBox, JumbfBox, parse_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE

    original = extract(mark("Hello world.", signer))
    assert original is not None
    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])

    replacement = JumbfBox(
        description=DescriptionBox(uuid=_jumbf.UUID_CBOR, label=label, requestable=True),
        content=((b"json", payload),),
    )
    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, box_payload in manifest.content:
        child, _ = _reparse(box_payload)
        if child.description.label == LABEL_ASSERTION_STORE:
            kept = [
                (inner_tbox, inner)
                for inner_tbox, inner in child.content
                if _reparse(inner)[0].description.label != label
            ]
            child = JumbfBox(
                description=child.description,
                content=(*kept, (_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(replacement)[8:])),
            )
        rebuilt.append((tbox, _jumbf.serialize_superbox(child)[8:]))

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

    if expected is None:
        parsed = parse_manifest_store(forged)
        assert label in parsed.assertion_bytes, "an assertion we do not decode is still hashable and linkable"
        assert label not in parsed.assertions
        return

    with pytest.raises(MarkCorruptError) as caught:
        parse_manifest_store(forged)
    assert caught.value.code is expected


def test_extract_refuses_multi_wrapper_text_as_verify_does(signer: Signer) -> None:
    """``extract`` used to return the FIRST wrapper's manifest on multi-wrapper text,
    with no error and no signal. It now refuses, and the reversal is deliberate.

    THE DEVIATION ENTRY ARGUES AGAINST THE OLD BEHAVIOUR IN ITS OWN WORDS. Recording why
    we reject plural wrappers where 15.12.1.3.1 would only reject those matching the
    exclusions, it says the permissive reading "lets an attacker append a wrapper and
    choose which one a given consumer reads, and 'different verifiers disagree about
    which claim applies' is exactly the failure a provenance format cannot have". An
    attacker appends the SECOND wrapper, so they choose what is FIRST by choosing what to
    prepend -- and an integrator calling ``extract`` to render "who signed this" got
    their manifest.

    I ARGUED THE OTHER WAY EARLIER TODAY: that ``extract`` performs no validation, that
    multiple wrappers is a validation verdict rather than a parse failure, and that a
    caller inspecting a suspicious document should be able to see what is in it. The
    last point stands and is served by ``locate``, which returns a SPAN rather than a
    manifest and documents its first-wrapper choice. The rest does not survive the
    deviation's own reasoning: handing back attacker-chosen provenance silently is not a
    lesser evil than refusing.

    ``manifest.text.multipleWrappers`` rather than the carrier's corruption code: the
    wrapper decoded perfectly and there are simply two of them, which is what that code
    exists to say. It is the same code ``verify`` reports, so the two entry points now
    agree about this input instead of disagreeing.
    """
    first = mark("Hello world.", signer)
    second = mark("A different document.", signer)

    assert extract(first) is not None, "one wrapper still parses"

    with pytest.raises(MarkCorruptError) as caught:
        extract(first + second)

    assert caught.value.code is StatusCode.TEXT_MULTIPLE_WRAPPERS


def test_a_metadata_assertion_carrying_both_box_types_reads_the_json_one() -> None:
    """18.17.2: the metadata assertion "shall contain a single JSON content type box".

    ``_parse_assertions`` tried ``cbor`` first for every assertion, so a
    ``c2pa.metadata`` carrying BOTH a cbor and a json box decoded as CBOR -- while a
    peer following 18.17.2 reads the JSON one. Identical bytes, different content, both
    hash-matching, and no code raised by either side. That is the worst shape an
    interoperability defect can take: two conforming readers disagreeing silently.

    A conforming producer emits one box. This decides which one wins when a
    non-conforming producer, or an attacker, emits two.
    """
    from c2patxt._extract import _parse_assertions
    from c2patxt._jumbf import UUID_CBOR, DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE, UUID_ASSERTION_STORE

    both = JumbfBox(
        description=DescriptionBox(uuid=UUID_CBOR, label="c2pa.metadata", requestable=True),
        content=((b"cbor", _cbor.dumps({"dc:format": "from-cbor"})), (b"json", b'{"dc:format": "from-json"}')),
    )
    store = JumbfBox(
        description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
        content=((b"jumb", serialize_superbox(both)[8:]),),
    )

    assertions, _raw = _parse_assertions(store)
    value = assertions["c2pa.metadata"]
    assert isinstance(value, dict)
    assert value["dc:format"] == "from-json", "18.17.2 makes the metadata assertion JSON-LD"


def test_duplicate_content_boxes_are_rejected_like_duplicate_labels() -> None:
    """``_children_with_bytes`` rejects two boxes under one LABEL, and says why:
    "a third-party JUMBF reader may take the FIRST box where we took the last, so two
    conforming implementations would authenticate different content from identical
    bytes."

    That argument applies unchanged one level down, and ``_content`` resolved duplicate
    CONTENT boxes first-wins. Two cbor boxes in one assertion is the same ambiguity at
    a smaller scale, with the same consequence: the bytes hash identically and two
    readers extract different claims from them.
    """
    from c2patxt._extract import _content
    from c2patxt._jumbf import UUID_CBOR, DescriptionBox, JumbfBox

    box = JumbfBox(
        description=DescriptionBox(uuid=UUID_CBOR, label="c2pa.metadata", requestable=True),
        content=((b"cbor", b"\x01"), (b"cbor", b"\x02")),
    )
    with pytest.raises(MarkCorruptError, match="more than one"):
        _content(box, b"cbor")
