# pyright: reportPrivateUsage=false
"""Extraction-layer tests: parse without verification; absence returns ``None``."""

from __future__ import annotations

import dataclasses
import datetime
import uuid

import pytest

from c2patxt import Provenance, _cbor, _jumbf, verify
from c2patxt._extract import _reparse, extract, parse_manifest_store
from c2patxt._jumbf import parse_superbox
from c2patxt._selectors import build_wrapper
from c2patxt.exceptions import C2paTextError, MarkCorruptError
from c2patxt.manifest import (
    ASSERTION_ACTIONS,
    ASSERTION_METADATA,
    LABEL_ASSERTION_STORE,
    LABEL_CLAIM,
    LABEL_CLAIM_SIGNATURE,
    UUID_MANIFEST,
    build_manifest_store,
    content_type_uuid,
)
from c2patxt.signing import Disclosure, ModelType, Signer
from c2patxt.status import StatusCode
from tests.conftest import mark

WHEN = datetime.datetime(2026, 8, 5, 12, 0, tzinfo=datetime.timezone.utc)
_UNKNOWN_STRUCTURAL_UUID = content_type_uuid(b"c2tm")
_EMBEDDED_FILE_UUID = bytes.fromhex("40CB0C32BB8A489DA70B2AD6F47F4369")
_LEGACY_MANIFEST_UUID = bytes.fromhex("63326D6400110010800000AA00389B71")


def _retype_required_structure(raw: bytes, target: str) -> bytes:
    """Change one structural UUID without changing its label or payload."""
    store, _ = parse_superbox(raw)
    if target == "store":
        return _jumbf.serialize_superbox(
            dataclasses.replace(
                store,
                description=dataclasses.replace(store.description, uuid=_UNKNOWN_STRUCTURAL_UUID),
            )
        )

    manifest, _ = _reparse(store.content[0][1])
    if target == "manifest":
        manifest = dataclasses.replace(
            manifest,
            description=dataclasses.replace(manifest.description, uuid=_UNKNOWN_STRUCTURAL_UUID),
        )
    else:
        found = False
        rebuilt: list[tuple[bytes, bytes]] = []
        for tbox, payload in manifest.content:
            child, _ = _reparse(payload)
            if child.description.label == target:
                child = dataclasses.replace(
                    child,
                    description=dataclasses.replace(child.description, uuid=_UNKNOWN_STRUCTURAL_UUID),
                )
                found = True
            rebuilt.append((tbox, _jumbf.serialize_superbox(child)[8:]))
        assert found, f"fixture carries no structural box labelled {target!r}"
        manifest = dataclasses.replace(manifest, content=tuple(rebuilt))

    return _jumbf.serialize_superbox(
        dataclasses.replace(
            store,
            content=((_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(manifest)[8:]),),
        )
    )


def _clear_requestable(raw: bytes, target_label: str) -> bytes:
    """Clear one description's Requestable toggle without changing its label."""

    def rewrite(box: _jumbf.JumbfBox) -> _jumbf.JumbfBox:
        description = box.description
        if description.label == target_label:
            description = dataclasses.replace(description, requestable=False)
        content: list[tuple[bytes, bytes]] = []
        for tbox, payload in box.content:
            if tbox == _jumbf.TBOX_SUPERBOX:
                child, _ = _reparse(payload)
                child_payload = _jumbf.serialize_superbox(rewrite(child))[8:]
            else:
                child_payload = payload
            content.append((tbox, child_payload))
        return dataclasses.replace(box, description=description, content=tuple(content))

    store, _ = parse_superbox(raw)
    return _jumbf.serialize_superbox(rewrite(store))


def _replace_assertion_content(raw: bytes, label: str, content: tuple[tuple[bytes, bytes], ...]) -> bytes:
    """Replace one assertion's content boxes while preserving the public wire shape."""
    store, _ = parse_superbox(raw)
    manifest, _ = _reparse(store.content[0][1])
    found = False
    manifest_content: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_ASSERTION_STORE:
            assertions: list[tuple[bytes, bytes]] = []
            for assertion_tbox, assertion_payload in child.content:
                assertion, _ = _reparse(assertion_payload)
                if assertion.description.label == label:
                    assertion = dataclasses.replace(assertion, content=content)
                    found = True
                assertions.append((assertion_tbox, _jumbf.serialize_superbox(assertion)[8:]))
            child = dataclasses.replace(child, content=tuple(assertions))
        manifest_content.append((tbox, _jumbf.serialize_superbox(child)[8:]))
    assert found, f"fixture carries no assertion labelled {label!r}"
    manifest = dataclasses.replace(manifest, content=tuple(manifest_content))
    store = dataclasses.replace(
        store,
        content=((_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(manifest)[8:]),),
    )
    return _jumbf.serialize_superbox(store)


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
        manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000001"),
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
        manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000002"),
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


def test_bytes_after_the_outer_manifest_store_are_rejected(signer: Signer) -> None:
    """A.8.2: manifestLength contains one complete C2PA Manifest Store."""
    original = mark("Hello world.", signer)
    store = extract(original)
    assert store is not None
    forged = "Hello world." + build_wrapper(store.raw + b"JUNK")

    with pytest.raises(MarkCorruptError, match="Manifest Store ends at byte"):
        extract(forged)

    verdict = verify(forged)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.TEXT_CORRUPTED_WRAPPER in verdict.codes()


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

    Two manifests use distinct labels; the last one must be returned.
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
    """15.10.3.1: "If the content of a standard assertion is not well-formed CBOR or is
    non-conforming JSON, the claim shall be rejected with a failure code of
    `assertion.cbor.invalid` or `assertion.json.invalid`."

    15.11.3.3: "Locate the claim, as described in Locating and Validating the Claim. If
    unable to, reject claim with a `claim.missing` failure code."

    These inputs carry intact selector wrappers around invalid manifest content, so
    they use the claim- or assertion-specific code rather than the corrupted-wrapper
    code.

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


@pytest.mark.parametrize(
    ("type_uuid", "tag"),
    [(UUID_MANIFEST, b"c2ma"), (_LEGACY_MANIFEST_UUID, b"c2md")],
    ids=["c2ma", "c2md"],
)
def test_a_standard_manifest_is_accepted_under_either_type_uuid(
    signer: Signer,
    type_uuid: bytes,
    tag: bytes,
) -> None:
    """C2PA 11.2.2: "Manifest Consumers **shall** also accept standard C2PA Manifests
    specified with JUMBF type UUID 63326D64-0011-0010-8000-00AA00389B71 (`c2md`), but
    claim generators shall not create manifests with this JUMBF type UUID."

    A `shall` on the CONSUMER and a prohibition on the PRODUCER, which is why the two
    halves are asserted separately: we accept both on read and continue to emit `c2ma`.
    Rejecting a `c2md` manifest would make us the implementation that breaks on valid
    input.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import DescriptionBox, JumbfBox, parse_superbox

    original = extract(mark("Hello world.", signer))
    assert original is not None

    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])
    assert manifest.description.uuid == UUID_MANIFEST, "the producer emits c2ma"
    retyped = JumbfBox(
        description=DescriptionBox(
            uuid=type_uuid,
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

    marked = "Hello world." + build_wrapper(forged)
    parsed = extract(marked)
    assert parsed is not None
    verdict = verify(marked)

    assert parsed.manifest_label == original.manifest_label
    assert parsed.claim_bytes == original.claim_bytes
    assert verdict.state is Provenance.VALID
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("store", StatusCode.TEXT_CORRUPTED_WRAPPER),
        ("manifest", StatusCode.TEXT_CORRUPTED_WRAPPER),
        (LABEL_ASSERTION_STORE, StatusCode.ASSERTION_MISSING),
        (LABEL_CLAIM, StatusCode.CLAIM_MISSING),
        (LABEL_CLAIM_SIGNATURE, StatusCode.CLAIM_SIGNATURE_MISSING),
    ],
    ids=["store", "manifest", "assertion-store", "claim", "signature"],
)
def test_an_unknown_structural_uuid_is_not_dispatched_by_its_label(
    signer: Signer,
    target: str,
    expected: StatusCode,
) -> None:
    """C2PA 11.1.2 skips an unrecognized JUMBF type and its contents.

    Each mutation preserves the known label, payload and byte length, so the type UUID
    is the field that must prevent dispatch.
    """
    marked = mark("Hello world.", signer)
    original = extract(marked)
    assert original is not None
    assert verify(marked).state is Provenance.VALID

    forged = "Hello world." + build_wrapper(_retype_required_structure(original.raw, target))
    verdict = verify(forged)

    assert verdict.state is Provenance.INVALID
    assert expected in verdict.codes()


def test_an_unknown_manifest_type_cannot_shadow_a_known_manifest_label(signer: Signer) -> None:
    """Skipping happens before duplicate-label rejection under C2PA 11.1.2."""
    original = extract(mark("Hello world.", signer))
    assert original is not None
    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])
    unknown = dataclasses.replace(
        manifest,
        description=dataclasses.replace(manifest.description, uuid=_UNKNOWN_STRUCTURAL_UUID),
    )
    forged = _jumbf.serialize_superbox(
        dataclasses.replace(
            store,
            content=(
                (_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(unknown)[8:]),
                *store.content,
            ),
        )
    )

    parsed = parse_manifest_store(forged)

    assert parsed.claim_bytes == original.claim_bytes


@pytest.mark.parametrize("tag", [b"c2cm", b"c2um"], ids=["compressed", "update"])
def test_an_unsupported_last_c2pa_manifest_never_falls_back_to_an_older_one(signer: Signer, tag: bytes) -> None:
    """15.5.1 selects the last C2PA Manifest before its supported type is checked."""
    from c2patxt._jumbf import DescriptionBox, JumbfBox

    original = extract(mark("Hello world.", signer))
    assert original is not None
    store, _ = parse_superbox(original.raw)
    unsupported = JumbfBox(
        description=DescriptionBox(
            uuid=content_type_uuid(tag),
            label=f"urn:c2pa:{tag.decode('ascii')}",
            requestable=True,
        ),
        content=((b"cbor", b"\xa0"),),
    )
    forged = _jumbf.serialize_superbox(
        dataclasses.replace(
            store,
            content=(*store.content, (_jumbf.TBOX_SUPERBOX, _jumbf.serialize_superbox(unsupported)[8:])),
        )
    )

    with pytest.raises(MarkCorruptError, match=rf"active C2PA Manifest type {tag.decode('ascii')}") as caught:
        extract("Document." + build_wrapper(forged))
    assert caught.value.code is StatusCode.GENERAL_ERROR


@pytest.mark.parametrize(
    "target",
    ["c2pa", "urn:c2pa:00000000-0000-4000-8000-000000000007", ASSERTION_METADATA],
    ids=["manifest-store", "manifest", "assertion"],
)
def test_every_c2pa_description_sets_label_and_requestable(signer: Signer, target: str) -> None:
    """C2PA 11.1.4.1.2 requires both toggles throughout a C2PA Manifest."""
    original = extract(mark("Hello world.", signer))
    assert original is not None
    forged = _clear_requestable(original.raw, target)

    with pytest.raises(MarkCorruptError, match="Label Present and Requestable") as caught:
        parse_manifest_store(forged)
    assert caught.value.code is StatusCode.GENERAL_ERROR


@pytest.mark.parametrize(
    ("label", "uuid", "content", "expected"),
    [
        (
            "c2pa.icon",
            _EMBEDDED_FILE_UUID,
            ((b"bfdb", b"\x00image/svg+xml\x00"), (b"bidb", b"<svg/>")),
            None,
        ),
        ("c2patxt.uuid", content_type_uuid(b"uuid"), ((b"uuid", b"\x00" * 16),), None),
        (
            "c2patxt.broken",
            _jumbf.UUID_CBOR,
            ((b"cbor", b"\xff"),),
            StatusCode.ASSERTION_CBOR_INVALID,
        ),
    ],
    ids=["embedded-file", "uuid", "broken-cbor"],
)
def test_an_assertion_may_carry_a_content_type_other_than_cbor(
    signer: Signer,
    label: str,
    uuid: bytes,
    content: tuple[tuple[bytes, bytes], ...],
    expected: StatusCode | None,
) -> None:
    """C2PA 11.1.4 permits standard assertion content types beyond CBOR.

    "The JUMBF Content Type ... box(es) contained in each assertion
    superbox **should be CBOR Content Type (`cbor`), JSON Content Type (`json`),
    Embedded File Content Type (`bfdb` & `bidb`) or UUID Content Type (`uuid`)** though
    any Content Type defined in JUMBF ... is permitted."

    Every content type retains its raw bytes for hashed-URI and undeclared-assertion
    checks. Only known CBOR/JSON content is decoded. The malformed-CBOR row remains a
    15.10.3.1 rejection.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import DescriptionBox, JumbfBox, parse_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE

    original = extract(mark("Hello world.", signer))
    assert original is not None
    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])

    extra = JumbfBox(description=DescriptionBox(uuid=uuid, label=label, requestable=True), content=content)
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

    A malformed JSON-LD ``c2pa.metadata`` assertion exists and hashes, so the precise
    result is ``assertion.json.invalid`` rather than ``assertion.missing``.
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
        ("c2pa.metadata", b"[1, 2, 3]", [1, 2, 3]),
        ("c2pa.metadata", b'[[1], {"a": 2.5}]', [[1], {"a": 2.5}]),
        ("c2pa.metadata", b'"a string"', "a string"),
        ("c2pa.metadata", b"NaN", StatusCode.ASSERTION_JSON_INVALID),
        ("c2pa.metadata", b"Infinity", StatusCode.ASSERTION_JSON_INVALID),
        ("c2pa.metadata", b"-Infinity", StatusCode.ASSERTION_JSON_INVALID),
        ("c2pa.metadata", b"{not json", StatusCode.ASSERTION_JSON_INVALID),
        ("c2pa.metadata__1", b'{"dc:format":"text/plain"}', {"dc:format": "text/plain"}),
        ("c2pa.metadata__22", b'{"dc:format":"text/plain"}', {"dc:format": "text/plain"}),
        ("c2pa.xmetadata", b'{"dc:format":"text/plain"}', None),
        ("c2pa.metadata__x", b'{"dc:format":"text/plain"}', None),
        ("c2pa.metadata_1", b'{"dc:format":"text/plain"}', None),
        ("c2pa.repository-receipt", b'{"@context": {}}', {"@context": {}}),
        ("c2pa.repository-receipt", b"{not json", StatusCode.ASSERTION_JSON_INVALID),
        ("c2patxt.notes", b"{not json", None),
        ("c2patxt.notes", b"[1, 2, 3]", None),
    ],
    ids=[
        "metadata-array",
        "metadata-nested-values",
        "metadata-string",
        "metadata-nan",
        "metadata-positive-infinity",
        "metadata-negative-infinity",
        "metadata-malformed",
        "metadata-instance-1",
        "metadata-instance-22",
        "not-metadata-without-dot",
        "not-metadata-nondigit-instance",
        "not-metadata-single-underscore",
        "receipt-object",
        "receipt-malformed",
        "other-malformed",
        "other-array",
    ],
)
def test_json_decoding_is_scoped_to_json_ld_assertion_labels(
    signer: Signer, label: str, payload: bytes, expected: object
) -> None:
    """Decode the standard JSON-LD assertions without imposing their producer schema.

    C2PA 15.10.3.1 points its ``assertion.json.invalid`` test at RFC 8259 clause 2.
    RFC 8259 defines a JSON text as any serialized JSON value, not only an object.
    C2PA Table 7 lists both metadata and repository receipts as JSON-LD.

    The custom ``c2patxt.notes`` rows hold the other boundary: 11.1.4 permits any
    content type in a custom assertion, so a JSON content box does not by itself make
    that assertion subject to a standard JSON-LD schema.
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
        description=DescriptionBox(uuid=_jumbf.UUID_JSON, label=label, requestable=True),
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

    if isinstance(expected, StatusCode):
        with pytest.raises(MarkCorruptError) as caught:
            parse_manifest_store(forged)
        assert caught.value.code is expected
        return

    parsed = parse_manifest_store(forged)
    if expected is None:
        assert label in parsed.assertion_bytes, "an assertion we do not decode is still hashable and linkable"
        assert label not in parsed.assertions
        return

    assert parsed.assertions[label] == expected


def test_extract_refuses_plural_text_without_selecting_a_manifest(signer: Signer) -> None:
    """Extraction has no signed exclusion context with which to select a wrapper.

    Verification applies 15.12.1.3.1 and may select one matching wrapper. Extraction
    exposes an unverified manifest, so plural input is ambiguous and refused.
    """
    first = mark("Hello world.", signer)
    second = mark("A different document.", signer)

    assert extract(first) is not None, "one wrapper still parses"

    with pytest.raises(MarkCorruptError) as caught:
        extract(first + second)

    assert caught.value.code is StatusCode.TEXT_MULTIPLE_WRAPPERS


@pytest.mark.parametrize(
    "content",
    [
        ((b"cbor", _cbor.dumps({"dc:format": "from-cbor"})),),
        (
            (b"cbor", _cbor.dumps({"dc:format": "from-cbor"})),
            (b"json", b'{"dc:format": "from-json"}'),
        ),
    ],
    ids=["cbor-only", "json-and-cbor"],
)
def test_a_metadata_assertion_requires_exactly_one_json_box(
    signer: Signer,
    content: tuple[tuple[bytes, bytes], ...],
) -> None:
    """C2PA 18.17.2 defines one JSON box, not a preferred box among many."""
    original = extract(mark("Hello world.", signer))
    assert original is not None
    forged = _replace_assertion_content(original.raw, ASSERTION_METADATA, content)

    with pytest.raises(MarkCorruptError) as caught:
        parse_manifest_store(forged)
    assert caught.value.code is StatusCode.ASSERTION_JSON_INVALID


def test_duplicate_content_boxes_are_rejected_like_duplicate_labels(signer: Signer) -> None:
    """``_children_with_bytes`` rejects two boxes under one LABEL, and says why:
    "a third-party JUMBF reader may take the FIRST box where we took the last, so two
    conforming implementations would authenticate different content from identical
    bytes."

    That argument applies unchanged one level down, and ``_content`` resolved duplicate
    CONTENT boxes first-wins. Two cbor boxes in one assertion is the same ambiguity at
    a smaller scale, with the same consequence: the bytes hash identically and two
    readers extract different claims from them.
    """
    original = extract(mark("Hello world.", signer))
    assert original is not None
    forged = _replace_assertion_content(
        original.raw,
        ASSERTION_ACTIONS,
        ((b"cbor", b"\x01"), (b"cbor", b"\x02")),
    )
    with pytest.raises(MarkCorruptError, match="more than one"):
        parse_manifest_store(forged)
