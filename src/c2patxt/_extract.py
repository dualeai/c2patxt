"""
``extract``: parse the manifest store out of marked text.

This PARSES. It does not verify. An extracted manifest is attacker-controlled data,
and the split exists so that someone can inspect a manifest that failed verification
-- to see which certificate signed it, or why a hash mismatched -- without having to
bypass the library to do it. If ``extract`` ever starts returning something a caller
could mistake for a verified result, the design has drifted.

Absence is never an exception. Most text ever written is unmarked; a library that
raises on the common case is one people wrap in a bare ``except``, and a bare
``except`` is how a genuine corruption gets swallowed.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from c2patxt import _cbor, _jumbf
from c2patxt._jumbf import JumbfBox, JumbfError, parse_superbox
from c2patxt._locate import find_wrappers
from c2patxt.exceptions import MarkCorruptError
from c2patxt.manifest import (
    ASSERTION_REPOSITORY_RECEIPT,
    LABEL_ASSERTION_STORE,
    LABEL_CLAIM,
    LABEL_CLAIM_SIGNATURE,
    LABEL_MANIFEST_STORE,
    UUID_ASSERTION_STORE,
    UUID_CLAIM,
    UUID_CLAIM_SIGNATURE,
    UUID_MANIFEST,
    UUID_MANIFEST_STORE,
    ManifestStore,
)
from c2patxt.status import StatusCode

_SUPERBOX_HEADER = 8
_UUID_LEGACY_MANIFEST = _jumbf.content_type_uuid(b"c2md")
_UUID_COMPRESSED_MANIFEST = _jumbf.content_type_uuid(b"c2cm")
_UUID_UPDATE_MANIFEST = _jumbf.content_type_uuid(b"c2um")
_STANDARD_MANIFEST_UUIDS = frozenset((UUID_MANIFEST, _UUID_LEGACY_MANIFEST))
_C2PA_MANIFEST_UUIDS = frozenset((*_STANDARD_MANIFEST_UUIDS, _UUID_COMPRESSED_MANIFEST, _UUID_UPDATE_MANIFEST))
_MANIFEST_PART_UUIDS = {
    LABEL_ASSERTION_STORE: UUID_ASSERTION_STORE,
    LABEL_CLAIM: UUID_CLAIM,
    LABEL_CLAIM_SIGNATURE: UUID_CLAIM_SIGNATURE,
}


def _reparse(payload: bytes) -> tuple[JumbfBox, int]:
    """Re-wrap a nested superbox payload with a header so it can be parsed.

    ``_jumbf`` keeps nested superboxes opaque so it stays a pure box codec; the
    length is recomputed here rather than trusted from the parent.
    """
    header = (_SUPERBOX_HEADER + len(payload)).to_bytes(4, "big") + _jumbf.TBOX_SUPERBOX
    return parse_superbox(header + payload)


def _require_c2pa_description(box: JumbfBox, what: str) -> str:
    """Return the label after requiring both C2PA description toggles."""
    label = box.description.label
    if label is not None and box.description.requestable:
        return label
    msg = f"{what} must set both the JUMBF Label Present and Requestable toggles"
    raise MarkCorruptError(msg, 0, code=StatusCode.GENERAL_ERROR)


def _children(
    box: JumbfBox,
    what: str,
    recognizes: Callable[[JumbfBox], bool] | None = None,
) -> dict[str, JumbfBox]:
    """Parse recognized nested superboxes, keyed by label.

    C2PA 11.1.2 requires a consumer to skip the contents of an unrecognized JUMBF
    type. Recognition therefore happens before duplicate-label handling: an unknown
    future box cannot shadow a known structural box merely by copying its label.
    """
    return {label: child for label, (child, _) in _children_with_bytes(box, what, recognizes=recognizes).items()}


def _children_with_bytes(
    box: JumbfBox,
    what: str,
    *,
    recognizes: Callable[[JumbfBox], bool] | None = None,
) -> dict[str, tuple[JumbfBox, bytes]]:
    """As :func:`_children`, but keeping each child's RAW hashable bytes.

    The bytes are the nested superbox payload -- the serialized box with its own
    LBox+TBox stripped -- which is exactly what C2PA 8.4.2.3 hashes. They must be
    carried through from the parse rather than re-serialized later: re-serializing
    would hash OUR encoding of the box, not the bytes that actually arrived, and an
    attacker who can make those two differ can substitute an assertion at will.

    A duplicate label inside one structural map is rejected, not overwritten. Otherwise
    a later assertion or claim box could silently replace the bytes the signed links
    name. Manifest-store selection is handled separately by 15.5.1, before this helper.
    """
    out: dict[str, tuple[JumbfBox, bytes]] = {}
    for tbox, payload in box.content:
        if tbox != _jumbf.TBOX_SUPERBOX:
            continue
        child, _ = _reparse(payload)
        label = _require_c2pa_description(child, f"a child of {what}")
        if recognizes is not None and not recognizes(child):
            continue
        if label in out:
            msg = f"{what} contains more than one box labelled {label!r}"
            if label == LABEL_CLAIM:
                code = StatusCode.CLAIM_MULTIPLE
            elif what == "the assertion store":
                # 8.4.1 makes a duplicated assertion-label path unresolved. It is not
                # a second claim box, so 15.6.1's claim.multiple does not apply.
                code = StatusCode.ASSERTION_MISSING
            else:
                code = StatusCode.GENERAL_ERROR
            raise MarkCorruptError(msg, 0, code=code)
        out[label] = (child, payload)
    return out


def _is_standard_manifest(box: JumbfBox) -> bool:
    """Recognize the current and legacy Standard Manifest UUIDs from 11.2.2."""
    return box.description.uuid in _STANDARD_MANIFEST_UUIDS


def _is_c2pa_manifest(box: JumbfBox) -> bool:
    """Recognize every C2PA Manifest type that participates in active selection."""
    return box.description.uuid in _C2PA_MANIFEST_UUIDS


def _is_manifest_part(box: JumbfBox) -> bool:
    """Recognize a structural manifest child by both its label and type UUID."""
    label = box.description.label
    return label is not None and _MANIFEST_PART_UUIDS.get(label) == box.description.uuid


def _active_manifest(store: JumbfBox) -> JumbfBox:
    """Select the last C2PA Manifest, then require a manifest type we implement."""
    manifest: JumbfBox | None = None
    for tbox, payload in store.content:
        if tbox != _jumbf.TBOX_SUPERBOX:
            continue
        child, _ = _reparse(payload)
        if not _is_c2pa_manifest(child):
            continue
        _require_c2pa_description(child, "a C2PA Manifest")
        manifest = child
    if manifest is None:
        msg = "manifest store contains no manifest"
        raise MarkCorruptError(msg, 0)

    # 15.5.1 selects the last C2PA Manifest before its type-specific validation.
    if not _is_standard_manifest(manifest):
        kind = manifest.description.uuid[:4].decode("ascii")
        msg = f"active C2PA Manifest type {kind} is not supported"
        raise MarkCorruptError(msg, 0, code=StatusCode.GENERAL_ERROR)
    return manifest


def _base_label(label: str) -> str:
    """Strip C2PA 6.4's ``__N`` instance suffix, if the label carries one.

    6.4: "Multiple assertions of the same type can occur in the same manifest... by
    adding a double-underscore and a monotonically increasing index to the label." So
    ``c2pa.metadata__1`` is a second metadata assertion, not a different type -- and a
    check written against the bare label misses every instance but the first.

    The suffix must be a double underscore followed by DIGITS. ``c2pa.metadata__x`` and
    ``c2pa.metadata_1`` are different assertions, and treating them as instances would
    accept manifests that are not conforming.
    """
    base, separator, index = label.rpartition("__")
    return base if separator and index.isdigit() else label


def _reject_json_constant(value: str) -> object:
    """Reject the non-finite number names accepted by Python but forbidden by JSON."""
    msg = f"{value} is not an RFC 8259 JSON number"
    raise ValueError(msg)


def _json_ld_assertion(box: JumbfBox, label: str) -> _cbor.CborValue | None:
    """Decode an assertion whose specified content type is JSON-LD.

    C2PA 18.17.2 requires each metadata assertion to contain exactly one JSON
    content box. Table 7 also defines ``c2pa.repository-receipt`` as JSON-LD. The
    ``__N`` suffix handling follows 6.4, while other custom JSON assertions remain
    opaque to this standard-assertion parser.

    Raises:
        MarkCorruptError: the JSON is not well-formed. It carries
            ``assertion.json.invalid``, which 15.10.3.1 names for non-conforming JSON.
            RFC 8259 defines a JSON text as any serialized JSON value, so arrays,
            strings, numbers, booleans and null are not rejected here as a schema
            check.
    """
    base = _base_label(label)
    if not base.endswith(".metadata") and base != ASSERTION_REPOSITORY_RECEIPT:
        return None
    if len(box.content) != 1 or box.content[0][0] != b"json":
        msg = f"assertion {label!r} must contain exactly one JSON content box"
        raise MarkCorruptError(msg, 0, code=StatusCode.ASSERTION_JSON_INVALID)
    payload = box.content[0][1]
    try:
        # json.loads without object hooks returns exactly the scalar/list/text-keyed
        # map union CborValue accepts. Traversing the full attacker tree again merely
        # to restate that stdlib contract would double the parse work.
        return json.loads(payload, parse_constant=_reject_json_constant)  # pyright: ignore[reportAny]
    except (RecursionError, ValueError) as exc:
        # 15.10.3.1 names a code for each serialization: "not well-formed CBOR or is
        # non-conforming JSON... assertion.cbor.invalid or assertion.json.invalid".
        # assertion.missing would say the store LACKS an assertion the claim named; the
        # store has it, and it does not parse.
        msg = f"assertion {label!r} is not well-formed JSON"
        raise MarkCorruptError(msg, 0, code=StatusCode.ASSERTION_JSON_INVALID) from exc


def _content(
    box: JumbfBox,
    tbox: bytes,
    *,
    duplicate_code: StatusCode = StatusCode.GENERAL_ERROR,
) -> bytes | None:
    """The single content box of type ``tbox``, or None if the box carries none.

    A duplicate is rejected rather than resolved first-wins because two content boxes
    of the same type leave no defined authenticated value.

    Raises:
        MarkCorruptError: the box carries more than one content box of that type,
            reported with the caller's format-specific code. C2PA 15.6.1 reserves
            ``claim.multiple`` for multiple recognized claim boxes, not content boxes.
    """
    found: bytes | None = None
    for kind, payload in box.content:
        if kind != tbox:
            continue
        if found is not None:
            label = box.description.label
            msg = f"assertion {label!r} carries more than one {tbox.decode('ascii')} content box"
            raise MarkCorruptError(msg, 0, code=duplicate_code)
        found = payload
    return found


def _parse_assertions(assertion_store: JumbfBox | None) -> tuple[dict[str, _cbor.CborValue], dict[str, bytes]]:
    """Decode every assertion, returning both the values and the raw box bytes.

    The raw bytes are what 8.4.2.3 hashes, so they are carried alongside the decoded
    values rather than re-serialized later: re-encoding a decoded assertion would hash
    our encoder's output instead of what actually arrived, which is the whole point of
    the hashed-URI check.

    An assertion store may be absent entirely; the claim's own links then fail, which
    is where that is reported.

    Raises:
        MarkCorruptError: an assertion's ``cbor`` box is invalid CBOR
            (``assertion.cbor.invalid``, 15.10.3.1), or a JSON-LD assertion's ``json``
            box is not well-formed JSON (``assertion.json.invalid``),
            or the assertion store holds two boxes under one label, which makes the
            claim's linked assertion path unresolved and reports ``assertion.missing``.

    An assertion carrying neither -- a ``bfdb``/``bidb``/``uuid`` box, for example -- does not
    raise. It keeps its raw bytes, so the hashed URI still authenticates it and the
    undeclared check still sees it, and simply has no decoded value. 11.1.4 permits any
    JUMBF content type in an assertion.
    """
    assertions: dict[str, _cbor.CborValue] = {}
    assertion_bytes: dict[str, bytes] = {}
    if assertion_store is None:
        return assertions, assertion_bytes

    for label, (box, raw_box) in _children_with_bytes(assertion_store, "the assertion store").items():
        # Record every assertion by raw bytes, whatever content type it carries.
        assertion_bytes[label] = raw_box

        # JSON-LD FIRST for a metadata assertion. 18.17.2 says it "shall contain a
        # single JSON content type box". A second content representation would leave
        # the authenticated assertion value ambiguous.
        metadata = _json_ld_assertion(box, label)
        if metadata is not None:
            assertions[label] = metadata
            continue

        payload = _content(box, b"cbor", duplicate_code=StatusCode.ASSERTION_CBOR_INVALID)
        if payload is None:
            # 11.1.4: an assertion's content box "should be CBOR ..., JSON ..., Embedded
            # File Content Type (bfdb & bidb) or UUID Content Type (uuid) though any
            # Content Type defined in JUMBF ... is permitted." At 2.4 this is not an
            # edge case -- data boxes were replaced by embedded data assertions, so a
            # claim generator's icon lives in a bfdb/bidb assertion. Rejecting those
            # made a conforming manifest unparseable and left 15.10.3.3's icon check
            # unable to reach the box it validates.
            continue
        try:
            # 18.1 constrains what a claim generator EMITS. The validator rule in
            # 15.10.3.1 is narrower: reject content that is not well-formed CBOR,
            # with well-formed defined by RFC 8949 Appendix C. Accept a well-formed,
            # non-deterministic serialization and authenticate its exact raw box bytes;
            # re-encoding here would change what the hashed URI covers. The decoder
            # also rejects duplicate map keys, which RFC 8949 calls invalid even when
            # their bytes satisfy the well-formed grammar.
            assertions[label] = _cbor.loads(payload, deterministic=False)
        except _cbor.CborDecodeError as exc:
            # 15.10.3.1: "If the content of a standard assertion is not well-formed
            # CBOR or is non-conforming JSON, the claim shall be rejected with a
            # failure code of assertion.cbor.invalid or assertion.json.invalid."
            # Caught HERE for the same reason the claim's decode is: the blanket
            # handler in parse_manifest_store would report
            # manifest.text.corruptedWrapper, which is 15.12.1.3.2's code for a damaged
            # selector run, not for an intact wrapper around a malformed assertion.
            msg = f"assertion {label!r} is not valid CBOR: {exc}"
            raise MarkCorruptError(msg, 0, code=StatusCode.ASSERTION_CBOR_INVALID) from exc
    return assertions, assertion_bytes


def parse_manifest_store(raw: bytes) -> ManifestStore:
    """Parse serialized JUMBF into a :class:`ManifestStore`.

    Raises:
        MarkCorruptError: if the structure is not a well-formed C2PA manifest store.
            The JUMBF and CBOR layers raise their own error types; they are
            translated here so a caller has one exception type to catch, carrying
            the C2PA status code.
    """
    try:
        store, end = parse_superbox(raw)
        if end != len(raw):
            msg = f"the C2PA Manifest Store ends at byte {end}, before its {len(raw)}-byte payload"
            raise MarkCorruptError(msg, 0)
        if store.description.uuid != UUID_MANIFEST_STORE or store.description.label != LABEL_MANIFEST_STORE:
            msg = "the outer superbox is not a recognized C2PA manifest store"
            raise MarkCorruptError(msg, 0)
        _require_c2pa_description(store, "the C2PA Manifest Store")

        # 15.5.1: "The last C2PA Manifest superbox in the C2PA Manifest Store
        # superbox shall be considered the active manifest." Do not collapse the store
        # into a label-keyed map before applying that ordered rule.
        manifest = _active_manifest(store)
        label = _require_c2pa_description(manifest, "the active C2PA Manifest")
        parts = _children(manifest, f"manifest {label}", _is_manifest_part)

        # 15.11.3.3: "Locate the claim, as described in Locating and Validating the
        # Claim. If unable to, reject claim with a claim.missing failure code." BOTH
        # branches are "unable to locate": a box that is not there, and a box that is
        # there, correctly labelled, and holds nothing. Reported as claim.missing
        # rather than as the wrapper's own manifest.text.corruptedWrapper, which
        # describes damage to the selector run and would send an investigator looking
        # for text corruption that is not present.
        claim_box = parts.get(LABEL_CLAIM)
        if claim_box is None:
            msg = f"manifest carries no {LABEL_CLAIM} box"
            raise MarkCorruptError(msg, 0, code=StatusCode.CLAIM_MISSING)
        claim_bytes = _content(claim_box, b"cbor", duplicate_code=StatusCode.CLAIM_MALFORMED)
        if claim_bytes is None:
            msg = "claim box carries no cbor content box"
            raise MarkCorruptError(msg, 0, code=StatusCode.CLAIM_MISSING)

        signature_box = parts.get(LABEL_CLAIM_SIGNATURE)
        signature = _content(signature_box, b"cbor") if signature_box is not None else None
        if signature is None:
            # 15.7 names a code for exactly this, so the carrier's default is wrong
            # here: the wrapper is intact and the signature box is the thing absent.
            msg = f"manifest carries no {LABEL_CLAIM_SIGNATURE} box"
            raise MarkCorruptError(msg, 0, code=StatusCode.CLAIM_SIGNATURE_MISSING)

        try:
            # 10.1 requires deterministic output from a generator. Validation in
            # 15.6.2 instead rejects claims that are not well-formed CBOR, as RFC
            # 8949 Appendix C defines that term. Keep the received bytes verbatim
            # for signature verification and accept well-formed alternative encodings
            # rather than imposing the producer rule on a reader. Duplicate map keys
            # remain invalid under RFC 8949 even when the grammar can parse them.
            claim = _cbor.loads(claim_bytes, deterministic=False)
        except _cbor.CborDecodeError as exc:
            # 15.6.2: "If the content of the claim is not well-formed CBOR, the claim
            # shall be rejected with a failure code of claim.cbor.invalid." Caught
            # HERE rather than by the blanket handler below, which would report
            # manifest.text.corruptedWrapper and send an investigator looking for
            # selector-run damage that is not present.
            msg = f"the claim is not valid CBOR: {exc}"
            raise MarkCorruptError(msg, 0, code=StatusCode.CLAIM_CBOR_INVALID) from exc
        if not isinstance(claim, dict):
            # 15.6.2 separates the two: claim.cbor.invalid is for bytes that are not
            # well-formed CBOR, claim.malformed for a claim that DECODED and is the
            # wrong shape. An array where a map belongs is the second -- the CBOR is
            # impeccable and the claim is not a claim.
            msg = "claim is not a CBOR map"
            raise MarkCorruptError(msg, 0, code=StatusCode.CLAIM_MALFORMED)

        assertion_store = parts.get(LABEL_ASSERTION_STORE)
        assertions, assertion_bytes = _parse_assertions(assertion_store)

    except JumbfError as exc:
        # One exception type for the caller. The underlying position is preserved in
        # the message rather than being silently dropped.
        raise MarkCorruptError(f"malformed manifest store: {exc}", 0) from exc

    return ManifestStore(
        manifest_label=label,
        claim={key: value for key, value in claim.items() if isinstance(key, str)},
        claim_bytes=claim_bytes,
        assertions=assertions,
        assertion_bytes=assertion_bytes,
        signature=signature,
        raw=raw,
    )


def extract(text: str) -> ManifestStore | None:
    """Return the embedded manifest store, or ``None`` if ``text`` carries no mark.

    Performs NO cryptographic validation. The returned manifest is untrusted input;
    call :func:`verify` before relying on anything in it.

    Raises:
        MarkCorruptError: a wrapper's magic number matched but the wrapper or the
            manifest inside it is malformed, or the text carries MORE THAN ONE wrapper
            (``manifest.text.multipleWrappers``). Absence of a mark is not an error and
            never raises.

    Plural wrappers are refused because extraction performs no binding validation and
    therefore cannot apply 15.12.1.3.1's exclusion-based selection. Use :func:`verify`
    to select and authenticate a matching manifest. Use :func:`locate` to inspect
    wrapper spans without choosing a manifest.
    """
    matches = find_wrappers(text)
    if not matches:
        return None
    if len(matches) > 1:
        msg = f"text carries {len(matches)} wrappers; exactly one is required"
        raise MarkCorruptError(msg, 0, code=StatusCode.TEXT_MULTIPLE_WRAPPERS)
    return parse_manifest_store(matches[0].payload)
