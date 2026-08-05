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

from c2patxt import _cbor, _jumbf
from c2patxt._jumbf import JumbfBox, JumbfError, parse_superbox
from c2patxt._locate import find_wrappers
from c2patxt.exceptions import MarkCorruptError
from c2patxt.manifest import (
    LABEL_ASSERTION_STORE,
    LABEL_CLAIM,
    LABEL_CLAIM_SIGNATURE,
    ManifestStore,
)
from c2patxt.status import StatusCode

__all__ = [
    "extract",
    "parse_manifest_store",
]

_SUPERBOX_HEADER = 8


def _reparse(payload: bytes) -> tuple[JumbfBox, int]:
    """Re-wrap a nested superbox payload with a header so it can be parsed.

    ``_jumbf`` keeps nested superboxes opaque so it stays a pure box codec; the
    length is recomputed here rather than trusted from the parent.
    """
    header = (_SUPERBOX_HEADER + len(payload)).to_bytes(4, "big") + _jumbf.TBOX_SUPERBOX
    return parse_superbox(header + payload)


def _children(box: JumbfBox, what: str) -> dict[str, JumbfBox]:
    """Parse every nested superbox child, keyed by its label.

    Children whose type UUID we do not recognise are not rejected, per C2PA 11.1.2's
    processing rules -- a conforming producer may emit boxes a given consumer has never
    heard of. Boxes are keyed by LABEL and the type UUID is never consulted here.

    That is also how C2PA 11.2.2 is satisfied: "Manifest Consumers shall also accept
    standard C2PA Manifests specified with JUMBF type UUID 63326D64-... (c2md), but
    claim generators shall not create manifests with this JUMBF type UUID." We read a
    manifest under either type and continue to emit c2ma, without a UUID list -- a
    constant naming c2md would assert a check that does not exist.
    """
    return {label: child for label, (child, _) in _children_with_bytes(box, what).items()}


def _children_with_bytes(box: JumbfBox, what: str) -> dict[str, tuple[JumbfBox, bytes]]:
    """As :func:`_children`, but keeping each child's RAW hashable bytes.

    The bytes are the nested superbox payload -- the serialized box with its own
    LBox+TBox stripped -- which is exactly what C2PA 8.4.2.3 hashes. They must be
    carried through from the parse rather than re-serialized later: re-serializing
    would hash OUR encoding of the box, not the bytes that actually arrived, and an
    attacker who can make those two differ can substitute an assertion at will.

    A DUPLICATE LABEL IS REJECTED, NOT OVERWRITTEN. This returns a label-keyed map,
    and an earlier version simply assigned into it -- last write wins -- which
    silently discarded a box and defeated three separate checks built on top:

      * the "more than one manifest" count, since two manifests sharing a label
        collapsed to one and never tripped it;
      * the "every assertion in the store is linked by the claim" guard, since the
        smuggled box vanished from the set being compared;
      * 15.6.1's "only one c2pa.claim.v2 box per manifest" rule, for the same reason.

    Beyond those, collapsing is a producer/consumer DIVERGENCE in its own right: a
    third-party JUMBF reader may take the FIRST box where we took the last, so two
    conforming implementations would authenticate different content from identical
    bytes. Rejecting is the only answer that keeps them in agreement.
    """
    out: dict[str, tuple[JumbfBox, bytes]] = {}
    for tbox, payload in box.content:
        if tbox != _jumbf.TBOX_SUPERBOX:
            continue
        child, _ = _reparse(payload)
        label = child.description.label
        if label is None:
            continue
        if label in out:
            msg = f"{what} contains more than one box labelled {label!r}"
            raise MarkCorruptError(msg, "", 0, StatusCode.CLAIM_MULTIPLE)
        out[label] = (child, payload)
    return out


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


def _json_ld_assertion(box: JumbfBox, label: str) -> _cbor.CborValue | None:
    """Decode a ``c2pa.metadata`` assertion's JSON-LD box, or None if this is not one.

    ONE EXCEPTION TO THE CBOR RULE, and it is required rather than tolerated. 18.17.2:
    "Each metadata assertion shall contain a single JSON content type box containing
    the JSON-LD serialization of one or more metadata values." Table 7 (18.4) lists
    ``c2pa.metadata`` as JSON-LD -- along with ``c2pa.repository-receipt``, which we
    neither emit nor read, and Embedded File entries for ingredients and thumbnails. So
    the scoping below is ours: ``c2pa.metadata`` is the only JSON-LD assertion this
    package handles, not the only one the specification defines.
    Refusing it made a CONFORMING producer's manifest read as invalid here -- and it
    is the very assertion the text conformance rubric's ``text:is_text_asset`` check
    reads.

    Scoped to labels whose BASE ends ``.metadata`` -- 18.17.2's own naming rule, read
    through 6.4's ``__N`` convention, so ``c2pa.metadata__1`` is recognised. It was
    scoped to the bare label, so a second metadata assertion landed in
    ``assertion_bytes`` and never in ``assertions``: a store with two conflicting
    ``dc:format`` values verified VALID while a consumer saw one of them. NOT
    widened to "any json box" -- the caller's guard against unparseable assertions
    keeps doing its job everywhere else.

    Raises:
        MarkCorruptError: the JSON is not well-formed, or is well-formed and not an
            object. Both carry ``assertion.json.invalid``, which 15.10.3.1 names for
            exactly this ("not well-formed CBOR or is non-conforming JSON"). Returning
            None for either would report the assertion as carrying no JSON-LD, which is
            a different and untrue statement.
    """
    if not _base_label(label).endswith(".metadata"):
        return None
    payload = _content(box, b"json")
    if payload is None:
        return None
    try:
        decoded: object = json.loads(payload)
    except ValueError as exc:
        # 15.10.3.1 names a code for each serialization: "not well-formed CBOR or is
        # non-conforming JSON... assertion.cbor.invalid or assertion.json.invalid".
        # assertion.missing would say the store LACKS an assertion the claim named; the
        # store has it, and it does not parse.
        msg = f"assertion {label!r} is not well-formed JSON"
        raise MarkCorruptError(msg, "", 0, StatusCode.ASSERTION_JSON_INVALID) from exc
    if not isinstance(decoded, dict):
        msg = f"assertion {label!r} is not a JSON object"
        raise MarkCorruptError(msg, "", 0, StatusCode.ASSERTION_JSON_INVALID)
    return _as_cbor_map(decoded)  # pyright: ignore[reportUnknownArgumentType]


def _as_cbor_map(mapping: object) -> dict[int | str | bytes, _cbor.CborValue]:
    """THE ONE Any BOUNDARY IN THIS PACKAGE, confined to three lines.

    ``json.loads`` is typed as returning ``Any``, so pyright cannot see the element
    types of a decoded object no matter how it is annotated. The suppressions below
    are scoped to the two expressions that touch that value; every element then goes
    through :func:`_as_cbor_value`, which narrows by ``isinstance`` at RUNTIME, so
    nothing untyped escapes this function.

    The alternative -- ``cast`` -- is banned repo-wide precisely because it asserts a
    type instead of checking one. This checks.
    """
    if not isinstance(mapping, dict):  # pragma: no cover - caller has already checked
        msg = "expected a JSON object"
        raise MarkCorruptError(msg, "", 0, StatusCode.ASSERTION_MISSING)
    pairs = mapping.items()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    out: dict[int | str | bytes, _cbor.CborValue] = {}
    for key, value in pairs:  # pyright: ignore[reportUnknownVariableType]
        out[str(key)] = _as_cbor_value(value)  # pyright: ignore[reportUnknownArgumentType]
    return out


def _as_cbor_value(value: object) -> _cbor.CborValue:
    """Narrow a JSON-decoded value into the CBOR value union.

    JSON and CBOR agree on every type we can receive here -- null, bool, number,
    string, array, object -- so this is a typing bridge, not a conversion.

    FLOATS ARE CARRIED AS FLOATS. They were rendered as their text form, on the
    reasoning that "a float is the one JSON type our CBOR union does not carry" -- true
    until ``CborValue`` gained ``float``, after which the same signed coordinate had two
    Python types depending on which box carried it: 0.5 from a CBOR assertion, "0.5"
    from a JSON-LD one. A consumer comparing a region across the two forms would find
    them unequal.

    The final ``repr`` remains for anything neither branch admits -- which ``json``
    cannot currently produce, and which is narrowed rather than trusted.
    """
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    if isinstance(value, list):
        items = list(value)  # pyright: ignore[reportUnknownArgumentType, reportUnknownVariableType]
        return [_as_cbor_value(item) for item in items]  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    if isinstance(value, dict):
        return _as_cbor_map(value)  # pyright: ignore[reportUnknownArgumentType]
    return repr(value)


def _content(box: JumbfBox, tbox: bytes) -> bytes | None:
    """The single content box of type ``tbox``, or None if the box carries none.

    A DUPLICATE IS REJECTED, NOT RESOLVED FIRST-WINS. `_children_with_bytes` rejects
    two boxes under one LABEL and states the reason: "a third-party JUMBF reader may
    take the FIRST box where we took the last, so two conforming implementations would
    authenticate different content from identical bytes." That argument applies
    unchanged one level down -- two cbor boxes in one assertion is the same ambiguity
    at a smaller scale, and the bytes hash identically either way -- and this function
    resolved it silently until 2026-08-06.

    Raises:
        MarkCorruptError: the box carries more than one content box of that type,
            reported as ``claim.multiple`` for the same reason a duplicated label is:
            15.6.1 names it for a duplicate, and the fault is ambiguity rather than
            byte damage to the carrier.
    """
    found: bytes | None = None
    for kind, payload in box.content:
        if kind != tbox:
            continue
        if found is not None:
            label = box.description.label
            msg = f"assertion {label!r} carries more than one {tbox.decode('ascii')} content box"
            raise MarkCorruptError(msg, "", 0, StatusCode.CLAIM_MULTIPLE)
        found = payload
    return found


def _parse_assertions(assertion_store: JumbfBox | None) -> tuple[dict[str, _cbor.CborValue], dict[str, bytes]]:
    """Decode every assertion, returning both the values and the raw box bytes.

    The RAW BYTES are what 8.4.2.3 hashes, so they are carried alongside the decoded
    values rather than re-serialized later: re-encoding a decoded assertion would hash
    our encoder's output instead of what actually arrived, which is the whole point of
    the hashed-URI check.

    An assertion store may be absent entirely; the claim's own links then fail, which
    is where that is reported.

    Raises:
        MarkCorruptError: an assertion's ``cbor`` box is not well-formed CBOR
            (``assertion.cbor.invalid``, 15.10.3.1), or a ``.metadata`` assertion's
            ``json`` box is not a well-formed JSON object (``assertion.json.invalid``),
            or the assertion store holds TWO BOXES UNDER ONE LABEL, which
            ``_children_with_bytes`` reports as ``claim.multiple``.

            That third path was missing here, and its absence is worse than an ordinary
            gap: the code says *claim*, so a reader handed ``claim.multiple`` for a
            duplicated ASSERTION label goes looking at the claim box. The code is the
            one 15.6.1 names for a duplicated label and we apply it to both, but a
            reader cannot infer that from a block that does not mention it.

    An assertion carrying NEITHER -- a ``bfdb``/``bidb``/``uuid`` box, say -- does not
    raise. It keeps its raw bytes, so the hashed URI still authenticates it and the
    undeclared check still sees it, and simply has no decoded value. 11.1.4 permits any
    JUMBF content type in an assertion, and refusing them made a conforming manifest
    unparseable.
    """
    assertions: dict[str, _cbor.CborValue] = {}
    assertion_bytes: dict[str, bytes] = {}
    if assertion_store is None:
        return assertions, assertion_bytes

    for label, (box, raw_box) in _children_with_bytes(assertion_store, "the assertion store").items():
        # EVERY assertion is recorded by its raw bytes, whatever it carries. That is
        # what keeps the guard closed: the hole fixed earlier was a non-cbor box
        # vanishing from this map, so the claim's "every assertion is linked" check
        # never saw it. Hashing works on bytes and never needed the decode.
        assertion_bytes[label] = raw_box

        # JSON-LD FIRST for a metadata assertion. 18.17.2: it "shall contain a single
        # JSON content type box". Trying cbor first meant that an assertion carrying
        # BOTH decoded as CBOR here while a peer following 18.17.2 read the JSON --
        # identical bytes, different content, both hash-matching, neither side raising.
        metadata = _json_ld_assertion(box, label)
        if metadata is not None:
            assertions[label] = metadata
            continue

        payload = _content(box, b"cbor")
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
            assertions[label] = _cbor.loads(payload)
        except _cbor.CborDecodeError as exc:
            # 15.10.3.1: "If the content of a standard assertion is not well-formed
            # CBOR or is non-conforming JSON, the claim shall be rejected with a
            # failure code of assertion.cbor.invalid or assertion.json.invalid."
            # Caught HERE for the same reason the claim's decode is: the blanket
            # handler in parse_manifest_store would report
            # manifest.text.corruptedWrapper, which is 15.12.1.3.2's code for a damaged
            # selector run, not for an intact wrapper around a malformed assertion.
            msg = f"assertion {label!r} is not well-formed CBOR: {exc}"
            raise MarkCorruptError(msg, "", 0, StatusCode.ASSERTION_CBOR_INVALID) from exc
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
        store, _ = parse_superbox(raw)
        manifests = _children(store, "the manifest store")
        if not manifests:
            msg = "manifest store contains no manifest"
            raise MarkCorruptError(msg, "", 0)

        # 15.5.1: "The last C2PA Manifest superbox in the C2PA Manifest Store
        # superbox shall be considered the active manifest." We follow it rather than
        # rejecting plural manifests, and the reasoning changed once the duplicate-
        # label collapse below was fixed:
        #
        # An earlier version rejected len(manifests) > 1, arguing that picking one
        # silently lets an attacker append a manifest and have different consumers
        # read different claims. But the rule is DETERMINISTIC, so every conforming
        # consumer picks the same one -- the divergence risk came from our own
        # departure, not from the rule. And appending anything grows the wrapper,
        # which breaks the exclusion range, so the hard binding rejects it regardless.
        #
        # What genuinely was exploitable is duplicate LABELS, which used to collapse
        # silently and is now refused outright. That is the check doing the security
        # work here; this line is spec conformance.
        label = list(manifests)[-1]
        manifest = manifests[label]
        parts = _children(manifest, f"manifest {label}")

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
            raise MarkCorruptError(msg, "", 0, StatusCode.CLAIM_MISSING)
        claim_bytes = _content(claim_box, b"cbor")
        if claim_bytes is None:
            msg = "claim box carries no cbor content box"
            raise MarkCorruptError(msg, "", 0, StatusCode.CLAIM_MISSING)

        signature_box = parts.get(LABEL_CLAIM_SIGNATURE)
        signature = _content(signature_box, b"cbor") if signature_box is not None else None
        if signature is None:
            # 15.7 names a code for exactly this, so the carrier's default is wrong
            # here: the wrapper is intact and the signature box is the thing absent.
            msg = f"manifest carries no {LABEL_CLAIM_SIGNATURE} box"
            raise MarkCorruptError(msg, "", 0, StatusCode.CLAIM_SIGNATURE_MISSING)

        try:
            claim = _cbor.loads(claim_bytes)
        except _cbor.CborDecodeError as exc:
            # 15.6.2: "If the content of the claim is not well-formed CBOR, the claim
            # shall be rejected with a failure code of claim.cbor.invalid." Caught
            # HERE rather than by the blanket handler below, which would report
            # manifest.text.corruptedWrapper and send an investigator looking for
            # selector-run damage that is not present.
            msg = f"the claim is not well-formed CBOR: {exc}"
            raise MarkCorruptError(msg, "", 0, StatusCode.CLAIM_CBOR_INVALID) from exc
        if not isinstance(claim, dict):
            # 15.6.2 separates the two: claim.cbor.invalid is for bytes that are not
            # well-formed CBOR, claim.malformed for a claim that DECODED and is the
            # wrong shape. An array where a map belongs is the second -- the CBOR is
            # impeccable and the claim is not a claim.
            msg = "claim is not a CBOR map"
            raise MarkCorruptError(msg, "", 0, StatusCode.CLAIM_MALFORMED)

        assertion_store = parts.get(LABEL_ASSERTION_STORE)
        assertions, assertion_bytes = _parse_assertions(assertion_store)

    except (JumbfError, _cbor.CborDecodeError) as exc:
        # One exception type for the caller. The underlying position is preserved in
        # the message rather than being silently dropped.
        raise MarkCorruptError(f"malformed manifest store: {exc}", "", 0) from exc

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

    PLURAL WRAPPERS ARE REFUSED, matching :func:`verify`. Returning the first would hand
    back attacker-chosen provenance: an attacker appends the second wrapper, so they
    choose which is first by choosing what to prepend, and docs/deviations.md rejects
    exactly that reading -- "lets an attacker append a wrapper and choose which one a
    given consumer reads". A caller who wants to INSPECT a suspicious document should use
    :func:`locate`, which returns a span rather than a manifest and documents its own
    first-wrapper choice.
    """
    matches = find_wrappers(text)
    if not matches:
        return None
    if len(matches) > 1:
        msg = f"text carries {len(matches)} wrappers; exactly one is required"
        raise MarkCorruptError(msg, "", 0, StatusCode.TEXT_MULTIPLE_WRAPPERS)
    return parse_manifest_store(matches[0].payload)
