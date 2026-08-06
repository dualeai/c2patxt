"""
Wrapper detection (C2PA 2.4 A.8.4.2, 15.5.2.5).

Scanning, and the one rewrite that follows from it. No keys, no hashing, no manifest
parsing -- but ``strip`` REMOVES a located wrapper and returns new text, so this module
is not read-only. It is here because removal is exactly "locate, then delete that
span", and putting it elsewhere would mean a second implementation of the span rules.

A note on the byte frame, because it is the easiest thing here to get subtly wrong.
Offsets returned by this module index the **as-stored** UTF-8 encoding of the text
handed to us, not an NFC-normalized re-encoding. That is the frame 15.12.1.3.1
operates in: step 5 removes the wrapper bytes *according to the exclusion range*,
and only step 6 normalizes what remains. An exclusion range therefore indexes the
text before normalization.

A.8.7.3 says the opposite -- "perform normalization before calculating offsets" --
and the two disagree whenever the stored text is not already NFC. For
``"cafe" + U+0301`` followed by a wrapper, the wrapper starts at byte 6 as stored
but byte 5 in NFC. A.8.5 delegates normativity to the Validation clause explicitly
("refer to the Validation clause for the normative procedure"), so 15.12.1.3.1 wins,
and both other public A.8 implementations independently chose the same. The
contradiction is recorded in the deviations document.

Our own encoder normalizes before appending, so for text this package produced the
two frames coincide. The divergence only reaches us via foreign input.
"""

from __future__ import annotations

import dataclasses
import re

from c2patxt._selectors import parse_wrapper_body, selector_to_byte
from c2patxt.constants import (
    HEADER_SIZE,
    MAGIC,
    MARKER,
    MAX_SELECTOR_RUN,
    VS_HIGH_BASE,
    VS_HIGH_MAX,
    VS_LOW_BASE,
    VS_LOW_MAX,
)
from c2patxt.exceptions import MarkCorruptError, UnencodableTextError

__all__ = [
    "Span",
    "WrapperMatch",
    "find_wrappers",
    "locate",
    "payload_at",
    "require_encodable",
    "strip",
]


@dataclasses.dataclass(frozen=True, slots=True)
class Span:
    """A byte range in the as-stored UTF-8 encoding of the text.

    These are BYTE offsets, not string indices. A.8.7.3 is explicit: "work with byte
    offsets, not character offsets". Slicing a ``str`` with them will silently
    produce the wrong result for any non-ASCII text -- for ``"cafe" + U+0301`` plus a
    wrapper, the wrapper begins at code point 5 but byte 6.

    This is also the range written to the ``exclusions`` field of the
    ``c2pa.hash.data`` assertion, and it INCLUDES the U+FEFF marker. Whether the
    marker falls inside the exclusion is undefined in A.8 -- A.8.2.2 does not make it
    part of the wrapper structure while A.8.4.1 says the wrapper is "prefixed with"
    it -- but both public implementations include it, and a 3-byte disagreement here
    silently breaks interoperability.
    """

    utf8_start: int
    utf8_stop: int

    def __post_init__(self) -> None:
        if self.utf8_start < 0 or self.utf8_stop < self.utf8_start:
            msg = f"invalid span: [{self.utf8_start}, {self.utf8_stop})"
            raise ValueError(msg)

    def __len__(self) -> int:
        return self.utf8_stop - self.utf8_start


@dataclasses.dataclass(frozen=True, slots=True)
class WrapperMatch:
    """One located wrapper: where it sits, and the JUMBF payload it carries."""

    span: Span
    payload: bytes


#: The two A.8.3.1 blocks as a character class, bounded by ``MAX_SELECTOR_RUN`` in the
#: pattern itself rather than by a Python counter -- the bound is what stops a long run
#: of selectors carrying no valid header from making us walk an arbitrarily long span,
#: so it has to survive the move into the regex engine.
_RUN = re.compile(
    f"[\\U{VS_LOW_BASE:08X}-\\U{VS_LOW_MAX:08X}\\U{VS_HIGH_BASE:08X}-\\U{VS_HIGH_MAX:08X}]{{0,{MAX_SELECTOR_RUN}}}"
)

#: Selector code point to the Latin-1 character standing for its byte. Built FROM
#: ``selector_to_byte``, the function carrying A.8.3.2's formula, so the bulk path
#: cannot disagree with the one-character path.
_DECODE_TABLE = {
    codepoint: chr(value)
    for codepoint in (*range(VS_LOW_BASE, VS_LOW_MAX + 1), *range(VS_HIGH_BASE, VS_HIGH_MAX + 1))
    if (value := selector_to_byte(codepoint)) is not None
}


def _decode_run(text: str, start: int) -> tuple[bytes, int]:
    """Decode the contiguous selector run beginning at ``start``.

    Returns the decoded bytes and the index one past the run. Bounded by
    ``MAX_SELECTOR_RUN`` so a long run of selectors carrying no valid header cannot
    make us walk an arbitrarily long span.

    THE RUN IS FOUND AND DECODED IN C, not in a Python loop over ``ord``. Written as
    that loop this was the single largest term in verifying a short document: it cost
    185-197 ms per MB of manifest payload, against 32 ms per MB for the form that ships.

    THE COMPARISON AGAINST DOCUMENT TEXT NEEDS ITS DENOMINATOR NAMED, and this sentence
    gave a figure -- "1.8 ms per MB of document text ... 110x" -- that matches neither
    available reading. Re-measured 2026-08-06 at 1, 2 and 4 MB, 9 repetitions: scanning
    plain text for a marker costs 0.017-0.031 ms/MB, and a whole ``verify`` of marked
    text costs 3.76-3.96 ms/MB of document.

    SO THE RATIO DEPENDS ON WHICH IMPLEMENTATION AND WHICH DENOMINATOR, and a first
    correction here got that wrong in the same way the original did -- it quoted
    "roughly 50x" and "several thousand", both computed from the REPLACED decoder.
    From the three figures above: as shipped, 32/3.96 to 32/3.76 is 8.1-8.5x against a
    whole verify, and 32/0.031 to 32/0.017 is one to two thousand times against the
    scan alone. The replaced form is where 50x comes from (190/3.86). Our own manifests
    are ~1 800
    bytes, but A.8 permits 2 MiB, and 2.4 replaced data boxes with embedded-data
    assertions, so a third-party manifest carrying an icon reaches the 100 KB range as
    ORDINARY input rather than adversarial input.

    Latin-1 is the round trip that maps code point N to byte N for all 256 values,
    which is what lets ``translate`` do the mapping and ``encode`` do the packing.
    """
    run = _RUN.match(text, start)
    if run is None:  # pragma: no cover -- the pattern matches the empty string, so this cannot happen
        return b"", start
    return run.group().translate(_DECODE_TABLE).encode("latin-1"), run.end()


def require_encodable(text: str) -> None:
    """Reject text UTF-8 cannot represent, before any offset arithmetic runs.

    Called at every public entry point. Cheap on the common path -- the check is a
    single encode attempt, and CPython encodes ASCII at memory speed -- and it turns
    a confusing codec error raised from deep inside the scan into one documented
    exception naming the offending index.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise UnencodableTextError(exc.start) from exc


def find_wrappers(text: str) -> list[WrapperMatch]:
    """Locate every structurally valid wrapper, in order of appearance.

    Implements A.8.4.2: scan for U+FEFF; for each, decode the following contiguous
    variation-selector run; if its first eight bytes are the magic, parse the rest.

    Four hazards A.8.4.2 does not address, all handled here:

    1. A candidate whose magic does not match is NOT an error. Scanning simply
       continues. Inventing a failure code here would hand a denial of service to
       anyone able to append a garbage selector run to a document -- they could
       invalidate a genuine wrapper elsewhere in the same text.
    2. A leading UTF-8 byte-order mark IS a U+FEFF and is scanned as a candidate. It
       is rejected on the magic check like any other non-match, with no special case.
    3. Fewer than eight selectors after a marker is undefined in A.8. Treated as
       "not a wrapper", consistent with (1).
    4. A wrapper ends at ``HEADER_SIZE + manifestLength`` decoded bytes, never at the
       end of the contiguous run. Variation selectors the author wrote immediately
       after a wrapper are not part of it.

    Raises:
        MarkCorruptError: when a candidate's magic matches but its structure is
            malformed. A matched magic is a positive assertion that a wrapper was
            intended, so unlike (1) above this is a real failure.
    """
    require_encodable(text)

    matches: list[WrapperMatch] = []
    corrupt: MarkCorruptError | None = None
    marker_bytes = len(MARKER.encode("utf-8"))

    index = 0
    # Running byte offset, advanced alongside `index`. Re-encoding text[:index] on
    # every match made this quadratic: 32,000 wrappers in 1.5 MB of text cost 8.3 s
    # seconds and tens of gigabytes of transient allocation. Allocation was bounded;
    # CPU was not, which is the same denial of service by another route.
    prefix_bytes = 0
    consumed_index = 0

    while True:
        found = text.find(MARKER, index)
        if found < 0:
            break

        prefix_bytes += len(text[consumed_index:found].encode("utf-8"))
        consumed_index = found

        run, _ = _decode_run(text, found + len(MARKER))

        # Hazards 1 and 3: the magic does not match, or the run is too short to hold
        # one. (Hazard 2, the leading BOM, has no branch of its own by design.)
        # Neither is an error; advance past this marker and keep scanning.
        if len(run) < len(MAGIC) or run[: len(MAGIC)] != MAGIC:
            index = found + len(MARKER)
            continue

        try:
            payload = parse_wrapper_body(run, doc=text, offset=prefix_bytes + marker_bytes)
        except MarkCorruptError as exc:
            # A corrupt candidate must NOT discard wrappers already found. Otherwise
            # appending twenty-odd characters of malformed run to a document makes a
            # genuine wrapper unfindable -- the same denial of service that hazard 1
            # rejects, arriving through the parse path instead of the scan path.
            # The error is remembered and raised only if nothing valid turns up.
            if corrupt is None:
                corrupt = exc
            index = found + len(MARKER)
            continue

        # Hazard 4: the wrapper's extent comes from the declared length, not the run.
        wrapper_chars = len(MARKER) + HEADER_SIZE + len(payload)
        wrapper_text = text[found : found + wrapper_chars]
        stop = prefix_bytes + len(wrapper_text.encode("utf-8"))

        matches.append(WrapperMatch(span=Span(prefix_bytes, stop), payload=payload))
        index = found + wrapper_chars

    if not matches and corrupt is not None:
        raise corrupt
    return matches


def locate(text: str) -> Span | None:
    """Return the byte span of the wrapper in ``text``, or ``None`` if unmarked.

    Offsets are byte offsets into the as-stored UTF-8 encoding; see the module
    docstring for why that frame and not NFC.

    Raises:
        MarkCorruptError: a wrapper's magic matched but its structure is malformed.
    """
    matches = find_wrappers(text)
    if not matches:
        return None
    # More than one wrapper is a validation-layer concern reported as
    # manifest.text.multipleWrappers, not a location failure. locate() answers
    # "where is the mark", and the first one is the answer to that question.
    return matches[0].span


def strip(text: str) -> str:
    """Return ``text`` with every Content Credential removed.

    THE REASON THIS EXISTS: :class:`Span` holds BYTE offsets, and slicing a ``str``
    with them silently produces the wrong result for any non-ASCII text. Without a
    shipped helper, every caller who wants to re-mark a document hand-rolls the
    encode/splice/decode dance, and the ones who do not notice the byte-versus-
    character distinction leave a residue of the old mark behind.

    That failure is triple-invisible. The residue is zero-width, so the text looks
    identical on screen. It is shorter than the magic number, so ``verify()`` reports
    UNMARKED rather than corrupt. And ``embed()`` then accepts it and bakes it
    permanently inside the newly hashed visible text.

    Unmarked text is returned unchanged. All wrappers are removed, not just the
    first: a document carrying several is already invalid, and leaving one behind
    would produce text that still fails to verify for a reason the caller thought
    they had fixed.

    Raises:
        MarkCorruptError: a wrapper's magic matched but its structure is malformed.
            Removing an unknown extent would be guesswork.
        UnencodableTextError: ``text`` cannot be encoded as UTF-8.
    """
    matches = find_wrappers(text)
    if not matches:
        return text

    encoded = text.encode("utf-8")
    kept: list[bytes] = []
    cursor = 0
    for match in matches:
        kept.append(encoded[cursor : match.span.utf8_start])
        cursor = match.span.utf8_stop
    kept.append(encoded[cursor:])
    return b"".join(kept).decode("utf-8")


def payload_at(text: str) -> bytes | None:
    """Return the JUMBF payload of the first wrapper, or ``None`` if unmarked."""
    matches = find_wrappers(text)
    return matches[0].payload if matches else None
