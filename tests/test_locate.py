"""Wrapper detection: A.8.4.2 plus the four hazards it leaves undefined."""

from __future__ import annotations

import pytest

from c2patxt._locate import Span, find_wrappers, locate, payload_at
from c2patxt._selectors import build_wrapper, bytes_to_selectors
from c2patxt.constants import MARKER
from c2patxt.exceptions import MarkCorruptError
from tests.vectors.loader import Vector, load_vectors

VECTORS = load_vectors()
PAYLOAD = bytes.fromhex("deadbeef")


def test_unmarked_text_locates_nothing() -> None:
    """Absence is a normal outcome, never an exception."""
    assert locate("Just ordinary prose.") is None
    assert locate("") is None
    assert payload_at("nothing here") is None


def test_span_covers_the_marker_and_the_run() -> None:
    text = "Doc." + build_wrapper(PAYLOAD)
    span = locate(text)
    assert span is not None
    assert span.utf8_start == len(b"Doc.")
    assert span.utf8_stop == len(text.encode("utf-8"))
    # The marker is inside the span: both public implementations include it, and a
    # 3-byte disagreement here silently breaks interop.
    assert text.encode("utf-8")[span.utf8_start :].startswith(MARKER.encode("utf-8"))


def test_offsets_are_bytes_not_code_points() -> None:
    """A.8.7.3: "work with byte offsets, not character offsets"."""
    text = "café" + build_wrapper(PAYLOAD)
    span = locate(text)
    assert span is not None
    assert span.utf8_start == 6, "byte offset"
    assert text.index(MARKER) == 5, "code point index differs -- that is the trap"


def test_payload_round_trips() -> None:
    assert payload_at("Doc." + build_wrapper(PAYLOAD)) == PAYLOAD
    big = bytes(range(256))
    assert payload_at("x" + build_wrapper(big)) == big


def test_a_leading_byte_order_mark_is_not_a_wrapper() -> None:
    """Hazard 2: a BOM IS a U+FEFF and gets scanned, then rejected on the magic."""
    assert locate(MARKER + "Leading BOM, nothing else.") is None


def test_marker_with_too_few_selectors_is_not_a_wrapper() -> None:
    """Hazard 3: fewer than eight selectors is undefined in A.8; not-a-wrapper."""
    assert locate("Short " + MARKER + bytes_to_selectors(b"\x01\x02\x03")) is None


def test_non_matching_magic_is_not_an_error() -> None:
    """Hazard 1: scanning continues. Inventing a failure here is a DoS vector."""
    assert locate("Bad " + MARKER + bytes_to_selectors(b"NOTC2PA!") + " tail") is None


def test_a_garbage_run_before_a_real_wrapper_does_not_invalidate_it() -> None:
    """SECURITY: otherwise anyone able to append text denies service to provenance."""
    garbage = MARKER + bytes_to_selectors(b"\x00\x01\x02\x03GARBAGE")
    text = "Doc " + garbage + " body" + build_wrapper(PAYLOAD)
    assert payload_at(text) == PAYLOAD
    assert len(find_wrappers(text)) == 1


def test_wrapper_extent_comes_from_declared_length_not_run_end() -> None:
    """Hazard 4: trailing author-written selectors are not swallowed.

    encypherai/c2pa-conformance-suite gets this wrong, ending a wrapper at "the
    start of the next wrapper, or EOF".
    """
    trailing = bytes_to_selectors(b"\xaa\xbb")
    text = "Doc." + build_wrapper(PAYLOAD) + trailing
    span = locate(text)
    assert span is not None
    assert payload_at(text) == PAYLOAD
    assert span.utf8_stop == len(("Doc." + build_wrapper(PAYLOAD)).encode("utf-8"))
    assert span.utf8_stop < len(text.encode("utf-8")), "trailing selectors excluded"


def test_two_wrappers_are_both_found_and_the_first_one_is_the_answer() -> None:
    """Reporting multipleWrappers is the validator's job; locating is ours.

    THE TWO PAYLOADS DIFFER ON PURPOSE. This test used the same payload at both
    positions and called only ``find_wrappers``, so ``matches[0] -> matches[-1]``
    survived in both ``locate`` and ``payload_at`` -- two identical wrappers cannot
    tell you which one you got back.

    Which one is returned is a security question, not a stylistic one:
    ``AlreadyMarkedError.span`` is built from the first match, and a caller who uses
    that span to ``strip()`` a two-wrapper document would otherwise cut at a range an
    attacker chose by appending the second wrapper.
    """
    first, second = PAYLOAD, bytes.fromhex("00112233")
    assert first != second
    text = "Doc." + build_wrapper(first) + " tail" + build_wrapper(second)

    matches = find_wrappers(text)
    assert len(matches) == 2
    assert [match.payload for match in matches] == [first, second], "document order"

    assert locate(text) == matches[0].span
    assert payload_at(text) == first


def test_malformed_wrapper_raises_rather_than_silently_skipping() -> None:
    """A matched magic asserts intent, so structural damage is a real failure."""
    text = "Doc." + build_wrapper(PAYLOAD)
    with pytest.raises(MarkCorruptError):
        locate(text[:-1])  # drop one payload selector


def test_span_rejects_impossible_ranges() -> None:
    with pytest.raises(ValueError, match="invalid span"):
        Span(5, 1)
    assert len(Span(2, 9)) == 7


@pytest.mark.parametrize(
    "vector",
    [v for v in VECTORS if v.op == "extract"],
    ids=lambda v: v.id,
)
def test_extract_vectors_locate_as_specified(vector: Vector) -> None:
    """Every extract record: found payload, absence, or the named failure code."""
    text = vector.text.decode("utf-8")

    if vector.status == "NONE":
        assert locate(text) is None
        return
    if vector.status == "manifest.text.corruptedWrapper":
        with pytest.raises(MarkCorruptError) as excinfo:
            find_wrappers(text)
        assert excinfo.value.code == vector.status
        return
    if vector.status == "manifest.text.multipleWrappers":
        assert len(find_wrappers(text)) > 1
        return
    assert payload_at(text) == vector.expect


@pytest.mark.parametrize("vector", [v for v in VECTORS if v.op == "embed" and v.is_ok], ids=lambda v: v.id)
def test_conformance_rule_6_round_trip(vector: Vector) -> None:
    """Vector rule 6: "For every op=embed record with status=OK,
    ``extract(expect_hex) == (payload_hex, OK)``".

    THE RULE WAS STATED AND NEVER EXECUTED. ``test_locate.py`` parametrized only
    ``op == "extract"`` records and ``test_selectors.py`` only the ``embed`` side, so
    nothing ever took an embed record's OUTPUT and extracted from it. Eight rules are
    published in the file; this one had no test behind it, which is the same defect
    class as a docstring asserting a guard nothing checks.

    This closes the loop the file promises: the bytes an embed record says we must
    produce are the bytes an extract must read back.
    """
    marked = vector.expect.decode("utf-8")
    assert payload_at(marked) == vector.payload


@pytest.mark.parametrize(
    "run",
    [
        "",
        "︀",
        "\U000e0100",
        "️\U000e0100",
        "".join(chr(c) for c in (*range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0))),
        "︀" * 3000,
    ],
    ids=["empty", "one-low", "one-high", "the-boundary", "every-selector", "long-low-run"],
)
@pytest.mark.parametrize("tail", ["", "A", "﻿", "é", "\U0001f600"], ids=["end", "ascii", "marker", "latin", "astral"])
def test_the_bulk_decoder_agrees_with_the_one_character_decoder(run: str, tail: str) -> None:
    """``_decode_run`` must return exactly what a per-character loop over
    ``selector_to_byte`` returns, and stop at exactly the same index.

    It is a compiled character class plus ``str.translate`` rather than that loop:
    the loop cost 197 ms per MB of manifest payload and was the largest single term
    in verifying a short document. The table is built from ``selector_to_byte``, so
    the two cannot diverge by construction -- and this is what CHECKS that, against
    the function carrying A.8.3.2's formula rather than against a second copy of the
    fast path.

    THE STOPPING INDEX MATTERS AS MUCH AS THE BYTES. A run is delimited by the first
    non-selector, and the caller uses the returned index to resume scanning; a
    decoder that agreed on the bytes and disagreed on where the run ended would
    silently move every subsequent wrapper. The ``tail`` cases cover the four kinds
    of character that can follow -- including U+FEFF, which starts the NEXT
    candidate, and an astral character, which is where a code-point/code-unit
    confusion would show.
    """
    # The private helper is the unit that owns the mapping; driving it through
    # find_wrappers would only exercise runs that happen to carry a valid header.
    from c2patxt._locate import (
        _decode_run,  # pyright: ignore[reportPrivateUsage] -- the decoder itself is the unit under test
    )
    from c2patxt._selectors import selector_to_byte

    text = "prefix " + run + tail
    start = len("prefix ")

    expected = bytearray()
    index = start
    while index < len(text) and (value := selector_to_byte(ord(text[index]))) is not None:
        expected.append(value)
        index += 1

    assert _decode_run(text, start) == (bytes(expected), index)
