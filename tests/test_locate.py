"""Wrapper detection: A.8.4.2 plus the four hazards it leaves undefined."""

from __future__ import annotations

import pytest

from c2patxt._locate import Span, find_wrappers, locate
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
    assert find_wrappers("nothing here") == []


def test_span_covers_the_marker_and_the_run() -> None:
    text = "Doc." + build_wrapper(PAYLOAD)
    span = locate(text)
    assert span is not None
    assert span.utf8_start == len(b"Doc.")
    assert span.utf8_stop == len(text.encode("utf-8"))
    # A.8.4.2 defines the wrapper as the marker followed by the selector run.
    assert text.encode("utf-8")[span.utf8_start :].startswith(MARKER.encode("utf-8"))


def test_offsets_are_bytes_not_code_points() -> None:
    """A.8.7.3: "work with byte offsets, not character offsets"."""
    text = "café" + build_wrapper(PAYLOAD)
    span = locate(text)
    assert span is not None
    assert span.utf8_start == 6, "byte offset"
    assert text.index(MARKER) == 5, "code point index differs -- that is the trap"


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
    matches = find_wrappers(text)
    assert len(matches) == 1
    assert matches[0].payload == PAYLOAD


def test_wrapper_extent_comes_from_declared_length_not_run_end() -> None:
    """A.8's declared manifest length does not swallow trailing author text."""
    trailing = bytes_to_selectors(b"\xaa\xbb")
    text = "Doc." + build_wrapper(PAYLOAD) + trailing
    span = locate(text)
    assert span is not None
    assert find_wrappers(text)[0].payload == PAYLOAD
    assert span.utf8_stop == len(("Doc." + build_wrapper(PAYLOAD)).encode("utf-8"))
    assert span.utf8_stop < len(text.encode("utf-8")), "trailing selectors excluded"


def test_two_wrappers_are_both_found_and_the_first_one_is_the_answer() -> None:
    """Reporting multipleWrappers is the validator's job; locating is ours.

    Distinct payloads make document order observable. ``locate`` returns the first
    match's span, while validation owns the plural-wrapper decision.
    """
    first, second = PAYLOAD, bytes.fromhex("00112233")
    assert first != second
    text = "Doc." + build_wrapper(first) + " tail" + build_wrapper(second)

    matches = find_wrappers(text)
    assert len(matches) == 2
    assert [match.payload for match in matches] == [first, second], "document order"

    assert locate(text) == matches[0].span


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
    matches = find_wrappers(text)
    assert len(matches) == 1
    assert matches[0].payload == vector.expect


@pytest.mark.parametrize("vector", [v for v in VECTORS if v.op == "embed" and v.is_ok], ids=lambda v: v.id)
def test_conformance_rule_6_locator_round_trip(vector: Vector) -> None:
    """Vector rule 6: "For every op=embed record with status=OK,
    ``extract(expect_hex) == (payload_hex, OK)``".

    The locator supplies the wire-level payload operation for this local corpus; the
    opaque payload need not be a parseable C2PA Manifest Store.
    """
    marked = vector.expect.decode("utf-8")
    matches = find_wrappers(marked)
    assert len(matches) == 1
    assert matches[0].payload == vector.payload
