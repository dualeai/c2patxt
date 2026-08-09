"""Byte-to-selector codec, validated against the spec formula and the vector file."""

from __future__ import annotations

import struct

import pytest

from c2patxt._locate import find_wrappers
from c2patxt._selectors import (
    build_wrapper,
    byte_to_selector,
    bytes_to_selectors,
    parse_wrapper_body,
    selector_to_byte,
)
from c2patxt.constants import HEADER_SIZE, MAGIC, MAX_MANIFEST_LENGTH
from c2patxt.exceptions import C2paTextError, MarkCorruptError
from tests.vectors.loader import Vector, load_vectors

VECTORS = load_vectors()


def _selectors_from_spec(payload: bytes) -> str:
    """A.8.3.1 written as literals, independent of the package tables."""
    return "".join(chr(0xFE00 + value) if value < 0x10 else chr(0xE0100 + value - 0x10) for value in payload)


def test_every_byte_matches_the_spec_formula_in_both_directions() -> None:
    """A.8.3.1 over the complete 256-value domain, using literal code points."""
    for value in range(256):
        codepoint = 0xFE00 + value if value < 0x10 else 0xE0100 + value - 0x10
        assert byte_to_selector(value) == chr(codepoint)
        assert selector_to_byte(codepoint) == value

    payload = bytes(range(256))
    expected = _selectors_from_spec(payload)
    assert bytes_to_selectors(payload) == expected


@pytest.mark.parametrize("value", [-1, 256, 1000])
def test_non_bytes_are_rejected(value: int) -> None:
    with pytest.raises(ValueError, match="not a byte"):
        byte_to_selector(value)


@pytest.mark.parametrize(
    "codepoint",
    [
        0xFDFF,  # just below the low block
        0xFE10,  # just above the low block
        0xE00FF,  # just below the high block
        0xE01F0,  # just above the high block -- the classic off-by-one
        0x41,  # "A"
        0xFEFF,  # the marker itself is NOT a selector
    ],
)
def test_non_selectors_decode_to_none(codepoint: int) -> None:
    """Returning None, not raising: a scan of arbitrary text asks this constantly."""
    assert selector_to_byte(codepoint) is None


def test_lone_surrogate_is_not_a_selector() -> None:
    """Decoders meet '\\ud800' from real-world JSON. It must not crash the scan."""
    assert selector_to_byte(0xD800) is None


def test_build_wrapper_refuses_what_the_parser_would_refuse() -> None:
    """Producer and consumer must agree on the limit, or we emit unreadable output."""
    with pytest.raises(ValueError, match="exceeds"):
        build_wrapper(b"\x00" * (MAX_MANIFEST_LENGTH + 1))


def test_parse_rejects_a_bad_version() -> None:
    body = MAGIC + bytes([2]) + struct.pack(">I", 0)
    with pytest.raises(MarkCorruptError, match="version 2"):
        parse_wrapper_body(body)


def test_parse_rejects_a_short_header() -> None:
    with pytest.raises(MarkCorruptError, match="header truncated"):
        parse_wrapper_body(MAGIC + bytes([1]) + b"\x00\x00")


def test_parse_rejects_an_oversized_declared_length() -> None:
    """A 13-byte header cannot raise the accepted manifest cap.

    Thirteen is `HEADER_SIZE`, and the body below is exactly that: magic(8) +
    version(1) + manifestLength(4).
    """
    body = MAGIC + bytes([1]) + struct.pack(">I", 0xFFFFFFFF)
    with pytest.raises(MarkCorruptError, match="exceeds the"):
        parse_wrapper_body(body)


def test_parse_rejects_a_length_that_overruns_the_run() -> None:
    body = MAGIC + bytes([1]) + struct.pack(">I", 8) + b"\x01\x02\x03"
    with pytest.raises(MarkCorruptError, match="3 bytes available"):
        parse_wrapper_body(body)


def test_corrupt_error_is_catchable_both_ways_and_picklable() -> None:
    """Structured attributes survive a process boundary; see __reduce__."""
    import pickle

    original = MarkCorruptError("boom", 1, 3)
    assert isinstance(original, C2paTextError)
    assert isinstance(original, ValueError)

    revived = pickle.loads(pickle.dumps(original))  # noqa: S301 - our own object, not untrusted input
    assert (revived.msg, revived.pos, revived.document_length) == ("boom", 1, 3)


def test_corrupt_error_message_is_truncation_aware() -> None:
    assert "end of text" in str(MarkCorruptError("boom", 99, 3))
    assert "byte 1" in str(MarkCorruptError("boom", 1, 3))


@pytest.mark.parametrize(
    "vector",
    [v for v in VECTORS if v.op == "embed" and v.is_ok],
    ids=lambda v: v.id,
)
def test_embed_vectors_reproduce(vector: Vector) -> None:
    """Every OK embed vector must be reproduced by build_wrapper."""
    text = vector.text.decode("utf-8")
    assert (text + build_wrapper(vector.payload)).encode("utf-8") == vector.expect


def test_the_scanner_decodes_every_selector_value_from_a_literal_wrapper() -> None:
    """Drive the regex and decode table through their real boundary.

    The wrapper comes from the A.8 literals rather than ``build_wrapper``. A missing
    regex range or translation-table entry must therefore fail at the scanner instead
    of being hidden by agreement between our encoder and decoder.
    """
    payload = bytes(range(256))
    body = bytes.fromhex("4332504154585400") + b"\x01" + struct.pack(">I", len(payload)) + payload
    text = "Document." + "\ufeff" + _selectors_from_spec(body)

    matches = find_wrappers(text)

    assert len(matches) == 1
    assert matches[0].payload == payload


def test_a_body_one_byte_short_of_the_header_is_refused_not_unpacked() -> None:
    """The 13-byte header boundary rejects 12 bytes before ``struct.unpack``."""
    twelve = MAGIC + bytes([1]) + b"\x00\x00\x00"
    assert len(twelve) == HEADER_SIZE - 1

    with pytest.raises(MarkCorruptError, match="header truncated"):
        parse_wrapper_body(twelve)

    # And the first length that IS valid parses, so the bound is not merely "large".
    thirteen = MAGIC + bytes([1]) + struct.pack(">I", 0)
    assert len(thirteen) == HEADER_SIZE
    assert parse_wrapper_body(thirteen) == b""


def test_a_non_default_status_code_survives_a_process_boundary() -> None:
    """Pickling preserves a non-default C2PA status code."""
    import pickle

    from c2patxt.status import StatusCode

    original = MarkCorruptError("a duplicated label", 0, code=StatusCode.CLAIM_MULTIPLE)
    revived = pickle.loads(pickle.dumps(original))  # noqa: S301 -- our own object, not untrusted input

    assert revived.code is StatusCode.CLAIM_MULTIPLE, "the status code did not survive pickling"
    assert (revived.msg, revived.pos, revived.document_length) == ("a duplicated label", 0, None)
    assert revived.code is not StatusCode.TEXT_CORRUPTED_WRAPPER
