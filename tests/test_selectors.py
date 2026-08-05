"""Byte-to-selector codec, validated against the spec formula and the vector file."""

from __future__ import annotations

import struct

import pytest

from c2patxt._selectors import (
    build_wrapper,
    byte_to_selector,
    bytes_to_selectors,
    is_selector,
    parse_wrapper_body,
    selector_to_byte,
    selectors_to_bytes,
)
from c2patxt.constants import HEADER_SIZE, MAGIC, MARKER, MAX_MANIFEST_LENGTH
from c2patxt.exceptions import C2paTextError, MarkCorruptError
from tests.vectors.loader import Vector, load_vectors

VECTORS = load_vectors()


@pytest.mark.parametrize(
    ("value", "codepoint"),
    [
        (0x00, 0xFE00),  # first byte of the low block
        (0x0F, 0xFE0F),  # last byte of the low block
        (0x10, 0xE0100),  # first byte of the high block
        (0xFF, 0xE01EF),  # last byte of the high block
    ],
)
def test_mapping_boundaries(value: int, codepoint: int) -> None:
    """The four boundary points of A.8.3.1, where an off-by-one would first show."""
    assert ord(byte_to_selector(value)) == codepoint
    assert selector_to_byte(codepoint) == value


def test_every_byte_round_trips() -> None:
    """All 256 values, both directions."""
    for value in range(256):
        assert selector_to_byte(ord(byte_to_selector(value))) == value
    payload = bytes(range(256))
    assert selectors_to_bytes(bytes_to_selectors(payload)) == payload


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        b"\x0f\x10",
        bytes(range(256)),
        bytes(range(256)) * 8,
        bytes([0]) * 2048,
        bytes([255]) * 2048,
    ],
    ids=["empty", "one-low", "the-boundary", "every-byte", "every-byte-x8", "all-low", "all-high"],
)
def test_the_bulk_encoder_agrees_with_the_one_byte_encoder(payload: bytes) -> None:
    """``bytes_to_selectors`` must equal ``byte_to_selector`` applied byte by byte.

    It is a ``str.translate`` over a 256-entry table rather than a per-byte Python
    call -- 306.5 us to 36.4 us on a 1 797-byte store, 8.4x, and the table is built
    from ``byte_to_selector`` itself so the two cannot diverge by construction.

    PINNED ANYWAY, because "by construction" is what the table's build says and this
    is what CHECKS it. ``byte_to_selector`` is the function carrying A.8.3.1's formula
    verbatim; asserting against it rather than against a literal expectation means
    this test compares the fast path to the specification rather than to a second
    copy of the fast path.

    The bytes this produces are the wire format. A change here that survived the
    suite would silently break every mark already in the world, so the boundary byte
    pair and the all-low/all-high extremes are named cases rather than left to a
    random sample.
    """
    assert bytes_to_selectors(payload) == "".join(byte_to_selector(b) for b in payload)


def test_utf8_cost_is_asymmetric_by_design() -> None:
    """Low block costs 3 UTF-8 bytes, high block 4. A property of the spec."""
    assert len(byte_to_selector(0x0F).encode("utf-8")) == 3
    assert len(byte_to_selector(0x10).encode("utf-8")) == 4


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
    assert not is_selector(chr(codepoint))


def test_lone_surrogate_is_not_a_selector() -> None:
    """Decoders meet '\\ud800' from real-world JSON. It must not crash the scan."""
    assert selector_to_byte(0xD800) is None


def test_selectors_to_bytes_rejects_foreign_characters() -> None:
    run = bytes_to_selectors(b"\x01\x02") + "A"
    with pytest.raises(MarkCorruptError) as excinfo:
        selectors_to_bytes(run)
    assert excinfo.value.pos == 2
    assert excinfo.value.code == "manifest.text.corruptedWrapper"


def test_build_wrapper_matches_the_spec_framing() -> None:
    payload = bytes.fromhex("deadbeef")
    wrapper = build_wrapper(payload)
    assert wrapper.startswith(MARKER)
    decoded = selectors_to_bytes(wrapper[len(MARKER) :])
    assert decoded[:8] == MAGIC
    assert decoded[8] == 1
    assert struct.unpack(">I", decoded[9:13])[0] == len(payload)
    assert decoded[HEADER_SIZE:] == payload


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


def test_parse_rejects_an_oversized_declared_length_before_allocating() -> None:
    """A 13-byte input must not be able to request a 4 GiB allocation.

    Thirteen is `HEADER_SIZE`, and the body below is exactly that: magic(8) +
    version(1) + manifestLength(4). Four documents said 17, including this docstring
    over a body that has always built 13.
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

    original = MarkCorruptError("boom", "abc", 1)
    assert isinstance(original, C2paTextError)
    assert isinstance(original, ValueError)

    revived = pickle.loads(pickle.dumps(original))  # noqa: S301 - our own object, not untrusted input
    assert (revived.msg, revived.doc, revived.pos) == ("boom", "abc", 1)


def test_corrupt_error_message_is_truncation_aware() -> None:
    assert "end of text" in str(MarkCorruptError("boom", "abc", 99))
    assert "byte 1" in str(MarkCorruptError("boom", "abc", 1))


@pytest.mark.parametrize(
    "vector",
    [v for v in VECTORS if v.op == "embed" and v.is_ok],
    ids=lambda v: v.id,
)
def test_embed_vectors_reproduce(vector: Vector) -> None:
    """Every OK embed vector must be reproduced by build_wrapper."""
    text = vector.text.decode("utf-8")
    assert (text + build_wrapper(vector.payload)).encode("utf-8") == vector.expect


def test_the_decode_table_covers_exactly_the_selectors() -> None:
    """The mirror of ``test_the_bulk_encoder_agrees_with_the_one_byte_encoder``, for the
    read direction, which had no such test.

    ``_locate._DECODE_TABLE`` argues it "cannot disagree with the one-character path"
    because it is built from ``selector_to_byte`` -- the identical "by construction"
    argument the encoder makes and then pins anyway.

    THE FAILURE MODE IS NOT A WRONG ANSWER, IT IS AN ESCAPED EXCEPTION. ``_decode_run``
    matches a character class and then calls ``.translate(...).encode("latin-1")``. If
    the class and the table ever cover different code points, that encode raises
    ``UnicodeEncodeError`` -- not ``MarkCorruptError`` -- and escapes ``verify()``,
    which is the one thing this package promises hostile input cannot do. Deleting a
    single table entry reproduces it.

    So both directions are asserted: every code point the class admits must be in the
    table, and every table value must be a byte ``latin-1`` can encode.
    """
    from c2patxt._locate import _DECODE_TABLE, _RUN  # pyright: ignore[reportPrivateUsage] -- the pair under test

    expected = {codepoint for codepoint in range(0x110000) if selector_to_byte(codepoint) is not None}
    assert set(_DECODE_TABLE) == expected, "the table and selector_to_byte disagree about what a selector is"

    for codepoint, char in _DECODE_TABLE.items():
        assert ord(char) < 256, f"U+{codepoint:04X} maps to a character latin-1 cannot encode"
        assert ord(char) == selector_to_byte(codepoint)

    # Every character the run pattern admits must be translatable, or the encode raises.
    for codepoint in expected:
        assert _RUN.match(chr(codepoint)).end() == 1, f"U+{codepoint:04X} decodes but the run pattern rejects it"  # pyright: ignore[reportOptionalMemberAccess] -- the pattern always matches


def test_a_body_one_byte_short_of_the_header_is_refused_not_unpacked() -> None:
    """The boundary is 13 bytes, and 12 is where the crash lives.

    ``parse_wrapper_body`` guards with ``len(body) < HEADER_SIZE``. Relaxing that by one
    -- the classic off-by-one -- passed all 1180 tests, and the consequence is not a
    wrong answer: a 12-byte body with a matching magic reaches
    ``struct.unpack(">I", body[9:13])`` with THREE bytes and raises ``struct.error``,
    which is neither a ``C2paTextError`` nor a ``ValueError`` this package catches. It
    escapes ``verify()``, which promises never to raise on attacker input.

    The existing tests sit at 3 bytes and 8 bytes -- both far enough from the edge that
    the guard is never asked the only question that can go wrong.
    """
    twelve = MAGIC + bytes([1]) + b"\x00\x00\x00"
    assert len(twelve) == HEADER_SIZE - 1

    with pytest.raises(MarkCorruptError, match="header truncated"):
        parse_wrapper_body(twelve)

    # And the first length that IS valid parses, so the bound is not merely "large".
    thirteen = MAGIC + bytes([1]) + struct.pack(">I", 0)
    assert len(thirteen) == HEADER_SIZE
    assert parse_wrapper_body(thirteen) == b""


def test_a_non_default_status_code_survives_a_process_boundary() -> None:
    """``__reduce__`` may drop the code and the suite passed.

    The existing pickle test builds the error with the DEFAULT code and asserts only
    ``(msg, doc, pos)``, so removing ``self.code`` from the reduce tuple changed
    nothing it could see. The consequence is precise: ``claim.multiple``,
    ``claim.missing``, ``claimSignature.missing`` and ``assertion.cbor.invalid`` all
    revert to ``manifest.text.corruptedWrapper`` across the boundary -- the exact
    misdirection five raise sites in ``_extract`` exist to prevent, on the path
    ``__reduce__``'s own docstring says "matters the moment anyone runs verification in
    a worker pool".
    """
    import pickle

    from c2patxt.status import StatusCode

    original = MarkCorruptError("a duplicated label", "", 0, StatusCode.CLAIM_MULTIPLE)
    revived = pickle.loads(pickle.dumps(original))  # noqa: S301 -- our own object, not untrusted input

    assert revived.code is StatusCode.CLAIM_MULTIPLE, "the status code did not survive pickling"
    assert (revived.msg, revived.doc, revived.pos) == ("a duplicated label", "", 0)
    assert revived.code is not StatusCode.TEXT_CORRUPTED_WRAPPER
