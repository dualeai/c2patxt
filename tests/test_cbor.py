"""Deterministic CBOR output and the broader RFC 8949 validator reader.

Expected bytes come from RFC 8949 and the published CBOR test corpus. ``cbor2``
decodes those fixed external bytes; it is not the encoder oracle.
"""

from __future__ import annotations

import pathlib
import re
from typing import TypeGuard

import cbor2
import pytest
from cbor2 import CBORSimpleValue, undefined

from c2patxt._cbor import TAG_COSE_SIGN1, TAG_DATETIME, CborDecodeError, MapKey, SimpleValue, Tagged, dumps, loads
from c2patxt.constants import MAX_CBOR_DEPTH

CBOR_VECTORS = pathlib.Path(__file__).parent / "vectors" / "cbor"


@pytest.mark.parametrize(
    ("value", "expected_hex"),
    [
        # RFC 8949 Appendix A, verbatim.
        (0, "00"),
        (1, "01"),
        (10, "0a"),
        (23, "17"),
        (24, "1818"),
        (25, "1819"),
        (100, "1864"),
        (1000, "1903e8"),
        (1000000, "1a000f4240"),
        (1000000000000, "1b000000e8d4a51000"),
        (-1, "20"),
        (-10, "29"),
        (-100, "3863"),
        (-1000, "3903e7"),
        (b"", "40"),
        (b"\x01\x02\x03\x04", "4401020304"),
        ("", "60"),
        ("a", "6161"),
        ("IETF", "6449455446"),
        ('"\\', "62225c"),
        ("ü", "62c3bc"),
        ("水", "63e6b0b4"),
        ([], "80"),
        ([1, 2, 3], "83010203"),
        ([1, [2, 3], [4, 5]], "8301820203820405"),
        ({}, "a0"),
        (False, "f4"),
        (True, "f5"),
        (None, "f6"),
    ],
)
def test_rfc8949_appendix_a_encodings(value: object, expected_hex: str) -> None:
    """Known-answer tests transcribed from the RFC, both directions."""
    assert dumps(value).hex() == expected_hex
    assert loads(bytes.fromhex(expected_hex)) == value


def test_map_keys_are_sorted_bytewise_not_length_first() -> None:
    """The reason this module exists instead of cbor2.

    RFC 8949 4.2.1 requires purely bytewise ordering of encoded keys. cbor2's
    ``canonical=True`` implements 4.2.3, which sorts length-first. For a map holding
    both a negative key and a positive key at or above 24 they disagree, and the
    wrong order violates the deterministic-encoding rule used by C2PA.
    """
    ours = dumps({-8: 0, 33: 0})
    theirs = cbor2.dumps({-8: 0, 33: 0}, canonical=True)

    assert ours.hex() == "a21821002700", "33 (0x1821) sorts before -8 (0x27) bytewise"
    assert theirs.hex() == "a22700182100", "cbor2 puts the shorter key first"
    assert ours != theirs, "if these ever agree, re-check which rule cbor2 implements"


def test_shortest_form_is_required_on_encode() -> None:
    """4.2.1: an argument must use the smallest width that fits."""
    assert dumps(23).hex() == "17", "fits in the initial byte"
    assert dumps(24).hex() == "1818", "steps up to one byte"
    assert dumps(255).hex() == "18ff"
    assert dumps(256).hex() == "190100", "steps up to two bytes"


@pytest.mark.parametrize(
    ("encoded_hex", "_why"),
    [
        ("1817", "24 encoded in one byte when it fits in the initial byte"),
        ("190017", "23 encoded in two bytes"),
        ("1a00000017", "23 encoded in four bytes"),
        ("1b0000000000000017", "23 encoded in eight bytes"),
    ],
)
def test_non_shortest_form_is_rejected_on_decode(encoded_hex: str, _why: str) -> None:
    """The strict mode pins the producer bytes; cbor2 does not verify this property."""
    with pytest.raises(CborDecodeError, match="shortest form"):
        loads(bytes.fromhex(encoded_hex))


@pytest.mark.parametrize(
    ("encoded_hex", "pattern"),
    [
        ("5f42010243030405ff", "indefinite"),  # indefinite-length byte string
        ("7f6161616bff", "indefinite"),  # indefinite-length text string
        ("9f018202039f0405ffff", "indefinite"),  # indefinite-length array
        ("bf61610161629f0203ffff", "indefinite"),  # indefinite-length map
    ],
)
def test_indefinite_lengths_are_rejected(encoded_hex: str, pattern: str) -> None:
    """Forbidden by deterministic encoding; a conforming producer never emits one."""
    with pytest.raises(CborDecodeError, match=pattern):
        loads(bytes.fromhex(encoded_hex))


def test_out_of_order_map_keys_are_rejected() -> None:
    """a2 6161 01 6160 02 -- "a" then "`", which is descending."""
    with pytest.raises(CborDecodeError, match="out-of-order"):
        loads(bytes.fromhex("a26161016160" + "02"))


@pytest.mark.parametrize("deterministic", [True, False], ids=["producer", "well-formed-reader"])
def test_duplicate_map_keys_are_rejected(*, deterministic: bool) -> None:
    with pytest.raises(CborDecodeError, match="duplicate"):
        loads(bytes.fromhex("a2616101616102"), deterministic=deterministic)


def test_unknown_tags_are_refused_by_the_writer_and_carried_by_the_reader() -> None:
    """The narrow producer and well-formed-input reader have different scopes."""
    with pytest.raises(ValueError, match="tag 55799 is not permitted"):
        dumps(Tagged(55799, 1))

    # Tag 1, epoch-based date/time: named by 6.9, and previously a hard reject on read.
    assert loads(bytes.fromhex("c11a514b67b0")) == Tagged(1, 1363896240)
    # A tag nobody has defined is carried too. Whether it is ALLOWED in a given position
    # is a CDDL question, answered by validation, not by the decoder.
    assert loads(bytes.fromhex("d9d9f701")) == Tagged(55799, 1)


def test_the_tdate_tag_round_trips() -> None:
    """RFC 8949 3.4.1 tag 0, the form the spec's own example uses:
    ``0("2023-02-11T09:00:00Z")``."""
    # 0xc0 tag(0), 0x74 text(20), then the 20 ASCII bytes. This is RFC 8949
    # Appendix A's own vector, so the bytes come from the RFC rather than from us.
    encoded = bytes.fromhex("c074") + b"2013-03-21T20:04:00Z"
    assert loads(encoded) == Tagged(0, "2013-03-21T20:04:00Z")
    assert dumps(Tagged(0, "2013-03-21T20:04:00Z")) == encoded


def test_floats_are_refused_rather_than_half_implemented() -> None:
    """4.2.1's shortest-float rule is easy to get subtly wrong, and we need none."""
    with pytest.raises(TypeError, match="floats are not supported"):
        dumps(1.5)


@pytest.mark.parametrize(
    ("encoded", "value"),
    [("e0", 0), ("f3", 19), ("f7", 23), ("f820", 32), ("f8ff", 255)],
)
def test_well_formed_simple_values_are_preserved(encoded: str, value: int) -> None:
    assert loads(bytes.fromhex(encoded)) == SimpleValue(value)


def test_simple_values_are_read_only_and_keep_their_type() -> None:
    assert SimpleValue(16) != 16
    with pytest.raises(TypeError, match="SimpleValue"):
        dumps(SimpleValue(16))


@pytest.mark.parametrize("encoded", ["f800", "f817", "f818", "f81f"])
def test_one_byte_simple_values_below_32_are_rejected(encoded: str) -> None:
    with pytest.raises(CborDecodeError, match="below 32"):
        loads(bytes.fromhex(encoded))


def test_trailing_bytes_are_rejected() -> None:
    """A decoder that ignores trailing data lets an attacker append a second message."""
    with pytest.raises(CborDecodeError, match="trailing"):
        loads(bytes.fromhex("0001"))


def test_truncated_input_is_rejected() -> None:
    with pytest.raises(CborDecodeError, match="truncated"):
        loads(bytes.fromhex("4401"))  # declares 4 bytes, supplies 1


def test_nesting_limit_is_inclusive_for_encoder_and_decoder() -> None:
    """Thirty-two arrays accept; the thirty-third is the first rejected level."""
    at_limit: object = 0
    for _ in range(MAX_CBOR_DEPTH):
        at_limit = [at_limit]
    literal = b"\x81" * MAX_CBOR_DEPTH + b"\x00"

    assert dumps(at_limit) == literal
    assert loads(literal) == at_limit

    over_limit = [at_limit]
    with pytest.raises(ValueError, match="nesting deeper"):
        dumps(over_limit)
    with pytest.raises(CborDecodeError, match="nesting deeper"):
        loads(b"\x81" + literal)


def test_bool_is_not_encoded_as_an_integer() -> None:
    """bool subclasses int; encoding True as 1 would be a silent wire-format bug."""
    assert dumps(True).hex() == "f5"
    assert dumps(1).hex() == "01"


#: One RFC 8949 Appendix A item: its description and its PUBLISHED bytes.
#:
#: The sidecar's ``decoded`` field is deliberately NOT carried. It is CBOR diagnostic
#: notation, and comparing a Python value against it would mean writing an EDN parser
#: -- so the oracle for the decoded value is cbor2, an independent implementation,
#: which is stronger than a string we would have had to interpret ourselves.
_CorpusItem = tuple[str, bytes, bool]

#: Total items across mt0-mt6. Asserted so a corpus that silently shrinks -- a bad
#: merge, a truncated download -- fails the build instead of quietly testing less.
_CORPUS_ITEM_COUNT = 70


def _corpus_items() -> list[_CorpusItem]:
    """Parse published bytes and each vector's deterministic-roundtrip expectation.

    The ``.edn`` files carry the RFC's expectations, so this parser reads those values
    rather than deriving them from the implementation under test.
    """
    items: list[_CorpusItem] = []
    for path in sorted(CBOR_VECTORS.glob("mt*.edn")):
        text = path.read_text("utf-8")
        for block in re.findall(r"\{(.*?)\}", text, re.DOTALL):
            encoded = re.search(r'"encoded":\s*h\'([0-9a-fA-F]*)\'', block)
            if encoded is None:
                continue
            described = re.search(r'"description":\s*"([^"]*)"', block)
            deterministic = re.search(r'"roundtrip":\s*false', block) is None
            items.append(
                (
                    described.group(1) if described else path.stem,
                    bytes.fromhex(encoded.group(1)),
                    deterministic,
                )
            )
    return items


def test_the_corpus_has_not_silently_shrunk() -> None:
    """Guards every test below: a glob over a missing corpus passes vacuously."""
    assert len(_corpus_items()) == _CORPUS_ITEM_COUNT


def _only_the_reader_admits(value: object) -> bool:
    """True if ``value`` contains something ``loads`` accepts and ``dumps`` refuses.

    That is exactly a float, or a tag outside the two we emit. Recursive, because the
    corpus nests them inside arrays and maps.
    """
    if isinstance(value, bool):  # bool before float: it is not a float, and int is not either
        return False
    if isinstance(value, (float, SimpleValue)):
        return True
    if isinstance(value, Tagged):
        return value.tag not in {TAG_DATETIME, TAG_COSE_SIGN1} or _only_the_reader_admits(value.value)
    if isinstance(value, list):
        return any(_only_the_reader_admits(item) for item in value)  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    if isinstance(value, dict):
        return any(_only_the_reader_admits(item) for item in value.values())  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    return False


@pytest.mark.parametrize(("description", "encoded", "deterministic"), _corpus_items(), ids=lambda v: str(v)[:40])
def test_each_appendix_a_item_meets_its_own_expectation(
    description: str, encoded: bytes, *, deterministic: bool
) -> None:
    """Every RFC 8949 Appendix A item, fed as its PUBLISHED BYTES.

    The vendored ``roundtrip`` field identifies each non-preferred float encoding.
    Those exact vectors must fail; every other Appendix A vector must decode. This is
    per-vector, so rejecting a valid simple value cannot be hidden by accidentally
    accepting a different non-deterministic float.
    """
    if not deterministic:
        with pytest.raises(CborDecodeError):
            loads(encoded)
        return

    value = loads(encoded)

    oracle = cbor2.loads(encoded)

    if isinstance(value, SimpleValue):
        expected = 23 if oracle is undefined else oracle.value if isinstance(oracle, CBORSimpleValue) else None
        assert value.value == expected, f"{description}: simple value disagreed"
    elif isinstance(value, Tagged) and value.tag == TAG_DATETIME:
        # cbor2 resolves tag 0 into a datetime; we keep the tagged STRING, because a
        # verifier must re-encode the exact bytes it was given and a parsed datetime
        # cannot reproduce, say, a "+00:00" offset written as "Z". Compare through
        # the reference decoder's own parse of our string instead of demanding the
        # same Python type.
        assert cbor2.loads(dumps(value)) == oracle, f"{description}: tdate disagreed"
    elif not _only_the_reader_admits(value):
        assert value == oracle, f"{description}: disagreed with the reference decoder"

    if _only_the_reader_admits(value):
        # The reader accepts foreign tags, floats and opaque simple values, while the
        # producer deliberately emits none of them. Pin that boundary per vector.
        with pytest.raises((TypeError, ValueError)):
            dumps(value)
        return
    assert dumps(value) == encoded, f"{description}: re-encoding was not byte-identical"


def _sidecar_items(name: str) -> list[tuple[str, bytes]]:
    """Parse one ``.edn`` sidecar into ``(description, published bytes)``."""
    text = (CBOR_VECTORS / f"{name}.edn").read_text("utf-8")
    items: list[tuple[str, bytes]] = []
    for block in re.findall(r"\{(.*?)\}", text, re.DOTALL):
        encoded = re.search(r'"encoded":\s*h\'([0-9a-fA-F]*)\'', block)
        if encoded is None:
            continue
        described = re.search(r'"description":\s*"([^"]*)"', block)
        items.append((described.group(1) if described else name, bytes.fromhex(encoded.group(1))))
    return items


#: Two items in the ill-formed corpus that this decoder ACCEPTS, correctly. Their
#: upstream file is titled "Inputs that should fail for RFC 8949", which is RFC 8949
#: VALIDITY -- wider than well-formedness. A tag 0 whose content is a map is invalid
#: under 5.3.2 and still well-formed under Appendix C, and C2PA 15.10.3.1 rejects only
#: content that is "NOT WELL-FORMED CBOR". Refusing them would be over-strictness, and
#: it would contradict ``test_the_decoder_preserves_any_well_formed_tag``.
_WELL_FORMED_BUT_TAG_INVALID = {
    "date: unexpected object instead of offset",
    "date: unexpected object instead of string",
}

#: Items in each vendored sidecar. Asserted so a truncated download fails the build
#: rather than parametrizing over nothing.
_BAD_ITEM_COUNT = 47
_STREAMING_ITEM_COUNT = 11

_VENDORED_CORPORA = (
    "bad",
    "mt0",
    "mt1",
    "mt2",
    "mt3",
    "mt4",
    "mt5",
    "mt6",
    "mt7-float",
    "mt7-simple",
    "streaming",
)


def _is_object_dict(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


@pytest.mark.parametrize(("description", "payload"), _sidecar_items("bad"), ids=lambda item: str(item)[:60])
def test_the_ill_formed_corpus_is_refused_with_our_own_error(description: str, payload: bytes) -> None:
    """cbor-wg's ``rfc8949/bad`` corpus: 47 inputs that must not decode.

    THE EXCEPTION TYPE IS PART OF THE ASSERTION. ``verify()`` is documented never to
    raise on hostile input, and it converts ``CborDecodeError`` and nothing else; a
    ``struct.error`` or an ``IndexError`` escaping the decoder would reach a caller
    from a manifest an attacker wrote.
    """
    if description in _WELL_FORMED_BUT_TAG_INVALID:
        loads(payload)  # accepted on purpose; see the constant above
        return
    with pytest.raises(CborDecodeError):
        loads(payload)


@pytest.mark.parametrize(("description", "payload"), _sidecar_items("streaming"), ids=lambda item: str(item)[:60])
def test_every_indefinite_length_item_in_the_corpus_is_refused(description: str, payload: bytes) -> None:
    """RFC 8949 Appendix A's streaming vectors, all eleven.

    4.2.1 requires definite lengths, so every one of these is a refusal. They are the
    published encodings rather than ones we constructed, which is the difference from
    ``test_indefinite_lengths_are_rejected`` three hand-written rows above.
    """
    assert description
    with pytest.raises(CborDecodeError):
        loads(payload)


def test_neither_vendored_sidecar_has_silently_shrunk() -> None:
    """A glob over a missing corpus parametrizes over nothing and passes."""
    assert len(_sidecar_items("bad")) == _BAD_ITEM_COUNT
    assert len(_sidecar_items("streaming")) == _STREAMING_ITEM_COUNT


@pytest.mark.parametrize("name", _VENDORED_CORPORA)
def test_binary_corpus_and_edn_sidecar_carry_the_same_vectors(name: str) -> None:
    """Both upstream representations carry the same bytes in the same order."""
    document: object = cbor2.loads((CBOR_VECTORS / f"{name}.cbor").read_bytes())
    assert _is_object_dict(document)
    tests = document.get("tests")
    assert _is_object_list(tests)

    binary_items: list[bytes] = []
    for item in tests:
        assert _is_object_dict(item)
        encoded = item.get("encoded")
        assert isinstance(encoded, bytes)
        binary_items.append(encoded)

    assert binary_items == [encoded for _, encoded in _sidecar_items(name)]


def test_the_vendored_cbor_file_inventory_is_exact() -> None:
    assert tuple(path.stem for path in sorted(CBOR_VECTORS.glob("*.cbor"))) == _VENDORED_CORPORA
    assert tuple(path.stem for path in sorted(CBOR_VECTORS.glob("*.edn"))) == _VENDORED_CORPORA


def test_argument_beyond_the_64_bit_range_is_refused() -> None:
    """CBOR arguments are at most 64 bits; a bigint has no representation."""
    with pytest.raises(ValueError, match="64-bit CBOR range"):
        dumps(1 << 64)


def test_unsupported_python_types_are_refused() -> None:
    with pytest.raises(TypeError, match="cannot encode set"):
        dumps({1, 2, 3})


def test_encoder_refuses_distinct_mapping_keys_with_the_same_cbor_identity() -> None:
    """RFC 8949 5.6: distinct Python keys may still encode as one CBOR key."""

    class IdentityText(str):
        __hash__ = object.__hash__

        def __eq__(self, other: object) -> bool:
            return self is other

        def __ne__(self, other: object) -> bool:
            return self is not other

    first = IdentityText("a")
    second = IdentityText("a")
    assert first is not second and first != second

    with pytest.raises(ValueError, match="duplicate map key"):
        dumps({first: 1, second: 2})


def test_reserved_additional_information_is_rejected() -> None:
    """Values 28-30 are reserved by RFC 8949 and must not be guessed at."""
    for info in (28, 29, 30):
        with pytest.raises(CborDecodeError, match="reserved additional information"):
            loads(bytes([info]))


def test_invalid_utf8_in_a_text_string_is_rejected() -> None:
    """Major type 3 is text; a lone continuation byte is not."""
    with pytest.raises(CborDecodeError, match="not valid UTF-8"):
        loads(bytes.fromhex("61ff"))


def test_a_stray_break_code_is_rejected() -> None:
    """0xff outside an indefinite-length item has no meaning."""
    with pytest.raises(CborDecodeError, match="break code"):
        loads(bytes.fromhex("ff"))


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        ("a18000", []),
        ("a1a000", {}),
        ("a1f500", True),
        ("a1f93c0000", 1.0),
        ("a1c10000", Tagged(1, 0)),
        ("a1e000", SimpleValue(0)),
    ],
    ids=["array", "map", "boolean", "float", "tag", "simple"],
)
def test_every_cbor_type_can_be_retained_as_a_map_key(encoded: str, expected: object) -> None:
    """RFC 8949 permits every data item as a key; Python dict does not.

    ``MapKey`` keeps the decoded value and a separate hashable identity. This matters
    for C2PA 18.3.3 custom assertion metadata, whose values are unconstrained CBOR.
    """
    decoded = loads(bytes.fromhex(encoded))
    assert isinstance(decoded, dict)
    assert len(decoded) == 1
    key, value = next(iter(decoded.items()))
    assert isinstance(key, MapKey)
    assert type(key.value) is type(expected)
    assert key.value == expected
    assert value == 0


@pytest.mark.parametrize(
    "encoded",
    [
        "a281000181180002",  # arrays containing shortest and non-shortest zero
        "a2a20001010200a20102000101",  # equal maps with reversed pair order
        "a2f9000001f9800002",  # positive and negative floating-point zero
        "a2f97e0001fa7fc0000002",  # one NaN significand at two widths
    ],
    ids=["array", "map-order", "signed-zero", "nan-width"],
)
def test_semantically_equal_compound_map_keys_are_duplicates(encoded: str) -> None:
    """Relaxed encoding does not relax RFC 8949 section 5.6.1 key identity."""
    with pytest.raises(CborDecodeError, match="duplicate map key"):
        loads(bytes.fromhex(encoded), deterministic=False)


def test_integer_and_numerically_equal_float_keys_stay_distinct() -> None:
    """The generic CBOR data model distinguishes integer 1 from float 1.0."""
    decoded = loads(bytes.fromhex("a20100f93c0001"))
    assert isinstance(decoded, dict)
    assert len(decoded) == 2


@pytest.mark.parametrize(
    ("name", "encoded", "expected"),
    [
        ("buuid-tag-37", bytes([0xD8, 0x25, 0x50]) + bytes(16), Tagged(37, bytes(16))),
        ("epoch-time-tag-1", bytes([0xC1, 0x1A, 0x68, 0x00, 0x00, 0x00]), Tagged(1, 0x68000000)),
        ("unknown-large-tag", bytes([0xDB, 0, 0, 0, 1, 0, 0, 0, 1, 0x01]), Tagged(0x100000001, 1)),
    ],
)
def test_the_decoder_preserves_any_well_formed_tag(name: str, encoded: bytes, expected: Tagged) -> None:
    """RFC 8949 Appendix C permits any tag over a well-formed item."""
    assert loads(encoded) == expected


@pytest.mark.parametrize(
    ("name", "encoded", "expected"),
    [
        ("float16-1.0", bytes([0xF9, 0x3C, 0x00]), 1.0),
        ("float16-0.5", bytes([0xF9, 0x38, 0x00]), 0.5),
        ("float16-negative", bytes([0xF9, 0xB8, 0x00]), -0.5),
        # Genuinely needs 32 bits: 0.1 is not representable in float16.
        ("float32-only", bytes([0xFA, 0x3D, 0xCC, 0xCC, 0xCD]), 0.10000000149011612),
        # Genuinely needs 64: 1e300 overflows both narrower widths.
        ("float64-only", bytes([0xFB, 0x7E, 0x37, 0xE4, 0x3C, 0x88, 0x00, 0x75, 0x9C]), 1e300),
        ("infinity", bytes([0xF9, 0x7C, 0x00]), float("inf")),
        ("negative-infinity", bytes([0xF9, 0xFC, 0x00]), float("-inf")),
    ],
)
def test_the_decoder_reads_floats(name: str, encoded: bytes, expected: float) -> None:
    """The CDDL puts floats in ``coordinate-map`` and ``shape-map`` (x, y, width, height),
    reachable from an action's ``changes`` field and from ``regionOfInterest`` in an
    assertion's metadata. A region expressed with a fractional coordinate -- the
    ordinary case -- made the manifest unreadable.

    All three widths, because RFC 8949 defines them as three encodings of one type and
    a decoder that read only float64 would still refuse the compact forms a
    deterministic encoder prefers.

    Every vector uses the shortest form of its value. The wider vectors are values that
    genuinely need the width: 0.1 is not representable in
    float16, and 1e300 overflows both narrower forms.
    """
    assert loads(encoded) == expected


def test_reader_and_writer_keep_their_distinct_cbor_scopes() -> None:
    """The well-formed-input reader accepts values outside the producer subset.

    Deterministic encoding is a producer obligation (RFC 8949 4.2.1) and our output is
    a wire commitment: any change to the bytes we emit is a MAJOR version of this
    package and of the vector file. Reader acceptance does not authorize writer output.
    """
    with pytest.raises(TypeError, match="float"):
        dumps(1.5)
    with pytest.raises(ValueError, match="tag 37 is not permitted"):
        dumps(Tagged(37, b"x"))


@pytest.mark.parametrize(
    ("name", "encoded_hex", "pattern"),
    [
        ("1.0-as-float64", "fb3ff0000000000000", "shortest form"),
        ("0.5-as-float32", "fa3f000000", "shortest form"),
        ("0.5-as-float64", "fb3fe0000000000000", "shortest form"),
        ("-0.5-as-float64", "fbbfe0000000000000", "shortest form"),
        ("nan-with-payload", "fb7ff8000000000001", "f97e00"),
        ("nan-as-float32", "fa7fc00000", "f97e00"),
    ],
)
def test_a_float_that_is_not_the_shortest_form_is_rejected(name: str, encoded_hex: str, pattern: str) -> None:
    """4.2.1 requires "the shortest form that preserves the value" for floats exactly
    as for integer arguments, and 4.2.2 pins NaN to ``f97e00``.

    NaN IS COMPARED ON BITS, not by value: every NaN payload is ``!= itself`` and never
    ``==`` any other NaN, so a value comparison would wave all of them through.
    """
    with pytest.raises(CborDecodeError, match=pattern):
        loads(bytes.fromhex(encoded_hex))


def test_the_canonical_nan_is_accepted() -> None:
    """``f97e00`` is the ONE NaN encoding 4.2.2 permits, and it must decode.

    Asserted separately because NaN cannot be compared by value -- it is unequal to
    itself -- so it cannot ride in the parametrized equality table above.
    """
    import math

    value = loads(bytes.fromhex("f97e00"))
    assert isinstance(value, float)
    assert math.isnan(value)


@pytest.mark.parametrize(
    ("value", "expected_hex"),
    [
        (0xFFFE, "19fffe"),
        (0xFFFF, "19ffff"),
        (0x1_0000, "1a00010000"),
    ],
    ids=["one-below", "the-boundary", "one-above"],
)
def test_the_two_byte_argument_boundary_is_exact(value: int, expected_hex: str) -> None:
    """65535 is the largest argument encoded in the two-byte form."""
    assert dumps(value).hex() == expected_hex
    assert loads(bytes.fromhex(expected_hex)) == value
