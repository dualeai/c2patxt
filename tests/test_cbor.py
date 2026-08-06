"""Deterministic CBOR: RFC 8949 4.2.1 encoding, and rejection of everything else.

Expected values come from RFC 8949 itself, not from running our encoder. cbor2 is
used only as a differential oracle, and only where the two specifications agree.
"""

from __future__ import annotations

import pathlib
import re

import cbor2
import pytest

from c2patxt._cbor import TAG_COSE_SIGN1, TAG_DATETIME, CborDecodeError, Tagged, dumps, loads
from c2patxt.constants import MAX_JUMBF_DEPTH

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
    wrong order silently produces a manifest another implementation will reject.
    """
    ours = dumps({-8: 0, 33: 0})
    theirs = cbor2.dumps({-8: 0, 33: 0}, canonical=True)

    assert ours.hex() == "a21821002700", "33 (0x1821) sorts before -8 (0x27) bytewise"
    assert theirs.hex() == "a22700182100", "cbor2 puts the shorter key first"
    assert ours != theirs, "if these ever agree, re-check which rule cbor2 implements"


def test_bytewise_and_length_first_agree_on_text_keys() -> None:
    """C2PA's actual maps are unaffected, which is why the bug is easy to miss.

    For text-string keys the CBOR head byte is monotonic in length, so bytewise
    ordering *is* length-first ordering. Asserting it keeps the claim honest.
    """
    payload = {"alg": 1, "a": 2, "signature": 3, "bb": 4}
    assert dumps(payload) == cbor2.dumps(payload, canonical=True)


def test_encoder_matches_cbor2_on_structures_c2pa_actually_uses() -> None:
    """Differential oracle, restricted to where the two specifications agree."""
    for payload in (
        {"dc:format": "text/plain", "instanceID": "urn:uuid:x"},
        {1: -8, 4: b"11", 33: [b"leaf", b"intermediate"]},
        ["Signature1", b"\xa2\x01\x27", b"", b"payload"],
        {"exclusions": [{"start": 11, "length": 74}], "alg": "sha256", "pad": b""},
    ):
        assert dumps(payload) == cbor2.dumps(payload, canonical=True)


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
    """Verifying determinism on READ is the security property cbor2 cannot give us."""
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


def test_duplicate_map_keys_are_rejected() -> None:
    with pytest.raises(CborDecodeError, match="duplicate"):
        loads(bytes.fromhex("a2616101616102"))


def test_unknown_tags_are_refused_by_the_writer_and_carried_by_the_reader() -> None:
    """The asymmetry is the design.

    It required ``loads`` to REJECT tag 1, which made a conforming third-party manifest
    unreadable: ``_parse_assertions`` turns a CborDecodeError into
    ``assertion.cbor.invalid``, so one unrecognised tag anywhere failed the whole
    manifest before verification began. 15.10.3.1 triggers only on content that "is NOT
    WELL-FORMED CBOR", defined by RFC 8949 Appendix C, whose grammar accepts any tag
    number over any well-formed item.

    ``dumps`` keeps the allowlist unchanged. Emitting is a wire commitment under 10.1's
    deterministic encoding, and we can only emit what we can round-trip faithfully.

    Tag 0 was ADDED to the writer on 2026-08-05. 18.15.12 types the actions assertion's
    ``when`` field as ``tdate``, which 6.9 defines as "serialized in CBOR as tag number
    0" -- we had been emitting an untagged text string, a different CBOR value that does
    not satisfy the CDDL.
    """
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


def test_cose_sign1_tag_round_trips() -> None:
    """Tag 18 is the one structure we must carry."""
    message = Tagged(18, [b"\xa2\x01\x27", {}, None, b"signature"])
    assert loads(dumps(message)) == message


def test_floats_are_refused_rather_than_half_implemented() -> None:
    """4.2.1's shortest-float rule is easy to get subtly wrong, and we need none."""
    with pytest.raises(TypeError, match="floats are not supported"):
        dumps(1.5)


def test_unsupported_simple_values_are_rejected() -> None:
    with pytest.raises(CborDecodeError, match="unsupported simple value"):
        loads(bytes.fromhex("f0"))  # simple(16)


def test_trailing_bytes_are_rejected() -> None:
    """A decoder that ignores trailing data lets an attacker append a second message."""
    with pytest.raises(CborDecodeError, match="trailing"):
        loads(bytes.fromhex("0001"))


def test_truncated_input_is_rejected() -> None:
    with pytest.raises(CborDecodeError, match="truncated"):
        loads(bytes.fromhex("4401"))  # declares 4 bytes, supplies 1


def test_nesting_is_bounded_both_ways() -> None:
    """A small input must not describe unbounded recursion."""
    deep: object = 0
    for _ in range(MAX_JUMBF_DEPTH + 2):
        deep = [deep]
    with pytest.raises(ValueError, match="nesting deeper"):
        dumps(deep)

    bomb = b"\x81" * (MAX_JUMBF_DEPTH + 2) + b"\x00"
    with pytest.raises(CborDecodeError, match="nesting deeper"):
        loads(bomb)


def test_bool_is_not_encoded_as_an_integer() -> None:
    """bool subclasses int; encoding True as 1 would be a silent wire-format bug."""
    assert dumps(True).hex() == "f5"
    assert dumps(1).hex() == "01"


def test_decode_error_is_picklable_and_carries_position() -> None:
    import pickle

    original = CborDecodeError("boom", 7)
    revived = pickle.loads(pickle.dumps(original))  # noqa: S301 - our own object
    assert (revived.msg, revived.pos) == ("boom", 7)


#: One RFC 8949 Appendix A item: its description and its PUBLISHED bytes.
#:
#: The sidecar's ``decoded`` field is deliberately NOT carried. It is CBOR diagnostic
#: notation, and comparing a Python value against it would mean writing an EDN parser
#: -- so the oracle for the decoded value is cbor2, an independent implementation,
#: which is stronger than a string we would have had to interpret ourselves.
_CorpusItem = tuple[str, bytes]

#: Total items across mt0-mt6. Asserted so a corpus that silently shrinks -- a bad
#: merge, a truncated download -- fails the build instead of quietly testing less.
_CORPUS_ITEM_COUNT = 70

#: Items the reader refuses, all of them non-deterministic encodings RFC 8949 4.2.1
#: and 4.2.2 forbid, plus three simple values this package does not carry. Their
#: upstream descriptions name them: "Infinity coded as f32 instead of f16".
_CORPUS_REFUSED_COUNT = 9


def _corpus_items() -> list[_CorpusItem]:
    """Parse the ``.edn`` sidecars for the published bytes and expected values.

    The ``.edn`` files were read by nothing but an ``.exists()`` check before this.
    They carry the RFC's own expectations, which is what makes them worth parsing
    rather than re-deriving the answers from a library.
    """
    items: list[_CorpusItem] = []
    for path in sorted(CBOR_VECTORS.glob("mt*.edn")):
        text = path.read_text("utf-8")
        for block in re.findall(r"\{(.*?)\}", text, re.DOTALL):
            encoded = re.search(r'"encoded":\s*h\'([0-9a-fA-F]*)\'', block)
            if encoded is None:
                continue
            described = re.search(r'"description":\s*"([^"]*)"', block)
            items.append((described.group(1) if described else path.stem, bytes.fromhex(encoded.group(1))))
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
    if isinstance(value, float):
        return True
    if isinstance(value, Tagged):
        return value.tag not in {TAG_DATETIME, TAG_COSE_SIGN1} or _only_the_reader_admits(value.value)
    if isinstance(value, list):
        return any(_only_the_reader_admits(item) for item in value)  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    if isinstance(value, dict):
        return any(_only_the_reader_admits(item) for item in value.values())  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    return False


@pytest.mark.parametrize(("description", "encoded"), _corpus_items(), ids=lambda v: str(v)[:40])
def test_each_appendix_a_item_is_accepted_correctly_or_refused_with_a_reason(description: str, encoded: bytes) -> None:
    """Every RFC 8949 Appendix A item, fed as its PUBLISHED BYTES.

    THE PREVIOUS VERSION OF THIS TEST PASSED WITH THE DECODER REPLACED BY AN
    UNCONDITIONAL RAISE. Three faults, all fixed here:
      1. it caught CborDecodeError, TypeError and ValueError and passed on each, so
         every possible outcome was accepted and the only assertion was `checked > 0`;
      2. it round-tripped each item through cbor2 first, so it tested our decoder
         against cbor2's output rather than against the RFC's published bytes;
      3. it broke after the FIRST item in each file, so "checked=7" meant seven
         items, not forty-two.

    Now: the raw bytes go to our decoder, and exactly one of two things must hold.
    ACCEPTED means the value matches cbor2's independent decode of the same bytes AND
    our encoder reproduces those bytes exactly -- deterministic encoding is what the
    claim signature depends on. REFUSED means a CborDecodeError, which is legitimate
    because the corpus covers CBOR generally and carries floats, indefinite lengths
    and tags C2PA 10.1 puts out of scope. A bare TypeError or ValueError is NOT a
    pass: those are crashes, and this decoder reads attacker-controlled bytes.
    """
    try:
        value = loads(encoded)
    except CborDecodeError:
        # Deliberate refusal, and legitimate per-item: the corpus covers CBOR generally
        # and carries floats, indefinite lengths and tags C2PA 10.1 puts out of scope.
        #
        # There is no assertion here BY DESIGN, and an earlier comment claimed one --
        # "assert it is one of the reasons we MEANT to refuse for" -- above a bare
        # return. Per item there is nothing honest to assert: any of these bytes may
        # legitimately be refused. The property that a decoder refusing EVERYTHING
        # must fail is real and lives one test down, in
        # test_the_corpus_is_neither_all_accepted_nor_all_refused, which is where it
        # can actually be expressed.
        return

    oracle = cbor2.loads(encoded)

    try:
        dumps(value)
    except (TypeError, ValueError):
        # THE READER IS DELIBERATELY WIDER THAN THE WRITER. `loads` accepts any
        # well-formed CBOR, because 15.10.3.1 rejects only content that is "NOT
        # WELL-FORMED CBOR" by RFC 8949 Appendix C, and a foreign tag or a float is
        # well-formed there. `dumps` stays narrow, because what we EMIT is a wire
        # commitment under 4.2.1.
        #
        # So byte-identical re-encoding cannot be demanded of these items. What IS
        # demanded is that the thing the writer refused really is one of the values
        # only the reader admits -- otherwise this branch would quietly absorb a
        # writer that had stopped being able to encode its own output.
        assert _only_the_reader_admits(value), f"{description}: dumps refused a value the writer is supposed to support"
        return

    if isinstance(value, Tagged) and value.tag == TAG_DATETIME:
        # cbor2 resolves tag 0 into a datetime; we keep the tagged STRING, because a
        # verifier must re-encode the exact bytes it was given and a parsed datetime
        # cannot reproduce, say, a "+00:00" offset written as "Z". Compare through
        # the reference decoder's own parse of our string instead of demanding the
        # same Python type.
        assert cbor2.loads(dumps(value)) == oracle, f"{description}: tdate disagreed"
    else:
        assert value == oracle, f"{description}: disagreed with the reference decoder"
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
_VALID_BUT_NOT_WELL_FORMED = {
    "date: unexpected object instead of offset",
    "date: unexpected object instead of string",
}

#: Items in each vendored sidecar. Asserted so a truncated download fails the build
#: rather than parametrizing over nothing.
_BAD_ITEM_COUNT = 47
_STREAMING_ITEM_COUNT = 11


@pytest.mark.parametrize(("description", "payload"), _sidecar_items("bad"), ids=lambda item: str(item)[:60])
def test_the_ill_formed_corpus_is_refused_with_our_own_error(description: str, payload: bytes) -> None:
    """cbor-wg's ``rfc8949/bad`` corpus: 47 inputs that must not decode.

    THE EXCEPTION TYPE IS PART OF THE ASSERTION. ``verify()`` is documented never to
    raise on hostile input, and it converts ``CborDecodeError`` and nothing else; a
    ``struct.error`` or an ``IndexError`` escaping the decoder would reach a caller
    from a manifest an attacker wrote.
    """
    if description in _VALID_BUT_NOT_WELL_FORMED:
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


def test_the_corpus_is_neither_all_accepted_nor_all_refused() -> None:
    """The test above passes vacuously if the decoder refuses EVERYTHING.

    BOTH ARMS ARE POPULATED, and what fills the refused arm is the point. 61 items
    decode; 9 do not, and every one of the 9 is a form RFC 8949 forbids in deterministic
    encoding -- six non-shortest-form floats and non-canonical NaNs whose own upstream
    descriptions say so ("Infinity coded as f32 instead of f16"), and three simple
    values this package does not carry.

    That is 4.2.1 and 4.2.2 enforcement asserted against SOMEBODY ELSE'S published
    bytes rather than against vectors written here. 15.10.3.1 gives no licence to refuse
    well-formed CBOR, so the 61 are the floor; determinism is what earns the 9.
    """

    def decodes(payload: bytes) -> bool:
        try:
            loads(payload)
        except CborDecodeError:
            return False
        return True

    accepted = sum(decodes(encoded) for _, encoded in _corpus_items())
    assert accepted == _CORPUS_ITEM_COUNT - _CORPUS_REFUSED_COUNT, (
        f"{accepted} of {_CORPUS_ITEM_COUNT} items decoded; every Appendix A item is "
        "well-formed CBOR, and 15.10.3.1 rejects only content that is not -- so a drop "
        "here is a false reject, and a rise means determinism enforcement was dropped"
    )

    def writer_refuses(payload: bytes) -> bool:
        try:
            dumps(loads(payload))
        except (CborDecodeError, TypeError, ValueError):
            return True
        return False

    # COUNTED BY REASON, not in aggregate. Stated as one number this was carried
    # entirely by tags, and mutating `dumps` to emit float64 -- a MAJOR wire change --
    # left it green. Each half now says what it checks.
    #
    # ONLY ITEMS THE READER ACCEPTS ARE CLASSIFIED. `writer_refuses` returns True both
    # when `dumps` refuses a value and when `loads` never produced one, so classifying
    # its output means decoding a second time; for the nine items the reader rejects,
    # that raises out of the test.
    refused_for_tag = refused_for_float = 0
    for _, encoded in _corpus_items():
        if not decodes(encoded) or not writer_refuses(encoded):
            continue
        value = loads(encoded)
        members = value if isinstance(value, list) else [value]
        if isinstance(value, Tagged) or any(isinstance(i, Tagged) for i in members):
            refused_for_tag += 1
        if isinstance(value, float) or any(isinstance(i, float) for i in members):
            refused_for_float += 1

    assert refused_for_tag >= 1, "the writer accepted every tagged item; it is supposed to emit only tags 0 and 18"
    assert refused_for_float >= 1, "the writer accepted a float from the corpus; dumps emits no floats"


def test_argument_beyond_the_64_bit_range_is_refused() -> None:
    """CBOR arguments are at most 64 bits; a bigint has no representation."""
    with pytest.raises(ValueError, match="64-bit CBOR range"):
        dumps(1 << 64)


def test_unsupported_python_types_are_refused() -> None:
    with pytest.raises(TypeError, match="cannot encode set"):
        dumps({1, 2, 3})


def test_encoder_refuses_a_map_with_two_equal_keys() -> None:
    """Distinct Python keys can encode identically; the wire form must stay unique.

    A dict cannot hold two equal keys, so this drives the pair list the encoder
    consumes directly.
    """
    from c2patxt._cbor import _encode_map  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(ValueError, match="duplicate map key"):
        _encode_map([("a", 1), ("a", 2)], 0)


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


def test_non_scalar_map_keys_are_rejected() -> None:
    """C2PA maps key on integers and text; an array key is malformed input.

    a1 80 00 -- a one-entry map whose key is an empty array.
    """
    with pytest.raises(CborDecodeError, match="map keys must be"):
        loads(bytes.fromhex("a18000"))


@pytest.mark.parametrize(
    ("name", "encoded", "expected"),
    [
        ("buuid-tag-37", bytes([0xD8, 0x25, 0x50]) + bytes(16), Tagged(37, bytes(16))),
        ("epoch-time-tag-1", bytes([0xC1, 0x1A, 0x68, 0x00, 0x00, 0x00]), Tagged(1, 0x68000000)),
        ("unknown-large-tag", bytes([0xDB, 0, 0, 0, 1, 0, 0, 0, 1, 0x01]), Tagged(0x100000001, 1)),
    ],
)
def test_the_decoder_preserves_any_well_formed_tag(name: str, encoded: bytes, expected: Tagged) -> None:
    """A tag outside our own two was rejected outright, failing the whole manifest.

    ``_ALLOWED_TAGS`` was ``{0, 18}``, so anything else raised, ``_parse_assertions``
    turned that into ``assertion.cbor.invalid``, and a conforming third-party manifest
    was refused before verification began.

    15.10.3.1 triggers on content that "is NOT WELL-FORMED CBOR", and says "Well-formed
    CBOR is defined in RFC 8949, Appendix C". A tagged item IS well-formed there --
    Appendix C's grammar accepts any tag number over any well-formed item, and says
    nothing about which tags a consumer recognises. We were refusing conforming CBOR on
    a well-formedness rule.

    Two the C2PA CDDL actually names: ``buuid = #6.37(bstr)``, used by ``instanceID`` in
    the action-items map, and tag 1 epoch time. The third is a tag nobody has defined --
    preserved rather than rejected, because a decoder's job is to report what the bytes
    say. Whether a tag is ALLOWED in a given position is a validation question the CDDL
    answers, not a well-formedness question the decoder answers.
    """
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
    """Floats were "unsupported simple value", which is the same false reject.

    The CDDL puts floats in ``coordinate-map`` and ``shape-map`` (x, y, width, height),
    reachable from an action's ``changes`` field and from ``regionOfInterest`` in an
    assertion's metadata. A region expressed with a fractional coordinate -- the
    ordinary case -- made the manifest unreadable.

    All three widths, because RFC 8949 defines them as three encodings of one type and
    a decoder that read only float64 would still refuse the compact forms a
    deterministic encoder prefers.

    EVERY VECTOR HERE IS THE SHORTEST FORM OF ITS VALUE. Three of these once were not
    -- 0.5 was written as float32 and as float64, and -0.5 as float64 -- which asserted
    that the decoder accepts encodings 4.2.1 forbids, 380 lines below the test whose
    docstring calls determinism-on-read the reason this module exists. The wider
    vectors are values that genuinely need the width: 0.1 is not representable in
    float16, and 1e300 overflows both narrower forms.
    """
    assert loads(encoded) == expected


def test_the_producer_still_refuses_to_emit_what_the_reader_now_accepts() -> None:
    """Widening the READER must not widen the WRITER.

    Deterministic encoding is a producer obligation (RFC 8949 4.2.1) and our output is
    a wire commitment: any change to the bytes we emit is a MAJOR version of this
    package and of the vector file. Accepting a float on the way in says nothing about
    emitting one on the way out, and this is the assertion that keeps those separate.
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

    THIS WAS BROKEN BY THE CHANGE THAT ADDED FLOAT SUPPORT. ``_argument`` had always
    refused a non-shortest integer; ``_simple`` gained floats with no equivalent rule,
    so ``fb3ff0000000000000`` decoded to 1.0 where the RFC requires ``f93c00``. That
    contradicted the module's leading claim -- a decoder that rejects non-deterministic
    input is a security property no general-purpose library offers -- and three of the
    accept-side vectors asserted the hole rather than catching it.

    NaN IS COMPARED ON BITS, not by value: every NaN payload is ``!= itself`` and never
    ``==`` any other NaN, so a value comparison would wave all of them through.
    """
    with pytest.raises(CborDecodeError, match=pattern):
        loads(bytes.fromhex(encoded_hex))


def test_the_canonical_nan_is_accepted() -> None:
    """``f97e00`` is the ONE NaN encoding 4.2.2 permits, and it must decode.

    Asserted separately because NaN cannot be compared by value -- it is unequal to
    itself -- so it cannot ride in the parametrized table above, which compares with
    ``==``. Without this the accept branch of the NaN check had never run: every NaN
    test drove a rejection.
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
    """65535 is the largest argument the two-byte form holds, and it had no vector.

    The 24 and 255 boundaries are covered; this one was not, so ``_FITS_2BYTE = 0xFFFF``
    could become ``0xFFFE`` and pass. The consequence is self-inflicted: 65535 would
    then encode in the FOUR-byte form, which OUR OWN decoder rejects as non-shortest.
    A producer and consumer in the same file, disagreeing.
    """
    assert dumps(value).hex() == expected_hex
    assert loads(bytes.fromhex(expected_hex)) == value
