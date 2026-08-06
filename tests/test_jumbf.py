"""JUMBF box codec: the wire format, and the bugs other implementations shipped.

Expected values come from the four corroborating sources described in
``_jumbf.py``, not from running our encoder.
"""

from __future__ import annotations

import struct

import pytest

from c2patxt._jumbf import (
    TBOX_DESCRIPTION,
    TBOX_SUPERBOX,
    UUID_CBOR,
    UUID_CONTIGUOUS_CODESTREAM,
    UUID_EMBEDDED_FILE,
    UUID_JSON,
    UUID_UUID,
    UUID_XML,
    DescriptionBox,
    JumbfBox,
    JumbfError,
    Toggle,
    content_type_uuid,
    parse_superbox,
    serialize_superbox,
)
from c2patxt.constants import MAX_JUMBF_DEPTH


def _superbox(description: DescriptionBox, payload: bytes = b"\x01\x02") -> bytes:
    return serialize_superbox(JumbfBox(description=description, content=((b"cbor", payload),)))


@pytest.mark.parametrize(
    ("four_cc", "expected"),
    [
        (b"cbor", "63626f72-0011-0010-8000-00aa00389b71"),
        (b"json", "6a736f6e-0011-0010-8000-00aa00389b71"),
        (b"xml ", "786d6c20-0011-0010-8000-00aa00389b71"),
        (b"uuid", "75756964-0011-0010-8000-00aa00389b71"),
        (b"c2pa", "63327061-0011-0010-8000-00aa00389b71"),
        (b"c2ma", "63326d61-0011-0010-8000-00aa00389b71"),
        (b"c2cl", "6332636c-0011-0010-8000-00aa00389b71"),
        (b"c2cs", "63326373-0011-0010-8000-00aa00389b71"),
    ],
)
def test_content_type_uuid_pattern(four_cc: bytes, expected: str) -> None:
    """<4CC> || 00 11 00 10 80 00 00 AA 00 38 9B 71, confirmed in WG1 RI-1 source."""
    got = content_type_uuid(four_cc).hex()
    assert f"{got[:8]}-{got[8:12]}-{got[12:16]}-{got[16:20]}-{got[20:]}" == expected


def test_the_two_uuids_that_break_the_pattern() -> None:
    """Both confirmed in WG1 RI-1 source AND in real file bytes.

    An implementation that derived these from their 4CCs would produce UUIDs no
    other implementation recognises.
    """
    assert UUID_EMBEDDED_FILE.hex() == "40cb0c32bb8a489da70b2ad6f47f4369"
    assert UUID_CONTIGUOUS_CODESTREAM.hex() == "6579d6fbdba2446bb2ac1b82feeb89d1"
    assert content_type_uuid(b"bfdb") != UUID_EMBEDDED_FILE
    assert content_type_uuid(b"jp2c") != UUID_CONTIGUOUS_CODESTREAM


def test_xml_content_type_pads_its_4cc_with_a_space() -> None:
    """ "xml " is three letters and a 0x20, not three letters."""
    assert UUID_XML[:4] == b"xml "
    assert UUID_XML[3] == 0x20


def test_a_four_cc_must_be_four_bytes() -> None:
    with pytest.raises(ValueError, match="four bytes"):
        content_type_uuid(b"cbo")


def test_toggle_bit_values() -> None:
    """0x04 and 0x08 are confirmed 4374/4374 against WG1 ground truth."""
    assert (Toggle.REQUESTABLE, Toggle.LABEL, Toggle.ID) == (0x01, 0x02, 0x04)
    assert (Toggle.SIGNATURE, Toggle.PRIVATE) == (0x08, 0x10)


def test_description_round_trips_with_every_field_set() -> None:
    description = DescriptionBox(
        uuid=UUID_CBOR,
        label="c2pa.assertions",
        requestable=True,
        box_id=60000,
        signature=bytes(range(32)),
        private=struct.pack(">I", 12) + b"c2sh" + b"\xaa" * 4,
    )
    assert description.toggles == 0x1F

    parsed, end = parse_superbox(_superbox(description))
    assert parsed.description == description
    assert end == len(_superbox(description))


def test_a_label_only_box_parses() -> None:
    """toggles=0x02 with no Requestable bit.

    c2pa-rs requires ``(toggles & 0x03) == 0x03`` before reading a label and so FAILS
    on this legal box. Five independent implementations test 0x02 alone, and real
    files carry such boxes: a parse of image_5jumbf.jpg APP11 #1 showed toggles=0x02
    with the label 'faiz mp3 data'. That asset is not vendored and the observation is
    not reproducible here -- see docs/known-divergences.md.
    """
    description = DescriptionBox(uuid=UUID_JSON, label="my xml data", requestable=False)
    assert description.toggles == Toggle.LABEL

    parsed, _ = parse_superbox(_superbox(description))
    assert parsed.description.label == "my xml data"
    assert parsed.description.requestable is False


def test_the_id_field_is_four_bytes_big_endian() -> None:
    """faceless2/c2pa reads two bytes and clamps at 65535; it is alone against ~8."""
    description = DescriptionBox(uuid=UUID_CBOR, label="x", box_id=0xDEADBEEF)
    parsed, _ = parse_superbox(_superbox(description))
    assert parsed.description.box_id == 0xDEADBEEF


def test_the_signature_field_is_thirty_two_bytes() -> None:
    """WG1 RI-2's deserialize() reads 256; its own serialize() writes 32."""
    with pytest.raises(ValueError, match="32-byte SHA-256"):
        DescriptionBox(uuid=UUID_CBOR, label="x", signature=b"\x00" * 256)


def test_the_private_field_is_kept_generic() -> None:
    """Real Adobe assets carry toggles=0x13 with a 24-byte 'c2sh' salt box.

    A parser that stops after the signature mis-reads genuine Adobe and Monotype
    output. Modelled as opaque bytes rather than hard-coding 'c2sh', matching WG1
    RI-1, dbench, jumbf-rs and MediaInfo.
    """
    salt_box = struct.pack(">I", 24) + b"c2sh" + bytes(range(16))
    description = DescriptionBox(uuid=UUID_JSON, label="stds.schema-org.CreativeWork", private=salt_box)
    assert description.toggles == 0x13

    parsed, _ = parse_superbox(_superbox(description))
    assert parsed.description.private == salt_box


def test_a_requestable_box_must_carry_a_label() -> None:
    """WG1 RI-1 enforces this; a URI reference needs something to point at."""
    with pytest.raises(ValueError, match="non-empty label"):
        DescriptionBox(uuid=UUID_CBOR, label=None, requestable=True)


@pytest.mark.parametrize("char", ["/", ";", "?", "#", "\x01", "\x7f", "﻿", "￿"])
def test_forbidden_label_characters_are_rejected(char: str) -> None:
    """C2PA 11.1.4.1.1. No implementation surveyed in docs/known-divergences.md
    enforces these -- we do.

    U+FEFF is on the list, which is a quiet irony given it is our wrapper marker.
    """
    with pytest.raises(ValueError, match=r"not permitted|surrogates"):
        DescriptionBox(uuid=UUID_CBOR, label=f"bad{char}label")


def test_a_uuid_must_be_sixteen_bytes() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        DescriptionBox(uuid=b"short", label="x")


def test_xlbox_is_read_when_lbox_is_one() -> None:
    """Clause 4.3: LBox == 1 means an 8-byte XLBox follows the TBox."""
    inner = _superbox(DescriptionBox(uuid=UUID_CBOR, label="x"))
    body = inner[8:]  # strip the 4-byte LBox and 4-byte TBox
    xl = struct.pack(">I", 1) + TBOX_SUPERBOX + struct.pack(">Q", len(body) + 16) + body

    parsed, end = parse_superbox(xl)
    assert parsed.description.label == "x"
    assert end == len(xl)


def test_lbox_zero_means_to_end_of_data() -> None:
    """Clause 4.3: "the box contains all bytes up to the end of the file"."""
    inner = _superbox(DescriptionBox(uuid=UUID_CBOR, label="x"))
    to_end = struct.pack(">I", 0) + TBOX_SUPERBOX + inner[8:]
    parsed, end = parse_superbox(to_end)
    assert parsed.description.label == "x"
    assert end == len(to_end)


@pytest.mark.parametrize("lbox", [2, 3, 4, 5, 6, 7])
def test_reserved_lbox_values_are_rejected(lbox: int) -> None:
    """Clause 4.3: "the values 2-7 are reserved".

    MediaInfo guesses read-to-EOF here and dbench takes the value literally. Both
    are guesses at undefined behaviour; erroring is the conservative reading.
    """
    data = struct.pack(">I", lbox) + TBOX_SUPERBOX + b"\x00" * 32
    with pytest.raises(JumbfError, match="reserved"):
        parse_superbox(data)


def test_reserved_toggle_bits_are_rejected() -> None:
    """Bits 5-7 are never set in 4,374 conformance files. Do not guess at them."""
    payload = UUID_CBOR + bytes([0x80])
    inner = struct.pack(">I", 8 + len(payload)) + TBOX_DESCRIPTION + payload
    data = struct.pack(">I", 8 + len(inner)) + TBOX_SUPERBOX + inner
    with pytest.raises(JumbfError, match="reserved toggle"):
        parse_superbox(data)


def test_a_superbox_must_begin_with_a_description_box() -> None:
    """ISO 19566-5 A.2: the jumd box is always first."""
    inner = struct.pack(">I", 10) + b"cbor" + b"\x01\x02"
    data = struct.pack(">I", 8 + len(inner)) + TBOX_SUPERBOX + inner
    with pytest.raises(JumbfError, match="must begin with a jumd"):
        parse_superbox(data)


def test_a_superbox_must_carry_content() -> None:
    """A.2: "one or more Content Boxes"."""
    description = struct.pack(">I", 8 + 17) + TBOX_DESCRIPTION + UUID_CBOR + bytes([0x00])
    data = struct.pack(">I", 8 + len(description)) + TBOX_SUPERBOX + description
    with pytest.raises(JumbfError, match="at least one content box"):
        parse_superbox(data)


def test_a_non_superbox_at_the_top_level_is_rejected() -> None:
    data = struct.pack(">I", 10) + b"cbor" + b"\x01\x02"
    with pytest.raises(JumbfError, match="expected a jumb superbox"):
        parse_superbox(data)


@pytest.mark.parametrize(
    ("data", "pattern"),
    [
        (b"\x00\x00", "truncated box header"),
        (struct.pack(">I", 1) + TBOX_SUPERBOX + b"\x00", "truncated XLBox"),
        (struct.pack(">I", 8) + TBOX_SUPERBOX, "truncated box header"),
        (struct.pack(">I", 999) + TBOX_SUPERBOX + b"\x00" * 4, "only"),
    ],
)
def test_malformed_input_is_rejected_with_an_offset(data: bytes, pattern: str) -> None:
    with pytest.raises(JumbfError, match=pattern) as excinfo:
        parse_superbox(data)
    assert excinfo.value.pos >= 0


def test_an_lbox_shorter_than_a_header_is_rejected() -> None:
    data = struct.pack(">I", 8) + TBOX_SUPERBOX + struct.pack(">I", 9) + TBOX_DESCRIPTION
    with pytest.raises(JumbfError):
        parse_superbox(data)


def test_a_child_box_may_not_overrun_its_superbox() -> None:
    description = struct.pack(">I", 8 + 17) + TBOX_DESCRIPTION + UUID_CBOR + bytes([0x00])
    child = struct.pack(">I", 500) + b"cbor"
    body = description + child
    data = struct.pack(">I", 8 + len(body)) + TBOX_SUPERBOX + body
    with pytest.raises(JumbfError, match="overruns"):
        parse_superbox(data)


def test_nesting_is_bounded() -> None:
    inner = _superbox(DescriptionBox(uuid=UUID_CBOR, label="x"))
    with pytest.raises(JumbfError, match="nesting deeper"):
        parse_superbox(inner, depth=MAX_JUMBF_DEPTH + 1)


def test_a_label_must_be_nul_terminated() -> None:
    payload = UUID_CBOR + bytes([Toggle.LABEL]) + b"no terminator"
    inner = struct.pack(">I", 8 + len(payload)) + TBOX_DESCRIPTION + payload
    data = struct.pack(">I", 8 + len(inner)) + TBOX_SUPERBOX + inner
    with pytest.raises(JumbfError, match="NUL-terminated"):
        parse_superbox(data)


def test_an_invalid_utf8_label_is_rejected() -> None:
    payload = UUID_CBOR + bytes([Toggle.LABEL]) + b"\xff\x00"
    inner = struct.pack(">I", 8 + len(payload)) + TBOX_DESCRIPTION + payload
    data = struct.pack(">I", 8 + len(inner)) + TBOX_SUPERBOX + inner
    with pytest.raises(JumbfError, match="not valid UTF-8"):
        parse_superbox(data)


@pytest.mark.parametrize("toggle", [Toggle.ID, Toggle.SIGNATURE])
def test_truncated_optional_fields_are_rejected(toggle: int) -> None:
    payload = UUID_CBOR + bytes([Toggle.LABEL | toggle]) + b"x\x00" + b"\x01"
    inner = struct.pack(">I", 8 + len(payload)) + TBOX_DESCRIPTION + payload
    data = struct.pack(">I", 8 + len(inner)) + TBOX_SUPERBOX + inner
    with pytest.raises(JumbfError, match="truncated"):
        parse_superbox(data)


def test_trailing_bytes_without_the_private_toggle_are_rejected() -> None:
    """Silently ignoring them would let an attacker smuggle data past a hash."""
    payload = UUID_CBOR + bytes([Toggle.LABEL]) + b"x\x00" + b"extra"
    inner = struct.pack(">I", 8 + len(payload)) + TBOX_DESCRIPTION + payload
    data = struct.pack(">I", 8 + len(inner)) + TBOX_SUPERBOX + inner
    with pytest.raises(JumbfError, match="trailing"):
        parse_superbox(data)


def test_multiple_content_boxes_round_trip() -> None:
    box = JumbfBox(
        description=DescriptionBox(uuid=UUID_UUID, label="c2pa"),
        content=((b"cbor", b"\x01"), (b"json", b"{}"), (b"free", b"\x00\x00")),
    )
    parsed, _ = parse_superbox(serialize_superbox(box))
    assert parsed.content == box.content


def test_error_is_picklable_and_carries_position() -> None:
    import pickle

    revived = pickle.loads(pickle.dumps(JumbfError("boom", 12)))  # noqa: S301 - our own object
    assert (revived.msg, revived.pos) == ("boom", 12)


def test_a_nul_in_a_label_is_rejected() -> None:
    """NUL is the terminator, so it cannot also be content."""
    with pytest.raises(ValueError, match="cannot contain NUL"):
        DescriptionBox(uuid=UUID_CBOR, label="bad\x00label")


def test_a_surrogate_in_a_label_is_rejected() -> None:
    """C2PA 11.1.4.1.1 forbids U+D800-U+DFFF because labels appear in JUMBF URIs."""
    with pytest.raises(ValueError, match="surrogates"):
        DescriptionBox(uuid=UUID_CBOR, label="bad\ud800label")
