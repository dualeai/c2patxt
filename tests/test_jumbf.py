"""JUMBF box codec against C2PA 2.4 and ISO 19566-5 field rules."""

from __future__ import annotations

import struct

import pytest

from c2patxt._jumbf import (
    TBOX_DESCRIPTION,
    TBOX_SUPERBOX,
    UUID_CBOR,
    DescriptionBox,
    JumbfBox,
    JumbfError,
    Toggle,
    content_type_uuid,
    parse_superbox,
    serialize_superbox,
)


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
    """C2PA 11.1.1: <4CC> || 00 11 00 10 80 00 00 AA 00 38 9B 71."""
    got = content_type_uuid(four_cc).hex()
    assert f"{got[:8]}-{got[8:12]}-{got[12:16]}-{got[16:20]}-{got[20:]}" == expected


def test_a_four_cc_must_be_four_bytes() -> None:
    with pytest.raises(ValueError, match="four bytes"):
        content_type_uuid(b"cbo")


def test_toggle_bit_values() -> None:
    """ISO 19566-5:2023 A.3 assigns the five description-box toggle bits."""
    assert (Toggle.REQUESTABLE, Toggle.LABEL, Toggle.ID) == (0x01, 0x02, 0x04)
    assert (Toggle.SIGNATURE, Toggle.PRIVATE) == (0x08, 0x10)


def test_description_with_every_field_matches_the_iso_layout() -> None:
    private = struct.pack(">I", 12) + b"c2sh" + b"\xaa" * 4
    description = DescriptionBox(
        uuid=UUID_CBOR,
        label="c2pa.assertions",
        requestable=True,
        box_id=60000,
        signature=bytes(range(32)),
        private=private,
    )
    description_payload = (
        UUID_CBOR + b"\x1f" + b"c2pa.assertions\x00" + (60000).to_bytes(4, "big") + bytes(range(32)) + private
    )
    description_box = struct.pack(">I", 8 + len(description_payload)) + b"jumd" + description_payload
    content_box = struct.pack(">I", 10) + b"cbor" + b"\x01\x02"
    expected = struct.pack(">I", 8 + len(description_box) + len(content_box)) + b"jumb" + description_box + content_box

    assert _superbox(description) == expected
    parsed, end = parse_superbox(expected)
    assert parsed.description == description
    assert end == len(expected)


def test_the_signature_field_is_thirty_two_bytes() -> None:
    """ISO 19566-5 A.3 fixes the SHA-256 signature field at 32 bytes."""
    with pytest.raises(ValueError, match="32-byte SHA-256"):
        DescriptionBox(uuid=UUID_CBOR, label="x", signature=b"\x00" * 256)


def test_a_requestable_box_must_carry_a_label() -> None:
    """ISO 19566-5 A.3 requires a label when Requestable is set."""
    with pytest.raises(ValueError, match="non-empty label"):
        DescriptionBox(uuid=UUID_CBOR, label=None, requestable=True)


@pytest.mark.parametrize("char", ["/", ";", "?", "#", "\x01", "\x7f", "﻿", "￿"])
def test_forbidden_label_characters_are_rejected(char: str) -> None:
    """C2PA 11.1.4.1.1 forbids these label code points."""
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
    """ISO 19566-5 clause 4.3 reserves LBox values 2 through 7."""
    data = struct.pack(">I", lbox) + TBOX_SUPERBOX + b"\x00" * 32
    with pytest.raises(JumbfError, match="reserved"):
        parse_superbox(data)


def test_reserved_toggle_bits_are_rejected() -> None:
    """ISO 19566-5 A.3 assigns bits 0 through 4; higher bits are reserved."""
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


def test_multiple_content_boxes_match_the_iso_box_layout() -> None:
    uuid = content_type_uuid(b"uuid")
    box = JumbfBox(
        description=DescriptionBox(uuid=uuid, label="c2pa"),
        content=((b"cbor", b"\x01"), (b"json", b"{}"), (b"free", b"\x00\x00")),
    )
    description_payload = uuid + b"\x03c2pa\x00"
    description = struct.pack(">I", 8 + len(description_payload)) + b"jumd" + description_payload
    contents = b"".join(
        (
            struct.pack(">I", 9) + b"cbor" + b"\x01",
            struct.pack(">I", 10) + b"json" + b"{}",
            struct.pack(">I", 10) + b"free" + b"\x00\x00",
        )
    )
    expected = struct.pack(">I", 8 + len(description) + len(contents)) + b"jumb" + description + contents

    assert serialize_superbox(box) == expected
    parsed, _ = parse_superbox(expected)
    assert parsed.content == box.content


def test_a_nul_in_a_label_is_rejected() -> None:
    """NUL is the terminator, so it cannot also be content."""
    with pytest.raises(ValueError, match="cannot contain NUL"):
        DescriptionBox(uuid=UUID_CBOR, label="bad\x00label")


def test_a_surrogate_in_a_label_is_rejected() -> None:
    """C2PA 11.1.4.1.1 forbids U+D800-U+DFFF because labels appear in JUMBF URIs."""
    with pytest.raises(ValueError, match="surrogates"):
        DescriptionBox(uuid=UUID_CBOR, label="bad\ud800label")
