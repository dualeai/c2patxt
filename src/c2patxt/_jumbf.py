"""JUMBF, ISO/IEC 19566-5:2023 as constrained by C2PA 2.4 clause 11.1.

The box layout follows ISO/IEC 19566-5; its public SIST preview includes the
LBox/XLBox/TBox rules used here. C2PA 11.1 constrains the description boxes and content
types. ISO BMFF/JUMBF box fields use big-endian byte order.
"""

from __future__ import annotations

import dataclasses
import struct

# Box type codes (4CC), ISO 19566-5 Table A.1.
TBOX_SUPERBOX = b"jumb"
TBOX_DESCRIPTION = b"jumd"

# Content-type UUID suffix. Every type-derived UUID is the 4CC followed by this.
_UUID_SUFFIX = bytes.fromhex("0011001080000 0AA00389B71".replace(" ", ""))

_LBOX_SIZE = 4
_TBOX_SIZE = 4
_XLBOX_SIZE = 8
_HEADER_SIZE = _LBOX_SIZE + _TBOX_SIZE
_UUID_SIZE = 16
_ID_SIZE = 4
_HASH_SIZE = 32

_LBOX_XLBOX_FOLLOWS = 1
_LBOX_TO_END = 0
_LBOX_RESERVED_MAX = 7

# Characters forbidden in a label by C2PA 11.1.4.1.1.
_FORBIDDEN_LABEL_CHARS = frozenset("/;?#\ufeff\uffff")

# C0 controls, DEL and the C1 range, plus the surrogate range. Named because the
# bare hex reads as noise at the point of use.
_C0_MAX = 0x1F
_DEL = 0x7F
_C1_MAX = 0x9F
_SURROGATE_MIN = 0xD800
_SURROGATE_MAX = 0xDFFF


class Toggle:
    """jumd toggle bits, and the field each one gates.

    Bit 0x10 is part of the 2023 edition; its foreword lists the CBOR content type,
    Padding Box and private description entry among that edition's additions.
    """

    REQUESTABLE = 0x01
    LABEL = 0x02
    ID = 0x04
    SIGNATURE = 0x08
    PRIVATE = 0x10

    #: Bits 5-7 are reserved by ISO/IEC 19566-5.
    RESERVED = 0xE0


class JumbfError(ValueError):
    """Malformed JUMBF. Carries the byte offset at which parsing stopped."""

    def __init__(self, msg: str, pos: int) -> None:
        self.msg = msg
        self.pos = pos
        super().__init__(f"{msg} (at byte {pos})")


def content_type_uuid(four_cc: bytes) -> bytes:
    """Build a content-type UUID from its 4CC.

    The pattern is ``<4 ASCII bytes> || 00 11 00 10 80 00 00 AA 00 38 9B 71``, e.g.
    ``cbor`` gives ``63626F72-0011-0010-8000-00AA00389B71``. This helper applies only
    to type-derived UUIDs; fixed UUIDs such as Embedded File are declared separately.
    """
    if len(four_cc) != _TBOX_SIZE:
        msg = f"a 4CC is four bytes, got {len(four_cc)}"
        raise ValueError(msg)
    return four_cc + _UUID_SUFFIX


UUID_CBOR = content_type_uuid(b"cbor")
UUID_JSON = content_type_uuid(b"json")


@dataclasses.dataclass(frozen=True, slots=True)
class DescriptionBox:
    """A ``jumd`` description box (ISO 19566-5 A.3).

    Field order and sizes::

        uuid(16) | toggles(1) | label(var, NUL-terminated) | id(4) | sha256(32) | private
    """

    uuid: bytes
    label: str | None = None
    requestable: bool = True
    box_id: int | None = None
    signature: bytes | None = None
    private: bytes | None = None

    def __post_init__(self) -> None:
        """Validate the box, raising :class:`JumbfError` for invalid fields."""
        if len(self.uuid) != _UUID_SIZE:
            msg = f"a JUMBF UUID is 16 bytes, got {len(self.uuid)}"
            raise JumbfError(msg, 0)
        if self.requestable and not self.label:
            # A requestable box must have a label so a JUMBF URI can name it.
            msg = "a requestable description box must carry a non-empty label"
            raise JumbfError(msg, 0)
        if self.label is not None:
            _validate_label(self.label)
        if self.signature is not None and len(self.signature) != _HASH_SIZE:
            msg = f"the jumd signature field is a 32-byte SHA-256, got {len(self.signature)}"
            raise JumbfError(msg, 0)

    @property
    def toggles(self) -> int:
        value = 0
        if self.requestable:
            value |= Toggle.REQUESTABLE
        if self.label is not None:
            value |= Toggle.LABEL
        if self.box_id is not None:
            value |= Toggle.ID
        if self.signature is not None:
            value |= Toggle.SIGNATURE
        if self.private is not None:
            value |= Toggle.PRIVATE
        return value


def _validate_label(label: str) -> None:
    """Apply the C2PA 11.1.4.1.1 label rules."""
    if "\x00" in label:
        msg = "a label is NUL-terminated and cannot contain NUL"
        raise JumbfError(msg, 0)
    for char in label:
        if char in _FORBIDDEN_LABEL_CHARS or ord(char) <= _C0_MAX or _DEL <= ord(char) <= _C1_MAX:
            msg = f"character U+{ord(char):04X} is not permitted in a JUMBF label"
            raise JumbfError(msg, 0)
        if _SURROGATE_MIN <= ord(char) <= _SURROGATE_MAX:
            msg = "surrogates are not permitted in a JUMBF label"
            raise JumbfError(msg, 0)


@dataclasses.dataclass(frozen=True, slots=True)
class JumbfBox:
    """A JUMBF superbox: one description box followed by one or more content boxes.

    ISO 19566-5 A.2: "shall contain exactly one JUMBF Description box followed by one
    or more Content Boxes... The JUMBF Description box shall always be the first box
    in the JUMBF superbox."
    """

    description: DescriptionBox
    content: tuple[tuple[bytes, bytes], ...]
    """(TBox, payload) pairs. Payloads are opaque here; nested superboxes are
    re-parsed by the caller so this module stays a pure box codec."""


def _box(tbox: bytes, payload: bytes) -> bytes:
    """Serialize one box with a 4-byte big-endian LBox covering the whole box."""
    return struct.pack(">I", _HEADER_SIZE + len(payload)) + tbox + payload


def _serialize_description(description: DescriptionBox) -> bytes:
    out = bytearray(description.uuid)
    out.append(description.toggles)
    if description.label is not None:
        out += description.label.encode("utf-8") + b"\x00"
    if description.box_id is not None:
        out += struct.pack(">I", description.box_id)
    if description.signature is not None:
        out += description.signature
    if description.private is not None:
        out += description.private
    return _box(TBOX_DESCRIPTION, bytes(out))


def serialize_superbox(box: JumbfBox) -> bytes:
    """Serialize a superbox and its contents."""
    body = b"".join(
        (
            _serialize_description(box.description),
            *(_box(tbox, payload) for tbox, payload in box.content),
        )
    )
    return _box(TBOX_SUPERBOX, body)


def _read_header(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read LBox/TBox/XLBox. Returns (box_length, tbox, payload_offset).

    ISO 19566-5 clause 4.3, quoted verbatim from the published sample: LBox is a
    4-byte big-endian integer covering the whole box; ``LBox == 1`` means an 8-byte
    XLBox follows the TBox and carries the real length; ``LBox == 0`` means the box
    runs to the end of the file; "the values 2-7 are reserved".
    """
    if offset + _HEADER_SIZE > len(data):
        msg = "truncated box header"
        raise JumbfError(msg, offset)

    (lbox,) = struct.unpack(">I", data[offset : offset + _LBOX_SIZE])
    tbox = data[offset + _LBOX_SIZE : offset + _HEADER_SIZE]
    payload_offset = offset + _HEADER_SIZE

    if lbox == _LBOX_XLBOX_FOLLOWS:
        if payload_offset + _XLBOX_SIZE > len(data):
            msg = "truncated XLBox"
            raise JumbfError(msg, payload_offset)
        (length,) = struct.unpack(">Q", data[payload_offset : payload_offset + _XLBOX_SIZE])
        # The XLBox value covers LBox + TBox + XLBox itself, so anything below that
        # is structurally impossible. Without this guard a declared 0 makes the
        # content loop advance by nothing and spin forever, and a value between 1
        # and 15 leaves payload_offset past the box end, so the loop resumes INSIDE
        # the XLBox field and can report a fabricated box in place of a real one.
        if length < _HEADER_SIZE + _XLBOX_SIZE:
            msg = f"XLBox {length} is shorter than the header it must cover"
            raise JumbfError(msg, payload_offset)
        return length, tbox, payload_offset + _XLBOX_SIZE
    if lbox == _LBOX_TO_END:
        return len(data) - offset, tbox, payload_offset
    if lbox <= _LBOX_RESERVED_MAX:
        msg = f"LBox value {lbox} is reserved by ISO 19566-5 clause 4.3"
        raise JumbfError(msg, offset)
    # 0 and 1 are handled above and 2-7 are reserved, so a plain LBox reaching this
    # point is already at least _HEADER_SIZE. The XLBox path is bounded separately.
    return lbox, tbox, payload_offset


def _parse_description(payload: bytes, base: int) -> DescriptionBox:
    """Parse a ``jumd`` payload."""
    if len(payload) < _UUID_SIZE + 1:
        msg = "description box shorter than its UUID and toggle byte"
        raise JumbfError(msg, base)

    uuid = payload[:_UUID_SIZE]
    toggles = payload[_UUID_SIZE]
    pos = _UUID_SIZE + 1

    if toggles & Toggle.RESERVED:
        msg = f"reserved toggle bits set: 0x{toggles:02x}"
        raise JumbfError(msg, base + _UUID_SIZE)

    label: str | None = None
    if toggles & Toggle.LABEL:
        # ISO/IEC 19566-5 assigns the label field to bit 0x02. The requestable bit is
        # independent, so a label does not require it.
        end = payload.find(b"\x00", pos)
        if end < 0:
            msg = "label is not NUL-terminated"
            raise JumbfError(msg, base + pos)
        try:
            label = payload[pos:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JumbfError("label is not valid UTF-8", base + pos) from exc
        pos = end + 1

    box_id: int | None = None
    if toggles & Toggle.ID:
        if pos + _ID_SIZE > len(payload):
            msg = "truncated ID field"
            raise JumbfError(msg, base + pos)
        (box_id,) = struct.unpack(">I", payload[pos : pos + _ID_SIZE])
        pos += _ID_SIZE

    signature: bytes | None = None
    if toggles & Toggle.SIGNATURE:
        # ISO/IEC 19566-5 defines this field as a 256-bit hash: 32 bytes.
        if pos + _HASH_SIZE > len(payload):
            msg = "truncated signature field"
            raise JumbfError(msg, base + pos)
        signature = payload[pos : pos + _HASH_SIZE]
        pos += _HASH_SIZE

    # The private field is one or more complete boxes and is kept opaque. C2PA 6.6 can
    # place a ``c2sh`` assertion salt box here; the producer emits no private entry.
    private = payload[pos:] if toggles & Toggle.PRIVATE else None
    if private is None and pos != len(payload):
        msg = f"{len(payload) - pos} unexpected trailing byte(s) in description box"
        raise JumbfError(msg, base + pos)

    return DescriptionBox(
        uuid=uuid,
        label=label,
        requestable=bool(toggles & Toggle.REQUESTABLE),
        box_id=box_id,
        signature=signature,
        private=private,
    )


def parse_superbox(data: bytes, offset: int = 0) -> tuple[JumbfBox, int]:
    """Parse one superbox. Returns the box and the offset just past it.

    Raises:
        JumbfError: on any malformed structure.
    """
    length, tbox, payload_offset = _read_header(data, offset)
    if tbox != TBOX_SUPERBOX:
        msg = f"expected a {TBOX_SUPERBOX.decode()} superbox, got {tbox!r}"
        raise JumbfError(msg, offset)

    end = offset + length
    if end > len(data):
        msg = f"superbox declares {length} bytes but only {len(data) - offset} remain"
        raise JumbfError(msg, offset)

    inner_length, inner_tbox, inner_payload = _read_header(data, payload_offset)
    if inner_tbox != TBOX_DESCRIPTION:
        msg = "a superbox must begin with a jumd description box"
        raise JumbfError(msg, payload_offset)

    description = _parse_description(data[inner_payload : payload_offset + inner_length], inner_payload)

    content: list[tuple[bytes, bytes]] = []
    pos = payload_offset + inner_length
    while pos < end:
        child_length, child_tbox, child_payload = _read_header(data, pos)
        if pos + child_length > end:
            msg = "child box overruns its superbox"
            raise JumbfError(msg, pos)
        content.append((child_tbox, data[child_payload : pos + child_length]))
        pos += child_length

    if not content:
        # A.2: "one or more Content Boxes".
        msg = "a superbox must contain at least one content box"
        raise JumbfError(msg, offset)

    return JumbfBox(description=description, content=tuple(content)), end
