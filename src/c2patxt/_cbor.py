"""
Deterministic CBOR, RFC 8949 4.2.1 ("Core Deterministic Encoding Requirements").

C2PA mandates this twice, normatively: 10.1 for the claim ("a CBOR payload, which
shall comply with the Core Deterministic Encoding Requirements of CBOR (see RFC 8949,
clause 4.2.1)") and 18.1 for all standard assertions.

SCOPE
-----
THE WRITER AND THE READER HAVE DIFFERENT SCOPES, deliberately.

``dumps`` is small: major types 0-5, the three simple values C2PA uses, and two tags,
0 (``tdate``, 6.9) and 18 (``COSE_Sign1``). No floats -- nothing this package emits
needs one, and 4.2.1's shortest-float rule is easy to get subtly wrong, so it is better
absent than half-implemented. What we emit is a wire commitment, so this stays narrow.

``loads`` defaults to deterministic CBOR. Its well-formed-input mode carries any tag
as ``Tagged``, retains every CBOR key type, decodes floats, and carries unassigned
simple values as ``SimpleValue``. C2PA 15.6.2 and 15.10.3.1 reject content that is not
well-formed CBOR; they do not impose the producer's deterministic subset. Duplicate
map keys remain an RFC 8949 validity failure. RFC 9052 section 9 likewise applies its
encoding restrictions to ``Sig_structure``, not the transported ``COSE_Sign1`` or its
header maps.

READ-SIDE REJECTION RULES
-------------------------

- In deterministic mode, indefinite lengths, non-shortest arguments, non-shortest
  FLOATS, a NaN encoded as anything but ``f97e00``, and out-of-order map keys are
  refused because RFC 8949 4.2.1 and 4.2.2 forbid them. Duplicate keys are refused in
  both modes.
- Tags 25/256 (string references) are refused BY US on the write side only, as a
  consequence of the two-tag allowlist in ``dumps``. That is our scope decision, not the
  specification's -- calling it "forbidden by deterministic encoding" would credit
  4.2.1 with a restriction it does not impose.
"""

from __future__ import annotations

import dataclasses
import math
import struct
from collections.abc import Hashable
from typing import TypeAlias

from c2patxt.constants import MAX_CBOR_DEPTH

# Major types, in the high three bits of the initial byte.
_MT_UINT = 0
_MT_NEGINT = 1
_MT_BYTES = 2
_MT_TEXT = 3
_MT_ARRAY = 4
_MT_MAP = 5
_MT_TAG = 6
_MT_SIMPLE = 7

# Additional-information values that introduce a following argument.
_AI_1BYTE = 24
_AI_2BYTE = 25
_AI_4BYTE = 26
_AI_8BYTE = 27
_AI_INDEFINITE = 31
_BREAK_BYTE = 0xFF

# Simple values (major type 7).
_SIMPLE_FALSE = 20
_SIMPLE_TRUE = 21
_SIMPLE_NULL = 22
_SIMPLE_UNDEFINED = 23
_SIMPLE_ONE_BYTE_MIN = 32

TAG_COSE_SIGN1 = 18
"""COSE_Sign1_Tagged (RFC 9052)."""

TAG_DATETIME = 0
"""RFC 8949 3.4.1 standard date/time string, the CDDL type ``tdate``.

C2PA 6.9: "The default specification for a date/time value in an assertion is the
date/time format which is serialized in CBOR as tag number 0". 18.15.12 types the
actions assertion's ``when`` field as ``tdate``, and the specification's own example
writes ``0("2023-02-11T09:00:00Z")``. An untagged text string is a different CBOR
value and does not satisfy the CDDL.
"""

#: Tags emitted by this producer. The reader can retain any integer tag; deterministic
#: encoding does not itself restrict which tags may be encoded.
_ALLOWED_TAGS = frozenset({TAG_DATETIME, TAG_COSE_SIGN1})

_MAX_UINT64 = (1 << 64) - 1


# Pyright requires this recursive TypeAlias to be one string literal; splitting it
# makes every use Unknown, so the line-length rule cannot be applied here.
CborKey: TypeAlias = "int | str | bytes | MapKey"
CborValue: TypeAlias = "int | float | bytes | str | bool | list[CborValue] | dict[int | str | bytes, CborValue] | dict[CborKey, CborValue] | SimpleValue | Tagged | None"  # noqa: E501


@dataclasses.dataclass(frozen=True, slots=True)
class SimpleValue:
    """A CBOR simple value with no native Python equivalent.

    ``loads`` uses this for unassigned values 0 through 19, undefined (23), and
    one-byte values 32 through 255. It stays distinct from :class:`int`, so CBOR
    ``simple(16)`` cannot silently become the unsigned integer 16. The writer does
    not accept it: no C2PA structure produced by this package needs one.
    """

    value: int


@dataclasses.dataclass(frozen=True, slots=True)
class MapKey:
    """A decoded CBOR map key that has no safe native Python ``dict`` key.

    CBOR permits every data item as a key, including arrays, maps and tagged values.
    ``loads`` keeps the decoded key in ``value`` and uses the stored identity for
    RFC 8949 section 5.6.1 equality and duplicate detection. The writer refuses this
    holder: no structure emitted by this package needs a wrapped key.
    """

    value: CborValue = dataclasses.field(compare=False, hash=False)
    identity: Hashable = dataclasses.field(repr=False)


@dataclasses.dataclass(frozen=True, slots=True)
class Tagged:
    """A CBOR tagged value.

    ``loads`` produces one for ANY tag: recognising a tag and accepting its bytes are
    different questions, and only the second is the decoder's. ``dumps`` accepts only
    :data:`_ALLOWED_TAGS`, because what we EMIT is a wire commitment.
    """

    tag: int
    value: CborValue


def _map_key_identity(value: CborValue) -> Hashable:
    """Return RFC 8949 section 5.6.1 generic-data-model key identity."""
    if value is None:
        identity: Hashable = ("null",)
    elif isinstance(value, bool):
        identity = ("bool", value)
    elif isinstance(value, int):
        identity = ("int", value)
    elif isinstance(value, float):
        if math.isnan(value):
            # Key equivalence ignores a NaN's sign and compares its significand after
            # extension to binary64. `_float` has already converted every width to
            # Python's binary64 representation.
            bits = int.from_bytes(struct.pack(">d", value), "big")
            identity = ("float-nan", bits & ((1 << 52) - 1))
        else:
            identity = ("float", 0.0 if value == 0.0 else value)
    elif isinstance(value, bytes):
        identity = ("bytes", value)
    elif isinstance(value, str):
        identity = ("text", value)
    elif isinstance(value, SimpleValue):
        identity = ("simple", value.value)
    elif isinstance(value, Tagged):
        identity = ("tag", value.tag, _map_key_identity(value.value))
    elif isinstance(value, list):
        identity = ("array", tuple(_map_key_identity(item) for item in value))
    else:
        pairs = frozenset(
            (
                key.identity if isinstance(key, MapKey) else _map_key_identity(key),
                _map_key_identity(item),
            )
            for key, item in value.items()
        )
        identity = ("map", pairs)
    return identity


class CborDecodeError(ValueError):
    """Input violates the selected CBOR decoding mode.

    Deriving from ``ValueError`` rather than this package's own root: this is a
    parsing fault in a self-contained codec, and callers reasonably expect
    ``except ValueError``. The C2PA-facing layers translate it into a status code.

    Attributes:
        pos: byte offset at which decoding stopped.
    """

    def __init__(self, msg: str, pos: int) -> None:
        self.msg = msg
        self.pos = pos
        super().__init__(f"{msg} (at byte {pos})")


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


# Argument-width thresholds. 4.2.1 requires the shortest form that fits, so these
# are the exact boundaries at which the encoding steps up.
_FITS_1BYTE = 0xFF
_FITS_2BYTE = 0xFFFF
_FITS_4BYTE = 0xFFFFFFFF

_SIMPLE_ENCODINGS = {
    None: bytes([(_MT_SIMPLE << 5) | _SIMPLE_NULL]),
    True: bytes([(_MT_SIMPLE << 5) | _SIMPLE_TRUE]),
    False: bytes([(_MT_SIMPLE << 5) | _SIMPLE_FALSE]),
}


def _head(major: int, argument: int) -> bytes:
    """Encode an initial byte plus argument in the SHORTEST form (4.2.1)."""
    prefix = major << 5
    if argument < _AI_1BYTE:
        return bytes([prefix | argument])
    if argument <= _FITS_1BYTE:
        return bytes([prefix | _AI_1BYTE, argument])
    if argument <= _FITS_2BYTE:
        return bytes([prefix | _AI_2BYTE]) + argument.to_bytes(2, "big")
    if argument <= _FITS_4BYTE:
        return bytes([prefix | _AI_4BYTE]) + argument.to_bytes(4, "big")
    if argument <= _MAX_UINT64:
        return bytes([prefix | _AI_8BYTE]) + argument.to_bytes(8, "big")
    msg = f"argument {argument} exceeds the 64-bit CBOR range"
    raise ValueError(msg)


def _encode_scalar(value: object) -> bytes | None:
    """Encode a non-container, or return None if ``value`` is not one.

    ``bool`` is checked before ``int`` because it is a subclass of it and would
    otherwise encode as 0/1 rather than as a simple value.
    """
    if isinstance(value, bool) or value is None:
        return _SIMPLE_ENCODINGS[value]
    if isinstance(value, int):
        return _head(_MT_UINT, value) if value >= 0 else _head(_MT_NEGINT, -1 - value)
    if isinstance(value, bytes):
        return _head(_MT_BYTES, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(_MT_TEXT, len(encoded)) + encoded
    return None


def _encode(value: object, depth: int) -> bytes:
    if depth > MAX_CBOR_DEPTH:
        msg = f"nesting deeper than {MAX_CBOR_DEPTH}"
        raise ValueError(msg)

    scalar = _encode_scalar(value)
    if scalar is not None:
        return scalar

    if isinstance(value, list):
        items: list[object] = list(value)  # pyright: ignore[reportUnknownArgumentType]
        return _head(_MT_ARRAY, len(items)) + b"".join(_encode(item, depth + 1) for item in items)
    if isinstance(value, dict):
        pairs: list[tuple[object, object]] = list(value.items())  # pyright: ignore[reportUnknownArgumentType]
        return _encode_map(pairs, depth)
    if isinstance(value, Tagged):
        if value.tag not in _ALLOWED_TAGS:
            msg = f"tag {value.tag} is not permitted"
            raise ValueError(msg)
        return _head(_MT_TAG, value.tag) + _encode(value.value, depth + 1)
    if isinstance(value, float):
        msg = "floats are not supported: no C2PA structure this package emits needs one"
        raise TypeError(msg)
    msg = f"cannot encode {type(value).__name__}"
    raise TypeError(msg)


def _encode_map(pairs: list[tuple[object, object]], depth: int) -> bytes:
    """Encode a map with keys sorted BYTEWISE on their encoded form (4.2.1).

    Not length-first. That is the whole reason this module exists rather than a call
    to ``cbor2.dumps(..., canonical=True)``.
    """
    encoded_pairs = [(_encode(key, depth + 1), _encode(item, depth + 1)) for key, item in pairs]
    encoded_pairs.sort(key=lambda pair: pair[0])

    seen: set[bytes] = set()
    for key_bytes, _ in encoded_pairs:
        if key_bytes in seen:
            msg = "duplicate map key"
            raise ValueError(msg)
        seen.add(key_bytes)

    return _head(_MT_MAP, len(encoded_pairs)) + b"".join(k + v for k, v in encoded_pairs)


def dumps(value: object) -> bytes:
    """Serialize to deterministically-encoded CBOR (RFC 8949 4.2.1)."""
    return _encode(value, 0)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


class _Decoder:
    __slots__ = ("data", "deterministic", "pos")

    def __init__(self, data: bytes, *, deterministic: bool) -> None:
        self.data = data
        self.deterministic = deterministic
        self.pos = 0

    def _fail(self, msg: str) -> CborDecodeError:
        return CborDecodeError(msg, self.pos)

    def _take(self, count: int) -> bytes:
        if self.pos + count > len(self.data):
            raise self._fail(f"truncated: wanted {count} more byte(s)")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def _argument(self, info: int) -> int:
        """Read an argument, rejecting non-shortest forms in deterministic mode.

        RFC 8949 4.2.1 requires the shortest form from a conforming generator.
        Validation paths that require only well-formed CBOR disable this check.
        """
        if info < _AI_1BYTE:
            return info
        if info > _AI_8BYTE:
            raise self._fail(f"reserved additional information {info}")

        width = 1 << (info - _AI_1BYTE)
        value = int.from_bytes(self._take(width), "big")

        minimum = (0, 0x18, 0x100, 0x10000, 0x100000000)[info - _AI_1BYTE + 1]
        if self.deterministic and value < minimum:
            raise self._fail(f"value {value} is not in shortest form")
        return value

    def _take_break(self) -> bool:
        """Consume and report a break code at the current position."""
        if self.pos < len(self.data) and self.data[self.pos] == _BREAK_BYTE:
            self.pos += 1
            return True
        return False

    def _indefinite_string(self, major: int) -> bytes | str:
        """Decode an indefinite byte/text string from definite chunks."""
        byte_chunks: list[bytes] = []
        text_chunks: list[str] = []
        while not self._take_break():
            chunk_start = self.pos
            initial = self._take(1)[0]
            chunk_major, info = initial >> 5, initial & 0x1F
            if chunk_major != major or info == _AI_INDEFINITE:
                kind = "byte" if major == _MT_BYTES else "text"
                raise CborDecodeError(
                    f"an indefinite {kind} string must contain definite chunks of its own type",
                    chunk_start,
                )
            argument = self._argument(info)
            if major == _MT_BYTES:
                byte_chunks.append(self._take(argument))
                continue
            raw = self._take(argument)
            try:
                text_chunks.append(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise CborDecodeError("text string is not valid UTF-8", chunk_start) from exc
        if major == _MT_BYTES:
            return b"".join(byte_chunks)
        return "".join(text_chunks)

    def _indefinite_array(self, depth: int) -> list[CborValue]:
        """Decode array items up to their break code."""
        out: list[CborValue] = []
        while not self._take_break():
            out.append(self.decode(depth + 1))
        return out

    def _decode_indefinite(self, major: int, depth: int, start: int) -> CborValue:
        """Decode an indefinite container in well-formed-input mode."""
        if self.deterministic:
            raise self._fail("indefinite-length item: forbidden by deterministic encoding")
        if major in (_MT_BYTES, _MT_TEXT):
            return self._indefinite_string(major)
        if major == _MT_ARRAY:
            return self._indefinite_array(depth)
        if major == _MT_MAP:
            return self._map(None, depth)
        raise CborDecodeError("this major type cannot use an indefinite length", start)

    def _decode_scalar(self, major: int, argument: int, start: int) -> CborValue:
        """Decode a non-container item. Callers handle containers themselves."""
        if major == _MT_UINT:
            return argument
        if major == _MT_NEGINT:
            return -1 - argument
        if major == _MT_BYTES:
            return self._take(argument)
        # major == _MT_TEXT
        raw = self._take(argument)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CborDecodeError("text string is not valid UTF-8", start) from exc

    def decode(self, depth: int = 0) -> CborValue:
        if depth > MAX_CBOR_DEPTH:
            raise self._fail(f"nesting deeper than {MAX_CBOR_DEPTH}")

        start = self.pos
        initial = self._take(1)[0]
        major, info = initial >> 5, initial & 0x1F

        if major == _MT_SIMPLE:
            return self._simple(info, start)

        if info == _AI_INDEFINITE:
            return self._decode_indefinite(major, depth, start)

        argument = self._argument(info)

        if major in (_MT_UINT, _MT_NEGINT, _MT_BYTES, _MT_TEXT):
            return self._decode_scalar(major, argument, start)
        if major == _MT_ARRAY:
            return [self.decode(depth + 1) for _ in range(argument)]
        if major == _MT_MAP:
            return self._map(argument, depth)
        # major == _MT_TAG. RFC 8949 Appendix C permits any integer tag over a
        # well-formed item. Position-specific C2PA validation happens after decoding;
        # ``dumps`` remains limited to the producer's tag allowlist.
        return Tagged(argument, self.decode(depth + 1))

    def _simple(self, info: int, start: int) -> SimpleValue | bool | float | None:
        """Decode major type 7 simple values and all three RFC 8949 float widths.

        Each float consumes a fixed 2, 4, or 8 bytes through ``_take``. The producer
        still refuses floats.
        """
        if _SIMPLE_FALSE <= info <= _SIMPLE_NULL:
            return (False, True, None)[info - _SIMPLE_FALSE]
        if info < _SIMPLE_FALSE:
            return SimpleValue(info)
        if info == _SIMPLE_UNDEFINED:
            return SimpleValue(info)
        if info == _AI_1BYTE:
            value = self._take(1)[0]
            if value < _SIMPLE_ONE_BYTE_MIN:
                raise CborDecodeError(f"one-byte simple value {value} is below 32", start)
            return SimpleValue(value)
        if info in (_AI_2BYTE, _AI_4BYTE, _AI_8BYTE):
            return self._float(info, start)
        if info == _AI_INDEFINITE:
            raise CborDecodeError("break code outside an indefinite-length item", start)
        raise CborDecodeError(f"unsupported simple value {info}", start)

    def _float(self, info: int, start: int) -> float:
        """Decode a float, enforcing 4.2.1 only in deterministic mode.

        Strict decoding remains the producer-side wire assertion: for example,
        ``fb3ff0000000000000`` is 1.0 where 4.2.1 requires ``f93c00``. Validation
        paths that require only well-formed CBOR retain the value instead.

        4.2.1 requires "the shortest form that preserves the value". Re-encoding at
        narrower widths determines whether the supplied width was necessary.

        4.2.2 pins NaN to ``f97e00`` exactly, which is why NaN is compared on BITS
        rather than by value: every NaN payload is ``!= itself`` and ``== nan`` is
        never true, so a value comparison would wave all of them through.
        """
        width = {_AI_2BYTE: 2, _AI_4BYTE: 4, _AI_8BYTE: 8}[info]
        code = {2: ">e", 4: ">f", 8: ">d"}[width]
        raw = self._take(width)
        value = struct.unpack(code, raw)[0]

        # 4.2.2 pins NaN to exactly f97e00. Checked FIRST and on the bits, because
        # every NaN is unequal to itself and to every other NaN, so the width
        # comparison below cannot identify one.
        if not self.deterministic:
            return value

        if math.isnan(value):
            if raw != b"\x7e\x00":
                msg = "NaN must be encoded as f97e00 (RFC 8949 4.2.2)"
                raise CborDecodeError(msg, start)
            return value

        # 4.2.1: "the shortest form that preserves the value". If a narrower width
        # round-trips to the same value, this encoding was not the shortest and no
        # conforming producer emitted it.
        for narrower, narrow_code in ((2, ">e"), (4, ">f")):
            if narrower >= width:
                break
            try:
                repacked = struct.pack(narrow_code, value)
            except (OverflowError, ValueError):
                # A value the narrower format cannot hold is trivially not expressible
                # in it, so that narrower width cannot preserve the value. `>e`
                # overflows above 65504; this is an expected part of probing widths,
                # not malformed CBOR and not an exception that may escape verification.
                continue
            if struct.unpack(narrow_code, repacked)[0] == value:
                msg = f"float is not in shortest form: {width} bytes where {narrower} preserves the value"
                raise CborDecodeError(msg, start)
        return value

    def _map(self, count: int | None, depth: int) -> dict[CborKey, CborValue]:
        """Decode a map, retaining every key type and enforcing uniqueness."""
        out: dict[CborKey, CborValue] = {}
        previous: bytes | None = None
        remaining = count
        while remaining is None or remaining > 0:
            if remaining is None and self._take_break():
                break
            key_start = self.pos
            decoded_key = self.decode(depth + 1)
            key_bytes = self.data[key_start : self.pos]

            if self.deterministic and previous is not None and key_bytes <= previous:
                what = "duplicate" if key_bytes == previous else "out-of-order"
                raise CborDecodeError(f"{what} map key: not deterministically encoded", key_start)
            previous = key_bytes

            # Python cannot use arrays or maps as dict keys, and it equates bool keys
            # with integer 0/1. Wrap every key without a safe native representation so
            # valid CBOR stays distinct and hashable without changing its decoded value.
            key: CborKey
            if type(decoded_key) is int or isinstance(decoded_key, (str, bytes)):
                key = decoded_key
            else:
                key = MapKey(decoded_key, _map_key_identity(decoded_key))
            if key in out:
                raise CborDecodeError("duplicate map key", key_start)
            if remaining is None and self._take_break():
                raise CborDecodeError("break code where a map value is required", self.pos - 1)
            out[key] = self.decode(depth + 1)
            if remaining is not None:
                remaining -= 1
        return out


def loads(data: bytes, *, deterministic: bool = True) -> CborValue:
    """Parse CBOR, requiring deterministic encoding unless explicitly disabled.

    Deterministic mode additionally rejects indefinite-length items, non-shortest-form
    integers, lengths and floats, a NaN encoded as anything but ``f97e00`` (4.2.2),
    and out-of-order map keys. Both modes reject duplicate keys, reserved additional
    information, malformed input, and trailing bytes.

    ACCEPTS any tag, carried as :class:`Tagged`, floats, and simple values carried as
    :class:`SimpleValue` when Python has no native equivalent. What is rejected is
    what 4.2.1 forbids, not what we happen not to emit; ``dumps`` is the narrow one,
    and deliberately.

    Raises:
        CborDecodeError: on any of the above.
    """
    decoder = _Decoder(data, deterministic=deterministic)
    value = decoder.decode()
    if decoder.pos != len(data):
        raise CborDecodeError(f"{len(data) - decoder.pos} trailing byte(s) after the top-level item", decoder.pos)
    return value
