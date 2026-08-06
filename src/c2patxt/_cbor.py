"""
Deterministic CBOR, RFC 8949 4.2.1 ("Core Deterministic Encoding Requirements").

C2PA mandates this twice, normatively: 10.1 for the claim ("a CBOR payload, which
shall comply with the Core Deterministic Encoding Requirements of CBOR (see RFC 8949,
clause 4.2.1)") and 18.1 for all standard assertions.

WHY THIS IS NOT cbor2
---------------------
cbor2's ``canonical=True`` implements the WRONG ORDERING. It sorts map keys
length-first -- by ``(len(encoded_key), encoded_key)`` -- which is RFC 8949 4.2.3,
the *old* CTAP2/RFC 7049 rule. 4.2.1 requires purely BYTEWISE lexicographic ordering
of the encoded keys. The two coincide for every map C2PA currently uses, because for
text-string keys the CBOR head byte is monotonic in length, but they diverge the
moment a negative integer key sits alongside a positive one at or above 24. We were
already sorting keys ourselves and calling ``canonical=False``, which reduced cbor2
to a primitive serializer.

The decisive reason is on the decode side: a decoder that REJECTS non-deterministic
input is a security property no general-purpose library offers. Anything not
deterministically encoded is input no conforming C2PA producer would ever emit, so
accepting it widens the attack surface for nothing. Everything here fails closed.

cbor2 remains a dev dependency, used only as a differential-testing oracle.

SCOPE
-----
THE WRITER AND THE READER HAVE DIFFERENT SCOPES, deliberately.

``dumps`` is small: major types 0-5, the three simple values C2PA uses, and two tags,
0 (``tdate``, 6.9) and 18 (``COSE_Sign1``). No floats -- nothing this package emits
needs one, and 4.2.1's shortest-float rule is easy to get subtly wrong, so it is better
absent than half-implemented. What we emit is a wire commitment, so this stays narrow.

``loads`` accepts any WELL-FORMED CBOR, because 15.10.3.1 rejects assertion content
only when it "is NOT WELL-FORMED CBOR", defined by RFC 8949 Appendix C. Any tag is
carried as ``Tagged`` and floats are decoded. Reading only what we write refused
conforming third-party manifests -- the CDDL needs tag 37 for ``instanceID`` and floats
for region coordinates.

WHAT IS STILL REFUSED ON READ, and the distinction matters because folding the two
together is the overclaim shape this package corrects elsewhere:

- Indefinite lengths, non-shortest arguments, non-shortest FLOATS, a NaN encoded as
  anything but ``f97e00``, and out-of-order or duplicate map keys are refused because
  RFC 8949 4.2.1 and 4.2.2 FORBID THEM. Rejecting non-deterministic input is a
  security property no general-purpose decoder offers.
- Tags 25/256 (string references) are refused BY US on the write side only, as a
  consequence of the two-tag allowlist in ``dumps``. That is our scope decision, not the
  specification's -- calling it "forbidden by deterministic encoding" would credit
  4.2.1 with a restriction it does not impose.
"""

from __future__ import annotations

import dataclasses
import math
import struct
from typing import TypeAlias

from c2patxt.constants import MAX_JUMBF_DEPTH

__all__ = [
    "CborDecodeError",
    "CborValue",
    "Tagged",
    "dumps",
    "loads",
]

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

# Simple values (major type 7).
_SIMPLE_FALSE = 20
_SIMPLE_TRUE = 21
_SIMPLE_NULL = 22

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

#: Deliberately an ALLOWLIST, not a check for known-bad tags: a tag we do not
#: understand is a value we cannot claim to have validated, and 10.1's deterministic
#: encoding gives us no way to round-trip one faithfully.
_ALLOWED_TAGS = frozenset({TAG_DATETIME, TAG_COSE_SIGN1})

_MAX_UINT64 = (1 << 64) - 1


CborValue: TypeAlias = (
    "int | float | bytes | str | bool | list[CborValue] | dict[int | str | bytes, CborValue] | Tagged | None"
)


@dataclasses.dataclass(frozen=True, slots=True)
class Tagged:
    """A CBOR tagged value.

    ``loads`` produces one for ANY tag: recognising a tag and accepting its bytes are
    different questions, and only the second is the decoder's. ``dumps`` accepts only
    :data:`_ALLOWED_TAGS`, because what we EMIT is a wire commitment.
    """

    tag: int
    value: CborValue


class CborDecodeError(ValueError):
    """Input is not valid deterministically-encoded CBOR.

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

    def __reduce__(self) -> tuple[type[CborDecodeError], tuple[str, int]]:
        return (self.__class__, (self.msg, self.pos))


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
    if depth > MAX_JUMBF_DEPTH:
        msg = f"nesting deeper than {MAX_JUMBF_DEPTH}"
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
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
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
        """Read an argument, rejecting any non-shortest-form encoding.

        This check is what makes the decoder *verify* determinism rather than merely
        produce it. RFC 8949 4.2.1 requires the shortest form, so a longer one is
        input no conforming producer emits.
        """
        if info < _AI_1BYTE:
            return info
        if info == _AI_INDEFINITE:
            raise self._fail("indefinite-length item: forbidden by deterministic encoding")
        if info > _AI_8BYTE:
            raise self._fail(f"reserved additional information {info}")

        width = 1 << (info - _AI_1BYTE)
        value = int.from_bytes(self._take(width), "big")

        minimum = (0, 0x18, 0x100, 0x10000, 0x100000000)[info - _AI_1BYTE + 1]
        if value < minimum:
            raise self._fail(f"value {value} is not in shortest form")
        return value

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
        if depth > MAX_JUMBF_DEPTH:
            raise self._fail(f"nesting deeper than {MAX_JUMBF_DEPTH}")

        start = self.pos
        initial = self._take(1)[0]
        major, info = initial >> 5, initial & 0x1F

        if major == _MT_SIMPLE:
            return self._simple(info, start)

        argument = self._argument(info)

        if major in (_MT_UINT, _MT_NEGINT, _MT_BYTES, _MT_TEXT):
            return self._decode_scalar(major, argument, start)
        if major == _MT_ARRAY:
            return [self.decode(depth + 1) for _ in range(argument)]
        if major == _MT_MAP:
            return self._map(argument, depth)
        # major == _MT_TAG. ANY tag is decoded, and carried as Tagged.
        #
        # This accepted only tags 0 and 18, so anything else raised and _parse_assertions
        # turned that into assertion.cbor.invalid -- refusing a whole conforming manifest
        # before verification began. 15.10.3.1 triggers on content that "is NOT WELL-
        # FORMED CBOR", and defines that by RFC 8949 Appendix C, whose grammar accepts
        # any tag number over any well-formed item. Recognising a tag and accepting its
        # bytes are different questions; only the second one is the decoder's.
        #
        # The CDDL needs at least two we did not have: the buuid type, which is CBOR
        # tag 37 over a byte string, used by instanceID in the action-items map; and
        # tag 1, epoch time.
        #
        # `dumps` is unchanged and still refuses everything outside _ALLOWED_TAGS.
        # Deterministic encoding is a PRODUCER obligation (RFC 8949 4.2.1) and our
        # output is a wire commitment.
        return Tagged(argument, self.decode(depth + 1))

    def _simple(self, info: int, start: int) -> bool | float | None:
        """Major type 7: the three simple values we emit, plus floats on READ only.

        Floats were rejected as "unsupported simple value", which was the same false
        reject as the tag one: the CDDL puts them in ``coordinate-map`` and
        ``shape-map`` (x, y, width, height), reachable from an action's ``changes``
        field and from ``regionOfInterest`` in an assertion's metadata. A region with a
        fractional coordinate -- the ordinary case -- made a manifest unreadable.

        All three widths are decoded because RFC 8949 defines them as three encodings
        of one type, and a deterministic encoder prefers the shortest that round-trips.

        NOTHING HERE WIDENS WHAT IS ALLOCATED. Each float is a fixed 2, 4 or 8 bytes
        read through the same ``_take`` bounds check as every other item; the reason
        this decoder is careful is that it is the first thing to touch attacker bytes,
        and that is a length-and-depth property, untouched by admitting a wider set of
        VALUES. ``dumps`` still refuses floats, so this cannot reach the wire.
        """
        if info == _SIMPLE_FALSE:
            return False
        if info == _SIMPLE_TRUE:
            return True
        if info == _SIMPLE_NULL:
            return None
        if info in (_AI_2BYTE, _AI_4BYTE, _AI_8BYTE):
            return self._float(info, start)
        if info == _AI_INDEFINITE:
            raise CborDecodeError("break code outside an indefinite-length item", start)
        raise CborDecodeError(f"unsupported simple value {info}", start)

    def _float(self, info: int, start: int) -> float:
        """Decode a float, REJECTING any encoding 4.2.1 forbids.

        This module's whole argument is that a decoder rejecting non-deterministic
        input is a security property no general-purpose library offers, and floats
        arrived without it: ``fb3ff0000000000000`` decoded to 1.0 where 4.2.1 requires
        ``f93c00``, sitting alongside ``_argument``, which refuses a
        non-shortest INTEGER. Widening the reader is not licence to stop checking.

        4.2.1: "the shortest form that preserves the value". So the test is a round
        trip -- if a narrower width decodes back to the same bits, this encoding was
        not the shortest and no conforming producer emitted it.

        4.2.2 pins NaN to ``f97e00`` exactly, which is why NaN is compared on BITS
        rather than by value: every NaN payload is ``!= itself`` and ``== nan`` is
        never true, so a value comparison would wave all of them through.
        """
        width = {_AI_2BYTE: 2, _AI_4BYTE: 4, _AI_8BYTE: 8}[info]
        code = {2: ">e", 4: ">f", 8: ">d"}[width]
        raw = self._take(width)
        value = struct.unpack(code, raw)[0]

        # 4.2.2 pins NaN to exactly f97e00. Checked FIRST and on the bits, because
        # every NaN is unequal to itself and to every other NaN, so the round-trip
        # test below cannot see one.
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
                # in it, so the encoding we were handed IS the shortest and the check
                # simply does not apply. `>e` overflows above 65504, which is an
                # ordinary magnitude, not an exotic one.
                #
                # THIS CARRIED `# pragma: no cover -- struct widens rather than failing`
                # AND STRUCT DOES NOT WIDEN: `struct.pack(">e", 1e300)` raises
                # OverflowError, and line-tracing `loads(fb7e37e43c8800759c)` shows this
                # handler running. The pragma hid a live branch from the coverage gate,
                # and deleting the handler on the strength of it would have put an
                # OverflowError -- not a CborDecodeError -- out of `verify()`, which
                # promises never to raise on attacker bytes.
                continue
            if struct.unpack(narrow_code, repacked)[0] == value:
                msg = f"float is not in shortest form: {width} bytes where {narrower} preserves the value"
                raise CborDecodeError(msg, start)
        return value

    def _map(self, count: int, depth: int) -> dict[int | str | bytes, CborValue]:
        """Decode a map, enforcing bytewise key ordering and uniqueness."""
        out: dict[int | str | bytes, CborValue] = {}
        previous: bytes | None = None
        for _ in range(count):
            key_start = self.pos
            key = self.decode(depth + 1)
            key_bytes = self.data[key_start : self.pos]

            if previous is not None and key_bytes <= previous:
                what = "duplicate" if key_bytes == previous else "out-of-order"
                raise CborDecodeError(f"{what} map key: not deterministically encoded", key_start)
            previous = key_bytes

            # bool is a subclass of int, so `True` would otherwise pass this gate and
            # then collide with integer key 1 in the output dict -- a two-entry map
            # would decode to one entry, silently dropping content a signer wrote.
            if isinstance(key, bool) or not isinstance(key, (int, str, bytes)):
                raise CborDecodeError("map keys must be integers, text or byte strings", key_start)
            out[key] = self.decode(depth + 1)
        return out


def loads(data: bytes) -> CborValue:
    """Parse deterministically-encoded CBOR, failing closed on anything else.

    Rejects, in addition to malformed input: indefinite-length items, non-shortest-form
    integers, lengths and FLOATS, a NaN encoded as anything but ``f97e00`` (4.2.2),
    out-of-order or duplicate map keys, simple values other than false/true/null, and
    trailing bytes after the top-level item.

    ACCEPTS any tag, carried as :class:`Tagged`, and floats. This said it rejected
    "unknown tags" and every simple value but the three -- both true before the reader
    was widened to all well-formed CBOR, and both then left contradicting the module
    docstring in this same file. What is rejected is what 4.2.1 FORBIDS, not what we
    happen not to emit; ``dumps`` is the narrow one, and deliberately.

    Raises:
        CborDecodeError: on any of the above.
    """
    decoder = _Decoder(data)
    value = decoder.decode()
    if decoder.pos != len(data):
        raise CborDecodeError(f"{len(data) - decoder.pos} trailing byte(s) after the top-level item", decoder.pos)
    return value
