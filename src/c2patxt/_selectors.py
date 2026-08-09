"""
The byte-to-variation-selector codec (C2PA 2.4 A.8.3.1, A.8.3.2) and wrapper framing.

Pure mapping and framing. No keys, no hashing, no manifest parsing. The functions
here are the innermost layer of the package and know nothing about C2PA semantics.
"""

from __future__ import annotations

import struct

from c2patxt.constants import (
    HEADER_SIZE,
    LENGTH_STRUCT_FORMAT,
    MAGIC,
    MARKER,
    MAX_MANIFEST_LENGTH,
    VERSION,
    VS_HIGH_BASE,
    VS_HIGH_MAX,
    VS_LOW_BASE,
    VS_LOW_MAX,
)
from c2patxt.exceptions import MarkCorruptError

_LOW_SPAN = VS_LOW_MAX - VS_LOW_BASE + 1  # 16: bytes 0x00-0x0F
_MAX_BYTE = 0xFF


def byte_to_selector(value: int) -> str:
    """Encode one byte as a variation selector (A.8.3.1).

    Verbatim from the specification::

        if (b >= 0 && b <= 15)   return U+FE00 + b;
        else if (b >= 16 && b <= 255) return U+E0100 + (b - 16);

    The 0x0F/0x10 boundary is also where the UTF-8 cost changes from 3 bytes to 4.
    """
    if not 0 <= value <= _MAX_BYTE:
        msg = f"not a byte: {value}"
        raise ValueError(msg)
    if value < _LOW_SPAN:
        return chr(VS_LOW_BASE + value)
    return chr(VS_HIGH_BASE + value - _LOW_SPAN)


def selector_to_byte(codepoint: int) -> int | None:
    """Decode a variation selector to its byte, or ``None`` if it is not one (A.8.3.2).

    Returns ``None`` rather than raising: the scanner uses this to decide where a
    contiguous run ends, and "this character is not a selector" is an ordinary,
    expected answer during a scan of arbitrary text.
    """
    if VS_LOW_BASE <= codepoint <= VS_LOW_MAX:
        return codepoint - VS_LOW_BASE
    if VS_HIGH_BASE <= codepoint <= VS_HIGH_MAX:
        return codepoint - VS_HIGH_BASE + _LOW_SPAN
    return None


#: The A.8.3.1 mapping as a translation table, built FROM ``byte_to_selector`` so the
#: bulk path cannot disagree with the one-byte path that carries the formula verbatim.
#: Latin-1 is the decoding that maps byte N to code point N for all 256 values, which
#: is what makes ``bytes`` addressable by ``str.translate`` at all.
_SELECTOR_TABLE = {value: byte_to_selector(value) for value in range(256)}


def bytes_to_selectors(data: bytes) -> str:
    """Encode a byte string as a contiguous variation-selector run.

    The table implements the A.8.3.1 formula over all 256 byte values.
    """
    return data.decode("latin-1").translate(_SELECTOR_TABLE)


def build_wrapper(payload: bytes) -> str:
    """Build a complete wrapper: U+FEFF followed by the encoded body (A.8.2.2, A.8.4.1).

    The body is ``magic(8) || version(1) || manifestLength(4) || payload``, with
    ``manifestLength`` big-endian.

    Raises:
        ValueError: if the payload exceeds :data:`MAX_MANIFEST_LENGTH`. Refusing to
            *produce* something we would refuse to *read* keeps the two halves of
            the codec from disagreeing.
    """
    if len(payload) > MAX_MANIFEST_LENGTH:
        msg = f"manifest of {len(payload)} bytes exceeds the {MAX_MANIFEST_LENGTH}-byte limit"
        raise ValueError(msg)
    body = MAGIC + bytes([VERSION]) + struct.pack(LENGTH_STRUCT_FORMAT, len(payload)) + payload
    return MARKER + bytes_to_selectors(body)


def _document_offset(body: bytes, index: int, offset: int) -> int:
    """Document byte offset of decoded byte ``index``, given the body starts at ``offset``.

    A.8.3.1 maps ``0x00-0x0F`` into U+FE00's plane -- three UTF-8 bytes -- and everything
    above into U+E0100's -- four. So a decoded index and a document offset are different
    units, and adding one to the other is what this function exists to stop.

    The exact cost is known for every byte, so error positions remain byte-accurate.
    """
    return offset + sum(3 if byte < _LOW_SPAN else 4 for byte in body[:index])


def parse_wrapper_body(body: bytes, *, document_length: int | None = None, offset: int = 0) -> bytes:
    """Validate a decoded wrapper body and return its JUMBF payload.

    ``body`` is the already-decoded byte string, magic included. The caller has
    matched the magic; this checks everything after it.

    Raises:
        MarkCorruptError: on a short header, a version other than 1, a
            ``manifestLength`` above :data:`MAX_MANIFEST_LENGTH`, or a length that
            overruns the decoded bytes.
    """
    if len(body) < HEADER_SIZE:
        msg = f"wrapper header truncated: {len(body)} of {HEADER_SIZE} bytes"
        raise MarkCorruptError(msg, offset, document_length)

    version = body[len(MAGIC)]
    if version != VERSION:
        msg = f"unsupported wrapper version {version}, expected {VERSION}"
        raise MarkCorruptError(msg, _document_offset(body, len(MAGIC), offset), document_length)

    (declared,) = struct.unpack(LENGTH_STRUCT_FORMAT, body[len(MAGIC) + 1 : HEADER_SIZE])

    # Bound before accepting or slicing the declared payload. The uint32 field can
    # express far more than this implementation's 2 MiB manifest policy.
    if declared > MAX_MANIFEST_LENGTH:
        msg = f"declared manifestLength {declared} exceeds the {MAX_MANIFEST_LENGTH}-byte limit"
        raise MarkCorruptError(msg, _document_offset(body, len(MAGIC) + 1, offset), document_length)

    # C2PA 15.12.1.3.4 ("Partial Text Extraction"): a wrapper cut short of its declared
    # length is what an excerpt of a marked document looks like, and the clause's
    # `shall` is to reject it with a failure code, which this does.
    #
    # Its two `should`s -- that a validator "indicate that the text appears to be a
    # fragment of a larger, signed text" -- are NOT implemented, deliberately. A
    # wrapper missing its tail is indistinguishable from a damaged one: the bytes look
    # the same whether a user copied half a document or an attacker clipped it.
    # Reporting "this looks like a fragment" would be a claim we cannot support.
    available = len(body) - HEADER_SIZE
    if declared > available:
        msg = f"declared manifestLength {declared} exceeds the {available} bytes available"
        raise MarkCorruptError(msg, _document_offset(body, len(body), offset), document_length)

    return body[HEADER_SIZE : HEADER_SIZE + declared]
