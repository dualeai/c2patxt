"""
Wire-format constants and resource limits for C2PA 2.4 Annex A.8.

Every value here is fixed by the specification or by a stated threat model. Nothing
in this module is tunable at runtime: a limit an attacker can raise is not a limit.

Verified against C2PA Technical Specification 2.4 (2026-04-01), HTML build c7e55d5a.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "HEADER_SIZE",
    "MAGIC",
    "MARKER",
    "MAX_CBOR_DEPTH",
    "MAX_MANIFEST_LENGTH",
    "MAX_NONSTARTERS",
    "MAX_SELECTOR_RUN",
    "VERSION",
    "VS_HIGH_BASE",
    "VS_HIGH_MAX",
    "VS_LOW_BASE",
    "VS_LOW_MAX",
]

# =============================================================================
# Wire format (A.8.2.2, A.8.3.1, A.8.4.1)
# =============================================================================

MAGIC: Final = b"C2PATXT\x00"
"""Wrapper magic number, 0x4332504154585400 (A.8.2.2).

Stored as literal bytes rather than an integer so that serialization never depends
on host integer width or byte order. This constant is also the package name.
"""

VERSION: Final = 1
"""Wrapper version (A.8.2.2 fixes ``version = 1``).

Distinct from the C2PA specification version. A wrapper carrying any other value is
rejected with ``manifest.text.corruptedWrapper``; A.8 defines no other version, so
tolerating one would mean guessing at a structure that does not exist.
"""

HEADER_SIZE: Final = 13
"""Bytes before the JUMBF payload: magic(8) + version(1) + manifestLength(4).

The wrapper therefore occupies exactly ``HEADER_SIZE + manifestLength`` decoded
bytes. That figure -- not the end of the contiguous selector run -- delimits the
wrapper, so variation selectors the author wrote immediately afterwards are not
swallowed into it.
"""

MARKER: Final = "\ufeff"
"""U+FEFF, the mandatory single-character prefix (A.8.4.1).

Spelled as an escape, never as a literal: an invisible character in source is
unreviewable. Note that a leading UTF-8 byte-order mark is also U+FEFF and will be
scanned as a wrapper candidate; it is rejected on the magic check, not specially.
"""

# manifestLength is a big-endian unsigned 32-bit integer. A.8.2.2 declares it in
# ISO-BMFF class syntax; the local A.8 fixture pins that chosen reading of the wire.
LENGTH_STRUCT_FORMAT: Final = ">I"

# =============================================================================
# Byte-to-selector mapping (A.8.3.1, A.8.3.2)
# =============================================================================

VS_LOW_BASE: Final = 0xFE00
"""Bytes 0x00-0x0F map to U+FE00 + b (Variation Selectors block)."""

VS_LOW_MAX: Final = 0xFE0F
"""Last code point of the low block. Encodes to 3 UTF-8 bytes."""

VS_HIGH_BASE: Final = 0xE0100
"""Bytes 0x10-0xFF map to U+E0100 + (b - 16) (Variation Selectors Supplement)."""

VS_HIGH_MAX: Final = 0xE01EF
"""Last code point of the high block. Encodes to 4 UTF-8 bytes."""

# =============================================================================
# DoS protection limits
# =============================================================================
#
# This library parses untrusted text and an untrusted length-prefixed binary
# structure, and is expected to run on a public, unauthenticated verification
# surface. A.8's uint32 length permits up to 2^32-1 and specifies no smaller
# operational resource cap, so the smaller bounds below are ours.
#
# Scope note: there is deliberately no maximum input length. A body-size cap belongs
# to the service that accepts the request, not to a codec whose caller has already
# materialised the string in memory. Bounding what we allocate on the attacker's
# instruction is our job; refusing large legitimate documents is not.

MAX_MANIFEST_LENGTH: Final = 1 << 21
"""Largest accepted ``manifestLength``, 2 MiB.

The limit is checked before a declared payload is accepted. It leaves room for
certificate chains and embedded assertion data while keeping the accepted manifest
finite. Python slicing would not allocate the declared length when the bytes are
absent; this is a payload-policy bound, not a claim about such an allocation and not a
C2PA limit.
"""

MAX_SELECTOR_RUN: Final = MAX_MANIFEST_LENGTH + HEADER_SIZE
"""Maximum selector code points decoded after one marker candidate.

The locator reads only this prefix of a longer contiguous run, independently of what
``manifestLength`` claims.
"""

MAX_CBOR_DEPTH: Final = 32
"""Maximum CBOR nesting depth accepted by both encoder and decoder.

A short byte string can otherwise drive recursion through nested arrays, maps or
tags. The bound applies only to CBOR. JUMBF child boxes are kept as opaque payloads
and parsed one level at a time, so the JUMBF codec does not recurse.
"""

MAX_NONSTARTERS: Final = 30
"""Largest NFKD nonstarter sequence accepted for NFC normalization.

UAX #15 D3 defines this as the Stream-Safe Text Format boundary. C2PA requires NFC
but sets no resource limit for canonical ordering, so this is package policy.
"""
