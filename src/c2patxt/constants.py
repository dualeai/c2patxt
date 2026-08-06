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
    "MAX_JUMBF_DEPTH",
    "MAX_MANIFEST_LENGTH",
    "MAX_SELECTOR_RUN",
    "UTF8_BYTES_PER_MANIFEST_BYTE",
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
# ISO-BMFF class syntax and the prose never states endianness -- the only clause in
# the specification that omits it, where clause 11, clause 18.6 and A.3.x all state
# it. Big-endian is confirmed by both public implementations and by re-deriving
# their published vectors; see tests/vectors/A8ConformanceTest-1.2.0.txt note 1.
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

UTF8_BYTES_PER_MANIFEST_BYTE: Final = 3.9375
"""Theoretical worst-case UTF-8 cost per manifest byte: (16*3 + 240*4) / 256.

Measured on real manifests it lands at 3.88-3.91, because length prefixes, zero
padding and hash high-nibbles put more bytes in the cheap 3-byte band. The asymmetry
is a property of the specification and is not optimisable.

(Re-measure after any change to what is emitted; see
``tests/test_embed.py::test_the_published_size_figures_are_still_true``.)
"""

# =============================================================================
# DoS protection limits
# =============================================================================
#
# This library parses untrusted text and an untrusted length-prefixed binary
# structure, and is expected to run on a public, unauthenticated verification
# surface. A.8 specifies NO bounds of any kind, so every bound below is ours.
#
# Scope note: there is deliberately no maximum input length. A body-size cap belongs
# to the service that accepts the request, not to a codec whose caller has already
# materialised the string in memory. Bounding what we allocate on the attacker's
# instruction is our job; refusing large legitimate documents is not.

MAX_MANIFEST_LENGTH: Final = 1 << 21
"""Largest accepted ``manifestLength``, 2 MiB.

THE MOST IMPORTANT LIMIT HERE. ``manifestLength`` is a 32-bit field read from
attacker-controlled input, so an unbounded reader can be told to allocate 4 GiB by a
13-byte header -- `HEADER_SIZE` below, and nothing longer is needed to ask. The
bound must be applied BEFORE allocating, not after reading.

2 MiB is roughly three orders of magnitude above a realistic manifest: measured
Ed25519 manifest stores are 1,797 bytes self-signed and 2,120 bytes with a leaf and
CA. Both are held by `tests/test_embed.py`, and the leaf+CA row NAMES ITS CONSTRUCTION
there -- without that the number is not reproducible, which is how this file came to
publish 2,102 while `docs/platform-handoff.md` published 2,090 a day apart, with
nothing asserting either. Even an RSA-4096 chain
lands near 4 KB. The headroom costs nothing and avoids
rejecting a legitimate manifest carrying an unusually long certificate chain.
"""

MAX_SELECTOR_RUN: Final = MAX_MANIFEST_LENGTH + HEADER_SIZE
"""Largest contiguous variation-selector run decoded from a single candidate.

Bounds the scan itself, independently of what ``manifestLength`` claims, so a run of
selectors with no valid header cannot make us walk an arbitrarily long span.
"""

MAX_JUMBF_DEPTH: Final = 32
"""Maximum nesting depth, for JUMBF superboxes AND for CBOR.

TWO SUBSYSTEMS, ONE CONSTANT, and the name says only the first. ``_jumbf`` bounds
superbox recursion with it; ``_cbor`` bounds BOTH encode and decode with it. Raising it
for a deeply nested manifest would silently widen what the CBOR decoder accepts from
attacker-controlled bytes, which is the decision this docstring exists to stop someone
taking by accident.

JUMBF superboxes nest arbitrarily, so a small input can describe unbounded recursion.
cbor2 shipped CVE-2026-26209 for exactly this class of bug in a neighbouring format
and settled on a default of 400; c2pa-rs independently chose 32 for JUMBF. We take
the tighter of the two, since real C2PA manifests nest four levels deep
(store > manifest > assertion store > assertion).
"""
