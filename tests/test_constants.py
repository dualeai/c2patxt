"""Wire constants asserted against the specification and the vector file.

These assertions matter more than they look. mutmut 3.x does not mutate code outside
functions, so module-level constants -- exactly the off-by-one surface we care about
(``<= 0x0F`` vs ``< 0x10``, ``0xE01EF`` vs ``0xE01F0``) -- are invisible to mutation
testing. Asserting them directly, and cross-checking against the vector file, is the
substitute.
"""

from __future__ import annotations

import struct

from c2patxt import constants as c


def test_magic_is_the_spec_value() -> None:
    """A.8.2.2: magic = 0x4332504154585400, ASCII "C2PATXT\\0"."""
    assert bytes.fromhex("4332504154585400") == c.MAGIC
    assert c.MAGIC == b"C2PATXT\x00"
    assert len(c.MAGIC) == 8
    assert int.from_bytes(c.MAGIC, "big") == 0x4332504154585400


def test_header_size_matches_its_fields() -> None:
    """magic(8) + version(1) + manifestLength(4) == 13."""
    assert len(c.MAGIC) + 1 + struct.calcsize(c.LENGTH_STRUCT_FORMAT) == c.HEADER_SIZE
    assert c.HEADER_SIZE == 13


def test_length_field_is_big_endian_uint32() -> None:
    """The endianness A.8 never states. See vector file note 1."""
    assert struct.calcsize(c.LENGTH_STRUCT_FORMAT) == 4
    assert struct.pack(c.LENGTH_STRUCT_FORMAT, 4) == b"\x00\x00\x00\x04"
    assert struct.pack(c.LENGTH_STRUCT_FORMAT, 0xFFFF) == b"\x00\x00\xff\xff"


def test_marker_is_u_feff_and_not_a_literal() -> None:
    assert c.MARKER == "﻿"
    assert len(c.MARKER) == 1
    assert c.MARKER.encode("utf-8") == b"\xef\xbb\xbf"


def test_version_is_one() -> None:
    assert c.VERSION == 1


def test_selector_block_bounds_are_exact() -> None:
    """A.8.3.1/A.8.3.2 boundaries, including the block sizes they imply."""
    assert c.VS_LOW_BASE == 0xFE00
    assert c.VS_LOW_MAX == 0xFE0F
    assert c.VS_HIGH_BASE == 0xE0100
    assert c.VS_HIGH_MAX == 0xE01EF
    # 16 low selectors cover bytes 0x00-0x0F; 240 high selectors cover 0x10-0xFF.
    assert c.VS_LOW_MAX - c.VS_LOW_BASE + 1 == 16
    assert c.VS_HIGH_MAX - c.VS_HIGH_BASE + 1 == 240


def test_limits_bound_attacker_controlled_payloads() -> None:
    """A 32-bit length field does not override the accepted payload policy."""
    assert c.MAX_MANIFEST_LENGTH < 2**32
    # BOTH the literal and the derivation. The derivation alone was unfalsifiable --
    # character for character the definition in constants.py, with both operands imported
    # from the module under test -- which left MAX_SELECTOR_RUN as the one constant in
    # this file with no test that could fail, in a file whose whole purpose is that
    # mutation testing cannot reach constants.
    assert c.MAX_SELECTOR_RUN == 2_097_165
    assert c.MAX_SELECTOR_RUN == c.MAX_MANIFEST_LENGTH + c.HEADER_SIZE
    assert c.MAX_CBOR_DEPTH == 32
    assert c.MAX_NONSTARTERS == 30
