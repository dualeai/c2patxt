"""Places where we deliberately DISAGREE with another implementation.

``tests/test_third_party_interop.py`` checks where we AGREE. This file pins where we
do not, and every test names the implementation, the defect, and the evidence.

The reason each test carries that comment: without it, a future contributor comparing
us against a reference implementation reads a difference as our bug, "fixes" it, and
silently breaks conformance. A test that says only "toggles=0x02 parses" is one
someone deletes; a test that says "c2pa-rs fails on this legal box, and here are five
implementations that do not" is one they read first.

Every construction here is by hand from the ISO field layout. Building a fixture with
our own encoder and asserting our own decoder reads it back would pass just as well
if both halves shared the bug being guarded against.
"""

from __future__ import annotations

import pytest

from c2patxt import _jumbf
from c2patxt._jumbf import DescriptionBox, JumbfBox, JumbfError, Toggle, parse_superbox, serialize_superbox

UUID = _jumbf.content_type_uuid(b"cbor")


def _description(toggles: int, tail: bytes) -> bytes:
    """Hand-build a jumd box: uuid(16) | toggles(1) | fields, per ISO 19566-5 A.3."""
    payload = UUID + bytes([toggles]) + tail
    return (8 + len(payload)).to_bytes(4, "big") + b"jumd" + payload


#: A minimal content box. A superbox must carry at least one, so every fixture here
#: needs one even when the test is only about the description box.
_CONTENT = (8 + 1).to_bytes(4, "big") + b"cbor" + b"\xf6"


def _superbox(description: bytes, content: bytes = _CONTENT) -> bytes:
    body = description + content
    return (8 + len(body)).to_bytes(4, "big") + b"jumb" + body


# --------------------------------------------------------------------------------
# 1. c2pa-rs label parsing
# --------------------------------------------------------------------------------


def test_a_label_toggle_alone_is_enough_to_read_a_label() -> None:
    """DIVERGENCE: c2pa-rs `boxes.rs:2085` requires ``(togs & 0x03) == 0x03`` before
    reading a label, so it FAILS on a legal box with toggles=0x02.

    ISO 19566-5 gates the label on bit 0x02 alone; 0x01 is Requestable, an unrelated
    property. Five independent implementations test 0x02 on its own -- MIPAMS,
    ExifTool, thorfdbg, iLEAPP, exifmodern -- and a real file bears it out: our own
    byte-level parse of ``image_5jumbf.jpg`` APP11 #1 shows a toggles=0x02 box
    labelled "faiz mp3 data".

    SVTA made the same mistake independently, which is why this is worth a test
    rather than a comment: two implementations converging on a wrong reading is how
    a wrong reading becomes the de facto standard.
    """
    box, _ = parse_superbox(_superbox(_description(Toggle.LABEL, b"a label\x00")))

    assert box.description.label == "a label"
    assert box.description.requestable is False


# --------------------------------------------------------------------------------
# 2. faceless2/c2pa ID width
# --------------------------------------------------------------------------------


def test_the_box_id_is_four_bytes_not_two() -> None:
    """DIVERGENCE: faceless2/c2pa reads and writes the jumd ID as 2 BYTES and clamps
    anything above 65535.

    Every other implementation uses 4 bytes big-endian, and MIPAMS states it outright
    as ``INT_BYTE_SIZE = 4``. The discriminating value is one above the 16-bit
    ceiling: a 2-byte reader either truncates it or refuses it.
    """
    big = 70000
    assert big > 0xFFFF

    original = JumbfBox(
        description=DescriptionBox(uuid=UUID, label="x", box_id=big),
        content=((b"cbor", b"\xf6"),),
    )
    serialized = serialize_superbox(original)
    assert big.to_bytes(4, "big") in serialized

    box, _ = parse_superbox(serialized)
    assert box.description.box_id == big


# --------------------------------------------------------------------------------
# 3. WG1 reference implementation 2 hash length
# --------------------------------------------------------------------------------


def test_the_jumd_signature_field_is_thirty_two_bytes() -> None:
    """DIVERGENCE: WG1 RI-2 ``db_jumbf_desc_box.cpp`` ``deserialize()`` reads 256
    bytes for the signature, while its OWN ``serialize()`` writes 32 and
    ``set_box_size()`` adds 32. The reader and the writer of the same file disagree.

    32 is correct: it is a SHA-256, and the WG1 conformance dataset is byte-identical
    to its own ``sha256.obj`` files at 32.
    """
    assert len(bytes(32)) == 32
    with pytest.raises(ValueError, match="32-byte SHA-256"):
        DescriptionBox(uuid=UUID, label="x", signature=bytes(256))

    box = DescriptionBox(uuid=UUID, label="x", signature=bytes(range(32)))
    assert box.signature is not None
    assert len(box.signature) == 32


# --------------------------------------------------------------------------------
# 4. The off-by-one toggle assignment
# --------------------------------------------------------------------------------


def test_an_id_without_a_label_parses_as_id_present() -> None:
    """DIVERGENCE: three of five AI-authored repositories found encode 0x01=label and
    0x02=ID -- shifted one bit down from the real assignment.

    (Apertrue/c2pa-extractor, ob192/ai-media-detection-tool,
    encypherai/c2pa-conformance-suite; richardwooding/c2pa and 0verkilll/jpeg get it
    right.)

    The bug survives because C2PA itself always writes toggles=0x03, so the common
    case works under either reading and no round-trip test catches it. THIS is the
    discriminating case: a box with 0x04 alone carries an ID and no label. Under the
    wrong assignment it reads as a label, and the four ID bytes get consumed as
    NUL-terminated text.
    """
    box, _ = parse_superbox(_superbox(_description(Toggle.ID, (7).to_bytes(4, "big"))))

    assert box.description.box_id == 7
    assert box.description.label is None


def test_the_toggle_bits_have_the_values_iso_assigns() -> None:
    """The assignment itself, asserted as values rather than inferred from behaviour.

    If this ever changes, every test above is testing a different format.
    """
    assert Toggle.REQUESTABLE == 0x01
    assert Toggle.LABEL == 0x02
    assert Toggle.ID == 0x04
    assert Toggle.SIGNATURE == 0x08
    assert Toggle.PRIVATE == 0x10


# --------------------------------------------------------------------------------
# 5. Box type drift
# --------------------------------------------------------------------------------


@pytest.mark.parametrize("legacy", [b"cais", b"cain", b"c2vc"])
def test_we_never_emit_a_c2pa_rs_legacy_box_type(legacy: bytes) -> None:
    """DIVERGENCE: ``cais``, ``cain`` and ``c2vc`` are c2pa-rs legacy types absent
    from the C2PA specification entirely.

    Emitting them would make our output depend on one implementation's history rather
    than on the specification.
    """
    from c2patxt import manifest

    emitted = {
        bytes(manifest.UUID_MANIFEST_STORE)[:4],
        bytes(manifest.UUID_MANIFEST)[:4],
        bytes(manifest.UUID_ASSERTION_STORE)[:4],
        bytes(manifest.UUID_CLAIM)[:4],
        bytes(manifest.UUID_CLAIM_SIGNATURE)[:4],
    }
    assert legacy not in emitted


@pytest.mark.parametrize("four_cc", [b"c2tm", b"c2md", b"cais"])
def test_an_unknown_box_uuid_is_skipped_not_rejected(four_cc: bytes) -> None:
    """C2PA 11.1.2: a box whose UUID is not recognised is SKIPPED, not an error.

    ``c2tm`` and ``c2md`` are in the specification but missing from c2pa-rs, so a
    conforming producer can legitimately emit boxes we do not know. Rejecting them
    would make us the implementation that breaks on valid input -- the same class of
    defect as every divergence above, pointed at ourselves.
    """
    unknown = _jumbf.content_type_uuid(four_cc)
    payload = UUID + bytes([Toggle.REQUESTABLE | Toggle.LABEL]) + b"outer\x00"
    inner = (8 + 16).to_bytes(4, "big") + b"jumb" + unknown

    box, _ = parse_superbox(_superbox((8 + len(payload)).to_bytes(4, "big") + b"jumd" + payload, inner + _CONTENT))
    assert box.description.label == "outer"


# --------------------------------------------------------------------------------
# Where we are STRICTER than everyone
# --------------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["a/b", "a;b", "a?b", "a#b", "a﻿b", "a￿b", "a\x00b", "a\x1fb", "a\x7fb"])
def test_forbidden_label_characters_are_refused(bad: str) -> None:
    """WE ARE STRICTER THAN EVERY OTHER IMPLEMENTATION, on purpose.

    C2PA 11.1.4.1.1 forbids U+0000-001F, U+007F-009F, ``/ ; ? #``, plus U+FEFF,
    U+FFFF and the surrogate range. No implementation anywhere enforces this. Labels
    become JUMBF URI path components, so an unescaped ``/`` or ``#`` in a label is a
    URI-injection primitive against any consumer that resolves ``self#jumbf=`` URIs
    by string manipulation -- which is how they are resolved.
    """
    with pytest.raises(ValueError, match="label"):
        DescriptionBox(uuid=UUID, label=bad)


def test_a_colon_is_allowed_because_c2pa_labels_require_it() -> None:
    """The one character we deliberately do NOT forbid.

    faceless2/c2pa re-allows ``:`` after copying a forbidden-character list, and its
    own commented-out "official list from ISO19566" line includes it -- the closest
    thing to a published quote of the ISO text we have found. But C2PA's own manifest
    labels are ``urn:c2pa:...`` -- 8.1's ABNF, ``c2pa_urn = "urn:c2pa:" UUID ...`` -- so
    forbidding ``:`` would make the specification unable to express its own required
    labels. C2PA 11.1.4.1.1 governs here.

    THE LABEL USED HERE IS THE ONE WE ACTUALLY EMIT. An earlier version wrote
    ``urn:uuid:``, which is RFC 9562's namespace rather than C2PA's, and is a defect this
    package fixed in signed bytes -- so the file whose job is to stop a contributor
    "reading a difference as our bug" was itself carrying the bug as its example.
    """
    box = DescriptionBox(uuid=UUID, label="urn:c2pa:00000000-0000-0000-0000-000000000000")
    assert box.label is not None
    assert box.label.startswith("urn:c2pa:")


def test_reserved_toggle_bits_are_refused() -> None:
    """Bits above 0x10 are unassigned. A parser that ignores them is guessing at a
    layout it has never seen, which is how a future extension gets misread as this
    version's fields."""
    with pytest.raises(JumbfError, match="reserved toggle"):
        parse_superbox(_superbox(_description(0x80 | Toggle.LABEL, b"x\x00")))
