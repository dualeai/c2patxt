"""Local A.8 wire vectors, producer-byte stability, and legacy read compatibility."""

from __future__ import annotations

import pytest

from tests.vectors.loader import VECTOR_FILE, Vector, load_vectors, vector_id

VECTORS = load_vectors()

#: Immutable public vector identities. A removed or replaced row is a wire-corpus
#: change even when the resulting file remains non-empty and every remaining row passes.
_EXPECTED_VECTOR_INVENTORY = [
    ("E0001", "@Part0", "embed", "OK"),
    ("X0001", "@Part1", "extract", "OK"),
    ("X0002", "@Part2", "extract", "manifest.text.corruptedWrapper"),
    ("X0003", "@Part2", "extract", "manifest.text.multipleWrappers"),
    ("X0004", "@Part2", "extract", "NONE"),
    ("E0002", "@Part0b", "embed", "OK"),
    ("E0003", "@Part0b", "embed", "OK"),
    ("E0004", "@Part0b", "embed", "OK"),
    ("E0005", "@Part0b", "embed", "OK"),
    ("E0006", "@Part0b", "embed", "OK"),
    ("X0005", "@Part1b", "extract", "NONE"),
    ("X0006", "@Part1b", "extract", "NONE"),
    ("X0007", "@Part1b", "extract", "NONE"),
    ("X0008", "@Part1b", "extract", "NONE"),
    ("X0009", "@Part1b", "extract", "NONE"),
    ("X0010", "@Part1b", "extract", "NONE"),
    ("X0011", "@Part1b", "extract", "NONE"),
    ("X0012", "@Part1b", "extract", "NONE"),
    ("X0013", "@Part2b", "extract", "OK"),
    ("X0014", "@Part2c", "extract", "manifest.text.corruptedWrapper"),
    ("X0015", "@Part2c", "extract", "manifest.text.corruptedWrapper"),
    ("X0016", "@Part2c", "extract", "manifest.text.corruptedWrapper"),
    ("X0021", "@Part2e", "extract", "OK"),
    ("X0022", "@Part2e", "extract", "OK"),
    ("X0023", "@Part2e", "extract", "OK"),
    ("X0017", "@Part2d", "extract", "OK"),
    ("X0018", "@Part2d", "extract", "OK"),
    ("X0019", "@Part2d", "extract", "manifest.text.corruptedWrapper"),
    ("X0020", "@Part2d", "extract", "manifest.text.corruptedWrapper"),
]


def test_data_portion_is_pure_ascii() -> None:
    """The file must survive editors, terminals, git diff and code review.

    Its subject matter is invisible characters. Storing them literally is how a
    vector corpus silently rots. NormalizationTest.txt applies the same rule.
    """
    raw = VECTOR_FILE.read_bytes()
    offenders = [(i, b) for i, b in enumerate(raw) if b > 0x7F]
    assert offenders == [], f"non-ASCII bytes at {offenders[:5]}"


def test_file_has_no_byte_order_mark() -> None:
    """A vector file about U+FEFF must not itself start with U+FEFF."""
    assert not VECTOR_FILE.read_bytes().startswith(b"\xef\xbb\xbf")


def test_line_endings_are_lf_only() -> None:
    assert b"\r" not in VECTOR_FILE.read_bytes()


def test_records_parse_and_ids_are_unique() -> None:
    assert VECTORS, "vector file yielded no records"
    ids = [v.id for v in VECTORS]
    assert len(ids) == len(set(ids)), "record ids must be unique and never reused"


def test_the_vector_inventory_is_exact() -> None:
    """A deleted, substituted, reordered or re-partitioned record is a visible corpus change."""
    assert [(vector.id, vector.part, vector.op, vector.status) for vector in VECTORS] == _EXPECTED_VECTOR_INVENTORY


@pytest.mark.parametrize("vector", VECTORS, ids=vector_id)
def test_record_shape_matches_its_status(vector: Vector) -> None:
    """Status governs which fields must be populated."""
    assert vector.op in {"embed", "extract"}
    assert vector.text != b"" or "no-wrapper" in vector.flags or vector.id.startswith("X")
    if vector.is_ok:
        # An empty `expect` normally means the author forgot to fill the column. It is
        # a real value for exactly one shape -- a wrapper declaring manifestLength 0 --
        # so that shape carries a flag saying the emptiness is the point.
        assert vector.expect != b"" or "empty-manifest" in vector.flags, "an OK record must state its expected bytes"
    else:
        assert vector.expect == b"", "a failure record must not state expected bytes"
        assert vector.status == "NONE" or "." in vector.status, (
            "a failure status must be NONE or a dotted C2PA status code"
        )


def test_failure_statuses_are_spec_code_strings() -> None:
    """Codes are the specification's own strings, never paraphrases.

    A user who reads our error and searches the C2PA specification must land on
    the right clause.
    """
    known = {
        "OK",
        "NONE",
        "manifest.text.corruptedWrapper",
        "manifest.text.multipleWrappers",
        "assertion.dataHash.mismatch",
        "assertion.dataHash.malformed",
    }
    unknown = {v.status for v in VECTORS} - known
    assert unknown == set(), f"unrecognised status codes: {unknown}"


def test_every_flag_is_documented_in_the_header() -> None:
    """A flag nobody documented is a flag nobody can act on."""
    header = VECTOR_FILE.read_text("ascii").split("@Part0")[0]
    for vector in VECTORS:
        for flag in vector.flags:
            assert f"\n#   {flag} " in header, f"flag {flag!r} is undocumented"


def _wrapper_from_spec_formula(payload: bytes) -> str:
    """Build a wrapper straight from A.8.2.2 and A.8.3.1, independent of src/.

    Deliberately NOT importing the package. This is the specification transcribed a
    second time, so that the vector file is validated against the spec rather than
    against our own encoder. A fixture generated by calling our code and asserted
    against our code proves only that a function is its own inverse.
    """
    import struct

    magic = bytes.fromhex("4332504154585400")
    body = magic + bytes([1]) + struct.pack(">I", len(payload)) + payload
    # "﻿" spelled as an escape, never as a literal: an invisible character in
    # source is unreviewable, and this file is about invisible characters.
    return "\ufeff" + "".join(chr(0xFE00 + b) if b <= 0x0F else chr(0xE0100 + (b - 16)) for b in body)


@pytest.mark.parametrize(
    "vector",
    [v for v in VECTORS if v.op == "embed" and v.is_ok],
    ids=vector_id,
)
def test_embed_records_match_the_spec_formula(vector: Vector) -> None:
    """expect == text || U+FEFF || selector-encoded wrapper, per A.8."""
    text = vector.text.decode("utf-8")
    derived = (text + _wrapper_from_spec_formula(vector.payload)).encode("utf-8")
    assert derived == vector.expect


def test_extract_success_records_carry_a_locatable_wrapper() -> None:
    """Every OK extract record's text must actually contain its expected payload."""
    for vector in (v for v in VECTORS if v.op == "extract" and v.is_ok):
        text = vector.text.decode("utf-8")
        assert _wrapper_from_spec_formula(vector.expect) in text, vector.id


#: SHA-256 of the manifest store produced by a fully pinned ``embed``. Regenerate
#: ONLY as part of a deliberate MAJOR release.
_GOLDEN_STORE_SHA256 = "2580096b93b4e4abfc6b12cda78db9a71fcfa33ca6ba5a574ddd8676a2777791"

#: SHA-256 of the complete UTF-8 document emitted by v0.1.2 for the legacy fixture.
#: The carrier below is rebuilt from the frozen A.8 literals, never current package code.
_LEGACY_MARKED_SHA256 = "3b51db34f58d4cba6cfbd6b4940583e738b211f821bab06f0e7bf3b0b4a80a01"


def test_the_previous_major_wire_still_verifies() -> None:
    """Version 1 changed producer bytes, not the ability to read version-0 marks.

    This v0.1.2-produced store is a local compatibility fixture, not independent
    interoperability evidence.
    """
    import base64
    import datetime
    import hashlib

    from c2patxt import Provenance, VerifyContext, _cose, extract, verify
    from c2patxt.status import StatusCode

    encoded = (VECTOR_FILE.parent.parent / "fixtures" / "legacy" / "v0.1.2-manifest-store.b64").read_bytes()
    raw = base64.b64decode(b"".join(encoded.splitlines()), validate=True)
    marked = "Hello world." + _wrapper_from_spec_formula(raw)
    assert hashlib.sha256(marked.encode("utf-8")).hexdigest() == _LEGACY_MARKED_SHA256

    store = extract(marked)
    assert store is not None
    assert store.raw == raw
    assert store.hash_data is not None
    assert store.hash_data["pad"], "the fixture must retain version 0's signed data-hash slack"
    assert _cose.parse(store.signature).unprotected == {}, "the fixture must predate version 1's COSE pad"

    verdict = verify(
        marked,
        context=VerifyContext(now=datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)),
    )
    assert verdict.state is Provenance.VALID
    assert StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED in verdict.codes()


def test_the_signed_manifest_bytes_are_exactly_what_they_were() -> None:
    """Pin exact producer bytes from a fully deterministic public ``embed``.

    The Annex A.8 vector pins the carrier, not the signed manifest inside it. A hash of
    the manifest is the one extra oracle needed for the repository's wire-major rule.
    The previous producer bytes remain executable in the compatibility test above.
    """
    import datetime
    import hashlib
    import uuid

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from c2patxt import EmbedContext, embed, extract
    from c2patxt.signing import Signer
    from tests.conftest import DISCLOSURE, build_certificate

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Signer(private_key=key, certificates=(build_certificate(key),))
    context = EmbedContext(
        manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000001"),
        instance_id="xmp:iid:00000000-0000-4000-8000-000000000002",
        when=datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc),
    )

    marked = embed("Hello world.", signer, DISCLOSURE, context=context)
    store = extract(marked)
    assert store is not None

    assert hashlib.sha256(store.raw).hexdigest() == _GOLDEN_STORE_SHA256, "the SIGNED MANIFEST bytes changed"
