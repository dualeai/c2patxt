"""Hostile-input and boundary regressions.

Each test carries a concrete input that reaches public behavior or a parser boundary.
"""

from __future__ import annotations

import struct
from typing import Literal

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from c2patxt import VerifyContext, _cbor, embed, verify
from c2patxt._cbor import loads
from c2patxt._jumbf import TBOX_SUPERBOX, JumbfError, content_type_uuid, parse_superbox
from c2patxt._locate import find_wrappers, locate
from c2patxt._selectors import build_wrapper, bytes_to_selectors
from c2patxt.constants import MAGIC, MARKER
from c2patxt.exceptions import MarkCorruptError, UnencodableTextError
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from c2patxt.verdict import Provenance
from tests.conftest import DISCLOSURE, RecordingTrustEvaluator
from tests.test_embed import PINNED as _PINNED

#: A CBOR map as the decoder produces one; every CBOR item may be a key.
CborMap = dict[_cbor.CborKey, _cbor.CborValue]


def _box(tbox: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + tbox + payload


def _description() -> bytes:
    return _box(b"jumd", content_type_uuid(b"cbor") + bytes([2]) + b"x\x00")


def test_xlbox_of_zero_does_not_hang() -> None:
    """A 51-byte input made the content loop advance by nothing, forever.

    _read_header returned the raw uint64 XLBox with no floor, so a declared 0 gave
    child_length == 0 and `pos += child_length` never progressed. SECURITY.md puts
    CPU exhaustion from adversarial input firmly in scope.
    """
    child = struct.pack(">I", 1) + b"free" + struct.pack(">Q", 0)
    data = _box(TBOX_SUPERBOX, _description() + child)

    # The non-termination guard is pyproject.toml's global ``--timeout=30``. The
    # assertion below owns the semantic result; CPU and memory measurements belong to
    # the CodSpeed benchmark job.
    with pytest.raises(JumbfError, match="XLBox 0 is shorter"):
        parse_superbox(data)


def test_a_short_xlbox_cannot_substitute_a_fabricated_box() -> None:
    """XLBox between 1 and 15 desynchronised the parser.

    It left payload_offset past the box end, so the content loop resumed INSIDE the
    XLBox field: the genuine cbor/REAL box vanished and a fabricated box took its
    place. A caller scanning content for the claim could be handed a different box
    than the bytes declare.
    """
    child = struct.pack(">I", 1) + b"free" + struct.pack(">Q", 8)
    data = _box(TBOX_SUPERBOX, _description() + child + _box(b"cbor", b"REAL"))

    with pytest.raises(JumbfError, match="shorter than the header"):
        parse_superbox(data)


def test_cbor_boolean_key_does_not_collide_with_integer_one() -> None:
    """`isinstance(True, int)` let CBOR true/false through as a map key.

    The key then collided with integer 1 in the output dict, so a two-entry map
    decoded to one entry and silently dropped content the signer wrote. For a
    decoder over signed claim structures that is content substitution, not a
    formatting nit.
    """
    decoded = loads(bytes.fromhex("a2016161f56162"))
    assert isinstance(decoded, dict)
    decoded_map: CborMap = {key: value for key, value in decoded.items()}
    assert decoded_map[1] == "a"
    compound = [key for key in decoded_map if isinstance(key, _cbor.MapKey)]
    assert len(compound) == 1
    assert compound[0].value is True
    assert decoded_map[compound[0]] == "b"


def test_a_corrupt_candidate_does_not_hide_a_genuine_wrapper() -> None:
    """Appending ~22 characters made a valid wrapper unfindable.

    parse_wrapper_body raised out of the scan loop, discarding every match already
    collected. That is the denial of service the module's own hazard-1 rationale
    rejects, arriving through the parse path instead of the scan path, and it is
    SECURITY.md's "failure to detect a mark that is present and valid".
    """
    genuine = "Genuine document. " + build_wrapper(bytes.fromhex("deadbeef"))
    corrupt_tail = MARKER + bytes_to_selectors(MAGIC + bytes([2]) + b"\x00\x00\x00\x00")

    alone = locate(genuine)
    assert alone is not None
    assert locate(genuine + " PS." + corrupt_tail) == alone


def test_a_corrupt_wrapper_alone_still_reports_corruption() -> None:
    """Tolerating a corrupt neighbour must not silence corruption entirely."""
    from c2patxt.exceptions import MarkCorruptError

    corrupt = "Doc." + MARKER + bytes_to_selectors(MAGIC + bytes([2]) + b"\x00\x00\x00\x00")
    with pytest.raises(MarkCorruptError, match="version 2"):
        locate(corrupt)


def test_a_structural_error_with_no_position_claims_no_position() -> None:
    """Only errors tied to actual input bytes may report a position."""
    assert str(MarkCorruptError("something is wrong", 0)) == "something is wrong"
    assert str(MarkCorruptError("truncated", 99, 3)).endswith("(at end of text)")
    assert str(MarkCorruptError("bad byte", 2, 6)).endswith("(at byte 2)")


@pytest.mark.parametrize("form", ["NFC", "NFD", "NFKC", "NFKD"])
def test_no_normalization_form_removes_the_mark(form: Literal["NFC", "NFD", "NFKC", "NFKD"]) -> None:
    """The gate behind docs/robustness.md's 1.000 in the "mark still found" column.

    The robustness battery needs the PAN'26 corpus and so cannot run in CI, which is
    offline by design. This is the part the suite can check on every commit:
    aggressive normalization on ingest must not remove the carrier characters.

    Asserted on the CODE POINTS rather than by round-tripping a mark, so it holds for
    every possible payload rather than for the one this test happened to build.
    """
    import unicodedata

    from c2patxt.constants import MARKER, VS_HIGH_BASE, VS_LOW_BASE

    codepoints = [ord(MARKER), *range(VS_LOW_BASE, VS_LOW_BASE + 16), *range(VS_HIGH_BASE, VS_HIGH_BASE + 240)]
    for codepoint in codepoints:
        char = chr(codepoint)
        assert unicodedata.normalize(form, char) == char, f"U+{codepoint:04X} changed under {form}"


@pytest.mark.parametrize(
    "patches",
    [
        # InvalidVersion: 31 is not a valid X509 version
        [(1445, 0x1F)],
        # KeyError: 0 -- raised from `certificate.issuer`, an ATTRIBUTE ACCESS
        [(1473, 0x00)],
        # DuplicateExtension: Duplicate 2.5.29.15 extension found
        [(1047, 105), (1615, 42), (1622, 15)],
    ],
    ids=["x509-version", "issuer-name-oid", "duplicate-extension"],
)
def test_hostile_certificate_bytes_do_not_escape_verify(signer: Signer, patches: list[tuple[int, int]]) -> None:
    """Hostile lazy-DER failures become an invalid-credential verdict.

    The fixed offsets exercise ``InvalidVersion``, ``KeyError``, and
    ``DuplicateExtension`` from fields that ``cryptography`` parses lazily. The exact
    credential status keeps each vector aimed at the certificate boundary.
    """
    marked = embed("Hello world.", signer, DISCLOSURE, context=_PINNED)
    matches = find_wrappers(marked)
    assert len(matches) == 1
    payload = bytearray(matches[0].payload)
    assert len(payload) == 1_795, "the vectors are offsets into the pinned manifest"
    visible = marked[: marked.index(MARKER)]

    for offset, value in patches:
        assert payload[offset] != value, f"offset {offset} already holds {value:#04x}; the vector is inert"
        payload[offset] = value

    evaluator = RecordingTrustEvaluator(trusted=True)
    context = VerifyContext(
        anchors_pem=signer.certificates[0].public_bytes(Encoding.PEM),
        trust_evaluator=evaluator,
    )
    verdict = verify(visible + build_wrapper(bytes(payload)), context=context)

    assert verdict.state is Provenance.INVALID
    assert not evaluator.calls, "hostile certificate bytes reached the trust backend"
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes(), (
        f"the credential must be rejected, not merely survived: {[c.value for c in verdict.codes()]}"
    )
    assert StatusCode.CLAIM_SIGNATURE_MISSING not in verdict.codes()


def test_the_truncation_wording_switches_exactly_at_the_end_of_the_document() -> None:
    """``pos >= document_length`` chooses between "end of text" and "byte N".

    The exact end position is the boundary between the two messages.
    """
    size = 3

    assert str(MarkCorruptError("truncated", size, size)).endswith("(at end of text)")
    assert str(MarkCorruptError("bad byte", size - 1, size)).endswith(f"(at byte {size - 1})")


def test_the_surrogate_position_is_the_index_that_was_reported() -> None:
    """``UnencodableTextError.position`` identifies the unpaired surrogate."""
    text = "ok\ud800bad"
    with pytest.raises(UnencodableTextError) as excinfo:
        verify(text)

    assert excinfo.value.position == 2, "the lone surrogate is at index 2"
    assert str(excinfo.value).count("index 2") == 1
