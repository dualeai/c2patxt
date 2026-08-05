"""Property-based tests. Hypothesis searches for the input we did not think of.

WHY THESE ARE NOT MORE ROUND TRIPS
-----------------------------------
``decode(encode(x)) == x`` is the weakest property a codec has: it stays true when
encode and decode share a bug, which is exactly the bug an in-house codec is most
likely to have. So the round trips here are paired with properties that hold against
an INDEPENDENT reference -- ``unicodedata`` for normalization, the A.8.3.1 formula
computed inline for the selector mapping -- and with properties about what must
NEVER happen, which no round trip can express.

The expensive ones are budgeted deliberately: embed() runs a padding search with a
full Ed25519 sign per candidate, so a 100-example default would dominate the suite.
"""

from __future__ import annotations

import contextlib
import unicodedata
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from c2patxt import (
    C2paTextError,
    MarkCorruptError,
    Provenance,
    UnencodableTextError,
    embed,
    extract,
    locate,
    strip,
    verify,
)
from c2patxt._cbor import CborDecodeError, dumps, loads
from c2patxt._selectors import bytes_to_selectors, selectors_to_bytes
from c2patxt.constants import MARKER
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from tests.conftest import DISCLOSURE, WHEN

#: Excludes surrogates, which UTF-8 cannot represent -- they have their own property
#: below. Everything else in the BMP and beyond is fair game.
TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200)


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


# --------------------------------------------------------------------------------
# The selector codec, against the A.8.3.1 formula rather than against itself
# --------------------------------------------------------------------------------


@given(st.binary(max_size=512))
def test_selectors_decode_back_to_the_same_bytes(payload: bytes) -> None:
    assert selectors_to_bytes(bytes_to_selectors(payload)) == payload


@given(st.binary(min_size=1, max_size=256))
def test_each_selector_matches_the_specification_formula(payload: bytes) -> None:
    """A.8.3.1 computed from LITERALS, so a wrong base offset cannot cancel out.

    The round trip above passes just as happily if both halves use the wrong plane.

    The literals are the point, and this docstring made the opposite claim while
    computing `expected` from `VS_LOW_BASE`/`VS_HIGH_BASE` imported out of the module
    under test -- under which a shifted plane cancels out exactly. Measured: move the
    low block to 0xFE10 with its span unchanged and this whole file still passed. The
    property survived only because `test_constants.py` pins the numbers, which is not
    what this file said held it.
    """
    encoded = bytes_to_selectors(payload)
    assert len(encoded) == len(payload)
    for char, byte in zip(encoded, payload, strict=True):
        expected = 0xFE00 + byte if byte < 0x10 else 0xE0100 + byte - 0x10
        assert ord(char) == expected


@given(st.binary(max_size=256))
def test_the_utf8_cost_of_a_run_follows_from_its_bytes(payload: bytes) -> None:
    """The fact the whole padding fixpoint rests on: cost depends on CONTENT.

    Bytes 0x00-0x0F land in U+FE00's plane and cost 3 UTF-8 bytes; everything else
    lands in U+E0100's and costs 4. If this ever stops holding, _fixpoint's search is
    solving the wrong problem.
    """
    expected = sum(3 if byte < 0x10 else 4 for byte in payload)
    assert len(bytes_to_selectors(payload).encode("utf-8")) == expected


# --------------------------------------------------------------------------------
# CBOR
# --------------------------------------------------------------------------------

CBOR_VALUE = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(2**63), max_value=2**64 - 1) | st.binary() | st.text(),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4),
    max_leaves=12,
)


@given(CBOR_VALUE)
def test_cbor_round_trips(value: object) -> None:
    assert loads(dumps(value)) == value


@given(CBOR_VALUE)
def test_cbor_encoding_is_deterministic(value: object) -> None:
    """Same value, same bytes, every time. The signature covers these bytes, so a
    non-deterministic encoder makes byte-stable re-embedding impossible.

    ``dumps(value) == dumps(value)`` alone is a TAUTOLOGY for any pure function -- it
    passes with ``dumps`` returning a constant. The real content is that the encoding
    survives a decode/re-encode cycle and stays identical, which pins the ORDERING
    RFC 8949 4.2.1 requires rather than merely pinning repeatability.
    """
    encoded = dumps(value)
    assert dumps(value) == encoded
    assert dumps(loads(encoded)) == encoded


@given(st.binary(max_size=64))
def test_cbor_never_raises_anything_but_its_own_error(payload: bytes) -> None:
    """Arbitrary bytes reach this decoder from attacker-controlled text.

    A stray IndexError or struct.error escaping here means a caller who correctly
    catches CborDecodeError still crashes.
    """
    with contextlib.suppress(CborDecodeError):
        loads(payload)


# --------------------------------------------------------------------------------
# What must never happen, on arbitrary input
# --------------------------------------------------------------------------------


@given(TEXT)
def test_verify_never_raises_an_unexpected_type(text: str) -> None:
    """verify()'s documented contract, searched rather than sampled.

    Only two exception types are permitted, both documented. Anything else -- an
    IndexError, a struct.error, a UnicodeDecodeError -- is a defect, because the
    integrator catching C2paTextError would not handle it.
    """
    try:
        verdict = verify(text)
    except C2paTextError:
        return
    assert verdict.state in set(Provenance)


@given(TEXT)
def test_locate_and_extract_agree_about_absence(text: str) -> None:
    """If one says unmarked, so must the other. A disagreement means a caller who
    checks locate() and then trusts extract() gets a surprise."""
    try:
        span, manifest = locate(text), extract(text)
    except MarkCorruptError:
        return
    assert (span is None) == (manifest is None)


@given(TEXT)
def test_strip_removes_every_marker_it_found(text: str) -> None:
    """After strip(), nothing locatable remains -- otherwise re-marking would produce
    the two-wrapper document strip() was called to avoid."""
    try:
        stripped = strip(text)
    except MarkCorruptError:
        return
    assert locate(stripped) is None


@given(st.text(alphabet=st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF), min_size=1, max_size=4))
def test_lone_surrogates_always_raise_our_own_error(surrogates: str) -> None:
    """Never a bare UnicodeEncodeError, which an integrator would not catch."""
    with pytest.raises(UnencodableTextError):
        verify(surrogates + MARKER + "x")


# --------------------------------------------------------------------------------
# The full pipeline. Budgeted: each example is a padding search of ~30 signatures.
# --------------------------------------------------------------------------------


@given(TEXT)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_marked_text_always_verifies(signer: Signer, text: str) -> None:
    """The end-to-end property, over text nobody chose by hand."""
    assert verify(embed(text, signer, DISCLOSURE)).state is Provenance.VALID


@given(TEXT)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_strip_undoes_embed_up_to_normalization(signer: Signer, text: str) -> None:
    """embed() normalizes to NFC, so the identity holds against NFC(text), not text.

    Asserted against ``unicodedata`` rather than against embed()'s own output, so a
    normalization bug in embed() cannot satisfy the property by agreeing with itself.
    """
    assert strip(embed(text, signer, DISCLOSURE)) == unicodedata.normalize("NFC", text)


@given(TEXT, st.integers(min_value=0, max_value=200))
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_any_edit_to_the_visible_text_is_detected(text: str, position: int) -> None:
    """THE security property, searched: no edit to the covered bytes goes unnoticed.

    Inserting a character rather than replacing one, so the edit is always a real
    change regardless of what was there.
    """
    from tests.conftest import build_certificate

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Signer(private_key=key, certificates=(build_certificate(key),))

    marked = embed(text, signer, DISCLOSURE)
    visible = marked[: marked.index(MARKER)]
    wrapper = marked[marked.index(MARKER) :]

    cut = min(position, len(visible))
    tampered = visible[:cut] + "\u200b" + visible[cut:] + wrapper

    verdict = verify(tampered)
    assert verdict.state is Provenance.INVALID
    # AND FOR THE RIGHT REASON. INVALID alone is satisfied by a manifest that failed to
    # parse, so a search that broke the wrapper instead of the binding would report the
    # security property as held while proving nothing about the binding.
    #
    # MALFORMED, NOT MISMATCH, and the distinction is why the next test exists. An
    # INSERTION lengthens the visible text, so the wrapper slides and the exclusion the
    # claim declared no longer names a located one -- 15.12.1.3.1 step 3 rejects it
    # before a single byte is hashed. This property is real, and it does not exercise
    # the digest comparison at all.
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()


@given(
    st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), min_size=1, max_size=64),
    st.integers(min_value=0, max_value=200),
)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_a_same_length_edit_is_caught_by_the_digest_itself(text: str, position: int) -> None:
    """The half the insertion property cannot reach: the HASH, doing the work.

    A replacement that keeps the byte length keeps the wrapper where the claim said it
    was, so the exclusion still names a located wrapper and step 3 passes. What rejects
    the document here is the digest over the covered bytes -- the comparison the whole
    hard binding exists to perform. Printable ASCII so a replacement is length-preserving
    by construction, and already NFC so embed() does not move anything either.
    """
    from tests.conftest import build_certificate

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Signer(private_key=key, certificates=(build_certificate(key),))

    marked = embed(text, signer, DISCLOSURE)
    visible = marked[: marked.index(MARKER)]
    wrapper = marked[marked.index(MARKER) :]

    cut = position % len(visible)
    replacement = "X" if visible[cut] != "X" else "Y"
    tampered = visible[:cut] + replacement + visible[cut + 1 :] + wrapper
    assert len(tampered.encode("utf-8")) == len(marked.encode("utf-8")), "the edit must not move the wrapper"

    verdict = verify(tampered)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()


@given(st.binary(max_size=400))
@settings(max_examples=200, deadline=None)
def test_verify_never_raises_on_arbitrary_manifest_bytes(payload: bytes) -> None:
    """The gap the text-level property could not reach.

    ``test_verify_never_raises_an_unexpected_type`` above generates arbitrary TEXT, so
    every input either has no wrapper or has one whose payload is whatever the text
    happened to decode to -- it essentially never produces a well-framed wrapper
    around hostile MANIFEST bytes. That is the layer where two real escapes lived: a
    forbidden character in a JUMBF label raised a bare ValueError, and an unreadable
    certificate key algorithm raised UnsupportedAlgorithm, neither of which is a
    C2paTextError.

    This wraps arbitrary bytes in a VALID wrapper frame, so the magic and length check
    out and the JUMBF, CBOR, COSE and certificate layers all see attacker-chosen
    input.
    """
    from c2patxt._selectors import build_wrapper

    try:
        verdict = verify("Doc." + build_wrapper(payload))
    except C2paTextError:
        return
    assert verdict.state in set(Provenance)


@given(TEXT)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_marking_never_changes_what_the_reader_sees(signer: Signer, text: str) -> None:
    """THE RENDERING INVARIANT -- the strongest property this package claims.

    Marking must never change what the recipient sees, in any format, no exception.
    That is the whole reason A.8 uses variation selectors rather than A.9's visible
    delimiters, and it is the property a customer notices being broken before they
    notice anything else.

    Asserted as a PROPERTY rather than spot-checked, per the founding memo, and
    stated the honest way: the visible text of the output equals the NFC form of the
    input. embed() normalizes before marking, so for already-NFC text -- effectively
    all real text -- that is the input unchanged, and for NFD input it is a real and
    documented change.

    The comparison uses ``unicodedata`` rather than embed()'s own output, so a
    normalization bug cannot satisfy the property by agreeing with itself.

    THE VISIBLE TEXT IS TAKEN FROM ``locate()``'s SPAN, not by splitting on the first
    U+FEFF. Hypothesis found that immediately: for the input ``"\ufeff"`` the first
    marker in the output is the USER'S, not the mark's, so a naive split returns the
    empty string. embed() handles that input correctly -- the bug was in the first
    version of this test, which is a fair demonstration of why the invariant is
    property-tested rather than spot-checked.
    """
    marked = embed(text, signer, DISCLOSURE)

    span = locate(marked)
    assert span is not None
    encoded = marked.encode("utf-8")
    visible = (encoded[: span.utf8_start] + encoded[span.utf8_stop :]).decode("utf-8")

    assert visible == unicodedata.normalize("NFC", text)


@given(TEXT)
@settings(max_examples=15, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_the_full_remark_cycle_is_byte_stable(signer: Signer, text: str) -> None:
    """embed -> strip -> embed produces identical bytes, over arbitrary input.

    The founding memo asks for this cycle specifically, and for it to be run more than
    once -- "a determinism test that runs once tests nothing". Hypothesis supplies the
    repetition, over inputs nobody chose by hand.

    Ed25519 has no randomness source (RFC 8032 5.1.6 derives the nonce from the key
    and message), so any instability here is a bug in our canonicalization, not in the
    signature. The context is pinned because the manifest UUID and instance ID are
    deliberately fresh per mark otherwise.
    """
    from c2patxt import EmbedContext

    context = EmbedContext(manifest_uuid=uuid.UUID(int=7), instance_id="xmp:iid:1", when=WHEN)

    first = embed(text, signer, DISCLOSURE, context=context)
    second = embed(strip(first), signer, DISCLOSURE, context=context)
    assert first == second


@given(TEXT)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_the_located_span_always_decodes_back_to_the_wrapper(signer: Signer, text: str) -> None:
    """The founding memo's second property, which was only ever spot-checked.

    ``locate()`` must return a range that IS the wrapper -- not merely a range near
    it. Sliced out of the caller's own bytes it must start with the U+FEFF marker,
    contain nothing but variation selectors after that, and be exactly the length the
    wrapper's own header declares.
    """
    marked = embed(text, signer, DISCLOSURE)
    span = locate(marked)
    assert span is not None

    encoded = marked.encode("utf-8")
    wrapper = encoded[span.utf8_start : span.utf8_stop].decode("utf-8")

    assert wrapper.startswith(MARKER)
    body = wrapper[len(MARKER) :]
    assert body, "a located span with no selector run is not a wrapper"
    for char in body:
        assert 0xFE00 <= ord(char) <= 0xFE0F or 0xE0100 <= ord(char) <= 0xE01EF

    # A.8.2.2: 13-byte header, then manifestLength bytes. One selector per byte.
    from c2patxt._selectors import selectors_to_bytes

    decoded = selectors_to_bytes(body)
    assert decoded is not None
    assert len(decoded) == 13 + int.from_bytes(decoded[9:13], "big")
