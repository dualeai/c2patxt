"""Property-based tests. Hypothesis searches for the input we did not think of.

WHY THESE ARE NOT MORE ROUND TRIPS
-----------------------------------
``decode(encode(x)) == x`` is the weakest property a codec has: it stays true when
encode and decode share a bug. The deterministic selector suite therefore owns the
complete A.8.3.1 formula check. Properties here cover larger input spaces and failure
invariants that example tests cannot enumerate.

The end-to-end ones are budgeted deliberately: each example normalizes, builds and
signs a complete manifest, so a 100-example default would dominate the suite.
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
    Provenance,
    UnencodableTextError,
    embed,
    extract,
    locate,
    strip,
    verify,
)
from c2patxt._cbor import CborDecodeError, loads
from c2patxt._locate import find_wrappers
from c2patxt._selectors import bytes_to_selectors
from c2patxt.constants import MARKER
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from tests.conftest import DISCLOSURE, WHEN

#: Excludes surrogates, which UTF-8 cannot represent -- they have their own property
#: below. Everything else in the BMP and beyond is fair game.
TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200)
ORDINARY_TEXT = st.text(
    alphabet=st.characters(exclude_categories=("Cs", "Mn"), exclude_characters=(MARKER,)),
    max_size=200,
)


def _is_stream_safe(text: str) -> bool:
    """UAX15-D3 stated directly over the whole NFKD form."""
    nonstarters = 0
    for character in unicodedata.normalize("NFKD", text):
        nonstarters = nonstarters + 1 if unicodedata.combining(character) else 0
        if nonstarters > 30:
            return False
    return True


STREAM_SAFE_TEXT = TEXT.filter(_is_stream_safe)


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


# --------------------------------------------------------------------------------
# Selector-run UTF-8 cost
# --------------------------------------------------------------------------------


@given(st.binary(max_size=256))
def test_the_utf8_cost_of_a_run_follows_from_its_bytes(payload: bytes) -> None:
    """The fact the whole padding fixpoint rests on: cost depends on CONTENT.

    Bytes 0x00-0x0F land in U+FE00's plane and cost 3 UTF-8 bytes; everything else
    lands in U+E0100's and costs 4. If this ever stops holding, _fixpoint's search is
    solving the wrong problem.
    """
    expected = sum(3 if byte < 0x10 else 4 for byte in payload)
    assert len(bytes_to_selectors(payload).encode("utf-8")) == expected


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

    This domain excludes lone surrogates, so the documented encoding exception is
    unreachable. Every generated value must therefore produce a verdict.
    """
    verdict = verify(text)
    assert verdict.state in set(Provenance)


@given(ORDINARY_TEXT)
def test_ordinary_text_is_unmarked_at_every_public_reader(text: str) -> None:
    """This domain excludes the marker and selector code points by construction."""
    assert locate(text) is None
    assert extract(text) is None
    assert verify(text).state is Provenance.UNMARKED


@given(st.text(alphabet=st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF), min_size=1, max_size=4))
def test_lone_surrogates_raise_our_error_at_every_public_text_entry_point(signer: Signer, surrogates: str) -> None:
    """No public fast path may return before enforcing the shared UTF-8 wire boundary."""
    operations = (
        lambda: embed(surrogates, signer, DISCLOSURE),
        lambda: extract(surrogates),
        lambda: locate(surrogates),
        lambda: strip(surrogates),
        lambda: verify(surrogates),
    )
    for operation in operations:
        with pytest.raises(UnencodableTextError) as caught:
            operation()
        assert caught.value.position == 0


# --------------------------------------------------------------------------------
# The full pipeline. Budgeted because every example builds and signs a manifest.
# --------------------------------------------------------------------------------


@given(STREAM_SAFE_TEXT)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_marked_text_always_verifies(signer: Signer, text: str) -> None:
    """The end-to-end property, over text nobody chose by hand."""
    assert verify(embed(text, signer, DISCLOSURE)).state is Provenance.VALID


@given(STREAM_SAFE_TEXT)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_strip_undoes_embed_up_to_normalization(signer: Signer, text: str) -> None:
    """embed() normalizes to NFC, so the identity holds against NFC(text), not text.

    Asserted against ``unicodedata`` rather than against embed()'s own output, so a
    normalization bug in embed() cannot satisfy the property by agreeing with itself.
    """
    assert strip(embed(text, signer, DISCLOSURE)) == unicodedata.normalize("NFC", text)


@given(STREAM_SAFE_TEXT, st.integers(min_value=0, max_value=200))
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_an_insertion_into_visible_text_invalidates_the_declared_exclusion(
    signer: Signer, text: str, position: int
) -> None:
    """An insertion moves the wrapper away from the signed byte range."""
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


def test_a_canonically_equivalent_equal_width_rewrite_keeps_the_binding(signer: Signer) -> None:
    """The hard binding covers NFC-normalized text, not the stored byte sequence."""
    marked = embed("q\u0323\u0301", signer, DISCLOSURE)
    rewritten = marked.replace("q\u0323\u0301", "q\u0301\u0323", 1)

    assert rewritten.encode() != marked.encode()
    assert len(rewritten.encode()) == len(marked.encode())
    verdict = verify(rewritten)
    assert verdict.state is Provenance.VALID
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()


@given(
    st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), min_size=1, max_size=64),
    st.integers(min_value=0, max_value=200),
)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_a_same_length_edit_is_caught_by_the_digest_itself(signer: Signer, text: str, position: int) -> None:
    """The half the insertion property cannot reach: the HASH, doing the work.

    A replacement that keeps the byte length keeps the wrapper where the claim said it
    was, so the exclusion still names a located wrapper and step 3 passes. What rejects
    the document here is the digest over the covered bytes -- the comparison the whole
    hard binding exists to perform. Printable ASCII so a replacement is length-preserving
    by construction, and already NFC so embed() does not move anything either.
    """
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


def _literal_a8_wrapper(payload: bytes) -> str:
    """Frame bytes from A.8 literals, independent of the package wrapper builder."""
    body = bytes.fromhex("4332504154585400") + b"\x01" + len(payload).to_bytes(4, "big") + payload
    selectors = "".join(chr(0xFE00 + value) if value < 0x10 else chr(0xE0100 + value - 0x10) for value in body)
    return "\ufeff" + selectors


@given(st.binary(max_size=400))
@settings(max_examples=200, deadline=None)
def test_verify_rejects_arbitrary_manifest_bytes_in_a_literal_carrier(payload: bytes) -> None:
    """The gap the ordinary-text property cannot reach.

    The literal magic, version, big-endian length and selector formula make the carrier
    valid without calling this package's encoder. The payload therefore reaches the
    JUMBF boundary. Deeper layers are reached only when the generated bytes have the
    structure that dispatches to them. Two real escapes lived below this boundary: a
    forbidden character in a JUMBF label raised a bare ValueError, and an unreadable
    certificate key algorithm raised UnsupportedAlgorithm, neither of which is a
    C2paTextError.
    """
    prefix = "Doc."
    text = prefix + _literal_a8_wrapper(payload)
    span = locate(text)
    assert span is not None
    assert (span.utf8_start, span.utf8_stop) == (len(prefix.encode("utf-8")), len(text.encode("utf-8")))

    verdict = verify(text)
    assert verdict.state is Provenance.INVALID
    assert verdict.failure


@given(STREAM_SAFE_TEXT)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_removing_the_carrier_restores_the_nfc_text(signer: Signer, text: str) -> None:
    """Removing the located A.8 carrier leaves exactly the NFC form of the input.

    This is a string-level producer property for unstructured text. It makes no claim
    about how every renderer treats variation selectors or about other C2PA carriers.

    The comparison uses ``unicodedata`` rather than the producer's own normalized
    output. The retained text comes from ``locate()`` rather than splitting on U+FEFF,
    which may also occur in the caller's visible text.
    """
    marked = embed(text, signer, DISCLOSURE)

    span = locate(marked)
    assert span is not None
    encoded = marked.encode("utf-8")
    visible = (encoded[: span.utf8_start] + encoded[span.utf8_stop :]).decode("utf-8")

    assert visible == unicodedata.normalize("NFC", text)


@given(STREAM_SAFE_TEXT)
@settings(max_examples=15, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_the_full_remark_cycle_is_byte_stable(signer: Signer, text: str) -> None:
    """embed -> strip -> embed produces identical bytes over generated input.

    Ed25519 has no randomness source (RFC 8032 5.1.6 derives the nonce from the key
    and message), so any instability here is a bug in our canonicalization, not in the
    signature. The context is pinned because the manifest UUID and instance ID are
    deliberately fresh per mark otherwise.
    """
    from c2patxt import EmbedContext

    context = EmbedContext(
        manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000007"),
        instance_id="xmp:iid:1",
        when=WHEN,
    )

    first = embed(text, signer, DISCLOSURE, context=context)
    second = embed(strip(first), signer, DISCLOSURE, context=context)
    assert first == second


@given(STREAM_SAFE_TEXT)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_the_located_span_always_decodes_back_to_the_wrapper(signer: Signer, text: str) -> None:
    """``locate()`` must return the exact wrapper range, not merely a nearby range.

    Sliced out of the caller's own bytes it must start with the U+FEFF marker,
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

    matches = find_wrappers(marked)
    assert len(matches) == 1
    assert matches[0].span == span
    store = extract(marked)
    assert store is not None
    assert matches[0].payload == store.raw
