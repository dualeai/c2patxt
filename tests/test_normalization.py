"""Unicode normalization at the public carrier and binding boundaries.

Independent expected values come from the Unicode Character Database via
``unicodedata`` or from the encoded code points, not from our encoder.

TWO PROPERTIES THAT POINT IN OPPOSITE DIRECTIONS
------------------------------------------------
1. The MARK survives all four normalization forms, including the compatibility ones.
   This is counter-intuitive enough that a reviewer will assume NFKC strips it.
2. The VISIBLE TEXT may well change under normalization, and its byte offsets with
   it. That is exactly why the hard binding is computed over the NFC form.
"""

from __future__ import annotations

import unicodedata
from typing import Literal

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt import Provenance, TextNormalizationError, VerifyContext, embed, locate, verify
from c2patxt.constants import MARKER, MAX_NONSTARTERS
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from tests.conftest import DISCLOSURE, PINNED_EMBED_CONTEXT, WHEN

#: Typed as a Literal because unicodedata.normalize takes one; a bare str would make
#: every call site an unchecked cast.
Form = Literal["NFC", "NFD", "NFKC", "NFKD"]
FORMS: list[Form] = ["NFC", "NFD", "NFKC", "NFKD"]


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


# --------------------------------------------------------------------------------
# Why the mark survives normalization at all
# --------------------------------------------------------------------------------


#: Literals, not `VS_LOW_BASE`/`VS_HIGH_BASE`: the question here is whether the UCD
#: gives THESE code points a decomposition, and importing the bounds from the module
#: under test would move the question along with any mistake in them.
@pytest.mark.parametrize("codepoint", [0xFEFF, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF])
def test_the_mark_codepoints_have_no_decomposition(codepoint: int) -> None:
    """The ROOT CAUSE, asserted directly rather than inferred from round trips.

    Normalization can only reorder characters with a non-zero combining class or
    replace ones with a decomposition mapping. U+FEFF and every variation selector
    have ccc=0 and no mapping, canonical or compatibility, so all four forms are
    the identity on them. Every "the mark survives X" test below follows from this;
    if this one ever fails, the others are testing a coincidence.
    """
    char = chr(codepoint)
    assert unicodedata.combining(char) == 0
    assert unicodedata.decomposition(char) == ""


@pytest.mark.parametrize("form", FORMS)
def test_all_four_forms_preserve_the_carrier(form: Form, signer: Signer) -> None:
    """Normalization leaves the A.8 marker and selector run locatable.

    This says only that the carrier characters survive. The visible text and therefore
    the hard-binding verdict can still change under NFD, NFKC, or NFKD.
    """
    marked = embed("Hello world.", signer, DISCLOSURE)
    assert MARKER in unicodedata.normalize(form, marked)
    assert locate(unicodedata.normalize(form, marked)) is not None


@pytest.mark.parametrize("form", ["NFD", "NFKD"])
def test_decomposing_the_stored_text_invalidates_this_mark(form: Form, signer: Signer) -> None:
    """This verifier rejects a mark whose stored text is decomposed after signing.

    This records current verification behavior; it does not turn NFD or NFKD rejection
    into a requirement of Annex A.8, which specifies NFC for binding calculations.
    """
    marked = embed("café and Ångström", signer, DISCLOSURE)
    assert verify(marked).state is Provenance.VALID
    verdict = verify(unicodedata.normalize(form, marked))
    assert verdict.state is Provenance.INVALID
    # THE BINDING is what must catch this, and it catches it at step 3 rather than at the
    # digest: decomposing lengthens the visible text, so the wrapper slides and the
    # exclusion the claim declared no longer names a located wrapper. INVALID on its own
    # would also be satisfied by a decomposition that damaged the wrapper -- a different
    # finding, and one that would mean the mark is fragile rather than that the text
    # changed.
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()


def test_suffix_placement_makes_the_orderings_identical(signer: Signer) -> None:
    """THE reason embed() always appends.

    With the wrapper as a suffix there is nothing after it to compose with, so a
    verifier reading A.8.7.3 and a verifier reading 15.12.1.3.1 hash the same bytes.
    The interoperability risk is designed out rather than documented around.
    """
    marked = embed("á and 가", signer, DISCLOSURE)
    visible = marked[: marked.index(MARKER)]
    assert marked.index(MARKER) == len(visible)
    assert unicodedata.normalize("NFC", visible) == visible


# --------------------------------------------------------------------------------
# Public offset and normalization behavior
# --------------------------------------------------------------------------------


def test_locate_reports_offsets_in_the_as_stored_frame(signer: Signer) -> None:
    """Slicing the caller's own bytes with the reported span must work.

    A span in a normalized frame would be unusable against the string the caller
    actually holds, which is the only string they have.
    """
    marked = embed("café", signer, DISCLOSURE)
    span = locate(marked)
    assert span is not None

    encoded = marked.encode("utf-8")
    assert encoded[span.utf8_start : span.utf8_start + 3].decode("utf-8") == MARKER
    assert span.utf8_stop == len(encoded)


def test_embed_normalizes_so_the_stored_and_nfc_frames_coincide(signer: Signer) -> None:
    """Our own output has no frame ambiguity, because we normalize before marking.

    Third-party marks may still need the distinction; ours never do, and that is a
    property worth asserting rather than assuming.
    """
    marked = embed("café", signer, DISCLOSURE)
    assert unicodedata.normalize("NFC", marked) == marked
    assert marked[: marked.index(MARKER)] == "café"


def test_stream_safe_limit_counts_the_nfkd_form(signer: Signer) -> None:
    """UAX15-D3 counts NFKD nonstarters, not source code points.

    U+0344 decomposes to two nonstarters, so fifteen instances meet the boundary and
    the sixteenth exceeds it.
    """
    assert len(unicodedata.normalize("NFKD", "\u0344")) == 2
    assert all(unicodedata.combining(char) for char in unicodedata.normalize("NFKD", "\u0344"))

    accepted = "\u0344" * (MAX_NONSTARTERS // 2)
    marked = embed(accepted, signer, DISCLOSURE, context=PINNED_EMBED_CONTEXT)
    assert verify(marked, context=VerifyContext(now=WHEN)).state is Provenance.VALID

    with pytest.raises(TextNormalizationError, match="30-nonstarter") as caught:
        embed(accepted + "\u0344", signer, DISCLOSURE, context=PINNED_EMBED_CONTEXT)
    assert caught.value.position == MAX_NONSTARTERS // 2


def test_stream_safe_limit_rejects_the_direct_nonstarter_run(signer: Signer) -> None:
    text = "a" + "\u0315" * (MAX_NONSTARTERS + 1)
    with pytest.raises(TextNormalizationError) as caught:
        embed(text, signer, DISCLOSURE, context=PINNED_EMBED_CONTEXT)
    assert caught.value.position == MAX_NONSTARTERS + 1


def test_verifier_reports_the_normalization_limit_as_malformed_data_hash(signer: Signer) -> None:
    """The verification result channel remains a Verdict for hostile marked text."""
    hostile = "a" + "\u0344" * (MAX_NONSTARTERS // 2 + 1)
    safe = "x" * len(hostile.encode("utf-8"))
    marked = embed(safe, signer, DISCLOSURE, context=PINNED_EMBED_CONTEXT)
    forged = hostile + marked[len(safe) :]

    verdict = verify(forged, context=VerifyContext(now=WHEN))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()
    assert StatusCode.DATA_HASH_MISMATCH not in verdict.codes()
