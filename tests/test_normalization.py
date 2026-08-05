# pyright: reportPrivateUsage=false
# Drives the private units directly. A mutation audit showed several of these guards
# were only ever exercised through a public entry point that another check answered
# first, so the guard itself could be deleted unnoticed.
"""Unicode normalization: what survives it, what moves under it, and why it matters.

Every expected value here was derived from the Unicode Character Database via
``unicodedata`` -- the reference implementation of the algorithm -- or by hand. None
was produced by running our encoder. Asserting that ``extract(embed(x)) == x`` only
proves a function is its own inverse, which stays true when both halves are wrong.

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

from c2patxt import Provenance, embed, locate, verify
from c2patxt.constants import MARKER
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from tests.conftest import DISCLOSURE, mark

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
def test_all_four_forms_preserve_the_mark(form: Form, signer: Signer) -> None:
    """Including NFKC and NFKD.

    Reviewers expect the compatibility forms to strip the mark, because that is what
    they do to most format characters. They do not here, and a system that normalizes
    aggressively on ingest therefore does NOT destroy provenance.
    """
    marked = mark("Hello world.", signer)
    assert MARKER in unicodedata.normalize(form, marked)
    assert locate(unicodedata.normalize(form, marked)) is not None


@pytest.mark.parametrize("form", ["NFC", "NFKC"])
def test_composing_forms_leave_a_valid_mark_valid(form: Form, signer: Signer) -> None:
    """Surviving as bytes is not enough; it must still VERIFY.

    Restricted to the composing forms deliberately: NFD and NFKD decompose the
    VISIBLE text, which changes the hashed bytes and correctly invalidates the
    binding. See the next test.
    """
    marked = mark("Hello world.", signer)
    assert verify(unicodedata.normalize(form, marked)).state is Provenance.VALID


@pytest.mark.parametrize("form", ["NFD", "NFKD"])
def test_decomposing_the_visible_text_breaks_the_binding(form: Form, signer: Signer) -> None:
    """And it SHOULD. NFD rewrites the covered bytes, which is a change to the text.

    Not a defect: the hard binding exists to detect exactly this. A consumer that
    decomposes on ingest must do so before verifying, not after.
    """
    marked = mark("café and Ångström", signer)
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


# --------------------------------------------------------------------------------
# The ordering divergence: remove-then-normalize vs normalize-then-remove
# --------------------------------------------------------------------------------

#: A stand-in wrapper: the marker plus a short selector run. Not a valid manifest --
#: these cases are about NORMALIZATION ARITHMETIC, and a real 6 KiB wrapper would
#: bury the point without changing the answer.
_STUB = MARKER + chr(0xFE00) * 8


def _remove_then_normalize(pre: str, post: str) -> bytes:
    """C2PA 15.12.1.3.1 steps 5-7, which A.8.5 designates as normative."""
    return unicodedata.normalize("NFC", pre + post).encode("utf-8")


def _normalize_then_remove(pre: str, post: str) -> bytes:
    """A.8.7.3's reading: "perform normalization before calculating offsets"."""
    return unicodedata.normalize("NFC", pre + _STUB + post).replace(_STUB, "").encode("utf-8")


#: Lifted out of the decorator so the table can be checked AS a table. Each row is
#: (pre, post, remove-first hex, normalize-first hex).
_DIVERGENCE_CASES: list[tuple[str, str, str, str]] = [
    # U+FEFF is a starter, so it BLOCKS composition across itself. Removing it
    # first lets a + U+0301 compose to U+00E1; normalizing first cannot.
    ("a", "́", "c3a1", "61cc81"),
    # Hangul jamo: L + V composes to a syllable, or does not. 3 bytes vs 6.
    ("ᄀ", "ᅡ", "eab080", "e18480e185a1"),
    ("A", "̊", "c385", "41cc8a"),
]


def test_every_divergence_case_actually_diverges() -> None:
    """A check on the TABLE, not on the package.

    This assertion used to sit inside the test below, where it compared two literals
    that the parametrize decorator had just handed it: no change to ``src/`` could
    make it fail. It is still worth making -- a row whose two orderings agree is a
    witness to nothing, and would sit in the table looking like coverage -- so it runs
    here, once, where what it guards is visible.
    """
    for pre, post, remove_first, normalize_first in _DIVERGENCE_CASES:
        assert remove_first != normalize_first, f"{pre!r} + {post!r} is not a witness"


@pytest.mark.parametrize(("pre", "post", "remove_first", "normalize_first"), _DIVERGENCE_CASES)
def test_the_two_hash_orderings_genuinely_diverge(pre: str, post: str, remove_first: str, normalize_first: str) -> None:
    """The contradiction is real, not theoretical, and these are the witnesses.

    Expected bytes computed from the UCD, not from our code. We follow
    15.12.1.3.1 -- remove, then normalize -- because A.8.5 delegates to it explicitly
    ("refer to the Validation clause for the normative procedure"), and because both
    other public A.8 implementations independently chose the same.
    """
    assert _remove_then_normalize(pre, post).hex() == remove_first
    assert _normalize_then_remove(pre, post).hex() == normalize_first


@pytest.mark.parametrize(
    ("pre", "post"),
    [
        ("é", ""),  # already composed: nothing to do either way
        ("", "́"),  # nothing precedes the combining mark
        ("café", ""),  # composed, no combining mark adjacent to the wrapper
    ],
)
def test_the_two_orderings_agree_when_nothing_composes_across_the_mark(pre: str, post: str) -> None:
    """The divergence needs a composable pair SPLIT by the wrapper. Absent that, the
    orderings agree -- which is why suffix placement eliminates the problem."""
    assert _remove_then_normalize(pre, post) == _normalize_then_remove(pre, post)


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
# Offsets move under normalization, and not always upward
# --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "as_stored", "as_nfc"),
    [
        ("café", 6, 5),  # NFD: e + combining acute collapses to one 2-byte char
        ("Ångstrom", 10, 9),  # singleton decomposition: U+212B -> U+00C5
        ("क़x", 4, 7),  # composition exclusion: the offset GROWS, not shrinks
    ],
)
def test_normalization_moves_the_wrapper_offset(text: str, as_stored: int, as_nfc: int) -> None:
    """Byte offsets are frame-dependent, and the third case grows rather than shrinks.

    U+0958 is a composition exclusion: NFC DECOMPOSES it rather than leaving it, so
    the prefix gets longer. Anyone who assumes normalization only ever shortens
    offsets writes an off-by-N that passes every Latin-script test.

    This is why every offset in this package is documented as being in the AS-STORED
    frame, and why locate() names its fields ``utf8_start``/``utf8_stop`` rather than
    anything implying a normalized frame.
    """
    assert len(text.encode("utf-8")) == as_stored
    assert len(unicodedata.normalize("NFC", text).encode("utf-8")) == as_nfc


def test_locate_reports_offsets_in_the_as_stored_frame(signer: Signer) -> None:
    """Slicing the caller's own bytes with the reported span must work.

    A span in a normalized frame would be unusable against the string the caller
    actually holds, which is the only string they have.
    """
    marked = mark("café", signer)
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


# --------------------------------------------------------------------------------
# The SHIPPED binding function, not a reimplementation of it
# --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pre", "post", "expected"),
    [
        ("a", "́", "c3a1"),
        ("ᄀ", "ᅡ", "eab080"),
        ("A", "̊", "c385"),
    ],
    ids=["a-acute", "hangul-jamo", "A-ring"],
)
def test_the_shipped_binding_removes_before_it_normalizes(pre: str, post: str, expected: str) -> None:
    """Drives ``_verify._hash_binding_bytes`` ITSELF. Nothing did, until now.

    A mutation audit rewrote that function to normalize BEFORE removing -- inverting
    the exact 15.12.1.3.1-versus-A.8.7.3 ordering its module's 25-line header
    docstring is entirely about -- and the whole suite stayed green.

    The reason is subtle and worth naming: the tests above define
    ``_remove_then_normalize`` and ``_normalize_then_remove`` as TEST-LOCAL
    reimplementations, and prove that those two local functions differ. That is a fact
    about the Unicode algorithm, not about our code. It stays true no matter which
    ordering the shipped verifier picks.

    Expected bytes are the same UCD-derived values, so this asserts the shipped
    function lands on the side we documented.
    """
    from c2patxt._verify import _hash_binding_bytes

    stored = pre + _STUB + post
    encoded = stored.encode("utf-8")
    start = len(pre.encode("utf-8"))
    length = len(_STUB.encode("utf-8"))

    assert encoded[start : start + length].decode("utf-8") == _STUB
    assert _hash_binding_bytes(encoded, start, length).hex() == expected


def test_the_shipped_binding_rejects_a_range_that_splits_a_code_point() -> None:
    """A range chosen one byte into a multi-byte character leaves invalid UTF-8.

    Malformed, not merely mismatched -- and reachable, because the exclusion offsets
    are attacker-supplied until the claim signature verifies.
    """
    from c2patxt._verify import _hash_binding_bytes

    text = "café"  # 'é' is two bytes; cut between them
    with pytest.raises(UnicodeDecodeError):
        _hash_binding_bytes(text.encode("utf-8"), 4, 1)


def test_the_shipped_binding_uses_the_as_stored_frame_for_its_offsets() -> None:
    """The case that distinguishes the two orderings when the ENDING is the same.

    ``_hash_binding_bytes`` normalizes at the end as well as removing at the start, so
    for text that is ALREADY NFC both orderings agree and a mutation swapping them is
    equivalent -- which is exactly what happened: rewriting the function to normalize
    first left the whole suite green, including the three divergence cases above,
    because U+FEFF blocks composition and the stored bytes were unchanged by NFC.

    NFD input is what separates them. "e" + U+0301 is three bytes as stored and two
    after NFC, so an implementation that normalizes BEFORE slicing removes the wrong
    three bytes and produces garbage. The exclusion offsets are byte offsets into the
    AS-STORED encoding; that is the property, and this is the test that holds it.
    """
    from c2patxt._verify import _hash_binding_bytes

    nfd = "é"  # NFD "é": 3 bytes stored, 2 after NFC
    stored = nfd + _STUB
    assert len(nfd.encode("utf-8")) == 3
    assert len(unicodedata.normalize("NFC", nfd).encode("utf-8")) == 2

    start = len(nfd.encode("utf-8"))
    length = len(_STUB.encode("utf-8"))

    # Remove the wrapper from the as-stored bytes, THEN normalize: "é" composes.
    assert _hash_binding_bytes(stored.encode("utf-8"), start, length) == "é".encode()
