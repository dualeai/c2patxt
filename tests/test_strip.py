"""Tests for :func:`c2patxt.strip`.

The non-ASCII cases are the point. An ASCII-only test suite passes just as happily
against the naive ``str``-slice this function exists to replace.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt import MarkCorruptError, Provenance, UnencodableTextError, embed, locate, strip, verify
from c2patxt.constants import MARKER
from c2patxt.signing import Signer
from tests.conftest import DISCLOSURE, mark


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


@pytest.mark.parametrize(
    "text",
    [
        "Hello world.",
        "Rapport sur l'été 漢字",
        "مرحبا שלום",
        "café",
        "emoji 👨‍👩‍👧‍👦 zwj",
        "",
    ],
)
def test_strip_returns_the_original_text(text: str, signer: Signer) -> None:
    """Round trip. The non-ASCII cases are why this function is not a str slice."""
    assert strip(mark(text, signer)) == text


def test_the_naive_string_slice_is_wrong_and_strip_is_not() -> None:
    """The exact failure strip() exists to prevent, demonstrated side by side.

    Span holds BYTE offsets. Slicing a str with them drops too few characters on
    non-ASCII text, leaving a zero-width residue of the old mark. That residue is
    invisible on screen, is shorter than the magic number so verify() calls the
    document UNMARKED rather than corrupt, and would be baked permanently inside the
    next mark's hashed text.
    """
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    from tests.conftest import build_certificate

    marked = embed(
        "Rapport sur l'été 漢字", Signer(private_key=key, certificates=(build_certificate(key),)), DISCLOSURE
    )

    span = locate(marked)
    assert span is not None
    naive = marked[: span.utf8_start] + marked[span.utf8_stop :]

    assert naive != "Rapport sur l'été 漢字"
    assert MARKER in naive, "the residue is what makes this dangerous"
    assert strip(marked) == "Rapport sur l'été 漢字"


def test_stripping_unmarked_text_changes_nothing() -> None:
    """Absence is not an error, and must not be a surprise."""
    for text in ("", "plain prose", "❤️ emoji selectors", "﻿leading BOM"):
        assert strip(text) == text


def test_strip_then_embed_is_the_supported_re_marking_path(signer: Signer) -> None:
    """What AlreadyMarkedError's message now tells the caller to do."""
    marked = mark("The original text.", signer)
    remarked = embed(strip(marked), signer, DISCLOSURE)
    assert verify(remarked).state is Provenance.VALID
    assert remarked.count(MARKER) == 1


def test_every_wrapper_is_removed_not_only_the_first(signer: Signer) -> None:
    """A document with two wrappers is already invalid; leaving one behind would
    produce text that still fails for a reason the caller thought they had fixed."""
    first = mark("Document one.", signer)
    second = mark("Document two.", signer)
    doubled = first + second[second.index(MARKER) :]

    assert doubled.count(MARKER) == 2
    assert strip(doubled) == "Document one."


def test_strip_refuses_a_corrupt_wrapper_rather_than_guessing() -> None:
    """Removing an unknown extent is guesswork, and guessing here silently truncates
    the caller's document."""
    from c2patxt._selectors import bytes_to_selectors
    from c2patxt.constants import MAGIC

    corrupt = "Doc." + MARKER + bytes_to_selectors(MAGIC + b"\x02" + b"\x00\x00\x00\x00")
    with pytest.raises(MarkCorruptError):
        strip(corrupt)


def test_strip_reports_unencodable_text_like_every_other_entry_point() -> None:
    with pytest.raises(UnencodableTextError):
        strip("\ud800" + MARKER + "x")
