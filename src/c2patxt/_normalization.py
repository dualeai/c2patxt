"""Bounded NFC normalization for public text inputs."""

from __future__ import annotations

import re
import unicodedata

from c2patxt.constants import MAX_NONSTARTERS
from c2patxt.exceptions import TextNormalizationError

_NON_ASCII_RUN = re.compile(r"[^\x00-\x7f]+")


def normalize_nfc(text: str) -> str:
    """Return NFC text after enforcing UAX #15's Stream-Safe input bound.

    C2PA requires NFC for text hard bindings. Unicode allows arbitrarily long
    nonstarter sequences and defines 30 NFKD nonstarters as the Stream-Safe Text
    Format boundary (UAX15-D3). This implementation rejects a longer sequence instead
    of applying UAX15-D4's CGJ insertion, because that insertion can make the result no
    longer canonically equivalent to the caller's text.
    """
    if text.isascii():
        return text
    for match in _NON_ASCII_RUN.finditer(text):
        _check_nonstarters(text, match.start(), match.end())
    return unicodedata.normalize("NFC", text)


def _check_nonstarters(text: str, start: int, stop: int) -> None:
    """Check one non-ASCII run; ASCII is a starter and resets the count."""
    nonstarters = 0
    for position in range(start, stop):
        character = text[position]
        combining = unicodedata.combining(character)
        decomposition = unicodedata.decomposition(character)
        if not decomposition:
            nonstarters = nonstarters + 1 if combining else 0
            if nonstarters > MAX_NONSTARTERS:
                raise TextNormalizationError(position)
            continue

        expanded = unicodedata.normalize("NFKD", character)
        initial = 0
        for item in expanded:
            if unicodedata.combining(item) == 0:
                break
            initial += 1
        if nonstarters + initial > MAX_NONSTARTERS:
            raise TextNormalizationError(position)

        trailing = 0
        for item in reversed(expanded):
            if unicodedata.combining(item) == 0:
                break
            trailing += 1
        nonstarters = nonstarters + trailing if trailing == len(expanded) else trailing
