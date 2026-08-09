# pyright: reportPrivateUsage=false
"""Tests for the exclusion-range fixpoint.

The property that matters is an identity, not an approximation: the wrapper's
declared exclusion length must equal the wrapper's actual UTF-8 byte length. Off by
one and the hash covers a byte of the mark, or misses a byte of the text.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from c2patxt import _fixpoint


def _builder(
    text: str,
) -> Callable[[int], Callable[[int], str]]:
    """A small monotone builder that isolates the fixpoint search.

    The base varies with the input's UTF-8 length. Each padding unit adds three UTF-8
    bytes, matching a zero byte represented by a variation selector. Public
    ``embed`` tests own the real CBOR, COSE, JUMBF and signature integration.
    """
    base = 100 + len(text.encode())

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        del exclusion_length

        def assemble(pad: int) -> str:
            return "x" * (base + 3 * pad)

        return assemble

    return prepare


@pytest.mark.parametrize(
    "text",
    ["", "a", "Hello world.", "漢字テキスト", "x" * 4096, "é combining", "emoji 👨‍👩‍👧‍👦"],
)
def test_the_declared_length_equals_the_actual_length(text: str) -> None:
    """The solver returns only an exact identity, across varied base lengths."""
    wrapper, target = _fixpoint.solve(_builder(text))
    assert len(wrapper.encode("utf-8")) == target


def test_an_unreachable_target_raises_rather_than_spinning() -> None:
    """A builder that never matches must fail loudly, not hang.

    verify() and embed() both live in services that handle untrusted input; a loop
    with no bound is a denial of service waiting for the wrong document.
    """

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        def never_matches(pad: int) -> str:
            del pad
            # Keep every candidate away from its declared length.
            return "x" * (100 if exclusion_length == 0 else exclusion_length - 30)

        return never_matches

    with pytest.raises(_fixpoint.FixpointError, match="own declared length"):
        _fixpoint.solve(prepare)
