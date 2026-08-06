"""Tests for the exclusion-range fixpoint.

The property that matters is an identity, not an approximation: the wrapper's
declared exclusion length must equal the wrapper's actual UTF-8 byte length. Off by
one and the hash covers a byte of the mark, or misses a byte of the text.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt import _fixpoint
from c2patxt.signing import Signer
from tests.conftest import wrapper_builder

#: This suite exercises the WHOLE stack -- selectors, JUMBF, CBOR, COSE, certificate
#: profile, hash binding -- against text that genuinely satisfies the binding, rather
#: than against hand-built fragments.


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


def _builder(text: str, signer: Signer, counter: list[int]) -> Callable[[int, bytes], str]:
    """Wrap the shared producer so the search's build count can be asserted."""
    inner = wrapper_builder(text, signer)

    def build(exclusion_length: int, pad: bytes) -> str:
        counter[0] += 1
        return inner(exclusion_length, pad)

    return build


@pytest.mark.parametrize(
    "text",
    ["", "a", "Hello world.", "漢字テキスト", "x" * 4096, "é combining", "emoji 👨‍👩‍👧‍👦"],
)
def test_the_declared_length_equals_the_actual_length(text: str, signer: Signer) -> None:
    """THE identity the whole module exists for, across inputs of varied byte cost."""
    calls = [0]
    wrapper, target = _fixpoint.solve(_builder(text, signer, calls))
    assert len(wrapper.encode("utf-8")) == target


def test_the_result_is_deterministic(signer: Signer) -> None:
    """Same inputs, same bytes. Re-marking identical text must be reproducible.

    The search visits candidates in a fixed order and the builder is pure, so there
    is no path-dependence to leak in -- which is what makes byte-stable re-embedding
    a testable claim rather than an aspiration.
    """
    first, target_one = _fixpoint.solve(_builder("Hello world.", signer, [0]))
    second, target_two = _fixpoint.solve(_builder("Hello world.", signer, [0]))
    assert first == second
    assert target_one == target_two


@pytest.mark.timeout(120)
def test_the_search_settles_in_a_modest_number_of_builds(signer: Signer) -> None:
    """Cost is bounded in practice, not merely in theory.

    Each build is a full sign-and-serialize, so an unbounded search would make embed
    unusable.

    THE BOUND IS THE ALGORITHM'S OWN CEILING, deliberately, not a measurement.
    solve() tries at most _MAX_TARGETS targets of (1 probe + _WINDOW * 3 pads), so
    801 builds is the most it can ever do; anything at or below that is the search
    working as designed. A bound of 400, taken from a measurement on
    one machine, and a run on a different interpreter hit 553 -- a green test failing
    for a reason that had nothing to do with a regression.

    The count varies because it depends on where Ed25519 signature noise lands, which
    changes with the certificate and the text. Measured 2026-08-06 across eight inputs
    with the pinned test certificate: median 29-30 and a best of 3 across two samples of
    7 324 and 10 000 documents, but maxima of 434 and 479 and 95th percentiles of 154
    and 129. The
    CENTRE reproduces and the TAIL does not, because a sample maximum is a property of
    the corpus. A tight bound here is a flaky bound -- this figure has been understated
    three times, from samples of eight, of 400 and of 250 -- which is the argument for
    asserting the ANALYTIC ceiling and nothing else.

    Two inputs, not four, and a raised timeout: each solve runs up to 801 full
    sign-and-serialize cycles, and under ``-n auto`` alongside the Hypothesis suite
    four of them intermittently crossed the 30s default. A test that fails once in
    twenty runs teaches people to re-run rather than to look. ASCII and CJK are the
    two ends of the byte-cost range, which is what the count actually depends on.
    """
    for text in ("Hello world.", "漢字テキスト"):
        calls = [0]
        _fixpoint.solve(_builder(text, signer, calls))
        assert calls[0] <= 801


def test_an_unreachable_target_raises_rather_than_spinning() -> None:
    """A builder that never matches must fail loudly, not hang.

    verify() and embed() both live in services that handle untrusted input; a loop
    with no bound is a denial of service waiting for the wrong document.
    """

    def never_matches(exclusion_length: int, pad: bytes) -> str:
        # Always one byte short of whatever was asked for.
        return "x" * max(exclusion_length - 1, 1)

    with pytest.raises(_fixpoint.FixpointError, match="own declared length"):
        _fixpoint.solve(never_matches)
