"""Resolve the exclusion-range circularity by padding to a declared length.

THE CIRCULARITY
---------------
The ``c2pa.hash.data`` exclusion range names the wrapper's byte range. The wrapper's
byte range depends on ``manifestLength``. ``manifestLength`` depends on the size of
the manifest, which contains the exclusion range.

WHY ITERATION DOES NOT RESOLVE IT
---------------------------------
The obvious fix -- guess a length, build, measure, re-build with the measured value,
repeat -- looks like it should settle, because Ed25519's signature is a fixed 64
bytes so the manifest's SIZE stops moving after a pass or two. It does not settle,
and the reason is specific to A.8: the exclusion length counts UTF-8 bytes of the
ENCODED wrapper, and A.8.3.1 maps ``0x00-0x0F`` to U+FE00+b, which costs 3 UTF-8
bytes, and ``0x10-0xFF`` to U+E0100+(b-16), which costs 4. So the wrapper's byte
length is a function of the manifest's CONTENT, not merely its length. Changing the
exclusion value changes the signature, which reshuffles the byte distribution, which
changes the wrapper length again. Measured on one input the loop happened to settle
after four passes; on others it oscillates between two values indefinitely. A naive
``while measured != assumed`` loop is a hang, not a fixpoint.

WHAT WE DO INSTEAD
------------------
Do not chase a discovered length -- DECLARE one, then pad up to it. The manifest is
written once claiming a target ``L``, and padding is grown until the wrapper measures
exactly ``L``. Nothing has to re-settle, because ``L`` never moves.

Padding lives in the hash assertion's ``pad`` field, which 10.4 exists for and which
validators "shall ignore". Padding anywhere else -- a trailing JUMBF ``free`` box, or
extra selectors after the manifest -- would sit outside the signed claim and would be
an invention A.8 does not describe; both public A.8 implementations invented one, and
no two inventions are guaranteed to agree.

REACHING AN EXACT TARGET
------------------------
A pad byte of ``0x00`` costs 3 UTF-8 bytes as a variation selector and ``0xFF`` costs
4, so padding nominally moves the wrapper length in steps of 3 with a per-byte
adjustment of 1. If that were the whole story, one pass over pad sizes would hit any
target exactly.

It is not the whole story, because ``pad`` sits INSIDE the signed claim: every change
to it produces a different Ed25519 signature, and while the signature's LENGTH is
fixed at 64 bytes its byte distribution is not, so its UTF-8 cost wanders by a few
bytes at random. Measured over 90 pad values on one input, roughly 70% of the
individual values in the reachable range are skipped -- the figure published here was
40%, taken before the manifest gained its `c2pa.metadata` assertion and `specVersion`
key, and the direction is more true than it was stated. A
single declared target is therefore not reliably reachable, and a search that fixes
one and gives up is a coin flip.

So the target is a search variable too. Candidate targets are tried in ascending
order, each seeded with a measurement so the pad ramp is not re-walked from zero, and
the first target a pad reaches exactly wins.

Cost is variable, because whether a given target is reachable depends on where the
signature noise happens to land. **The centre is stable and the tail is not.** Two
independent samples on 2026-08-06, different corpora and different seeds: median 29-30
builds, best 3 in both, roughly 0.35 ms per build (10 ms at the median). The upper tail
disagrees with itself -- 95th percentile 129 and 154, maximum 479 over 10 000 documents
and 434 over 7 324.

**DO NOT READ A WORST OBSERVED AS A BOUND.** This figure has been published wrong three
times -- "4 to 131" from eight inputs, "3 to 279", then "3 to 456" -- each honestly
taken and each understating a tail that a sample of that size cannot show. The two
samples above bracket 456 from either side, which settles what the maximum is: a
property of the corpus, not of this code. **The only bound is 801, and it is analytic:
1 + _MAX_TARGETS * (1 + _WINDOW * 3).** It is what ``tests/test_fixpoint.py`` asserts.

THE SAMPLE SIZE IS PART OF THE FIGURE. An earlier version published "median 28 builds
(14 ms), best 5 (2.5 ms), worst 203 (101 ms)" from NINE inputs, and the worst case was
low by more than a factor of two -- a distribution's tail is exactly what nine samples
do not show. The milliseconds also halved when the selector encoder became a table
lookup, so the old figures were stale in both directions at once.

That variance is inherent to the approach and is acceptable here -- embed runs once per document, not per token -- but
it is the number to look at first if embed ever needs to be fast.

The search is bounded and raises rather than spinning, since an unbounded loop in a
library that also handles untrusted input is a denial of service waiting for a
caller.
"""

from __future__ import annotations

from collections.abc import Callable

from c2patxt.exceptions import C2paTextError

__all__ = [
    "FixpointError",
    "solve",
]

#: UTF-8 bytes the first candidate target sits above the unpadded probe. Covers the
#: CBOR integer for the exclusion length widening as it grows (1 byte at 0, up to 5
#: for a 32-bit value) plus room for the search to manoeuvre.
_SLACK = 32

#: Candidate targets tried, ascending from ``probe + _SLACK``. Each is independently
#: about 38% likely to be reachable -- measured per-target hit rates of 36.7%, 44.2%,
#: 37.7%, 36.4% and 38.1% over 150 solves, NOT the 60% published here earlier. The
#: conclusion survives the correction and the constant does not change: 0.62 ** 32 is
#: 2.27e-7, so 32 targets still makes an overall miss vanishingly unlikely while keeping
#: the worst case bounded. (That read "about 4e-7", which is 0.63 ** 32 -- off by 1.8x
#: and it changes nothing, but a justification that cannot be reproduced on a calculator
#: is not one.) Recorded because the number is what the constant is
#: justified BY, and a justification may not be wrong even when its conclusion is right.
_MAX_TARGETS = 32

#: Pad byte counts tried per target. Padding moves the length ~3 bytes per byte, so
#: this reaches 144 bytes past the base by its own arithmetic (48 x 3) and 149 measured
#: -- comfortably past ``_SLACK`` plus the candidate range plus signature noise. This
#: said "~96", which is 1.55x low and disagrees with the two constants named beside it.
_MAX_PAD = 48

#: UTF-8 cost of the cheapest pad byte. A.8.3.1 maps 0x00-0x0F into U+FE00's plane,
#: which is 3 UTF-8 bytes; used only to seed the search, so being an underestimate
#: for high bytes is fine -- it biases the estimate low, and the window scans up.
_BYTES_PER_PAD_BYTE = 3

#: Pad counts scanned around the seeded estimate, for each target. Signature noise is
#: a few bytes, so the true answer is within a byte or two of the estimate; this is
#: several times that.
_WINDOW = 8


class FixpointError(C2paTextError, RuntimeError):
    """The padding search could not reach the declared target length.

    Catchable as ``C2paTextError`` and as ``RuntimeError``. It derived from
    ``RuntimeError`` alone until 2026-08-05, which meant a caller following
    ``exceptions.py``'s instruction to catch ``C2paTextError`` did not catch it -- and it
    is reachable from ``embed()``.

    Never expected in practice. Raised rather than looped so that a builder which
    stops behaving monotonically fails loudly instead of hanging.
    """


def solve(build: Callable[[int, bytes], str], *, probe_length: int = 0) -> tuple[str, int]:
    """Return ``(wrapper, target_length)`` for a wrapper that is exactly its own size.

    Args:
        build: given ``(exclusion_length, pad)``, returns the ENCODED wrapper string.
            Called repeatedly, so it must be deterministic -- a builder that reads a
            clock or an RNG makes the result unreproducible, not merely slower.
        probe_length: exclusion length used for the initial size probe. The default
            of 0 is fine; the slack absorbs the CBOR width difference.

    Returns:
        The wrapper, and the byte length it declares. The declared length is exactly
        ``len(wrapper.encode("utf-8"))`` -- that identity is the whole point.

    Raises:
        FixpointError: the target was not reachable within the search bound.
    """
    base = len(build(probe_length, b"").encode("utf-8")) + _SLACK

    for target in range(base, base + _MAX_TARGETS):
        # Seed the pad size from a measurement rather than ramping up from zero for
        # every candidate, which would re-walk the same ground _MAX_TARGETS times.
        unpadded = len(build(target, b"").encode("utf-8"))
        if unpadded == target:
            return build(target, b""), target
        estimate = max(0, (target - unpadded) // _BYTES_PER_PAD_BYTE)

        for zeros in range(estimate, min(estimate + _WINDOW, _MAX_PAD)):
            for high in (0, 1, 2):
                # Zeros move the length in steps of 3; the high bytes shift the
                # sequence by 4 and 8, covering residues 1 and 2 modulo 3. Signature
                # noise then scatters the result by a few bytes either way, which is
                # why the target itself is also searched.
                wrapper = build(target, bytes(zeros) + b"\xff" * high)
                if len(wrapper.encode("utf-8")) == target:
                    return wrapper, target

    msg = f"no wrapper in [{base}, {base + _MAX_TARGETS}) is its own declared length"
    raise FixpointError(msg)
