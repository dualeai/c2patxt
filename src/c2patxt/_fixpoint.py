"""Resolve the A.8 exclusion-length circularity with unprotected COSE padding.

The data-hash exclusion names the wrapper's UTF-8 byte range, while the wrapper
contains that same exclusion length. A.8 maps each manifest byte to a variation
selector costing either three or four UTF-8 bytes, so manifest byte length alone does
not determine the exclusion length.

For each declared target, the caller prepares the assertions and signs the claim once.
This module then changes only the zero-filled ``pad`` in the COSE unprotected map,
which RFC 9052 excludes from ``Sig_structure``. C2PA 10.4.2 defines that header and
10.4.4 applies the same signature property when shrinking preallocated padding. This
producer grows the field during its bounded search. If one declared length is not
reached, the next signed candidate is tried.

Changing the target still changes signed claim bytes, so a small ascending target
search remains necessary. Padding trials within one target do not rebuild the claim or
re-sign it. The normal pass prepares at most 33 candidates including its probe; the
bounded search raises rather than looping.
"""

from __future__ import annotations

from collections.abc import Callable

from c2patxt.exceptions import C2paTextError

# Room for the exclusion integer to widen and for a short zero-filled pad. The target
# itself is searched, so this is a tuning offset rather than a reachability claim.
# Twelve is the selected wire-size/signing-work trade-off; failure remains explicit
# and bounded for an input with no hit.
_SLACK = 12

# Declared wrapper lengths tried in ascending order.
_MAX_TARGETS = 32

# Inclusive pad bound. From the zero probe to the last target, the target rises by at
# most 12 + 31 = 43 bytes. Rebuilding can lower the wrapper's UTF-8 cost by at most
# 64 hashed-URI bytes + 64 signature bytes + two bytes from each of six enclosing
# 32-bit lengths, offset by at least seven bytes for the widened exclusion integer:
# 133 bytes, hence a required growth of at most 176. For pad >= 24, zero bytes cost
# 3p, its wider CBOR header adds four, and five enclosing lengths can lower the cost
# by at most ten: growth >= 3p - 6. Pad 61 therefore grows by at least 177, so 60 is
# the inclusive cap.
_MAX_PAD = 60
_BYTES_PER_ZERO = 3
# Writing pad growth as 3p+e gives e in [-10, 9] across the CBOR length thresholds;
# floor(growth/3) is therefore within four bytes of an exact p.
_WINDOW = 4

_PaddedBuilder = Callable[[int], str]
_PrepareBuilder = Callable[[int], _PaddedBuilder]


class FixpointError(C2paTextError, RuntimeError):
    """No wrapper in the bounded search matched its declared UTF-8 length."""


def _utf8_length(wrapper: str) -> int:
    return len(wrapper.encode("utf-8"))


def _try_padding(build: _PaddedBuilder, target: int) -> str | None:
    """Try a short window of zero-filled ``pad`` sizes for one signed target."""
    baseline = build(0)
    measured = _utf8_length(baseline)
    if measured == target:
        return baseline

    estimate = max(0, (target - measured) // _BYTES_PER_ZERO)
    start = max(0, estimate - _WINDOW)
    stop = min(_MAX_PAD, estimate + _WINDOW)
    for pad in range(start, stop + 1):
        if pad == 0:
            continue
        wrapper = build(pad)
        if _utf8_length(wrapper) == target:
            return wrapper
    return None


def solve(prepare: _PrepareBuilder) -> tuple[str, int]:
    """Return a wrapper whose declared exclusion length equals its UTF-8 byte length.

    ``prepare(target)`` builds and signs one candidate, then returns a cheap assembler
    accepting a zero-filled COSE ``pad`` length. It must be deterministic.
    """
    probe = prepare(0)
    base = _utf8_length(probe(0)) + _SLACK

    # The common path uses only the required unprotected `pad` field.
    for target in range(base, base + _MAX_TARGETS):
        wrapper = _try_padding(prepare(target), target)
        if wrapper is not None:
            return wrapper, target

    msg = f"no wrapper in [{base}, {base + _MAX_TARGETS}) is its own declared length"
    raise FixpointError(msg)
