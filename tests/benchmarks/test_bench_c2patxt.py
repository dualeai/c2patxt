"""Benchmarks for the paths a caller actually pays for.

Run with: make test-bench

EACH BENCHMARK DISCRIMINATES A DEFECT CLASS THIS PACKAGE HAS HAD. A benign-only set
catches one of the four: three move no benchmark above its own run-to-run noise,
because the defects amplify structures benign input does not contain -- one reference
per assertion, zero decoy markers, one actions link -- so the amplification factor is
exactly 1. That is why three of these inputs are hostile, and why ``strip``, which is
public API, has one of its own.

Measured 2026-08-06 by restoring each defect: decoys 105.7x, hash amplification 8.4x,
duplicate actions 11.7x on the dedupe alone and 12.1x with both halves of its fix
removed.

TWO RULES THIS FILE FOLLOWS, both learned by getting them wrong:

1. MEASURE AT THE LAYER THAT CAN REGRESS. A benchmark on a private helper stays flat
   while its caller starts calling it twice -- which is defect 4 exactly: all four
   ``find_wrappers`` benchmarks were flat (ratio 1.000) on it while ``verify`` moved
   41%. Conversely a benchmark on the public path hides a 10x regression in a helper
   worth 2% of the total. Neither layer is right in general, so each benchmark says
   which it chose.

2. FIXED INPUTS, AND ASSERT THE SHAPE. Simulation mode measures ONE call, so a single
   sample of a varying distribution is not a measurement. Every input is pinned, and
   each benchmark asserts -- outside the measured region -- that it measured the path it
   names. Without that, a regression making ``find_wrappers`` return ``[]`` would cut a
   benchmark's cost 95% and report as an improvement.

   A BENCHMARK ID IS ITS HISTORY. CodSpeed tracks each id separately, so renaming one
   resets it to zero and deleting one discards it. Renaming
   ``decode_selector_run[typical]`` to ``[typical-1792B]`` reset
   two histories, visible in the local ``.codspeed/results_*.json`` files either side
   of 2026-08-05. Rename an id only when the old name was WRONG, never for tidiness.

   ONE MEASURED CALL IS NOT ONE CALL. On an interpreter built with
   ``PY_HAVE_PERF_TRAMPOLINE`` -- which the CI interpreter is, verified against the
   pinned 3.12 build -- pytest-codspeed runs the callable once unmeasured to warm
   CPython's perf map, then measures the second call. Locally, on a build without it,
   there is no warmup. So these figures are the SECOND call in a cold process, not a
   steady state: for the cheapest paths the second call still runs ~2x the steady-state
   cost. That does not affect comparison against this benchmark's own history, which is
   all CodSpeed does; it does mean the absolute numbers are not what a warm server pays.

   Every benchmark here runs its measured callable once in its assertion before
   measuring, so the warmup depth is uniform across the file -- it was not before, when
   8 of 23 had an assertion and 15 did not, making cross-benchmark comparison in the UI
   not apples to apples.

   THE ALLOCATOR IS NOT PRODUCTION'S EITHER, in the simulation pass: the runner forces
   ``PYTHONMALLOC=malloc``, so pymalloc's arenas are absent. The memory pass does not
   force it. A figure here is therefore not directly comparable to a production
   profile, in either direction.
"""

from __future__ import annotations

import datetime
import hashlib
import uuid
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_codspeed import BenchmarkFixture

from c2patxt import EmbedContext, embed, extract, strip, verify
from c2patxt._locate import find_wrappers
from c2patxt._selectors import build_wrapper, bytes_to_selectors
from c2patxt.constants import MAGIC, MARKER
from c2patxt.signing import Signer
from c2patxt.verdict import Provenance
from tests.conftest import DISCLOSURE, build_certificate, mark

# ONE builder for the duplicate-actions store, imported rather than copied. The repo's
# own rule: two copies drift, and the copy this file used would silently stop being the
# thing the regression suite proved correct.
from tests.test_regressions import _hostile_store  # pyright: ignore[reportPrivateUsage] -- one builder, not two

#: One paragraph repeated. ASCII, so `.encode()` is a memcpy and the benchmark measures
#: scanning rather than transcoding.
_PARAGRAPH = "The quick brown fox jumps over the lazy dog. "

#: Every non-deterministic input to embed(), pinned. Without this the search cost is a
#: function of two fresh UUIDs and the wall clock, which put embed at CV 134% over 20
#: runs -- unusable in simulation mode, which takes a single sample.
_PINNED_CONTEXT = EmbedContext(
    manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000001"),
    instance_id="xmp:iid:00000000-0000-4000-8000-000000000002",
    when=datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc),
)

#: Two endpoints, and they measure DIFFERENT TERMS -- which is why both stay and the
#: middle sizes went. [1MB] is 71% CPython (encode, NFC normalize, sha256): it is the
#: document term, and a 10x regression in COSE parsing is invisible in it (+0.6%).
#: [12B] is the only benchmark where the certificate profile and COSE are visible at
#: all. [1KB] tracked [12B] to within 1% under every perturbation tried, and [100KB]
#: sits between two kept points. A benchmark is a threshold that can flake, so a size
#: earns its place by responding differently from its neighbours.
_SIZES = [pytest.param(12, id="12B"), pytest.param(1_000_000, id="1MB")]


def _document(size: int) -> str:
    """A document of roughly ``size`` bytes. ASCII, so bytes and characters coincide."""
    return (_PARAGRAPH * (size // len(_PARAGRAPH) + 1))[:size]


@pytest.fixture(scope="module")
def bench_signer() -> Signer:
    """The suite's pinned signer, module-scoped so key generation and certificate
    building never land inside a measured region."""
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    return Signer(private_key=key, certificates=(build_certificate(key),))


# ---------------------------------------------------------------------------
# The honest paths
# ---------------------------------------------------------------------------


def test_bench_verify_unmarked(benchmark: BenchmarkFixture) -> None:
    """The common case. Most text on earth carries no mark, so this is what a
    verification surface pays on nearly every call: one encode and one ``str.find``.

    ONE SIZE. The scan is linear and flat -- three smaller sizes measured the same
    ~1.2 us prologue plus a proportional encode, and none responded differently from
    this one under any perturbation tried.
    """
    text = _document(1_000_000)
    assert verify(text).state is Provenance.UNMARKED
    benchmark(verify, text)


@pytest.mark.parametrize("size", _SIZES)
def test_bench_verify_valid(benchmark: BenchmarkFixture, size: int, bench_signer: Signer) -> None:
    """A genuine mark, all the way through: locate, decode, parse, hash, verify.

    THE TWO SIZES ARE NOT THE SAME MEASUREMENT. At 12 B the manifest term dominates and
    this is the only benchmark in the file where the certificate profile (2.5%) and COSE
    (1.1%) appear at all -- a 10x regression in either shows here and nowhere else. At
    1 MB the document term dominates and the manifest becomes invisible.
    """
    text = mark(_document(size), bench_signer)
    # Outside the measured region, and not decoration: a regression making find_wrappers
    # return [] would flip this to UNMARKED, cut cost ~95%, and report as an IMPROVEMENT.
    assert verify(text).state is Provenance.VALID
    benchmark(verify, text)


def test_bench_extract(benchmark: BenchmarkFixture, bench_signer: Signer) -> None:
    """Parsing the manifest store out of a mark: JUMBF boxes, then CBOR.

    No signature check and no hashing -- the parser alone, which is the part an attacker
    reaches before any credential has been verified. 65% of this is our code, the
    highest proportion of any benchmark here, which is what makes it the right layer.
    """
    text = mark("Hello world.", bench_signer)
    assert extract(text) is not None
    benchmark(extract, text)


def test_bench_decode_selector_run(benchmark: BenchmarkFixture) -> None:
    """Decoding a variation-selector run back to manifest bytes.

    ONE SIZE, and it is the large one. 100 KB is what a third-party manifest carrying an
    embedded icon assertion looks like -- 2.4 replaced data boxes with embedded-data
    assertions, so that is ordinary input, and A.8 permits 2 MiB. The typical 1.8 KB
    manifest is covered end to end by the extract benchmark, 53x less sensitively.

    Driven through ``find_wrappers`` rather than the private decoder: ``_decode_run`` is
    96% of the cumulative time either way, and the public path is what a caller runs.
    """
    payload_size = 99_840
    payload = bytes(range(256)) * (payload_size // 256)
    assert len(payload) == payload_size, "the id must name the real size"
    text = "Document. " + build_wrapper(payload)
    assert len(find_wrappers(text)) == 1
    benchmark(find_wrappers, text)


def test_bench_encode_selector_run(benchmark: BenchmarkFixture) -> None:
    """Encoding manifest bytes into a variation-selector run: the OTHER half of A.8.3.1.

    ``decode_selector_run`` above covers the decode direction only. These are two
    separate functions with two separate hot paths, and a benchmark on one says nothing
    about the other -- ``bytes_to_selectors`` is a ``str.translate`` over a latin-1
    decode, ``_decode_run`` a regex match plus a different translate.

    IT HAD NO BENCHMARK AND IT IS 8.5% OF A PADDING-SEARCH CANDIDATE: 28.7 us of 339.4 us
    measured 2026-08-06, and the search runs a median of 29 candidates per ``embed``. A
    10x regression here moves ``embed[1MB]`` by 77%, where it would be read as an embed
    regression rather than a codec one -- which is the layer confusion rule 1 of this
    file's header is about.

    1 797 BYTES, NOT A ROUND NUMBER. That is our own manifest store, and it is the size
    the 8.4x figure in ``bytes_to_selectors``' docstring was taken on, so this benchmark
    and that justification measure the same thing. Reverting the table lookup to the
    per-byte generator it replaced moves this benchmark by that factor and moves
    ``decode_selector_run`` not at all. Verified 2026-08-06: encode 34.5 us -> 300.1 us,
    8.70x; decode 4344.1 us -> 4317.9 us, 0.6% and inside the noise.
    """
    payload_size = 1_797
    payload = (bytes(range(256)) * (payload_size // 256 + 1))[:payload_size]
    assert len(payload) == payload_size, "the docstring must name the real size"
    assert len(bytes_to_selectors(payload)) == payload_size, "one selector per byte"
    benchmark(bytes_to_selectors, payload)


def test_bench_strip(benchmark: BenchmarkFixture, bench_signer: Signer) -> None:
    """Removing a mark from a 1 MB marked document.

    PUBLIC API WITH NO COVERAGE UNTIL NOW. ``strip`` is one of the four functions this
    package exports, and it is not a thin wrapper over something already measured: it
    costs 2.14 ms here, 46% of a full verify at the same size, because it locates the
    wrapper and then rebuilds the document without it.
    """
    text = mark(_document(1_000_000), bench_signer)
    assert strip(text) != text
    benchmark(strip, text)


def _candidate_count(text: str, signer: Signer) -> int:
    """How many wrappers the padding search builds for ``text``.

    Wraps the callable ``_embed`` hands to ``_fixpoint.solve``, so it counts the real
    search on the real input rather than re-deriving it. Patched on ``_embed`` rather
    than on ``_fixpoint`` because ``_embed`` binds ``solve`` at import.
    """
    from c2patxt import _embed as embed_module

    real = embed_module.solve
    count = 0

    def counting(build: Callable[[int, bytes], str], **kwargs: int) -> tuple[str, int]:
        def wrapped(exclusion_length: int, pad: bytes) -> str:
            nonlocal count
            count += 1
            return build(exclusion_length, pad)

        return real(wrapped, **kwargs)

    embed_module.solve = counting
    try:
        embed(text, signer, DISCLOSURE, context=_PINNED_CONTEXT)
    finally:
        embed_module.solve = real
    return count


@pytest.mark.parametrize("size", _SIZES)
def test_bench_embed(benchmark: BenchmarkFixture, size: int, bench_signer: Signer) -> None:
    """Producing a mark, including the padding search.

    THE CANDIDATE COUNT IS ASSERTED, NOT ASSUMED, and that is what makes this benchmark
    usable at all. Cost is dominated by the number of search candidates, which runs 3 to
    456 for the same code depending on where Ed25519 signature noise falls, and is NOT a
    function of document length -- these pinned inputs happen to take 3 candidates at
    12 B and 156 at 1 MB. Any change to the manifest's size re-rolls both. Without the
    assertion below that re-roll reports as a phantom 50x regression with nothing having
    got slower; with it, the benchmark fails and a human decides.

    The two sizes are the floor of the distribution and a mid-tail draw, so between them
    they measure the manifest build without the search multiplier and with it.
    """
    text = _document(size)
    # THE DRAW IS PINNED BY COUNTING THE CANDIDATES, not by the output length. The length
    # was a PROXY and it is a weak one: holding len(marked) at the pinned 1852 and varying
    # only the instance id, the search still draws anywhere from 3 to 278 candidates -- a
    # 92.7x spread, 1.08 ms to 100 ms at 0.360 ms per candidate, with a length assertion
    # silent throughout. Over 600 same-length documents one modal length covered counts 3
    # through 56. Roughly one re-draw in three also moves the length, so the proxy caught
    # about a third of what this docstring claimed it caught.
    #
    # The count is the quantity that sets the cost, and it is directly countable. It costs
    # one extra embed, outside the measured region, which is what the proxy was avoiding.
    expected_candidates = {12: 3, 1_000_000: 156}[size]
    drawn = _candidate_count(text, bench_signer)
    assert drawn == expected_candidates, (
        f"the padding search has re-drawn for the {size} B input ({drawn} candidates, "
        f"expected {expected_candidates}); this benchmark's cost moved with it and its "
        "history is no longer comparable"
    )
    # The length is still pinned, for a different reason: it is the manifest SIZE, and a
    # change to it is a MAJOR version of the wire format under CONTRIBUTING.md's rule.
    expected = {12: 1_852, 1_000_000: 1_001_847}[size]
    marked = embed(text, bench_signer, DISCLOSURE, context=_PINNED_CONTEXT)
    assert len(marked) == expected, f"the marked length moved to {len(marked)}"
    benchmark(embed, text, bench_signer, DISCLOSURE, context=_PINNED_CONTEXT)


# ---------------------------------------------------------------------------
# Hostile inputs
#
# SECURITY.md names CPU and memory exhaustion from adversarial input. Every defect this
# package has had in that class was invisible to a benign benchmark, because benign
# input contains none of the structure the defect multiplies. These three reproduce the
# structures, at sizes an attacker can send cheaply.
#
# THEY DO NOT REPLACE THE COUNTING ASSERTIONS in tests/test_regressions.py and must not
# be read as doing so. Those pin a SHAPE -- one digest per assertion, at most one walk
# per label, at most three encodes per document -- exactly, as integers, on any machine.
# What they cannot pin is the CONSTANT: they stay green if each permitted digest becomes
# 40x more expensive. On work an unauthenticated attacker commands, a 40x constant is
# the same vulnerability with a smaller exponent. That is what these track.
# ---------------------------------------------------------------------------


def test_bench_verify_hostile_decoys(benchmark: BenchmarkFixture) -> None:
    """16 000 magic-matching, structurally-malformed candidates in 531 KiB.

    Each decoy is a bare magic number with no header behind it -- valid enough to enter
    the parse, malformed enough to raise. ``find_wrappers`` builds a ``MarkCorruptError``
    for each and discards all but the first, so the work buys nothing.

    THE CORRUPT-WRAPPER PATH HAS NO OTHER BENCHMARK. When the exception constructor
    resolved its location eagerly, this input cost 107x what it costs now -- and no
    benign benchmark moved more than 6.7%, on a 1.5 us measurement where 6.7% is a
    single function call of jitter.
    """
    text = (MARKER + bytes_to_selectors(MAGIC)) * 16_000
    assert verify(text).state is Provenance.INVALID
    benchmark(verify, text)


def test_bench_verify_hostile_hash_amplification(benchmark: BenchmarkFixture, bench_signer: Signer) -> None:
    """2 000 claim links naming ONE 256 KiB assertion.

    ``created_assertions`` is never de-duplicated, so without memoisation each link
    re-hashes the same assertion: 2 000 x 256 KiB of SHA-256 from a 1.57 MB request, all
    before any signature is checked. The memo makes it one hash. (This said 1.4 MB; the
    figure was taken before the manifest last changed and never re-taken. Re-measured
    2026-08-06 at 1 568 849 UTF-8 bytes.)

    The hashed-URI path is 0.31% of the best benign benchmark, so a 40x regression there
    is invisible everywhere else in this file.
    """
    text = _amplification_text(bench_signer, repeats=2_000, filler=256 * 1024)
    assert verify(text).state is Provenance.INVALID
    benchmark(verify, text)


def test_bench_verify_hostile_duplicate_actions(benchmark: BenchmarkFixture) -> None:
    """400 duplicate actions links x 400 icon-bearing templates, in 542 KiB.

    The two counts are independent and both attacker-chosen, so the cost was their
    PRODUCT before the reference walk was deduped and made lazy.

    ``instance=True`` IS LOAD-BEARING. Repeating the BASE actions label is rejected by
    ``_actions_status`` as ``assertion.action.malformed`` before the walk is drawn --
    ``_action_references`` called 0 times, ``_reference_status`` 0 times -- so that
    payload times the rejection, at CBOR-decode and selector-decode cost already covered
    by ``extract`` and ``decode_selector_run``. The reachable form links the base label
    once and a 6.4 ``__1`` instance N times, which passes every shape rule: 2 walks and
    800 reference checks.

    That is the difference between catching one defect and catching two. Measured here,
    min of 5, restoring each half of the fix separately:

    ====================  ===============  ==================
    tree                  base-label only  ``__1`` instance
    ====================  ===============  ==================
    pristine               9.14 ms          15.21 ms
    dedupe removed         9.22 ms (1.0x)  177.82 ms (11.7x)
    both removed          76.19 ms (8.3x)  184.31 ms (12.1x)
    ====================  ===============  ==================

    The base-label payload cannot see the dedupe at all. The LAZINESS moves neither payload
    on its own (15.29 ms here) and is held where it belongs, by an assertion:
    ``test_a_repeated_actions_link_does_not_multiply_the_reference_walk`` pins the walk
    count at zero for a store the shape check rejects.

    THIS IS ALSO THE ONLY BENCHMARK THAT REACHES 15.10.3.3 AT ALL. Across the other eleven,
    ``_reference_status`` is called zero times, so the reference-validation procedure had
    no benchmark coverage of any kind.

    THE PEAK IS NOT THIS BENCHMARK'S JOB. Against the fixed tree this input peaks at
    1.77 MiB by ``tracemalloc`` and at 38.22 MiB with both halves removed, and every
    other benchmark moves at most 0.1% under the same defect -- which is why the CI
    ``memory`` pass points here. But what memtrack reports is NOT established: it hooks
    libc rather than pymalloc, and ``AnalysisInstrument`` measures the second call of an
    already-warm process. So the allocation guarantee is held by an assertion instead,
    ``test_a_repeated_actions_link_allocates_a_bounded_multiple_of_its_input``, as a
    ratio that holds on any machine. What this benchmark holds is the CONSTANT on the
    time side, which no assertion can.
    """
    text = _hostile_store(repeats=400, templates=400, instance=True)
    assert verify(text).state is Provenance.INVALID
    benchmark(verify, text)


def _amplification_text(signer: Signer, *, repeats: int, filler: int) -> str:
    """Marked text whose claim links one large assertion ``repeats`` times.

    Built from a genuine mark and then re-linked, so everything except the link count is
    a manifest this package produced. The signature will not verify -- it covers the
    original claim -- and that is immaterial: the amplification happens in
    ``_check_assertions``, which runs BEFORE ``_check_signature`` precisely because an
    unauthenticated attacker must not be able to command unbounded work.
    """
    from c2patxt import _cbor
    from c2patxt._jumbf import UUID_CBOR, DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import (
        ASSERTION_METADATA,
        LABEL_ASSERTION_STORE,
        LABEL_CLAIM,
        LABEL_CLAIM_SIGNATURE,
        LABEL_MANIFEST_STORE,
        UUID_ASSERTION_STORE,
        UUID_CLAIM,
        UUID_CLAIM_SIGNATURE,
        UUID_MANIFEST,
        UUID_MANIFEST_STORE,
    )

    original = extract(mark("Hello world.", signer))
    assert original is not None

    def payload_of(box: JumbfBox) -> bytes:
        return serialize_superbox(box)[8:]

    def assertion(label: str, body: bytes) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=UUID_CBOR, label=label, requestable=True),
            content=((b"cbor", body),),
        )

    # One deliberately large assertion, plus the originals so the store is otherwise
    # real. The originals are reused AS THEIR RAW PAYLOADS -- `assertion_bytes` already
    # holds the nested-superbox bytes 8.4.2.3 hashes, so re-wrapping them as cbor
    # content boxes produces a store that fails at assertion.cbor.invalid before the
    # link walk ever runs. It did, and the benchmark measured nothing until this was
    # fixed; the diagnosis was a hash-call count of zero.
    big = assertion(ASSERTION_METADATA, _cbor.dumps({"dc:format": "text/plain", "pad": b"\x00" * filler}))
    children = [raw for label, raw in original.assertion_bytes.items() if label != ASSERTION_METADATA]
    children.append(payload_of(big))

    digest = hashlib.sha256(payload_of(big)).digest()
    link: _cbor.CborValue = {
        "url": f"self#jumbf={LABEL_ASSERTION_STORE}/{ASSERTION_METADATA}",
        "hash": digest,
        "alg": "sha256",
    }
    existing = original.claim["created_assertions"]
    assert isinstance(existing, list)
    # The ORIGINAL metadata link is dropped: its digest names the assertion we replaced,
    # so leaving it in place makes the very first link mismatch and _link_status
    # short-circuits before walking the 2 000 that carry the amplification. That is how
    # this builder failed the first time -- the store parsed, the verdict looked
    # plausible, and the measured hash count was 1.
    kept = [
        entry
        for entry in existing
        if not (isinstance(entry, dict) and str(entry.get("url", "")).endswith(ASSERTION_METADATA))
    ]
    links: list[_cbor.CborValue] = [*kept, *([link] * repeats)]
    claim: dict[str, _cbor.CborValue] = {**original.claim, "created_assertions": links}

    def superbox(uuid_: bytes, label: str, children: list[bytes]) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=uuid_, label=label),
            content=tuple((b"jumb", child) for child in children),
        )

    manifest = superbox(
        UUID_MANIFEST,
        original.manifest_label,
        [
            payload_of(superbox(UUID_ASSERTION_STORE, LABEL_ASSERTION_STORE, children)),
            payload_of(
                JumbfBox(
                    description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                    content=((b"cbor", _cbor.dumps(claim)),),
                )
            ),
            payload_of(
                JumbfBox(
                    description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
                    content=((b"cbor", original.signature),),
                )
            ),
        ],
    )
    store = superbox(UUID_MANIFEST_STORE, LABEL_MANIFEST_STORE, [payload_of(manifest)])
    return "Hostile. " + build_wrapper(serialize_superbox(store))
