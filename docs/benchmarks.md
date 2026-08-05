# Benchmarks

`tests/benchmarks/` holds a CodSpeed suite run by
`make test-bench` and by `.github/workflows/codspeed.yml` on pushes to `main` and
`develop` and on pull requests against `main`. `pytest-codspeed` simulation mode was the tool named here before the
requirement existed, and it is the one adopted: hardware-agnostic instruction counts,
so CI can gate regressions without runner noise. The `memory` instrument runs beside
it, because the worst defect found in this package so far was quadratic in allocation
as well as in CPU.

**A benchmark is not a test, and does not replace one.** It carries no assertion, so
by CONTRIBUTING.md's definition it cannot fail when the code it covers breaks. The
division is deliberate:

| Held by CodSpeed | Held by assertions in `tests/` |
| --- | --- |
| Constant-factor drift, which nothing else watches | Complexity class — a ratio re-derived every run |
| Memory trend | Operation counts (encodes, scans, digests, reference walks) |
| | Termination, via `--timeout=30` and the hang guards |

The reason for the split is that a CodSpeed alert is measured against a rolling
baseline on the default branch. An accepted slowdown re-baselines, and after that the
property is no longer checked by anything; a defect that lands on the default branch
*becomes* the baseline. The regression threshold also lives in CodSpeed's web
interface rather than in this repository, where a third party auditing the package
cannot read it. Neither is a reason to skip benchmarking. Both are reasons not to let
benchmarking hold a claim an assertion should hold.

The number worth knowing is still recorded where it matters rather than in a
benchmark: `embed()`'s padding search costs **a median of 29-30 sign-and-serialize
cycles, best 3, measured 2026-08-06 over two samples of 7 324 and 10 000 documents**,
depending on where Ed25519
signature noise lands, bounded at 801 by construction. It is asserted in
`tests/test_fixpoint.py` against the algorithm's own ceiling — not against a
measurement from one machine, which is a flaky bound and was one, briefly.

**This figure has now been wrong three times.** It was published
as "4–131" from eight inputs, then "3 to 279", then "3 to 456" from 250 documents. Each
version was taken honestly, and each was a sample maximum published as if it were a
bound — which is the defect, whichever way the next sample lands.

The third correction is the one that changes the practice rather than the number. Two
larger samples taken the same day, with different corpora, give maxima of **434 and
479** and 95th percentiles of **154 and 129** — they bracket the previously published
456 from both sides. So the maximum is a property of the sample, and no amount of
resampling will make it a property of the code. The centre is stable and worth
publishing; the tail is not, and the only bound worth asserting is the analytic 801.
State the sample size beside any figure, and do not let a worst observed be read as a
ceiling.


## Two things that will mislead you locally

**A local `--codspeed` run is not the CI measurement.** CI runs
`mode: simulation,memory`; locally the plugin falls back to WALLTIME, whose reported
"Time (best)" column is not the per-call cost — it disagreed by up to 2000x when
measured (`verify_unmarked`: 19.6 us computed and 19.4 us by `timeit`, against 9 ns
reported). `Run time / Iters` matches `timeit`. Use `timeit` for absolute numbers and
leave the CodSpeed table for comparing a benchmark against its own history, which is
all CodSpeed does.

**A benchmark id is its history.** CodSpeed tracks each id separately, so renaming one
resets it to zero and deleting one discards it. That has already happened here
unnoticed. Rename an id only when the old name was WRONG, never for tidiness.

## The memory instrument is on probation

`mode: simulation,memory` runs a second pass, and it is not established that the second
pass can see what it is there for. memtrack hooks libc `malloc`/`free` and friends, but
the memory executor does not force `PYTHONMALLOC=malloc`, so it runs under pymalloc
where every object below 512 B comes from an arena that never reaches a hooked symbol —
and `AnalysisInstrument` measures an already-warm SECOND call. Keep the mode only while
someone can point at a CI run where the memory leg actually moved. The allocation
guarantee itself does not depend on it: it is asserted as a ratio in
`tests/test_regressions.py`, which holds on any machine with no baseline.
