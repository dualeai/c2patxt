# Benchmarks

`tests/benchmarks/` holds a CodSpeed suite run by `make test-bench` and by
`.github/workflows/codspeed.yml` on pushes to `main` and `develop` and on pull requests
against `main`. `pytest-codspeed` simulation mode gives hardware-agnostic instruction
counts, so CI can gate regressions without runner noise. The `memory` instrument runs
beside it, because the worst defect found in this package so far was quadratic in
allocation as well as in CPU.

**A benchmark is not a test, and does not replace one.** It carries no assertion, so by
CONTRIBUTING.md's definition it cannot fail when the code it covers breaks. The division
is deliberate:

| Held by CodSpeed | Held by assertions in `tests/` |
| --- | --- |
| Constant-factor drift, which nothing else watches | Complexity class — a ratio re-derived every run |
| Memory trend | Operation counts (encodes, scans, digests, reference walks) |
| | Termination, via `--timeout=30` and the hang guards |

The reason for the split is that a CodSpeed alert is measured against a rolling baseline
on the default branch. An accepted slowdown re-baselines, and after that the property is
no longer checked by anything; a defect that lands on the default branch *becomes* the
baseline. The regression threshold also lives in CodSpeed's web interface rather than in
this repository, where a third party auditing the package cannot read it. Neither is a
reason to skip benchmarking. Both are reasons not to let benchmarking hold a claim an
assertion should hold.

**Do not publish a sample maximum as a bound**, and state the sample size beside any
figure. The cost of `embed()`'s padding search is recorded where it is enforced rather
than here: `tests/test_fixpoint.py::test_the_search_settles_in_a_modest_number_of_builds`
gives the measured centre and tail with their sample sizes in its docstring, and asserts
the algorithm's analytic ceiling of 801 — not a measurement from one machine, which is a
flaky bound.

## Two local traps

**A local `--codspeed` run is not the CI measurement.** CI runs `mode: simulation,memory`;
locally the plugin falls back to WALLTIME, whose reported "Time (best)" column is not the
per-call cost — it disagreed by up to 2000x when measured (`verify_unmarked`: 19.6 us
computed and 19.4 us by `timeit`, against 9 ns reported). `Run time / Iters` matches
`timeit`. Use `timeit` for absolute numbers and leave the CodSpeed table for comparing a
benchmark against its own history, which is all CodSpeed does.

**A benchmark id is its history.** CodSpeed tracks each id separately, so renaming one
resets it to zero and deleting one discards it. Rename an id only when the old name was
WRONG, never for tidiness.

## The memory instrument may not measure anything

It is not established that the memory pass can see what it is there for. The reasoning,
with the pinned upstream source it rests on, is in `.github/workflows/codspeed.yml`
beside the mode that turns it on. Keep the mode only while someone can point at a CI run
where the memory leg actually moved.

The allocation guarantee does not depend on it: it is asserted as a ratio in
`tests/test_regressions.py`, which holds on any machine with no baseline.
