# Benchmarks

`tests/benchmarks/` holds a CodSpeed suite run by `make test-bench` and by
`.github/workflows/codspeed.yml` on pushes to `main` and `develop` and on pull requests
against both branches. `pytest-codspeed` simulation mode gives hardware-agnostic
CPU-performance signals, while memory mode records allocation drift. CodSpeed owns
both benchmark histories, as it does in `hpke-http`.

**A benchmark does not replace a functional test.** Each case checks a public semantic
precondition so a broken path cannot look faster. It sets no CPU, memory or private
call-count threshold; CodSpeed owns those comparisons. The division is:

| Held by CodSpeed | Held by assertions in `tests/` |
| --- | --- |
| Comparative CPU and memory drift | Results, specification bounds, and termination |

The reason for the split is that a pull request's CodSpeed alert uses the latest measured
commit on its base branch. An accepted slowdown becomes part of later comparisons after
it lands. The [public dashboard](https://codspeed.io/dualeai/c2patxt) shows the
repository's shared 10% regression threshold, but that setting lives outside this
repository and cannot be reviewed with a source change. Neither is a reason to skip
benchmarking. Both are reasons not to let benchmarking hold a correctness claim an
assertion should hold.

Functional tests do not assert elapsed time, allocation ratios, instruction counts or
private call counts. They retain input-size limits and finite-search failures because
those are correctness and availability rules, not measurements.

## Two local traps

**A local `--codspeed` run is not the CI measurement.** CI runs
`mode: simulation,memory` through CodSpeed;
locally the plugin falls back to wall time. Use local runs for diagnosis, not as a
replacement for the CodSpeed CPU and memory histories.

**Keep benchmark ids stable.** CodSpeed compares measurements by benchmark identity;
rename an id only when the measured operation or input meaning changes.
