# Contributing

```console
$ make install     # uv sync
$ make test        # static checks + every test except the benchmarks
$ make lint        # ruff format, ruff check --fix, pyright strict, vulture
```

Both must be green before a pull request. CI runs `make test-static` and
`make test-func` — the same checks, not the same targets: it cannot run `make lint`,
which rewrites files rather than reporting on them.

**Branch from `develop` and open the pull request against `develop`.** `main` is the
release branch: it is what the publish workflow reads and what `git describe` tags. Work
lands on `develop` first and reaches `main` when a release is cut.

**Commit subjects are [Conventional Commits](https://www.conventionalcommits.org)** —
`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:` — because the release notes are
written from the log. No CLA and no DCO sign-off; the Apache-2.0 licence on the
repository covers the contribution.

## Rules that are not obvious, and are not negotiable

These exist because breaking them produces tests that pass while the code is wrong —
which for a compliance artefact is worse than a failing build.

**Expected values come from the specification or from hand calculation. Never from
running our own implementation.** A fixture generated with `embed()` and checked with
`extract()` proves only that a function is its own inverse, and stays green when both
halves share a bug. Where a reference exists — `unicodedata` for normalization, the
RFC 8949 corpus for CBOR, another implementation's published vectors — assert against
that instead.

**A test must fail if you break the code it covers.** Before adding one, delete the
function body in your head: if the test still passes, the assertion is too weak. This
is not theoretical. Two shapes recur: a corpus test that catches every exception the
decoder can raise, so an unconditional `raise` satisfies it; and an assertion pinning
the wrong value while citing the clause that contradicts it, so the test *defends* the
defect.

**Write the failing test first.** Reproduce the bug, watch the test fail, then fix it.
Prefer parametrized cases: a defect where one input behaves differently from its
neighbours is invisible in a single-case test.

**No `pytest.skip`. Ever.** A missing dependency means a broken environment, not a
test to skip. Use `xfail(strict=True)` for a known unfixed bug.

**There are no test markers, and adding one needs a reason.** Selection is by
directory: `make test-func` runs everything except `tests/benchmarks/`, and
`make test-bench` runs only that. Nothing here talks to a database, a network or a
clock it does not own — `--disable-socket` enforces the middle one — so a
unit/integration split would label tests without letting anyone select differently.

**The vector file's data is ASCII-only**, and CI enforces it. The subject matter is
invisible characters; a file containing them literally is one no reviewer, diff tool
or terminal renders honestly.

**If you break the code deliberately — to check a test bites — two traps turn a broken
probe green.** Both have caught someone here:

- **Stale bytecode after a same-length revert.** Python invalidates a `.pyc` on source
  size and mtime, and `0xFFFE` → `0xFFFF` changes neither at second granularity, so the
  restored file keeps loading the mutant. Run
  `find src -name __pycache__ -type d -exec rm -rf {} +` after reverting.
- **zsh does not word-split unquoted expansions.** `pytest $ARGS` with
  `ARGS="file -k selector"` hands pytest ONE argument, selects nothing, and prints
  `no tests ran` — which reads like success at a glance. Use `${=ARGS}`, and read the
  result as the literal words `1 failed` rather than as the absence of a failure.

**Every lint suppression carries a reason.** `# noqa: S607` alone is not acceptable;
say why the rule does not apply here. Rules for static analysis are strict on purpose:
**if it fails, fix the issue — never turn off the linter.**

**New deviations from the specification go in [docs/deviations.md](docs/deviations.md)
with both sides quoted**, not in a code comment. The document exists because that
reasoning is recoverable from nowhere else. A clause cited in `src/` should also appear
in [docs/c2pa-compatibility.md](docs/c2pa-compatibility.md).

**One direction of that is checked, and only one.**
`tests/test_compatibility.py::test_every_where_column_names_a_file_that_cites_its_clause`
holds that each file a row NAMES cites that clause. Two gaps, both on review: a row
naming no file at all passes, and nothing checks the reverse direction — a clause you
cite in `src/` and forget to add to the document goes unnoticed.

## Changing the wire format

Any change to the bytes we emit is a **MAJOR** version of both this package and the
conformance vector file. Text marked by an older version must keep verifying, or the
compliance artefact was worthless.

`tests/test_vector_file.py::test_the_signed_manifest_bytes_are_exactly_what_they_were`
is what holds this — a SHA-256 over one fully pinned `embed()`. Nothing else in the
suite covers the emitted bytes, down to a four-byte change in the COSE `x5chain`
encoding. Adding vector records is MINOR; changing what a
record means is MAJOR.

## Changing anything under `tests/vectors/`

Run `make checksums`. Every file in that directory is listed in `SHA256SUMS` — the
data file, the README, the LICENCE, the loader, the third-party corpora — so editing
any of them, including a one-line prose change, invalidates the manifest.

`tests/test_external_vectors.py::test_every_checksummed_file_exists_and_matches` is what
fails, and it fails on a clean checkout rather than only for you. The manifest is not
decoration: `tests/vectors/README.md` tells third parties to run
`shasum -a 256 -c SHA256SUMS`, and a corpus offered to C2PA and C2SP whose own integrity
check does not pass is worse than one carrying no check at all.

Refreshing an external corpus is a separate step: `make download-vectors-cose`,
`make download-vectors-cbor` and `make download-vectors-third-party` re-fetch the COSE
working group, CBOR working group and third-party implementation vectors respectively;
`make download-vectors` does all three. Those are other people's numbers, which is what
makes them worth vendoring — re-fetch, then `make checksums`, and read the diff before
committing.

## Benchmarks

`make test-bench` runs them; CI runs them via CodSpeed on pushes to `main` and `develop`, and on pull requests
against `main`.
What a benchmark holds, what an assertion holds, and the two things that will mislead
you reading a local run are in [docs/benchmarks.md](docs/benchmarks.md).

## Cutting a release

A GitHub Release publishes. `git push --tags` does not. The runbook, the job graph and
the trusted-publisher setup are in [docs/releasing.md](docs/releasing.md).

## Writing

No marketing copy. No superlatives, no "first", no "only", no "reference
implementation" — a regulator reading a boast goes looking for the gap, and another
project already self-describes that way. Do not call this "the C2PA text library"; it
is *our implementation of* C2PA text marking.

Prefer the shorter word, cut what can be cut, and never use a long word where a short
one will do.

## Security

Do not open a public issue for a suspected vulnerability. See [SECURITY.md](SECURITY.md).
