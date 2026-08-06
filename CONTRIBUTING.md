# Contributing

```console
$ make install     # uv sync
$ make test        # static checks + every test except the benchmarks
$ make lint        # ruff format, ruff check --fix, pyright strict, vulture
```

Both must be green before a pull request. CI runs `make test-static` and
`make test-func` — the same checks, not the same targets: it cannot run `make lint`,
which rewrites files rather than reporting on them.

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

**Every lint suppression carries a reason.** `# noqa: S607` alone is not acceptable;
say why the rule does not apply here. Rules for static analysis are strict on purpose:
**if it fails, fix the issue — never turn off the linter.**

**New deviations from the specification go in [docs/deviations.md](docs/deviations.md)
with both sides quoted**, not in a code comment. The document exists because that
reasoning is recoverable from nowhere else. If a clause is cited in `src/`, it must
also appear in [docs/c2pa-compatibility.md](docs/c2pa-compatibility.md) — a test
enforces this.

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

Publishing is triggered by a **GitHub Release**, not by pushing a tag. `git push --tags`
runs nothing: the workflow's `push` trigger filters on `branches: [main]`, and a branch
filter excludes tag pushes.

1. Land everything on `main`. There is no changelog file to edit: **the release notes
   are the changelog**, written on the Release itself, so nothing about them can go
   stale in a checkout.
2. Tag that commit `vX.Y.Z` and push the tag. Nothing runs yet; the tag exists so the
   next step can point at it, and so `cicd/version.sh` can find it.
3. Create a GitHub Release for that tag. **This is the step that publishes.** Write the
   notes there, and say what was evaluated and rejected as well as what shipped — a
   release nobody can read the reasoning for gets the same question asked again.

The workflow file is read from the **tagged commit**, not from `main`. A fix landed on
`main` after the tag does nothing for that release, and re-running the failed run
re-reads the same broken file: move the tag, or cut the next version.

What then happens. Every job needs `build`, and the publish chain is sequential:

| Job | Does | Gate |
| --- | --- | --- |
| `build` | injects the version from `git describe --tags --abbrev=0`, builds sdist and wheel, generates CycloneDX and SPDX SBOMs, attests both plus build provenance | **no `if:` — every trigger**, including the release event |
| `publish-testpypi` | uploads to TestPyPI | `release` event |
| `publish-pypi` | uploads to PyPI | `release` event, after TestPyPI |
| `upload-release` | attaches artifacts and SBOMs to the Release | `release` event, after PyPI |

**`build` runs again at release time, and that run is the one that ships.**
`publish-testpypi` downloads the `dist` artifact with no `run-id`, so it takes it from
the current workflow run — not from the earlier push to `main`. Two consequences a
maintainer should expect rather than discover:

- the build's two hard assertions are live gates at release time, not formalities
  already passed: the wheel-content check and `test "$COMPONENTS" -le 8` on the SBOM;
- the two builds inject **different versions**. On a push to `main`, `git describe`
  resolves to the *previous* tag; on the release event the checkout is at the tagged
  commit and resolves to the new one. So the `main` build exercises the chain — which
  is why it exists — but it is not the artifact.

TestPyPI gating PyPI is deliberate: an upload that fails only on the real index is one
that cannot be retried under the same version, because PyPI filenames are immutable.

`workflow_dispatch` runs `build` alone. Useful for exercising the chain without
publishing.

**Before the first release**, both the `testpypi` and `pypi` environments need a
trusted publisher configured on the respective index. Three fields have to match
exactly, and a mismatch in any of them is the standard first-release failure:
`dualeai/c2patxt`, the workflow filename `release.yml`, and the environment name
(`testpypi` or `pypi`). No API token exists or should; see [SECURITY.md](SECURITY.md).

> **The repository was renamed** from `dualeai/c2pa-text` to `dualeai/c2patxt`. If a
> trusted publisher was configured under the old name it must be updated on **both**
> indexes. GitHub's rename redirect does not help: the OIDC token the workflow mints
> carries the *current* repository, and the index compares that claim against what it
> has stored. A stale entry fails the upload at `publish-testpypi` — after `build` has
> already run and attested — and because TestPyPI gates PyPI, someone fixing only the
> one they hit will meet the other on the next attempt.

Nothing published predates the rename, so no released artifact carries provenance
naming the old repository and there is no historical mismatch for an auditor to
reconcile. That is only true until the first release.

**The version comes from the tag**, via `cicd/version.sh`, which falls back to `0.1.0`
when `git describe` finds nothing. `fetch-depth: 0` in the workflow is what makes tags
available to it — nothing asserts that the resolved version matches the Release tag, so
check the "Injecting version:" line in the build log before trusting the artifact.

## Writing

No marketing copy. No superlatives, no "first", no "only", no "reference
implementation" — a regulator reading a boast goes looking for the gap, and another
project already self-describes that way. Do not call this "the C2PA text library"; it
is *our implementation of* C2PA text marking.

Prefer the shorter word, cut what can be cut, and never use a long word where a short
one will do.

## Security

Do not open a public issue for a suspected vulnerability. See [SECURITY.md](SECURITY.md).
