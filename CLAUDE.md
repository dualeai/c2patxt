# Working in this repository

`c2patxt` implements C2PA 2.4 Annex A.8 text marking. It is a compliance artefact
under EU AI Act Article 50(2): a third party with no relationship to us must be able
to install it and check a document. Every rule below follows from that.

## Commands

```console
$ make install     # uv sync
$ make test        # static checks + every test except the benchmarks
$ make lint        # ruff format, ruff check --fix, pyright strict, vulture
```

Both green before anything is considered done. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the testing rules — they are not the usual ones and they are not optional.

## Searching the code

Use `seek`, not `grep` or `rg`. It ranks by relevance, groups by file, labels symbol
definitions and prints three lines of context, so one call usually answers the
question. It searches this repo by default; paths after the query narrow or widen it.

```console
$ seek [flags] '<query>' [path...]
```

Filters go inside the single-quoted query, separated by spaces (implicit AND):
`sym:Name` for a definition, `file:x` / `-file:x` on the path, `lang:python`,
`content:<regex>` for file contents only, `type:file` to list matching filenames,
`case:yes`, and `or` with `()` for boolean logic.

Queries worth reusing here:

```console
$ seek 'sym:verify -file:test'                       # the four public entry points
$ seek 'sym:Verdict file:src'                        # the type, not its 30 test uses
$ seek 'content:signingCredential\.[a-z]+ -file:test'  # every status code we emit
$ seek 'lang:yaml uses: actions/checkout'            # audit the SHA pins
$ seek 'x5chain' src/c2patxt/_cose.py                # one file only
```

Pitfalls: filters stay in **one** argument (`seek 'sym:Foo file:bar'`, not
`seek sym:Foo file:bar`); flags come before the query (`seek -n 5 'Foo'`); anything
after the query is a filesystem path, not a filter; single-quote to stop the shell
eating `|`, `(`, `)`. A multi-word query ANDs substrings — it is not a phrase match.
Cap large output with `-n` (files) and `-m` (matches per file). Exit codes: 0 found,
1 nothing, 2 error.

When you spawn a sub-agent it does not inherit this file, so tell it: *"Use
`seek 'pattern' [path...]` for code search. Keep query filters in one quoted string.
Never use grep/rg."*

If `seek` is missing:
`curl -sSfL https://raw.githubusercontent.com/dualeai/seek/main/install.sh | sh`
(needs `universal-ctags`: `brew install universal-ctags`).

## Writing

Six rules, from Orwell:

1. Never use a metaphor, simile or figure of speech you are used to seeing in print.
2. Never use a long word where a short one will do.
3. If it is possible to cut a word out, cut it out.
4. Never use the passive where you can use the active.
5. Never use a foreign phrase, a scientific word or a jargon word if you can think of
   an everyday English equivalent.
6. Break any of these rules sooner than say anything outright barbarous.

Repo-specific, and non-negotiable:

- **No marketing copy.** No superlatives, no "first", no "only", no "best". A
  regulator reading a boast goes looking for the gap.
- **Do not claim to be the reference implementation.** `encypherai/c2pa-text` already
  self-describes that way. We claim interoperability, not primacy.
- **Do not call this "the C2PA text library".** It is *our implementation of* C2PA
  text marking, and it is not a consortium release.
- **A claim in shipped text must be true today, or marked as planned.** An overclaim
  takes one shape: a sentence asserting a property with nothing checking it. If you
  write a claim, write the assertion that holds it.

## GitHub Actions must be SHA-pinned

Never reference an action by tag. Resolve the tag to a commit SHA and pin that, with
the tag in a trailing comment so the version stays readable:

```console
$ gh api repos/actions/checkout/commits/v4.2.2 --jq '.sha'
11bd71901bbe5b1630ceea73d27597364c9af683
```

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**Use `commits/<tag>`, not `git/ref/tags/<tag>`.** The latter is correct only for
*lightweight* tags. `actions/checkout`
uses those, which is why the worked example above is right either way. `CodSpeedHQ/action`
uses **annotated** tags, where the ref points at a tag OBJECT and `.object.sha` returns
that object rather than the commit:

```console
$ gh api repos/CodSpeedHQ/action/git/ref/tags/v5.0.2 --jq '.object.type, .object.sha'
tag
95b3994cf33230316e44b642e0e2cb8b949166f6   # the tag object -- NOT what you pin
$ gh api repos/CodSpeedHQ/action/commits/v5.0.2 --jq '.sha'
0ca9cbbf4623b599a6c3ed4fc8a922942705d9f1   # the commit
```

`commits/<tag>` resolves both kinds. `git ls-remote <repo> refs/tags/<tag>^{}` also
works.

**Nothing in CI checks this.** `zizmor`'s `unpinned-uses` audit is unavailable — the
action is not on the enterprise allowlist — and it would not catch the subtle half
anyway: a SHA that is really a tag OBJECT is syntactically a valid pin. Both halves are
on the author, enforced by review.

A tag is mutable; a SHA is not. For a package whose whole argument is supply-chain
verifiability, a mutable reference in the release path would undercut the claim.

## Static analysis

Rules for static testing are strict and must be followed. **If it fails, fix the
issue — NEVER turn off the linter.** Where a suppression is genuinely correct, it
carries a comment saying why the rule does not apply.

## Two things that are easy to get wrong

**The wire format is versioned separately from the API.** The API is unstable before
1.0.0. The bytes are not: any change to what we emit is a MAJOR version of both this
package and the vector file, because text marked by an older version must keep
verifying. Held by
`tests/test_vector_file.py::test_the_signed_manifest_bytes_are_exactly_what_they_were`;
nothing else in the suite covers the emitted bytes, down to a four-byte change in the
COSE `x5chain` encoding.

**`VALID` is not a failure.** Our credential is self-signed and we ship no trust
anchors, so a correct mark verifies as `VALID` carrying `signingCredential.untrusted`.
C2PA 14.3.5 defines *Valid* without requiring trust. Code or documentation that treats
that as an error is the single most likely mistake in this repository.
