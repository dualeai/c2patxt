# What ships in 0.1.0

Written because forty-odd tasks existed and nothing said which subset constituted a
release. Without this line, "0.1.0" means "whenever someone decides", and every tail
task silently becomes a blocker.

## Definition of done

Every row was re-verified on 2026-08-06 and every one held.

| Requirement | Status | Evidence |
| --- | --- | --- |
| The vector file's own rules hold, byte for byte | ✅ | `tests/test_vector_file.py` (41), `test_selectors.py` (rule 2), `test_locate.py` (rules 3, 5, 6) |
| Three-way agreement with the encypher and writerslogic vectors | ✅ | `tests/test_third_party_interop.py` — their vectors against the spec transcribed a second time, AND against the shipped codec, encoding and reading both |
| Coverage ≥ 90, and the gate is real rather than tautological | ✅ | 99.83%; mutation-verified — see below |
| Exactly one runtime dependency | ✅ | `tests/test_package.py`, `tests/test_leaf_rule.py` |
| README states its six load-bearing claims without hedging | ✅ | Review only. Nothing automated checks the wording |
| Every unresolved item described as unverified, or removed | ✅ | [open-questions.md](open-questions.md) |

The evidence is in [mutation-audit.md](mutation-audit.md).

**On the first row, precisely:** `test_vector_file.py` deliberately does NOT import
the package — it validates the file against a second transcription of A.8, which is
what makes the file independent evidence rather than a mirror of our encoder. The
codec is driven against the records separately: rule 2 (embed) in
`tests/test_selectors.py`, rules 3 and 5 (extract, absence) and rule 6 (round trip) in
`tests/test_locate.py`. `verify()` and `strip()` have **no vector record** — the file
covers the wire format, not the binding or the signature, and says so in its own scope
statement.

**"The gate is real" is a claim we can support, not an aspiration.** Several tests
were verified by deliberately breaking the code and confirming they fail: the CBOR
corpus test, the assertion-authentication check, the duplicate-label rejection, the
non-`cbor` assertion rejection, and the quadratic-scan guard. Where a test did *not*
bite, it was rewritten rather than kept.

## In scope, and delivered

The codec end to end (constants, selector codec, `locate`, `extract`, JUMBF, CBOR,
COSE, `verify`, the trust seam, `embed`, the claim model, the padding fixpoint, the
frozen public surface, the status registry, `Signer`/`Disclosure`), the conformance
story (vector file and records, cross-validation, property tests, negative and
rejection suites, known-divergence pins), and the release story (release workflow,
SECURITY.md, README, leaf rule, deviations, external vectors, the 2.4 compatibility
statement, the text conformance rubric).

**Delivered ahead of its planned scope:** the adversarial robustness numbers were
explicitly *not* required for 0.1.0, on the grounds that they are a measurement rather
than a correctness gate. They were measured anyway and are published in
[robustness.md](robustness.md).

## Deliberately not in 0.1.0

- **An AUTOMATED mutation-testing audit.** The audit itself was done by hand and is
  [recorded](mutation-audit.md); automating it buys less than it costs, because
  mutmut 3.x skips module-level constants -- exactly what a codec most needs mutated.
- **Splitting the vectors into their own repository.** Triggered by an external
  consumer asking, which by definition has not happened yet.
- **A separate trust-roots distribution.** We ship no anchors on purpose.

## Three things 0.1.0 must not do

1. **Must not claim conformance it has not tested.** It does not: the compatibility
   document lists what is implemented *and* what is excluded, and says plainly that
   passing the text rubric is self-assessed and that no certification exists to obtain.
2. **Must not ship robustness numbers we did not measure.** It does not: every number
   in [robustness.md](robustness.md) came from running `tools/robustness.py` against
   the PAN'26 corpus, with the md5 recorded so the run can be repeated.
3. **Must not imply the trust store does anything.** It does not: it ships empty, and
   the README, the package docstring and `trust.py` all say that `VALID` with
   `signingCredential.untrusted` is the expected outcome.

## Where we departed from the requirements

The founding memo (2026-08-04) is **internal to Duale AI and not in this repository**,
so each row below states what it asked for rather than citing it — the table stands on
its own for an outside reader. Six departures, each decided after the memo was written
and each recorded so a reader does not have to guess which are drift and which are
decisions.

| Memo says | We ship | Why |
| --- | --- | --- |
| §2 distribution `duale-c2pa-text`, import `duale_c2pa_text` | `c2patxt` | Renamed on the owner's instruction. The wrapper's own magic number is ASCII `C2PATXT\0`, so the name is the format's. |
| §2 "a cryptography library and a CBOR library" | `cryptography` only | C2PA 10.1 mandates RFC 8949 §4.2.1 bytewise map ordering; `cbor2`'s `canonical=True` implements §4.2.3 length-first. A dependency that cannot express the required encoding is not a shortcut. |
| §3 `embed(text, manifest)` | `embed(text, signer, disclosure)` | A caller who must construct a `ManifestStore` must know C2PA. `ManifestStore` is now output-only. |
| §3 `Verdict` with four booleans, and "`if verify(text):` should get something useful" | four-state `Provenance`; `__bool__` **raises** | Any single boolean collapses `UNMARKED` and `INVALID`, which renders unmarked text as forged. See `verdict.py`. |
| §5 "ship our published root **in the package**" | **zero** trust anchors | A bundled root makes `TRUSTED` reachable without the caller ever choosing whom to trust. Trust is a caller-supplied seam. |
| §5 "ship `python -m … verify <file>`" | **no CLI** | Decided by the owner: how a CLI is exposed and how it fits an existing pipeline is the integrating developer's call under constraints we cannot see. This is an SDK. |

### The one that departs from a prohibition, not a preference

**§1 and §8 forbid a removal helper outright** — *"do not add a 'removal' helper
either"*, and *"Any 'strip' or 'remove' helper"* is on the out-of-scope list. **We
ship `strip()`.** That is the most consequential departure here, so the reasoning is
set out rather than assumed.

The memo's own argument is that removal is inherent — *"Publishing the extractor
publishes a remover… Removal is what an attacker writes in ten lines from our own
detection algorithm; we do not ship it, promote it, or make it easier."* The first half
is right and unchanged: the format and the detection algorithm are published, so
`strip()` gives an attacker essentially nothing. It converts ten lines into one.

What it does give a *legitimate* caller is the only correct way to re-mark a document.
`AlreadyMarkedError` tells a caller to remove the existing wrapper and call again, and
the span it hands them is in **bytes**. Slicing a `str` with byte offsets silently
leaves a zero-width residue on any non-ASCII text — and that failure is triple
invisible: the residue does not render, it is shorter than the magic number so
`verify()` reports `UNMARKED` rather than corrupt, and `embed()` then bakes it
permanently inside the newly hashed text. Demonstrated in
`tests/test_strip.py::test_the_naive_string_slice_is_wrong_and_strip_is_not`.

So the trade is: a marginal convenience for an attacker who already has everything they
need, against a silent document-corruption bug for every honest integrator who follows
our own error message. We took the second. `strip()` is not promoted in the README
beyond one clause, and no "remove" alias exists.

One more, smaller: §6 says "ours will be the reference" and we deliberately do **not**
claim that — `encypherai/c2pa-text` already self-describes as a reference
implementation. We claim interoperability. See CONTRIBUTING.md.

The memo's §4 also contradicts itself on the hash-binding order; that is a correction
to the memo rather than a departure from it, and it is in
[platform-handoff.md](platform-handoff.md).

## Release mechanics

The **build** job — `uv build`, `twine check`, SBOM, attestation — runs on every push
to `main`. The **publish** jobs are gated on the `release` event. That leaves the OIDC
handshake as the single untested step at release time, rather than the whole chain.

**Not on a tag.** `git push --tags` produces nothing at all: the `push` trigger filters
on `branches: [main]`, and a branch filter excludes tag pushes. Publishing means creating
a GitHub **Release**. The runbook is in [CONTRIBUTING.md](../CONTRIBUTING.md#cutting-a-release).
