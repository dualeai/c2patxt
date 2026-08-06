# What ships in 0.1.0

## Definition of done

Every row was re-verified on 2026-08-06 and every one held.

| Requirement | Status | Evidence |
| --- | --- | --- |
| The vector file's own rules hold, byte for byte | ✅ | `tests/test_vector_file.py` (44 tests), `test_selectors.py` (rule 2), `test_locate.py` (rules 3, 5, 6) |
| Three-way agreement with the encypher and writerslogic vectors | ✅ | `tests/test_third_party_interop.py` — their vectors against the spec transcribed a second time, AND against the shipped codec, encoding and reading both |
| Coverage ≥ 90, and the gate is real rather than tautological | ✅ | 99.83%; mutation-verified — see below |
| Exactly one runtime dependency | ✅ | `tests/test_package.py`, `tests/test_leaf_rule.py` |
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

Several tests were verified by breaking the code and confirming they fail: the CBOR
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
  [recorded](mutation-audit.md). Three tools were considered and each is out for its
  own reason: `mutmut` 3.x skips module-level constants, exactly what a codec most
  needs mutated; `atheris` 3.1.0 ships cp312/cp313/cp314 manylinux x86_64 wheels only,
  covering neither the Python 3.10 we support nor macOS; and `HypoFuzz` permits
  non-commercial use only, its open-source carve-out reaching "open source projects
  that are not commercially supported, or which are governed by a non-profit
  organization", which this is not.
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

## Release mechanics

The **build** job — `uv build`, `twine check`, SBOM, attestation — runs on every push
to `main`. The **publish** jobs are gated on the `release` event, which leaves the OIDC
handshake as the single untested step at release time rather than the whole chain. The
runbook is in [releasing.md](releasing.md).
