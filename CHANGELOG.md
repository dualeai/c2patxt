# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the
caveat below.

**The public API is unstable until 1.0.0.** Anything not in `c2patxt.__all__` is
private and may change without notice. The *wire format* is a separate axis: any
change to the bytes we emit is a MAJOR version of both this package and the
conformance vector file, because text marked by an older version must keep verifying.

## [0.1.0] — unreleased

First release. The five functions — `embed`, `verify`, `extract`, `strip`, `locate` — work end
to end against C2PA 2.4 build `c7e55d5a`, Annex A.8.

### Added

- Validation enforces, on read: the hard binding over the NFC text with the wrapper
  excluded, **whose exclusion range must both name a located wrapper and be a suffix of
  the text** — two independently load-bearing conditions, since without the membership
  test an attacker chooses which bytes the hash covers, and without the suffix rule a
  canonically-equivalent respelling slides the wrapper into the middle of the text and
  still verifies; exactly one hard binding, or `assertion.multipleHardBindings`; text
  carrying more than one wrapper rejected outright; the claim's required fields (15.6.2);
  every assertion authenticated by the claim's hashed URI, with an assertion
  the claim does not link rejected as `assertion.undeclared`; `c2pa.ai-disclosure`
  present on every `__N` instance and carrying a non-empty `modelType`; an actions
  assertion whose inception action is first, in the first actions assertion the claim
  links, and — for `c2pa.created` — carrying `digitalSourceType`, which a template may
  supply; the claim's `signature` URI resolving to this manifest; generator and action
  icon references (15.10.3.3); the 14.5.1.1 certificate profile, minus the two rules
  that cannot apply to a text-only implementation (see
  [docs/c2pa-compatibility.md](docs/c2pa-compatibility.md)); and every certificate
  in `x5chain` inside its validity window, not just the leaf.
  **`c2pa-kp-claimSigning` is NOT required** — 14.5.1.1 names no claim-signing OID — and
  `modelType` is not restricted to Table 12, whose CDDL socket admits any string.

- `embed()`, `verify()`, `extract()`, `strip()`, `locate()`, and the four-state
  `Provenance` / `Verdict` result model.
- Hand-rolled deterministic CBOR (RFC 8949 §4.2.1 bytewise ordering — `cbor2`'s
  `canonical=True` implements §4.2.3 length-first, which C2PA does not permit), JUMBF
  box codec, and COSE_Sign1 with `x5chain` at RFC 9360 label 33.
- Ed25519 signing only. 13.2.1's allowed list is wider — ES256/384/512, PS256/384/512
  and EdDSA, with Ed25519 the only permitted EdDSA instance — so this is OUR narrowing,
  not the specification's. `Signer` refuses a certificate that fails
  the 14.5.1.1 claim-signing profile at construction.
- A caller-supplied `TrustEvaluator` seam. **Zero trust anchors ship.**
- Wire-format conformance vectors (`tests/vectors/A8ConformanceTest-1.1.0.txt`, 26
  records) — the C2PA text rubric has none.
- Documentation: [compatibility](docs/c2pa-compatibility.md),
  [deviations](docs/deviations.md), [known divergences](docs/known-divergences.md),
  [robustness](docs/robustness.md), [open questions](docs/open-questions.md).

### Evaluated but rejected

Recorded here permanently so "why didn't you just use X?" is answered once.

- **`c2pa-python` / `c2pa-rs` for the manifest.** It reserves roughly 11 KB for the
  signature. At A.8's measured cost of 3.90 UTF-8 bytes per manifest byte that is
  catastrophic: **12,006 bytes of marked text where ours produces 7,001**. The
  reservation is sound for an image and unusable for a sentence.
- **`cbor2` for the CBOR layer.** C2PA 10.1 mandates RFC 8949 §4.2.1 bytewise map
  ordering. `cbor2`'s `canonical=True` implements §4.2.3, length-first. Those produce
  different bytes for the same map, and the signature covers those bytes. A dependency
  that cannot express the required encoding is not a shortcut.
- **`pycose` for COSE_Sign1.** Six transitive dependencies for one detached-payload
  `Sig_structure` we can build in forty lines. Every runtime dependency is code that
  executes inside the caller's process on attacker-supplied input.
- **Reproducible builds as the provenance mechanism.** The right mechanism is
  attestation — SLSA for artifact→commit, PEP 740 for artifact→publisher. Bit-for-bit
  reproducibility answers a different question and would not let a third party check
  who published a wheel.
- **A CLI.** How a CLI is exposed, and how it fits an existing pipeline, is the
  integrating developer's decision under constraints we cannot see. This is an SDK.

### Known limitations

- The signing credential is **self-signed**, so `verify()` returns `VALID` with
  `signingCredential.untrusted` rather than `TRUSTED` unless you supply anchors. That
  is the specification's own model (14.3.5 vs 14.3.6), not a defect.
- No time-stamping (`sigTst2`), no stapled OCSP (`rVals`), no revocation checking.
  Certificate validity is judged against the current time at validation (15.8).
- No update manifests, no ingredient chains, no compressed manifests, no redaction.
- A.9 (structured text) and A.7 (HTML) are out of scope; A.9 permanently, on
  rendering-invariance grounds.
