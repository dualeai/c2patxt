# Implementation scope

## Included

The package implements the C2PA 2.4 Annex A.8 text carrier and the validation needed
to produce, locate, extract and verify its manifests. The clause-by-clause boundary is
in [c2pa-compatibility.md](c2pa-compatibility.md); choices where clauses conflict or
leave a gap are in [deviations.md](deviations.md).

The public result distinguishes an intact but untrusted credential (`VALID`) from one
approved by the caller's `TrustEvaluator` (`TRUSTED`). The package ships no anchors
and provides no remote retrieval.

## Excluded

- A bundled trust-root distribution or a package-owned RFC 5280 validation backend.
- Package-owned remote certificate, revocation or timestamp retrieval.
- Media carriers other than Annex A.8 text.
- Peer-implementation compatibility tests. Conformance tests use the C2PA and cited
  RFC requirements directly.

Open specification questions are listed in [open-questions.md](open-questions.md).
CPU and memory measurements live in the CodSpeed suite described in
[benchmarks.md](benchmarks.md).

## Release checks

The release workflow uses the organization build sequence: `uv build`, archive
presence checks and `twine check`. It then generates and attests the SBOM and build
provenance. Publishing remains gated on a GitHub Release. The maintainer steps are in
[releasing.md](releasing.md).
