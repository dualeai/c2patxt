# A.8 conformance vectors

Wire-format conformance vectors for **C2PA Technical Specification 2.4 (2026-04-01),
HTML build `c7e55d5a`, Annex A.8**, "Embedding Manifests into Unstructured Text".

The normative artefact is `A8ConformanceTest-1.1.0.txt`. Everything a consuming
implementation needs — the wire format, the eight conformance invariants, and the
flag vocabulary — is stated in that file's header, so it is self-describing and
needs no code to interpret.

## Using these from another language

Split each data line on `;`, discard anything after `#`, and hex-decode the byte
fields. No dependency, no parser generator, no toolchain. That is the whole point of
the flat-file format: a Rust, Go or TypeScript implementer should not have to install
a Python package to obtain a data file.

The data portion is **pure US-ASCII with no byte-order mark**. The subject matter is
invisible characters, and a corpus that stored them literally would be silently
corrupted by editors, terminals, diff viewers and review tools. Unicode's own
`NormalizationTest.txt` applies the same discipline.

## Licence

**CC0 1.0** — see `LICENSE` in this directory. Deliberately more permissive than the
Apache-2.0 package around it, so any implementation under any licence can vendor
these without an attribution obligation.

## Integrity

```bash
shasum -a 256 -c SHA256SUMS
```

Maintainers: `make checksums` regenerates the manifest, and must run after ANY change
in this directory — this README included. The suite fails otherwise, in
`tests/test_external_vectors.py::test_every_checksummed_file_exists_and_matches`.

## Versioning

The version is in the filename and in line 1. Record ids are immutable and are never
reused; a retired record stays as a commented-out line stating why.

- **MAJOR** — an expected value changed, or a record was removed. Any consumer may
  now fail.
- **MINOR** — records added.
- **PATCH** — comments or flags only; data bytes unchanged.

Pin the SHA-256 rather than the version if you need certainty: it is strictly
stronger.

## Scope

These cover the A.8 **wire format**: wrapper framing, the byte-to-selector mapping,
detection, and malformed-input handling. They do not cover manifest semantics, the
hash binding, or signature validation — those need a signing key and belong to the
package's own suite.

**The bytes of a signed manifest are pinned separately**, in
`tests/test_vector_file.py::test_the_signed_manifest_bytes_are_exactly_what_they_were`
— a SHA-256 of one fully pinned `embed()`. That test exists because this file's scope,
correctly drawn above, left CONTRIBUTING.md's rule unenforceable: a change to the
manifest's bytes is a MAJOR version of the package *and* of this file, and nothing
could detect one. A four-byte change to the COSE `x5chain` encoding passed the whole
suite. The golden digest lives in the package's suite rather than here because
reproducing it needs a private key, which this corpus deliberately does not carry.

Three properties here are, as far as we can establish, untested anywhere else:
failure cases with their specific C2PA status codes, the distinction between "no
mark" and "broken mark", and the requirement that `embed` must not normalize the
caller's text.

## Contributing them upstream

These are offered to C2PA and to [C2SP](https://c2sp.org) as a governance home. If a
third party wants to consume them without this repository, say so on the issue
tracker and they move to a standalone repository — the licence and checksums are
already in place so that move costs nothing.

## Scope, and what has no oracle at all

The A.8 conformance file covers the **wire format only** — 6 `embed` records and 20
`extract` records, with statuses limited to `manifest.text.corruptedWrapper`,
`manifest.text.multipleWrappers`, `OK` and `NONE`. Nothing in it reaches the validator.

The genuinely third-party corpora here cover the layers beneath: `cose/` from the COSE
working group, `cbor/` from the CBOR working group. Both are other people's numbers,
which is what makes them worth vendoring.

**So every C2PA validation rule in this package has no independent oracle.** C2PA
publishes no A.8 vectors — that absence is why this file exists — and the manifest CBOR
is deliberately opaque to it, so the claim's contents are checked only against tests
written alongside the code they check. Where that matters, the tests say so: the
round-trip assertions in `test_embed.py` pin the emitted claim fields, and
`docs/mutation-audit.md` records what mutation testing found the day those were added.

A reader should not infer from this directory that the validator is externally checked.
It is not.
