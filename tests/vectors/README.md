# A.8 conformance vectors

Wire-format conformance vectors for **C2PA Technical Specification 2.4 (2026-04-01),
HTML build `c7e55d5a`, Annex A.8**, "Embedding Manifests into Unstructured Text".

The canonical local fixture is `A8ConformanceTest-2.0.0.txt`. Its header states the
wire rules, the local corrupt-prefix selection policy, and the flag vocabulary. The
file is self-describing and needs no package code to interpret.

## Using these from another language

**Discard anything from the first `#`, then split on `;`**, and hex-decode the byte
fields. That order matters: ten comments contain a semicolon, so splitting first gives
you eight or nine fields on 34% of the corpus.

No dependency, no parser generator, no toolchain. That is the whole point of the
flat-file format: a Rust, Go or TypeScript implementer should not have to install a
Python package to obtain a data file.

The data portion is **pure US-ASCII with no byte-order mark**. The subject matter is
invisible characters, and a corpus that stored them literally would be silently
corrupted by editors, terminals, diff viewers and review tools. Unicode's own
`NormalizationTest.txt` applies the same discipline.

## Licence

**The conformance file is CC0 1.0** — `A8ConformanceTest-*.txt`, see
`LICENSE` in this directory. Deliberately more permissive than the Apache-2.0 package
around it, so any implementation under any licence can vendor it without an
attribution obligation.

**The vendored standards corpora are not.** `cbor/` is BSD-2-Clause and `cose/` is
Unlicense. Each directory's `PROVENANCE.md` carries its licence and upstream commit.
Take the conformance file alone if you want the CC0 set.

## Versioning

The version is in the filename and in line 1. Record ids are immutable and are never
reused; a retired record stays as a commented-out line stating why.

- **MAJOR** — an expected value changed, a record was removed, or the package's signed
  producer wire changed. Any consumer may now fail or need to pin a release boundary.
- **MINOR** — records added.
- **PATCH** — comments or flags only; data bytes unchanged.

Version 2 accompanies producer-wire major 1. The A.8 carrier records did not change;
the shared major lets a consumer pin one release boundary.

## Scope, and what has no oracle at all

C2PA publishes no A.8 vectors — that absence is why this file exists — and the manifest
CBOR is deliberately opaque to it. The normal suite therefore checks the claim's
contents against tests derived from the corresponding C2PA validation clauses.

These vectors cover the A.8 **wire format**: wrapper framing, the byte-to-selector
mapping, detection, and malformed-input handling — 6 `embed` records and 23 `extract`
records, with statuses limited to `manifest.text.corruptedWrapper`,
`manifest.text.multipleWrappers`, `OK` and `NONE`. They do not cover manifest semantics,
the hash binding, or signature validation; those need a signing key and belong to the
package's own suite.

The standards corpora cover the layers beneath: `cose/` comes from the COSE working
group and `cbor/` from the CBOR working group.

**The bytes of a signed manifest are pinned separately**, in
`tests/test_vector_file.py::test_the_signed_manifest_bytes_are_exactly_what_they_were`
— a SHA-256 of one fully pinned `embed()`. A change to those bytes is a MAJOR version
of the package and this file. The digest lives in the package suite because reproducing
it needs a private key, which this corpus does not carry.
