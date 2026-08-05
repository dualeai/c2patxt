# CBOR vectors — RFC 8949 Appendix A

Source: <https://github.com/cbor-wg/cbor-test-vectors>, `tests/rfc8949-appendixA/`
— the CBOR working group's own corpus.

**Licence: BSD-2-Clause.** Retrieved 2026-08-05; upstream last pushed 2026-02-22.

`mt0.cbor` … `mt7.cbor` hold encoded values grouped by major type, each paired with
an `.edn` file giving the same values in CBOR diagnostic notation.

## Why this repository and not `cbor/test-vectors`

The older `cbor/test-vectors` is unmaintained since 2019-08-07 and ships **no licence
file at all**, which makes it legally unvendorable however good the data is. That is
the cautionary precedent this directory exists to avoid.

## Scope

These cover CBOR generally. They do **not** cover RFC 8949 §4.2.1 *deterministic*
encoding, which is what C2PA §10.1 and §18.1 mandate and what our decoder enforces on
read. Vectors for bytewise map ordering, shortest-form lengths, and rejection of
indefinite-length containers are ours to author — a genuine gap in the ecosystem and
a cheap contribution back.

Refresh with `make download-vectors`.
