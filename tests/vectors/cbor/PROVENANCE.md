# CBOR vectors — RFC 8949 Appendix A

Source: <https://github.com/cbor-wg/cbor-test-vectors>, `tests/rfc8949-appendixA/`
— the CBOR working group's own corpus.

**Licence: BSD-2-Clause.** Retrieved 2026-08-05; Upstream `tests/rfc8949-appendixA/` last changed 2026-01-22 in `001eb684`.

`mt0.cbor` … `mt7-simple.cbor` hold encoded values grouped by major type, each paired with
an `.edn` file giving the same values in CBOR diagnostic notation.

`bad` (47 items, from `tests/rfc8949/`, last changed `e70ea1fe0781`) and `streaming`
(11 items, from `tests/rfc8949-appendixA/`) are the two refusal corpora. Every
`streaming` item is an indefinite-length encoding, which §4.2.1 forbids, so all eleven
must be refused. 45 of `bad`'s 47 must be refused with our own `CborDecodeError` and
no other exception type.

**The other two `bad` items are accepted, on purpose.** The upstream file is titled
"Inputs that should fail for RFC 8949", which means RFC 8949 *validity* — wider than
well-formedness. A tag 0 carrying a map is invalid under §5.3.2 and still well-formed
under Appendix C, and C2PA §15.10.3.1 rejects only content that is "NOT WELL-FORMED
CBOR". `tests/test_cbor.py` names both and says why.

## Why this repository and not `cbor/test-vectors`

The older `cbor/test-vectors` is unmaintained since 2019-08-07 and ships **no licence
file at all**, which makes it legally unvendorable however good the data is. That is
the cautionary precedent this directory exists to avoid.

## Scope

These cover CBOR generally. They do **not** cover RFC 8949 §4.2.1 *deterministic*
encoding, which is what C2PA §10.1 and §18.1 mandate and what our decoder enforces on
read — except that `streaming` supplies the indefinite-length half of it. Vectors for
bytewise map ordering and shortest-form lengths are ours to author: upstream publishes
only `rfc8949-appendixA`, `rfc8949` and `spike`, none of which carries them.

Refresh with `make download-vectors`.
