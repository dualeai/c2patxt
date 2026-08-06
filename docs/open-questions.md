# Open questions

Things we could not settle from evidence. Listed rather than resolved, because a
compliance artefact that overstates its own evidence base is worse than one that says
less. Nothing here gates anything that ships.

Last checked 2026-08-05.

## CAWG has no text-specific credential specification — VERIFIED ABSENT

Checked against the Creator Assertions Working Group's own specification index at
`cawg.io`, which lists every specification it publishes:

| Specification | Status |
| --- | --- |
| Identity Assertion | current 1.2, draft 1.3 (+governance, +vc-vp, +vlei) |
| Metadata Assertion | current 1.1, draft 1.2 |
| Training and Data Mining Assertion | current 1.1 |
| Consent Assertion | draft 1.0 |
| Endorsement Assertion | draft 1.0 |
| Organizational Identity Profile | current 1.0, draft 1.1 |
| User Experience Guidance | current 1.0 |

None is text-specific, and the index mentions neither `text/plain` nor "unstructured"
anywhere. This is absence confirmed against the authoritative list, not a search that came back
empty. We are not designing around a specification that does not exist.

## HypoFuzz licensing — UNRESOLVED, and a legal question rather than a technical one

The HypoFuzz licence simultaneously grants free use to "open source initiatives" and
bars "any use within a commercial organization". Those clauses conflict for our exact
situation: an open-source project developed inside a commercial organisation.
`hypofuzz.com/pricing.html` returns **404** (the site itself returns 200), so the
terms cannot be resolved from the vendor's own published material.

**This gates nothing.** HypoFuzz would only be used by the optional post-v1 mutation
audit. The property-based testing that ships uses Hypothesis, which is MPL-2.0 and
carries no such restriction. If the audit is ever taken up, the licence needs a legal
answer first; until then this is recorded, not blocking.

## No status code exists for "the manifest store is not parseable JUMBF" — UNRESOLVED

A wrapper can be entirely well formed — correct magic, version 1, a `manifestLength`
that matches what is there — and still contain bytes that are not a JUMBF superbox at
all. We report `manifest.text.corruptedWrapper`.

**That is not a precise description and we know it.** 15.12.1.3.2 defines that code for
a wrapper with an "invalid version, algorithm, or manifest length", and none of those
applies: the carrier is intact and the payload is not.

Nothing better exists. Every code below this level presupposes a store that parsed —
`claim.missing`, `claim.cbor.invalid`, `assertion.cbor.invalid`, `claim.multiple` all
name things you can only find once the JUMBF has been read. `general.error` is the
specification's catch-all, but substituting it here would be a wire-visible choice
resting on no clause, and it would tell a reader strictly less than the code we already
emit.

So the fallback stands, the exception MESSAGE carries the diagnosis a reader actually
needs (`expected a jumb superbox, got …`), and
`tests/test_negative.py::test_a_wrapper_whose_manifest_is_garbage_is_corrupt` asserts
both — the message as the discriminator, the code as the acknowledged compromise.

Worth raising upstream alongside the other filings: the status table has no entry for a
manifest store that fails to parse, which every implementation must handle and each will
answer differently.

## Should verification check the signature before it hashes? — UNRESOLVED

`verify` runs assertions, then the hard binding, then the claim signature. 15.1.2 says
the phases are "listed in no particular order", so both orders conform.

**Everything before the signature check runs on input nobody has authenticated.** That is
what allowed pre-authentication hash amplification: a manifest could name one large
assertion many times and have it re-hashed per reference. Closed by memoizing digests per
`(label, algorithm)`, which bounds the work at the store's own size — but the exposure
class remains, and the next expensive check added before the signature would reopen it.

Signature-first would remove it at the root. Two things argue against doing it casually:

- **It changes the ORDER of reported codes, not the set.** `verify` runs all three
  phases unconditionally and accumulates every code, so a manifest broken in several ways already reports all of
  them. Nothing pins the top-level phase order — the three ordering tests pin
  `_assertion_failure`'s INTERNAL order, which is a different rule.
- **It changes what a caller learns.** Reporting `claimSignature.mismatch` for a manifest
  whose disclosure is also missing tells an operator less than reporting the missing
  disclosure.

The honest position is that the current order is a choice with a known cost, defended by
one specific mitigation, and that anything added to the pre-signature path needs its work
bounded the way `_assertion_digest` bounds hashing.

## Closed

- **JUMBF constants, `jumd` layout, toggle bits, content-type UUIDs, LBox/XLBox
  semantics, the Padding Box.** Resolved by four independent sources plus verbatim
  free normative text from the ISO clause 4.3 sample. No purchase was needed.
- **The C2PA box type UUIDs** (`c2pa`, `c2ma`, `c2as`, `c2cl`, `c2cs`) were read from
  the 2.0 PDF and have been re-verified byte for byte against the 2.4 build. See
  [c2pa-compatibility.md](c2pa-compatibility.md).
- **pytest-codspeed simulation mode** was adopted on 2026-08-05, in `tests/benchmarks/`
  and `.github/workflows/codspeed.yml`. What is held by a benchmark and what is held by an assertion is
  set out in [benchmarks.md](benchmarks.md).
