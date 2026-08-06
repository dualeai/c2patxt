# Open questions

Things we could not settle from evidence. Nothing here gates anything that ships.

Last checked 2026-08-05.

## CAWG has no text-specific credential specification — VERIFIED ABSENT

Checked against the Creator Assertions Working Group's own specification index at
`cawg.io`, which lists every specification it publishes. The seven it lists cover
identity, metadata, training and data mining, consent, endorsement, organizational
identity and user experience. None is text-specific, and the index mentions neither
`text/plain` nor "unstructured". We are not designing around a specification that does
not exist.

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

The current order is a choice with a known cost, defended by one mitigation. Anything
added to the pre-signature path needs its work bounded the way `_assertion_digest`
bounds hashing.
