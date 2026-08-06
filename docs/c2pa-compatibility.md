# C2PA compatibility

> **c2patxt implements C2PA Technical Specification 2.4 (2026-04-01), HTML build
> `c7e55d5a`, Annex A.8 "Embedding Manifests into Unstructured Text".**
> Verified against that build on 2026-08-05.

This document is the conformance claim. It is meant to be *checkable* — every clause
listed below is one you can open in the spec and compare against the code. If you
find a clause listed here that we do not actually implement, that is a bug in this
file and we want the report.

**Nothing automated checks it.** Grading prose is not the test suite's job, so the
tables below are a claim maintained by hand. Read them as one — and report a row you
cannot find in the code.

For the places where the specification is ambiguous or self-contradictory and we had
to choose, see [deviations.md](deviations.md). This file says *what* we implement;
that one says *how we read it where it was unclear*.

## Why the claim cites a build hash and not just "2.4"

"C2PA 2.4" is not a stable identifier, and pretending otherwise would make this claim
unverifiable. The facts, each independently checked:

- **2.4 has no release tag.** The `c2pa-org/specifications` repository carries tags
  for 2.3, 1.3 and v1.0 only. There is no 2.4 tag and no 2.4 GitHub release.
- **2.4 is published,** as HTML and as a PDF (8,139,117 bytes, last modified
  2026-04-23; page 1 reads "2.4, 2026-04-01"). But 2.4 does not appear in the
  specification site's own Download navigation.
- **Eleven distinct 2.4 HTML builds exist.** We verified against build `c7e55d5a`
  (2026-04-23).
- **Annex A.8 changed exactly once across those builds:** commit `666bdf8f`
  (2026-04-01) added the sentence "It remains under review and may be subject to
  change based on implementation feedback and interoperability testing." Clause
  15.12.1.3 never changed.
- **In 2.3 the same annex is A.7,** renumbered to A.8 in 2.4. Normalising the clause
  numbers, the two texts are identical apart from that added sentence. Citing the 2.3
  PDF would therefore give a reader the wrong clause letter for the same content.

Naming a version alone would leave you unable to tell which of eleven documents we
built against. Naming the build makes the claim falsifiable, which is the only kind
worth making.

## Two different version numbers

They are unrelated axes and are easy to confuse:

| Axis | Value | Where it lives |
| --- | --- | --- |
| Wrapper format version | `1` | The `version` field of `C2PATextManifestWrapper` (A.8.2.2) |
| Specification version | 2.4 build `c7e55d5a` | This document; not present in the wire format |

Our encoder emits wrapper version `1`. Our decoder rejects any other value with
`manifest.text.corruptedWrapper`. A future spec revision could introduce wrapper
version 2 without changing its own version number, or change clauses without touching
the wrapper version — so neither number predicts the other.

## What this claim covers

Clauses implemented, with the 2.4 titles as published:

### Annex A.8 — text marking

| Clause | Title | Where |
| --- | --- | --- |
| A.8.2.1 | Wrapper quantity — "Zero or one" per asset | `_verify.py`, `_locate.py` |
| A.8.2.2 | The C2PATextManifestWrapper Structure — Syntax | `constants.py`, `_selectors.py` |
| A.8.3.1 | Byte-to-Variation-Selector Conversion | `_selectors.py` |
| A.8.3.2 | Variation-Selector-to-Byte Conversion | `_selectors.py` |
| A.8.4.1 | Placement Rules | `_embed.py` |
| A.8.4.2 | Detection Algorithm | `_locate.py` |
| A.8.5 | Content Binding with Data Hash | `_verify.py` |
| A.8.6.1 | Validating a data hash | `_verify.py` |
| A.8.7.1 | Failure Codes | `status.py` |
| A.8.7.2 | Normalization | `_embed.py`, `_verify.py` |
| A.8.7.3 | Exclusion Handling | `_verify.py` |

### Core clauses

| Clause | Title | Where |
| --- | --- | --- |
| 6.6 | Assertion salts (`c2sh`) — read tolerance only, never emitted | `_jumbf.py` |
| 8.1 | Unique Identifiers — the `urn:c2pa:` ABNF for manifest labels | `manifest.py` |
| 8.4.2.1 | `self#jumbf` URIs — manifest-relative and store-relative forms | `_verify.py` |
| 8.4.2.3 | Hashing JUMBF Boxes — what every hashed URI covers | `_extract.py`, `manifest.py`, `_verify.py` |
| 9.2.4 | Hashing unstructured text assets | `_verify.py` |
| 10.1 | CBOR — Overview (deterministic encoding) | `_cbor.py` |
| 10.2.1 | Claim — Schema (`claim-map-v2`) | `manifest.py` |
| 10.2.3.2 | Generator Info Map — `name`, optional `version`, `specVersion` | `manifest.py` |
| 10.3.2.4 | Signing a Claim | `_cose.py` |
| 10.4 | Multiple Step Processing | `_fixpoint.py` |
| 11.1.2 | Processing Rules (unknown-UUID skip) | `_jumbf.py`, `_extract.py` |
| 11.1.4 | C2PA Box details — labels, toggles, boxes, assertion content types | `_jumbf.py`, `manifest.py`, `_extract.py` |
| 11.2.2 | Standard Manifests — read under `c2ma` or `c2md`; see note | `_extract.py` |
| 14.3 | Validation states — *Valid* (14.3.5) and *Trusted* (14.3.6) | `verdict.py`, `_verify.py` |
| 13.1 | Hashing | `manifest.py` (`HASH_ALGORITHMS`) |
| 13.2.1 | Signature Algorithms | `signing.py` (Ed25519 only) |
| 13.2.2 | Use of COSE | `_cose.py` |
| 13.2.3 | Computing the Signature | `_cose.py` (`Sig_structure`, `external_aad`) |
| 14.2 | Identity of Signers | `signing.py` |
| 14.4.1 | `c2pa-kp-claimSigning` EKU (OID 1.3.6.1.4.1.62558.2.1) — exported for producers; NOT required on read, see note | `signing.py` |
| 14.5 | X.509 Certificates — `x5chain` at label 33 *and* the string label; protected bucket only, see [deviations](deviations.md) | `_cose.py` |
| 14.5.1.1 | Certificate Profiles — see note for the two rules that cannot apply | `trust.py` |
| 5.1 | Versioning — `specVersion` declaration, and deprecation semantics: a deprecated construct may be read, never written | `manifest.py`, `_verify.py` |
| 6.2.2 | Namespacing of entity-specific values | `signing.py` |
| 6.4 | Multiple Instances — the `__N` label convention, honoured when counting | `_verify.py` |
| 15.1.2 | Validation phases are "listed in no particular order" | `_verify.py` |
| 15.2.1 | Status-code enumeration | `status.py` |
| 15.2.2 | Success and informational status codes | `status.py` |
| 15.4.1 | Hash algorithm for the hard binding, inherited from the claim | `_verify.py` |
| 15.4.2 | Hash algorithm for a `hashed-uri`, resolved through the enclosing structure | `_verify.py` |
| 15.2.2.3 | Failure codes | `status.py` |
| 15.5.1 | The last manifest superbox is the active manifest | `_extract.py` |
| 15.5.2.1 | Plural embedded manifest stores are invalid | `_embed.py` |
| 15.5.2.5 | Special Considerations for Unstructured Text | `_locate.py`, `_verify.py` |
| 15.6.1 | Locating (the claim box) | `_extract.py` |
| 15.6.2 | Validating (required claim fields, and the generator icon reference) | `_extract.py`, `_verify.py` |
| 15.7 | Validate the Signature | `_verify.py` |
| 15.10.1.2 | Exactly one hard binding, and exactly one inception action | `_verify.py` |
| 15.8 | Validity period of the signing certificate and every CA above it | `_verify.py` |
| 15.10.3.1 | Validation of assertion hashed URIs | `_verify.py` |
| 15.10.3.2.3 | Actions — inception action rules and icon references; see note | `_verify.py` |
| 15.10.3.3 | Validation of References (`hashedURI.missing` / `hashedURI.mismatch`) | `_verify.py` |
| 15.11.3.3 | `claim.missing` when the claim cannot be located | `_extract.py` |
| 15.12.1.1 | Validating a data hash — General | `_verify.py` |
| 15.12.1.3.1 | Validating a text data hash | `_verify.py` |
| 15.12.1.3.2 | Handling Corrupted Wrappers | `exceptions.py`, `_selectors.py` |
| 15.12.1.3.4 | Partial Text Extraction — the `shall` only; see note | `_selectors.py` |
| 6.9 | Date/time values as CBOR tag 0 (`tdate`) | `_cbor.py`, `manifest.py` |
| 18.1 | Standard assertion labels | `manifest.py` |
| 18.4 | Assertion content types — CBOR, and JSON-LD for metadata | `_extract.py`, `manifest.py` |
| 18.5.2 | `data-hash-map` (`c2pa.hash.data`) | `manifest.py` |
| 18.15 | Actions — emits `c2pa.actions.v2`, reads it and v1 `c2pa.actions` (5.1), and `digitalSourceType` on `c2pa.created` | `manifest.py`, `_verify.py` |
| 18.17 | Metadata assertions — `c2pa.metadata` carrying `dc:format` | `manifest.py` |
| 18.6 | Box byte order (big-endian), which A.8.2.2 omits | `constants.py`, `_jumbf.py` |
| 18.21.1 | Table 12 — the model-type vocabulary `c2pa.ai-disclosure` draws on | `signing.py` |
| 18.28 | `c2pa.ai-disclosure` — emitted, and `modelType` validated on read | `manifest.py`, `signing.py`, `_verify.py` |

**Note on 14.5.1.1.** Checked for the leaf, which is the only certificate our
validation path consults: the
`signatureAlgorithm` allowlist (the eight values the clause tables), version v3,
absence of `issuerUniqueID` / `subjectUniqueID`, AKI on any certificate that is not
self-signed, `cA` not asserted, Key Usage present and asserting `digitalSignature` but
not `keyCertSign`, EKU present, non-empty, free of `anyExtendedKeyUsage`, and carrying neither `id-kp-timeStamping` nor
`id-kp-OCSPSigning` — the exclusivity rule that 14.5.1.2 restates as a validator
obligation, and that constrains OUR leaf rather than some certificate we never see.

Two of the clause's rules cannot apply here. The named-curve and 2048-bit-modulus
requirements govern `id-ecPublicKey` and RSA **subject** keys, and 13.2.1 restricts the
key we verify a claim with to Ed25519, so a certificate reaching either rule was
already rejected. The Subject Key Identifier requirement is a `should` for end-entity
certificates, and a `should` is not a rejection condition.

**Two more are genuinely not implemented:**

- **RSASSA-PSS parameters.** When `signatureAlgorithm` is `id-RSASSA-PSS` the clause
  requires `hashAlgorithm` to be present and to be one of `id-sha256` / `id-sha384` /
  `id-sha512`, `maskGenAlgorithm` to be present, and its parameters' algorithm to equal
  `hashAlgorithm`'s. We admit `id-RSASSA-PSS` to the signature-algorithm allowlist and
  check none of it. Unlike the two rules above, this one is **reachable**: our leaf must
  be Ed25519, but its *issuer* may sign with RSASSA-PSS. `cryptography` does not surface
  `RSASSA-PSS-params`, so implementing it means another DER walk.
- **Scope.** The clause opens "All certificates shall fulfill the following
  requirements"; we apply the profile to the leaf only. 14.5 requires intermediates to
  be present in `x5chain`, so they are certificates we hold and could check. Chain
  building itself is the `TrustEvaluator` seam's job, but the profile is not.

`issuerUniqueID` / `subjectUniqueID` are the one rule requiring us to read DER
directly — `cryptography` exposes no accessor for either — and the walk stays at the
top level of the `TBSCertificate` SEQUENCE so a `0x81` length byte inside a nested
structure can never be mistaken for a field.

**We do NOT require `c2pa-kp-claimSigning`.** 14.5.1.1
names no required EKU OID; 14.4.1, which we cited for it, is addressed to validators
about their own trust-anchor configuration and explicitly anticipates
`id-kp-emailProtection` and `id-kp-documentSigning` instead — the pair previous versions
of the specification required, and which the entire pre-2.2 installed base carries.
Demanding the newer OID gave every one of those certificates `signingCredential.invalid`,
a hard reject. Which EKUs a deployment accepts is a trust question (14.5.1.2), belonging
to the `TrustEvaluator` seam; with no anchors shipped, our accepted-EKU list is empty and
the question decides nothing about validity.

**14.5.1.2 remains unclaimed.** Its EKU-scoped trust-anchor selection and RFC 5280 §6
path building are the `TrustEvaluator` seam's job, and we bundle no evaluator.

**Note on 11.2.2.** The clause requires consumers to "also accept standard C2PA
Manifests specified with JUMBF type UUID 63326D64-… (`c2md`)", while forbidding claim
generators from creating them. We satisfy both halves, and the read half falls out of
how the parse works rather than from a UUID list: the manifest box is located **by its
label**, and its type UUID is not consulted. There is consequently no `c2md` constant
to add — adding one would be an unused declaration asserting a check that does not
exist. `c2md` is also one of the two box types
[known-divergences.md](known-divergences.md) records as missing from c2pa-rs, so being
able to read it is that entry's point.

**Note on 15.10.3.2.3.** We implement its `c2pa.created` / `c2pa.opened` rule in full —
the action must be the first element of its assertion's `actions` array, and that
assertion must be the first actions assertion the claim links, counted across 6.4's
`__N` instances — and its reference validations: the `icon` in an action's
`softwareAgent`, in each entry of the assertion's `softwareAgents`, and in each
`templates` entry, all routed through 15.10.3.3 as the clause requires. **`parameters.relatedAssertions` is deliberately not implemented.**
Its rule is not only a 15.10.3.3 validation — it also requires the value to be "an
array with at least one element" and forbids the referenced assertion from being an
ingredient or an actions assertion, both reported as `assertion.action.malformed`.
Those are actions-validation rules rather than reference rules, and half-implementing
them would let us report a claim as fully checked when it is not. The same applies to
this clause's `c2pa.opened` / `c2pa.placed` ingredient rules, `c2pa.redacted`, and the
`c2pa.watermarked` soft-binding rule: we neither emit nor validate them.

**Note on 15.12.1.3.4.** Its `shall` — reject a truncated wrapper with a failure code
— is implemented. Its two `should`s, that a validator "indicate that the text appears
to be a fragment of a larger, signed text", are **not**: a wrapper missing its tail is
indistinguishable from a damaged one, so we report `manifest.text.corruptedWrapper`
without guessing which. See `_selectors.py`.

### JUMBF box type UUIDs

Read directly out of the 2.4 build on 2026-08-05 and byte-compared against what we
emit. All five we use match:

| Box | UUID | Emitted |
| --- | --- | --- |
| Manifest Store | `63327061-0011-0010-8000-00AA00389B71` (`c2pa`) | yes |
| Standard Manifest | `63326D61-0011-0010-8000-00AA00389B71` (`c2ma`) | yes |
| Assertion Store | `63326173-0011-0010-8000-00AA00389B71` (`c2as`) | yes |
| Claim | `6332636C-0011-0010-8000-00AA00389B71` (`c2cl`) | yes |
| Claim Signature | `63326373-0011-0010-8000-00AA00389B71` (`c2cs`) | yes |
| Compressed Manifest | `6332636D-...` (`c2cm`) | no — we do not compress |
| Update Manifest | `6332756D-...` (`c2um`) | no — see below |
| Compressed box | box ID `0x62726F62` (`brob`) | no |

2.4 additionally pins the ISO year for the description-box rules — "ISO 19566-5:2023,
A.3" — where 2.0 did not. That also tells you the `jumd` description box is Annex A.3
of that standard, which is how the toggle bits were cross-checked without buying the
document.

## What this claim does NOT cover

Stating this matters as much as the list above; a claim that omits its own boundary is
an overclaim.

- **A.7, embedding manifests into HTML.** Different carrier, different rules.
- **A.9, embedding manifests into structured text** (comment and front-matter forms).
  Permanently out of scope: A.9 puts visible characters into the document, so marking
  is not rendering-invariant. A.8 exists precisely because variation selectors are
  zero-width.
- **Image, audio and video carriers.** Use `c2pa-rs` or `c2pa-python`.
- **RFC 3161 time-stamping (`sigTst2`) and stapled OCSP (`rVals`).** Both require
  network access at signing time; verification here is a pure offline function.
- **Compressed manifests (`brob`), update manifests (`c2um`), ingredient chains,
  redaction (`c2sh` salt boxes).** We emit exactly one standard manifest describing
  one act of generation. There is no ingredient to reference and nothing to redact.
- **Certificate revocation (14.5.2).** Offline, so no CRL or OCSP fetch.
- **Certification.** There is none to claim: of the 152 products on the C2PA
  conformance list, none is certified above specification 2.2 and none declares a
  valid text media type -- one declares a bare non-IANA `txt` token. This package is not a C2PA consortium release and carries no
  conformance certification.

## The text conformance rubric

The **C2PA Text Asset Conformance Rubric v0.1.0** (`c2pa-org/conformance-public`,
`asset-rubrics/asset-rubric-text-conformance.yml`, C2PA Conformance Task Force,
2026-05-04) is the only formal conformance instrument that exists for text. We pass
all six of its checks; each is asserted individually in `tests/test_rubric.py`.

**Passing it is self-assessed, and it tests less than its name suggests.** Both facts
matter more than the pass:

- Nothing in the rubric exercises variation-selector encoding, the wrapper
  magic/version/length framing, the U+FEFF marker, NFC normalization, byte-offset
  computation, or hash recomputation. It is six JMESPath expressions over a parsed
  manifest.
- `text:exclusions_defined` only checks that the exclusion list is non-empty. It never
  checks that the exclusion *matches a wrapper* — the check that actually stops an
  attacker choosing which bytes the hash covers.
- Neither `manifest.text.corruptedWrapper` nor `manifest.text.multipleWrappers` is
  referenced anywhere in it.
- There are **no wire vectors**. That gap is what
  `tests/vectors/A8ConformanceTest-1.2.0.txt` exists to fill.

The rubric is also the only authority partitioning media types — A.8 names none at
all:

| Group | Types |
| --- | --- |
| A.8, unstructured | `text/plain`, `text/csv`, `text/tab-separated-values` |
| A.9, structured | `text/markdown`, `text/xml`, `application/xml`, `application/xhtml+xml` |
| A.7, HTML | `text/html` |

**We deliberately depart from it for `text/markdown`,** marking it under A.8 on
rendering-invariant grounds: A.9's forms insert *visible* delimiters, which is exactly
what A.8 exists to avoid. See `tests/test_rubric.py` for the pinned reasoning.

## Trust is not bundled

We ship **zero trust anchors**, and `verify()` therefore returns `VALID`, not
`TRUSTED`, for a correct self-signed mark. That is the specification's own model —
14.3.5 defines a *Valid* manifest without requiring `signingCredential.trusted`, and
14.3.6 adds trust separately — not a limitation we are apologising for. Supply your
own anchors and a `TrustEvaluator` to reach `TRUSTED`.

## When 2.5 lands

A.8 says in the spec's own words that it "remains under review and may be subject to
change based on implementation feedback and interoperability testing". So the policy
is defined now, before it is convenient to bend:

1. The compatibility statement names **one** specification build at a time.
2. A new build is re-verified against the conformance vector file before the claim
   moves. The claim never gets silently re-pointed.
3. Any change to the bytes on the wire is a **major** version of both this package and
   the vector file — not a minor, not a patch. Text marked by an older version must
   keep verifying, or the compliance artefact was worthless.
