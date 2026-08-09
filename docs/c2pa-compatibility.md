# C2PA compatibility

> **c2patxt implements C2PA Technical Specification 2.4 (2026-04-01), HTML build
> `c7e55d5a`, Annex A.8 "Embedding Manifests into Unstructured Text".**
> Verified against that build on 2026-08-05.

This document is the conformance claim. It is meant to be *checkable* — every clause
listed below is one you can open in the spec and compare against the code. If you
find a clause listed here that we do not actually implement, that is a bug in this
file and we want the report.

**One property of the clause tables is checked, and no more.**
`tests/test_compatibility.py` holds that the CORE clause table is in clause order; the
shorter A.8 table above it is not order-checked. Nothing checks that a "Where" entry
cites its clause, that the clause is correctly implemented, or the reverse direction —
a clause cited in `src/` and missing from these tables goes unnoticed. The tables are a
claim maintained by hand; report a row you cannot find in the code.

For the places where the specification is ambiguous or self-contradictory and we had
to choose, see [deviations.md](deviations.md). This file says *what* we implement;
that one says *how we read it where it was unclear*.

## Why this exists: EU AI Act Article 50(2)

Article 50(2) obliges providers of AI systems generating synthetic text to mark it in a
machine-readable form and make it detectable as artificially generated. The Commission's
Guidelines on Article 50 (C(2026) 5054 final, para 76) say a provider "must rely on
publicly-available industry standard detection solutions that allow any third party to
implement detection". The Commission adopted the Guidelines on 20 July 2026. This
package implements the published C2PA 2.4 Annex A.8 specification; whether that choice
satisfies the Guidelines in a deployment is outside this implementation claim.

**The Guidelines do not bind.** They give practical guidance under Article 96. No
standard is mandated: the Code of Practice on Transparency of AI-generated Content
(10 June 2026) names none, and mentions neither C2PA nor Content Credentials.

What that leaves undecided is most of it. Whether a given deployment satisfies Article
50(2) depends on the system, the exemptions in the Article's own text, and advice this
package cannot give. Marking is one obligation among several in Article 50, and nothing
here speaks to the others. The claim in this document is narrow on purpose: it says what
of A.8 is implemented and what is excluded, and nothing about anyone's compliance.

## Why the claim cites a build hash and not just "2.4"

The published 2.4 HTML has changed without a new version identifier. This claim uses
the full source commit
`c7e55d5a3c1e758eeabad058e501fadbb8cfe777` behind the reviewed HTML build so the
normative text can be recovered exactly. The claim's wire `specVersion` remains
`2.4.0`; the build hash is documentation provenance, not another protocol version.

## Version identifiers

They are unrelated axes and are easy to confuse:

| Axis | Value | Where it lives |
| --- | --- | --- |
| Wrapper format version | `1` | The `version` field of `C2PATextManifestWrapper` (A.8.2.2) |
| Claimed specification version | `2.4.0` | `claim_generator_info.specVersion` in every emitted claim |
| Specification build reviewed | 2.4 build `c7e55d5a` | Documentation and source citations; not a separate wire field |

Our encoder emits wrapper version `1`. Our decoder rejects any other value with
`manifest.text.corruptedWrapper`. A future spec revision could introduce wrapper
version 2 without changing its own version number, or change clauses without touching
the wrapper version — so neither number predicts the other.

## Cryptographic profile and quantum scope

The text carrier and the authenticated mark are separate layers:

| Layer | This package | Security consequence |
| --- | --- | --- |
| Carrier | A.8 marker and wrapper encoded as U+FEFF plus variation selectors | Encoding only; it has no cryptographic strength |
| Manifest hashing | SHA-256 by default; SHA-384 and SHA-512 are also permitted for the hard binding and hashed assertion references | Checks the NFC-normalized covered text and signed assertion references; does not authenticate a signer |
| Claim signature | COSE Sign1 with Ed25519 for generation; ES256/384/512, PS256/384/512 and Ed25519 on validation | Authenticates the signed claim under a key; all accepted algorithms are classical |
| Credential | A carried X.509 chain evaluated against caller-supplied trust policy | Relates the signing key to that policy; this package implements no post-quantum certificate path |

The authenticated mark is **not post-quantum resistant**. The
[C2PA 2.4 signature profile](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_signature_algorithms)
contains only the classical algorithms in the table, and validators reject a signature
algorithm outside that set. C2PA's
[Security Considerations](https://spec.c2pa.org/specifications/specifications/2.4/security/Security_Considerations.html#_threat_and_attack_assumptions)
put attacks using quantum cryptanalysis outside their scope. [RFC 8032 section
1](https://www.rfc-editor.org/rfc/rfc8032.html#section-1) states that a sufficiently
large quantum computer would break Ed25519. The C2PA 2.4
[Explainer](https://spec.c2pa.org/specifications/specifications/2.4/explainer/Explainer.html#_is_post_quantum_cryptography_supported_by_the_c2pa_standard)
describes ML-DSA support as planned, not part of the 2.4 profile.

Selecting SHA-384 or SHA-512 through `EmbedContext.algorithm` changes the hard binding,
the hashed assertion references and the claim's hash-algorithm declaration. It does
not change the Ed25519 claim signature or the X.509 credential chain, so it cannot make
the authenticated mark post-quantum resistant.

## What this claim covers

Clauses implemented. The Title column is a gloss of what we take from each clause, not
the published heading — open the clause number to read that.

### Annex A.8 — text marking

| Clause | Title | Where |
| --- | --- | --- |
| A.8.2.1 | Producer emits at most one; validation selects the wrapper named by the signed exclusion | `_embed.py`, `_verify.py` |
| A.8.2.2 | The C2PATextManifestWrapper Structure — Syntax | `constants.py`, `_selectors.py` |
| A.8.3.1 | Byte-to-Variation-Selector Conversion | `_selectors.py` |
| A.8.3.2 | Variation-Selector-to-Byte Conversion | `_selectors.py` |
| A.8.4.1 | Placement Rules | `_embed.py`, `_selectors.py`, `_locate.py`, `constants.py` |
| A.8.4.2 | Detection Algorithm | `_locate.py` |
| A.8.5 | Content Binding with Data Hash | `_verify.py` |
| A.8.6.1 | Validating a data hash | `_verify.py` |
| A.8.7.1 | Failure Codes | `status.py` |
| A.8.7.2 | Normalization | `_embed.py`, `_verify.py` |
| A.8.7.3 | Exclusion Handling | `_verify.py` |

### Core clauses

| Clause | Title | Where |
| --- | --- | --- |
| 5.1 | Versioning — `specVersion` declaration, and deprecation semantics: a deprecated construct may be read, never written | `manifest.py`, `_verify.py` |
| 6.2.2 | Namespacing of entity-specific values | `signing.py` |
| 6.4 | Multiple Instances — the `__N` label convention, honoured when counting | `_verify.py` |
| 6.6 | Assertion salts (`c2sh`) — read tolerance only, never emitted | `_jumbf.py`, `_embed.py` |
| 6.9 | Date/time values as CBOR tag 0 (`tdate`) | `_cbor.py`, `manifest.py` |
| 8.1 | Unique Identifiers — the `urn:c2pa:` ABNF for manifest labels | `manifest.py` |
| 8.4.2.1 | `self#jumbf` URIs — manifest-relative and store-relative forms | `_verify.py` |
| 8.4.2.3 | Hashing JUMBF Boxes — what every hashed URI covers | `_extract.py`, `manifest.py`, `_verify.py` |
| 9.2.4 | Hashing unstructured text assets | `_verify.py` |
| 10.1 | CBOR — Overview (deterministic encoding) | `_cbor.py` |
| 10.2.1 | Claim — Schema (`claim-map-v2`) | `manifest.py` |
| 10.2.3.2 | Generator Info Map — `name`, optional `version`, `specVersion` | `manifest.py` |
| 10.3.2.4 | Signing a Claim | `_cose.py` |
| 10.4 | Multiple Step Processing — A.8 adaptation using unprotected `pad`; see deviation | `_fixpoint.py` |
| 11.1.2 | Processing Rules (unknown-UUID skip) | `_extract.py` |
| 11.1.4 | C2PA Box details — labels, toggles, boxes, assertion content types | `_jumbf.py`, `manifest.py`, `_extract.py` |
| 11.2.2 | Standard Manifests — read under `c2ma` or `c2md`; see note | `_extract.py` |
| 13.1 | Hashing | `manifest.py` (`HASH_ALGORITHMS`) |
| 13.2.1 | Signature Algorithms — Ed25519 generation; full ES/PS/Ed25519 validation set | `signing.py`, `_cose.py` |
| 13.2.2 | Use of COSE | `_cose.py` |
| 13.2.3 | Computing the Signature | `_cose.py` (`Sig_structure`, `external_aad`) |
| 14.2 | Identity of Signers | `signing.py` |
| 14.3 | Validation states — *Valid* (14.3.5) and *Trusted* (14.3.6) | `verdict.py`, `_verify.py` |
| 14.4.1 | `c2pa-kp-claimSigning` EKU (OID 1.3.6.1.4.1.62558.2.1) — exported for producers; NOT required on read, see note | `signing.py` |
| 14.5 | X.509 Certificates — `x5chain` at label 33 *and* the string label; protected or unprotected bucket on read | `_cose.py` |
| 14.5.1.1 | Certificate Profiles — checked by role across the carried chain; see note | `trust.py` |
| 15.1.2 | Validation phases are "listed in no particular order" | `_verify.py` |
| 15.2.1 | Status-code enumeration | `status.py` |
| 15.2.2 | Success and informational status codes | `status.py` |
| 15.2.2.3 | Failure codes | `status.py` |
| 15.4.1 | Hash algorithm for the hard binding, inherited from the claim | `_verify.py` |
| 15.4.2 | Hash algorithm for a `hashed-uri`, resolved through the enclosing structure | `_verify.py` |
| 15.5.1 | The last recognized C2PA Manifest is active; unsupported active types fail explicitly | `_extract.py` |
| 15.5.2.1 | Producer refuses a second embedded store; validation follows the A.8 exact-exclusion selection — see deviation | `_embed.py`, `_verify.py` |
| 15.5.2.5 | Special Considerations for Unstructured Text | `_locate.py` |
| 15.6.1 | Locating (the claim box) | `_extract.py` |
| 15.6.2 | Validating (required claim fields, and the generator icon reference) | `_extract.py`, `_verify.py` |
| 15.7 | Validate the Signature | `_verify.py` |
| 15.8 | Validity period of the signer and every certificate carried in `x5chain`; see boundary below | `_verify.py` |
| 15.10.1.2 | Exactly one hard binding, one inception action, and at most one parent ingredient | `_verify.py` |
| 15.10.3.1 | Validation of assertion hashed URIs | `_verify.py` |
| 15.10.3.2.3 | Actions — inception, ingredient, redaction, related-assertion, soft-binding and icon rules; see note | `_verify.py` |
| 15.10.3.3 | Validation of References (`hashedURI.missing` / `hashedURI.mismatch`) | `_verify.py` |
| 15.11.3.3 | `claim.missing` when the claim cannot be located | `_extract.py` |
| 15.12.1.1 | Validating a data hash — ordered ranges and the additional-exclusions informational status | `_verify.py`, `status.py` |
| 15.12.1.3.1 | Validating a text data hash — select wrappers by exact exclusion match | `_verify.py` |
| 15.12.1.3.2 | Handling Corrupted Wrappers | `exceptions.py`, `_extract.py`, `status.py` |
| 15.12.1.3.4 | Partial Text Extraction — the `shall` only; see note | `_selectors.py` |
| 18.1 | Standard assertions are deterministic CBOR (RFC 8949 4.2.1) | `_cbor.py` |
| 18.4 | Assertion content types — CBOR, and JSON-LD for metadata | `_extract.py`, `manifest.py` |
| 18.5.2 | `data-hash-map` (`c2pa.hash.data`) | `manifest.py` |
| 18.15 | Actions — emits `c2pa.actions.v2` with `digitalSourceType`; reads it and v1 `c2pa.actions` (5.1) | `manifest.py`, `_verify.py` |
| 18.17 | Metadata assertions — current producer carries `dc:format` in `c2pa.metadata` | `manifest.py` |
| 18.21.1 | Table 12 — the model-type vocabulary `c2pa.ai-disclosure` draws on | `signing.py` |
| 18.28 | `c2pa.ai-disclosure` — producer emits the required `modelType` | `manifest.py`, `signing.py` |

**Note on 14.5.1.1.** Checked by role across every certificate carried in `x5chain`.
The common checks cover the `signatureAlgorithm` allowlist, including explicit
SHA-256/384/512 and matching MGF1 hashes for RSASSA-PSS, permitted EC subject curves,
RSA subject keys of at least 2048 bits, version v3, absence of
`issuerUniqueID` / `subjectUniqueID`, and AKI on a certificate that is not self-signed.
When AKI is present it must be non-critical and carry ``keyIdentifier``.
The leaf must not assert `cA` or `keyCertSign`; it must carry Key Usage with
`digitalSignature` and a non-empty EKU free of `anyExtendedKeyUsage`,
`id-kp-timeStamping`, and `id-kp-OCSPSigning`. Each carried CA must assert `cA` in a
critical Basic Constraints extension, carry non-critical SKI and Key Usage, and assert
`keyCertSign`. A CA's EKU does not affect profile
acceptance. SKI remains a `should` for the leaf, so its absence is not a rejection.

Two checks need narrow DER reads because `cryptography` does not expose all of their
inputs: `issuerUniqueID` / `subjectUniqueID`, and the MGF1 hash and explicit-field
presence inside RSASSA-PSS parameters. The unique-ID walk stays at the top level of
the `TBSCertificate` SEQUENCE; the PSS walk enters only the outer
`signatureAlgorithm` and its two required parameter fields. Neither is a general
ASN.1 parser.

**We do NOT require `c2pa-kp-claimSigning`.** 14.5.1.1
names no required EKU OID; 14.4.1, which we cited for it, is addressed to validators
about their own trust-anchor configuration and explicitly anticipates
`id-kp-emailProtection` and `id-kp-documentSigning` instead — the pair previous versions
of the specification used for legacy configurations. Demanding the newer OID gave such
certificates `signingCredential.invalid`, a hard reject. Which EKUs a deployment accepts
is a trust question (14.5.1.2), belonging to the `TrustEvaluator` seam; with no anchors
shipped, our accepted-EKU list is empty and the question decides nothing about validity.

**14.5.1.2 remains unclaimed.** Its EKU-scoped trust-anchor selection and RFC 5280 §6
path building are the `TrustEvaluator` seam's job, and we bundle no evaluator. Backend
adoption also requires an offline dependency core and an answer on
[RFC 9618](https://www.rfc-editor.org/rfc/rfc9618.html), which replaces RFC 5280's
certificate-policy tree with a graph to prevent exponential work from crafted policy
mappings. Remote retrieval, if added, belongs behind an async public API.

**Note on 11.2.2.** The clause requires consumers to "also accept standard C2PA
Manifests specified with JUMBF type UUID 63326D64-… (`c2md`)", while forbidding claim
generators from creating them. The reader recognizes both `c2ma` and `c2md`; the
producer emits only `c2ma`. Recognition uses the type UUID as 11.1.2 requires, so an
unknown box that copies a structural label is skipped rather than interpreted as that
structure.

**Note on 15.10.3.2.3.** Action validation covers created and gathered actions
together. It checks the single inception action and its position; declared ingredient
relationships; redaction targets; the shape, digest and target type of
`parameters.relatedAssertions`; the soft binding required by watermarked actions; and
generator, software-agent and template icon references through 15.10.3.3. Ingredient
assertion validation is not implemented, so a manifest carrying one fails closed even
when its action relationship is otherwise consistent.

The reader exposes one active Standard Manifest. A `c2pa.removed` action must instead
name a `componentOf` ingredient in another manifest. Since that earlier manifest is
not available through this data model, such an action is rejected with
`assertion.action.ingredientMismatch`; it is never accepted against a same-manifest
ingredient. Support is planned as a store-wide manifest index plus a signed public
multi-manifest regression; accepting the action before both exist would skip the
cross-manifest relationship check.

**Note on 15.12.1.3.4.** Its `shall` — reject a truncated wrapper with a failure code
— is implemented. Its two `should`s, that a validator "indicate that the text appears
to be a fragment of a larger, signed text", are **not**: a wrapper missing its tail is
indistinguishable from a damaged one, so we report `manifest.text.corruptedWrapper`
without guessing which. See `_selectors.py`.

### JUMBF box type UUIDs

Read directly out of the 2.4 build on 2026-08-05 and byte-compared against the
constants used in every emitted description box. `tests/test_compatibility.py` holds
those values; `tests/test_vector_file.py` separately pins the complete signed producer
wire. All five we use match:

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
document: JPEG WG1's JLINK WD 3.0 publishes a toggle table giving bits 0-3 as
Requestable, Label, ID and Signature, and reserving the rest. Bit 4, Private, comes
straight from C2PA 11.1.4.1.2, which gives it as the mask `xxx1xxxx`. The JLINK draft
is a different standard, so it corroborates bits 0-3 without establishing that
19566-5 A.3 is worded identically.

## What this claim does NOT cover

Stating this matters as much as the list above; a claim that omits its own boundary is
an overclaim.

- **A.7, embedding manifests into HTML.** Different carrier, different rules.
- **A.9, embedding manifests into structured text** (comment and front-matter forms).
  Permanently out of scope: A.9 puts visible characters into the document, so marking
  is not rendering-invariant. A.8 selectors are designed to be visually non-rendering.
- **Image, audio and video carriers.** Use an implementation that supports those
  carrier formats.
- **RFC 3161 time-stamping (`sigTst2`) and stapled revocation data (`rVals`).** This
  package neither obtains nor validates them. Obtaining fresh TSA or OCSP material is
  external; validation of carried material can be offline.
- **Compressed manifests (`c2cm`/`brob`), update manifests (`c2um`), ingredient
  chains, and secure-redaction salt boxes (`c2sh`).** We emit and validate one Standard
  Manifest describing one act of generation. The reader recognizes compressed and
  update manifests for active-manifest selection, then rejects an unsupported active
  type explicitly. It does not resolve earlier manifests or perform secure redaction.
- **Certificate revocation (14.5.2).** No carried `rVals`, local cache, CRL, or OCSP
  validation, and no package-owned fetch.
- **`c2pa.asset-type.v2`.** The producer records `dc:format` in authenticated
  `c2pa.metadata` but does not emit the asset-type assertion that 18.21.3 says should
  carry an exact IANA text/application type. Adding it changes the signed producer
  wire and requires the package's wire-major process.
- **Post-quantum security.** The carrier is an encoding and the authenticated mark
  uses classical cryptography. See
  [Cryptographic profile and quantum scope](#cryptographic-profile-and-quantum-scope).
- **Certification.** This package is not a C2PA consortium release and carries no
  conformance certification.

## Trust is not bundled

We ship **zero trust anchors**, and `verify()` therefore returns `VALID`, not
`TRUSTED`, for a correct self-signed mark. That is the specification's own model —
14.3.5 defines a *Valid* manifest without requiring `signingCredential.trusted`, and
14.3.6 adds trust separately — not a limitation we are apologising for. Supply your
own anchors and a `TrustEvaluator` to reach `TRUSTED`.

## Specification-update and wire-version policy

A.8 says it "remains under review and may be subject to change based on implementation
feedback and interoperability testing". The update policy is:

1. The compatibility statement names **one** specification build at a time.
2. A new build is re-verified against the conformance vector file before the claim
   moves. The claim never gets silently re-pointed.
3. Any change to emitted bytes is a **major** version of both this package and the
   vector file. Text marked by an older version must keep verifying.
