# Deviations and ambiguity resolutions

Where C2PA 2.4 is ambiguous, self-contradictory, or silent, we had to choose. This
document records each choice and why.

All quotations are from **C2PA Technical Specification 2.4 (2026-04-01), HTML build
`c7e55d5a`**, re-checked against that build on 2026-08-05. See
[c2pa-compatibility.md](c2pa-compatibility.md) for why the claim cites a build hash.

The compatibility document carries the clause inventory; this one carries the
reasoning.

**Which of these matter.** Most are wire-format choices no reader will ever hit. The
ones where a conforming peer reading the specification the other way disagrees with us
on the bytes are **1** (hash ordering), **2** and **28** (which wrappers are rejected),
**3** and **4** (what the exclusion covers, and byte order) and **8** (where the padding
lives). **21** differs only in what we emit: every reader involved accepts both forms,
so nothing breaks. The one that bears on the Article 50(2) disclosure itself is **23**:
we reject a mark whose AI disclosure discloses nothing, where the specification obliges
no validator to. Everything else is internal.

---

## Index by clause

Which deviations touch a given clause. Generated from the sections below and held by
`tests/test_deviations_index.py`, so it cannot drift from them.

| Clause | Deviations |
| --- | --- |
| 6.2.2 | 23 |
| 6.4 | 19, 23 |
| 8.4.2.1 | 21, 26 |
| 10.1 | 20, 27 |
| 10.2.2 | 21 |
| 10.2.3.2 | 26 |
| 10.4 | 8 |
| 10.4.4 | 8 |
| 13.2.1 | 11 |
| 14.3.5 | 12 |
| 14.3.6 | 12 |
| 14.5 | 18 |
| 14.5.1.1 | 11 |
| 15.2.1 | 14 |
| 15.4 | 20 |
| 15.5.2.1 | 2 |
| 15.6.2 | 20 |
| 15.7 | 12 |
| 15.10.1.2 | 19 |
| 15.10.3.1 | 20, 27 |
| 15.10.3.2 | 23 |
| 15.10.3.2.3 | 19, 25 |
| 15.10.3.3 | 26, 29 |
| 15.12.1.1 | 9, 22 |
| 15.12.1.3.1 | 1, 2, 14, 17 |
| 15.12.1.3.2 | 5 |
| 15.12.1.3.3 | 14 |
| 18.5.1 | 7 |
| 18.5.2 | 8 |
| 18.15.2 | 24, 25 |
| 18.15.6.1 | 24 |
| 18.28.2 | 13, 23 |
| 18.28.4 | 23 |
| A.8.2.1 | 2 |
| A.8.2.2 | 3, 4, 5 |
| A.8.4.1 | 2 |
| A.8.4.2 | 3, 15 |
| A.8.5 | 1 |
| A.8.7.1 | 2, 14 |
| A.8.7.3 | 1, 28 |

Numbers are stable: five files cite deviations by ordinal, including `src/`, so a
withdrawn item keeps its number rather than closing the gap.

---

## 1. The hash ordering is specified twice, incompatibly

**15.12.1.3.1** (steps 5–7): remove the wrapper bytes per the exclusion range,
normalize the remainder to NFC, encode UTF-8, hash.

**A.8.7.3**: "perform normalization before calculating offsets."

These produce different bytes. **We follow 15.12.1.3.1**, because A.8.5 delegates to
it in so many words — "refer to the Validation clause for the normative procedure" —
and because both other public A.8 implementations independently chose the same.
Throughout this document those two are `encypherai/c2pa-text` and
`writerslogic/c2pa-text-binding`, pinned to the commits we read in
[tests/vectors/third_party/PROVENANCE.md](../tests/vectors/third_party/PROVENANCE.md).

Computed from the Unicode Character Database:

| Text | Remove first | Normalize first |
| --- | --- | --- |
| `a` + wrapper + U+0301 | `c3 a1` | `61 cc 81` |
| U+1100 + wrapper + U+1161 | `ea b0 80` | `e1 84 80 e1 85 a1` (3 vs 6 bytes) |
| `A` + wrapper + U+030A | `c3 85` | `41 cc 8a` |

The cause is that U+FEFF is a **starter** — combining class 0 — so it blocks
composition across itself. Removing it first lets `a` + U+0301 compose to U+00E1;
normalizing first cannot.

**`embed()` avoids the question.** It always places the wrapper as a suffix,
so there is nothing after it to compose with and both readings hash the same bytes.
A verifier that reads A.8.7.3 the other way still agrees with us. Guarded by
`tests/test_normalization.py`.

## 2. Four incompatible rules for multiple wrappers

| Clause | Says |
| --- | --- |
| A.8.2.1 | "Quantity: Zero or one" |
| A.8.4.1 | select the wrapper by matching the exclusions |
| A.8.7.1 | `manifest.text.multipleWrappers` — "More than one …" |
| 15.5.2.1 | plural manifest stores are all invalid |
| 15.12.1.3.1 | "If more than one wrapper **matches the exclusions**, reject with `manifest.text.multipleWrappers`" |

The last is narrower than the rest: it makes plurality a failure only among wrappers
that match the exclusion range, which would let an attacker append a second wrapper
that does not match and have it ignored.

**We reject on more than one wrapper, full stop**, before parsing any of them. The
permissive reading lets an attacker append a wrapper and choose which one a given
consumer reads, and "different verifiers disagree about which claim applies" is
exactly the failure a provenance format cannot have.

`verify()` and `extract()` both refuse; `locate()` deliberately does not, because it
returns a *span* rather than a manifest and exists for inspecting a document rather than
trusting it.

## 3. Whether U+FEFF is inside the exclusion range

Undefined. A.8.2.2 defines the wrapper structure starting at `magic`; the U+FEFF that
precedes it is described in A.8.4.2 as the detection marker, and no clause says
whether the hash exclusion covers it.

**We include it.** Both public implementations do. If it were excluded, the marker
would sit inside the hashed region while being pure mark rather than content, and
every producer would have to agree on the same answer anyway — so the question is
one of convention, and we follow the existing one.

## 4. Endianness is never stated

A.8.2.2 gives `unsigned int(64) magic`, `unsigned int(8) version` and
`unsigned int(32) manifestLength` with no byte order. This is the only clause in the
specification that omits it.

**We use big-endian**, from ISO/IEC 14496-12's convention, which the JUMBF box
headers this format wraps already follow. The magic number resolves itself — it is
ASCII `C2PATXT\0`, so a little-endian writer would produce `\0TXTAP2C`, which is
visibly wrong. `manifestLength` is the field that genuinely needed a decision.

## 5. 15.12.1.3.2 names a field that does not exist

> "…appears to be corrupted (invalid version, **algorithm**, or manifest length)"

A.8.2.2's syntax has exactly four members: `magic`, `version`, `manifestLength`,
`jumbfContainer`. There is no algorithm field in the wrapper.

**We treat it as a drafting error** and do not look for one. An unsupported hash
algorithm is reported as `algorithm.unsupported` from the assertion, where the
algorithm actually lives, not as `manifest.text.corruptedWrapper`.

## 6. No status code for "detected but absent"

There is no code for "a U+FEFF was found but no wrapper followed", nor for "this is a
text asset with no wrapper at all".

**Neither is an error and neither gets a code.** Absence returns `UNMARKED` with an
empty code list. Most text ever written is unmarked; a library that reports a
failure code for it is one whose output gets ignored.

## 7. 18.5.1 forbids what A.8 requires

18.5.1 says exclusion ranges shall not cover an asset's header or length fields. A.8
requires the exclusion to cover the entire wrapper, header and `manifestLength`
included.

**A.8 wins**, as *lex specialis*: the specific provision for this carrier governs
over the general one. The alternative — excluding only `jumbfContainer` — would leave
13 bytes of attacker-controlled header inside the hashed region while the length
field that describes them sits outside it.

## 8. `pad` is mandatory, and A.8 defines no padding

`data-hash-map` (18.5.2) makes `pad` non-optional — the CDDL carries no `?` — and
validators "shall ignore the presence and contents of pad and pad2". A.8 defines no
padding mechanism for the selector run at all: the wrapper structure has no pad
field, and nothing says how a two-pass producer reserves space.

**We put the padding in `pad`**, which is where 10.4 "Multiple Step Processing" says
slack bytes go. It is inside the signed claim, so it cannot be tampered with, and it
is a field every C2PA implementation already knows to ignore.

`encypherai/c2pa-text` instead pads the selector run itself, in
`encode_wrapper_padded`, which puts the slack outside the signature;
`writerslogic/c2pa-text-binding` declares `pad` and leaves it empty. Three
implementations, three answers — tabulated as item 8 in
[known-divergences.md](known-divergences.md).

**Our `pad` is not zero-filled, and that is a deviation.** The CDDL comment reads
"zero-filled byte string used for filling up space", and c2pa-rs's `pad_to_size`
pushes `0x00`. We append up to two `0xFF` bytes because a `0x00` costs 3 UTF-8 bytes
as a variation selector and a high byte costs 4, and mixing the two is what lets the
search hit an exact target length. Practical risk is nil — c2pa-rs declares the field
`pub pad: Vec<u8>` with no length or content validation anywhere, and the
specification tells validators to ignore its contents — but the field's stated
semantics say zeros, so this is recorded here rather than presented as free.

We do not emit `pad2`. 10.4.4 introduces it because deterministic CBOR length
encoding makes some total sizes unreachable with one length-prefixed field; we reach
every size by varying the *content* of `pad` instead, since a `0x00` byte costs 3
UTF-8 bytes as a variation selector and a high byte costs 4. See
`src/c2patxt/_fixpoint.py`.

## 9. Update-manifest offset arithmetic is undefined here

15.12.1.1 describes adjusting offsets when a manifest is replaced. The arithmetic
assumes a linear relationship between manifest bytes and asset bytes. For a selector
run there is none: the UTF-8 length of the encoded wrapper depends on the *values* of
the manifest bytes, not only their count.

**We do not emit update manifests**, so the clause does not arise. Recorded because
anyone adding them will hit this immediately, and the fix is not obvious.

## 10. A.8 assigns no media type

A.8 never says which `dc:format` values it applies to. Only the conformance rubric
does, and it lists `text/plain`, `text/csv` and `text/tab-separated-values`.

**We accept any `text/*` type**, including `text/markdown`. Markdown is
rendering-invariant under zero-width insertion in exactly the way A.8 requires, and
the rubric's omission of it reads as an oversight rather than an exclusion. This is a
deliberate deviation from the rubric, pinned by
`tests/test_rubric.py::test_markdown_is_marked_under_a8_as_a_deliberate_deviation`.

## 11. No Ed25519 SPKI constraint in the certificate profile

14.5.1.1 constrains key usage and extended key usage but does not constrain the
subject public key algorithm, and this package accepts only Ed25519 — our narrowing,
since 13.2.1's list also carries ES256/384/512 and PS256/384/512.

**We check the key type at verification**, not only the COSE `alg`. Ed448 shares the
COSE algorithm identifier −8 with Ed25519, so `alg` alone does not distinguish them
and the key type is what actually decides.

## 12. "Rejected" versus "Valid but not Trusted"

15.7 describes an untrusted signing credential as grounds for rejection. 14.3.5
defines a *Valid* manifest **without** requiring `signingCredential.trusted`, and
14.3.6 adds trust as a separate, higher state.

**We follow 14.3.5/14.3.6**: `signingCredential.untrusted` yields `VALID`, not
`INVALID`. Under the other reading, a correct, intact, honestly-signed self-signed
mark reads as forged — which would make every mark this package produces, out of the
box, indistinguishable from a forgery. A profile *violation* is different and does
hard-reject; see `src/c2patxt/trust.py`.

## 13. `scientificDomain`: not emitted, not parsed

The CDDL declares a list; the specification's own prose example shows a bare string
(`"cs.AI"`). The ambiguity is real.

**We do not emit the field and we do not read it,** so the ambiguity does not reach
us. 18.28.2 makes it optional — "If present, the value of the `scientificDomain` field
shall conform to the arXiv taxonomy" — and we hold no reliable signal for it. A
guessed value inside a signed assertion is worse than its absence.

The field is neither emitted nor parsed; `grep -rn scientificDomain src/ tests/`
returns only docstrings saying so.

## 14. `manifest.text.*` codes are absent from the normative CDDL enum

The `$status-code` socket in 15.2.1 declares its codes as a CDDL group. Verified on
2026-08-05, reading the socket in build `c7e55d5a`: **none** of them is `manifest.text.corruptedWrapper` or
`manifest.text.multipleWrappers`, though both are defined in prose at A.8.7.1 and
15.12.1.3.3 and used normatively at 15.12.1.3.1.

**We emit them anyway.** They are the only codes A.8 defines for its own failures,
and a validator that reported something else would be less interoperable, not more.
A strict CDDL validator will reject our status output; that is a specification bug,
and it is filed upstream.

## 15. A.8.4.2 detection hazards

The detection algorithm is described in prose and leaves four cases open. Our
resolutions, each with a test in `tests/test_negative.py`:

| Hazard | Resolution |
| --- | --- |
| Leading UTF-8 BOM | Not a mark. Every Windows-authored text file starts with one. |
| Fewer than 8 selectors | Not a mark, not corruption. Too short to spell the magic. |
| Adjacent user variation selectors (emoji) | Not a mark. U+FE0F is everywhere in ordinary text. |
| Unbounded `manifestLength` | Bounded before allocation against `MAX_MANIFEST_LENGTH`. |

The governing principle: a non-matching run must never prevent a genuine wrapper
elsewhere in the text from being found. Otherwise anyone able to prepend text — a
mail client adding a quoted header, a CMS adding a byline — could make a marked
document read as `UNMARKED`, which invites no investigation at all.

## 16. Withdrawn

A cosmetic unresolved cross-reference in the published build, affecting no wire
format. Filed as one of the items in [upstream-filing.md](upstream-filing.md); it was
never a deviation. The number stays because five files cite these by ordinal.

## 17. `locate()` reports as-stored offsets, not NFC-frame offsets

`locate()` returns offsets into the **as-stored** encoding of the string the caller
handed us, and the field names say so: `Span.utf8_start`, `Span.utf8_stop`, not
`nfc_utf8_start`. An NFC-frame reading was considered and rejected.

**The specification decides it.** 15.12.1.3.1 step 5 removes the wrapper bytes
*according to the exclusion range*, and only step 6 normalizes what remains. An
exclusion range therefore indexes the text **before** normalization, so a `locate()`
that reported NFC-frame offsets would return numbers that cannot be compared against
the exclusion without re-deriving them.

It also decides usability. A caller slices *their own string*, which is the as-stored
one — an NFC-frame offset would be unusable against the only string they hold. That is
why `strip()` exists and why its tests demonstrate the naive slice going wrong.

The two frames genuinely differ, and not only by shrinking:

| Text | As stored | After NFC |
| --- | ---: | ---: |
| `café` (NFD) | 6 bytes | 5 bytes |
| `Ångstrom` (U+212B) | 10 bytes | 9 bytes |
| `क़x` (U+0958, a composition exclusion) | 4 bytes | **7 bytes** |

The third row is the trap: NFC *decomposes* U+0958, so the offset **grows**. Anyone
who assumes normalization only ever shortens offsets writes an off-by-N that passes
every Latin-script test. Guarded by `tests/test_normalization.py`.

For our own output the question never arises: `embed()` normalizes before marking, so
the two frames coincide. It arises only for foreign input — which is exactly the input
a verifier receives.

## 18. We refuse an `x5chain` from the unprotected COSE bucket

**14.5** gives validators two instructions about where the certificate chain may live:

> "Validators **shall accept** either the string `x5chain` or the integer 33 as the
> label for this header. If both labels are present, validators shall use the header
> with the integer label 33 and ignore the header with the string `x5chain`."

> "Validators **shall accept** the header from either the protected or unprotected
> bucket, to maintain compatibility with previous versions of this specification."

**We follow the first and decline the second.** Both labels are accepted; only the
**protected** bucket is.

The unprotected bucket is not covered by the signature. A chain taken from it is one
an attacker can replace at will — and the chain's entire job is to say *which key
signed this claim*. Accepting it would mean letting unsigned data nominate the key
used to check a signature, which is not a compatibility concession but a hole.

The compatibility the clause is protecting is with *previous versions of the
specification*, not with any producer we have seen: C2PA 14.5 elsewhere requires
generators to place the header in the protected bucket, so a conforming 2.4 producer
is unaffected. What we lose is the ability to verify marks made by a pre-2.x producer.
For a format whose first text implementation is younger than 2.4, that set is empty.

Pinned by `tests/test_cose.py::test_the_unprotected_bucket_is_still_refused`, asserting
the exact message rather than merely a rejection, so the refusal cannot become
incidental.

## 19. Withdrawn

Recorded as a deviation on a reading of 15.10.1.2 alone, which names no failure code
for a missing or duplicated inception action. 15.10.3.2.3 states the whole rule
including the code, so `assertion.action.malformed` is the specification's and there
was nothing to deviate from. The rules it implies — the inception action first in its
assertion's `actions` array, in the first actions assertion the claim links, counted
across 6.4's `__N` instances — are implemented and documented at
[c2pa-compatibility.md](c2pa-compatibility.md). The number stays because five files
cite these by ordinal.

## 20. We decline the v1 `c2pa.claim` label, which 10.1 says we *should* accept

> "Validators **should** still accept this label (and associated claim-map)."

**We accept `c2pa.claim.v2` only.** A `should`, so declining is legitimate — but the
reason matters more than the modal verb. `claim-map` v1 is not the same map under an
older name: `claim_generator_info` is an **array** of generator-info-maps where v2 has
a single map, `dc:format` and `dc:title` are present, and `assertions` replaces
`created_assertions` / `gathered_assertions`.

Accepting it therefore means carrying a second claim model through every validation
path that reads a claim field — 15.6.2's required fields, 15.4's algorithm resolution,
15.10.3.1's link walk, and 15.6.2's icon reference. Each would need a v1 branch, and
each branch would be code no test we can write from our own producer ever exercises,
because we emit v2. Untested branches in the security path are worse than an honest
refusal.

A v1 claim reads as `claim.missing`, because the box we look for is not there.

## 21. The `signature` URI is manifest-relative, not absolute

> 10.2.2: the `signature` field "shall contain an absolute URI reference".

**We emit `self#jumbf=c2pa.signature`**, which 8.4.2.1 calls "relative to the current
C2PA Manifest".

The two clauses read against each other. 8.4.2.1 defines exactly two forms for a
`self#jumbf` URI — manifest-relative and store-relative — and both are *relative* in
the ordinary sense; "absolute URI reference" in 10.2.2 most plausibly means the
store-relative form, which is absolute *within the manifest store*, but the
specification does not say so.

**c2pa-rs emits the store-relative form** — `sdk/src/jumbf/labels.rs:79` at
`9b6b2e52` builds
`{to_manifest_uri}/c2pa.signature`, pinned by its own test to
`self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.signature` — and accepts the
manifest-relative form on read: `to_normalized_uri` strips the prefix and
`verify_claim`'s catch-all arm (`sdk/src/claim.rs:1910-1913`, commented "relative
signature box") takes it from there. So the two producers disagree and both readers cope.

**We ACCEPT both forms on read** (see `_verify.py`'s `_signature_uri_resolves`), so a
producer that reads 10.2.2 either way verifies here.

**Why we emit the form we emit, honestly.** The original reason recorded here was that
c2pa-rs emitted the same form. It does not, and that reason is withdrawn. What holds the
choice now is the wire-format rule: what we emit is a MAJOR version of this package and
of the vector file, so changing it costs a major bump and buys nothing measurable, since
both readers accept both forms. The manifest-relative form is also the shorter one and
does not repeat the manifest label. If 10.2.2 is ever clarified against us, that is the
version to change it in.

Not filed upstream: with both readers accepting both forms, the ambiguity costs nobody
anything.

## 22. Multiple exclusion ranges are rejected, not reported as informational

> 15.12.1.1 defines `assertion.dataHash.additionalExclusionsPresent` as an
> **informational** code, for a data hash assertion carrying exclusion ranges beyond
> the one covering the manifest store.

**We reject a hard binding naming anything other than exactly one range**, as
`assertion.dataHash.malformed`.

This is hardening, and it is specific to this carrier. A.8 places **one contiguous
wrapper** at one position, so a conforming A.8 producer has exactly one range to
declare; a second range is not a richer manifest, it is a region of text an attacker
has arranged for the hash not to cover. Accepting it and noting the fact
informationally would mean computing the binding over bytes chosen by whoever wrote
the assertion, which is the property the exclusion checks exist to deny.

The cost of being wrong here is bounded and visible: a conforming producer that
declared extra ranges would be rejected rather than silently mis-verified, and would
see `assertion.dataHash.malformed` naming the assertion at fault.

## 23. We reject an AI disclosure that discloses nothing, where the specification obliges no validator to

18.28.2 puts a `shall` on the **producer**:

> "The value of the `modelType` field is an enumeration of AI model types defined in
> Table 12, 'Model type values' and it shall be present in the ai-model-disclosure-map
> object."

15.10.3.2 gives a validator no `c2pa.ai-disclosure` rule at all — there is no subclause
for it, and no status code anywhere in the table for a malformed one. So a conforming
validator may read `c2pa.ai-disclosure = {}` and say nothing.

**We reject it, reported as `general.error`**, and we check it on **every** `__N`
instance (6.4), not only the base label.

This follows the deviation that made the assertion required in the first place. That one
already exceeded the specification, for a stated reason: this package exists under EU AI
Act Article 50(2) to carry the fact that a machine generated the text, and a mark that
omits the assertion carries nothing. Requiring the assertion and then accepting an empty
one would have kept the letter of that decision and lost its point.

`general.error` rather than a new code, because the specification defines it as "A value
to be used when there was an error not specifically listed here" and this error is not
listed anywhere. Inventing `assertion.aiDisclosure.malformed` would put a string in a
verdict that no clause authorizes, and a third party reading our output would have no way
to look it up.

**We check PRESENCE, not membership.** Table 12 is not a closed enumeration, so
"all twenty-four values are accepted on read" is not a mitigation. 18.28.4's CDDL — the schema
18.28.2 itself points at — extends the socket:

```
$model-type-choice /= tstr
```

so the twenty-four literals are a union with any text string, exactly as its sibling
`$asset-type-choice` is, under a rule the specification comments as "one of the listed
choices **or a custom value**". The membership test refused
`ai.duale.types.model.generative` — 6.2.2 entity-specific namespacing, which `signing.py`
itself notes the specification permits — along with any framework Table 12 predates.
`signing.MODEL_TYPES` keeps the twenty-four as the **producer's** vocabulary; the read
side accepts any non-empty string.

`scientificDomain` is not checked at all: 18.28.2 constrains it to the arXiv taxonomy,
which would mean vendoring that taxonomy, and nothing here resolves over the network.

## 24. We require `digitalSourceType` on a `c2pa.created` action, which the specification does put on us

Recorded not as a deviation but because it is easy to mistake for one. 18.15.2:

> "For all assets, a corresponding `digitalSourceType` field, with an appropriate value,
> **shall** be recorded with the `c2pa.created` action, to indicate the nature of the
> asset at its inception."

**Presence and type only.** The clause says "an appropriate value" and names just the
empty-content case explicitly; the vocabulary is IPTC's plus c2pa.org's, and demanding
membership of a list we vendor would reject a conforming producer using a term we have
not heard of.

**Presence is tested after 18.15.6.1's template overlay.** A template may supply
`digitalSourceType` for all actions (`"action": "*"`) or for one by name, and the
specification's own Example 9 does exactly that while the actions carry none. Reading the
action alone rejected that example.

`c2pa.opened` is exempt, by the clause's own next sentence: "No `digitalSourceType` field
is required in conjunction with a `c2pa.opened` action" — which is a note, not a
numbered rule, so we let a non-normative note narrow a `shall`. (Both the quotation
above and this note are 18.15.2.)

---

## 25. An inception action in a *gathered* actions assertion is not recognised

15.10.3.2.3 places the inception action in "the first actions assertion in the
created_assertions **or gathered_assertions** array (of a v2 claim)". We check
`created_assertions` only. A manifest whose inception action sits in its first
*gathered* actions assertion is therefore rejected with `assertion.action.malformed` —
twice over, since the gathered one is not examined and the first *created* actions
assertion then fails the position test.

The clauses genuinely disagree, and this is a choice between them rather than a reading
of one:

- 18.15.2 points the other way: "the actions array in the first `c2pa.actions`
  assertion in the created_assertions array … shall have a `c2pa.opened` action as its
  first element".
- The 2.4 change log is blunter: "Required that the mandatory actions assertion appear
  only in created_assertions (not gathered_assertions)."
- 15.10.3.2.3 is nonetheless the clause supplying the failure code we emit.

We follow 18.15.2 and the change log, because an inception action states what the
*producer of this manifest* did, and an assertion a producer merely gathered is another
party's statement carried along. `c2pa.created` is where `digitalSourceType =
trainedAlgorithmicMedia` lives; honouring a gathered one would let a manifest claim
machine origin on someone else's authority.

This is a false reject for any producer that follows 15.10.3.2.3 literally, and it is
worth filing upstream: two clauses and a change log cannot all three be satisfied.

---

## 26. A reference into a data box is passed over, not resolved

10.2.3.2: "Manifest Consumers SHOULD ALSO SUPPORT the data box approach recommended by
earlier versions of this specification." We do not implement data boxes, and 15.10.3.3
says a destination that "cannot be located" is `hashedURI.missing` — which rejects the
CLAIM.

So the literal reading turns declining a SHOULD into rejecting conforming manifests.
We treat `self#jumbf=c2pa.databoxes/<label>` the way the same clause already treats an
external `hashed_ext_uri`: a resource the validator chooses not to retrieve, passed
over rather than failed. Declining a SHOULD is legitimate; escalating that into a
rejection is not.

The pass-over is exactly as wide as the excuse. The tail must be non-empty, so
`self#jumbf=c2pa.databoxes/` — which names no destination — is still
`hashedURI.missing`, as is `c2pa.databoxesEVIL/x` and any assertion URI that fails to
resolve. Only the manifest-relative form is recognised; the store-relative form
(`self#jumbf=/c2pa/<manifest>/c2pa.databoxes/<label>`) still fails, which is a gap
rather than a decision, since 8.4.2.1 defines both and the specification's own example
uses the second.

A manifest whose generator icon lives in a data box therefore verifies here, with that
one reference unchecked, where a data-box-supporting validator would check it.

---

## 27. The CBOR reader accepts more than the writer emits

10.1 requires deterministic encoding (RFC 8949 4.2.1) and we enforce it on READ, which
is a security property general-purpose decoders do not offer: indefinite lengths,
non-shortest integers, non-shortest floats, a NaN encoded as anything but `f97e00`, and
out-of-order or duplicate map keys are all refused.

What the reader does NOT do is refuse well-formed CBOR merely because we would never
emit it. 15.10.3.1 rejects assertion content only when it "is NOT WELL-FORMED CBOR",
defined by RFC 8949 Appendix C, and any tag over any well-formed item is well-formed
there. So every tag is carried as an opaque `Tagged`, and floats are decoded — the CDDL
needs tag 37 for `instanceID` and floats for `coordinate-map` and `shape-map`.

`dumps` is unchanged and stays narrow: major types 0–5, three simple values, tags 0 and
18, no floats. What we EMIT is a wire commitment under CONTRIBUTING.md's versioning
rule;
what we ACCEPT is governed by the clause. Recognising a tag and accepting its bytes are
different questions, and only the second is the decoder's — whether a tag is permitted
in a given position is a CDDL question, answered by validation.

---

## 28. We REJECT a wrapper that is not a suffix of the text

Deviation 1 records that `embed` always PLACES the wrapper last. This is the other
half, and it is the consequential one: `_binding_status` rejects any manifest whose
exclusion range is not a suffix, so **we refuse marks a conforming producer could
emit**. A.8 does not require the wrapper to be last.

The reason is that the hard binding removes the wrapper *before* normalizing, so
composition runs across the removed gap. A canonically-equivalent respelling with a
code-point boundary at the declared start slides the wrapper into the middle of the
text and still matches. Demonstrated: `embed("ee" with acutes)` declares `start=4`, and
`"ée" + wrapper + "́"` also has a 4-byte prefix, so the mid-text wrapper bound and
verified VALID.

Canonical equivalence bounds the visible damage, so that is not content forgery by
itself — but it demolishes the invariant everything else rests on. A verifier reading
A.8.7.3's ordering computes DIFFERENT bytes for such a string and rejects it, so an
attacker could mint text we call VALID and a peer implementation calls INVALID, at
will. Requiring a suffix costs us nothing, since we only ever produce suffixes, and it
is what makes the two readings agree by construction.

The membership test and the suffix rule are **independently load-bearing**: without
membership an attacker chooses which bytes the hash covers; without the suffix rule the
respelling above passes. Neither rule subsumes the other: dropping the membership test survives the suffix
rule, and only `test_the_exclusion_must_name_a_located_wrapper_not_merely_be_trailing`
kills it.

---

## 29. Three smaller rules that are ours, not the specification's

Each needs a sentence rather than a section.

- **Self-signed is decided by issuer == subject**, which is strictly self-*issued*. A
  certificate issued under its own name by a different key would be treated as
  self-signed. It would then fail signature verification anyway, so the looser test
  costs nothing — but it is our test, not a clause's.
- **"External reference" means "carries an RFC 3986 scheme."** 15.10.3.3 scopes external
  work to "a hashed_ext_uri whose resource the validator chooses to retrieve" and draws
  no line; the scheme test is where we drew it.
- **`MAX_SELECTOR_RUN` and `MAX_JUMBF_DEPTH` are ours.** `constants.py` says "every
  bound below is ours" and only the `manifestLength` bound reached this document. The
  values are exported from the package so an operator can see them.

---

## Filing these upstream

A number of these are specification defects rather than choices, and are worth
reporting to the C2PA. **[upstream-filing.md](upstream-filing.md) is the authority for
which, and for what happens to each** — four are drafted as issues, fourteen are listed
inside issue 1. They are the input to that work, along with the
conformance vector file, which we offer as a starting point for A.8 interoperability
testing — the very thing A.8 says it is waiting on.
