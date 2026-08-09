# Deviations and ambiguity resolutions

Where C2PA 2.4 is ambiguous, self-contradictory, or silent, we had to choose. This
document records each choice and why.

All quotations are from **C2PA Technical Specification 2.4 (2026-04-01), HTML build
`c7e55d5a`**, re-checked against that build on 2026-08-05. See
[c2pa-compatibility.md](c2pa-compatibility.md) for why the claim cites a build hash.

The compatibility document carries the clause inventory; this one carries the
reasoning.

---

## Hash ordering

**15.12.1.3.1** (steps 5–7): remove the wrapper bytes per the exclusion range,
normalize the remainder to NFC, encode UTF-8, hash.

**A.8.7.3**: "perform normalization before calculating offsets."

These produce different bytes. **We follow 15.12.1.3.1**, because A.8.5 delegates to
it in so many words — "refer to the Validation clause for the normative procedure".
The validation procedure is the controlling rule; another producer's output is not.

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

## Multiple wrappers

| Clause | Says |
| --- | --- |
| A.8.2.1 | "Quantity: Zero or one" |
| A.8.4.1 | select the wrapper by matching the exclusions |
| A.8.7.1 | `manifest.text.multipleWrappers` — "More than one …" |
| 15.5.2.1 | plural manifest stores are all invalid |
| 15.12.1.3.1 | "If more than one wrapper **matches the exclusions**, reject with `manifest.text.multipleWrappers`" |

For validation we follow the exact procedure in 15.12.1.3.1. Each readable manifest
is compared with its wrapper's UTF-8 range. No match is
`assertion.dataHash.malformed`; more than one match is
`manifest.text.multipleWrappers`; one match selects that manifest. An unmatched second
wrapper does not replace the selected credential, but its bytes remain covered by the
selected manifest's data hash.

`extract()` has no binding-validation context with which to select a wrapper, so it
requires exactly one. `locate()` returns the first span for inspection and does not
claim which manifest is valid.

## Whether U+FEFF is inside the exclusion range

Undefined. A.8.2.2 defines the wrapper structure starting at `magic`; the U+FEFF that
precedes it is described in A.8.4.2 as the detection marker, and no clause says
whether the hash exclusion covers it.

**We include it.** If it were excluded, the marker would sit inside the hashed region
while being part of the mark rather than the visible content. The exclusion therefore
covers the complete marker-plus-wrapper sequence that validation removes.

## Endianness

A.8.2.2 gives `unsigned int(64) magic`, `unsigned int(8) version` and
`unsigned int(32) manifestLength` with no byte order.

**We use big-endian**, from ISO/IEC 14496-12's convention, which the JUMBF box
headers this format wraps already follow. The magic number resolves itself — it is
ASCII `C2PATXT\0`, so a little-endian writer would produce `\0TXTAP2C`, which is
visibly wrong. `manifestLength` is the field that genuinely needed a decision.

## The nonexistent wrapper algorithm field

> "…appears to be corrupted (invalid version, **algorithm**, or manifest length)"

A.8.2.2's syntax has exactly four members: `magic`, `version`, `manifestLength`,
`jumbfContainer`. There is no algorithm field in the wrapper.

**We treat it as a drafting error** and do not look for one. An unsupported hash
algorithm is reported as `algorithm.unsupported` from the assertion, where the
algorithm actually lives, not as `manifest.text.corruptedWrapper`.

## No status code for an absent wrapper

There is no code for "a U+FEFF was found but no wrapper followed", nor for "this is a
text asset with no wrapper at all".

**Neither is an error and neither gets a code.** Absence returns `UNMARKED` with an
empty code list. Most text ever written is unmarked; a library that reports a
failure code for it is one whose output gets ignored.

## Excluding the A.8 wrapper header

18.5.1 says exclusion ranges shall not cover an asset's header or length fields. A.8
requires the exclusion to cover the entire wrapper, header and `manifestLength`
included.

**The specific A.8 rule controls this carrier.** The alternative — excluding only
`jumbfContainer` — would leave
13 bytes of attacker-controlled header inside the hashed region while the length
field that describes them sits outside it.

## Size-control padding

A.8 adds no padding field to the selector wrapper, but the core manifest procedure
already defines one. 10.4.2 requires the temporary `COSE_Sign1` unprotected map to
carry the string label `pad` with a zero-filled byte string. 10.4.4 then permits that
field to shrink after signing because it is not part of `Sig_structure`.

RFC 9052 excludes the unprotected map from `Sig_structure`, so changing `pad` does not
alter the signature. C2PA applies that property by shrinking a preallocated pad. This
producer instead starts at zero and grows the zero-filled pad during a bounded search.
For each candidate exclusion length it signs once, then varies only that unprotected
field while measuring the A.8 wrapper. If a CBOR size jump makes one declared length
unreachable, it signs the next candidate. This direction is an implementation-specific
use of the same COSE property, pending clarification in C2PA.

The separate 18.5.2 data-hash `pad` remains mandatory and zero-filled. It is empty in
our output because we build the final assertion before signing rather than patching a
preallocated assertion box. We do not need its optional `pad2`.

## Update-manifest offset arithmetic

15.12.1.1 describes adjusting offsets when a manifest is replaced. The arithmetic
assumes a linear relationship between manifest bytes and asset bytes. For a selector
run there is none: the UTF-8 length of the encoded wrapper depends on the *values* of
the manifest bytes, not only their count.

**We do not emit or validate update manifests.** The reader recognizes `c2um` while
selecting the last C2PA Manifest and rejects it explicitly if it is active, so it never
falls back silently to an older Standard Manifest.

## Media type

A.8 is the unstructured-text carrier. The API accepts an unparameterized C2PA format
string beginning with `text/`, but rejects `text/html` and `text/markdown`, whose
carriers are defined by A.7 and A.9. The caller remains responsible for choosing the
right carrier for other structured text formats.

## "Rejected" versus "Valid but not Trusted"

15.7 describes an untrusted signing credential as grounds for rejection. 14.3.5
defines a *Valid* manifest **without** requiring `signingCredential.trusted`, and
14.3.6 adds trust as a separate, higher state.

**We follow 14.3.5/14.3.6**: `signingCredential.untrusted` yields `VALID`, not
`INVALID`. Under the other reading, a correct, intact, honestly-signed self-signed
mark reads as forged — which would make every mark this package produces, out of the
box, indistinguishable from a forgery. A profile *violation* is different and does
hard-reject; see `src/c2patxt/trust.py`.

## `scientificDomain`

The CDDL declares a list; the specification's own prose example shows a bare string
(`"cs.AI"`). The ambiguity is real.

**We do not emit the field and we do not read it,** so the ambiguity does not reach
us. 18.28.2 makes it optional — "If present, the value of the `scientificDomain` field
shall conform to the arXiv taxonomy" — and we hold no reliable signal for it. A
guessed value inside a signed assertion is worse than its absence.

## `manifest.text.*` codes are absent from the normative CDDL enum

The `$status-code` socket in 15.2.1 declares its codes as a CDDL group. Verified on
2026-08-05, reading the socket in build `c7e55d5a`: **none** of them is `manifest.text.corruptedWrapper` or
`manifest.text.multipleWrappers`, though both are defined in prose at A.8.7.1 and
15.12.1.3.3 and used normatively at 15.12.1.3.1.

**We emit them.** They are the only codes A.8 defines for its own failures,
and a validator that reported something else would be less interoperable, not more.
A strict CDDL validator will reject our status output; that is a specification bug,
prepared for filing in [upstream-filing.md](upstream-filing.md) but not yet filed.

## A.8.4.2 detection hazards

The detection algorithm is described in prose and leaves four cases open. Our
resolutions, each with a test in `tests/test_negative.py`:

| Hazard | Resolution |
| --- | --- |
| Leading UTF-8 BOM | Not a mark. Every Windows-authored text file starts with one. |
| Fewer than 8 selectors | Not a mark, not corruption. Too short to spell the magic. |
| Adjacent user variation selectors (emoji) | Not a mark. U+FE0F is everywhere in ordinary text. |
| Unbounded `manifestLength` | Rejected against `MAX_MANIFEST_LENGTH` before the payload is accepted. |

The governing principle: a non-matching run must never prevent a genuine wrapper
elsewhere in the text from being found. Otherwise anyone able to prepend text — a
mail client adding a quoted header, a CMS adding a byline — could make a marked
document read as `UNMARKED`, which invites no investigation at all.

## `locate()` reports as-stored offsets

`locate()` returns offsets into the **as-stored** encoding of the string the caller
handed us, and the field names say so: `Span.utf8_start`, `Span.utf8_stop`, not
`nfc_utf8_start`.

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

## The v1 `c2pa.claim` label

> "Validators **should** still accept this label (and associated claim-map)."

**We accept `c2pa.claim.v2` only.** A `should`, so declining is legitimate — but the
reason matters more than the modal verb. `claim-map` v1 is not the same map under an
older name: `claim_generator_info` is an **array** of generator-info-maps where v2 has
a single map, `dc:format` and `dc:title` are present, and `assertions` replaces
`created_assertions` / `gathered_assertions`.

Accepting it requires a second claim model through 15.6.2's required fields, 15.4's
algorithm resolution, 15.10.3.1's link walk, and 15.6.2's icon reference. That model
is outside this package's validator scope.

A v1 claim reads as `claim.missing`, because the box we look for is not there.

## The `signature` URI

> 10.2.2: the `signature` field "shall contain an absolute URI reference".

**We emit `self#jumbf=c2pa.signature`**, which 8.4.2.1 calls "relative to the current
C2PA Manifest".

The two clauses read against each other. 8.4.2.1 defines exactly two forms for a
`self#jumbf` URI — manifest-relative and store-relative — and both are *relative* in
the ordinary sense; "absolute URI reference" in 10.2.2 most plausibly means the
store-relative form, which is absolute *within the manifest store*, but the
specification does not say so.

**We ACCEPT both forms on read** (see `_verify.py`'s `_signature_uri_resolves`), so a
producer that reads 10.2.2 either way verifies here.

**Why we emit the form we emit.** What holds the choice is the wire-format rule: what
we emit is a MAJOR version of this package and of the vector file, so changing it costs
a major bump while both forms already verify here. The manifest-relative form is also
shorter and does not repeat the manifest label. If 10.2.2 is clarified against us,
that is the version to change it in.

Not filed upstream: accepting both specified forms contains the ambiguity locally.

## References into data boxes

10.2.3.2 says Manifest Consumers should support the data-box approach used by older
specification versions. This package does not parse data boxes. Under 15.10.3.3, a
local `hashed_uri` destination that cannot be located reports `hashedURI.missing`; a
data-box reference therefore invalidates the manifest here. External
`hashed_ext_uri` retrieval remains optional and is a separate branch.

---

## Claim and assertion CBOR accepts more than the writer emits

10.1 requires deterministic encoding (RFC 8949 4.2.1) for claims, and 18.1 applies it
to assertions. The writer and its wire test enforce that rule. The validation rules in
15.6.2 and 15.10.3.1 are narrower: they reject content that is not **well-formed CBOR**,
as RFC 8949 Appendix C defines it. The reader therefore accepts indefinite lengths,
non-shortest encodings and out-of-order map keys in claims and assertions, while
authenticating their received bytes rather than a re-encoding. It still rejects
duplicate map keys: RFC 8949 calls those invalid and their decoded meaning is ambiguous.

RFC 9052 likewise does not impose deterministic encoding on the transported outer COSE
message or its protected header. Those containers use the same well-formed-input mode
with duplicate-key rejection.

What the reader does NOT do is refuse well-formed CBOR merely because we would never
emit it. 15.10.3.1 rejects assertion content only when it "is NOT WELL-FORMED CBOR",
defined by RFC 8949 Appendix C, and any tag over any well-formed item is well-formed
there. So every tag is carried as an opaque `Tagged`, floats are decoded, and every map
key type is retained. The CDDL needs tag 37 for `instanceID`, floats for
`coordinate-map` and `shape-map`, and 18.3.3 lets custom assertion metadata contain
arbitrary CBOR values.

`dumps` stays narrow: major types 0–5, three simple values, tags 0 and 18, no floats.
What we emit is a wire commitment under CONTRIBUTING.md's versioning rule; what we
accept is governed by the validation clause. Recognising a tag and accepting its bytes
are different questions. The later validation steps enforce the fields and types that
the named C2PA validation clauses require; this package has no general CDDL validator.

---

## Two implementation rules outside the specification

Each needs a sentence rather than a section.

- **"External reference" means "carries an RFC 3986 scheme."** 15.10.3.3 scopes external
  work to "a hashed_ext_uri whose resource the validator chooses to retrieve" and draws
  no line; the scheme test is where we drew it.
- **The resource bounds are ours.** `MAX_SELECTOR_RUN` and `MAX_CBOR_DEPTH` bound
  structural parsing. `MAX_NONSTARTERS=30` adopts [Unicode UAX #15 D3's Stream-Safe
  Text Format boundary](https://www.unicode.org/reports/tr15/#Stream_Safe_Text_Format)
  before the NFC operation C2PA requires. We reject a longer sequence instead of
  applying D4's U+034F insertion, because UAX #15 states that the insertion can break
  canonical equivalence. The values are exported so a caller can inspect the policy.
  The normalization bound remains while supported CPython releases can use the
  quadratic canonical-ordering path fixed by
  [CPython #149080](https://github.com/python/cpython/pull/149080). Removing it is
  planned only after the package's Python floor excludes every unfixed patch release.

---

## Filing these upstream

Open specification questions and their reproducible cases are recorded in
[upstream-filing.md](upstream-filing.md).
