# Known divergences from other implementations

Where we deliberately **disagree** with another implementation, and why. Each case has
a test in `tests/test_divergences.py` carrying the same reasoning, so the test cannot
be weakened without someone reading what it protects.

Agreement is checked separately, in `tests/test_third_party_interop.py`.

---

## 1. c2pa-rs requires two toggle bits where ISO requires one

`boxes.rs:2085` requires `(togs & 0x03) == 0x03` before reading a label. ISO 19566-5
gates the label on bit `0x02` alone; `0x01` is *Requestable*, an unrelated property.
**c2pa-rs therefore fails on a legal box with `toggles=0x02`.**

Five independent implementations test `0x02` on its own — MIPAMS, ExifTool, thorfdbg,
iLEAPP, exifmodern — each locatable by name and checkable against their source. That
survey is the evidence for this item.

A byte-level parse of a real asset, `image_5jumbf.jpg` APP11 #1, also showed a
`toggles=0x02` box labelled `faiz mp3 data`. **That observation is not reproducible
here**: the file is not vendored, we can no longer establish which corpus it came from,
and nothing in the suite touches it. Recorded as an observation rather than as evidence,
because the divergence stands on the five implementations without it.

SVTA made the same mistake independently. Two implementations converging on a wrong
reading is how a wrong reading becomes the standard. Hence a test, not a comment.

**We read the label on `0x02` alone.**

## 2. faceless2/c2pa uses a 2-byte box ID

It reads and writes the `jumd` ID as **2 bytes** and clamps anything above 65535.
Every other implementation surveyed uses 4 bytes big-endian, and MIPAMS states it
outright as
`INT_BYTE_SIZE = 4`.

**We use 4 bytes.** The discriminating test value is one above the 16-bit ceiling: a
2-byte reader either truncates it or refuses it.

## 3. WG1 reference implementation 2 disagrees with itself

`db_jumbf_desc_box.cpp` `deserialize()` reads **256 bytes** for the signature field,
while its own `serialize()` writes **32** and `set_box_size()` adds 32. The reader and
the writer of the same file disagree.

32 is correct: the field is a SHA-256, and the WG1 conformance dataset is
byte-identical to its own `sha256.obj` files at 32.

**We require exactly 32** and reject anything else at construction.

## 4. Three AI-authored repositories shift the toggle assignment by one bit

Apertrue/c2pa-extractor, ob192/ai-media-detection-tool and
encypherai/c2pa-conformance-suite all encode `0x01`=label, `0x02`=ID — one bit down
from the real assignment. (richardwooding/c2pa and 0verkilll/jpeg get it right.)

The bug survives because C2PA itself always writes `toggles=0x03`, so the common case
works under either reading and no round-trip test catches it. The discriminating case
is a box with `0x04` **alone**: it carries an ID and no label. Under the wrong
assignment it reads as a label, and the four ID bytes get consumed as NUL-terminated
text.

**We use the assignment `0x01` Requestable, `0x02` Label, `0x04` ID, `0x08` Signature,
`0x10` Private**, sourced in two halves. Bits 0-3 are JPEG WG1's JLINK WD 3.0, Table
A.2, which reserves everything above bit 3. Bit 4 is C2PA 11.1.4.1.2, which writes the
toggles as masks and gives Private as `xxx1xxxx` — the same notation it uses for Label
(`xxxxxx1x`) and Requestable (`xxxxxx11`). That clause is the only primary source we
can reach for bit 4; ISO/IEC 19566-5:2023's Foreword independently records a "new
Private entry in the JUMBF Description Box", but its Annex A.3 is paywalled.

Note what 11.1.4.1.2 does **not** give: ID and Signature. Those two rest on JLINK and
on the four implementations surveyed in `_jumbf.py`, which is why this document records
where three repositories got them wrong.

## 5. encypherai/c2pa-conformance-suite: three divergences

- It hashes the raw bytes minus the exclusion with **no NFC normalization**, which
  A.8.6.1 requires. See deviation 1 in [deviations.md](deviations.md).
- It maps "zero wrappers found" to `manifest.text.corruptedWrapper`, where
  15.12.1.3.1 step 3 says `assertion.dataHash.malformed`.
- It takes a wrapper's end as "the start of the next wrapper, or EOF" rather than the
  declared `manifestLength` — so appending a second wrapper changes where it thinks
  the first one ends.

**We normalize, we report `assertion.dataHash.malformed`, and we bound the wrapper by
its declared length.**

## 6. c2pa-rs box types have drifted from the specification

`cais`, `cain` and `c2vc` are c2pa-rs legacy types **absent from the C2PA
specification entirely**. `c2db` is in the specification but deprecated. `c2tm` and
`c2md` are in the specification but **missing from c2pa-rs**.

**We emit none of the legacy set**, and we tolerate `c2tm` / `c2md` on read via the
11.1.2 unknown-UUID skip rule. Rejecting a box a conforming producer may legitimately
emit would make us the implementation that breaks on valid input — the same defect
class as everything above, pointed at ourselves.

## 7. Where we are STRICTER than everyone

C2PA 11.1.4.1.1 forbids these characters in a label: U+0000–001F, U+007F–009F,
`/ ; ? #`, plus U+FEFF, U+FFFF and the surrogate range. **Of the implementations
surveyed in this document, none enforces it.** We do.

Labels become JUMBF URI path components, so an unescaped `/` or `#` in a label is a
URI-injection primitive against any consumer that resolves `self#jumbf=` references by
string manipulation — which is how they are resolved.

The one character we deliberately do **not** forbid is `:`. faceless2/c2pa re-allows
it after copying a forbidden-character list, and its own commented-out "official list
from ISO19566" line includes it — the closest thing to a published quote of the ISO
text we have found. But C2PA's own manifest labels are `urn:c2pa:…` (8.1), so forbidding `:`
would leave the specification unable to express its own required labels. C2PA
11.1.4.1.1 governs.

## 8. Padding for the two-pass search goes in three different places

A.8 defines no padding mechanism at all: the wrapper structure has no pad field, and
nothing says how a producer that must hit an exact length reserves space. Each
implementation answered differently, and only one of the three answers puts the slack
inside the signature.

- **encypherai/c2pa-text pads the selector run.** `encode_wrapper_padded` appends extra
  VS-encoded bytes after the JUMBF container and relies on `manifestLength` to tell a
  decoder where the manifest ends. Its own changelog calls this "deterministic padding"
  and pairs it with `worst_case_wrapper_byte_length()`, `3 + (13 + M) * 4 + 6`.
- **writerslogic/c2pa-text-binding does not pad.** `soft_binding.rs` declares
  `pub pad: Vec<u8>` and leaves it empty — "kept empty. Present to match the reference
  writer."
- **We put the padding in `pad`**, the field 18.5.2 makes mandatory and 10.4 designates
  for slack bytes, which puts it inside the signed claim.

Nothing here breaks interoperability on read: `manifestLength` bounds the manifest, and
validators are told to ignore `pad`. It is recorded because padding outside the
signature is attacker-malleable space in a provenance format, and because the reasoning
for our choice is not recoverable from the code. See deviation 8 in
[deviations.md](deviations.md) for the clause argument.

---

## Filing these

Items 1 to 5 are implementation bugs, not specification defects, and belong
upstream with their maintainers rather than with the C2PA. Item 6 is drift worth
raising with c2pa-rs. Item 7 is a gap in every implementation surveyed here, and is
worth raising as a conformance-suite item. Item 8 is a gap in the specification rather
than in anyone's implementation, and belongs with the C2PA — it is deviation 8 in
[deviations.md](deviations.md).
