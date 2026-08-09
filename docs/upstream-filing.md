# Four ambiguities in Annex A.8

Four ambiguities in C2PA 2.4 Annex A.8 that permit different wire interpretations.
Each is written here in issue-ready form.

**Not yet filed.** Posting public issues on a specification repository is an
outward-facing act on behalf of Duale AI, so a maintainer must approve it.

Target: `c2pa-org/specifications`. All quotations are from 2.4 build `c7e55d5a`.

---

## Issue 1 — A.8.7.3 contradicts 15.12.1.3.1 on the hash ordering

**Title:** `A.8.7.3 contradicts 15.12.1.3.1 on normalization order, producing different hashes`

A.8.7.3 says *"perform normalization before calculating offsets"*. 15.12.1.3.1 steps
5–7 remove the wrapper bytes **first**, then normalize to NFC, then encode and hash.
The two produce different bytes whenever the wrapper is not a suffix, because U+FEFF
is a starter and blocks composition across itself.

Computed from the Unicode Character Database:

| Text | Remove first | Normalize first |
| --- | --- | --- |
| `a` + wrapper + U+0301 | `c3 a1` | `61 cc 81` |
| U+1100 + wrapper + U+1161 | `ea b0 80` | `e1 84 80 e1 85 a1` |
| `A` + wrapper + U+030A | `c3 85` | `41 cc 8a` |

It is resolvable — A.8.5 delegates to the Validation clause for the normative
procedure — but the contradictory sentence remains in the reviewed 2.4 build.

**Suggested fix:** delete the sentence from A.8.7.3, or replace it with an explicit
cross-reference to 15.12.1.3.1.

Related implementation choices and unresolved status-code questions are recorded by
section title in [deviations.md](deviations.md) and
[open-questions.md](open-questions.md). Those documents, not numeric issue shorthand,
are the maintained inventory.

**U+FEFF is not on this list**, because it is Issue 3 below.

---

## Issue 2 — A.8.2.2 never states endianness

**Title:** `A.8.2.2 does not state the byte order of magic and manifestLength`

A.8.2.2 declares `unsigned int(64) magic`, `unsigned int(8) version` and
`unsigned int(32) manifestLength` in ISO-BMFF class syntax with no byte order stated
anywhere in the clause or its prose.

The magic number resolves itself in practice, since a little-endian writer produces a
visibly wrong `\0TXTAP2C`. **`manifestLength` does not**, and a disagreement there is
a silent interop failure rather than a visible one.

The ISO BMFF/JUMBF box structures surrounding this field use big-endian fields. The
local literal A.8 fixture applies that same byte order.

**Suggested fix:** add "All multi-byte fields are big-endian." to A.8.2.2.

---

## Issue 3 — Is U+FEFF inside the exclusion range?

**Title:** `A.8 does not say whether the U+FEFF marker is inside the hash exclusion range`

A.8.2.2 defines the wrapper structure beginning at `magic`. A.8.4.2 describes the
preceding U+FEFF as the detection marker. No clause states whether the `c2pa.hash.data`
exclusion covers it.

The two readings differ by exactly 3 UTF-8 bytes. A producer and validator that choose
differently will report a hash mismatch with no diagnostic that identifies this
choice. **Suggested fix:** state the required boundary in A.8.5.

---

## Issue 4 — Four incompatible statements about multiple wrappers

**Title:** `Four clauses give incompatible rules for text containing more than one wrapper`

| Clause | Says |
| --- | --- |
| A.8.2.1 | "Quantity: Zero or one" |
| A.8.4.1 | select the wrapper by matching the exclusions |
| A.8.7.1 | `manifest.text.multipleWrappers` — "More than one …" |
| 15.5.2.1 | plural manifest stores are all invalid |
| 15.12.1.3.1 | "If more than one wrapper **matches the exclusions**, reject with `manifest.text.multipleWrappers`" |

The last is materially narrower than the rest: it makes plurality a failure only among
wrappers that *match the exclusion range*, which permits an attacker to append a second
wrapper that does not match and have it ignored.

This is a security-relevant ambiguity, not only an editorial one: a permissive
implementation and a strict one disagree about whether an attacker-appended wrapper
invalidates a document.

**Suggested fix:** state one rule in A.8.2.1 and have the other clauses reference it.
