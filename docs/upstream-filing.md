# Upstream filing — drafted, not sent

Four defects in C2PA 2.4 Annex A.8 that cause **silent divergence**: two conforming
implementations produce different bytes and neither is wrong. They are drafted here in
full and ready to send.

> **NOT YET FILED.** Posting public issues on a specification repository is an
> outward-facing act on behalf of Duale AI, so it needs a person to press send. The
> exact command for each is given below. The other **fourteen** ambiguities we found
> are deliberately *not* separate issues — filing eighteen issues against an annex
> maintained by a small task force is noise, and noise gets ignored. They are listed
> once, as a list, inside issue 1.

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
procedure — but the contradictory sentence is unretracted and has survived from 2.3's
A.7 through all eleven published 2.4 builds.

**Likely cause, offered as a lead:** A.8.7.2 and A.8.7.3 carry `shall` requirements
while nested under a heading titled *"Validation Status Codes"*. Normative text
mis-filed under a status-code heading is easy to miss in review, which would explain
why it survived.

**Suggested fix:** delete the sentence from A.8.7.3, or replace it with an explicit
cross-reference to 15.12.1.3.1.

Fourteen further ambiguities we resolved locally, listed here rather than filed
separately, with their [deviation](deviations.md) numbers: 18.5.1 forbidding what A.8
requires of exclusion ranges (7); A.8 defining no padding mechanism while `pad` is
mandatory in `data-hash-map` (8); 15.12.1.3.2 naming a wrapper `algorithm` field A.8.2.2
does not define (5); no status code for "detected but absent" (6); undefined update-manifest
offset arithmetic for a non-linear selector run (9); A.8 assigning no media type (10);
`scientificDomain` declared as a list in CDDL and shown as a bare string in the
example (13); `manifest.text.*` absent from the normative `$status-code` enum (14); no Ed25519
SPKI constraint in the certificate profile (11); "Rejected" (15.7) versus "Valid but not
Trusted" (14.3.5/14.3.6) for `signingCredential.untrusted` (12); the unresolved
`[_embedding_manifests_into_html]` cross-reference at A.1 and A.9.2 (16); an inception
action in a *gathered* actions assertion, where two clauses and a change log cannot all
three be satisfied (25); a reference into a data box, which 10.2.3.2 makes a SHOULD we
decline (26); and no status code for a manifest store that fails to parse at all,
recorded in [open-questions.md](open-questions.md).

**U+FEFF is not on this list**, because it is Issue 3 above. It was on both, which made
the count wrong twice over — filed and explicitly not filed in the same document.

---

## Issue 2 — A.8.2.2 never states endianness

**Title:** `A.8.2.2 does not state the byte order of magic and manifestLength`

A.8.2.2 declares `unsigned int(64) magic`, `unsigned int(8) version` and
`unsigned int(32) manifestLength` in ISO-BMFF class syntax with no byte order stated
anywhere in the clause or its prose.

This appears to be the only place in the specification that omits it — clause 11,
clause 18.6 and A.3.x all state it explicitly.

The magic number resolves itself in practice, since a little-endian writer produces a
visibly wrong `\0TXTAP2C`. **`manifestLength` does not**, and a disagreement there is
a silent interop failure rather than a visible one.

Both public implementations use big-endian (`struct.Struct("!8sBI")`;
`len.to_be_bytes()`), so the fix is to write down what everyone already does.

**Suggested fix:** add "All multi-byte fields are big-endian." to A.8.2.3.

---

## Issue 3 — Is U+FEFF inside the exclusion range?

**Title:** `A.8 does not say whether the U+FEFF marker is inside the hash exclusion range`

A.8.2.2 defines the wrapper structure beginning at `magic`. A.8.4.2 describes the
preceding U+FEFF as the detection marker. No clause states whether the `c2pa.hash.data`
exclusion covers it.

The two readings differ by exactly 3 UTF-8 bytes. Two otherwise-correct implementations
that choose differently will fail to verify each other's marks, with no diagnostic
that points at the cause — the hash simply does not match.

Both public implementations include it. **Suggested fix:** state it in A.8.5,
whichever way the task force prefers; the value of the answer is entirely in its
existence.

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

---

## Offering the vectors

We publish a wire-format conformance vector file — `A8ConformanceTest-1.1.0.txt`, 26
records, CC0 — because the C2PA text conformance rubric v0.1.0 has none. Format
modelled on `NormalizationTest.txt`: ASCII-only data, one record per line, semicolon
separated, `#` comments.

Offered **once**, to C2PA or to C2SP under the CCTV model (*"All cryptography-related
test vectors are welcome… projects are encouraged to reuse them and contribute back"*).
If there is no uptake we keep it in-repo and move on.

## Commands to send

```console
$ gh issue create --repo c2pa-org/specifications \
    --title "A.8.7.3 contradicts 15.12.1.3.1 on normalization order, producing different hashes" \
    --body-file <(sed -n '/^## Issue 1/,/^---$/p' docs/upstream-filing.md)
```

…and the same for issues 2–4. Read each body before sending; these are public and
attributed to Duale AI.

## What we deliberately do not do

No coordinated engagement programme with the other implementations, no direct query to
CAWG (its specification index is [already conclusive](open-questions.md)), and no
scheduled tracking of `c2pa-rs` PR #2117. Instead we cross-validate against their
published vectors in CI and open an issue only on a genuine disagreement.
**Byte-for-byte agreement is a better contribution than correspondence.**

Worth knowing, not worth a task: `c2pa-rs` PR #2117 (TextIO behind a non-default
`plain_text` feature, depending on the encypher `c2pa-text` crate) has been open since
2026-05-05 with no maintainer merge in roughly three months. If it lands, the reference
implementation gains A.8 support and our conformance target gains a second authority.
Check it next time we touch conformance, not on a schedule.
