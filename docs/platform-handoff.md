# Handoff to the platform side

Four things found while building this package that do **not** belong in it, and will
be lost if nobody writes them down. Owner: whoever owns the monorepo and RFC-136.

**Internal correspondence.** RFC-136 is not in this repository and this document
corrects it, so it reads as a letter rather than as reference. It is kept here because
the findings are about this package's subject matter; an outside reader should treat
it as background, not as documentation of what c2patxt does.

Nothing here blocks this package. Everything here blocks something else.

---

## 1. RFC-136 corrections

Six factual updates, each verified rather than inferred.

**§7 — "2.4 has no release tag or PDF" is half wrong.** The *tag* claim is true (tags
are 2.3, 1.3, v1.0 only). The *PDF* claim is false: the 2.4 PDF is live at
`spec.c2pa.org/.../2.4/specs/_attachments/C2PA_Specification.pdf` — HTTP 200,
8,139,117 bytes, last modified 2026-04-23, page 1 reads "2.4, 2026-04-01". It is
merely absent from the site's Download navigation.

**§10 size table is pessimistic.** Measured, Ed25519, self-signed:

| Configuration | Manifest store | Marked text | Inflation |
| --- | ---: | ---: | ---: |
| Single certificate | 1,797 B | 7,001 B UTF-8 | 3.896 |
| Leaf + CA | 2,120 B | 8,218 B UTF-8 | 3.876 |

Re-measured 2026-08-05 against the shipped code, **under the test suite's pinned
`EmbedContext`** — a fixed manifest UUID, `instance_id="xmp:iid:pinned"` and a fixed
timestamp. That condition is what makes these reproducible, and it is not what a real
caller gets: a default context mints an `xmp:iid:<uuid>` 31 characters longer and a
timestamp with microseconds, measuring about **7,155 B of marked text** for the single-
certificate row rather than 7,001. Size a column or a quota from the larger figure.

**These are larger than the figures
first reported** (1,192 → 4,583 and 1,556 → 5,949). Two changes account for the growth:
the manifest gained a `c2pa.metadata` assertion carrying `dc:format`, required by the
C2PA text conformance rubric's `text:is_text_asset` check, and then a `specVersion`
key in `claim_generator_info` (10.2.3.2), worth about 31 bytes of store and 129 bytes
of marked text. Each earlier number was correct when taken and was not re-measured
after the change that invalidated it; recorded here so the same mistake is not
inherited a third time.

UTF-8 inflation measured **3.88–3.90**, not 3.94 — 3.9375 is the theoretical worst
case, not the observed one. Character count is exactly `manifest_bytes + 14`. The
"4–8 KB manifest / 16–31 KB on a 1,200-character response" figures should still come
down, but by less than first thought.

**§7 — drop the absolute phrasing on media types.** "All 152 conforming products, none
declares a text media type": 152 and spec-2.2-only are both exactly right, but *one*
product (Digitality Consulting Secure Content Engine) declares a bare `txt` token under
the `document` group for both generate and validate. It is not a valid IANA media type
and not in the rubric's text list, so the conclusion stands — but "none" does not.

**§11 verification contract — category 7 cannot live in the codec package.** See item 3.

**A.8 stability, precisely.** The "remains under review" paragraph was *added* on
2026-04-01, commit `666bdf8f`, and is the **only** change to A.8 across all eleven
published 2.4 builds. Clause 15.12.1.3 never changed. Normalising clause numbers,
2.4's A.8 is byte-identical to 2.3's A.7 apart from that paragraph.

**§4 CONTRADICTS ITSELF, and the numbered steps are the correct half.** Steps 3–5 say
*remove the wrapper's byte range, then normalize to NFC, then encode* — which is
15.12.1.3.1 and is right. The paragraph immediately after says *"Offsets are byte
offsets in the NFC-normalized UTF-8 encoding, computed after normalization"* and cites
**A.8.7.3** — which is the clause we established is wrong, and which contradicts the
steps directly above it. Anyone reading only that paragraph implements the inverted
order. Fix the paragraph; keep the steps.

**§4's hash-binding order is CORRECT and must not be "fixed".** It matches
15.12.1.3.1, which A.8.5 designates as the normative procedure. A.8.7.3 contradicts it
and loses. Both public implementations chose the RFC's ordering. **Add a footnote
recording the contradiction**, or someone will helpfully correct it later — this was
very nearly changed here on the strength of A.8.7.3 alone.

---

## 2. The Terraform signing credential will fail the C2PA profile

RFC-136's Custody section specifies `tls_private_key` with algorithm `ED25519` plus
`tls_self_signed_cert`. **A default self-signed certificate asserts `cA` and carries no
EKU.** C2PA 14.5.1.1 requires, for a claim-signing certificate:

- `cA` **not** asserted
- `keyCertSign` **not** asserted
- EKU present and **non-empty**
- `anyExtendedKeyUsage` (2.5.29.37.0) **absent**

**14.5.1.1 requires no particular EKU OID**, and an earlier version of this document said
14.4.1 required `c2pa-kp-claimSigning` (`1.3.6.1.4.1.62558.2.1`). It does not: 14.4.1 is
addressed to *validators*, about which trust anchors they associate with which EKUs, and
it explicitly anticipates `id-kp-emailProtection` and `id-kp-documentSigning` — the pair
previous versions of the specification required. **Include `c2pa-kp-claimSigning`
anyway**: 14.5.1.2 lets a validator accept only credentials bearing an EKU it holds
anchors for, so the OID is what a C2PA-aware trust store will look for. It is a
compatibility choice, not a profile requirement, and adding one of the older pair
alongside it improves compatibility with pre-2.2 validators.

Get the rules that ARE in 14.5.1.1 wrong and validators return
`signingCredential.invalid` — a **hard reject** where the manifest is not even *Valid* —
instead of the expected `signingCredential.untrusted`. Those two outcomes look similar in
a status list and are not remotely the same thing.

Two details worth carrying:

- **AKI** is required on any certificate that is *not* self-signed, so a self-signed
  root is exempt from that one.
- **Root validity 20–25 years**, matching every CA on the C2PA trust list (Google 2050,
  DigiCert 2050, SSL.com 2050, vivo 2055).

**Partially mitigated here already:** `Signer.__post_init__` applies the same 14.5.1.1
profile check the verifier does, so a non-conformant credential now fails at *signing
time* rather than silently producing marks that every consumer rejects. The Terraform
still needs fixing — this only moves the discovery earlier.

`c2patxt` exports `C2PA_CLAIM_SIGNING_EKU`, and the README carries a complete
conformant certificate builder.

---

## 3. The scope-rule conformance test goes in the router suite

Memo §6 category 7 asserts the `ResponseFormat → marked` mapping *against the imported
enum*, so that adding a format without deciding its marking status fails the build.
That requires importing `duale_models`, which this package's leaf rule forbids
absolutely — **no `duale_*` package, ever**, because the whole compliance argument
rests on a third party being able to install and run it.

The rule lives in `output_publisher.py`; **the test lives next to it** and imports
`ResponseFormat` there. Decision already taken; recorded so it is not silently dropped.

Related, for the router: the **C2PA text conformance rubric v0.1.0** — not the
specification — is the only authority partitioning media types.

The partition is tabulated in
[c2pa-compatibility.md](c2pa-compatibility.md), once. RFC-136 §2 already documents
marking markdown under A.8 as a deliberate deviation, so we are ahead of it — but
**cite the rubric as the source of the partition, not the specification**, because A.8
names no media type at all.

---

## 4. CRA organisation-level obligations — deadline 11 September 2026

Chapter IV of Regulation (EU) 2024/2847 has been in force since **11 June 2026**.
Outstanding at the organisation level, not the repository level:

- **Article 24(1)**: a documented, verifiable cybersecurity policy. This repository's
  [SECURITY.md](../SECURITY.md) is written to serve as that artefact for `c2patxt`;
  the organisation needs the equivalent.
- A **published security contact**. Done for this package (`security@duale.ai`).
- **EU Login access to ENISA's Single Reporting Platform** — which is itself only
  "scheduled to be operational by" that date, so start the access request rather than
  waiting for the platform.

We are an open-source **steward** under Article 24, not a manufacturer. The distinction
matters and the basis is recorded in [SECURITY.md](../SECURITY.md).
