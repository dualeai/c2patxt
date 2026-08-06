# c2patxt

Embed, extract and verify C2PA Content Credentials in plain Unicode text.

Implements **C2PA Technical Specification 2.4 (2026-04-01), HTML build `c7e55d5a`,
Annex A.8 "Embedding Manifests into Unstructured Text"** — a manifest store encoded as
Unicode variation selectors, appended after the visible text. Marked text renders
exactly as the original: the mark is zero-width.

This is Duale AI's implementation of C2PA text marking. It is **not** a C2PA
consortium release and carries no conformance certification.

```console
$ pip install c2patxt
```

Python 3.10+. One runtime dependency: `cryptography`.

Or from a checkout:

```console
$ git clone https://github.com/dualeai/c2patxt && cd c2patxt
$ make install
```

**[Five minutes](#five-minutes)** — working code, and the certificate rules people get
wrong · **[Why this exists](#why-this-exists)** — the AI Act obligation ·
**[What this proves](#what-this-proves-and-what-it-does-not)** ·
**[Rendering the verdict](#rendering-the-verdict)** — read this before you print
anything to a user · **[Limits](#limits)** ·
**[Security review](#security-review)** ·
**[Specification status](#specification-status)**

---

## Five minutes

```python
import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from c2patxt import (
    C2PA_CLAIM_SIGNING_EKU,
    Disclosure,
    ModelType,
    Provenance,
    Signer,
    embed,
    verify,
)


def build_leaf(key):
    """A conformant self-signed leaf. Self-signed verifies as VALID (untrusted)."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "your signing key")])
    start = datetime.datetime.now(tz=datetime.timezone.utc)
    end = start + datetime.timedelta(days=365)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Omit this line and Signer refuses to construct (14.5.1.1), unless you
        # also pass allow_nonconformant=True.
        .add_extension(x509.ExtendedKeyUsage([C2PA_CLAIM_SIGNING_EKU]), critical=False)
        .sign(key, None)  # None: Ed25519 prehashes internally (RFC 8032)
    )


key = ed25519.Ed25519PrivateKey.generate()
leaf = build_leaf(key)

signer = Signer(private_key=key, certificates=(leaf,))
disclosure = Disclosure(media_type="text/plain", model_type=ModelType.GENERIC)

marked = embed("Text your model produced.", signer, disclosure)
# renders identically to the input; the mark is zero-width

result = verify(marked)
match result.state:
    case Provenance.TRUSTED:
        ...  # verifies AND chains to an anchor you supplied
    case Provenance.VALID:
        ...  # intact and signed; signer not corroborated
    case Provenance.INVALID:
        ...  # a mark is present and failed validation
    case Provenance.UNMARKED:
        ...  # no mark. NOT a finding about the text.
```

`strip(text)` removes a mark. `extract(text)` returns the manifest without validating
it. `locate(text)` returns the wrapper's byte span without decoding the manifest.

Those five are the call surface, and producing a mark also needs `Signer`, `Disclosure`
and `ModelType`. `__all__` exports thirty names in all: those eight, plus five
exceptions, the two context objects that buy determinism (`EmbedContext`,
`VerifyContext`), five verdict and status types, `ManifestStore` and `Span` for what
`extract` and `locate` return, `TrustEvaluator`, `MODEL_TYPES`,
`C2PA_CLAIM_SIGNING_EKU`, the three allocation bounds, and two version strings. Read
`c2patxt.__all__` for the list; anything not in it is private and may change without
notice.

**`strip(embed(x))` is not always `x`.** `embed` normalizes to NFC before marking,
because the hard binding is defined over the NFC form; `strip` only removes the
wrapper. So for text that was not already NFC, the round trip returns the NFC form of
what you passed in. Both halves are correct and the asymmetry is the surprising part.

### The certificate is the part people get wrong

The leaf **must** carry an EKU extension, present and non-empty (C2PA 14.5.1.1), must
not assert `cA` or `keyCertSign`, and must assert `digitalSignature`. Miss any of those
and every verifier — including this one — rejects it as `signingCredential.invalid`.
`Signer` refuses a non-conformant certificate at construction, so you find out now
rather than after the bytes ship — unless you pass `allow_nonconformant=True`, which
exists so the verifier can be tested against credentials it must reject.

The `c2pa-kp-claimSigning` OID itself is **not** required by 14.5.1.1, which names no
claim-signing OID — the OIDs it does name are `anyExtendedKeyUsage` (forbidden),
`id-kp-timeStamping` and `id-kp-OCSPSigning`. Include it anyway: 14.5.1.2 says a
validator **shall** use only the trust anchors it associates with EKUs present in the
certificate, so a credential carrying no EKU a trust store recognises cannot chain,
whatever else is right about it. A leaf carrying only `id-kp-emailProtection` verifies
here as `VALID` (untrusted).

The builder is in [Five minutes](#five-minutes) above, annotated. Every extension
there is one of the four rules in this section; drop any of them and `Signer` refuses
to construct, unless you pass `allow_nonconformant=True`.

`C2PA_CLAIM_SIGNING_EKU` is `1.3.6.1.4.1.62558.2.1`. You need the number, not the name,
if you mint the leaf with OpenSSL or a CA rather than with the code above.

---

## Why this exists

EU AI Act Article 50(2) obliges providers of AI systems generating synthetic text to
mark it in a machine-readable form and make it detectable as artificially generated,
**"as far as this is technically feasible"** — and it exempts systems performing an
assistive function for standard editing, systems that do not substantially alter the
input or its semantics, and use authorised by law for law enforcement. It applies from
**2 August 2026** (Reg. (EU) 2024/1689, Art. 113). Systems **placed on the market**
before that date get a four-month transitional period, to 2 December 2026 (Art. 111(4),
as added by Reg. (EU) 2026/1744) — a deferral, not an exemption.

The Commission's [Guidelines on Article 50](https://digital-strategy.ec.europa.eu/en/library/guidelines-transparency-obligations-providers-and-deployers-ai-systems)
(C(2026) 5054 final, 20 July 2026), para (76), say providers "must rely on
publicly-available industry standard detection solutions that allow any third party to
implement detection … **Where such standards are not available** … the provider may
rely on its own detection solution". That is the design brief here, and the escape
hatch is why: the format is a published specification, the vectors are CC0, and
verification needs this package or any other A.8 implementation — not us.

Guidelines under Art. 96 do not bind, and these are **not yet formally adopted**: the
accompanying Communication says they apply only once adopted in all language versions.
Read them as the Commission's stated expectation, not as law.

**What this does not do.** It does not make anyone compliant, and the law mandates no
standard: the Code of Practice on Transparency of AI-generated Content (10 June 2026)
names no marking or detection standard, and mentions neither C2PA nor Content
Credentials. Marking is one
obligation among several in Article 50, and this package implements marking for text.
Whether your deployment satisfies the Article is a question for your counsel, not for a
library.

---

## What this proves, and what it does not

**Proves.** That the text was marked by the holder of a specific signing key, that it
declares itself machine-generated, and that **not one byte of the covered text has
changed since**. A cryptographic statement, not a probabilistic one.

**Does not prove.** That the content is accurate, that the claims in it are true, or
who the signer *is* in the world — that last one depends entirely on which trust
anchors you supply.

**Absence of a mark proves nothing.** Most text ever written is unmarked. Human text
is unmarked. Text from a model that does not mark is unmarked. Text whose mark was
stripped is unmarked. This is the DKIM lesson: unsigned mail is not forged mail, and
treating it as such is the most damaging thing you can do with this library.

---

## Rendering the verdict

There is no CLI and no UI here. **Your interface is the only place this result reaches
a human.**

`Verdict` is deliberately **not** boolean-convertible. `bool(verdict)` raises
`TypeError`, because `"CLEAN" if verdict else "FAKE"` would render unmarked text as
forged, and a frozen dataclass is always truthy.

```python
# WRONG — every one of these ships a lie
if verdict:
    ...  # raises TypeError, by design
"AI-generated" if verdict.manifest else "Human"  # present whenever the manifest PARSED
StatusCode.CLAIM_SIGNATURE_VALIDATED in verdict.codes()  # TRUE on tampered text

# RIGHT — name your threshold
if verdict.at_least(Provenance.VALID):  # -> bool
    ...
verdict.raise_for_state(Provenance.VALID)  # -> None, or raises ValueError
```

`verdict.codes()` returns `tuple[StatusCode, ...]` across all three buckets.

The third is the subtle one: `claimSignature.validated` is genuinely present on a
document whose text was rewritten. The signature over the *claim* really is intact;
only its binding to the text broke.

`verdict.manifest` is `None` for unmarked text, a corrupt wrapper, more than one
wrapper, and any structural failure inside the manifest, so
`verdict.manifest.assertions` raises `AttributeError` on exactly the hostile inputs
where you most need it not to. `verdict.span` is `None` in those cases too.

| State | Say | Never say |
| --- | --- | --- |
| `TRUSTED` | "Signed by «name», verified against your trust list" | — |
| `VALID` | "Declares AI generation; signer not independently verified" | "Unverified", "Suspicious" |
| `INVALID` | "Carries a credential that failed validation — may have been edited" | "Fake" |
| `UNMARKED` | "No credential present" | "Human-written", "Fake", "Failed" |

**`VALID` carrying `signingCredential.untrusted` is the normal, correct outcome** for a
self-signed credential, and this package ships **zero** trust anchors. C2PA 14.3.5
defines a *Valid* manifest without requiring trust; 14.3.6 adds trust separately. To
reach `TRUSTED`, supply both through `VerifyContext` — anchors as a PEM bundle, and an
evaluator that decides whether a chain reaches one:

```python
import pathlib

from c2patxt import VerifyContext, verify

verdict = verify(
    marked,
    context=VerifyContext(
        anchors_pem=pathlib.Path("anchors.pem").read_bytes(),
        trust_evaluator=your_evaluator,  # see TrustEvaluator; the default trusts nothing
    ),
)
```

`anchors_pem` is the only channel: nothing is read from the environment, from a
bundled store or from disk on its own. `VerifyContext(now=...)` fixes the instant
validity is judged against and must be timezone-aware — a naive datetime raises
`ValueError` at construction rather than deep inside verification.

---

### `verdict.failure` is not empty on a good mark

The codes are bucketed three ways — `verdict.success`, `verdict.failure`,
`verdict.informational`. **Every mark this package produces puts one entry in
`failure`**, because a self-signed credential cannot be corroborated:

```text
state   : valid
success : assertion.hashedURI.match, assertion.dataHash.match,
          claimSignature.validated, claimSignature.insideValidity
failure : signingCredential.untrusted
```

So `if verdict.failure:` is a fourth wrong line, and the most tempting one: it reads
like the check you want and paints a red error on the normal outcome. **`state` is the
answer to "is this good".** The buckets say which rules were evaluated and how each came
out.

Reaching `TRUSTED` needs `VerifyContext(anchors_pem=...)` **and** a `trust_evaluator`.
`anchors=` is not a keyword you can pass: it is derived, and passing it is a
`TypeError`.

### `verify` never raises; `extract`, `strip` and `locate` do

`verify` is total: absent, corrupt and invalid marks are all `Verdict`s. The other
three are not. On a malformed wrapper — the 13-byte header declaring a 4 GiB manifest
from [Limits](#limits) — the split is:

```text
verify   -> Verdict(state=invalid)
extract  -> raises MarkCorruptError
strip    -> raises MarkCorruptError
locate   -> raises MarkCorruptError
```

Catch `C2paTextError`; `MarkCorruptError`, `AlreadyMarkedError`,
`UnencodableTextError` and `ProfileError` all derive from it. `ProfileError` is the one
most integrators meet first — it is what `Signer(...)` raises for a non-conformant
certificate. Catch the base class rather than the four subclasses; the list can grow. An uncaught
`MarkCorruptError` on a public verification endpoint is a disclosure surface — see
[SECURITY.md](https://github.com/dualeai/c2patxt/blob/main/SECURITY.md). The same split
applies when a limit trips: `verify` returns `INVALID`, the other three raise.

## Limits

| Property | Answer |
| --- | --- |
| Survives copy-paste of the full text | Yes, where the application preserves variation selectors |
| Survives any edit to the visible text | **No.** By design — see [robustness](https://github.com/dualeai/c2patxt/blob/main/docs/robustness.md) |
| Survives NFC/NFD/NFKC/NFKD | The **mark** does; the binding does not. Decomposing is enough — see below |
| Detects tampering | Yes; that is the mechanism |
| Identifies the signer | Only against anchors you supply |
| Network access | None, ever. No revocation fetch, no OCSP, no timestamp authority |
| Determinism | Only with `VerifyContext(now=...)`. By default `verify` reads the clock — see below |
| Signature algorithm | Ed25519 only — our narrowing; 13.2.1 also allows ES256/384/512 and PS256/384/512 |
| Size cost | **3.90 UTF-8 bytes per manifest byte, measured** — that ratio is the stable figure, and the manifest is dominated by your certificate chain. One reproducible point: 7,001 B per mark for a single self-signed Ed25519 leaf, under the test suite's pinned context AND its pinned key (`tests/conftest.py` seeds both; `tests/test_embed.py` asserts the 1,797 B store). Vary the key alone and the same configuration spans 6,993-7,009 B, because the signature's own bytes cost 3 or 4 UTF-8 bytes each. Your own total moves with the serial length, the subject name and the chain depth, so measure it rather than budgeting from ours |
| Thread safety | Safe to share, exercised by `tests/test_embed.py::test_one_signer_marks_correctly_from_many_threads`. Every public type is a frozen dataclass, the digest cache is per-call, and there is no module-level mutable state. A `Signer` wraps a `cryptography` `Ed25519PrivateKey`, whose signing operation is safe to call from multiple threads |
| Maximum input length | **None, deliberately — body-size limiting is yours.** See below |

**Decomposing a marked document breaks it, with nothing visibly edited.** The mark
survives — variation selectors have no decomposition — but the binding covers the
*bytes*, and NFD rewrites them:

```text
NFC form -> valid
NFD form -> invalid   assertion.dataHash.malformed
```

The two are canonically equivalent and render identically. Any transport that
normalizes — macOS filenames, some CMSes, some Java stacks — will do this to a document
nobody edited. Note the code is `malformed`, not `mismatch`: the wrapper moved, so the
declared exclusion no longer names it.

**A verdict has a shelf life.** C2PA 15.8 judges certificate validity at *validation*
time, not signing time, so the same bytes give different answers as the leaf expires:

```python
from c2patxt import VerifyContext

inside = leaf.not_valid_after_utc - datetime.timedelta(days=1)
after = leaf.not_valid_after_utc + datetime.timedelta(days=1)

verify(marked, context=VerifyContext(now=inside)).state  # Provenance.VALID
verify(marked, context=VerifyContext(now=after)).state  # Provenance.INVALID
```

The second carries `claimSignature.outsideValidity`. Nothing was tampered with; the
credential simply expired between the two calls.

Pass `VerifyContext(now=...)` to fix the instant and make `verify` a pure function of
its arguments — which is what makes a stored verdict reproducible. Without it, do not
cache one and treat it as permanent.

### Resource limits

Verification allocates in proportion to its input and refuses to grow past three
bounds, all of which are ours rather than the specification's:

| Bound | Value | What it stops |
| --- | --- | --- |
| `MAX_MANIFEST_LENGTH` | 2 MiB | A 13-byte header declaring a 4 GiB manifest |
| `MAX_SELECTOR_RUN` | 2 MiB + 13 | Walking an unbounded run of variation selectors |
| `MAX_JUMBF_DEPTH` | 32 | Unbounded recursion in JUMBF *and* in CBOR |

**There is no limit on the length of the text you pass in, and that is deliberate** —
this library cannot know what your endpoint considers a reasonable request. Cap the
body size at your edge. Two figures to budget from, each with the fixture it was taken
under:

- **Unmarked text: about 0.10 ms of CPU per MB**, linear to 4.32 MB. What is pinned is
  the mechanism rather than the timing — one `str.find` and one encode per call, held
  by `tests/test_regressions.py::test_verify_walks_unmarked_text_exactly_once`.
- **Marked text: peak memory about 3.4x the manifest store**, not the document — 1.77
  MiB peak on a 0.53 MiB store, `tracemalloc`. Held as a ratio by
  `tests/test_regressions.py::test_a_repeated_actions_link_allocates_a_bounded_multiple_of_its_input`.

Per-attack survival rates are in **[docs/robustness.md](https://github.com/dualeai/c2patxt/blob/main/docs/robustness.md)** (PAN'26
Text Watermarking task dataset, 300 documents, CC-BY-4.0, DOI
10.5281/zenodo.18620130). Read both columns:
**carrier survival is not provenance survival.** A transform can leave every selector
intact, so the mark is still found, while the covered bytes changed and the binding
correctly fails. Read the notes beside the rows before quoting a figure: each row says
what transform it actually applies, which is not always what its name suggests.

Copy-paste survival through Slack, Notion, Discord and Google Docs is **untested**. We
do not repeat vendor claims about it.

---

## Security review

Everything an AppSec questionnaire asks is in
[SECURITY.md](https://github.com/dualeai/c2patxt/blob/main/SECURITY.md): the security
properties and what holds each, the one runtime dependency with the command to check
it, the supply-chain attestations with the commands to verify a release yourself, and
the CRA Article 24(1) reporting policy. In short: Apache-2.0, one runtime dependency,
CPython 3.10–3.14, no network, no ambient configuration, no log records.

---

## Specification status

- **A.8 is under review.** The specification says of itself that it "remains under
  review and may be subject to change based on implementation feedback and
  interoperability testing". That sentence was *added* on 2026-04-01 (commit
  `666bdf8f`) and is the only change to A.8 across the published 2.4 builds.
- **2.4 has no release tag.** The last tag is 2.3, where the clause is numbered A.7.
  The 2.4 PDF and HTML are published. That is why our claim cites a build hash.
- **No certification exists to obtain.** Every conformance-listed product is certified
  against specification 2.2, and none declares a valid text media type (one declares a
  bare non-IANA `txt` token). 156 products at `7d19b332`.
- **The text conformance rubric is v0.1.0** — six manifest-level checks, no wire
  vectors. We pass all six.

We publish a wire-format conformance vector file
(`tests/vectors/A8ConformanceTest-1.2.1.txt`) because the rubric has none.
`tests/test_third_party_interop.py` tests interoperability with the two other public
A.8 implementations.

### The rest of the documentation

| Document | Answers |
| --- | --- |
| [compatibility](https://github.com/dualeai/c2patxt/blob/main/docs/c2pa-compatibility.md) | Which clauses we implement, and what the claim excludes |
| [deviations](https://github.com/dualeai/c2patxt/blob/main/docs/deviations.md) | How we read the specification where it was unclear |
| [known divergences](https://github.com/dualeai/c2patxt/blob/main/docs/known-divergences.md) | Where we deliberately disagree with another implementation |
| [open questions](https://github.com/dualeai/c2patxt/blob/main/docs/open-questions.md) | What we could not settle |
| [upstream filing](https://github.com/dualeai/c2patxt/blob/main/docs/upstream-filing.md) | Four defects causing silent divergence, written up for the C2PA |
| [robustness](https://github.com/dualeai/c2patxt/blob/main/docs/robustness.md) | What a marked document survives, measured |
| [release scope](https://github.com/dualeai/c2patxt/blob/main/docs/release-scope.md) | What ships, and what deliberately does not |
| [mutation audit](https://github.com/dualeai/c2patxt/blob/main/docs/mutation-audit.md) · [benchmarks](https://github.com/dualeai/c2patxt/blob/main/docs/benchmarks.md) | Whether the tests bite, and what CodSpeed holds |
| [releasing](https://github.com/dualeai/c2patxt/blob/main/docs/releasing.md) | How a release is cut (maintainers) |

---

## Reproduce

```console
$ make install && make test        # static checks + every test except the benchmarks
$ make lint                        # ruff, pyright strict, vulture
$ curl -sSL -o train.jsonl \
    "https://zenodo.org/records/18620130/files/train.jsonl?download=1"
$ uv run python -m tools.robustness train.jsonl   # the robustness numbers
```

## Licence

Apache-2.0. See [LICENSE](https://github.com/dualeai/c2patxt/blob/main/LICENSE).
