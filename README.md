# c2patxt

Embed, extract and verify C2PA Content Credentials in plain Unicode text.

Implements **C2PA Technical Specification 2.4 (2026-04-01), HTML build `c7e55d5a`,
Annex A.8 "Embedding Manifests into Unstructured Text"** — a manifest store encoded as
Unicode variation selectors appended after NFC-normalized text. The selectors are
designed not to render; actual rendering depends on the consuming text system.

This is Duale AI's implementation of C2PA text marking. It is **not** a C2PA
consortium release and carries no conformance certification.

```console
$ pip install c2patxt
```

Python 3.10+. The base install has one direct runtime dependency: `cryptography`.

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
        # Optional on a leaf; when present, cA must be false.
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
        .sign(key, None)  # Ed25519 takes no separately selected certificate hash
    )


key = ed25519.Ed25519PrivateKey.generate()
leaf = build_leaf(key)

signer = Signer(private_key=key, certificates=(leaf,))
disclosure = Disclosure(media_type="text/plain", model_type=ModelType.GENERIC)

marked = embed("Text your model produced.", signer, disclosure)
# NFC-normalized text followed by selectors designed not to render

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

`strip(text)` removes a mark. `extract(text)` parses and returns the manifest without
cryptographic validation. `locate(text)` returns the wrapper's byte span without
decoding the manifest.

Those five are the call surface, and producing a mark also needs `Signer`, `Disclosure`
and `ModelType`. Context, result, error and resource-limit types are exported beside
them. Read `c2patxt.__all__` for the exact list; anything not in it is private and may
change without notice.

**`strip(embed(x))` is not always `x`.** `embed` normalizes to NFC before marking,
because the hard binding is defined over the NFC form; `strip` only removes the
wrapper. So for text that was not already NFC, the round trip returns the NFC form of
what you passed in. Both halves are correct and the asymmetry is the surprising part.

### The certificate is the part people get wrong

The leaf **must** carry an EKU extension, present and non-empty (C2PA 14.5.1.1), must
not assert `cA` or `keyCertSign`, and must assert `digitalSignature`. Miss any of those
and this implementation rejects it as `signingCredential.invalid`. C2PA separately
permits a validator's private credential store to accept an exact credential.
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

The builder is in [Five minutes](#five-minutes) above, annotated. Basic Constraints
may be absent on a leaf; when present, it must not assert `cA`. Key Usage and a
non-empty EKU are required, and `Signer` refuses violations unless you pass
`allow_nonconformant=True`.

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

The Commission adopted the Guidelines on 20 July 2026. They give practical guidance
under Article 96; they do not turn this package or C2PA into a legal safe harbour.

**What this does not do.** It does not make anyone compliant, and the law mandates no
standard: the Code of Practice on Transparency of AI-generated Content (10 June 2026)
names no marking or detection standard, and mentions neither C2PA nor Content
Credentials. Marking is one
obligation among several in Article 50, and this package implements marking for text.
Whether your deployment satisfies the Article is a question for your counsel, not for a
library.

---

## What this proves, and what it does not

**Proves.** That the holder of the signing key bound the signed declaration to the
NFC-normalized covered text and that the signature and binding still validate. This is
a cryptographic statement, not a claim that the stored bytes are unchanged:
canonically equivalent text can have different UTF-8 bytes and the same binding input.

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

`verdict.manifest` is `None` when no manifest can be parsed and selected: unmarked
text, a corrupt wrapper, or plural wrappers whose signed exclusions do not identify
exactly one of them. Once selected, it remains available when later assertion,
binding, signature or credential validation fails. `verdict.span` is `None` only when
no structurally valid wrapper was located; a plural-selection failure reports the
first located span but no manifest.

| State | Say | Never say |
| --- | --- | --- |
| `TRUSTED` | "Signature and certificate path accepted by your trust policy" | "Signed by «name»" unless your application obtained that identity separately |
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
`verdict.informational`. With the default context and this self-signed example, the
mark carries one `failure` entry because no trust evaluator corroborates it:

```text
state   : valid
success : assertion.hashedURI.match (4 entries), assertion.dataHash.match,
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

### Validation failures are verdicts; producer input errors are exceptions

Absent, corrupt and invalid marks are all `Verdict`s from `verify`. A string containing
an unpaired surrogate raises `UnencodableTextError` at every text entry point because
it cannot be represented on the A.8 UTF-8 wire. `embed` raises
`TextNormalizationError` when normalization would exceed the limit below; verification
reports the same condition as `assertion.dataHash.malformed`. The other three entry
points also raise on malformed wrappers. For example:

```text
verify   -> Verdict(state=invalid)
extract  -> raises MarkCorruptError
strip    -> raises MarkCorruptError
locate   -> raises MarkCorruptError
```

Catch `C2paTextError`; every named package error exported through `c2patxt.__all__`
derives from it. `ProfileError` is what `Signer(...)` raises for a non-conformant
certificate. An uncaught `MarkCorruptError` on a public verification endpoint is a
disclosure surface — see
[SECURITY.md](https://github.com/dualeai/c2patxt/blob/main/SECURITY.md).

## Limits

| Property | Answer |
| --- | --- |
| Survives copy-paste of the full text | Yes, where the application preserves variation selectors |
| Detects every stored-byte edit | No. The binding covers NFC-normalized text; canonically equivalent equal-width rewrites can still validate |
| Survives NFC/NFD/NFKC/NFKD | The mark does. The binding fails when normalization changes the declared wrapper offset or the NFC-normalized covered text — see below |
| Detects a surviving mark whose NFC-normalized covered text changed | Yes; removing the whole mark yields `UNMARKED`, not evidence about origin |
| Identifies the signer | Only against anchors you supply |
| Package-owned network access | None. No revocation fetch, OCSP, or timestamp authority |
| Determinism | With `VerifyContext(now=...)` and an offline deterministic evaluator. By default `verify` reads the clock — see below |
| Signature algorithm | Generation: Ed25519. Validation: ES256/384/512, PS256/384/512 and Ed25519, the full C2PA 13.2.1 set |
| Size cost | Each manifest byte becomes one variation selector costing 3 or 4 UTF-8 bytes, plus the A.8 header and marker. Certificate fields and chain depth determine the manifest size, so measure your own credential |
| Thread safety | One `Signer` is exercised concurrently by `tests/test_embed.py::test_one_signer_marks_correctly_from_many_threads`; verification caches are per-call |
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

**A verdict has a shelf life when no validated trusted timestamp is available.** This
implementation does not validate `sigTst2`, so it uses the validation clock. The same
bytes therefore give different answers as a carried certificate expires:

```python
from c2patxt import VerifyContext

inside = leaf.not_valid_after_utc - datetime.timedelta(days=1)
after = leaf.not_valid_after_utc + datetime.timedelta(days=1)

verify(marked, context=VerifyContext(now=inside)).state  # Provenance.VALID
verify(marked, context=VerifyContext(now=after)).state  # Provenance.INVALID
```

The second carries `claimSignature.outsideValidity`. Nothing was tampered with; the
credential simply expired between the two calls.

Pass `VerifyContext(now=...)` with a deterministic evaluator to make `verify` a pure
function of its arguments. Without both, do not cache a verdict and treat it as
permanent.

### Resource limits

Verification allocates in proportion to its input and applies four component bounds.
They are implementation policy, not limits from the specification:

| Bound | Value | What it stops |
| --- | --- | --- |
| `MAX_MANIFEST_LENGTH` | 2 MiB | Accepting or emitting a larger manifest payload |
| `MAX_SELECTOR_RUN` | 2 MiB + 13 | Decoding an unbounded candidate run of variation selectors |
| `MAX_CBOR_DEPTH` | 32 | Deeply nested attacker-controlled CBOR |
| `MAX_NONSTARTERS` | 30 | Canonically ordering an unbounded Unicode nonstarter sequence during NFC normalization |

The last value is [Unicode UAX #15's Stream-Safe Text Format
boundary](https://www.unicode.org/reports/tr15/#Stream_Safe_Text_Format). This package
rejects longer sequences rather than inserting U+034F, because UAX #15 says that
insertion can make the result no longer canonically equivalent to the input.

**There is no limit on the length of the text you pass in, and that is deliberate** —
this library cannot know what your endpoint considers a reasonable request. Cap the
body size at your edge. CodSpeed owns the CPU and memory measurements; the functional
suite checks results and security bounds, not machine-dependent performance figures.

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

Security properties and release-verification commands are in
[SECURITY.md](https://github.com/dualeai/c2patxt/blob/main/SECURITY.md): the security
properties and what holds each, the base runtime dependency with the command to check
it, the supply-chain attestations with the commands to verify a release yourself, and
the CRA Article 24(1) reporting policy. In short: Apache-2.0, one base direct runtime dependency,
CPython 3.10–3.14, no package-owned network, no ambient configuration, no log records.

---

## Specification status

- **A.8 is under review.** The specification says it "remains under review and may be
  subject to change based on implementation feedback and interoperability testing".
- **The implementation claim names an exact build.** The 2.4 HTML and PDF are
  published; [compatibility](https://github.com/dualeai/c2patxt/blob/main/docs/c2pa-compatibility.md)
  records the source commit reviewed by this package.
- **This is not a C2PA consortium release and carries no conformance certification.**

The repository includes a local wire fixture derived from the C2PA A.8 rules.

### The rest of the documentation

| Document | Answers |
| --- | --- |
| [compatibility](https://github.com/dualeai/c2patxt/blob/main/docs/c2pa-compatibility.md) | Which clauses we implement, and what the claim excludes |
| [deviations](https://github.com/dualeai/c2patxt/blob/main/docs/deviations.md) | How we read the specification where it was unclear |
| [open questions](https://github.com/dualeai/c2patxt/blob/main/docs/open-questions.md) | What we could not settle |
| [upstream filing](https://github.com/dualeai/c2patxt/blob/main/docs/upstream-filing.md) | Four Annex A.8 ambiguities prepared for upstream review |
| [robustness](https://github.com/dualeai/c2patxt/blob/main/docs/robustness.md) | What a marked document survives, measured |
| [implementation scope](https://github.com/dualeai/c2patxt/blob/main/docs/release-scope.md) | What the package includes and excludes |
| [test design](https://github.com/dualeai/c2patxt/blob/main/docs/mutation-audit.md) · [benchmarks](https://github.com/dualeai/c2patxt/blob/main/docs/benchmarks.md) | Manual mutation method, test-layer rules, and what CodSpeed holds |
| [releasing](https://github.com/dualeai/c2patxt/blob/main/docs/releasing.md) | How a release is cut (maintainers) |

---

## Reproduce

```console
$ make install && make test        # static checks + every test except benchmarks
$ make lint                        # ruff, pyright strict, vulture
$ curl -sSL -o train.jsonl \
    "https://zenodo.org/records/18620130/files/train.jsonl?download=1"
$ uv run python -m tools.robustness train.jsonl   # the robustness numbers
```

## Licence

Apache-2.0. See [LICENSE](https://github.com/dualeai/c2patxt/blob/main/LICENSE).
