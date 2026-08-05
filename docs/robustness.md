# Robustness

Measured, not estimated. Reproduce with:

```console
$ curl -sSL -o train.jsonl \
    "https://zenodo.org/records/18620130/files/train.jsonl?download=1"
$ md5sum train.jsonl   # 777a1f5376eb6e0d5b54db2acff8c3ff
$ uv run python -m tools.robustness train.jsonl
```

**Corpus:** PAN'26 Text Watermarking, [zenodo.org/records/18620130](https://zenodo.org/records/18620130),
DOI 10.5281/zenodo.18620130, CC-BY-4.0. 300 documents, 701,594 characters.
Measured 2026-08-05.

## Results

| Attack | Still verifies | Mark still found |
| --- | ---: | ---: |
| identity | **1.000** | 1.000 |
| NFKD + casefold + whitespace collapse | 0.000 | **1.000** |
| strip invisible characters | 0.000 | 0.000 |
| retype (visible text only) | 0.000 | 0.000 |
| truncate to 50% | 0.000 | 1.000 |
| excerpt 30% | 0.000 | 1.000 |
| delete 15% of words | 0.000 | 1.000 |
| typos in 5% of tokens | 0.000 | 1.000 |
| paraphrase | 0.000 | 1.000 |
| translate round-trip | 0.000 | 1.000 |
| markdown round-trip (reflow) | 0.500 | 1.000 |

The two bolded cells are the only ones that gate a build. Everything else is a
measurement and gates nothing.

## Read the two columns separately

**Carrier survival is not provenance survival**, and a table headed "survival" hides
that unless both columns are shown.

- **Mark still found** asks whether the variation-selector run survived.
- **Still verifies** asks whether the hard binding held.

The reflow row is the case that makes the distinction concrete: a `pandoc md → html →
md` pass, or an email MIME round trip, leaves every selector intact and reflows the
visible text. The mark is still there, and where the bytes it covers changed the binding
correctly fails.

**It reads 0.500, and the row does not measure reflow at all.** Measured against the
corpus above:

| | count |
| --- | ---: |
| documents | 300 |
| containing a newline | **0** |
| containing U+00A0 | **150** (444 occurrences) |
| altered by `" ".join(text.split())` | **150** |

`tools/robustness.py:149` implements reflow as `" ".join(visible.split())`. Every
document in this corpus is already a single line, so there is no line structure to
reflow — and `str.split()` splits on U+00A0 as well as ASCII whitespace. The 150
documents that fail are exactly the 150 containing a non-breaking space. **The row
measures NBSP folding**, and its label is wrong for this corpus. A transform that
genuinely rewrapped lines would change nothing here and the row would read 1.000.

Three earlier explanations of this number were wrong, the last of them saying the
fraction "is not something this repository can check" — which the reproduce block at the
top of this file refutes. The corpus is one `curl` away and the measurement took a
minute. **Not run in CI is not the same as not checkable**, and treating it as such is
how an unverified claim gets written down twice.

## Why almost every row is 0.000, and why that is not a defect

**A hard binding is not a watermark.** It is a cryptographic hash over the exact
bytes. Any edit to the visible text invalidates it — that is the entire mechanism, and
a row that survived paraphrase would mean the binding was not doing its job.

EU AI Act Article 50(2) requires marking to be effective "to the extent this is
technically feasible", and a hash binding is the technically feasible option that
gives a third party a *verifiable* answer rather than a probabilistic one. A
statistical watermark survives paraphrase and cannot tell you who generated the text
or prove the text is unaltered. This can do both, and cannot survive paraphrase. Those
are the same trade, seen from two ends.

The NFKD row is the one to understand before reading the rest: it is 0.000 in the
first column and 1.000 in the second, deliberately. Casefolding and collapsing
whitespace rewrite the hashed bytes, so the binding must fail. What must *never*
happen is the mark disappearing, and it does not: U+FEFF and every variation selector
have combining class 0 and no decomposition mapping, canonical or compatibility, so no
normalization form touches them. Aggressive normalization on ingest does **not**
destroy provenance.

## False positives

Balanced accuracy is deliberately **not** reported as a headline. For a hard binding
the true-negative rate is near-trivially 1.0, so a balanced-accuracy figure is
dominated by the true-positive rate and tells a reader nothing this table does not.

The honest form of the same claim is analytic: a false positive requires U+FEFF
followed by eight variation selectors decoding to exactly `0x4332504154585400`.
Treating each selector as uniform over its 256 reachable values, that is 2⁻⁶⁴ per
U+FEFF encountered. No natural-language process emits that sequence.

## Limitations, stated rather than buried

- **One corpus.** The attack harness we borrowed the list from states its own
  limitation plainly: single-dataset robustness does not transfer. We used one dataset
  and we are not claiming otherwise.
- **The attack list is reused verbatim** from `writerslogic/c2pa-text-binding`'s
  disclosed list, so these numbers are directly comparable to the only other published
  set. Their `ROBUSTNESS.md` is the comparison point.
- **Paraphrase and translation are stand-ins.** Both are implemented as deterministic
  visible-text rewrites rather than by calling a model. For a hash binding the answer
  does not depend on *how* the bytes changed, only that they did, so a model would add
  cost and non-determinism without changing a single cell.
- **Copy-paste survival through third-party applications is untested.** We have not
  measured Slack, Notion, Discord or Google Docs and we do not repeat vendor claims
  about them. X is known to strip U+200B, which is a different character from the ones
  this format uses; we have not tested X either.
