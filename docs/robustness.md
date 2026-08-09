# Robustness

Measured, not estimated. Reproduce with:

```console
$ curl -sSL -o train.jsonl \
    "https://zenodo.org/records/18620130/files/train.jsonl?download=1"
$ md5 -q train.jsonl   # 777a1f5376eb6e0d5b54db2acff8c3ff  (md5sum on Linux)
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
| truncate to 50% | 0.000 | 1.000 |
| excerpt 30% | 0.000 | 1.000 |
| delete 15% of words | 0.000 | 1.000 |
| typos in 5% of tokens | 0.000 | 1.000 |
| synthetic word substitution | 0.000 | 1.000 |
| whitespace collapse (NBSP folding) | 0.500 | 1.000 |

The manual command exits nonzero if either bolded cell falls below 1.000. It is not a
CI build gate; everything else is a measurement.

## Read the two columns separately

**Carrier survival is not provenance survival**, and a table headed "survival" hides
that unless both columns are shown.

- **Mark still found** asks whether the variation-selector run survived.
- **Still verifies** asks whether the hard binding held.

The **whitespace collapse (NBSP folding)** row leaves every selector intact while
rewriting visible text. It reads 0.500 on this corpus. The input facts are:

| | count |
| --- | ---: |
| documents | 300 |
| containing a newline | **0** |
| containing U+00A0 | **150** (444 occurrences) |
| altered by `" ".join(text.split())` | **150** |

`whitespace_collapse` is `" ".join(visible.split())`. Every document is already one
line, and `str.split()` treats U+00A0 as whitespace. The 150 documents whose binding
fails are exactly those containing a non-breaking space.

## Why almost every row is 0.000, and why that is not a defect

**A hard binding is not a watermark.** It is a cryptographic hash over the
NFC-normalized covered text. An edit that changes that normalized text invalidates the
binding. A canonically equivalent rewrite can change stored UTF-8 bytes without
changing the binding input; a changed byte offset can still make the declared wrapper
exclusion malformed.

This implementation provides a cryptographic binding to normalized text bytes. It does
not survive edits, and signer identity depends on caller-supplied trust policy. Whether
a deployment satisfies EU AI Act Article 50(2) depends on its effectiveness,
interoperability, robustness, reliability, costs, limitations, and the state of the
art; this corpus does not answer that legal or deployment question.

The NFKD row is the one to understand before reading the rest: it is 0.000 in the
first column and 1.000 in the second, deliberately. Casefolding and collapsing
whitespace rewrite the hashed bytes, so the binding must fail. What must *never*
happen is the mark disappearing, and it does not: U+FEFF and every variation selector
have combining class 0 and no decomposition mapping, canonical or compatibility, so no
normalization form removes the carrier. The changed covered bytes still invalidate the
hard binding, so the carrier remains detectable but the provenance no longer validates.

## False positives

Balanced accuracy is deliberately **not** reported as a headline. For a hard binding
the true-negative rate is near-trivially 1.0, so a balanced-accuracy figure is
dominated by the true-positive rate and tells a reader nothing this table does not.

The analytic candidate-detection model assumes each selector byte is independent and
uniform over 256 values. Under that model, U+FEFF followed by eight selectors decoding
to `0x4332504154585400` has probability 2⁻⁶⁴ per U+FEFF encountered. This is not a
measured natural-language false-positive rate and does not imply a valid credential;
the wrapper and signed manifest must still parse and verify.

## Limitations, stated rather than buried

- **One corpus.** The attack harness we borrowed the list from states its own
  limitation plainly: single-dataset robustness does not transfer. We used one dataset
  and we are not claiming otherwise.
- **The deterministic transforms are literal.** The table is not a model-backed
  paraphrase or translation evaluation.
- **Synthetic word substitution is literal.** It applies three fixed replacements and
  does not claim to measure paraphrase or translation quality.
- **Copy-paste survival through third-party applications is untested.** We have not
  measured Slack, Notion, Discord or Google Docs and we do not repeat vendor claims
  about them. X is known to strip U+200B, which is a different character from the ones
  this format uses; we have not tested X either.
