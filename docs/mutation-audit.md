# Mutation audit

Done by hand, at a milestone, gating nothing. The question it answers is the only one
coverage cannot: **do the tests actually bite?**

Line coverage says every line ran. It does not say a single assertion would have
noticed if the line were wrong. The gate is `--cov-fail-under=90`; the figure the run
reports today is in [release-scope.md](release-scope.md), stated once so two documents
cannot drift apart on it.

Where a pass states a suite size, that is the size it ran against; the suite grew
between passes.

The first pass applied 24 mutations across `_verify`, `_extract`, `_selectors`,
`_jumbf`, `_cbor` and `manifest`; 16 died immediately and 8 survived. **All eight are
now dead.**

## Method

Break the code deliberately, run `uv run pytest -q`, restore. A mutation that survives
is a gap in the suite, not a defect in the code — and it names the missing test.

## Results — one table, both rounds

`caught` means the mutation died the first time it was applied. `survived → fixed`
means the suite did not notice, a test was written for it, and the mutation was
re-applied to confirm it now dies.

| Mutation | Verdict |
| --- | --- |
| `_cbor.loads` → unconditional `raise` | caught (50 tests) |
| `_verify._check_assertions` → always `(verdict, True)` | caught |
| `_extract` → drop the duplicate-label rejection | caught |
| `_extract` → skip assertions with no `cbor` content box | caught |
| `MarkCorruptError.__str__` → eager whole-document encode | caught |
| `_verify._binding_status` → drop the suffix check | caught |
| `manifest.py` → `claim_generator_info` as an array | caught |
| `manifest.py` → label `urn:uuid:` instead of `urn:c2pa:` | caught |
| `_selectors` → off-by-one on `VS_HIGH_BASE` | caught (105 tests) |
| `_selectors` → accept `version != 1` | caught |
| `_jumbf` → read the box ID as 2 bytes | caught |
| `_jumbf` → drop label-character validation | caught (19 tests) |
| `_cbor` → allow non-shortest-form integers | caught |
| `_cbor` → allow out-of-order map keys | caught |
| `manifest.py` → hash the superbox WITH its header | caught (40 tests) |
| `_verify._compare_digest` → always `DATA_HASH_MATCH` | caught (7 tests) |
| `_verify._REQUIRED_ASSERTIONS` check → `if False` | **survived → fixed** |
| `_verify._hash_binding_bytes` → normalize before removing | **survived → fixed** |
| `_selectors` → drop the `MAX_MANIFEST_LENGTH` cap | **survived → fixed** |
| `_verify` → `len(exclusions) != 1` → `if False` | **survived → fixed** |
| `_verify` → drop the `bool`-before-`int` guard | **survived → fixed** |
| `_verify` → drop the `HASH_ALGORITHMS` membership test | **survived → fixed** |
| `_extract` → `manifests[-1]` → `manifests[0]` | **survived → fixed** |
| `_verify` → drop the exact-span membership test | **survived → fixed** (see below) |

## What this audit actually found

Two tests that did **not** bite, both now rewritten. This is the entire value of the
exercise, and neither was visible in a coverage report:

1. **`tests/test_cbor.py` passed with the decoder replaced by an unconditional
   `raise`.** It caught `CborDecodeError`, `TypeError` *and* `ValueError` and `pass`ed
   on each, so every possible outcome satisfied it; the only assertion was
   `checked > 0`. It also fed each item through `cbor2` first, so it compared our
   decoder against `cbor2`'s output rather than against the RFC's published bytes, and
   it broke after the first item in each file — "checked=7" meant seven items, not 42.
   Rewritten: 42 parametrized cases over the raw published bytes, each either decoding
   correctly *and* re-encoding byte-identically, or refused with a `CborDecodeError`.
   Plus a guard that the corpus is neither all-accepted nor all-refused, because a
   decoder that refuses everything satisfies every individual case.

2. **`tests/test_manifest.py` asserted `urn:uuid:` while citing C2PA 8.1**, which says
   `urn:c2pa:`. The test was *defending* a wire defect. Corrected, and the label is now
   matched against 8.1's ABNF as a regex rather than against our own f-string.

## What the eight survivors were guarding

None was visible in a coverage report.

| Survivor | What it actually guarded |
| --- | --- |
| `_REQUIRED_ASSERTIONS` check | **`c2pa.ai-disclosure`** — the one fact this artefact carries |
| `_hash_binding_bytes` ordering | the 15.12.1.3.1-vs-A.8.7.3 order its 25-line docstring is about |
| `MAX_MANIFEST_LENGTH` | the 2 MiB allocation cap, at 100% line coverage |
| `len(exclusions) != 1` | a rule two docstrings called a security property |
| `bool`-before-`int` | `{"start": True}` describing a real attacker-chosen range |
| `HASH_ALGORITHMS` membership | `algorithm.unsupported`, never once produced by a test |
| `manifests[-1]` | C2PA 15.5.1's active-manifest rule, justified by a 16-line comment |
| exact-span membership | 15.12.1.3.1 step 3 — looks equivalent until you build the input |

Three patterns, all worth recognising elsewhere:

- **A claim asserted in prose with nothing checking it.** Four of the eight. Identical
  in shape to a label test that once asserted `urn:uuid:` while citing the clause
  saying `urn:c2pa:` — the test was *defending* the defect.
- **A guard reachable only behind another guard that answers first.** The allocation
  cap sat at 100% line coverage because a `declared > available` check fired before it.
  Coverage counts execution, not attribution.
- **A test that reimplements the thing it tests.** `test_normalization.py` proved two
  *test-local* functions differ — a fact about Unicode, not about our code — and never
  drove the shipped one.

### The exact-span membership mutant is not equivalent

The tempting reading is that the suffix rule already forces the span, so a test for
membership would be a test that cannot fail. It is false, and three lines disprove it.

Slide the wrapper one **whole code point** (3 bytes) earlier and pad the tail by 3.
The signed `start + length == len(encoded)` still holds, so the suffix rule passes,
while the declared range coincides with no located wrapper:

| | declared | spans | suffix ok | membership ok | status |
| --- | --- | --- | --- | --- | --- |
| pristine | (12, 6791) | {(9, 6791)} | yes | **no** | `dataHash.malformed` |
| mutant | (12, 6792) | {(9, 6792)} | yes | **no** | `dataHash.mismatch` |

A one-**byte** shift genuinely is indistinguishable — it splits U+FEFF, and
`_compare_digest`'s `UnicodeDecodeError` branch also returns `malformed`. Aligning the
shift to a code-point boundary is what separates them, and that near-miss is exactly
why the first attempt looked equivalent.

**The lesson is the finding.** "I could not construct a distinguishing input" is not
"no distinguishing input exists", and writing the first down as the second is how a
live mutant gets filed as equivalent. Now killed by
`test_the_exclusion_must_name_a_located_wrapper_not_merely_be_trailing`.

`_hash_binding_bytes` is worth its own note. The first corrective test drove the
shipped function directly with the three UCD counterexamples and the mutation *still*
survived: the function normalizes at the end as well as removing at the start, so for
already-NFC text both orderings genuinely agree. Only NFD input separates them —
`"e" + U+0301` is 3 bytes stored and 2 after NFC, so normalizing before slicing removes
the wrong three. **Driving the right function was not enough; it needed the right
input.**

## Pass 3 — 2026-08-05, against 944 tests

70 mutations, applied one at a time on a throwaway copy, each reverted before the next.
**56 of 69 killed, 81%** — one was discarded as an invalid mutation (it reordered two
independent statements, so it was equivalent by construction rather than by any fault of
the suite) rather than counted as a pass.

`trust.py` and `manifest.py` were near-saturated: every profile rule in
`check_claim_signing_profile` and `_check_x509_structure` died to a named test, as did
`SPEC_VERSION = "2.4.0"` → `"2.4"`, dropping the `specVersion` emission, moving it to the
deprecated claim-level position, and repointing `CLAIM_SIGNATURE_URI` at the claim box.

**Eleven survivors, all now closed.** The four
worth remembering as a class:

- The **wiring** survivors. `_count_hard_bindings`, `_chain_inside_validity`,
  `_claim_malformed` and `verify`'s `exc.code` were each correct and each called from a
  line nothing asserted. Every one had a passing unit test on the helper. That is the
  shape to look for first in the next pass: a rule proved inside a function, and the
  call site unprotected.
- The **fixture-shape** survivors. Every `Signer` in the suite carried exactly one
  certificate, so a rule about "all CA certificates up to the trust anchor" could not be
  exercised at all; every icon list had one element, so three loops ran one iteration.
  Not weak assertions — incapable inputs.
- The **prose** survivors. `_assertion_failure`'s check ordering, `_json_ld_assertion`'s
  `.metadata` scoping, and the digest cache's `(label, algorithm)` key were each stated
  in a docstring as a deliberate decision, and none had an assertion. This repository's
  own rule — "If you write a claim, write the assertion that holds it" — applies to
  docstrings about internal behaviour, not only to shipped text.
- The **boundary** survivors. `end > len(encoded)` loosened by one byte, and `<=` → `<`
  on both validity endpoints. The existing vectors sat two units from the boundary.

### Two survivors that are NOT suite failures

Recorded so nobody "fixes" them later:

- Dropping the `isinstance(key, str)` narrowing in `_hashed_uri_list` is **equivalent
  under pytest and caught by pyright**. Non-`str` keys survive into the map, but every
  consumer reads by string key only, so no runtime behaviour changes. `make lint` holds
  it; `make test` cannot. It is a typing guard, not a security one.
- `trust.py`'s `if first < _DER_LONG_FORM:` → `<=` is **provably equivalent**. The
  preceding `if first == _DER_LONG_FORM: raise` means control reaches that line only
  when `first != 0x80`, so both agree for all 256 byte values, and `_der_contents` has
  exactly two callers, both downstream of that guard.

### Method note

**Before you run a single mutation**, two things, each of which turns a broken probe
into a green one if you skip it:

```bash
find src -name __pycache__ -type d -exec rm -rf {} +  # after any same-length revert
```

zsh does not word-split unquoted `$VAR`; use `${=VAR}`. Read every result as the literal
words `1 failed`. The reasoning is below.


Every survivor needs a **distinguishing probe** — a test that passes on pristine code
and fails under the mutant — before it is filed as untested rather than equivalent. The
probe is the cheap part and it is what makes the distinction honest.

Two traps, both of which produce a green result from a broken probe. (A third, about
reading a local CodSpeed table, is in [benchmarks.md](benchmarks.md) — it misleads a
reader but does not make a probe pass.)

- **Stale bytecode after a same-length revert.** Python invalidates a `.pyc` on source
  size and mtime, and `0xFFFE` → `0xFFFF` changes neither at second granularity. The
  restored file keeps loading the mutant. Run
  `find src -name __pycache__ -type d -exec rm -rf {} +` after reverting.
- **zsh does not word-split unquoted expansions.** A harness running `pytest $ARGS`
  with `ARGS="file -k selector"` hands pytest ONE argument, selects nothing, and prints
  `no tests ran` — which reads like success at a glance. Use `${=ARGS}`, and read every
  mutation result as the words `1 failed`, never as the absence of a failure.

## Why not automate it

`mutmut` 3.7.0 is BSD-3 and actively maintained, and mutation testing's strongest suit
— off-by-one and boundary errors, `<= 15` versus `< 16`, `0xE01EF` versus `0xE01F0` —
is exactly a codec's failure mode. But **mutmut 3.x does not mutate code outside
functions**, so `MAGIC`, `VERSION` and the `0xFE00` / `0xE0100` bases — precisely the
constants we most want mutated — are skipped.

That gap is already covered more cheaply and more durably: the vector file's invariant
1 asserts those constants directly, from an independent transcription of the
specification. `HypoFuzz` would help and is blocked on a
[self-contradicting licence](open-questions.md). `atheris` is out — 3.1.0 dropped
Python 3.10, which we support, and ships Linux-x86_64 wheels only.

So the audit stays manual, at milestones. Automating it would buy less than the
afternoon costs.

## Benchmarks

Covered in [benchmarks.md](benchmarks.md) — what CodSpeed holds, what assertions hold,
and the harness traps.
