# Mutation audit

A hand-run audit. It gates nothing. It answers the one question coverage cannot: **do
the tests bite?**

Line coverage says every line ran. It does not say a single assertion would have
noticed if the line were wrong. The gate is `--cov-fail-under=90`; the figure the run
reports today is in [release-scope.md](release-scope.md), stated once so two documents
cannot drift apart on it.

The first pass applied 24 mutations across `_verify`, `_extract`, `_selectors`,
`_jumbf`, `_cbor` and `manifest`; 16 died immediately and 8 survived. **All eight are
now dead.**

## Method

Break the code deliberately, run `uv run pytest -q`, restore. A mutation that survives
is a gap in the suite, not a defect in the code — and it names the missing test.

## The eight that survived

Of 24 mutations applied, 16 died on first application and are not listed — a mutation
the suite catches immediately is a non-event. The eight that survived are below;
For each, the suite did not notice, a test was written for it, and the mutation was
re-applied to confirm it now dies. All eight are dead.

- `_verify._REQUIRED_ASSERTIONS` check → `if False`
- `_verify._hash_binding_bytes` → normalize before removing
- `_selectors` → drop the `MAX_MANIFEST_LENGTH` cap
- `_verify` → `len(exclusions) != 1` → `if False`
- `_verify` → drop the `bool`-before-`int` guard
- `_verify` → drop the `HASH_ALGORITHMS` membership test
- `_extract` → `manifests[-1]` → `manifests[0]`
- `_verify` → drop the exact-span membership test (see below)

## What the audit found

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

"I could not construct a distinguishing input" is not "no distinguishing input
exists", and writing the first down as the second is how a live mutant gets filed as
equivalent. Now killed by
`test_the_exclusion_must_name_a_located_wrapper_not_merely_be_trailing`.

The first corrective test for `_hash_binding_bytes` drove the shipped function
directly with the three UCD counterexamples and the mutation *still* survived: the function normalizes at the end as well as removing at the start, so for
already-NFC text both orderings genuinely agree. Only NFD input separates them —
`"e" + U+0301` is 3 bytes stored and 2 after NFC, so normalizing before slicing removes
the wrong three. **Driving the right function was not enough; it needed the right
input.**

## Pass 3 — 2026-08-05

70 mutations, applied one at a time on a throwaway copy, each reverted before the next.
One was discarded as invalid — it reordered two independent statements, so it was
equivalent by construction rather than by any fault of the suite — leaving 69.
**56 killed, 81%.** Of the 13 that survived, one is provably equivalent —
`trust._der_contents`'s `<` versus `<=`, unreachable behind the guard above it — and is
recorded as a comment beside that code so nobody writes a test that cannot fail. The
other **twelve were suite gaps and are now closed.**

A second was filed as equivalent and was not. Dropping `_hashed_uri_list`'s
`isinstance(key, str)` narrowing fails
`tests/test_negative.py::test_attacker_cbor_of_the_wrong_shape_narrows_rather_than_raising`,
which has existed since the initial commit — the audit reached "no test holds this"
without running the suite against the removal, and a comment in the source repeated it
for a while. Filing an equivalent mutant needs the same distinguishing probe as filing
an untested one, run in the other direction.

`trust.py` and `manifest.py` were near-saturated: every profile rule in
`check_claim_signing_profile` and `_check_x509_structure` died to a named test, as did
`SPEC_VERSION = "2.4.0"` → `"2.4"`, dropping the `specVersion` emission, moving it to the
deprecated claim-level position, and repointing `CLAIM_SIGNATURE_URI` at the claim box.

Four classes account for them, and each is worth recognising elsewhere:

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

