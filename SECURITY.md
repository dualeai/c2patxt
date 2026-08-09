# Security policy

**Report a vulnerability privately, either way:**

- [`/security/advisories/new`](https://github.com/dualeai/c2patxt/security/advisories/new)
  — private vulnerability reporting is enabled, and this is the preferred route.
- **Email `security@duale.ai`** if you would rather not use GitHub.

**Do not open a public issue for a suspected vulnerability.** The timeline below runs
from whichever channel you use.

## Response timeline

- **48 hours**: initial acknowledgment
- **7 days**: assessment and action plan
- **90 days**: target for fix and coordinated disclosure

We will keep you informed of progress and will credit reporters who wish to be
credited.

### Coordinated disclosure

Duale AI is not a CVE Numbering Authority. Where a CVE identifier is warranted, we
request one through GitHub, which is a CNA, using the repository's Security Advisory
workflow. Advisories published this way propagate to Dependabot alerts for downstream
users.

### Third-party dependencies

The base install has one direct runtime dependency, `cryptography`. Report
vulnerabilities in it to [pyca/cryptography](https://github.com/pyca/cryptography)
directly. We still want to hear about it if the issue affects users of this package, so
that we can pin or advise.

## Supported versions

The public API is explicitly unstable while the major version is 0. Security fixes are
released against the latest `0.x` only.

## Scope

### In scope

- Failure to detect a mark that is present and valid (false negative).
- Reporting a mark as valid when the hash binding or claim signature does not verify
  (false positive), including any input that yields `Provenance.VALID` or
  `Provenance.TRUSTED` without a genuine, verifying signature.
- Memory or CPU exhaustion from adversarial input. This library parses untrusted text
  and untrusted binary structures, and we expect it to run on a public, unauthenticated
  verification surface. Unbounded allocation from an attacker-supplied
  length field is a vulnerability, not a performance bug.
- Information disclosure through exceptions, return values or timing that reveals more
  than the verdict and the manifest fields.
- Any network access, filesystem access, or subprocess execution performed by
  package-owned code. A caller-supplied `TrustEvaluator` is caller code; c2patxt does
  not provide it with a remote-fetching facility.

### Out of scope, by design

These are documented properties of the format, not defects. Listed here so you need
not report them.

- **Mark removal.** Publishing a detector publishes a remover: the detection algorithm
  read backwards is a stripping algorithm. This is inherent to the design and is
  accepted; erasure of a mark by a computationally bounded attacker is possible even
  when insertion and detection share a secret.

  **This is why `strip()` ships.** It removes wrappers using their UTF-8 byte spans.
  Slicing a Python `str` with those byte offsets can leave selector code points behind
  on non-ASCII text; `strip()` performs the required encode, splice, and decode steps.
  `AlreadyMarkedError` reports the span, while `strip()` supplies the public removal
  operation. Held by
  `tests/test_embed.py::test_the_already_marked_span_is_enough_to_re_mark`.
- **Regeneration.** Any transform that reproduces the meaning and discards the bytes
  removes the mark. Paraphrase, retyping and truncation all defeat it.
- **Absence of a mark.** Unmarked text is the normal case for almost all text. A
  `Provenance.UNMARKED` result is not a security failure and carries no claim about
  the text's origin.
- **`signingCredential.untrusted` on a self-signed credential.** This package bundles
  no trust anchors. With none supplied by the caller there is nothing to chain to, so
  a correct, intact, honestly-signed mark yields `Provenance.VALID` together with
  `signingCredential.untrusted`. That is the specified and expected outcome.

## Security properties of this library

- **No package-owned network.** Package-owned verification performs no network I/O.
  Without `VerifyContext.now`, it reads the current clock; a custom evaluator is
  caller-owned code and can add its own state or I/O. The exercised package paths run
  with `pytest-socket` and `--disable-socket`, so a socket operation on those paths
  fails the build.
- **Silent public codec paths.** Package-owned embed and verification emit no log
  records, so they do not leak partial-match detail into a host application's logs.
  Held over real valid, invalid and absent inputs by
  `tests/test_package.py::test_public_codec_work_emits_no_log_records`.
- **Bounded Unicode normalization.** C2PA text binding requires NFC. Before that
  operation, the package enforces [UAX #15's 30-nonstarter Stream-Safe
  boundary](https://www.unicode.org/reports/tr15/#Stream_Safe_Text_Format) without
  changing the text by inserting CGJ. Public producer and verifier behavior at 30 and
  31 is held by `tests/test_normalization.py`. The policy remains while supported
  CPython patch releases can predate the linear-time fix in
  [CPython #149080](https://github.com/python/cpython/pull/149080).
- **No ambient configuration.** No environment scanning, no implicit credential store,
  no configuration file discovery. Trust anchors are supplied explicitly by the caller.
  Held by `tests/test_trust.py::test_no_anchors_ship_by_default` and
  `tests/test_trust.py::test_the_environment_cannot_supply_anchors`.
- **One direct dependency in the base install.** `cryptography`. Check it yourself:

  ```console
  $ python -c "from importlib.metadata import requires; \
      print([r for r in requires('c2patxt') if 'extra ==' not in r])"
  ['cryptography~=48.0']
  ```

  The optional `[trust]` extra preserves the published install contract and currently
  adds `pyhanko-certvalidator`. This package neither imports nor adapts it; installing
  the extra provides no c2patxt-owned trust backend or HTTP path, though Requests is a
  transitive dependency of that backend. c2patxt performs no remote fetching. Any
  future package-owned AIA, OCSP, or CRL fetching will require an async verification
  API. c2patxt-provided evaluators for synchronous `verify()` will remain offline;
  arbitrary caller evaluators remain caller-owned code.
- **Licence.** Apache-2.0, including its express patent grant.
- **Supported Python.** 3.10 – 3.14, CPython.

## Supply chain

Releases are published to PyPI using Trusted Publishing (OIDC); no long-lived API token
exists. Releases produced by the current workflow carry PEP 740 attestations and SLSA
build provenance binding each artifact to its source commit, plus CycloneDX and SPDX
SBOMs attached to the GitHub release. Verify such a release yourself:

```bash
# artifact -> commit (SLSA provenance)
gh attestation verify ./c2patxt-<version>-py3-none-any.whl -R dualeai/c2patxt

# artifact -> publisher (PEP 740; no GitHub account required)
pypi-attestations verify pypi \
  --repository https://github.com/dualeai/c2patxt \
  https://files.pythonhosted.org/packages/.../c2patxt-<version>-py3-none-any.whl

# pin the whole tree by hash
uv export --frozen --no-emit-project -o requirements.txt
pip install --require-hashes -r requirements.txt
```

An attestation tells you *where* a package came from, not *whether* you should trust
it. Neither `pip` nor `uv` gate installation on attestations, so verification is a
step you run deliberately.

## Regulatory basis

We are an open-source **steward** under Article 24 of Regulation (EU) 2024/2847, the
Cyber Resilience Act, not a manufacturer. The Act applies in stages: Chapter IV
(Articles 35-51, notification of conformity assessment bodies) from 11 June 2026,
Article 14's reporting duties from 11 September 2026, and the substantive obligations
including Article 24 from 11 December 2027.

This document is the Article 24(1) artefact for `c2patxt`. It does not speak for the
organisation that maintains the package, which owns its own obligations separately.
