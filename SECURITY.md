# Security Policy

This document is the coordinated vulnerability handling policy for `c2patxt`. It is
written to serve as the documented, verifiable policy required of an open-source
software steward under Article 24(1) of Regulation (EU) 2024/2847 (the Cyber
Resilience Act), and not merely as a repository convention.

> **Status.** `c2patxt` is not published and this repository is internal. The reporting
> channel below works now; the GitHub and PyPI links elsewhere in this document become
> live at the first release.

## Reporting a Vulnerability

**Email `security@duale.ai`.** This works today and is the channel the timeline below
is measured against.

GitHub Security Advisories are the preferred route once this repository is public —
private vulnerability reporting is enabled, and
`https://github.com/dualeai/c2pa-text/security/advisories/new` will accept reports at
that point. It does not resolve while the repository is internal, which is why email
comes first here rather than second.

Do not open a public issue for a suspected vulnerability.

### Response Timeline

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

### Third-Party Dependencies

This package has exactly one runtime dependency, `cryptography`. Vulnerabilities in
it should be reported to [pyca/cryptography](https://github.com/pyca/cryptography)
directly. We will still want to hear about it if the issue affects users of this
package, so that we can pin or advise.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

The public API is explicitly unstable while the major version is 0. Security fixes
are released against the latest `0.x` only.

## Scope

### In scope

- Failure to detect a mark that is present and valid (false negative).
- Reporting a mark as valid when the hash binding or claim signature does not verify
  (false positive), including any input that yields `Provenance.VALID` or
  `Provenance.TRUSTED` without a genuine, verifying signature.
- Memory or CPU exhaustion from adversarial input. This library parses untrusted text
  and untrusted binary structures, and is expected to be run on a public,
  unauthenticated verification surface. Unbounded allocation from an attacker-supplied
  length field is a vulnerability, not a performance bug.
- Information disclosure through exceptions, return values or timing that reveals more
  than the verdict and the manifest fields.
- Any network access, filesystem access, or subprocess execution performed by this
  library. It is designed to do none of these; observing any of them is a finding.

### Out of scope, by design

These are documented properties of the format, not defects. They are stated here so
that reporting them is unnecessary.

- **Mark removal.** Publishing a detector publishes a remover. The detection algorithm
  read backwards is a stripping algorithm. This is inherent to the design and is
  accepted; erasure of a mark by a computationally bounded attacker is possible even
  when insertion and detection share a secret.
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

- **No network.** Verification is a pure function of its arguments. The test suite
  runs with `pytest-socket` and `--disable-socket`, so any egress fails the build.
- **No logging.** This library emits no log records, so it cannot leak partial-match
  detail into a host application's logs. Asserted in CI over real embed and
  verify calls, captured at the root logger.
- **No ambient configuration.** No environment scanning, no implicit credential store,
  no configuration file discovery. Trust anchors are supplied explicitly by the caller.
- **One runtime dependency.** `cryptography`, and nothing else. Check it yourself:

  ```console
  $ python -c "from importlib.metadata import requires; \
      print([r for r in requires('c2patxt') if 'extra ==' not in r])"
  ['cryptography~=48.0']
  ```

  Asserted by `tests/test_package.py::test_the_package_declares_exactly_one_runtime_dependency`,
  which runs on every CI job. (`uv tree --no-dev` is NOT a useful check here: the dev
  set is an extra rather than a dependency group, so `--no-dev` is a no-op.)

## Supply chain

**No release exists yet**, so everything in this section describes what the release
pipeline is configured to do rather than something you can check today. It becomes
verifiable at the first release.

Releases will be published to PyPI using Trusted Publishing (OIDC); no long-lived API
token exists. Each release will carry PEP 740 digital attestations and SLSA build
provenance binding the artifact to the source commit, plus CycloneDX and SPDX SBOMs
attached to the GitHub release. Verify a release yourself:

```bash
# artifact -> commit (SLSA provenance)
gh attestation verify ./c2patxt-<version>-py3-none-any.whl -R dualeai/c2pa-text

# artifact -> publisher (PEP 740; no GitHub account required)
pypi-attestations verify pypi \
  --repository https://github.com/dualeai/c2pa-text \
  https://files.pythonhosted.org/packages/.../c2patxt-<version>-py3-none-any.whl
```

An attestation tells you *where* a package came from, not *whether* you should trust
it. Neither `pip` nor `uv` gate installation on attestations, so verification is a
step you run deliberately.
