# Cutting a release

Publishing is triggered by a **GitHub Release**, not by pushing a tag. `git push --tags`
runs nothing: the workflow's `push` trigger filters on `branches: [main]`, and a branch
filter excludes tag pushes.

1. Land everything on `main`. There is no changelog file to edit: **the release notes
   are the changelog**, written on the Release itself, so nothing about them can go
   stale in a checkout.
2. Tag that commit `vX.Y.Z` and push the tag. Nothing runs yet; the tag exists so the
   next step can point at it, and so `cicd/version.sh` can find it.
3. Create a GitHub Release for that tag. **This is the step that publishes.** Put the
   user-visible changes and compatibility notes in the release body.

The workflow file is read from the **tagged commit**, not from `main`. A fix landed on
`main` after the tag does nothing for that release, and re-running the failed run
re-reads the same broken file: move the tag, or cut the next version.

What then happens. Every job needs `build`, and the publish chain is sequential:

| Job | Does | Gate |
| --- | --- | --- |
| `build` | injects the version from `git describe --tags --abbrev=0`, builds sdist and wheel, generates CycloneDX and SPDX SBOMs, attests both plus build provenance | **no `if:` — every trigger**, including the release event |
| `publish-testpypi` | uploads to TestPyPI | `release` event |
| `publish-pypi` | uploads to PyPI | `release` event, after TestPyPI |
| `upload-release` | attaches artifacts and SBOMs to the Release | `release` event, after PyPI |

**`build` runs again at release time, and that run is the one that ships.**
`publish-testpypi` downloads `dist` from that workflow run. Two consequences follow:

- the build's artifact-presence checks, `twine check`, and
  `test "$COMPONENTS" -le 8` SBOM cap are live release gates, not formalities already
  passed;
- a push to `main` may resolve the previous tag, while the release event resolves the
  release tag. The push build exercises the chain but is not the published artifact.

TestPyPI gating PyPI is deliberate: an upload that fails only on the real index is one
that cannot be retried under the same version, because PyPI filenames are immutable.

`workflow_dispatch` runs `build` alone. Useful for exercising the chain without
publishing.

Both the `testpypi` and `pypi` environments require a trusted publisher configured on
the respective index. Three fields must match exactly:
`dualeai/c2patxt`, the workflow filename `release.yml`, and the environment name
(`testpypi` or `pypi`). No API token exists or should; see [SECURITY.md](../SECURITY.md).

**The version comes from the tag**, via `cicd/version.sh`, which falls back to `0.1.0`
when `git describe` finds nothing. `fetch-depth: 0` in the workflow is what makes tags
available to it — nothing asserts that the resolved version matches the Release tag, so
check the "Injecting version:" line in the build log before trusting the artifact.
