"""Links and filenames in shipped documentation, resolved.

NOT PROSE GRADING. Commit df22b89 removed 61 tests that checked banned words, required
substrings and link resolution, on the grounds that grading prose is not the test suite's
job. That was right about the prose and wrong about the filenames: with nothing left, two
provenance documents came to name files that do not exist --
``tests/vectors/cbor/PROVENANCE.md`` claiming an ``mt7.cbor`` and
``tests/vectors/cose/PROVENANCE.md`` globbing ``sign1-*``, which matches nothing on disk.
Both are read by someone deciding whether to trust vendored bytes.

So this checks two things and no others: a relative link points at a file that exists,
and a backticked filename points at a file that exists -- repo-anchored paths anywhere,
and bare names and globs under ``tests/vectors/``, where both original bugs were. It
reads no sentence and enforces no wording.

WHAT IT DOES NOT CATCH, stated because a check described more broadly than it runs is
how the two false "a test enforces this" claims got written in the first place:
``docs/deviations.md`` once linked ``known-divergences.md`` for a padding entry that
document did not contain. The link resolved, because the file existed. Pointing at the
right file for the wrong reason is not something a resolver can see.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "vectors"

#: Files named in the vector documentation that belong to somebody else. Unicode's
#: NormalizationTest.txt is the format our own vector file is modelled on.
_NOT_OURS = frozenset({"NormalizationTest.txt"})

#: Every markdown file that ships. MANIFEST.in grafts docs/ and tests/ into the sdist,
#: so a reader who unpacks the artefact gets all of these.
SHIPPED = sorted(
    path
    for path in ROOT.rglob("*.md")
    if not any(part.startswith(".") or part in {"build", "dist", "htmlcov", "node_modules"} for part in path.parts)
)

#: ``[text](target)`` where target is not a URL, a mailto, or a bare in-page anchor.
_RELATIVE_LINK = re.compile(r"\[[^\]]*\]\((?!https?://|mailto:|#)([^)\s]+)\)")

#: A backticked token naming a file in THIS repository: it starts at one of our own
#: top-level directories and ends in an extension we ship.
#:
#: ANCHORED ON PURPOSE. These documents quote paths inside OTHER repositories --
#: `golden/vectors.json` in encypherai/c2pa-text, `conforming-products-list.json` in
#: c2pa-org/conformance-public -- and those must not be resolved against our tree. A
#: pattern matching any slashed path flags all of them, which would train a reader to
#: ignore the failure. Missing a few of our own paths is the better error.
_REPO_PATH = re.compile(
    r"`((?:src|tests|docs|tools|cicd|\.github)/[A-Za-z0-9_./-]*[A-Za-z0-9_-]\.(?:py|md|txt|json|toml|yml|cbor|edn|pem))`"
)

#: A bare filename or glob, resolved against the document's OWN directory.
#:
#: This is the half that catches a provenance file naming a vector that is not there:
#: both bugs that motivated this module were bare -- `mt7.cbor` and `sign1-*` -- and the
#: anchored pattern above cannot see either.
#:
#: APPLIED ONLY UNDER tests/vectors/, where a bare name means "a file beside this one".
#: Elsewhere it does not: docs/upstream-filing.md names `A8ConformanceTest-1.2.1.txt`,
#: which lives under tests/vectors/, and resolving it from docs/ would be a false alarm.
#: Restricted to data extensions and to globs without a slash, so a media type like
#: `text/*` and a clause like `A.8.7.3` are not mistaken for files.
_LOCAL_FILE = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:cbor|edn|json|pem|txt))`")
_LOCAL_GLOB = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_-]*\*[A-Za-z0-9_.-]*)`")


def _document_ids() -> list[str]:
    return [str(path.relative_to(ROOT)) for path in SHIPPED]


@pytest.mark.parametrize("document", SHIPPED, ids=_document_ids())
def test_every_relative_link_resolves(document: pathlib.Path) -> None:
    """A link to a file we moved or deleted is a dead end for whoever follows it."""
    broken = [
        target
        for target in _RELATIVE_LINK.findall(document.read_text("utf-8"))
        if not (document.parent / target.split("#", 1)[0]).exists()
    ]
    assert not broken, f"{document.relative_to(ROOT)} links to missing: {broken}"


@pytest.mark.parametrize("document", SHIPPED, ids=_document_ids())
def test_every_backticked_repository_path_exists(document: pathlib.Path) -> None:
    """The half that catches a provenance file naming a vector that is not there."""
    text = document.read_text("utf-8")
    missing = [
        path
        for path in _REPO_PATH.findall(text)
        if not (ROOT / path).exists() and not (document.parent / path).exists()
    ]
    if VECTORS in document.parents:
        missing += [
            name
            for name in _LOCAL_FILE.findall(text)
            if name not in _NOT_OURS and not (document.parent / name).exists()
        ]
        missing += [pattern for pattern in _LOCAL_GLOB.findall(text) if not any(document.parent.glob(pattern))]
    assert not missing, f"{document.relative_to(ROOT)} names missing paths: {sorted(set(missing))}"
