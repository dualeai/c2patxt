"""The documentation must not rot.

These docs carry the conformance claim and the reasoning behind every deviation. A
broken internal link or a pointer to a file that no longer exists costs a reader the
one thing the documents are for: being able to check us.
"""

from __future__ import annotations

import datetime
import pathlib
import re

import pytest
from cryptography import x509

from c2patxt import Provenance, Verdict, VerifyContext, verify

DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"
ROOT = DOCS.parent

#: README.md is checked ALONGSIDE docs/ because three separate artefacts point readers
#: at it -- the package docstring says "see the README for what is and is not
#: claimed", pyproject's Documentation URL resolves to it, and `readme = "README.md"`
#: makes it the entire PyPI long description. Nothing checked it, so its links could
#: dangle indefinitely in the one document most readers see first.
#: CONTRIBUTING.md and CLAUDE.md are here for the same reason and were NOT, until
#: 2026-08-06. Between them they hold the release runbook, the vectors procedure and
#: the static-analysis rules -- the most procedural prose in the repository, dense with
#: links and `tests/...::test_...` paths -- and no test had ever looked at any of it.
MARKDOWN = sorted(
    [
        *DOCS.glob("*.md"),
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / "CHANGELOG.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CLAUDE.md",
    ]
)


def test_the_docs_directory_is_not_empty() -> None:
    """Guards the guard: a glob over an empty directory passes every test below."""
    assert sorted(p.name for p in DOCS.glob("*.md"))


@pytest.mark.parametrize("document", MARKDOWN, ids=lambda p: p.name)
def test_every_relative_link_resolves(document: pathlib.Path) -> None:
    """A dangling link between our own documents is a promise we did not keep.

    Only relative targets are checked. Following external URLs would put the network
    in the test suite, which the whole package is built to avoid.
    """
    targets = re.findall(r"\]\(([^)]+)\)", document.read_text("utf-8"))
    relative = [t for t in targets if not t.startswith(("http://", "https://", "#"))]
    broken = sorted(t for t in relative if not (document.parent / t.split("#")[0]).exists())
    assert broken == []


#: Any link into our own repository, however it is spelled. Absolute links are needed
#: because README.md IS the PyPI long description and PyPI does not rewrite relative
#: hrefs -- readme_renderer has no base-URL logic (pypa/readme_renderer#71, closed
#: 2026-03-29), so a relative link in it resolved against pypi.org and 404'd.
#:
def _repository_url() -> str:
    """Our repository, read from ``pyproject.toml`` rather than written down here.

    THE LITERAL KEPT GOING STALE, three times in one day, and each time it narrowed a
    guarantee without failing anything. It matched only `blob/main/`, so a `tree/main/`
    link to a missing file passed both link tests; and a repository RENAME would have
    silenced it again, because a pattern that matches nothing reports nothing broken.

    `pyproject.toml`'s `Repository` URL is the right source: it has to be correct
    anyway -- it is what PyPI shows in the sidebar -- and reading it means the pattern
    and the links cannot disagree without something failing.

    Read with a regex rather than ``tomllib``, which is 3.11+ and this package supports
    3.10 -- and a TOML parser as a test dependency is a lot of machinery for one line.
    """
    text = (ROOT / "pyproject.toml").read_text("utf-8")
    match = re.search(r'^Repository = "([^"]+)"', text, re.M)
    assert match, "pyproject.toml has no [project.urls] Repository entry"
    return match.group(1).removesuffix(".git")


#: A PATTERN over that URL, covering every form GitHub serves a file under.
_REPO_LINK = re.compile(re.escape(_repository_url()) + r"/(?:blob|tree|raw)/[^/]+/(?P<path>[^)#]+)")


@pytest.mark.parametrize("document", MARKDOWN, ids=lambda p: p.name)
def test_every_link_into_our_own_repository_resolves(document: pathlib.Path) -> None:
    """The same guarantee as the relative-link test, for links that had to go absolute.

    Making README.md's links absolute fixed them on PyPI and QUIETLY REMOVED THEM FROM
    THE ONE TEST THAT CHECKED THEM: ``test_every_relative_link_resolves`` skips anything
    starting with ``https://``, so thirteen links to our own files stopped being
    verified and the suite stayed green. A fix that silently drops a guarantee is worse
    than the defect it fixed.

    The URL is still not FETCHED -- that would put the network in the suite. What is
    checked is that the path after the blob prefix names a file we actually ship.

    README.md IS REQUIRED TO CARRY SOME. Without that, every way this test has been
    weakened -- an absolute prefix it did not match, a rename it did not follow -- reads
    as "nothing broken" instead of "nothing checked". A vacuous pass is the failure mode
    of this test specifically, so it is the one thing asserted unconditionally.
    """
    targets = re.findall(r"\]\(([^)]+)\)", document.read_text("utf-8"))
    if document.name == "README.md":
        assert any(_REPO_LINK.fullmatch(target) for target in targets), (
            f"no links into {_repository_url()} found in README.md; the pattern and the "
            "links have drifted apart, and this test is checking nothing"
        )
    broken = sorted(
        target
        for target in targets
        if (match := _REPO_LINK.fullmatch(target)) and not (ROOT / match.group("path")).exists()
    )
    assert broken == []


@pytest.mark.parametrize("document", MARKDOWN, ids=lambda p: p.name)
def test_every_cited_source_file_exists(document: pathlib.Path) -> None:
    """Docs point at modules by path; a stale path sends a reader hunting."""
    cited = set(re.findall(r"`(src/[\w/]+\.py|tests/[\w/]+\.py)`", document.read_text("utf-8")))
    broken = sorted(path for path in cited if not (ROOT / path).exists())
    assert broken == []


#: Fenced ``python`` blocks in README.md, in file order.
_PYTHON_BLOCK = re.compile(r"```python\n(.*?)```", re.S)


def _readme_blocks() -> list[str]:
    return _PYTHON_BLOCK.findall((ROOT / "README.md").read_text("utf-8"))


def test_every_readme_python_block_at_least_parses() -> None:
    """Nothing ran the README until 2026-08-06, and it showed.

    ``test_api_surface.py`` covers the module docstring; ``test_docs.py`` covered links
    and banned words. The code a reader copies was checked by nobody, and README.md:51
    said the package "is exercised by the test suite on every commit" -- true of the
    library, not of this file. In one day that gap shipped a quickstart calling a
    function defined fifty lines below it and an example whose two dates were already
    false.

    Not every block can EXECUTE: one demonstrates calls that raise on purpose, another
    reads an ``anchors.pem`` that no reader has. Those still have to be valid Python,
    which is what this holds. The runnable path is held by the test below.
    """
    blocks = _readme_blocks()
    assert blocks, "no python blocks found; the fence pattern has drifted from the file"
    for index, block in enumerate(blocks):
        compile(block, f"README.md[python block {index}]", "exec")


def test_the_readme_quickstart_runs_as_written() -> None:
    """THE FIRST BLOCK IS THE ONE A READER PASTES, so it has to work alone.

    In file order, unmodified, in one namespace. Running it in a hand-chosen order is
    what let the previous defect survive an audit: the blocks passed only if the
    certificate builder was moved ahead of the block that calls it, which is not what a
    reader does. That is why the builder now lives INSIDE this block rather than in a
    section below it.

    Nothing is stubbed. ``embed`` runs a real padding search and a real Ed25519 sign;
    it costs milliseconds, and stubbing it would test a README nobody can run.
    """
    blocks = _readme_blocks()
    namespace: dict[str, object] = {}
    exec(compile(blocks[0], "README.md[quickstart]", "exec"), namespace)  # noqa: S102 -- running the docs IS the test

    result = namespace["result"]
    assert isinstance(result, Verdict)
    assert result.state is Provenance.VALID

    # THE SHELF-LIFE BLOCK CONTINUES THIS NAMESPACE -- it reads `leaf`, `marked` and
    # `datetime` from the quickstart, which is what a reader scrolling down has. Run
    # here rather than alone, and assert the two states it claims in its comments; the
    # dates it used to quote were true for one day.
    shelf_life = next(block for block in blocks if "not_valid_after_utc" in block)
    exec(compile(shelf_life, "README.md[shelf life]", "exec"), namespace)  # noqa: S102 -- as above

    # THE BLOCK'S OWN `inside` AND `after`, not values recomputed here. A first version
    # of this test derived both from `leaf.not_valid_after_utc` itself, so breaking the
    # block's arithmetic -- `+ 1 day` to `- 2 days` -- left it green. An assertion whose
    # operands both come from the test cannot fail on a change to the document.
    leaf, marked = namespace["leaf"], namespace["marked"]
    inside, after = namespace["inside"], namespace["after"]
    assert isinstance(leaf, x509.Certificate)
    assert isinstance(marked, str)
    assert isinstance(inside, datetime.datetime)
    assert isinstance(after, datetime.datetime)

    assert inside < leaf.not_valid_after_utc < after, "the two instants must straddle expiry"
    assert verify(marked, context=VerifyContext(now=inside)).state is Provenance.VALID
    assert verify(marked, context=VerifyContext(now=after)).state is Provenance.INVALID


def test_the_readme_is_not_a_stub() -> None:
    """Three artefacts promise the reader something here; for a long time there was
    a single heading.

    ``src/c2patxt/__init__.py`` says "see the README for what is and is not claimed",
    ``pyproject.toml``'s Documentation URL resolves to it, and ``readme = "README.md"``
    makes it the entire PyPI long description. This asserts the specific claims those
    promises imply, so the README cannot quietly regress to a stub.
    """
    readme = (ROOT / "README.md").read_text("utf-8")
    collapsed = " ".join(readme.split())

    for promised in (
        "c7e55d5a",  # the spec build the claim cites
        "Absence of a mark proves nothing",  # the DKIM lesson
        "carries no conformance certification",  # the disclaimer
        "signingCredential.untrusted",  # why VALID != TRUSTED
        "docs/robustness.md",  # the measured numbers
        "Apache-2.0",  # licence
    ):
        assert promised in collapsed, f"the README no longer states: {promised}"


def test_the_readme_carries_no_marketing_superlatives() -> None:
    """A regulator reading a boast goes looking for the gap.

    Also factually necessary: encypherai/c2pa-text already self-describes as "A
    Reference Implementation for C2PA Text Embedding", so claiming to be THE reference
    would be both boastful and wrong.
    """
    lowered = " ".join((ROOT / "README.md").read_text("utf-8").lower().split())

    # Matched as SELF-DESCRIPTION, not as substrings. "the only formal conformance
    # instrument that exists for text" is a fact about the ecosystem; "the only
    # implementation" would be a boast. A bare "the only" catches both and would push
    # the next writer to reword an accurate sentence.
    for boast in (
        "industry-leading",
        "world's first",
        "best-in-class",
        "the reference implementation",
        "the only implementation",
        "the only library",
        "the first implementation",
    ):
        assert boast not in lowered, f"marketing copy in the README: {boast}"


@pytest.mark.parametrize(
    "path",
    [
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "CLAUDE.md",
        "SECURITY.md",
        "CHANGELOG.md",
        "LICENSE",
        ".github/CODEOWNERS",
        ".github/ISSUE_TEMPLATE/verification-failed.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
    ],
)
def test_the_governance_files_exist(path: str) -> None:
    """Present and non-empty.

    These are OpenSSF Scorecard inputs and, more to the point, the things an evaluator
    checks before reading a line of code. A package whose audience includes regulators
    and competitors cannot inherit their absence from a template.
    """
    target = ROOT / path
    assert target.exists(), f"{path} is missing"
    assert target.stat().st_size > 0, f"{path} is empty"


def test_the_issue_template_asks_for_the_two_answers_that_make_a_report_actionable() -> None:
    """Without the exact code string and the transport path, every report is a guess.

    The template also pre-answers the three non-bugs that account for most reports:
    VALID+untrusted is expected, UNMARKED is not a finding, and an edit after marking
    is supposed to fail.
    """
    template = (ROOT / ".github" / "ISSUE_TEMPLATE" / "verification-failed.yml").read_text("utf-8")
    for required in ("verdict.codes()", "transport", "signingCredential.untrusted", "UNMARKED"):
        assert required in template, f"the template no longer asks about: {required}"


def test_the_changelog_records_what_was_evaluated_and_rejected() -> None:
    """The section that preempts "why didn't you just use X?" permanently.

    Each entry cost real investigation; losing them means re-litigating a decision
    whose evidence nobody wrote down.
    """
    changelog = (ROOT / "CHANGELOG.md").read_text("utf-8")
    assert "Evaluated but rejected" in changelog
    for rejected in ("c2pa-python", "cbor2", "pycose", "12,006"):
        assert rejected in changelog, f"the rationale for rejecting {rejected} is gone"
