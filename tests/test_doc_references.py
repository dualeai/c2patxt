"""Resolve links, repository paths and vector filenames in repository documentation.

This checks file and symbol identity. It does not grade prose or infer whether a cited
file supports the sentence that names it.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "vectors"

#: Files named in the vector documentation that belong to somebody else. Unicode's
#: NormalizationTest.txt is the format our own vector file is modelled on.
_NOT_OURS = frozenset({"NormalizationTest.txt"})

#: Every Markdown document tracked in the repository. Package contents are owned by
#: setuptools and the release workflow, as in hpke-http; this is not an sdist inventory.
DOCUMENTS = sorted(
    path
    for path in ROOT.rglob("*.md")
    if not any(part.startswith(".") or part in {"build", "dist", "htmlcov", "node_modules"} for part in path.parts)
)

#: ``[text](target)`` where target is not a URL, a mailto, or a bare in-page anchor.
_RELATIVE_LINK = re.compile(r"\[[^\]]*\]\((?!https?://|mailto:|#)([^)\s]+)\)")

#: A backticked token naming a file in THIS repository: it starts at one of our own
#: top-level directories and ends in an extension we ship.
#:
#: Anchored so paths quoted from external specifications and repositories are not
#: mistaken for files in this checkout.
_REPO_PATH = re.compile(
    r"`((?:src|tests|docs|tools|cicd|\.github)/[A-Za-z0-9_./-]*[A-Za-z0-9_-]"
    r"\.(?:py|md|txt|json|toml|yml|cbor|edn|pem))(?:\:\:([A-Za-z_][A-Za-z0-9_]*))?`"
)

#: A bare filename or glob, resolved against the document's OWN directory.
#:
#: This covers provenance references such as `mt7.cbor` and `sign1-*`, which the
#: repository-qualified pattern above does not match.
#:
#: Applied only under tests/vectors/, where a bare name means a file beside the
#: provenance or vector document. Shipped docs use repository-qualified paths.
#: Restricted to data extensions and globs without a slash, so a media type like
#: `text/*` and a clause like `A.8.7.3` are not mistaken for files.
_LOCAL_FILE = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:cbor|edn|json|pem|txt))`")
_LOCAL_GLOB = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_-]*\*[A-Za-z0-9_.-]*)`")


def _document_ids() -> list[str]:
    return [str(path.relative_to(ROOT)) for path in DOCUMENTS]


def _resolve_path(document: pathlib.Path, name: str) -> pathlib.Path | None:
    for candidate in (ROOT / name, document.parent / name):
        if candidate.exists():
            return candidate
    return None


def _has_top_level_symbol(path: pathlib.Path, symbol: str) -> bool:
    tree = ast.parse(path.read_text("utf-8"), filename=str(path))
    return any(
        isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and node.name == symbol
        for node in tree.body
    )


@pytest.mark.parametrize("document", DOCUMENTS, ids=_document_ids())
def test_every_relative_link_resolves(document: pathlib.Path) -> None:
    """A link to a file we moved or deleted is a dead end for whoever follows it."""
    broken = [
        target
        for target in _RELATIVE_LINK.findall(document.read_text("utf-8"))
        if not (document.parent / target.split("#", 1)[0]).exists()
    ]
    assert not broken, f"{document.relative_to(ROOT)} links to missing: {broken}"


@pytest.mark.parametrize("document", DOCUMENTS, ids=_document_ids())
def test_every_backticked_repository_path_exists(document: pathlib.Path) -> None:
    """The half that catches a provenance file naming a vector that is not there."""
    text = document.read_text("utf-8")
    missing: list[str] = []
    for name, symbol in _REPO_PATH.findall(text):
        path = _resolve_path(document, name)
        if path is None:
            missing.append(name)
        elif symbol and (path.suffix != ".py" or not _has_top_level_symbol(path, symbol)):
            missing.append(f"{name}::{symbol}")
    if VECTORS in document.parents:
        missing += [
            name
            for name in _LOCAL_FILE.findall(text)
            if name not in _NOT_OURS and not (document.parent / name).exists()
        ]
        missing += [pattern for pattern in _LOCAL_GLOB.findall(text) if not any(document.parent.glob(pattern))]
    assert not missing, f"{document.relative_to(ROOT)} names missing paths: {sorted(set(missing))}"
