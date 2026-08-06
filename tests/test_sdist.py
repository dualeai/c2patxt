"""The sdist must carry a suite that actually runs.

release.yml sells the sdist as the artefact that "lets an auditor diff shipped source
against the git tag with no rebuild". The obvious next thing an auditor does is run
the tests. setuptools' default sdist picks up ``tests/test_*.py`` and drops
``tests/conftest.py``, ``tests/__init__.py``, ``tests/_json.py`` and the entire
``tests/vectors/`` tree, so every test needing a fixture or a vector corpus dies on
import.

Shipping a suite that cannot run is worse than shipping none: it invites the one
check we most want an auditor to perform and then fails in a way that looks like our
code is broken.

WHAT IS CHECKED HERE IS THE CONTENTS, NOT A RUN. Unpacking the sdist and executing the
whole suite inside it costs 15.3 s of a 22 s run -- every test a second time -- and
makes OTHER tests lie: under ``-x`` the subprocess is reported as the failure instead
of the test that names the rule; under ``--deselect`` it does not inherit the flag, so
a selective probe reports kills it has not earned; and on a cold ``uv`` cache it
resolves the package to the archive cache rather than ``src/``, turning the default
target red. The files it would prove present are asserted directly below, in under a
second.
"""

from __future__ import annotations

import pathlib
import subprocess
import tarfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Files the suite cannot start without, each one absent before MANIFEST.in existed.
_REQUIRED = (
    "tests/conftest.py",
    "tests/__init__.py",
    "tests/_json.py",
    "tests/vectors/__init__.py",
    "tests/vectors/loader.py",
)


@pytest.fixture(scope="session")
def sdist(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Build the sdist once and return the unpacked tree."""
    out = tmp_path_factory.mktemp("sdist")
    subprocess.run(  # noqa: S603
        ["uv", "build", "--sdist", "--out-dir", str(out)],  # noqa: S607
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    archives = sorted(out.glob("*.tar.gz"))
    assert len(archives) == 1, f"expected exactly one sdist, got {archives}"

    with tarfile.open(archives[0]) as archive:
        archive.extractall(out, filter="data")
    unpacked = sorted(p for p in out.iterdir() if p.is_dir())
    assert len(unpacked) == 1, f"expected one unpacked tree, got {unpacked}"
    return unpacked[0]


@pytest.mark.parametrize("required", _REQUIRED)
def test_the_sdist_carries_what_the_suite_needs(sdist: pathlib.Path, required: str) -> None:
    """Each of these was missing, and each one alone breaks collection entirely."""
    assert (sdist / required).exists(), f"{required} is absent from the sdist"


def test_the_sdist_carries_the_conformance_vectors(sdist: pathlib.Path) -> None:
    """The vector corpus is the thing we offer C2PA and C2SP; an sdist without it
    cannot demonstrate the claim the vectors exist to support."""
    vectors = sdist / "tests" / "vectors"
    assert sorted(p.name for p in vectors.glob("A8ConformanceTest-*.txt"))
    assert (vectors / "cbor").is_dir()


def test_the_sdist_carries_the_documentation(sdist: pathlib.Path) -> None:
    """The conformance claim and the deviations list are the documents an auditor
    came for; shipping source without them ships the answer without the question."""
    docs = sdist / "docs"
    assert (docs / "c2pa-compatibility.md").exists()
    assert (docs / "deviations.md").exists()


def test_the_sdist_carries_no_compiled_artefacts(sdist: pathlib.Path) -> None:
    """A .pyc in a source distribution is unreproducible ballast, and one that
    disagrees with its .py is actively misleading to someone diffing against a tag."""
    assert list(sdist.rglob("*.pyc")) == []
    assert list(sdist.rglob("__pycache__")) == []
