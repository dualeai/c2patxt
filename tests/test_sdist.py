"""The sdist must carry a suite that actually runs.

release.yml sells the sdist as the artefact that "lets an auditor diff shipped source
against the git tag with no rebuild". The obvious next thing an auditor does is run
the tests. Before 2026-08-05 that produced a wall of collection errors: setuptools'
default sdist picked up ``tests/test_*.py`` but dropped ``tests/conftest.py``,
``tests/__init__.py``, ``tests/_json.py`` and the entire ``tests/vectors/`` tree, so
every test needing a fixture or a vector corpus died on import.

Shipping a suite that cannot run is worse than shipping none: it invites the one
check we most want an auditor to perform and then fails in a way that looks like our
code is broken.
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


@pytest.mark.timeout(600)
def test_the_suite_in_the_sdist_actually_passes(sdist: pathlib.Path) -> None:
    """THE TEST THAT MATTERS. Everything above checks for files; this runs them.

    Coverage and xdist are disabled: the auditor's environment is not ours, and a
    coverage threshold failing in their checkout would tell them nothing about the
    source they are auditing.

    test_sdist.py and test_leaf_rule.py are DESELECTED from the inner run, and the
    reason is not tidiness -- both shell out to ``uv build``, so an inner run that
    included this very test would build an sdist, unpack it, and run the suite again,
    forever. The first version of this test did exactly that and hit the 600s timeout
    rather than failing on anything about the sdist. What is under test here is the
    packaged SOURCE, and packaging tests are about the repository.
    """
    # "uv" is resolved from PATH deliberately: this test asks whether an AUDITOR's
    # environment can run the shipped suite, and an auditor has uv on their path, not
    # at ours.
    command = [
        "uv",
        "run",
        "--no-project",
        # "." installs the unpacked sdist itself, which also proves it BUILDS.
        "--with",
        ".",
        # pytest-timeout is required, not optional: pyproject registers
        # @pytest.mark.timeout, and without the plugin the inner run warns on an
        # unknown mark and every per-test timeout silently does not apply.
        "--with",
        "pytest",
        "--with",
        "pytest-socket",
        "--with",
        "pytest-timeout",
        "--with",
        "hypothesis",
        "--with",
        "cbor2",
        "python",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-q",
        "-p",
        "no:cov",
        "-o",
        "addopts=",
        "--disable-socket",
        # Deselected because both shell out to `uv build`. Including this very test
        # would build an sdist, unpack it, and run the suite again, forever -- the
        # first version did exactly that and hit the 600s timeout rather than failing
        # on anything about the sdist.
        "--ignore=tests/test_sdist.py",
        "--ignore=tests/test_leaf_rule.py",
        # Benchmarks import pytest-codspeed, which an auditor has no reason to install
        # and which this command deliberately does not provide. Without this the inner
        # run dies at COLLECTION -- one ModuleNotFoundError aborts the whole suite, so
        # the sdist would look broken over a benchmarking plugin.
        #
        # It passed without this line for a while, and the reason is worth knowing: the
        # subprocess inherits VIRTUAL_ENV from the developer's shell, so `uv run` layered
        # on top of an environment that already had the plugin. Run from a clean shell --
        # an auditor's situation, which is the whole point of this test -- it failed.
        "--ignore=tests/benchmarks",
        "tests",
    ]
    result = subprocess.run(command, cwd=sdist, capture_output=True, text=True, check=False)  # noqa: S603

    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
