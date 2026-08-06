"""The leaf rule, and what the built wheel actually contains.

THE PROMISE: this package has NO internal dependency on any `duale_*` package, ever.
That is not a style preference. The entire compliance argument rests on a third party
with no relationship to us being able to `pip install c2patxt` and check a document
for themselves. An internal dependency would make the verifier unavailable to exactly
the people Article 50(2) exists for.

These build a real wheel rather than inspecting the source tree, because the source
tree is not what ships. `py.typed` present in `src/` proves nothing about whether
setuptools put it in the archive.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import zipfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Any package name matching these must never appear as a dependency, in the default
#: install or in ANY extra.
_INTERNAL_PREFIXES = ("duale", "duale_", "duale-", "dualeai")


@pytest.fixture(scope="session")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """Build the wheel once, and inspect THAT.

    Built into a temp directory rather than reusing ``dist/``, which may hold a stale
    artefact from an earlier version and would make these tests assert about a build
    nobody is about to ship.
    """
    out = tmp_path_factory.mktemp("wheel")
    subprocess.run(  # noqa: S603
        ["uv", "build", "--wheel", "--out-dir", str(out)],  # noqa: S607
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    built = sorted(out.glob("*.whl"))
    assert len(built) == 1, f"expected exactly one wheel, got {built}"
    return built[0]


def test_no_internal_package_is_a_dependency_in_any_extra() -> None:
    """THE LEAF RULE. Checked across the default install and every extra.

    An extra is still something a user installs; a duale_* package hiding behind
    `[trust]` would break the promise for anyone who opted in.
    """
    from importlib.metadata import requires

    for requirement in requires("c2patxt") or []:
        name = requirement.split()[0].split(";")[0].split("[")[0].split("~")[0].split("=")[0].lower()
        assert not name.startswith(_INTERNAL_PREFIXES), f"internal dependency declared: {requirement}"


def test_no_internal_package_is_reachable_after_import() -> None:
    """Belt and braces: nothing pulls an internal package in at import time either.

    A dependency can arrive without being declared -- a stray import of something
    already on the path in our own environment would pass the metadata check above
    and fail on a clean machine.
    """
    code = (
        "import c2patxt, sys;"
        "bad=[m for m in sys.modules if m.split('.')[0].lower().startswith(('duale','dualeai'))];"
        "assert not bad, bad;"
        "print('clean')"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "clean"


def test_the_optional_trust_backend_is_not_imported_by_default() -> None:
    """`pip install c2patxt` must not drag in the [trust] extra's import cost, and
    must not silently behave differently depending on whether it happens to be
    installed in the caller's environment."""
    code = "import c2patxt, sys; assert 'pyhanko_certvalidator' not in sys.modules; print('clean')"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "clean"


def test_the_wheel_carries_py_typed(wheel: pathlib.Path) -> None:
    """PEP 561: without this file in the ARCHIVE, every caller's type checker treats
    the package as untyped, and the strict typing throughout buys them nothing."""
    names = zipfile.ZipFile(wheel).namelist()
    assert any(name.endswith("c2patxt/py.typed") for name in names), names


def test_the_wheel_carries_no_test_vectors(wheel: pathlib.Path) -> None:
    """The vector corpus is a REPO artefact, not a package artefact.

    It is several hundred kilobytes that no caller executes, and shipping it would
    imply the package validates itself at runtime, which it does not.
    """
    names = zipfile.ZipFile(wheel).namelist()
    assert [n for n in names if "vectors" in n] == []
    assert [n for n in names if n.endswith((".cbor", ".edn"))] == []


def test_the_wheel_carries_no_trust_anchors(wheel: pathlib.Path) -> None:
    """We ship ZERO anchors, deliberately -- see trust.py. A .pem in the wheel would
    make TRUSTED reachable without the caller ever choosing whom to trust."""
    names = zipfile.ZipFile(wheel).namelist()
    assert [n for n in names if n.endswith((".pem", ".crt", ".der"))] == []


def test_the_wheel_contains_the_package_and_not_the_tests(wheel: pathlib.Path) -> None:
    """A wheel shipping tests/ would put our fixtures on the caller's import path."""
    names = zipfile.ZipFile(wheel).namelist()
    assert any(name.endswith("c2patxt/__init__.py") for name in names)
    assert [n for n in names if n.startswith("tests/")] == []
