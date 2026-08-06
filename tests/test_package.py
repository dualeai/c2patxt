"""Package-level smoke tests: the surface exists, is typed, and imports cleanly."""

from __future__ import annotations

import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import build_certificate


def test_version_is_importable() -> None:
    """__version__ resolves from installed metadata, not a hardcoded literal."""
    import c2patxt

    assert isinstance(c2patxt.__version__, str)
    assert c2patxt.__version__ != ""


def test_import_pulls_no_optional_trust_backend() -> None:
    """Importing the package must not drag in the [trust] extra.

    The default install reaches C2PA state "Valid" with cryptography alone;
    pyhanko-certvalidator is only needed to reach "Trusted". If a plain import
    pulled it in, the leaf rule and the dependency claim in the README would both
    be false.
    """
    code = "import c2patxt, sys; print('pyhanko_certvalidator' in sys.modules)"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False"


def test_no_log_records_are_emitted_while_doing_real_work(caplog: pytest.LogCaptureFixture) -> None:
    """This library emits NO log records, ever -- asserted over actual codec work.

    The detection surface is required to expose "a verdict and the manifest
    fields only, with no similarity score or partial-match detail". A library that
    logged intermediate hash comparisons, candidate wrapper offsets, or certificate
    subjects would undercut that guarantee from underneath, inside a process the
    detection service does not control.

    Exercised across embed, verify and a deliberate corruption rather than over a
    version-string read: the paths that HAVE something interesting to leak are the
    only ones where silence is worth asserting. Captured at the ROOT logger, so a
    record emitted under any name is caught, not only ones under ``c2patxt``.
    """
    import c2patxt

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = c2patxt.Signer(private_key=key, certificates=(build_certificate(key),))
    disclosure = c2patxt.Disclosure(media_type="text/plain", model_type=c2patxt.ModelType.GENERIC)

    with caplog.at_level("DEBUG"):
        marked = c2patxt.embed("Hello world.", signer, disclosure)
        c2patxt.verify(marked)
        c2patxt.verify(marked.replace("Hello", "Hellp", 1))
        c2patxt.verify("no mark here")

    assert caplog.records == []


def test_the_package_declares_exactly_one_runtime_dependency() -> None:
    """SECURITY.md makes this claim; this is what makes it a claim rather than a hope.

    A verification library's dependency count is part of its threat model: every
    runtime dependency is code that runs inside the caller's process on
    attacker-supplied input. The claim was previously "asserted in CI" by nothing at
    all, and the command it pointed readers at (`uv tree --no-dev`) is a no-op here
    because the dev set is an extra rather than a dependency group.

    Extras are excluded deliberately -- `[trust]` is opt-in and is not installed by
    `pip install c2patxt`.
    """
    from importlib.metadata import requires

    declared = requires("c2patxt") or []
    runtime = sorted(r for r in declared if "extra ==" not in r)
    assert runtime == ["cryptography~=48.0"], f"runtime dependency set changed: {runtime}"
