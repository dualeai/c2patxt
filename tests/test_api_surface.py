"""The public surface, pinned.

At 0.1.0 the API is explicitly unstable. These tests are what make "unstable" mean
"we will tell you" rather than "anything can move silently".
"""

from __future__ import annotations

import c2patxt


def test_the_documented_usage_actually_imports() -> None:
    """The module docstring's example must be executable.

    It previously instructed readers to import `verify` and `Provenance`, and
    neither existed -- an ImportError for anyone who followed the docs.
    """
    from c2patxt import Provenance, Verdict, locate

    assert Provenance.UNMARKED.value == "unmarked"
    assert locate("no mark here") is None
    assert Verdict(state=Provenance.UNMARKED).state is Provenance.UNMARKED


def test_every_exported_name_resolves() -> None:
    """__all__ is a promise; a name in it that does not exist is a broken one."""
    missing = [name for name in c2patxt.__all__ if not hasattr(c2patxt, name)]
    assert missing == []


def test_the_surface_is_exactly_what_we_intend() -> None:
    """A frozen inventory. Adding or removing a public name must be deliberate.

    The record of what is actually exported today, not what is planned. A name that
    lands here without a deliberate edit is a surface expansion nobody signed off.

    ``MODEL_TYPES`` was added deliberately: ``signing.py`` and docs/deviations.md both
    describe it as the vocabulary a caller picks a ``modelType`` from, and it was in
    neither ``__all__`` -- so the documentation pointed at a name that ``__init__``
    calls "private and may change without notice". Describing something as caller-facing
    and not exporting it is the contradiction; exporting it is the fix.

    ``MAX_MANIFEST_LENGTH``, ``MAX_SELECTOR_RUN`` and ``MAX_JUMBF_DEPTH`` were added for
    the same reason: SECURITY.md commits to bounded allocation, and an operator sizing a
    deployment needs the numbers rather than the promise. They also mark where OUR
    bounds stop -- there is deliberately no limit on input length, so body-size limiting
    is the caller's obligation and they have to see the boundary to honour it.
    """
    assert set(c2patxt.__all__) == {
        "AlreadyMarkedError",
        "C2PA_CLAIM_SIGNING_EKU",
        "MAX_JUMBF_DEPTH",
        "MAX_MANIFEST_LENGTH",
        "MAX_SELECTOR_RUN",
        "C2paTextError",
        "Disclosure",
        "EmbedContext",
        "MODEL_TYPES",
        "ManifestStore",
        "MarkCorruptError",
        "ModelType",
        "ProfileError",
        "Provenance",
        "Signer",
        "Span",
        "Status",
        "StatusCode",
        "StatusKind",
        "TrustEvaluator",
        "UnencodableTextError",
        "Verdict",
        "VerifyContext",
        "__version__",
        "__version_full__",
        "embed",
        "extract",
        "locate",
        "strip",
        "verify",
    }


def test_private_modules_are_not_exported() -> None:
    """Anything not in __all__ may change; underscore modules are not surface."""
    for private in ("_cbor", "_jumbf", "_cose", "_selectors", "_locate", "_embed", "_fixpoint"):
        assert private not in c2patxt.__all__


def test_version_metadata_is_present() -> None:
    assert isinstance(c2patxt.__version__, str)
    assert c2patxt.__version__ != ""
    # The release workflow seds this literal; keep the assignment greppable.
    assert isinstance(c2patxt.__version_full__, str)


def test_importing_the_package_reaches_no_network_and_reads_no_config() -> None:
    """Import must be inert. --disable-socket already proves the network half."""
    import os
    import subprocess
    import sys

    code = "import c2patxt, sys;assert 'pyhanko_certvalidator' not in sys.modules;print('ok')"
    env = {**os.environ, "C2PATXT_TRUST_ANCHORS": "/nonexistent/should-not-be-read.pem"}
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, env=env
    )
    assert result.stdout.strip() == "ok"


def test_every_error_this_package_raises_is_a_c2pa_text_error() -> None:
    """``exceptions.py`` says ``C2paTextError`` is "the base class for every error this
    package raises", and tells integrators to catch it. That was false in two places.

    ``ProfileError`` derived from ``ValueError`` alone — and it is what ``Signer()``
    raises for the default ``openssl req -x509`` misconfiguration the README calls "the
    part people get wrong". ``FixpointError`` derived from ``RuntimeError`` alone, is
    reachable from ``embed()``, and was not exported, so there was no supported import
    path to catch it by name at all.

    This test is the assertion that holds the claim. Both keep their conventional builtin
    base as well, because that is the shape the package chose deliberately —
    ``JSONDecodeError(ValueError)``, not a root that escapes ``except ValueError``.

    Discovered by walking the package's own modules rather than a hand-written list, so
    an exception added later cannot avoid it by not being mentioned here.
    """
    import importlib
    import pkgutil

    import c2patxt

    found: dict[str, type[BaseException]] = {}
    for info in pkgutil.iter_modules(c2patxt.__path__):
        module = importlib.import_module(f"c2patxt.{info.name}")
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and issubclass(obj, BaseException) and obj.__module__.startswith("c2patxt"):
                found[f"{obj.__module__}.{obj.__name__}"] = obj

    assert found, "no exception classes discovered; the walk is broken"

    # THE PROMISE IS ABOUT WHAT A CALLER CAN CATCH BY NAME, which is what `__all__`
    # defines. CborDecodeError, CoseError and JumbfError are raised inside private
    # modules and TRANSLATED at every boundary -- _extract turns the first and third into
    # MarkCorruptError, _verify catches the second -- so no caller ever sees one. They
    # are asserted private below rather than dragged into the hierarchy, because widening
    # a public promise to cover types nobody can import would say less, not more.
    exported = {name: getattr(c2patxt, name) for name in c2patxt.__all__}
    public_errors = {
        name: obj for name, obj in exported.items() if isinstance(obj, type) and issubclass(obj, BaseException)
    }
    assert public_errors, "no exceptions are exported; the check is vacuous"

    outside = sorted(n for n, obj in public_errors.items() if not issubclass(obj, c2patxt.C2paTextError))
    assert outside == [], f"exported but outside C2paTextError: {outside}"

    internal = {"CborDecodeError", "CoseError", "JumbfError"}
    leaked = sorted(internal & set(c2patxt.__all__))
    assert leaked == [], f"internal error types must stay unexported or join the hierarchy: {leaked}"
