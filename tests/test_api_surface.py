"""The exact public import surface."""

from __future__ import annotations

import base64

import c2patxt
from tests.conftest import mark


def test_the_documented_usage_actually_imports() -> None:
    """Every name used by the module docstring's public example is importable."""
    from c2patxt import Provenance, Verdict, locate

    assert Provenance.UNMARKED.value == "unmarked"
    assert locate("no mark here") is None
    assert Verdict(state=Provenance.UNMARKED).state is Provenance.UNMARKED


def test_every_exported_name_resolves() -> None:
    """__all__ is a promise; a name in it that does not exist is a broken one."""
    missing = [name for name in c2patxt.__all__ if not hasattr(c2patxt, name)]
    assert missing == []


def test_the_surface_is_exactly_what_we_intend() -> None:
    """Adding or removing a public name changes the package contract."""
    assert set(c2patxt.__all__) == {
        "AlreadyMarkedError",
        "C2PA_CLAIM_SIGNING_EKU",
        "MAX_CBOR_DEPTH",
        "MAX_MANIFEST_LENGTH",
        "MAX_NONSTARTERS",
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
        "TextNormalizationError",
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


def test_public_verification_loads_no_owned_trust_backend_or_http_stack(signer: c2patxt.Signer) -> None:
    """The default public path stays offline and leaves the optional backend unloaded."""
    import subprocess
    import sys

    code = """
import base64
import sys

def reject_network(event, args):
    del args
    if event.startswith("socket."):
        raise AssertionError(f"package-owned verification attempted network access: {event}")

sys.addaudithook(reject_network)
import c2patxt
marked = base64.b64decode(sys.stdin.buffer.read()).decode("utf-8")
assert c2patxt.verify(marked).state is c2patxt.Provenance.VALID
for module in ("pyhanko_certvalidator", "requests", "oscrypto", "uritools", "aiohttp"):
    assert module not in sys.modules, module
print("ok")
"""
    encoded = base64.b64encode(mark("Hello world.", signer).encode("utf-8"))
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], input=encoded, capture_output=True, check=True
    )
    assert result.stdout.strip() == b"ok"


def test_every_exported_error_type_joins_the_public_error_hierarchy() -> None:
    """A caller can catch every named public package error as ``C2paTextError``.

    This asserts the exported type hierarchy, not the stronger and unprovable claim
    that introspecting exception classes can detect every runtime escape. Hostile
    public calls are tested in the suites that own those entry points.
    """
    exported = {name: getattr(c2patxt, name) for name in c2patxt.__all__}
    public_errors = {
        name: obj for name, obj in exported.items() if isinstance(obj, type) and issubclass(obj, BaseException)
    }
    assert public_errors, "no exceptions are exported; the check is vacuous"

    outside = sorted(n for n, obj in public_errors.items() if not issubclass(obj, c2patxt.C2paTextError))
    assert outside == [], f"exported but outside C2paTextError: {outside}"

    assert {name for name in public_errors} == {
        "AlreadyMarkedError",
        "C2paTextError",
        "MarkCorruptError",
        "ProfileError",
        "TextNormalizationError",
        "UnencodableTextError",
    }


def test_every_structured_public_error_survives_pickling() -> None:
    """Public exception attributes and messages survive a worker-process boundary."""
    import pickle

    errors = (
        c2patxt.AlreadyMarkedError(3, 9),
        c2patxt.MarkCorruptError("broken", 5, 12, c2patxt.StatusCode.CLAIM_MALFORMED),
        c2patxt.ProfileError("certificate profile"),
        c2patxt.TextNormalizationError(7),
        c2patxt.UnencodableTextError(11),
    )
    revived_errors = tuple(
        pickle.loads(pickle.dumps(original))  # noqa: S301 -- package-owned values
        for original in errors
    )
    for original, revived in zip(errors, revived_errors, strict=True):
        assert type(revived) is type(original)
        assert str(revived) == str(original)

    marked = revived_errors[0]
    corrupt = revived_errors[1]
    assert isinstance(marked, c2patxt.AlreadyMarkedError)
    assert marked.span == (3, 9)
    assert isinstance(corrupt, c2patxt.MarkCorruptError)
    assert (corrupt.pos, corrupt.document_length, corrupt.code) == (
        5,
        12,
        c2patxt.StatusCode.CLAIM_MALFORMED,
    )
