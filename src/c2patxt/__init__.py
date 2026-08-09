"""
Embed, extract and verify C2PA Content Credentials in plain Unicode text.

Implements C2PA Technical Specification 2.4 (2026-04-01), HTML build ``c7e55d5a``,
Annex A.8 "Embedding Manifests into Unstructured Text": a ``C2PATextManifestWrapper``
encoded as Unicode variation selectors, prefixed with U+FEFF and appended after the
visible text. The package name is the wrapper's own magic number --
``0x4332504154585400``, ASCII ``"C2PATXT\\0"`` (A.8.2.2).

This is Duale AI's implementation of C2PA text marking. It is not a C2PA consortium
release and carries no conformance certification; see the README for what is and is
not claimed.

Package-owned verification performs no network access, consults no credential store
or ambient configuration, and emits no log records. It is a pure function of its
arguments when the caller supplies ``VerifyContext.now`` and an offline deterministic
trust evaluator; with the defaults it reads the clock because certificate validity is
judged at validation time (15.8).

Usage::

    from c2patxt import Disclosure, ModelType, Provenance, Signer, embed, verify

    marked = embed(
        text,
        Signer(private_key=key, certificates=(leaf,)),
        Disclosure(media_type="text/plain", model_type=ModelType.GENERIC),
    )

``marked`` is ``NFC(text)`` followed by selectors designed to be visually
non-rendering, and carries a signed Content Credential any third party can check::

    from c2patxt import Provenance, verify

    result = verify(suspicious_text)
    match result.state:
        case Provenance.TRUSTED:
            ...  # signature verifies and chains to an anchor you supplied
        case Provenance.VALID:
            ...  # signature and normalized-text binding validate; signer not corroborated
        case Provenance.INVALID:
            ...  # a mark is present and failed validation
        case Provenance.UNMARKED:
            ...  # no mark. This is NOT a negative finding about the text.

A ``VALID`` result carrying ``signingCredential.untrusted`` is the EXPECTED outcome
for a self-signed credential and is not an error. Trust is evaluated only against
anchors the caller supplies, and this package bundles none.

``Verdict`` is deliberately not boolean-convertible: ``bool(verdict)`` raises, because
``"CLEAN" if verdict else "FAKE"`` would render unmarked text as forged. Branch on
``.state``, or call ``.at_least(Provenance.VALID)`` and name your threshold.

Anything not in ``__all__`` is private and may change without notice.
"""

from __future__ import annotations

from importlib.metadata import version

from c2patxt._embed import AlreadyMarkedError, EmbedContext, embed
from c2patxt._extract import extract
from c2patxt._locate import Span, locate, strip
from c2patxt._verify import VerifyContext, verify
from c2patxt.constants import MAX_CBOR_DEPTH, MAX_MANIFEST_LENGTH, MAX_NONSTARTERS, MAX_SELECTOR_RUN
from c2patxt.exceptions import C2paTextError, MarkCorruptError, TextNormalizationError, UnencodableTextError
from c2patxt.manifest import ManifestStore
from c2patxt.signing import C2PA_CLAIM_SIGNING_EKU, MODEL_TYPES, Disclosure, ModelType, Signer
from c2patxt.status import Status, StatusCode, StatusKind
from c2patxt.trust import ProfileError, TrustEvaluator
from c2patxt.verdict import Provenance, Verdict

__all__ = [
    "C2PA_CLAIM_SIGNING_EKU",
    # The four component bounds. There is deliberately no input-length bound, so the
    # caller still owns request-body limiting.
    "MAX_CBOR_DEPTH",
    "MAX_MANIFEST_LENGTH",
    "MAX_NONSTARTERS",
    "MAX_SELECTOR_RUN",
    "MODEL_TYPES",
    "AlreadyMarkedError",
    "C2paTextError",
    "Disclosure",
    "EmbedContext",
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
]

__version__ = version("c2patxt")
__version_full__ = "dev"
