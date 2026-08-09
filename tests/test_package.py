"""Public codec operations stay silent under the caller's logging setup."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.conftest import build_certificate


def test_public_codec_work_emits_no_log_records(caplog: pytest.LogCaptureFixture) -> None:
    """Public embed and verification paths stay silent under real codec work.

    The detection surface is required to expose "a verdict and the manifest
    fields only, with no similarity score or partial-match detail". A library that
    logged intermediate hash comparisons, candidate wrapper offsets, or certificate
    subjects would undercut that guarantee from underneath, inside a process the
    detection service does not control.

    Exercised across embed, valid and invalid verification, and absence rather than a
    version-string read. Captured at the root logger, so a record emitted under any
    name is caught, not only one under ``c2patxt``.
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
