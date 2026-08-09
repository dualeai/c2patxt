"""Append a signed C2PA Annex A.8 Content Credential to plain text.

The producer first normalizes the visible text to NFC, then appends the wrapper as a
suffix. This makes the hard-binding offsets and the bytes hashed by the validator refer
to the same normalized text.

With a fixed signer, disclosure, normalized input and fully resolved
:class:`EmbedContext`, Ed25519 produces stable signed bytes. Context fields left unset
generate a new manifest UUID, instance ID or creation time.

``embed`` accepts a :class:`Disclosure` rather than arbitrary assertions, so every
field this producer emits remains part of its explicit schema.
"""

from __future__ import annotations

import dataclasses
import datetime
import uuid
from collections.abc import Callable

from c2patxt._cose import (
    _prepare_signed_claim,  # pyright: ignore[reportPrivateUsage] -- producer-internal handoff
    _serialize_signed_claim,  # pyright: ignore[reportPrivateUsage] -- same handoff
)
from c2patxt._fixpoint import solve
from c2patxt._locate import find_wrappers
from c2patxt._normalization import normalize_nfc
from c2patxt._selectors import build_wrapper
from c2patxt.exceptions import C2paTextError
from c2patxt.manifest import (
    DEFAULT_HASH_ALGORITHM,
    HASH_ALGORITHMS,
    _prepare_manifest,  # pyright: ignore[reportPrivateUsage] -- both modules are producer internals
    _serialize_prepared_manifest,  # pyright: ignore[reportPrivateUsage] -- same producer boundary
)
from c2patxt.signing import Disclosure, Signer

# ``max-tstr-length`` in the C2PA 2.4 CDDL schemas. CDDL ``.size`` on a text
# string counts its UTF-8 bytes (RFC 8610 3.8.1), not Python code points.
_MAX_TSTR_LENGTH = 1_000_000
_UUID_VERSION = 4


class AlreadyMarkedError(C2paTextError, ValueError):
    """``embed`` was called on text that already carries a wrapper.

    This is a producer policy: appending could introduce an ambiguous second matching
    wrapper, while replacing would discard another producer's signed claim. Validation
    rejects multiple wrappers only when more than one matches the declared exclusion.

    Attributes:
        span: byte range of the wrapper already present. Use :func:`strip` to remove
            it -- these are BYTE offsets, and slicing a ``str`` with them silently
            corrupts any non-ASCII document.
    """

    def __init__(self, utf8_start: int, utf8_stop: int) -> None:
        self.span = (utf8_start, utf8_stop)
        super().__init__(
            f"text already carries a Content Credential at bytes {utf8_start}-{utf8_stop}; "
            "call strip() first if you mean to re-mark it, or leave it alone"
        )

    def __reduce__(self) -> tuple[type[AlreadyMarkedError], tuple[int, int]]:
        return (self.__class__, self.span)


def _default_when() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


@dataclasses.dataclass(frozen=True, slots=True)
class EmbedContext:
    """Manifest identity, time and hard-binding choices for :func:`embed`.

    The defaults do the normal thing -- a fresh UUID, a fresh instance ID, the
    current time -- so ordinary callers never touch this. Pin all three to make context
    resolution stable; reproducible output also requires the same text, signer and
    disclosure.
    """

    manifest_uuid: uuid.UUID | None = None
    """Identifies THIS manifest (8.1). Fresh per manifest by default. Reusing one
    across different documents is a correctness error, not merely untidy."""

    instance_id: str | None = None
    """The claim's required ``instanceID``. Defaults to a fresh ``xmp:iid:`` URN."""

    when: datetime.datetime | None = None
    """Claimed creation time, recorded in ``c2pa.created``. Defaults to now, UTC.
    Pin it only when replaying a known event or building a deterministic fixture. A
    naive datetime is rejected rather than assumed to be UTC."""

    generator_name: str = "c2patxt"
    """Value for ``claim_generator_info.name``. Intended to name the software."""

    generator_version: str | None = None
    """Optional generator version. Left unset by default -- it is not needed for
    validation, and pinning a version into signed bytes makes every release produce
    different output for identical input."""

    algorithm: str = DEFAULT_HASH_ALGORITHM
    """Hash algorithm for the hard binding. 13.1 permits sha256, sha384 and sha512
    and states implementations "shall not support additional algorithms"."""

    def __post_init__(self) -> None:
        if self.manifest_uuid is not None and (
            self.manifest_uuid.variant != uuid.RFC_4122 or self.manifest_uuid.version != _UUID_VERSION
        ):
            msg = "EmbedContext.manifest_uuid must be an RFC 4122 variant UUID version 4 (C2PA 8.1)"
            raise ValueError(msg)
        try:
            generator_name_size = len(self.generator_name.encode("utf-8"))
        except (AttributeError, UnicodeEncodeError) as exc:
            msg = "EmbedContext.generator_name must be a UTF-8 text string"
            raise ValueError(msg) from exc
        if not 1 <= generator_name_size <= _MAX_TSTR_LENGTH:
            msg = "EmbedContext.generator_name must contain 1 to 1,000,000 UTF-8 bytes (C2PA generator-info-map)"
            raise ValueError(msg)

    def resolve(self) -> tuple[uuid.UUID, str, datetime.datetime]:
        """Fill in the defaults, once, so a single embed uses consistent values."""
        manifest_uuid = self.manifest_uuid or uuid.uuid4()
        instance_id = self.instance_id or f"xmp:iid:{uuid.uuid4()}"
        when = self.when or _default_when()
        if when.tzinfo is None or when.utcoffset() is None:
            msg = "EmbedContext.when must be timezone-aware; a naive datetime has no defined instant"
            raise ValueError(msg)
        return manifest_uuid, instance_id, when


def embed(text: str, signer: Signer, disclosure: Disclosure, *, context: EmbedContext | None = None) -> str:
    """Return ``text`` with a signed Content Credential appended.

    The visible text is returned in NFC form and the mark is appended after it as one
    contiguous run of variation selectors preceded by U+FEFF. The selectors are
    designed not to render, but rendering behavior belongs to the consuming text
    system rather than this codec.

    Args:
        text: the text to mark. Must not already carry a wrapper.
        signer: the Ed25519 key and its certificate chain.
        disclosure: what the AI-disclosure assertion states about the generating
            model. Carries no information about who ran it.
        context: pins the manifest UUID, instance ID and claimed creation time. Omit
            for normal use; supply it for reproducible output.

    Returns:
        ``unicodedata.normalize("NFC", text)`` followed by the A.8 wrapper.

    Raises:
        FixpointError: the bounded padding search found no exact wrapper length. A
            subclass of ``C2paTextError`` and ``RuntimeError``.
        ValueError: one certificate's validity period does not contain
            ``EmbedContext.when``.
        AlreadyMarkedError: ``text`` already carries a Content Credential.
        MarkCorruptError: ``text`` carries something that looks like a wrapper but is
            malformed. Marking on top of it would bury the damage.
        TextNormalizationError: ``text`` exceeds the 30-nonstarter normalization
            resource limit.
        UnencodableTextError: ``text`` holds an unpaired surrogate and cannot be
            encoded as UTF-8.
        ValueError: the algorithm is not one 13.1 permits, or ``context.when`` is
            naive.
    """
    if context is None:
        context = EmbedContext()
    if context.algorithm not in HASH_ALGORITHMS:
        msg = f"unsupported hash algorithm {context.algorithm!r}; C2PA 13.1 permits {sorted(HASH_ALGORITHMS)}"
        raise ValueError(msg)

    manifest_uuid, instance_id, when = context.resolve()

    # Signer checks the static 14.5.1.1 profile at construction. Validity is checked on
    # every embed against the supplied claimed creation instant; the default is the
    # current clock, while pinned contexts support deterministic replay. Verification
    # still judges the mark against its own validation clock under 15.8.
    for index, certificate in enumerate(signer.certificates):
        if certificate.not_valid_before_utc <= when <= certificate.not_valid_after_utc:
            continue
        role = "signing certificate" if index == 0 else f"x5chain[{index}] carried CA"
        msg = (
            f"the {role}'s validity period "
            f"({certificate.not_valid_before_utc.isoformat()} to {certificate.not_valid_after_utc.isoformat()}) "
            f"does not contain the claimed creation time {when.isoformat()}"
        )
        raise ValueError(msg)

    # Checked BEFORE normalization so the reported offsets refer to the caller's own
    # bytes rather than to a string they never had.
    existing = find_wrappers(text)
    if existing:
        raise AlreadyMarkedError(existing[0].span.utf8_start, existing[0].span.utf8_stop)

    normalized = normalize_nfc(text)
    encoded = normalized.encode("utf-8")
    # The mark is a suffix, so the bytes covered by the hash are exactly the visible
    # text -- 15.12.1.3.1's "remove the exclusions, then normalize" is a no-op here,
    # which is the whole reason for forcing suffix placement.
    digest = HASH_ALGORITHMS[context.algorithm](encoded).digest()
    exclusion_start = len(encoded)

    def prepare(exclusion_length: int) -> Callable[[int], str]:
        prepared = _prepare_manifest(
            disclosure=disclosure,
            digest=digest,
            exclusion_start=exclusion_start,
            exclusion_length=exclusion_length,
            instance_id=instance_id,
            when=when,
            generator_name=context.generator_name,
            generator_version=context.generator_version,
            algorithm=context.algorithm,
            pad=b"",
        )
        signed = _prepare_signed_claim(signer, prepared.claim_bytes)

        def build(pad: int) -> str:
            signature = _serialize_signed_claim(signed, pad=pad)
            return build_wrapper(
                _serialize_prepared_manifest(
                    prepared,
                    signature=signature,
                    manifest_uuid=manifest_uuid,
                )
            )

        return build

    # The exclusion range names the wrapper, whose length depends on the manifest,
    # which contains the range. c2patxt._fixpoint performs the bounded search.
    wrapper, _ = solve(prepare)
    return normalized + wrapper
