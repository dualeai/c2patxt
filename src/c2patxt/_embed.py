"""
``embed``: append a signed Content Credential to plain text.

WHY THE WRAPPER IS ALWAYS A SUFFIX, AND THE TEXT IS ALWAYS NFC
--------------------------------------------------------------
A.8 leaves both open -- placement "at the end" is a SHOULD, and A.8.6.1 requires NFC
for HASHING without saying anything about embedding. Left open, they produce the two
divergence classes this format has:

* 15.12.1.3.1 removes the wrapper and then normalizes; A.8.7.3 normalizes first. The
  orders differ whenever the wrapper is not a suffix, because U+FEFF is a starter and
  blocks composition across it. Forcing a suffix makes both orders identical BY
  CONSTRUCTION, so a verifier that reads the clause the other way still agrees.
* Marking text that is not already NFC would mean the producer's offsets and a
  verifier's offsets are computed over different byte strings.

So we normalize before marking and we always append. The cost is stated plainly in
``embed``'s docstring: the returned visible text is the NFC form of the input, which
for already-NFC text -- effectively all of it -- is the input unchanged.

DETERMINISM IS A DESIGN REQUIREMENT, NOT A TEST CONVENIENCE
-----------------------------------------------------------
Every varying input is injected through :class:`EmbedContext`, so marking the same
text twice with the same context yields the same bytes. Without that, "re-marking is
byte-stable" is not a testable claim, and a producer cannot be diffed against a
reference implementation at all.

Ed25519 is what makes this free: RFC 8032 5.1.6 derives the nonce deterministically
as ``r = SHA-512(dom2(F,C) || prefix || PH(M))``, with no randomness anywhere, and
COSE ``EdDSA`` (alg -8) is pure EdDSA per RFC 9053 2.2. Cite the RFC, not the
library: pyca/cryptography's Ed25519 documentation never states determinism. If
ES256 is ever added, byte-stability disappears -- ECDSA is randomized -- and the
determinism tests must be skipped for it rather than quietly relaxed.

The founding memo asked for this to be exercised under ``pytest-repeat``, on the
grounds that "a determinism test that runs once tests nothing". We do not take that
dependency. Repetition samples for instability; :class:`EmbedContext` REMOVES the
sources of it, which is the stronger move, and the residual risk -- a seed we forgot
to pin -- is covered instead by a Hypothesis property that re-marks arbitrary text
(``test_the_full_remark_cycle_is_byte_stable``) and by having pinned every RNG in the
test suite after one such seed produced an intermittent failure.

The remaining sources of variation are the ones the context names: the manifest UUID,
the instance ID, and the signing time. We deliberately do NOT emit ``c2sh`` salt
boxes (6.6): they exist for secure redaction, which needs per-assertion randomness,
and we have nothing to redact -- a mark carries no payload to hide.

WHAT THE MANIFEST MAY NOT CONTAIN
---------------------------------
No tenant, agent, account, end-user, author, prompt or conversation content, ever.
The mark says "a model generated this" and nothing else. There is a test that asserts
the emitted bytes contain none of it, because this is a property of the output, not
an intention of the author.
"""

from __future__ import annotations

import dataclasses
import datetime
import unicodedata
import uuid

from c2patxt import _cose
from c2patxt._fixpoint import solve
from c2patxt._locate import find_wrappers
from c2patxt._selectors import build_wrapper
from c2patxt.exceptions import C2paTextError
from c2patxt.manifest import DEFAULT_HASH_ALGORITHM, HASH_ALGORITHMS, build_manifest_store, claim_payload_bytes
from c2patxt.signing import Disclosure, Signer

__all__ = [
    "AlreadyMarkedError",
    "EmbedContext",
    "embed",
]


class AlreadyMarkedError(C2paTextError, ValueError):
    """``embed`` was called on text that already carries a wrapper.

    A hard error rather than a silent replace or a second append. Appending would
    produce two wrappers, which 15.5.2.1 makes invalid -- so the failure would only
    surface at the consumer, in someone else's system. Replacing would silently
    discard another producer's signed claim.

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


def _default_when() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


@dataclasses.dataclass(frozen=True, slots=True)
class EmbedContext:
    """Every non-deterministic input to :func:`embed`, made explicit.

    The defaults do the normal thing -- a fresh UUID, a fresh instance ID, the
    current time -- so ordinary callers never touch this. Pin all three and marking
    becomes a pure function, which is what makes byte-stability testable and what a
    reproducible build needs.
    """

    manifest_uuid: uuid.UUID | None = None
    """Identifies THIS manifest (8.1). Fresh per manifest by default. Reusing one
    across different documents is a correctness error, not merely untidy."""

    instance_id: str | None = None
    """The claim's required ``instanceID``. Defaults to a fresh ``xmp:iid:`` URN."""

    when: datetime.datetime | None = None
    """Signing time, recorded in the ``c2pa.created`` action. Defaults to now, UTC.
    A naive datetime is rejected rather than assumed to be UTC."""

    generator_name: str = "c2patxt"
    """``claim_generator_info.name``. Names the SOFTWARE, never the operator: a
    tenant or account name here would be exactly the payload that must not ship."""

    generator_version: str | None = None
    """Optional generator version. Left unset by default -- it is not needed for
    validation, and pinning a version into signed bytes makes every release produce
    different output for identical input."""

    algorithm: str = DEFAULT_HASH_ALGORITHM
    """Hash algorithm for the hard binding. 13.1 permits sha256, sha384 and sha512
    and states implementations "shall not support additional algorithms"."""

    def resolve(self) -> tuple[uuid.UUID, str, datetime.datetime]:
        """Fill in the defaults, once, so a single embed uses consistent values."""
        manifest_uuid = self.manifest_uuid or uuid.uuid4()
        instance_id = self.instance_id or f"xmp:iid:{uuid.uuid4()}"
        when = self.when or _default_when()
        if when.tzinfo is None:
            msg = "EmbedContext.when must be timezone-aware; a naive datetime has no defined instant"
            raise ValueError(msg)
        return manifest_uuid, instance_id, when


def embed(text: str, signer: Signer, disclosure: Disclosure, *, context: EmbedContext | None = None) -> str:
    """Return ``text`` with a signed Content Credential appended.

    The visible text is returned in NFC form and the mark is appended after it as one
    contiguous run of variation selectors preceded by U+FEFF. For text that is
    already NFC -- effectively all text in practice -- the visible portion is
    byte-identical to the input. See the module docstring for why both are forced.

    Args:
        text: the text to mark. Must not already carry a wrapper.
        signer: the Ed25519 key and its certificate chain.
        disclosure: what the AI-disclosure assertion states about the generating
            model. Carries no information about who ran it.
        context: pins the manifest UUID, instance ID and signing time. Omit for
            normal use; supply it for reproducible output.

    Returns:
        The marked text. Rendering is unaffected: variation selectors are
        zero-width, so the string displays exactly as ``unicodedata.normalize("NFC",
        text)`` does.

    Raises:
        FixpointError: the padding search could not settle on a length. Never expected
            in practice; a subclass of ``C2paTextError`` and ``RuntimeError``.
        ValueError: the signing certificate's validity period does not contain
            ``EmbedContext.when``, so the mark would be invalid the moment it was made.
        AlreadyMarkedError: ``text`` already carries a Content Credential.
        MarkCorruptError: ``text`` carries something that looks like a wrapper but is
            malformed. Marking on top of it would bury the damage.
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

    # A MARK SIGNED WITH AN OUT-OF-WINDOW CREDENTIAL IS BORN INVALID, and signed bytes
    # cannot be recalled. Signer checks the 14.5.1.1 profile at construction but not the
    # dates -- the one property that changes without anyone touching the deployment --
    # so a service holding a Signer past its leaf's notAfter emitted invalid marks
    # silently. Checked HERE rather than in Signer because nothing reconstructs a Signer,
    # and against `when` rather than the clock so embed stays a pure function of its
    # arguments. It cannot promise the mark will still be valid when READ: verification
    # judges against its own clock (15.8). It promises the credential was usable when the
    # mark was made.
    leaf = signer.certificates[0]
    if not leaf.not_valid_before_utc <= when <= leaf.not_valid_after_utc:
        msg = (
            f"the signing certificate's validity period "
            f"({leaf.not_valid_before_utc.isoformat()} to {leaf.not_valid_after_utc.isoformat()}) "
            f"does not contain {when.isoformat()}; the mark would be invalid the moment it was made"
        )
        raise ValueError(msg)

    # Checked BEFORE normalization so the reported offsets refer to the caller's own
    # bytes rather than to a string they never had.
    existing = find_wrappers(text)
    if existing:
        raise AlreadyMarkedError(existing[0].span.utf8_start, existing[0].span.utf8_stop)

    normalized = unicodedata.normalize("NFC", text)
    encoded = normalized.encode("utf-8")
    # The mark is a suffix, so the bytes covered by the hash are exactly the visible
    # text -- 15.12.1.3.1's "remove the exclusions, then normalize" is a no-op here,
    # which is the whole reason for forcing suffix placement.
    digest = HASH_ALGORITHMS[context.algorithm](encoded).digest()
    exclusion_start = len(encoded)

    def build(exclusion_length: int, pad: bytes) -> str:
        claim = claim_payload_bytes(
            disclosure=disclosure,
            digest=digest,
            exclusion_start=exclusion_start,
            exclusion_length=exclusion_length,
            instance_id=instance_id,
            when=when,
            generator_name=context.generator_name,
            generator_version=context.generator_version,
            algorithm=context.algorithm,
            pad=pad,
        )
        return build_wrapper(
            build_manifest_store(
                disclosure=disclosure,
                digest=digest,
                exclusion_start=exclusion_start,
                exclusion_length=exclusion_length,
                signature=_cose.sign_claim(signer, claim),
                instance_id=instance_id,
                manifest_uuid=manifest_uuid,
                when=when,
                generator_name=context.generator_name,
                generator_version=context.generator_version,
                algorithm=context.algorithm,
                pad=pad,
            )
        )

    # The exclusion range names the wrapper, whose length depends on the manifest,
    # which contains the range. See c2patxt._fixpoint for why this does not iterate.
    wrapper, _ = solve(build)
    return normalized + wrapper
