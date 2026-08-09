"""
The result model: :class:`Provenance` and :class:`Verdict`.

Four states, not four booleans. The design constraint that forces this is our own
output: the signing credential is self-signed, so a correct, intact, honestly-signed
mark yields ``signingCredential.untrusted``. C2PA 14.3.5 defines a *Valid* manifest
without requiring ``signingCredential.trusted`` -- 14.3.6 adds it for *Trusted* -- so
"the signature verifies but the signer is not corroborated" is a first-class outcome
and not a failure. Model it as a boolean and every verification of our own output
reads as forged.

Absence is folded in as a peer state rather than kept as a separate ``marked`` flag.
Unmarked text rendered as "FAKE" is the most damaging collapse available, and a
separate flag is the one an integrator forgets. RFC 8601 made the same call for mail
authentication: ``none`` is a peer of ``pass`` and ``fail``, not a modifier on them.

There is no fifth state. Package-owned verification performs no network or ambient
configuration lookup. It is a pure function of ``(text, context)`` when the caller
supplies ``VerifyContext.now`` and a deterministic evaluator; the default reads the
clock, and caller-owned evaluators can use their own state.
"""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Iterable

from c2patxt._locate import Span
from c2patxt.manifest import ManifestStore
from c2patxt.status import Status, StatusCode, StatusKind

__all__ = [
    "Provenance",
    "Verdict",
]


class Provenance(str, enum.Enum):
    """How much assurance a piece of text carries.

    Ordered by increasing assurance for :meth:`Verdict.at_least`, with ``UNMARKED``
    and ``INVALID`` both below ``VALID``. They are not ranked against each other:
    one is an absence of evidence, the other is evidence of a problem.
    """

    UNMARKED = "unmarked"
    """No Content Credential is present.

    This is NOT a negative finding about the text. It is the absence of a finding.
    Most text ever written is unmarked, and absence of a mark proves nothing about
    origin -- the DKIM lesson. Never render this as "fake", "altered" or "failed".
    """

    INVALID = "invalid"
    """A Content Credential is present and failed validation.

    A mark is present and this package will not stand behind it. ``codes()`` is the
    authority on which of these happened; the families are given so a reader knows what
    kind of thing to expect, not so they can be matched on.

    THE CARRIER
        The wrapper itself is damaged, or more than one located wrapper matches the
        signed exclusions.

    THE MANIFEST STRUCTURE
        The claim will not parse, is duplicated, or links an assertion that is absent,
        outside this manifest, or whose hashed URI does not resolve or does not match.

    WHAT THE ASSERTIONS ASSERT
        ``assertion.action.malformed`` covers an inception action that is not first.
        Producer-only schema rules are not promoted into generic validator failures.

    THE BINDING
        The hard binding does not match the text, names a range that is not the located
        wrapper, or there is more than one binding to choose between.

    THE SIGNATURE AND THE CREDENTIAL
        The claim signature does not verify, a carried certificate is outside its
        validity window, or the certificate chain fails the 14.5.1.1 profile.

        Generation uses Ed25519. Validation accepts C2PA 13.2.1's ES256/384/512,
        PS256/384/512 and Ed25519 set. An algorithm outside that set reports
        ``algorithm.unsupported``; an allowed algorithm paired with an incompatible key
        reports ``claimSignature.mismatch``. ``signingCredential.invalid`` stays limited
        to credential shape and profile failures.

    SO INVALID DOES NOT MEAN "TAMPERED". "The text may have been altered after signing"
    is true of the binding case and false of an expired certificate, where nothing was
    altered and the mark is simply no longer acceptable.
    """

    VALID = "valid"
    """Well-formed, the hard binding matches, and the claim signature verifies.

    The signer is NOT corroborated against any trust anchor supplied to this call.
    **This is the expected outcome for a self-signed credential and is not an
    error.** This package bundles no trust anchors, so with none supplied there is
    nothing to chain to and this is as far as verification can go.
    """

    TRUSTED = "trusted"
    """VALID, and the certificate chain reaches a supplied trust anchor.

    Requires a ``TrustEvaluator``; see :mod:`c2patxt.trust`.
    """

    def __str__(self) -> str:
        """Return the bare wire string on every supported interpreter.

        A plain ``(str, Enum)`` renders as ``Provenance.VALID`` in an f-string on
        3.11+ but as ``valid`` on 3.10, and this value is one an integrator will
        interpolate into their own API response.
        """
        return self.value

    __format__ = str.__format__


#: Assurance ordering for at_least(). UNMARKED and INVALID share the floor when
#: compared with the two assurance thresholds; neither ranks against the other.
_RANK: dict[Provenance, int] = {
    Provenance.UNMARKED: 0,
    Provenance.INVALID: 0,
    Provenance.VALID: 1,
    Provenance.TRUSTED: 2,
}


@dataclasses.dataclass(frozen=True, slots=True)
class Verdict:
    """The result of :func:`verify`.

    Deliberately NOT boolean-convertible; see :meth:`__bool__`. There is also no
    ``.ok``, ``.valid`` or ``.is_valid`` property, because any single boolean
    accessor becomes the thing integrators reach for and re-creates exactly the
    collapse this type exists to prevent.

    A ``Verdict`` IS freely constructible -- ``Verdict(state=Provenance.TRUSTED)``
    succeeds -- and that is left deliberately open rather than gated. Python
    dataclasses are constructible, a caller who wants a stub for their own tests
    should have one, and sealing the constructor would only push them to
    ``unittest.mock``, which produces a worse stub that answers every attribute.
    What IS closed is the mutator: :meth:`_add` is private, so there is no supported
    way to bolt success codes onto a verdict after the fact. **A Verdict means
    something only when it was returned by** :func:`verify`; one you built yourself
    asserts nothing about any text.
    """

    state: Provenance
    success: tuple[Status, ...] = ()
    informational: tuple[Status, ...] = ()
    """Statuses that report a condition without invalidating the manifest.

    A data-hash assertion with extra exclusion ranges adds
    ``assertion.dataHash.additionalExclusionsPresent`` here while its digest can still
    match and the verdict can remain Valid.
    """

    failure: tuple[Status, ...] = ()
    manifest: ManifestStore | None = None
    """The parsed manifest, present whenever the manifest PARSED -- including when
    validation then failed, so a caller can inspect what was rejected without bypassing
    verification to do it.

    ``None`` WHEN PARSING AND SELECTION DID NOT YIELD ONE MANIFEST: unmarked text, a
    corrupt wrapper, or plural wrappers whose signed exclusions do not identify one
    candidate. It remains present when later validation fails.

    ``verdict.manifest.assertions`` raises ``AttributeError`` on precisely the hostile
    inputs where a caller most needs their code not to crash, so check for ``None``."""

    span: Span | None = None
    """Byte range of the wrapper in the text as stored.

    ``None`` when unmarked, AND on the corrupt-wrapper path -- a wrapper whose magic
    matched but whose structure is malformed has no span to report.

    Typed concretely rather than as ``object`` so removing the mark -- the single most
    common thing to do with it -- needs no cast."""

    def __bool__(self) -> bool:
        """Always raises. A verdict is not a boolean.

        ``UNMARKED``, ``INVALID``, ``VALID``, and ``TRUSTED`` have no safe truth-value
        mapping. Callers must branch on ``state`` or use ``at_least`` explicitly.
        """
        msg = (
            f"Verdict is not a boolean (state={self.state}). Unmarked text is not "
            "invalid text, and valid-but-untrusted is not invalid. Branch on "
            "`.state`, or call `.at_least(Provenance.VALID)`."
        )
        raise TypeError(msg)

    def at_least(self, minimum: Provenance) -> bool:
        """True if this verdict reaches ``minimum`` assurance.

        ``VALID`` and ``TRUSTED`` are assurance thresholds. ``UNMARKED`` describes
        absence and ``INVALID`` describes a failed mark, so neither is accepted as a
        threshold or ranked against the other.
        """
        if minimum not in (Provenance.VALID, Provenance.TRUSTED):
            msg = "minimum must be Provenance.VALID or Provenance.TRUSTED"
            raise ValueError(msg)
        return _RANK[self.state] >= _RANK[minimum]

    def raise_for_state(self, minimum: Provenance = Provenance.VALID) -> None:
        """Raise unless the verdict reaches ``minimum``.

        Defaults to ``VALID``, not ``TRUSTED``. Defaulting to TRUSTED would raise on
        our own honestly-signed self-signed output, which is the opposite of the
        mistake this type exists to prevent.
        """
        if not self.at_least(minimum):
            codes = ", ".join(str(status.code) for status in self.failure) or "no failure codes"
            msg = f"provenance is {self.state}, required at least {minimum} ({codes})"
            raise ValueError(msg)

    def _add(self, code: StatusCode, explanation: str | None = None, *, url: str | None = None) -> Verdict:
        """Return a copy with ``code`` filed into its specification bucket.

        Private: this is the verdict BUILDER, and a public mutator on a result type
        invites a caller to assemble a verdict that verification never produced.
        """
        return self._add_many((Status(code, url=url, explanation=explanation),))

    def _add_many(self, statuses: Iterable[Status]) -> Verdict:
        """File several statuses with one immutable result copy.

        Verification can report one success for every authenticated claim link. Building
        a new tuple for each link copies the whole prefix each time, so the verifier
        batches that private construction and freezes the public tuples once.
        """
        success = list(self.success)
        informational = list(self.informational)
        failure = list(self.failure)
        changed = False
        for status in statuses:
            changed = True
            if status.kind is StatusKind.SUCCESS:
                success.append(status)
            elif status.kind is StatusKind.INFORMATIONAL:
                informational.append(status)
            else:
                failure.append(status)
        if not changed:
            return self
        return dataclasses.replace(
            self,
            success=tuple(success),
            informational=tuple(informational),
            failure=tuple(failure),
        )

    def codes(self) -> tuple[StatusCode, ...]:
        """Every status code, in bucket order. Convenient for assertions and logs."""
        return tuple(status.code for group in (self.success, self.informational, self.failure) for status in group)
