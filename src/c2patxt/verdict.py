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

There is no fifth state. RFC 8601 needs ``temperror`` because DKIM does DNS lookups;
verification here has no network and no ambient configuration, so there are no
transient failures. It is a pure function of ``(text, context)`` when the caller
supplies ``VerifyContext.now``; with the default it reads the clock, so a mark can pass
before its certificate expires and fail after. That is a property worth stating, not an omission.
"""

from __future__ import annotations

import dataclasses
import enum

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
        The wrapper itself is damaged, or the text carries more than one.
        ``manifest.text.multipleWrappers`` is the reason verification returns a result
        rather than raising: two wrappers is a specification failure code, not an
        exception, and the caller still needs the manifest back.

    THE MANIFEST STRUCTURE
        The claim will not parse, is duplicated, or links an assertion that is absent,
        outside this manifest, or whose hashed URI does not resolve or does not match.

    WHAT THE ASSERTIONS ASSERT -- and these two are why this package exists.
        ``assertion.action.malformed`` covers a ``c2pa.created`` action with no
        ``digitalSourceType``, which is the field that actually says a model generated
        the text, and an inception action that is not first. ``general.error`` covers an
        AI disclosure carrying no ``modelType``. A mark can be perfectly well-formed,
        correctly bound and validly signed, and still land here because it discloses
        nothing -- which is the case an EU AI Act Article 50(2) reader most needs to see
        and is least likely to predict.

    THE BINDING
        The hard binding does not match the text, names a range that is not the located
        wrapper, or there is more than one binding to choose between.

    THE SIGNATURE AND THE CREDENTIAL
        The claim signature does not verify, the leaf is outside its validity window,
        or the certificate fails the 14.5.1.1 profile.

        ``signingCredential.invalid`` ALSO carries a restriction that is ours, not the
        clause's: this package accepts Ed25519 alone, where 13.2.1's list is wider. A
        conforming ES256 mark is refused here and reported under the same code. That is
        deliberate and it is a deviation -- see docs/deviations.md -- but it is not
        14.5.1.1 speaking, so do not describe the profile as the only cause.

    SO INVALID DOES NOT MEAN "TAMPERED". "The text may have been altered after signing"
    is true of the binding case and false of an expired certificate, where nothing was
    altered and the mark is simply no longer acceptable. It is equally false of a
    disclosure that names no model, where the text is exactly what was signed and the
    claim is the thing that is inadequate.
    """

    VALID = "valid"
    """Well-formed, the hard binding matches, and the claim signature verifies.

    The signer is NOT corroborated against any trust anchor supplied to this call.
    **This is the expected outcome for a self-signed credential and is not an
    error.** This package bundles no trust anchors, so with none supplied there is
    nothing to chain to and this is as far as verification can go. Maps to c2pa-rs
    ``ValidationState::Valid``.
    """

    TRUSTED = "trusted"
    """VALID, and the certificate chain reaches a supplied trust anchor.

    Maps to c2pa-rs ``ValidationState::Trusted``. Requires a ``TrustEvaluator``;
    see :mod:`c2patxt.trust`.
    """

    def __str__(self) -> str:
        """Return the bare wire string on every supported interpreter.

        A plain ``(str, Enum)`` renders as ``Provenance.VALID`` in an f-string on
        3.11+ but as ``valid`` on 3.10, and this value is one an integrator will
        interpolate into their own API response.
        """
        return self.value

    __format__ = str.__format__


#: Assurance ordering for at_least(). UNMARKED and INVALID share a rank: neither
#: clears any threshold, and neither is "better" than the other.
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
    """**Always empty today.** Present because 15.2.2 defines the bucket, not because
    anything fills it: every code this package emits is a success or a failure.

    The specification does define informational codes -- ``assertion.dataHash.
    additionalExclusionsPresent`` among them -- and we emit none of them, because the
    cases they describe are ones we reject instead (see docs/deviations.md). So the
    bucket is real and our set is empty.

    Said here so a caller building a three-panel display knows the third panel is dead
    BY DESIGN and can decide not to render it, rather than shipping an empty box and
    wondering. ``test_the_informational_bucket_is_empty_until_a_code_lands_in_it``
    fails the day that stops being true, which forces this paragraph to change with it.
    """

    failure: tuple[Status, ...] = ()
    manifest: ManifestStore | None = None
    """The parsed manifest, present whenever the manifest PARSED -- including when
    validation then failed, so a caller can inspect what was rejected without bypassing
    verification to do it.

    ``None`` WHEN THE PARSE ITSELF DID NOT GET THERE: unmarked text, a corrupt wrapper,
    more than one wrapper, and every structural failure inside the manifest. The
    carrier-level codes are exactly the ones that report those cases.

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

        Without this, ``if verify(text):`` is always true -- a frozen dataclass is
        truthy -- so unmarked text silently reads as marked. Returning something
        instead would be worse: ``requests.Response.__bool__`` returns ``self.ok``,
        its own docstring needs a bolded disclaimer, its author called it a mistake
        in psf/requests#2002, a removal was merged to a 3.0 branch in 2015 and never
        shipped, and it was rejected again in 2022 as too breaking. Ten years of an
        unfixable footgun because a truthiness answer was guessed.

        numpy sets the precedent for refusing: ``bool()`` on an ambiguous array
        raises rather than picking. Our case is strictly more ambiguous -- there is
        no defensible default among four states -- so this raises ``TypeError``,
        which is what Python raises for unsupported protocol use.
        """
        msg = (
            f"Verdict is not a boolean (state={self.state}). Unmarked text is not "
            "invalid text, and valid-but-untrusted is not invalid. Branch on "
            "`.state`, or call `.at_least(Provenance.VALID)`."
        )
        raise TypeError(msg)

    def at_least(self, minimum: Provenance) -> bool:
        """True if this verdict reaches ``minimum`` assurance.

        Requires the caller to NAME a threshold, which is the point: there is no
        universally right answer, and making the choice explicit is the only honest
        way to collapse four states into one bit.
        """
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

    def _add(self, code: StatusCode, explanation: str | None = None) -> Verdict:
        """Return a copy with ``code`` filed into its specification bucket.

        Private: this is the verdict BUILDER, and a public mutator on a result type
        invites a caller to assemble a verdict that verification never produced.
        """
        status = Status(code, explanation=explanation)
        bucket = status.kind
        return dataclasses.replace(
            self,
            success=(*self.success, status) if bucket is StatusKind.SUCCESS else self.success,
            informational=(*self.informational, status) if bucket is StatusKind.INFORMATIONAL else self.informational,
            failure=(*self.failure, status) if bucket is StatusKind.FAILURE else self.failure,
        )

    def codes(self) -> tuple[StatusCode, ...]:
        """Every status code, in bucket order. Convenient for assertions and logs."""
        return tuple(status.code for group in (self.success, self.informational, self.failure) for status in group)
