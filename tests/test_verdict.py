# pyright: reportPrivateUsage=false
# Verdict._add is the verdict BUILDER, kept private so the public result type has no
# mutator a caller could use to forge a verdict verification never produced. Its
# bucketing logic still needs testing, and this is the only file that reaches for it.
"""The result model, and its resistance to being collapsed into a wrong binary."""

from __future__ import annotations

import inspect
import json

import pytest

from c2patxt.status import StatusCode, StatusKind
from c2patxt.verdict import Provenance, Verdict


@pytest.mark.parametrize("state", list(Provenance))
def test_states_render_as_bare_wire_strings(state: Provenance) -> None:
    """Version-portability, same trap as StatusCode."""
    assert str(state) == state.value
    assert f"{state}" == state.value
    assert format(state) == state.value
    assert json.dumps(state) == json.dumps(state.value)


@pytest.mark.parametrize("state", list(Provenance))
def test_a_verdict_is_never_a_boolean(state: Provenance) -> None:
    """THE misuse-resistance test.

    `"CLEAN" if v else "FAKE"` is the single most likely line an integrator writes.
    It must fail loudly for every state, not quietly for some.
    """
    verdict = Verdict(state=state)
    with pytest.raises(TypeError, match="not a boolean"):
        bool(verdict)
    with pytest.raises(TypeError, match="not a boolean"):
        _ = "CLEAN" if verdict else "FAKE"


def test_the_error_message_names_the_state_and_the_alternative() -> None:
    """A crash is only useful if it carries the fix."""
    with pytest.raises(TypeError) as excinfo:
        bool(Verdict(state=Provenance.UNMARKED))
    message = str(excinfo.value)
    assert "unmarked" in message
    assert ".state" in message
    assert "at_least" in message


def test_there_is_no_single_boolean_accessor() -> None:
    """Any .ok/.valid/.is_valid would become the thing people reach for."""
    verdict = Verdict(state=Provenance.VALID)
    for forbidden in ("ok", "valid", "is_valid", "trusted", "marked", "binding_valid"):
        assert not hasattr(verdict, forbidden), f"{forbidden} re-creates the collapse"


@pytest.mark.parametrize(
    ("state", "threshold", "expected"),
    [
        (Provenance.TRUSTED, Provenance.VALID, True),
        (Provenance.TRUSTED, Provenance.TRUSTED, True),
        (Provenance.VALID, Provenance.VALID, True),
        (Provenance.VALID, Provenance.TRUSTED, False),
        (Provenance.INVALID, Provenance.VALID, False),
        (Provenance.UNMARKED, Provenance.VALID, False),
    ],
)
def test_at_least_requires_naming_a_threshold(state: Provenance, threshold: Provenance, expected: bool) -> None:
    assert Verdict(state=state).at_least(threshold) is expected


def test_a_self_signed_result_clears_valid_but_not_trusted() -> None:
    """Our own normal output. It must not read as a failure.

    14.3.5 defines Valid WITHOUT requiring signingCredential.trusted; 14.3.6 adds it
    for Trusted. c2pa-rs agrees, excluding that one code from the failures that
    degrade a manifest below Valid.
    """
    verdict = Verdict(state=Provenance.VALID)._add(StatusCode.SIGNING_CREDENTIAL_UNTRUSTED)
    assert verdict.at_least(Provenance.VALID) is True
    assert verdict.at_least(Provenance.TRUSTED) is False
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED in verdict.codes()


def test_raise_for_state_defaults_to_valid_not_trusted() -> None:
    """Defaulting to TRUSTED would raise on our own honestly-signed output."""
    self_signed = Verdict(state=Provenance.VALID)._add(StatusCode.SIGNING_CREDENTIAL_UNTRUSTED)
    self_signed.raise_for_state()  # must not raise

    with pytest.raises(ValueError, match="required at least trusted"):
        self_signed.raise_for_state(Provenance.TRUSTED)


def test_raise_for_state_reports_the_failure_codes() -> None:
    verdict = Verdict(state=Provenance.INVALID)._add(StatusCode.DATA_HASH_MISMATCH)
    with pytest.raises(ValueError, match=r"assertion\.dataHash\.mismatch"):
        verdict.raise_for_state()


def test_unmarked_and_invalid_are_not_ranked_against_each_other() -> None:
    """One is an absence of evidence, the other evidence of a problem.

    Neither clears a threshold, and claiming one is "better" would invite ranking
    unmarked text as almost-valid.
    """
    unmarked = Verdict(state=Provenance.UNMARKED)
    invalid = Verdict(state=Provenance.INVALID)
    assert unmarked.at_least(Provenance.INVALID) is True
    assert invalid.at_least(Provenance.UNMARKED) is True
    assert unmarked.at_least(Provenance.VALID) is False
    assert invalid.at_least(Provenance.VALID) is False


def test_statuses_are_filed_into_their_specification_buckets() -> None:
    verdict = (
        Verdict(state=Provenance.VALID)._add(StatusCode.DATA_HASH_MATCH)._add(StatusCode.SIGNING_CREDENTIAL_UNTRUSTED)
    )
    assert [s.code for s in verdict.success] == [StatusCode.DATA_HASH_MATCH]
    assert [s.code for s in verdict.failure] == [StatusCode.SIGNING_CREDENTIAL_UNTRUSTED]

    # The informational bucket is currently EMPTY BY DESIGN, not by omission. C2PA's
    # only informational code for this carrier is
    # assertion.dataHash.additionalExclusionsPresent, and we reject extra exclusions
    # outright rather than noting them -- A.8 places one contiguous wrapper. The
    # bucket stays because it is part of the specification's vocabulary and a future
    # code may land in it.
    assert verdict.informational == ()


def test_a_verdict_is_immutable() -> None:
    """A Verdict a caller can mutate is a bug waiting to be filed against us."""
    verdict = Verdict(state=Provenance.VALID)
    with pytest.raises(AttributeError):
        verdict.state = Provenance.TRUSTED  # type: ignore[misc]

    # add() returns a copy rather than mutating.
    assert verdict._add(StatusCode.DATA_HASH_MATCH) is not verdict
    assert verdict.codes() == ()


def test_there_is_no_fifth_state() -> None:
    """No temperror: verification is a pure function with no network."""
    assert {state.value for state in Provenance} == {"unmarked", "invalid", "valid", "trusted"}


def _invalid_prose() -> str:
    """The text written under ``INVALID = "invalid"`` in verdict.py.

    READ FROM SOURCE, NOT FROM ``__doc__``, and that is a finding rather than a
    convenience. An enum member does not carry its own docstring: the string literal
    after the assignment is discarded at class creation, so ``Provenance.INVALID.__doc__``
    returns the CLASS docstring and ``help(Provenance)`` shows none of this prose.
    Verified: ``'Article 50(2)' in pydoc.render_doc(Provenance)`` is False.

    So the audience for this text is someone reading the source, or a documentation
    generator that parses it -- not someone calling ``help()``. The test asserts what
    is actually there.
    """
    import c2patxt.verdict as verdict_module

    source = inspect.getsource(verdict_module)
    start = source.index('INVALID = "invalid"')
    return source[start : source.index('VALID = "valid"', start)]


def test_the_invalid_prose_names_the_two_article_50_2_causes() -> None:
    """What INVALID means listed the carrier, the manifest, the binding, the signature
    and the credential -- and omitted the two families this package exists for: an
    action with no ``digitalSourceType``, and an AI disclosure with no ``modelType``.

    A mark can be well-formed, correctly bound and validly signed and still be INVALID
    because it discloses nothing. That is the case an Article 50(2) reader most needs
    and is least likely to predict.

    ASSERTED IN BOTH DIRECTIONS, because naming a code proves nothing on its own: each
    must also be a code the implementation can still return, so the prose cannot drift
    into describing behaviour that was removed.
    """
    import c2patxt._verify as verify_module

    prose = _invalid_prose()
    implementation = inspect.getsource(verify_module)
    for code in (StatusCode.ASSERTION_ACTION_MALFORMED, StatusCode.GENERAL_ERROR, StatusCode.TEXT_MULTIPLE_WRAPPERS):
        assert code.value in prose, f"the INVALID prose does not mention {code.value}"
        assert code.name in implementation, f"{code.name} is named in the prose but no longer reachable"


def test_the_invalid_prose_does_not_blame_the_profile_for_our_own_narrowing() -> None:
    """Ed25519-only is OUR restriction; 13.2.1's list is wider.

    The only account of ``signingCredential.invalid`` was "fails the 14.5.1.1 profile",
    which attributed our narrowing to the clause -- the exact overclaim shape corrected
    elsewhere in this package, committed inside a correction. A conforming ES256 mark is
    refused here, and the prose must say that choice is ours and where it is recorded.
    """
    prose = _invalid_prose()
    assert "Ed25519" in prose, "the prose must name the algorithm restriction it applies"
    assert "deviations.md" in prose, "and must point at where that choice is recorded"


def test_the_informational_bucket_is_empty_until_a_code_lands_in_it() -> None:
    """``Verdict.informational`` is public and presented as a peer of success and
    failure, and nothing has ever gone into it: ``_KIND`` maps all 31 codes to SUCCESS
    or FAILURE.

    An integrator building a three-panel display gets a dead panel with no way to know
    it is dead by design. The field's own text now says so -- and this is what makes
    that text falsifiable. THE DAY A CODE LANDS IN THIS BUCKET, THIS TEST FAILS AND THE
    PARAGRAPH HAS TO BE REWRITTEN, which is the point: the alternative is prose that
    quietly becomes wrong.

    The bucket is not a mistake. 15.2.2 defines it, and the specification has
    informational codes -- ``assertion.dataHash.additionalExclusionsPresent`` among
    them -- that we do not emit because we reject those cases instead.
    """
    from c2patxt.status import _KIND

    informational = sorted(code.value for code, kind in _KIND.items() if kind is StatusKind.INFORMATIONAL)
    assert informational == [], (
        f"{informational} now map to INFORMATIONAL; Verdict.informational's docstring says the bucket is always empty"
    )
    assert set(_KIND) == set(StatusCode), "every code must have a bucket, or codes() silently drops it"


def test_the_manifest_and_span_are_absent_exactly_when_the_parse_did_not_get_there() -> None:
    """Both fields were documented with rules that read as complete and were not.

    ``manifest`` said "present even when validation FAILED"; the README taught the same
    sentence as the RIGHT half of a WRONG/RIGHT pair. ``span`` said "None when
    unmarked". Both are also None on the corrupt-wrapper path, so a caller following
    either sentence writes ``verdict.manifest.assertions`` and gets ``AttributeError``
    on precisely the hostile inputs where the code most needs to survive.
    """
    from c2patxt import verify
    from c2patxt._selectors import bytes_to_selectors
    from c2patxt.constants import MAGIC, MARKER

    # A wrapper whose magic matches but whose version is 2: corrupt, not absent.
    corrupt = verify("Doc." + MARKER + bytes_to_selectors(MAGIC + bytes([2]) + b"\x00" * 4))
    assert corrupt.state is Provenance.INVALID
    assert corrupt.manifest is None, "a corrupt wrapper never produced a manifest to inspect"
    assert corrupt.span is None, "and it has no span either, which 'None when unmarked' did not say"

    unmarked = verify("Ordinary prose.")
    assert (unmarked.manifest, unmarked.span) == (None, None)
