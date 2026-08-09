# pyright: reportPrivateUsage=false
# Verdict._add and Verdict._add_many are the verdict builders, kept private so the
# public result type has no mutator a caller could use to forge a verdict verification
# never produced. Their bucketing logic still needs testing, and this is the only file
# that reaches for it.
"""The result model, and its resistance to being collapsed into a wrong binary."""

from __future__ import annotations

import json

import pytest

from c2patxt.status import Status, StatusCode
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
    for Trusted.
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
    for verdict in (Verdict(state=Provenance.UNMARKED), Verdict(state=Provenance.INVALID)):
        for non_threshold in (Provenance.UNMARKED, Provenance.INVALID):
            with pytest.raises(ValueError, match=r"VALID or Provenance\.TRUSTED"):
                verdict.at_least(non_threshold)
        assert verdict.at_least(Provenance.VALID) is False


def test_statuses_are_filed_into_their_specification_buckets() -> None:
    original = Verdict(state=Provenance.VALID)._add(
        StatusCode.DATA_HASH_MATCH,
        url="self#jumbf=c2pa.assertions/c2pa.hash.data",
    )
    verdict = original._add_many(
        (
            Status(StatusCode.DATA_HASH_ADDITIONAL_EXCLUSIONS),
            Status(StatusCode.SIGNING_CREDENTIAL_UNTRUSTED),
        )
    )
    assert [s.code for s in verdict.success] == [StatusCode.DATA_HASH_MATCH]
    assert verdict.success[0].url == "self#jumbf=c2pa.assertions/c2pa.hash.data"
    assert [s.code for s in verdict.failure] == [StatusCode.SIGNING_CREDENTIAL_UNTRUSTED]
    assert [s.code for s in verdict.informational] == [StatusCode.DATA_HASH_ADDITIONAL_EXCLUSIONS]
    assert original.codes() == (StatusCode.DATA_HASH_MATCH,), "batching must not mutate the source verdict"


def test_a_verdict_is_immutable() -> None:
    """A Verdict a caller can mutate is a bug waiting to be filed against us."""
    verdict = Verdict(state=Provenance.VALID)
    with pytest.raises(AttributeError):
        verdict.state = Provenance.TRUSTED  # type: ignore[misc]

    # add() returns a copy rather than mutating.
    assert verdict._add(StatusCode.DATA_HASH_MATCH) is not verdict
    assert verdict.codes() == ()


def test_there_is_no_fifth_state() -> None:
    """The public validation-state model has exactly the four C2PA outcomes."""
    assert {state.value for state in Provenance} == {"unmarked", "invalid", "valid", "trusted"}


def test_the_manifest_and_span_are_absent_exactly_when_the_parse_did_not_get_there() -> None:
    """No parsed manifest or valid wrapper span is exposed on pre-parse outcomes."""
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
