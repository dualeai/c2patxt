"""Status codes: the spec's own strings, pinned across every supported interpreter."""

from __future__ import annotations

import json
import pathlib

import pytest

from c2patxt.status import (
    _KIND,  # pyright: ignore[reportPrivateUsage] -- the bucket table IS the property under test
    UNREGISTERED_IN_CDDL,
    Status,
    StatusCode,
    StatusKind,
)


@pytest.mark.parametrize(
    ("member", "wire"),
    [
        (StatusCode.TEXT_CORRUPTED_WRAPPER, "manifest.text.corruptedWrapper"),
        (StatusCode.TEXT_MULTIPLE_WRAPPERS, "manifest.text.multipleWrappers"),
        (StatusCode.DATA_HASH_MATCH, "assertion.dataHash.match"),
        (StatusCode.DATA_HASH_MISMATCH, "assertion.dataHash.mismatch"),
        (StatusCode.DATA_HASH_MALFORMED, "assertion.dataHash.malformed"),
        (StatusCode.CLAIM_SIGNATURE_VALIDATED, "claimSignature.validated"),
        (StatusCode.SIGNING_CREDENTIAL_TRUSTED, "signingCredential.trusted"),
        (StatusCode.SIGNING_CREDENTIAL_UNTRUSTED, "signingCredential.untrusted"),
        (StatusCode.SIGNING_CREDENTIAL_INVALID, "signingCredential.invalid"),
        (StatusCode.ALGORITHM_UNSUPPORTED, "algorithm.unsupported"),
        (StatusCode.CLAIM_HARD_BINDINGS_MISSING, "claim.hardBindings.missing"),
    ],
)
def test_codes_are_the_specification_strings(member: StatusCode, wire: str) -> None:
    """Table 4 spelling: camelCase after the last dot, lowercase first segment."""
    assert member.value == wire


@pytest.mark.parametrize("member", list(StatusCode))
def test_every_rendering_produces_the_bare_wire_string(member: StatusCode) -> None:
    """THE version-portability test.

    A plain (str, Enum) renders as 'StatusCode.NAME' in an f-string on 3.11+ but as
    the value on 3.10. These codes are wire strings an integrator interpolates into
    their own API response, so a version-dependent rendering is a silent
    wire-format bug. All five forms must agree, on every supported interpreter.
    """
    wire = member.value
    assert str(member) == wire
    assert f"{member}" == wire
    assert format(member) == wire
    assert "%s" % member == wire  # noqa: UP031 - the %-form is one of the paths under test
    assert json.dumps(member) == json.dumps(wire)


def test_codes_compare_equal_to_their_wire_string() -> None:
    """Round-tripping through JSON or CBOR must not lose identity."""
    assert StatusCode.SIGNING_CREDENTIAL_UNTRUSTED == "signingCredential.untrusted"
    assert StatusCode("signingCredential.untrusted") is StatusCode.SIGNING_CREDENTIAL_UNTRUSTED


def test_status_kinds_render_as_wire_strings_too() -> None:
    for kind in StatusKind:
        assert str(kind) == kind.value
        assert f"{kind}" == kind.value


@pytest.mark.parametrize("member", list(StatusCode))
def test_every_code_has_a_bucket(member: StatusCode) -> None:
    """15.2 groups statuses as success, informational or failure."""
    assert Status(member).kind in set(StatusKind)


def test_the_untrusted_code_is_a_failure_but_does_not_invalidate() -> None:
    """The distinction the whole result model rests on.

    signingCredential.untrusted sits in the FAILURE bucket, yet 14.3.5's definition
    of a Valid manifest deliberately omits signingCredential.trusted from its
    conditions -- 14.3.6 adds it for Trusted. So a self-signed credential yields a
    failure code while the manifest remains Valid. c2pa-rs agrees: it excludes this
    one code from the failures that degrade a manifest below Valid.
    """
    assert Status(StatusCode.SIGNING_CREDENTIAL_UNTRUSTED).kind is StatusKind.FAILURE
    assert Status(StatusCode.SIGNING_CREDENTIAL_TRUSTED).kind is StatusKind.SUCCESS


def test_the_registry_carries_no_code_this_package_cannot_emit() -> None:
    """Every StatusCode must have a producer in src/, or it is a promise we do not keep.

    A registry with aspirational members teaches a reader to distrust the whole enum:
    they cannot tell which codes they might actually receive. Two were deleted on
    2026-08-05 for exactly this -- manifest.inaccessible, which needs a remote
    manifest fetch this package never performs, and
    assertion.dataHash.additionalExclusionsPresent, which C2PA treats as informational
    but which we reject outright, since A.8 places one contiguous wrapper and a
    manifest naming several exclusions is not something a conforming producer emits.
    """
    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "c2patxt"
    sources = "\n".join(path.read_text("utf-8") for path in root.glob("*.py") if path.name != "status.py")
    # MENTION, NOT REACHABILITY. A code named only in a comment would satisfy this, which
    # is the same substring weakness that let the compatibility inventory guard pass
    # vacuously for its whole life. Checked by hand on 2026-08-05: none of the thirty is
    # comment-only, and every code added that day has a real return or raise behind it.
    # Tightening this means parsing, and the cheaper guard is the one below it -- a code
    # with no producer tends to have no test either.
    unemitted = sorted(code.name for code in StatusCode if f"StatusCode.{code.name}" not in sources)
    assert unemitted == []


def test_the_two_text_codes_are_flagged_as_missing_from_the_cddl() -> None:
    """A real spec defect, recorded rather than silently worked around.

    manifest.text.corruptedWrapper and manifest.text.multipleWrappers are absent
    from the normative $status-code enumeration in 15.2.1, while all five
    manifest.structuredText.* codes are present. They validate only via the
    catch-all custom-code regex, so a strict third-party validator will classify
    them as custom. We emit them as Table 4 spells them regardless.
    """
    assert {
        StatusCode.TEXT_CORRUPTED_WRAPPER,
        StatusCode.TEXT_MULTIPLE_WRAPPERS,
    } == UNREGISTERED_IN_CDDL


def test_we_do_not_emit_codes_the_spec_does_not_define() -> None:
    """signingCredential.expired exists in c2pa-rs but NOT in spec 2.2-2.4."""
    values = {member.value for member in StatusCode}
    assert "signingCredential.expired" not in values


def test_status_carries_a_jumbf_uri_and_stays_frozen() -> None:
    status = Status(StatusCode.DATA_HASH_MISMATCH, url="self#jumbf=c2pa.assertions")
    assert str(status) == "assertion.dataHash.mismatch"
    assert status.url == "self#jumbf=c2pa.assertions"
    with pytest.raises(AttributeError):
        status.url = "other"  # type: ignore[misc]


def test_every_status_code_is_filed_into_the_bucket_the_specification_gives_it() -> None:
    """29 of the 31 bucket assignments were unasserted, and `codes()` cannot see them.

    `codes()` concatenates all three buckets, so a code filed under the wrong one still
    appears there -- which is why flipping `assertion.undeclared` from FAILURE to
    SUCCESS passed the whole suite. A caller reading `verdict.failure`, which is the
    documented way to ask what went wrong, would not have found it.

    THE WHOLE TABLE, against a hand-written expectation. This is the wire vocabulary an
    integrator republishes, and 15.2.2's three buckets are part of it: a code's bucket
    is as much a published fact as its string.
    """
    successes = {
        StatusCode.DATA_HASH_MATCH,
        StatusCode.ASSERTION_HASHED_URI_MATCH,
        StatusCode.CLAIM_SIGNATURE_VALIDATED,
        StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY,
        StatusCode.SIGNING_CREDENTIAL_TRUSTED,
    }

    for code in StatusCode:
        expected = StatusKind.SUCCESS if code in successes else StatusKind.FAILURE
        assert _KIND[code] is expected, f"{code.name} is filed as {_KIND[code].name}, expected {expected.name}"

    # signingCredential.untrusted is the one that looks misfiled and is not: the
    # specification puts it in FAILURE, and 14.3.5 defines a Valid manifest without
    # requiring trust. Pinned explicitly because it is the code most likely to be
    # "corrected" by someone who has not read that clause.
    assert _KIND[StatusCode.SIGNING_CREDENTIAL_UNTRUSTED] is StatusKind.FAILURE
