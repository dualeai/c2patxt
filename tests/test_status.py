"""Status codes: the spec's own strings, pinned across every supported interpreter."""

from __future__ import annotations

import json

import pytest

from c2patxt.status import (
    _KIND,  # pyright: ignore[reportPrivateUsage] -- the bucket table IS the property under test
    Status,
    StatusCode,
    StatusKind,
)

_SPEC_STATUS = [
    (StatusCode.TEXT_CORRUPTED_WRAPPER, "manifest.text.corruptedWrapper", StatusKind.FAILURE),
    (StatusCode.TEXT_MULTIPLE_WRAPPERS, "manifest.text.multipleWrappers", StatusKind.FAILURE),
    (StatusCode.DATA_HASH_MATCH, "assertion.dataHash.match", StatusKind.SUCCESS),
    (StatusCode.DATA_HASH_MISMATCH, "assertion.dataHash.mismatch", StatusKind.FAILURE),
    (StatusCode.DATA_HASH_MALFORMED, "assertion.dataHash.malformed", StatusKind.FAILURE),
    (
        StatusCode.DATA_HASH_ADDITIONAL_EXCLUSIONS,
        "assertion.dataHash.additionalExclusionsPresent",
        StatusKind.INFORMATIONAL,
    ),
    (StatusCode.ASSERTION_HASHED_URI_MATCH, "assertion.hashedURI.match", StatusKind.SUCCESS),
    (StatusCode.ASSERTION_HASHED_URI_MISMATCH, "assertion.hashedURI.mismatch", StatusKind.FAILURE),
    (StatusCode.ASSERTION_ACTION_MALFORMED, "assertion.action.malformed", StatusKind.FAILURE),
    (
        StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH,
        "assertion.action.ingredientMismatch",
        StatusKind.FAILURE,
    ),
    (
        StatusCode.ASSERTION_ACTION_REDACTION_MISMATCH,
        "assertion.action.redactionMismatch",
        StatusKind.FAILURE,
    ),
    (
        StatusCode.ASSERTION_ACTION_SOFT_BINDING_MISSING,
        "assertion.action.softBindingMissing",
        StatusKind.FAILURE,
    ),
    (
        StatusCode.ASSERTION_CLOUD_DATA_HARD_BINDING,
        "assertion.cloud-data.hardBinding",
        StatusKind.FAILURE,
    ),
    (StatusCode.ASSERTION_CLOUD_DATA_MALFORMED, "assertion.cloud-data.malformed", StatusKind.FAILURE),
    (StatusCode.ASSERTION_CBOR_INVALID, "assertion.cbor.invalid", StatusKind.FAILURE),
    (
        StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED,
        "assertion.external-reference.malformed",
        StatusKind.FAILURE,
    ),
    (StatusCode.ASSERTION_JSON_INVALID, "assertion.json.invalid", StatusKind.FAILURE),
    (StatusCode.ASSERTION_MISSING, "assertion.missing", StatusKind.FAILURE),
    (StatusCode.ASSERTION_UNDECLARED, "assertion.undeclared", StatusKind.FAILURE),
    (StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS, "assertion.multipleHardBindings", StatusKind.FAILURE),
    (StatusCode.ASSERTION_OUTSIDE_MANIFEST, "assertion.outsideManifest", StatusKind.FAILURE),
    (StatusCode.ASSERTION_SELF_REDACTED, "assertion.selfRedacted", StatusKind.FAILURE),
    (StatusCode.ASSERTION_TIMESTAMP_MALFORMED, "assertion.timestamp.malformed", StatusKind.FAILURE),
    (StatusCode.GENERAL_ERROR, "general.error", StatusKind.FAILURE),
    (StatusCode.CLAIM_SIGNATURE_VALIDATED, "claimSignature.validated", StatusKind.SUCCESS),
    (StatusCode.CLAIM_SIGNATURE_MISMATCH, "claimSignature.mismatch", StatusKind.FAILURE),
    (StatusCode.CLAIM_SIGNATURE_MISSING, "claimSignature.missing", StatusKind.FAILURE),
    (StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY, "claimSignature.insideValidity", StatusKind.SUCCESS),
    (StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY, "claimSignature.outsideValidity", StatusKind.FAILURE),
    (StatusCode.SIGNING_CREDENTIAL_TRUSTED, "signingCredential.trusted", StatusKind.SUCCESS),
    (StatusCode.SIGNING_CREDENTIAL_UNTRUSTED, "signingCredential.untrusted", StatusKind.FAILURE),
    (StatusCode.SIGNING_CREDENTIAL_INVALID, "signingCredential.invalid", StatusKind.FAILURE),
    (StatusCode.CLAIM_CBOR_INVALID, "claim.cbor.invalid", StatusKind.FAILURE),
    (StatusCode.CLAIM_MALFORMED, "claim.malformed", StatusKind.FAILURE),
    (StatusCode.CLAIM_MISSING, "claim.missing", StatusKind.FAILURE),
    (StatusCode.HASHED_URI_MISSING, "hashedURI.missing", StatusKind.FAILURE),
    (StatusCode.HASHED_URI_MISMATCH, "hashedURI.mismatch", StatusKind.FAILURE),
    (StatusCode.CLAIM_MULTIPLE, "claim.multiple", StatusKind.FAILURE),
    (StatusCode.CLAIM_HARD_BINDINGS_MISSING, "claim.hardBindings.missing", StatusKind.FAILURE),
    (StatusCode.MANIFEST_MULTIPLE_PARENTS, "manifest.multipleParents", StatusKind.FAILURE),
    (StatusCode.ALGORITHM_UNSUPPORTED, "algorithm.unsupported", StatusKind.FAILURE),
]


@pytest.mark.parametrize(("member", "wire", "kind"), _SPEC_STATUS)
def test_codes_are_the_specification_strings_and_buckets(
    member: StatusCode,
    wire: str,
    kind: StatusKind,
) -> None:
    """Pin the complete validation-status vocabulary and its 15.2.2 bucket."""
    assert member.value == wire
    assert _KIND[member] is kind


def test_the_literal_status_table_covers_every_member_once() -> None:
    assert [member for member, _, _ in _SPEC_STATUS] == list(StatusCode)


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


def test_the_untrusted_code_is_a_failure_but_does_not_invalidate() -> None:
    """The distinction the whole result model rests on.

    signingCredential.untrusted sits in the FAILURE bucket, yet 14.3.5's definition
    of a Valid manifest deliberately omits signingCredential.trusted from its
    conditions -- 14.3.6 adds it for Trusted. So a self-signed credential yields a
    failure code while the manifest remains Valid.
    """
    assert Status(StatusCode.SIGNING_CREDENTIAL_UNTRUSTED).kind is StatusKind.FAILURE
    assert Status(StatusCode.SIGNING_CREDENTIAL_TRUSTED).kind is StatusKind.SUCCESS


def test_status_carries_a_jumbf_uri_and_stays_frozen() -> None:
    status = Status(StatusCode.DATA_HASH_MISMATCH, url="self#jumbf=c2pa.assertions")
    assert str(status) == "assertion.dataHash.mismatch"
    assert status.url == "self#jumbf=c2pa.assertions"
    with pytest.raises(AttributeError):
        status.url = "other"  # type: ignore[misc]
