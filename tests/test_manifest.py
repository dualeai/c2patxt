"""Manifest store: structure, determinism, and the payload prohibition."""

from __future__ import annotations

import datetime
import re
import uuid

import pytest

from c2patxt import _cbor, _jumbf
from c2patxt._jumbf import JumbfBox
from c2patxt.manifest import (
    ASSERTION_AI_DISCLOSURE,
    ASSERTION_HASH_DATA,
    CLAIM_SIGNATURE_URI,
    DIGITAL_SOURCE_TYPE_TRAINED,
    HASH_ALGORITHMS,
    LABEL_CLAIM,
    LABEL_CLAIM_SIGNATURE,
    UUID_MANIFEST_STORE,
    Assertion,
    Claim,
    build_manifest_store,
    claim_payload_bytes,
    hashed_uri,
)
from c2patxt.signing import Disclosure, ModelType
from tests._json import as_mapping

WHEN = datetime.datetime(2026, 8, 5, 12, 0, tzinfo=datetime.timezone.utc)
MANIFEST_UUID = uuid.UUID("00000000-0000-4000-8000-000000000001")
DIGEST = bytes(range(32))


def _disclosure() -> Disclosure:
    return Disclosure(
        media_type="text/plain",
        model_type=ModelType.GENERIC,
        model_name="test-model",
        model_identifier="pkg:generic/test-model@1",
    )


def _store(**overrides: object) -> bytes:
    kwargs: dict[str, object] = {
        "disclosure": _disclosure(),
        "digest": DIGEST,
        "exclusion_start": 11,
        "exclusion_length": 74,
        "signature": b"\xaa" * 64,
        "instance_id": "xmp:iid:00000000-0000-4000-8000-000000000002",
        "manifest_uuid": MANIFEST_UUID,
        "when": WHEN,
        "generator_name": "c2patxt",
    }
    kwargs.update(overrides)
    return build_manifest_store(**kwargs)  # type: ignore[arg-type]


def test_store_parses_as_a_jumbf_superbox_with_the_right_label() -> None:
    box, end = _jumbf.parse_superbox(_store())
    assert box.description.uuid == UUID_MANIFEST_STORE
    assert box.description.label == "c2pa"
    assert end == len(_store())


def test_the_manifest_label_is_a_c2pa_urn() -> None:
    """C2PA 8.1: each manifest is labelled urn:c2pa:<uuid>.

    This test PINNED THE DEFECT until 2026-08-05: it asserted ``urn:uuid:`` and cited
    8.1, which says the opposite.
    """
    store, _ = _jumbf.parse_superbox(_store())
    manifest, _ = _jumbf.parse_superbox(b"\x00\x00\x00\x00jumb" + store.content[0][1])
    assert manifest.description.label == f"urn:c2pa:{MANIFEST_UUID}"


def test_the_manifest_holds_assertion_store_claim_and_signature() -> None:
    """11.1.4.2 structure, in order."""
    store, _ = _jumbf.parse_superbox(_store())
    manifest, _ = _jumbf.parse_superbox(b"\x00\x00\x00\x00jumb" + store.content[0][1])
    assert len(manifest.content) == 3

    labels: list[str | None] = []
    for _, payload in manifest.content:
        child, _ = _jumbf.parse_superbox(b"\x00\x00\x00\x00jumb" + payload)
        labels.append(child.description.label)
    assert labels == ["c2pa.assertions", LABEL_CLAIM, LABEL_CLAIM_SIGNATURE]


def test_construction_is_deterministic() -> None:
    """No clock read, no RNG, no UUID generated inside. Byte-stable by construction.

    Every varying input is a parameter, which is what makes a byte-stable re-embed
    testable at all.
    """
    assert len({_store() for _ in range(20)}) == 1


def test_changing_any_input_changes_the_bytes() -> None:
    """Determinism must not come from ignoring inputs."""
    baseline = _store()
    assert _store(digest=bytes(range(1, 33))) != baseline
    assert _store(exclusion_start=12) != baseline
    assert _store(signature=b"\xbb" * 64) != baseline
    assert _store(when=WHEN + datetime.timedelta(seconds=1)) != baseline


def test_the_created_action_declares_trained_algorithmic_media() -> None:
    """The one fact the mark exists to carry."""
    payload = claim_payload_bytes(
        disclosure=_disclosure(),
        digest=DIGEST,
        exclusion_start=11,
        exclusion_length=74,
        instance_id="xmp:iid:1",
        when=WHEN,
        generator_name="c2patxt",
    )
    assert isinstance(_cbor.loads(payload), dict)
    # THE FULL LITERAL, not a suffix. Replacing this constant with
    # "http://example.invalid/NOT-IPTC/trainedAlgorithmicMedia" left the entire suite
    # green -- so we could have shipped a digitalSourceType no IPTC-aware consumer
    # recognises, on a compliance artefact, and nothing would have said so. A suffix
    # check cannot see the vocabulary the term belongs to, and the vocabulary is the
    # whole point: the term means something because IPTC defines it.
    assert DIGITAL_SOURCE_TYPE_TRAINED == "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"


def test_claim_carries_the_fields_15_6_2_requires() -> None:
    """A claim missing any of these is claim.malformed on read."""
    claim = _cbor.loads(
        claim_payload_bytes(
            disclosure=_disclosure(),
            digest=DIGEST,
            exclusion_start=11,
            exclusion_length=74,
            instance_id="xmp:iid:1",
            when=WHEN,
            generator_name="c2patxt",
            generator_version="0.1.0",
        )
    )
    fields = as_mapping(claim, "claim")
    assert {"instanceID", "signature", "created_assertions", "claim_generator_info"} <= set(fields)

    # A BARE MAP, not an array. The two claim versions differ here:
    #   claim-map    (v1): "claim_generator_info": [1* generator-info-map]
    #   claim-map-v2     : "claim_generator_info": $generator-info-map
    # We emit c2pa.claim.v2, so an array is claim.malformed to a CDDL-strict
    # validator, and the signature covers these bytes so it cannot be patched later.
    # This test previously asserted the ARRAY, which is how the wrong shape survived.
    generator = as_mapping(fields["claim_generator_info"], "claim_generator_info")
    assert generator["name"] == "c2patxt"
    assert generator["version"] == "0.1.0"


def test_the_claim_is_deterministically_encoded_cbor() -> None:
    """10.1 mandates RFC 8949 4.2.1; our decoder rejects anything else."""
    payload = claim_payload_bytes(
        disclosure=_disclosure(),
        digest=DIGEST,
        exclusion_start=11,
        exclusion_length=74,
        instance_id="xmp:iid:1",
        when=WHEN,
        generator_name="c2patxt",
    )
    assert _cbor.loads(payload) is not None  # round-trips through the strict decoder


def test_hash_data_assertion_shape() -> None:
    """18.5.2: exclusions, alg, hash, and a REQUIRED pad."""
    assertion = Assertion(
        label=ASSERTION_HASH_DATA,
        payload={"exclusions": [{"start": 1, "length": 2}], "alg": "sha256", "hash": DIGEST, "pad": b""},
    )
    box = assertion.to_box()
    assert box.description.label == ASSERTION_HASH_DATA
    assert box.content[0][0] == b"cbor"


def test_hashed_uri_excludes_the_superbox_header() -> None:
    """8.4.2.3: the hash covers the description and content boxes, not the header.

    Getting this wrong yields a claim that verifies structurally while every
    assertion link fails.
    """
    assertion = Assertion(label="c2pa.actions", payload={"a": 1})
    box = assertion.to_box()
    link = hashed_uri(box, "self#jumbf=c2pa.assertions/c2pa.actions")

    serialized = _jumbf.serialize_superbox(box)
    assert link["hash"] == HASH_ALGORITHMS["sha256"](serialized[8:]).digest()
    assert link["hash"] != HASH_ALGORITHMS["sha256"](serialized).digest()
    assert link["alg"] == "sha256"


def test_only_the_three_permitted_hash_algorithms_exist() -> None:
    """13.1: "shall not support additional algorithms on an optional basis"."""
    assert set(HASH_ALGORITHMS) == {"sha256", "sha384", "sha512"}
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        hashed_uri(Assertion(label="x", payload=1).to_box(), "self#jumbf=x", "md5")


def test_the_manifest_carries_no_identifying_fields() -> None:
    """Our marking policy, enforced in code rather than by review.

    Three independent legal grounds forbid tenant, agent, account, end-user, author,
    prompt and conversation content. Because embed() takes a closed Disclosure, none
    of it can reach the manifest -- this asserts that end to end over the real bytes.
    """
    blob = _store()
    for forbidden in (b"tenant", b"agent", b"account", b"prompt", b"conversation", b"author"):
        assert forbidden not in blob.lower()


def test_ai_disclosure_omits_pending_and_oversight_fields() -> None:
    """18.28: modelType is the only required field.

    humanOversightLevel is omitted deliberately -- it describes the customer's
    process, we hold no signal for it, and a guessed value inside a signed assertion
    is worse than its absence. The pending fields are omitted because the
    specification marks them pending.
    """
    payload = claim_payload_bytes(
        disclosure=_disclosure(),
        digest=DIGEST,
        exclusion_start=11,
        exclusion_length=74,
        instance_id="xmp:iid:1",
        when=WHEN,
        generator_name="c2patxt",
    )
    blob = _store()
    assert ASSERTION_AI_DISCLOSURE.encode() in blob
    for absent in (b"humanOversightLevel", b"modelFrontier", b"trainingCleared", b"harmEvaluation"):
        assert absent not in blob
    assert payload


def test_manifest_store_accessors() -> None:
    """ManifestStore is a parsed view, not a verdict: absence is not an error here."""
    from c2patxt.manifest import ManifestStore

    store = ManifestStore(
        manifest_label=f"urn:c2pa:{MANIFEST_UUID}",
        claim={"instanceID": "xmp:iid:1"},
        claim_bytes=b"",
        assertions={ASSERTION_HASH_DATA: {"alg": "sha256", "hash": DIGEST}},
        assertion_bytes={},
        signature=b"\xaa" * 64,
        raw=b"",
    )
    assert store.assertion(ASSERTION_HASH_DATA) == {"alg": "sha256", "hash": DIGEST}
    assert store.hash_data == {"alg": "sha256", "hash": DIGEST}

    with pytest.raises(KeyError):
        store.assertion("c2pa.absent")


def test_hash_data_is_none_when_the_manifest_has_no_hard_binding() -> None:
    """claim.hardBindings.missing is a validation-layer verdict, not a parse error."""
    from c2patxt.manifest import ManifestStore

    store = ManifestStore(
        manifest_label="urn:c2pa:x",
        claim={},
        claim_bytes=b"",
        assertions={},
        assertion_bytes={},
        signature=b"",
        raw=b"",
    )
    assert store.hash_data is None


def test_hash_data_is_none_when_the_assertion_is_not_a_map() -> None:
    """Malformed input must not crash a parsed view."""
    from c2patxt.manifest import ManifestStore

    store = ManifestStore(
        manifest_label="urn:c2pa:x",
        claim={},
        claim_bytes=b"",
        assertions={ASSERTION_HASH_DATA: [1, 2, 3]},
        assertion_bytes={},
        signature=b"",
        raw=b"",
    )
    assert store.hash_data is None


#: Fixed values, not uuid4(). Any UUID satisfies the ABNF, so a random one adds no
#: coverage and makes a failure unreproducible from the report alone. int=0 is the
#: all-zero edge; the third is an ordinary random-looking v4 captured once.
@pytest.mark.parametrize(
    "manifest_uuid",
    [
        uuid.UUID(int=0),
        uuid.UUID(int=7),
        uuid.UUID("8f14e45f-ea18-4c9b-b3a2-7d1e6f0a5b2c"),
    ],
)
def test_the_manifest_label_follows_the_c2pa_urn_abnf(manifest_uuid: uuid.UUID) -> None:
    """C2PA 11.1.4.2: "The C2PA Manifest box shall be labelled with a urn:c2pa value".

    8.1 gives the ABNF::

        c2pa_urn       = c2pa-namespace UUID [claim-generator [version-reason]]
        c2pa-namespace = "urn:c2pa:"
        UUID           = 4hexOctet "-" 2hexOctet "-" 2hexOctet "-" 2hexOctet "-" 6hexOctet

    We emitted ``urn:uuid:`` -- the RFC 9562 namespace, not C2PA's. Not cosmetic:
    the label is inside the SIGNED claim and inside every ``self#jumbf=`` resolution
    path, so a strict consumer rejects it and no amount of re-reading fixes marks
    already produced.

    The optional ``claim-generator`` and ``version-reason`` suffixes are omitted; both
    are optional, and version-reason only applies to manifests versioned due to a
    conflict, which we never produce.
    """
    store = build_manifest_store(
        disclosure=_disclosure(),
        digest=DIGEST,
        exclusion_start=11,
        exclusion_length=74,
        signature=b"\xaa" * 64,
        instance_id="xmp:iid:1",
        manifest_uuid=manifest_uuid,
        when=WHEN,
        generator_name="c2patxt",
    )
    label = f"urn:c2pa:{manifest_uuid}".encode()
    assert label in store
    assert f"urn:uuid:{manifest_uuid}".encode() not in store
    assert re.fullmatch(
        r"urn:c2pa:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        label.decode(),
    )


def test_the_claim_declares_which_specification_version_produced_it() -> None:
    """C2PA 10.2.3.2 / 5.1: a claim generator "should declare which version of the
    specification it is using to generate the C2PA Manifest by providing a
    `specVersion` key in the claim_generator_info field of the claim."

    THE 2.4 CHANGE LOG RAISED THIS FROM "may" TO "should", and moved the field out of
    the claim itself: "Moved the specVersion field from the claim to the
    claim_generator_info object; the claim-level specVersion is now deprecated." So the
    field goes in the generator info map, and the claim-level one stays absent.

    IT CARRIES REAL INFORMATION NOW rather than being decoration. 5.1: "When a claim
    generator sets this field, it is declaring that the active manifest of the asset is
    produced in accordance with that version of the specification and thus, for example,
    does not contain any constructs that are deprecated in that version." We moved to
    `c2pa.actions.v2` precisely because `c2pa.actions` is deprecated at 2.4, so the
    declaration is a claim we can actually stand behind.

    The value is a `semver-string`, and the specification's own example uses `"2.4.0"`
    -- "e.g., '2.4.0' for version 2.4" -- so a bare "2.4" would not satisfy the type.
    """
    claim = Claim(
        instance_id="xmp:iid:1",
        claim_generator_name="c2patxt",
        claim_generator_version=None,
        created_assertions=(),
        signature_url=CLAIM_SIGNATURE_URI,
    )
    payload = claim.to_payload()
    generator = payload["claim_generator_info"]

    assert isinstance(generator, dict)
    assert generator["specVersion"] == "2.4.0"
    assert "specVersion" not in payload, "the claim-level field is deprecated at 2.4"


def test_the_manifest_label_is_lowercase_and_that_is_deliberate() -> None:
    """8.1's ABNF looks like it forbids this, and does not.

    ``c2pa_urn = "urn:c2pa:" UUID``, and the UUID's hex digits come from RFC 5234's
    core ``HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"`` -- uppercase as written.
    Python's ``uuid`` stringifies lowercase, so the label looks like it violates the
    grammar that governs it.

    IT CONFORMS. RFC 5234 2.3: "ABNF strings are case insensitive", so the terminal
    ``"A"`` matches ``a``; a grammar needing case sensitivity uses RFC 7405's ``%s``
    prefix, which 8.1 does not. RFC 9562 4 then settles the direction: UUIDs SHOULD be
    output lowercase.

    PINNED BECAUSE IT IS WIRE. The label sits inside the signed claim and inside every
    ``self#jumbf`` resolution path, so changing its case is a MAJOR version of this
    package and of the vector file, not a cosmetic edit. Nothing exercised it before:
    the one test using a literal label used an all-zero UUID, which is case-neutral.
    """
    # Hex digits above 9 in every group, so the case is actually observable -- unlike
    # MANIFEST_UUID, which is all zeros and fours and proves nothing about case.
    manifest_uuid = uuid.UUID("abcdefab-cdef-4bcd-abcd-efabcdefabcd")
    assert str(manifest_uuid) != str(manifest_uuid).upper(), "the fixture must not be case-neutral"

    raw = _store(manifest_uuid=manifest_uuid)
    expected = f"urn:c2pa:{manifest_uuid}".encode()

    assert expected in raw, "the label must appear on the wire exactly as constructed"
    assert expected.upper() not in raw, "and must not appear uppercased anywhere"
    assert re.fullmatch(rb"urn:c2pa:[0-9a-f-]{36}", expected), "and must match 8.1's shape, lowercase"


def test_the_two_claim_builders_produce_identical_bytes() -> None:
    """``embed`` SIGNS the output of ``claim_payload_bytes`` and SHIPS the claim built
    inside ``build_manifest_store``. They are two literal copies of the same six lines
    -- the assertion list, its order, the labels, the URI template, the algorithm.

    They agree today. Nothing made them agree, and the failure mode is misdirecting:
    drift surfaces as ``claimSignature.mismatch``, which sends an investigator into
    COSE and certificate handling rather than to a copy-paste in this file.

    This is the pattern the package already applies once and states the reason for --
    ``build_wrapper`` and ``parse_wrapper_body`` share ``MAX_MANIFEST_LENGTH`` because
    "refusing to produce something we would refuse to read keeps the two halves of the
    codec from disagreeing". The same argument holds here and was not applied.

    ASSERTED RATHER THAN REFACTORED. Deriving one from the other is the better fix and
    is a larger change to a wire-producing path; until then this is what makes the
    duplication safe, and it fails the moment either copy is edited alone.
    """
    from c2patxt._jumbf import parse_superbox
    from c2patxt.manifest import claim_payload_bytes

    signed = claim_payload_bytes(
        disclosure=_disclosure(),
        digest=DIGEST,
        exclusion_start=11,
        exclusion_length=74,
        instance_id="xmp:iid:00000000-0000-4000-8000-000000000002",
        when=WHEN,
        generator_name="c2patxt",
        pad=b"",
    )

    store, _ = parse_superbox(_store(pad=b""))
    shipped = _claim_bytes_from(store)

    assert shipped == signed, (
        "the claim that is SIGNED and the claim that is SHIPPED have diverged; "
        "this surfaces to a caller as claimSignature.mismatch"
    )


def _claim_bytes_from(store: JumbfBox) -> bytes:
    """Dig the claim's CBOR out of a parsed manifest store.

    Reaches for ``_reparse`` because nested superboxes are kept opaque by ``_jumbf`` --
    it is a pure box codec and does not know a manifest from an assertion store.
    """
    from c2patxt._extract import (
        _reparse,  # pyright: ignore[reportPrivateUsage] -- the only way to open a nested superbox
    )
    from c2patxt.manifest import LABEL_CLAIM

    manifest, _ = _reparse(store.content[0][1])
    for _tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_CLAIM:
            return next(body for box_type, body in child.content if box_type == b"cbor")
    msg = "no claim box in the store"
    raise AssertionError(msg)
