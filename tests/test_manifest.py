"""Manifest-store structure, deterministic construction, and emitted schemas."""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import uuid

import pytest

from c2patxt import EmbedContext, _jumbf, embed, extract
from c2patxt._extract import parse_manifest_store
from c2patxt.manifest import (
    ASSERTION_HASH_DATA,
    ASSERTION_METADATA,
    HASH_ALGORITHMS,
    LABEL_CLAIM,
    LABEL_CLAIM_SIGNATURE,
    UUID_MANIFEST_STORE,
    Assertion,
    Claim,
    ManifestStore,
    build_manifest_store,
    hashed_uri,
)
from c2patxt.signing import Disclosure, ModelType, Signer
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


def _store(
    *,
    disclosure: Disclosure | None = None,
    digest: bytes = DIGEST,
    exclusion_start: int = 11,
    exclusion_length: int = 74,
    signature: bytes = b"\xaa" * 64,
    instance_id: str = "xmp:iid:00000000-0000-4000-8000-000000000002",
    manifest_uuid: uuid.UUID = MANIFEST_UUID,
    when: datetime.datetime = WHEN,
    generator_name: str = "c2patxt",
    generator_version: str | None = None,
    algorithm: str = "sha256",
    pad: bytes = b"",
) -> bytes:
    return build_manifest_store(
        disclosure=disclosure or _disclosure(),
        digest=digest,
        exclusion_start=exclusion_start,
        exclusion_length=exclusion_length,
        signature=signature,
        instance_id=instance_id,
        manifest_uuid=manifest_uuid,
        when=when,
        generator_name=generator_name,
        generator_version=generator_version,
        algorithm=algorithm,
        pad=pad,
    )


def _embedded_store(
    signer: Signer,
    *,
    generator_version: str | None = None,
    manifest_uuid: uuid.UUID = MANIFEST_UUID,
) -> ManifestStore:
    """Return the parsed output of the public producer with every varying input pinned."""
    context = EmbedContext(
        manifest_uuid=manifest_uuid,
        instance_id="xmp:iid:1",
        when=WHEN,
        generator_version=generator_version,
    )
    store = extract(embed("Manifest test.", signer, _disclosure(), context=context))
    assert store is not None
    return store


def _nested_superboxes(box: _jumbf.JumbfBox) -> list[_jumbf.JumbfBox]:
    """Parse nested JUMBF boxes without duplicating their codec."""
    children: list[_jumbf.JumbfBox] = []
    for kind, payload in box.content:
        if kind != _jumbf.TBOX_SUPERBOX:
            continue
        child, end = _jumbf.parse_superbox(b"\x00\x00\x00\x00jumb" + payload)
        assert end == len(payload) + 8
        children.append(child)
    return children


def test_store_parses_as_a_jumbf_superbox_with_the_right_label() -> None:
    box, end = _jumbf.parse_superbox(_store())
    assert box.description.uuid == UUID_MANIFEST_STORE
    assert box.description.label == "c2pa"
    assert end == len(_store())


def test_the_manifest_label_is_a_c2pa_urn(signer: Signer) -> None:
    """C2PA 8.1 labels each manifest ``urn:c2pa:<uuid>``."""
    assert _embedded_store(signer).manifest_label == f"urn:c2pa:{MANIFEST_UUID}"


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


def test_representative_signed_inputs_change_the_bytes() -> None:
    """Determinism must not come from ignoring inputs."""
    baseline = _store()
    assert _store(digest=bytes(range(1, 33))) != baseline
    assert _store(exclusion_start=12) != baseline
    assert _store(signature=b"\xbb" * 64) != baseline
    assert _store(when=WHEN + datetime.timedelta(seconds=1)) != baseline


@pytest.mark.parametrize(
    "when",
    [
        WHEN.replace(tzinfo=None),
        datetime.datetime(
            2026,
            6,
            1,
            12,
            0,
            tzinfo=datetime.timezone(datetime.timedelta(seconds=30)),
        ),
    ],
    ids=["naive", "seconds-resolution-offset"],
)
def test_public_builder_refuses_a_time_without_an_rfc3339_offset(when: datetime.datetime) -> None:
    with pytest.raises(ValueError, match=r"timezone-aware|whole-minute UTC offset"):
        _store(when=when)


def test_the_created_action_declares_trained_algorithmic_media(signer: Signer) -> None:
    """The public producer emits the exact C2PA action and IPTC vocabulary term."""
    actions = as_mapping(_embedded_store(signer).assertion("c2pa.actions.v2"), "c2pa.actions.v2")
    entries = actions["actions"]
    assert isinstance(entries, list)
    assert entries
    created = as_mapping(entries[0], "c2pa.actions.v2.actions[0]")

    # Independent literals: importing either production constant would let the test
    # follow a wrong vocabulary term or action name without observing the wire defect.
    assert created["action"] == "c2pa.created"
    assert created["digitalSourceType"] == "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"


def test_metadata_is_json_ld_in_a_json_content_box(signer: Signer) -> None:
    """C2PA 18.17.2 fixes both the serialization and the required context."""
    outer, _ = _jumbf.parse_superbox(_embedded_store(signer).raw)
    manifest = _nested_superboxes(outer)[0]
    assertion_store = next(box for box in _nested_superboxes(manifest) if box.description.label == "c2pa.assertions")
    metadata = next(box for box in _nested_superboxes(assertion_store) if box.description.label == ASSERTION_METADATA)

    assert metadata.description.uuid == _jumbf.UUID_JSON
    assert len(metadata.content) == 1
    kind, raw = metadata.content[0]
    assert kind == b"json"
    document = json.loads(raw)
    assert document == {
        "@context": {"dc": "http://purl.org/dc/elements/1.1/"},
        "dc:format": "text/plain",
    }


def test_claim_carries_the_fields_15_6_2_requires(signer: Signer) -> None:
    """A claim missing any of these is claim.malformed on read."""
    fields = _embedded_store(signer, generator_version="0.1.0").claim
    assert {"instanceID", "signature", "created_assertions", "claim_generator_info"} <= set(fields)

    # A map, not an array. The two claim versions differ here:
    #   claim-map    (v1): "claim_generator_info": [1* generator-info-map]
    #   claim-map-v2     : "claim_generator_info": $generator-info-map
    # We emit c2pa.claim.v2, whose claim_generator_info field is a map.
    generator = as_mapping(fields["claim_generator_info"], "claim_generator_info")
    assert generator["name"] == "c2patxt"
    assert generator["version"] == "0.1.0"


def test_public_builder_enforces_instance_id_utf8_byte_bounds() -> None:
    exact_limit = "é" * 500_000
    assert parse_manifest_store(_store(instance_id=exact_limit)).claim["instanceID"] == exact_limit

    for invalid in ("", exact_limit + "x", "\ud800"):
        with pytest.raises(ValueError, match="claim instanceID"):
            _store(instance_id=invalid)


def test_claim_rejects_a_non_text_instance_id() -> None:
    with pytest.raises(ValueError, match="claim instanceID must be a UTF-8 text string"):
        Claim(
            instance_id=7,  # pyright: ignore[reportArgumentType] -- defensive runtime validation
            claim_generator_name="c2patxt",
            claim_generator_version=None,
            created_assertions=(),
            signature_url="self#jumbf=c2pa.signature",
        )


def test_public_builder_accepts_only_zero_filled_data_hash_padding() -> None:
    """18.5.2: producer data-hash pad bytes are zero-filled."""
    store = parse_manifest_store(_store(pad=bytes(24)))
    assert store.hash_data is not None
    assert store.hash_data["pad"] == bytes(24)

    with pytest.raises(ValueError, match="must be zero-filled"):
        _store(pad=b"\x00\xff")


def test_hashed_uri_excludes_the_superbox_header() -> None:
    """8.4.2.3: the hash covers the description and content boxes, not the header.

    Getting this wrong yields a claim that verifies structurally while every
    assertion link fails.
    """
    assertion = Assertion(label="c2pa.actions", payload={"a": 1})
    box = assertion.to_box()
    link = hashed_uri(box, "self#jumbf=c2pa.assertions/c2pa.actions")

    serialized = _jumbf.serialize_superbox(box)
    assert link["hash"] == hashlib.sha256(serialized[8:]).digest()
    assert link["hash"] != hashlib.sha256(serialized).digest()
    assert link["alg"] == "sha256"


def test_only_the_three_permitted_hash_algorithms_exist() -> None:
    """13.1: "shall not support additional algorithms on an optional basis"."""
    assert set(HASH_ALGORITHMS) == {"sha256", "sha384", "sha512"}
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        hashed_uri(Assertion(label="x", payload=1).to_box(), "self#jumbf=x", "md5")


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        ("sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            "sha384",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            "sha512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ],
)
def test_hash_registry_matches_nist_abc_known_answers(algorithm: str, expected: str) -> None:
    """The name-to-function mapping has an expected value outside this package."""
    assert HASH_ALGORITHMS[algorithm](b"abc").hexdigest() == expected


def test_ai_disclosure_omits_pending_and_oversight_fields(signer: Signer) -> None:
    """18.28: modelType is the only required field.

    humanOversightLevel is omitted deliberately -- it describes the customer's
    process, we hold no signal for it, and a guessed value inside a signed assertion
    is worse than its absence. The pending fields are omitted because the
    specification marks them pending.
    """
    disclosure = as_mapping(
        _embedded_store(signer).assertion("c2pa.ai-disclosure"),
        "c2pa.ai-disclosure",
    )
    for absent in ("humanOversightLevel", "modelFrontier", "trainingCleared", "harmEvaluation"):
        assert absent not in disclosure


def test_manifest_store_accessors() -> None:
    """ManifestStore is a parsed view, not a verdict: absence is not an error here."""
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


def test_the_manifest_label_uses_the_required_uuid_v4(signer: Signer) -> None:
    """C2PA 8.1 requires a version-4 UUID in every manifest identifier.

    The label also follows 11.1.4.2's ``urn:c2pa`` form::

        c2pa_urn       = c2pa-namespace UUID [claim-generator [version-reason]]
        c2pa-namespace = "urn:c2pa:"
    """
    manifest_uuid = uuid.UUID("8f14e45f-ea18-4c9b-b3a2-7d1e6f0a5b2c")
    label = _embedded_store(signer, manifest_uuid=manifest_uuid).manifest_label
    assert label == f"urn:c2pa:{manifest_uuid}"
    assert re.fullmatch(
        r"urn:c2pa:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        label,
    )


@pytest.mark.parametrize("manifest_uuid", [uuid.UUID(int=0), uuid.UUID(int=7)])
def test_the_public_producer_refuses_a_manifest_identifier_that_is_not_uuid_v4(
    manifest_uuid: uuid.UUID,
) -> None:
    with pytest.raises(ValueError, match="UUID version 4"):
        EmbedContext(manifest_uuid=manifest_uuid)


@pytest.mark.parametrize("manifest_uuid", [uuid.UUID(int=0), uuid.UUID(int=7)])
def test_the_public_manifest_builder_refuses_an_identifier_that_is_not_uuid_v4(
    manifest_uuid: uuid.UUID,
) -> None:
    with pytest.raises(ValueError, match="UUID version 4"):
        _store(manifest_uuid=manifest_uuid)


def test_public_builder_enforces_generator_name_utf8_byte_bounds() -> None:
    exact_limit = "é" * 500_000
    claim = parse_manifest_store(_store(generator_name=exact_limit)).claim
    generator = claim["claim_generator_info"]
    assert isinstance(generator, dict)
    assert generator["name"] == exact_limit

    for invalid in ("", exact_limit + "x"):
        with pytest.raises(ValueError, match="1 to 1,000,000 UTF-8 bytes"):
            _store(generator_name=invalid)


def test_the_manifest_label_uses_pythons_lowercase_uuid_form(signer: Signer) -> None:
    """Lowercase UUID text satisfies 8.1; RFC 9562 permits either case.

    ``c2pa_urn = "urn:c2pa:" UUID``, and the UUID's hex digits come from RFC 5234's
    core ``HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"`` -- uppercase as written.
    Python's ``uuid`` stringifies lowercase. RFC 5234 2.3 makes ABNF string terminals
    case-insensitive, so the terminal
    ``"A"`` matches ``a``; a grammar needing case sensitivity uses RFC 7405's ``%s``
    prefix, which 8.1 does not. Python's stable lowercase form is the producer's wire
    choice, not an RFC 9562 requirement.
    """
    # Hex digits above 9 in every group make case observable.
    manifest_uuid = uuid.UUID("abcdefab-cdef-4bcd-abcd-efabcdefabcd")
    assert str(manifest_uuid) != str(manifest_uuid).upper(), "the fixture must not be case-neutral"

    label = _embedded_store(signer, manifest_uuid=manifest_uuid).manifest_label

    assert label == f"urn:c2pa:{manifest_uuid}"
    assert label != label.upper(), "the emitted label must preserve lowercase hex"
    assert re.fullmatch(r"urn:c2pa:[0-9a-f-]{36}", label), "and must match 8.1's shape, lowercase"
