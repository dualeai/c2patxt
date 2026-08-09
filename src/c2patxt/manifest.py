"""
The C2PA manifest store: claim, assertion store, and the hashed URIs between them.

Structure, per C2PA 2.4 clause 11.1.4.2::

    c2pa   Manifest Store        (JUMBF superbox, label "c2pa")
      c2ma   Manifest            (label "urn:c2pa:<uuid>")
        c2as   Assertion Store   (label "c2pa.assertions")
          <assertion superboxes, one per assertion>
        c2cl   Claim             (label "c2pa.claim.v2", one cbor content box)
        c2cs   Claim Signature   (label "c2pa.signature", one cbor content box)

``ManifestStore`` is an OUTPUT-ONLY type. It is what :func:`extract` returns and what
``Verdict`` carries; it is never accepted as an input, because :func:`embed` takes a
signer and a disclosure and builds the manifest itself. An extracted manifest is
attacker-controlled data, and the naming should make that hard to forget.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import uuid

from c2patxt import _cbor, _jumbf
from c2patxt._jumbf import DescriptionBox, JumbfBox, content_type_uuid
from c2patxt.signing import Disclosure

__all__ = [
    "Assertion",
    "Claim",
    "ManifestStore",
    "build_manifest_store",
    "hashed_uri",
]

# Box UUIDs, from C2PA 11.1.4.2. All follow the <4CC> pattern.
UUID_MANIFEST_STORE = content_type_uuid(b"c2pa")
UUID_MANIFEST = content_type_uuid(b"c2ma")
UUID_ASSERTION_STORE = content_type_uuid(b"c2as")
UUID_CLAIM = content_type_uuid(b"c2cl")
UUID_CLAIM_SIGNATURE = content_type_uuid(b"c2cs")

LABEL_MANIFEST_STORE = "c2pa"
LABEL_ASSERTION_STORE = "c2pa.assertions"
LABEL_CLAIM = "c2pa.claim.v2"
#: The specification version this producer declares in every claim (10.2.3.2). A
#: semver-string, as the CDDL requires and as the clause's own example spells it:
#: "2.4.0" for version 2.4, not a bare "2.4".
SPEC_VERSION = "2.4.0"

LABEL_CLAIM_SIGNATURE = "c2pa.signature"

#: The URI a claim uses to point at its own signature box, in 8.4.2.1's
#: manifest-relative form. Validators resolve it under 15.7.
CLAIM_SIGNATURE_URI = f"self#jumbf={LABEL_CLAIM_SIGNATURE}"

ASSERTION_URI_PREFIX = f"self#jumbf={LABEL_ASSERTION_STORE}/"
"""The manifest-relative assertion URI prefix (8.4.2.1)."""

#: C2PA 13.1 permits exactly these three and states that implementations "shall not
#: support additional algorithms on an optional basis".
HASH_ALGORITHMS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
DEFAULT_HASH_ALGORITHM = "sha256"
_MAX_TSTR_LENGTH = 1_000_000
_UUID_VERSION = 4

#: IPTC digital source type for content produced by a generative model.
DIGITAL_SOURCE_TYPE_TRAINED = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"

ASSERTION_HASH_DATA = "c2pa.hash.data"
#: C2PA 18.15.1 defines deprecated ``c2pa.actions`` v1 and current
#: ``c2pa.actions.v2``. This producer emits v2.
ASSERTION_ACTIONS = "c2pa.actions.v2"

ASSERTION_ACTIONS_V1 = "c2pa.actions"
"""The deprecated v1 actions label, accepted on read and never emitted (C2PA 5.1).

Validation applies the fields v1 and v2 share. V2-only template and plural
``softwareAgents`` fields are not inferred for a v1 body.
"""
ASSERTION_AI_DISCLOSURE = "c2pa.ai-disclosure"
ASSERTION_METADATA = "c2pa.metadata"
ASSERTION_REPOSITORY_RECEIPT = "c2pa.repository-receipt"


@dataclasses.dataclass(frozen=True, slots=True)
class Assertion:
    """One assertion: a label and its payload, in the serialization its clause requires."""

    label: str
    payload: object
    """Any CBOR-encodable value. Typed as ``object`` rather than ``CborValue``
    because that alias's map-key union is invariant, which makes an ordinary
    ``dict[str, ...]`` unassignable to it. ``_cbor.dumps`` validates at encode time."""

    json_ld: bytes | None = None
    """Pre-serialized JSON-LD, when the clause requires JSON rather than CBOR.

    Table 7 (18.4) lists ``c2pa.metadata`` and ``c2pa.repository-receipt`` as JSON-LD.
    This producer emits metadata only. Section 18.17.2 requires one JSON content box
    and an ``@context`` property.
    """

    def to_box(self) -> JumbfBox:
        """Wrap as a requestable JUMBF superbox holding a single content box."""
        if self.json_ld is not None:
            return JumbfBox(
                description=DescriptionBox(uuid=_jumbf.UUID_JSON, label=self.label, requestable=True),
                content=((b"json", self.json_ld),),
            )
        return JumbfBox(
            description=DescriptionBox(uuid=_jumbf.UUID_CBOR, label=self.label, requestable=True),
            content=((b"cbor", _cbor.dumps(self.payload)),),
        )


def hashed_uri(box: JumbfBox, url: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> dict[str, object]:
    """Build a ``hashed-uri-map`` linking the claim to an assertion (C2PA 8.4.2).

    The hash covers the description box and the content boxes but EXCLUDES the
    superbox header (8.4.2.3). Getting that wrong produces a claim that verifies
    structurally while every assertion link fails.
    """
    if algorithm not in HASH_ALGORITHMS:
        msg = f"unsupported hash algorithm {algorithm!r}; C2PA 13.1 permits {sorted(HASH_ALGORITHMS)}"
        raise ValueError(msg)

    serialized = _jumbf.serialize_superbox(box)
    # Strip the superbox's own LBox+TBox: 8.4.2.3 hashes what is inside it.
    digest = HASH_ALGORITHMS[algorithm](serialized[8:]).digest()
    return {"url": url, "alg": algorithm, "hash": digest}


@dataclasses.dataclass(frozen=True, slots=True)
class Claim:
    """A ``claim-map-v2`` (C2PA 10.2.1).

    Required fields, enforced on read by 15.6.2: ``instanceID``, ``signature``,
    ``created_assertions`` and ``claim_generator_info`` with a ``name``. A claim
    missing any of them is rejected as ``claim.malformed``.
    """

    instance_id: str
    claim_generator_name: str
    claim_generator_version: str | None
    created_assertions: tuple[dict[str, object], ...]
    signature_url: str
    algorithm: str = DEFAULT_HASH_ALGORITHM

    def __post_init__(self) -> None:
        try:
            name_size = len(self.claim_generator_name.encode("utf-8"))
        except (AttributeError, UnicodeEncodeError) as exc:
            msg = "claim generator name must be a UTF-8 text string"
            raise ValueError(msg) from exc
        if not 1 <= name_size <= _MAX_TSTR_LENGTH:
            msg = "claim generator name must contain 1 to 1,000,000 UTF-8 bytes (C2PA generator-info-map)"
            raise ValueError(msg)

    def to_payload(self) -> dict[str, object]:
        generator: dict[str, object] = {"name": self.claim_generator_name}
        if self.claim_generator_version is not None:
            generator["version"] = self.claim_generator_version
        # 10.2.3.2 places specVersion in claim_generator_info. Declaring 2.4 also states
        # that this producer emits no construct deprecated in that version.
        generator["specVersion"] = SPEC_VERSION
        return {
            "instanceID": self.instance_id,
            # claim-map-v2 carries one generator-info map; v1 used an array.
            "claim_generator_info": generator,
            "created_assertions": list(self.created_assertions),
            "signature": self.signature_url,
            "alg": self.algorithm,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class _PreparedManifest:
    """The assertion boxes and exact claim bytes for one producer candidate."""

    assertion_boxes: tuple[JumbfBox, ...]
    claim_bytes: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class ManifestStore:
    """A parsed C2PA manifest store. OUTPUT ONLY -- never an input to embed().

    Attributes:
        manifest_label: the ``urn:c2pa:`` label of the active manifest (8.1).
        claim: the decoded claim payload.
        assertions: label to decoded payload. UNAUTHENTICATED until the claim's
            hashed-URI links have been verified; see ``verify()``.
        assertion_bytes: label to the RAW bytes C2PA 8.4.2.3 hashes -- the assertion's
            serialized superbox with its own LBox+TBox stripped. Carried through from
            the parse rather than re-serialized, because re-serializing would hash our
            encoding of the box instead of the bytes that arrived, and an attacker who
            can make those differ can substitute an assertion undetected.
        claim_bytes: the claim's raw cbor content-box bytes -- exactly what the
            signature covers. Kept verbatim because re-encoding the decoded claim
            could produce different bytes and silently break verification.
        signature: the raw ``COSE_Sign1`` bytes from the claim-signature box.
        raw: the complete serialized store, needed to re-verify without re-encoding.
    """

    manifest_label: str
    claim: dict[str, _cbor.CborValue]
    claim_bytes: bytes
    assertions: dict[str, _cbor.CborValue]
    assertion_bytes: dict[str, bytes]
    signature: bytes
    raw: bytes

    def assertion(self, label: str) -> _cbor.CborValue:
        """Return one assertion payload.

        Raises:
            KeyError: if absent. Callers that tolerate absence should use
                ``.assertions.get``.
        """
        return self.assertions[label]

    @property
    def hash_data(self) -> dict[str, _cbor.CborValue] | None:
        """The ``c2pa.hash.data`` assertion, or None if the manifest carries none.

        Absence is ``claim.hardBindings.missing`` at the validation layer (15.12),
        not an error here -- this type is a parsed view, not a verdict.
        """
        payload = self.assertions.get(ASSERTION_HASH_DATA)
        if not isinstance(payload, dict):
            return None
        # CBOR permits int and bytes keys; a C2PA assertion uses text keys, and
        # anything else is not addressable by name.
        return {key: value for key, value in payload.items() if isinstance(key, str)}


def _actions_assertion(when: datetime.datetime) -> Assertion:
    """The ``c2pa.created`` action.

    ``digitalSourceType`` is ``trainedAlgorithmicMedia``: this content was produced
    by a generative model, which is the single fact the mark exists to carry.
    """
    return Assertion(
        label=ASSERTION_ACTIONS,
        payload={
            "actions": [
                {
                    "action": "c2pa.created",
                    "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED,
                    # The actions-v2 CDDL types `when` as tdate, encoded with CBOR tag
                    # 0. UTC instants use the `Z` form.
                    "when": _cbor.Tagged(0, when.isoformat().replace("+00:00", "Z")),
                }
            ]
        },
    )


def _ai_disclosure_assertion(disclosure: Disclosure) -> Assertion:
    """The ``c2pa.ai-disclosure`` assertion (C2PA 18.28).

    ``modelType`` is the only required field. ``contentProfile.humanOversightLevel``
    is deliberately omitted: it describes how much a human reviewed the generation,
    which is a property of the customer's process upstream of us. We hold no reliable
    signal for it, and a guessed value inside a signed assertion is worse than its
    absence. Being optional in 18.28.2, omitting it needs no deviation note.

    Also omitted, because the specification marks them pending: ``modelFrontier``,
    ``trainingCleared``, ``category``, ``harmEvaluation``, ``evaluationMethod`` and
    ``evaluationDate``.
    """
    payload: dict[str, object] = {"modelType": disclosure.model_type}
    if disclosure.model_name is not None:
        payload["modelName"] = disclosure.model_name
    if disclosure.model_identifier is not None:
        payload["modelIdentifier"] = disclosure.model_identifier
    return Assertion(label=ASSERTION_AI_DISCLOSURE, payload=payload)


def _metadata_assertion(disclosure: Disclosure) -> Assertion:
    """The ``c2pa.metadata`` assertion, carrying ``dc:format`` (C2PA 18.17).

    This producer records the format in metadata because ``claim-map-v2`` removed its
    former ``dc:format`` field. C2PA 18.21.3 also says exact IANA text/application
    types should appear in ``c2pa.asset-type.v2``; emitting that additional assertion
    would change the signed producer wire and is not part of the current profile.
    """
    # JSON-LD in a `json` content box, with @context, per 18.17.2. Serialized with
    # sorted keys and no whitespace so the bytes are deterministic -- the hashed-URI
    # link covers them, so an unstable encoding would break byte-stable re-marking.
    document = {
        "@context": {"dc": "http://purl.org/dc/elements/1.1/"},
        "dc:format": disclosure.media_type,
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return Assertion(label=ASSERTION_METADATA, payload=document, json_ld=payload)


def _hash_data_assertion(
    digest: bytes,
    start: int,
    length: int,
    *,
    algorithm: str,
    pad: bytes,
) -> Assertion:
    """The ``c2pa.hash.data`` hard binding (C2PA 18.5.2).

    ``pad`` is required and must be zero-filled. The A.8 size solver leaves it empty
    and changes the separate unprotected COSE padding described by 10.4.2 and 10.4.4.
    This producer does not preallocate the assertion box, so it does not need the
    optional data-hash ``pad2`` used to bridge preallocated CBOR size gaps.

    ``url`` is deprecated: "claim generators shall not add this field".
    """
    if any(pad):
        msg = "data-hash pad must be zero-filled (C2PA 18.5.2)"
        raise ValueError(msg)
    payload: dict[str, _cbor.CborValue] = {
        "exclusions": [{"start": start, "length": length}],
        "alg": algorithm,
        "hash": digest,
        "pad": pad,
    }
    return Assertion(label=ASSERTION_HASH_DATA, payload=payload)


def _prepare_manifest(
    *,
    disclosure: Disclosure,
    digest: bytes,
    exclusion_start: int,
    exclusion_length: int,
    instance_id: str,
    when: datetime.datetime,
    generator_name: str,
    generator_version: str | None = None,
    algorithm: str = DEFAULT_HASH_ALGORITHM,
    pad: bytes = b"",
) -> _PreparedManifest:
    """Build each assertion box and the signed claim bytes once for one candidate."""
    assertions = [
        _actions_assertion(when),
        _ai_disclosure_assertion(disclosure),
        _metadata_assertion(disclosure),
        _hash_data_assertion(
            digest,
            exclusion_start,
            exclusion_length,
            algorithm=algorithm,
            pad=pad,
        ),
    ]
    assertion_boxes = tuple(assertion.to_box() for assertion in assertions)
    created = [
        hashed_uri(box, f"{ASSERTION_URI_PREFIX}{assertion.label}", algorithm)
        for assertion, box in zip(assertions, assertion_boxes, strict=True)
    ]
    claim = Claim(
        instance_id=instance_id,
        claim_generator_name=generator_name,
        claim_generator_version=generator_version,
        created_assertions=tuple(created),
        signature_url=CLAIM_SIGNATURE_URI,
        algorithm=algorithm,
    )
    return _PreparedManifest(assertion_boxes=assertion_boxes, claim_bytes=_cbor.dumps(claim.to_payload()))


def _serialize_prepared_manifest(
    prepared: _PreparedManifest,
    *,
    signature: bytes,
    manifest_uuid: uuid.UUID,
) -> bytes:
    """Insert a signature beside the exact assertion boxes and claim bytes it covers."""
    if manifest_uuid.variant != uuid.RFC_4122 or manifest_uuid.version != _UUID_VERSION:
        msg = "manifest_uuid must be an RFC 4122 variant UUID version 4 (C2PA 8.1)"
        raise ValueError(msg)

    # C2PA 11.1.4.2 requires a `urn:c2pa:` label. It identifies this manifest and is
    # the resolution context for manifest-relative `self#jumbf` URIs. Python's UUID
    # string form is lowercase; RFC 9562 permits upper-, lower- or mixed-case hex.
    manifest_label = f"urn:c2pa:{manifest_uuid}"

    assertion_store = JumbfBox(
        description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
        content=tuple((b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in prepared.assertion_boxes),
    )
    claim_box = JumbfBox(
        description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
        content=((b"cbor", prepared.claim_bytes),),
    )
    signature_box = JumbfBox(
        description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
        content=((b"cbor", signature),),
    )

    manifest = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST, label=manifest_label),
        content=tuple(
            (b"jumb", _jumbf.serialize_superbox(box)[8:]) for box in (assertion_store, claim_box, signature_box)
        ),
    )
    store = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label=LABEL_MANIFEST_STORE),
        content=((b"jumb", _jumbf.serialize_superbox(manifest)[8:]),),
    )
    return _jumbf.serialize_superbox(store)


def build_manifest_store(
    *,
    disclosure: Disclosure,
    digest: bytes,
    exclusion_start: int,
    exclusion_length: int,
    signature: bytes,
    instance_id: str,
    manifest_uuid: uuid.UUID,
    when: datetime.datetime,
    generator_name: str,
    generator_version: str | None = None,
    algorithm: str = DEFAULT_HASH_ALGORITHM,
    pad: bytes = b"",
) -> bytes:
    """Assemble a complete manifest store from caller-supplied deterministic inputs.

    This remains public for compatibility with the package's pre-1.0 releases. The
    producer uses the private prepared-manifest path so it signs and emits the same
    claim bytes; callers of this lower-level builder remain responsible for supplying
    the matching signature.
    """
    prepared = _prepare_manifest(
        disclosure=disclosure,
        digest=digest,
        exclusion_start=exclusion_start,
        exclusion_length=exclusion_length,
        instance_id=instance_id,
        when=when,
        generator_name=generator_name,
        generator_version=generator_version,
        algorithm=algorithm,
        pad=pad,
    )
    return _serialize_prepared_manifest(prepared, signature=signature, manifest_uuid=manifest_uuid)
