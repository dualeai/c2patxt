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
#: manifest-relative form. Named rather than inlined because a validator must RESOLVE
#: this field (15.7) rather than assume it, so the producing and validating sides are
#: two separate readings of one rule and the constant is where they are seen to agree.
CLAIM_SIGNATURE_URI = f"self#jumbf={LABEL_CLAIM_SIGNATURE}"

ASSERTION_URI_PREFIX = f"self#jumbf={LABEL_ASSERTION_STORE}/"
"""The manifest-relative assertion URI prefix (8.4.2.1).

DERIVED, NOT SPELLED OUT, for the reason `CLAIM_SIGNATURE_URI` already gives: the
producing and validating sides are two separate readings of one rule, and the constant
is where they are seen to agree. This was a literal in three places -- the producer's
f-string here and two prefixes in `_verify` -- for the URI written four times per
manifest, which is the one most worth deriving.
"""

#: C2PA 13.1 permits exactly these three and states that implementations "shall not
#: support additional algorithms on an optional basis".
HASH_ALGORITHMS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
DEFAULT_HASH_ALGORITHM = "sha256"

#: IPTC digital source type for content produced by a generative model.
DIGITAL_SOURCE_TYPE_TRAINED = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"

ASSERTION_HASH_DATA = "c2pa.hash.data"
#: C2PA 18.15.1: "There are two versions of the actions assertion - the deprecated v1
#: (with label c2pa.actions) and the new v2 (which shall have a label of
#: c2pa.actions.v2)." 5.1 makes "deprecated" mean a claim generator SHALL NOT write
#: it, and Appendix C.1 lists c2pa.actions as deprecated in both 2.3 and 2.4. We
ASSERTION_ACTIONS = "c2pa.actions.v2"

ASSERTION_ACTIONS_V1 = "c2pa.actions"
"""The deprecated v1 actions label. READ ONLY -- we never emit it.

C2PA 5.1: a deprecated construct "can be read, but never written".

THIS CITED 6.6 AND 6.6 IS ASSERTION SALTS. The repo used both numbers for the same
rule, eight lines apart in this file. Two independent citations settle it without
reaching for the specification: ``_embed.py`` cites 6.6 for salt boxes existing "for
secure redaction, which needs per-assertion randomness", and this file cites 5.1
twice more for ``specVersion`` declaration -- so 5.1 is versioning, which is where
"deprecated" is defined. Recorded because the compatibility inventory only checks
that a clause NUMBER appears somewhere, so it cannot catch a number filed under the
wrong meaning. 15.10.3.2.3 opens
"If the assertion's label is c2pa.actions or c2pa.actions.v2", and Table 7 lists the two
as one row, so a validator that knows only v2 rejects a conforming v1 manifest -- and
reports assertion.missing, naming a condition that is not the one that failed.

Accepting the LABEL is not accepting the v2 SHAPE. The rules applied to a v1 body are
the ones v1 shares: the ``actions`` array, each entry's ``action`` name, and
``digitalSourceType``. ``templates`` and the plural ``softwareAgents`` are v2-only, and
a v1 body carries neither, so the reference walk simply finds nothing.
"""
ASSERTION_AI_DISCLOSURE = "c2pa.ai-disclosure"
ASSERTION_METADATA = "c2pa.metadata"


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

    ONE ASSERTION WE EMIT NEEDS THIS. Table 7 (18.4) lists ``c2pa.metadata`` as JSON-LD
    -- and also ``c2pa.repository-receipt``, plus Embedded File entries for ingredients
    and thumbnails, none of which we produce. 18.17.2 is explicit: "Each metadata
    assertion shall contain a single JSON content type box containing the JSON-LD
    serialization of one or more metadata values. The @context property within the
    JSON-LD object shall be included".
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
    structurally while every assertion link fails, and it is the first thing to
    instrument when chasing a mismatch against another implementation.
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

    def to_payload(self) -> dict[str, object]:
        generator: dict[str, object] = {"name": self.claim_generator_name}
        if self.claim_generator_version is not None:
            generator["version"] = self.claim_generator_version
        # 10.2.3.2 and 5.1: a claim generator "should declare which version of the
        # specification it is using". 2.4 raised this from "may" to "should" and moved
        # the field OUT of the claim into the generator info map, deprecating the
        # claim-level one -- so it belongs here and nowhere else.
        #
        # It carries real information rather than decoration: 5.1 says setting it
        # declares the manifest "does not contain any constructs that are deprecated in
        # that version", and we emit c2pa.actions.v2 precisely because c2pa.actions is
        # deprecated at 2.4. Changing this constant is therefore a claim about the
        # WHOLE producer, not a version bump.
        generator["specVersion"] = SPEC_VERSION
        return {
            "instanceID": self.instance_id,
            # A BARE MAP, not an array. The two claim versions differ here and the
            # difference is easy to miss:
            #   claim-map    (v1): "claim_generator_info": [1* generator-info-map]
            #   claim-map-v2     : "claim_generator_info": $generator-info-map
            # We emit c2pa.claim.v2, so an array makes the claim claim.malformed to a
            # CDDL-strict validator. c2pa-rs agrees, serializing only cgi[0] as a bare
            # object for V2 claims. The signature covers these bytes, so getting it
            # wrong cannot be patched after the fact.
            "claim_generator_info": generator,
            "created_assertions": list(self.created_assertions),
            "signature": self.signature_url,
            "alg": self.algorithm,
        }


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
    """The ``c2pa.created`` action (RFC-136 4).

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
                    # TAG 0, not a bare string. 18.15.12's CDDL types this `tdate`,
                    # 6.9 defines that as "serialized in CBOR as tag number 0", and
                    # the spec's own example writes 0("2023-02-11T09:00:00Z"). We
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

    THIS IS WHERE ``dc:format`` LIVES IN A v2 CLAIM. The spec is explicit: "The
    c2pa.claim has a dc:format field which is no longer present in c2pa.claim.v2",
    and 18.17 defines the metadata assertion as the standardized home for exactly
    this kind of field. Putting it in an assertion rather than the claim also means it
    is covered by a hashed-URI link and therefore authenticated, which a claim field
    would be too but by a different route.

    It is not decoration. The C2PA Text Asset Conformance Rubric v0.1.0's second
    check, ``text:is_text_asset``, is "Active manifest declares a supported text MIME
    type in dc:format" -- so a manifest without it fails the only formal conformance
    instrument that exists for text.
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


def _hash_data_assertion(digest: bytes, start: int, length: int, algorithm: str, pad: bytes) -> Assertion:
    """The ``c2pa.hash.data`` hard binding (C2PA 18.5.2).

    ``pad`` is REQUIRED -- the CDDL has no ``?`` on it -- and validators "shall
    ignore the presence and contents of pad and pad2". It is also the only
    spec-sanctioned place to put slack bytes (10.4 "Multiple Step Processing"), which
    is what :mod:`c2patxt._fixpoint` uses to hit an exact wrapper length. A.8 defines
    no padding mechanism of its own, so padding anywhere else would be an invention
    that no other implementation could be expected to agree with.

    ``pad2`` is not emitted. 10.4.4 introduces it because deterministic CBOR makes
    some total sizes unreachable with one length-prefixed field; we reach every size
    instead by varying the CONTENT of ``pad`` rather than only its length, since a
    zero byte costs 3 UTF-8 bytes as a variation selector and a high byte costs 4.

    ``url`` is deprecated: "claim generators shall not add this field".
    """
    return Assertion(
        label=ASSERTION_HASH_DATA,
        payload={
            "exclusions": [{"start": start, "length": length}],
            "alg": algorithm,
            "hash": digest,
            "pad": pad,
        },
    )


def _assertions_and_claim(
    *,
    disclosure: Disclosure,
    digest: bytes,
    exclusion_start: int,
    exclusion_length: int,
    instance_id: str,
    when: datetime.datetime,
    generator_name: str,
    generator_version: str | None,
    algorithm: str,
    pad: bytes,
) -> tuple[list[Assertion], Claim]:
    """The assertion list and the claim that links it -- built ONCE, for both callers.

    ``embed`` SIGNS the claim from :func:`claim_payload_bytes` and SHIPS the claim
    built inside :func:`build_manifest_store`. Those were two literal copies of the six
    lines below: the assertion list, its order, the labels, the URI template and the
    algorithm. They agreed, and nothing made them agree -- drift would have surfaced to
    a caller as ``claimSignature.mismatch``, sending an investigator into COSE and
    certificate handling rather than to a copy-paste in this file.

    That is the pattern this package already applies once and states the reason for:
    ``build_wrapper`` and ``parse_wrapper_body`` share ``MAX_MANIFEST_LENGTH`` because
    "refusing to produce something we would refuse to read keeps the two halves of the
    codec from disagreeing". One source, so the question cannot arise.
    """
    assertions = [
        _actions_assertion(when),
        _ai_disclosure_assertion(disclosure),
        _metadata_assertion(disclosure),
        _hash_data_assertion(digest, exclusion_start, exclusion_length, algorithm, pad),
    ]
    created = [hashed_uri(item.to_box(), f"{ASSERTION_URI_PREFIX}{item.label}", algorithm) for item in assertions]
    claim = Claim(
        instance_id=instance_id,
        claim_generator_name=generator_name,
        claim_generator_version=generator_version,
        created_assertions=tuple(created),
        signature_url=CLAIM_SIGNATURE_URI,
        algorithm=algorithm,
    )
    return assertions, claim


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
    """Assemble a complete manifest store and return its serialized JUMBF bytes.

    Every varying input is a parameter. Nothing here reads a clock, calls an RNG or
    generates a UUID, so the output is a pure function of its arguments -- which is
    what makes byte-stable re-embedding testable at all. The caller supplies the
    clock and identifiers; see ``EmbedContext``.
    """
    assertions, claim = _assertions_and_claim(
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

    # C2PA 11.1.4.2: "shall be labelled with a urn:c2pa value". 8.1's ABNF is
    #   c2pa_urn = "urn:c2pa:" UUID [claim-generator [version-reason]]
    # NOT urn:uuid:, which is RFC 9562's namespace. The label lives inside the SIGNED claim and inside every
    # self#jumbf= resolution path, so it is a wire defect rather than a cosmetic one.
    # The two optional suffixes are omitted: version-reason applies only to manifests
    # versioned due to a conflict, which we never produce.
    #
    # THE UUID IS LOWERCASE, AND THAT CONFORMS. 8.1's ABNF spells the hex digits with
    # RFC 5234's core rule, HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F", which
    # reads as uppercase-only -- and Python's uuid stringifies lowercase, so the label
    # looks like it violates the grammar that governs it. It does not: RFC 5234 2.3
    # says "ABNF strings are case insensitive", so the terminal "A" matches "a", and a
    # grammar wanting case sensitivity must use RFC 7405's %s prefix, which 8.1 does
    # not. RFC 9562 4 then settles the direction -- UUIDs SHOULD be output lowercase.
    #
    # Worth writing down because the label sits inside the SIGNED claim and inside
    # every self#jumbf resolution path, so changing its case later would be a MAJOR
    # version of this package and of the vector file. It is pinned by
    # test_the_manifest_label_is_lowercase_and_that_is_deliberate.
    manifest_label = f"urn:c2pa:{manifest_uuid}"

    assertion_store = JumbfBox(
        description=DescriptionBox(uuid=UUID_ASSERTION_STORE, label=LABEL_ASSERTION_STORE),
        content=tuple((b"jumb", _jumbf.serialize_superbox(item.to_box())[8:]) for item in assertions),
    )
    claim_box = JumbfBox(
        description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
        content=((b"cbor", _cbor.dumps(claim.to_payload())),),
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


def claim_payload_bytes(
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
) -> bytes:
    """Return the claim's CBOR content-box bytes -- the payload the signature covers.

    C2PA 13.2.2 calls this "the contents of the claim JUMBF box" while 10.3.2.4 calls
    it "the serialized CBOR of the claim document". They reconcile through 8.4.2.3's
    rule that JUMBF hashing covers the description and content boxes but not the
    superbox header, which makes this the claim's cbor content-box bytes. It is the
    first thing to instrument on a signature mismatch against another implementation.
    """
    _assertions, claim = _assertions_and_claim(
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
    return _cbor.dumps(claim.to_payload())
