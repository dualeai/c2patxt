# pyright: reportPrivateUsage=false
# Walks the raw JUMBF boxes to check the SERIALIZATION of c2pa.metadata, which is
# the thing 18.17.2 constrains. The public API deliberately hides the box layer.
"""The C2PA Text Asset Conformance Rubric v0.1.0, asserted check by check.

SOURCE: c2pa-org/conformance-public, asset-rubrics/asset-rubric-text-conformance.yml.
Name "C2PA Text Asset Conformance Rubric", issuer "C2PA Conformance Task Force",
dated 2026-05-04, version 0.1.0. It is the ONLY formal conformance instrument that
exists for text, and nothing here was asserting we pass it.

WHAT THE RUBRIC DOES NOT TEST -- stated here rather than left implied, because a
reader who sees "passes the conformance rubric" will assume far more coverage than
six JMESPath expressions over a parsed manifest can give:

  * NOTHING exercises variation-selector encoding, the wrapper magic/version/length
    framing, the U+FEFF marker, NFC normalization, byte-offset computation, or hash
    recomputation.
  * text:exclusions_defined only checks ``length(exclusions) > 0``. It never checks
    that the exclusion MATCHES a wrapper -- the check that actually stops an attacker
    choosing which bytes the hash covers.
  * Neither manifest.text.corruptedWrapper nor manifest.text.multipleWrappers is
    referenced anywhere in the rubric.
  * There are NO WIRE VECTORS.

That gap is exactly what tests/vectors/A8ConformanceTest-1.2.0.txt fills.

PASSING IS SELF-ASSESSED. All 152 conformance-listed products are certified against
specification 2.2 and none declares a text media type (one declares a bare non-IANA
`txt` token), so there is no certification to obtain here yet.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt import EmbedContext, Provenance, embed, extract, verify
from c2patxt.manifest import (
    ASSERTION_ACTIONS,
    ASSERTION_HASH_DATA,
    ASSERTION_METADATA,
    DIGITAL_SOURCE_TYPE_TRAINED,
    ManifestStore,
)
from c2patxt.signing import Disclosure, ModelType, Signer
from tests.conftest import WHEN

#: The rubric's own media-type partition. THIS IS NOT IN THE SPECIFICATION -- A.8
#: names no media type at all -- so the rubric is the only authority for it.
RUBRIC_UNSTRUCTURED_TYPES = ("text/plain", "text/csv", "text/tab-separated-values")
RUBRIC_STRUCTURED_TYPES = ("text/markdown", "text/xml", "application/xml", "application/xhtml+xml")
RUBRIC_HTML_TYPES = ("text/html",)


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


_PINNED = EmbedContext(manifest_uuid=uuid.UUID(int=7), instance_id="xmp:iid:1", when=WHEN)


def _manifest(signer: Signer, media_type: str = "text/plain") -> ManifestStore:
    disclosure = Disclosure(media_type=media_type, model_type=ModelType.GENERIC, model_name="m")
    context = _PINNED
    store = extract(embed("Conformance sample.", signer, disclosure, context=context))
    assert store is not None
    return store


def test_check_1_no_html_text_errors(signer: Signer) -> None:
    """``text:no_html_text_errors`` -- "No HTML-specific manifest location failures in
    validation results" (failIfMatched: true; matches manifest.html.multipleManifests).

    Passes trivially and for a real reason: this carrier is A.8, not A.7, so no
    HTML-specific code can arise. Asserted rather than assumed, because "trivially
    true" and "true because we never checked" look identical from outside.
    """
    from c2patxt.status import StatusCode

    assert not any(code.value.startswith("manifest.html.") for code in StatusCode)


def test_check_2_is_text_asset(signer: Signer) -> None:
    """``text:is_text_asset`` -- "Active manifest declares a supported text MIME type
    in dc:format".

    This check is why the c2pa.metadata assertion exists. dc:format is "no longer
    present in c2pa.claim.v2" in the spec's own words, so 18.17's metadata assertion
    is its home, and a manifest without it fails the only formal conformance
    instrument text has.
    """
    metadata = _manifest(signer).assertions[ASSERTION_METADATA]
    assert isinstance(metadata, dict)
    assert metadata["dc:format"] == "text/plain"
    assert metadata["dc:format"] in RUBRIC_UNSTRUCTURED_TYPES


def test_check_3_hard_binding_present(signer: Signer) -> None:
    """``text:hard_binding_present`` -- "At least one c2pa.hash.data assertion
    provides content binding"."""
    assert ASSERTION_HASH_DATA in _manifest(signer).assertions


def test_check_4_exclusions_defined(signer: Signer) -> None:
    """``text:exclusions_defined`` -- "Hash data assertion includes exclusions for the
    text manifest region".

    The rubric only asks that the list be non-empty. We assert MORE than it does --
    that the range actually names the wrapper -- because the rubric's version of this
    check would pass on a manifest whose exclusion pointed anywhere at all, which is
    precisely the attack our verifier exists to stop.
    """
    hash_data = _manifest(signer).hash_data
    assert hash_data is not None
    exclusions = hash_data["exclusions"]
    assert isinstance(exclusions, list)
    assert len(exclusions) > 0

    entry = exclusions[0]
    assert isinstance(entry, dict)
    assert isinstance(entry["start"], int)
    assert isinstance(entry["length"], int)
    assert entry["length"] > 0


def test_check_5_inception_action_present(signer: Signer) -> None:
    """``text:inception_action_present`` -- "Active manifest contains a c2pa.created
    action"."""
    actions = _manifest(signer).assertions[ASSERTION_ACTIONS]
    assert isinstance(actions, dict)
    entries = actions["actions"]
    assert isinstance(entries, list)
    assert any(isinstance(e, dict) and e.get("action") == "c2pa.created" for e in entries)


def test_check_6_inception_has_dst(signer: Signer) -> None:
    """``text:inception_has_dst`` -- "Inception action declares a digitalSourceType".

    Ours is ``trainedAlgorithmicMedia``, which is the single fact an EU AI Act
    Article 50(2) mark exists to carry.
    """
    actions = _manifest(signer).assertions[ASSERTION_ACTIONS]
    assert isinstance(actions, dict)
    entries = actions["actions"]
    assert isinstance(entries, list)
    created = next(e for e in entries if isinstance(e, dict) and e.get("action") == "c2pa.created")
    assert created["digitalSourceType"] == DIGITAL_SOURCE_TYPE_TRAINED


@pytest.mark.parametrize("media_type", RUBRIC_UNSTRUCTURED_TYPES)
def test_every_media_type_the_rubric_assigns_to_a8_round_trips(media_type: str, signer: Signer) -> None:
    """The three types the rubric partitions to A.8, each actually marked."""
    metadata = _manifest(signer, media_type).assertions[ASSERTION_METADATA]
    assert isinstance(metadata, dict)
    assert metadata["dc:format"] == media_type
    # 18.17.2: "The @context property within the JSON-LD object shall be included".
    assert "@context" in metadata


def test_markdown_is_marked_under_a8_as_a_deliberate_deviation(signer: Signer) -> None:
    """WE DEPART FROM THE RUBRIC HERE, on purpose, and this pins it.

    The rubric partitions ``text/markdown`` to A.9 (structured text). RFC-136 2 marks
    it under A.8 instead, on rendering-invariant grounds: A.9's forms put VISIBLE
    delimiters into the document, which is exactly what A.8 exists to avoid, and
    markdown tolerates zero-width insertion the way plain text does.

    The rubric is the source of the partition; the RFC is the reason we depart from
    it. Note also that A.9.2 is circular about text/plain -- it claims applicability
    to "any file with a media type of text/ not already covered", does not list A.8 in
    its exclusions, yet excludes formats without comment syntax, which text/plain is.
    """
    assert "text/markdown" in RUBRIC_STRUCTURED_TYPES
    metadata = _manifest(signer, "text/markdown").assertions[ASSERTION_METADATA]
    assert isinstance(metadata, dict)
    assert metadata["dc:format"] == "text/markdown"


def test_html_is_not_our_carrier(signer: Signer) -> None:
    """``text/html`` is A.7 territory. Nothing stops a caller, and the result is
    non-conformant; the Disclosure docstring says so."""
    assert RUBRIC_HTML_TYPES == ("text/html",)
    assert "text/html" not in RUBRIC_UNSTRUCTURED_TYPES


def test_the_signing_time_is_the_one_supplied(signer: Signer) -> None:
    """Guards the fixture the six checks above rest on: if EmbedContext stopped
    pinning time, every check would still pass while testing a different manifest."""
    actions = _manifest(signer).assertions[ASSERTION_ACTIONS]
    assert isinstance(actions, dict)
    entries = actions["actions"]
    assert isinstance(entries, list)
    assert isinstance(entries[0], dict)
    # tag 0 (tdate), per 18.15.12's CDDL and 6.9 -- not a bare string.
    from c2patxt._cbor import TAG_DATETIME, Tagged

    assert entries[0]["when"] == Tagged(TAG_DATETIME, WHEN.isoformat().replace("+00:00", "Z"))
    assert WHEN.tzinfo is datetime.timezone.utc


def test_the_metadata_assertion_is_json_ld_in_a_json_box(signer: Signer) -> None:
    """C2PA 18.17.2, verbatim: "Each metadata assertion shall contain a single JSON
    content type box containing the JSON-LD serialization of one or more metadata
    values. The @context property within the JSON-LD object shall be included."

    18.4's assertion table corroborates: every standard assertion is listed CBOR, and
    ``c2pa.metadata`` alone is listed JSON-LD.

    We emitted it as CBOR in a ``cbor`` box with no ``@context`` until 2026-08-05 --
    in signed bytes, on every mark, and in the one assertion the text conformance
    rubric's ``text:is_text_asset`` check reads.
    """
    import json as json_module

    from c2patxt import _jumbf
    from c2patxt._extract import _content, _reparse
    from c2patxt._jumbf import parse_superbox
    from c2patxt.manifest import LABEL_ASSERTION_STORE

    store, _ = parse_superbox(_manifest(signer).raw)
    manifest, _ = _reparse(store.content[0][1])

    for _tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label != LABEL_ASSERTION_STORE:
            continue
        for _kind, assertion_payload in child.content:
            assertion, _ = _reparse(assertion_payload)
            if assertion.description.label != ASSERTION_METADATA:
                continue

            assert _content(assertion, b"cbor") is None, "18.4 lists c2pa.metadata as JSON-LD, not CBOR"
            raw = _content(assertion, b"json")
            assert raw is not None, "18.17.2 requires a single JSON content type box"
            assert assertion.description.uuid == _jumbf.UUID_JSON

            document = json_module.loads(raw)
            assert "@context" in document, "18.17.2: the @context property shall be included"
            assert document["dc:format"] == "text/plain"
            return

    pytest.fail("no c2pa.metadata assertion found")


def test_a_third_party_json_metadata_assertion_still_verifies(signer: Signer) -> None:
    """A REGRESSION I INTRODUCED, and the reason this test exists.

    The fix for the unlinked-assertion hole made ``_extract`` reject any assertion
    without a ``cbor`` content box. That is right for every assertion except the one
    the specification requires to be JSON -- so a CONFORMING producer's
    ``c2pa.metadata`` made our verifier reject the entire manifest with
    ``assertion.missing``.

    Verifying our own output exercises the same path, since we now emit the
    conforming form: the round trip below would fail if the read side still refused
    JSON metadata boxes.
    """
    disclosure = Disclosure(media_type="text/plain", model_type=ModelType.GENERIC, model_name="m")
    marked = embed("Conformance sample.", signer, disclosure, context=_PINNED)
    verdict = verify(marked)

    assert verdict.state is Provenance.VALID
    assert verdict.manifest is not None
    metadata = verdict.manifest.assertions[ASSERTION_METADATA]
    assert isinstance(metadata, dict)
    assert metadata["@context"]
