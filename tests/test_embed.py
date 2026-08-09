"""Tests for :func:`c2patxt.embed`.

The round trip -- embed then verify -- is the only test that proves the producer and
the consumer agree, and it is the one a wrong constant fails first.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import hashlib
import unicodedata
import uuid
from collections.abc import Callable
from typing import TypeGuard

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from c2patxt import (
    AlreadyMarkedError,
    EmbedContext,
    MarkCorruptError,
    Provenance,
    StatusCode,
    _jumbf,
    embed,
    extract,
    locate,
    strip,
    verify,
)
from c2patxt._cose import parse
from c2patxt._selectors import selector_to_byte
from c2patxt.manifest import ManifestStore
from c2patxt.signing import C2PA_CLAIM_SIGNING_EKU, Signer
from tests.conftest import DISCLOSURE, WHEN, FloatingTimezone

PINNED = EmbedContext(
    manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000007"),
    instance_id="xmp:iid:pinned",
    when=WHEN,
)
MARKER = "\ufeff"  # C2PA A.8.4.1 literal, not the production constant.


#: This suite exercises the WHOLE stack -- selectors, JUMBF, CBOR, COSE, certificate
#: profile, hash binding -- against text that genuinely satisfies the binding, rather
#: than against hand-built fragments.


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


def _assertion_cbor_bytes(store: ManifestStore, label: str) -> bytes:
    """Return the received assertion content, leaving CBOR decoding to the caller."""
    raw_box = store.assertion_bytes[label]
    box, end = _jumbf.parse_superbox(b"\x00\x00\x00\x00jumb" + raw_box)
    assert end == len(raw_box) + 8
    assert len(box.content) == 1
    kind, payload = box.content[0]
    assert kind == b"cbor"
    return payload


def _is_object_mapping(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def test_context_refuses_an_empty_generator_name() -> None:
    with pytest.raises(ValueError, match="1 to 1,000,000 UTF-8 bytes"):
        EmbedContext(generator_name="")


def test_context_limits_generator_name_by_utf8_bytes() -> None:
    exact_limit = "é" * 500_000
    assert EmbedContext(generator_name=exact_limit).generator_name == exact_limit

    with pytest.raises(ValueError, match="1 to 1,000,000 UTF-8 bytes"):
        EmbedContext(generator_name=exact_limit + "x")


def test_context_enforces_the_instance_id_utf8_byte_bounds() -> None:
    exact_limit = "é" * 500_000
    assert EmbedContext(instance_id="x").instance_id == "x"
    assert EmbedContext(instance_id=exact_limit).instance_id == exact_limit

    for invalid in ("", exact_limit + "x"):
        with pytest.raises(ValueError, match="instance_id must contain 1 to 1,000,000 UTF-8 bytes"):
            EmbedContext(instance_id=invalid)


def test_context_refuses_a_non_utf8_instance_id() -> None:
    for invalid in ("\ud800", 7):
        with pytest.raises(ValueError, match="instance_id must be a UTF-8 text string"):
            EmbedContext(instance_id=invalid)  # pyright: ignore[reportArgumentType] -- runtime API guard


# --------------------------------------------------------------------------------
# The round trip
# --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Hello world.",
        "",
        "a",
        "漢字テキスト",
        "مرحبا שלום",
        "x" * 4096,
        "line one\nline two\r\n\ttabbed",
        "emoji 👨‍👩‍👧‍👦 zwj",
        "markdown **bold** and `code`",
    ],
)
def test_embed_then_verify_round_trips(text: str, signer: Signer) -> None:
    """Public producer and verifier agree across representative UTF-8 byte costs.

    The codes prove that signature, validity, and binding checks ran. The self-signed
    fixture correctly remains untrusted while the mark is VALID under C2PA 14.3.5.
    """
    verdict = verify(embed(text, signer, DISCLOSURE, context=PINNED))

    assert verdict.state is Provenance.VALID
    codes = set(verdict.codes())
    assert {
        StatusCode.DATA_HASH_MATCH,
        StatusCode.CLAIM_SIGNATURE_VALIDATED,
        StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY,
        StatusCode.SIGNING_CREDENTIAL_UNTRUSTED,
    } <= codes


def test_nfc_text_precedes_the_wrapper_unchanged(signer: Signer) -> None:
    """For NFC input, embedding appends the wrapper without changing prior code points."""
    text = "The quick brown fox."
    marked = embed(text, signer, DISCLOSURE, context=PINNED)
    assert marked[: marked.index(MARKER)] == text
    assert marked.startswith(text)


def test_the_mark_is_a_suffix_and_there_is_exactly_one(signer: Signer) -> None:
    """Suffix placement is what makes the two normalization orders agree."""
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    assert marked.count(MARKER) == 1
    assert marked.index(MARKER) == len("Hello world.")


def test_the_exclusion_names_the_wrapper_exactly(signer: Signer) -> None:
    """15.12.1.3.1 step 3: the exclusion must correspond to a located wrapper.

    Asserted directly rather than trusted via verify(), so an off-by-one shows up
    here as an offset rather than as an unexplained hash mismatch.
    """
    text = "Hello world."
    marked = embed(text, signer, DISCLOSURE, context=PINNED)
    manifest = extract(marked)
    assert manifest is not None
    hash_data = manifest.hash_data
    assert hash_data is not None

    exclusions = hash_data["exclusions"]
    assert isinstance(exclusions, list)
    entry = exclusions[0]
    assert isinstance(entry, dict)

    encoded = marked.encode("utf-8")
    assert entry["start"] == len(text.encode("utf-8"))
    assert entry["length"] == len(encoded) - len(text.encode("utf-8"))


def test_the_wrapper_carries_the_magic_number(signer: Signer) -> None:
    """A.8.2.2: the public producer emits the literal magic and wrapper version."""
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)

    span = locate(marked)
    assert span is not None
    emitted = marked.encode("utf-8")[span.utf8_start : span.utf8_stop].decode("utf-8")

    assert emitted.startswith(MARKER)
    body = bytes(selector_to_byte(ord(char)) or 0 for char in emitted[len(MARKER) :])
    magic = bytes.fromhex("4332504154585400")
    assert body[: len(magic)] == magic
    assert body[len(magic)] == 1


def test_the_emitted_disclosure_states_the_model_type(signer: Signer) -> None:
    """The one field the artefact exists to carry, read back off the wire.

    Article 50(2) is about disclosing that content is machine-generated, and
    ``modelType`` is where that disclosure lives. On the producer side it was checked
    only as "the ``Disclosure`` constructor rejects an empty string" -- nothing read
    it back out of a marked document.
    """
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    store = extract(marked)
    assert store is not None

    disclosure = store.assertion("c2pa.ai-disclosure")
    assert isinstance(disclosure, dict)
    assert disclosure["modelType"] == DISCLOSURE.model_type
    assert disclosure["modelName"] == DISCLOSURE.model_name


def test_non_default_caller_facts_reach_the_signed_wire(signer: Signer) -> None:
    """Public inputs are held by distinct literals at the serialization boundary."""
    from c2patxt.signing import Disclosure, ModelType

    disclosure = Disclosure(
        media_type="text/csv",
        model_type=ModelType.ONNX,
        model_name="wire-model",
        model_identifier="urn:example:model:wire-v7",
    )
    context = EmbedContext(
        manifest_uuid=PINNED.manifest_uuid,
        instance_id=PINNED.instance_id,
        when=PINNED.when,
        generator_name="example-generator",
        generator_version="7.4.1",
    )
    store = extract(embed("heading,value\nanswer,42\n", signer, disclosure, context=context))
    assert store is not None

    metadata = store.assertion("c2pa.metadata")
    assert isinstance(metadata, dict)
    assert metadata == {
        "@context": {"dc": "http://purl.org/dc/elements/1.1/"},
        "dc:format": "text/csv",
    }

    ai_disclosure = store.assertion("c2pa.ai-disclosure")
    assert isinstance(ai_disclosure, dict)
    assert ai_disclosure == {
        "modelType": "c2pa.types.model.onnx",
        "modelName": "wire-model",
        "modelIdentifier": "urn:example:model:wire-v7",
    }

    generator = store.claim["claim_generator_info"]
    assert isinstance(generator, dict)
    assert generator["name"] == "example-generator"
    assert generator["version"] == "7.4.1"


def test_the_emitted_claim_keeps_a_supplied_instance_id(signer: Signer) -> None:
    """The accepted public value reaches the signed claim bytes unchanged."""
    instance_id = "com.example:instance:é"
    context = EmbedContext(
        manifest_uuid=PINNED.manifest_uuid,
        instance_id=instance_id,
        when=PINNED.when,
    )
    store = extract(embed("Hello world.", signer, DISCLOSURE, context=context))
    assert store is not None

    independently_decoded = cbor2.loads(store.claim_bytes)
    assert isinstance(independently_decoded, dict)
    assert independently_decoded["instanceID"] == instance_id
    assert store.claim["instanceID"] == instance_id


def test_the_emitted_store_carries_exactly_the_four_assertions(signer: Signer) -> None:
    """The label set of a store ``embed`` produced, not of a hand-built fixture.

    ``test_extract.py`` asserts this against ``build_manifest_store`` with a fake
    signature. Dropping an assertion from the emitted store leaves that test green.
    """
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    store = extract(marked)
    assert store is not None

    assert set(store.assertions) == {
        "c2pa.actions.v2",
        "c2pa.ai-disclosure",
        "c2pa.hash.data",
        "c2pa.metadata",
    }


def test_the_emitted_signature_declares_eddsa_in_the_protected_bucket(signer: Signer) -> None:
    """13.2.1's algorithm, on a signature ``embed`` produced."""
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    store = extract(marked)
    assert store is not None

    assert parse(store.signature).decoded_protected[1] == -8


# --------------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------------


def test_embedding_twice_with_a_pinned_context_is_byte_identical(signer: Signer) -> None:
    """The claim the whole EmbedContext design exists to make testable.

    Ed25519's deterministic nonce (RFC 8032 5.1.6) is what makes this reachable at
    all; every other varying input is pinned by the context.
    """
    first = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    second = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    assert first == second


def test_embedding_twice_without_a_context_differs(signer: Signer) -> None:
    """Unpinned marks differ, and MUST: a reused manifest UUID or instanceID across
    documents is a correctness error, not a tidiness one."""
    assert embed("Hello world.", signer, DISCLOSURE) != embed("Hello world.", signer, DISCLOSURE)


def test_an_unpinned_mark_still_verifies(signer: Signer) -> None:
    """The default path is the one users take; it must not be the untested one."""
    assert verify(embed("Hello world.", signer, DISCLOSURE)).state is Provenance.VALID


# --------------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------------


def test_nfd_input_is_normalized_before_marking(signer: Signer) -> None:
    """A.8.6.1 requires NFC for hashing; we normalize before marking so the
    producer's offsets and the verifier's are over the same bytes.

    The visible text therefore comes back as NFC, which for NFD input is a real
    change to the caller's bytes. That is deliberate and documented -- the
    alternative is a mark whose offsets no verifier can reproduce.
    """
    nfd = unicodedata.normalize("NFD", "café")
    assert nfd != "café"

    marked = embed(nfd, signer, DISCLOSURE, context=PINNED)
    assert marked[: marked.index(MARKER)] == "café"
    assert verify(marked).state is Provenance.VALID


def test_nfc_input_is_returned_byte_identical(signer: Signer) -> None:
    """NFC input is unchanged before the appended wrapper."""
    text = "café and 漢字"
    marked = embed(text, signer, DISCLOSURE, context=PINNED)
    assert marked[: marked.index(MARKER)] == text


# --------------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------------


def test_embedding_over_an_existing_mark_raises(signer: Signer) -> None:
    """Producer policy requires an explicit strip before replacement or another append."""
    marked = embed("Hello world.", signer, DISCLOSURE, context=PINNED)
    with pytest.raises(AlreadyMarkedError, match="already carries") as excinfo:
        embed(marked, signer, DISCLOSURE, context=PINNED)

    start, stop = excinfo.value.span
    encoded = marked.encode("utf-8")
    assert encoded[:start].decode("utf-8") == "Hello world."
    assert stop == len(encoded)


def test_embedding_over_an_independent_a8_carrier_raises(signer: Signer) -> None:
    """The public guard recognizes a foreign carrier, not only this producer's manifest dialect."""
    from tests.vectors.loader import load_vectors

    vector = next(item for item in load_vectors() if item.id == "E0001")
    marked = vector.expect.decode("utf-8")

    with pytest.raises(AlreadyMarkedError) as caught:
        embed(marked, signer, DISCLOSURE, context=PINNED)

    assert caught.value.span == (len(vector.text), len(vector.expect))


def test_the_already_marked_span_is_enough_to_re_mark(signer: Signer) -> None:
    """The reported span must be actionable, not merely informative."""
    text = "café 漢字"
    marked = embed(text, signer, DISCLOSURE, context=PINNED)
    with pytest.raises(AlreadyMarkedError) as excinfo:
        embed(marked, signer, DISCLOSURE, context=PINNED)

    start, stop = excinfo.value.span
    encoded = marked.encode("utf-8")
    assert start == len(text.encode("utf-8"))
    assert encoded[start:stop].decode("utf-8").startswith(MARKER)
    # The span must name exactly what strip() removes, or the error is telling the
    # caller something the shipped helper contradicts.
    assert (encoded[:start] + encoded[stop:]).decode("utf-8") == text == strip(marked)
    assert verify(embed(strip(marked), signer, DISCLOSURE, context=PINNED)).state is Provenance.VALID


def test_embedding_over_a_corrupt_mark_raises(signer: Signer) -> None:
    """Marking on top of damage would bury it under a valid-looking signature."""
    corrupt = embed("Hello world.", signer, DISCLOSURE, context=PINNED)[:-400]
    with pytest.raises(MarkCorruptError):
        embed(corrupt, signer, DISCLOSURE, context=PINNED)


def test_an_unsupported_algorithm_is_refused(signer: Signer) -> None:
    """13.1 permits sha256/384/512 and says implementations "shall not support
    additional algorithms on an optional basis"."""
    context = EmbedContext(when=WHEN, algorithm="sha1")
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        embed("Hello world.", signer, DISCLOSURE, context=context)


@pytest.mark.parametrize(("algorithm", "digest_size"), [("sha256", 32), ("sha384", 48), ("sha512", 64)])
def test_every_permitted_algorithm_reaches_every_signed_hash(
    algorithm: str,
    digest_size: int,
    signer: Signer,
) -> None:
    """The requested algorithm is observed on wire using only stdlib expected hashes."""
    context = EmbedContext(
        manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000007"),
        instance_id="x",
        when=WHEN,
        algorithm=algorithm,
    )
    marked = embed("Hello world.", signer, DISCLOSURE, context=context)
    store = extract(marked)
    assert store is not None
    assert store.hash_data is not None

    assert store.claim["alg"] == algorithm
    assert store.hash_data["alg"] == algorithm
    binding_digest = store.hash_data["hash"]
    assert isinstance(binding_digest, bytes)
    assert len(binding_digest) == digest_size
    assert binding_digest == hashlib.new(algorithm, b"Hello world.").digest()

    created_assertions = store.claim["created_assertions"]
    assert isinstance(created_assertions, list)
    assert len(created_assertions) == len(store.assertion_bytes)
    for link in created_assertions:
        assert isinstance(link, dict)
        assert link["alg"] == algorithm
        url = link["url"]
        assert isinstance(url, str)
        prefix = "self#jumbf=c2pa.assertions/"
        assert url.startswith(prefix)
        label = url.removeprefix(prefix)
        received = store.assertion_bytes[label]
        digest = link["hash"]
        assert isinstance(digest, bytes)
        assert len(digest) == digest_size
        assert digest == hashlib.new(algorithm, received).digest()

    exclusions = store.hash_data["exclusions"]
    assert isinstance(exclusions, list)
    exclusion = exclusions[0]
    assert isinstance(exclusion, dict)
    assert exclusion["length"] == len(marked[marked.index(MARKER) :].encode())
    assert verify(marked).state is Provenance.VALID


def test_a_naive_signing_time_is_refused(signer: Signer) -> None:
    """A naive datetime names no instant. Assuming UTC would silently misdate marks
    produced anywhere else."""
    context = EmbedContext(when=datetime.datetime(2026, 6, 1, 12, 0))  # noqa: DTZ001
    with pytest.raises(ValueError, match="timezone-aware"):
        embed("Hello world.", signer, DISCLOSURE, context=context)


def test_a_tzinfo_without_an_offset_is_still_refused(signer: Signer) -> None:
    """Python treats a datetime as naive when ``utcoffset()`` returns ``None``."""
    floating = datetime.datetime(2026, 6, 1, 12, 0, tzinfo=FloatingTimezone())
    with pytest.raises(ValueError, match="timezone-aware"):
        embed("Hello world.", signer, DISCLOSURE, context=EmbedContext(when=floating))


@pytest.mark.parametrize(
    ("when", "expected_tdate"),
    [
        (datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc), "2026-06-01T12:00:00Z"),
        (
            datetime.datetime(
                2026,
                6,
                1,
                12,
                0,
                tzinfo=datetime.timezone(datetime.timedelta(hours=5, minutes=30)),
            ),
            "2026-06-01T12:00:00+05:30",
        ),
    ],
)
def test_action_time_is_rfc3339_on_the_actual_wire(
    signer: Signer,
    when: datetime.datetime,
    expected_tdate: str,
) -> None:
    context = EmbedContext(
        manifest_uuid=PINNED.manifest_uuid,
        instance_id=PINNED.instance_id,
        when=when,
    )
    store = extract(embed("Hello world.", signer, DISCLOSURE, context=context))
    assert store is not None

    actions = store.assertion("c2pa.actions.v2")
    assert isinstance(actions, dict)
    entries = actions["actions"]
    assert isinstance(entries, list)
    created = entries[0]
    assert isinstance(created, dict)
    tagged = created["when"]
    assert getattr(tagged, "tag", None) == 0
    assert getattr(tagged, "value", None) == expected_tdate

    decoded: object = cbor2.loads(_assertion_cbor_bytes(store, "c2pa.actions.v2"))
    assert _is_object_mapping(decoded)
    decoded_entries = decoded.get("actions")
    assert _is_object_list(decoded_entries)
    decoded_created = decoded_entries[0]
    assert _is_object_mapping(decoded_created)
    decoded_when = decoded_created.get("when")
    assert isinstance(decoded_when, datetime.datetime)
    assert decoded_when.isoformat() == when.isoformat()


def test_a_seconds_resolution_utc_offset_is_refused(signer: Signer) -> None:
    when = datetime.datetime(
        2026,
        6,
        1,
        12,
        0,
        tzinfo=datetime.timezone(datetime.timedelta(seconds=30)),
    )
    context = EmbedContext(when=when)

    with pytest.raises(ValueError, match="whole-minute UTC offset"):
        embed("Hello world.", signer, DISCLOSURE, context=context)


def test_one_signer_marks_correctly_from_many_threads(signer: Signer) -> None:
    """README publishes "Safe to share", and nothing held it.

    The claim is specific: every public type is a frozen dataclass, the digest cache is
    per-call, there is no module-level mutable state, and ``Ed25519PrivateKey.sign`` is
    safe to call concurrently. Each of those is a reason to believe the conclusion; none
    of them IS the conclusion. This shares one ``Signer`` across threads, marks distinct
    documents, and verifies each result -- so torn state shows up as a bad verdict or a
    raised exception rather than as a passing test about immutability.
    """
    texts = [f"Document number {n}." for n in range(32)]

    def mark(text: str) -> str:
        return embed(text, signer, DISCLOSURE, context=PINNED)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        marked = list(pool.map(mark, texts))
        verdicts = list(pool.map(verify, marked))

    assert [strip(m) for m in marked] == texts
    assert all(v.state is Provenance.VALID for v in verdicts), [v.state for v in verdicts]


def _signer_with_ca(
    signing_key: Ed25519PrivateKey,
    *,
    ca_not_after: datetime.datetime = datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc),
) -> Signer:
    """Build the one carried-CA chain shared by the size and validity regressions."""
    ca_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2patxt test CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2patxt test leaf")])
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    leaf_not_after = datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(0xC2A7E47_CA)
        .not_valid_before(not_before)
        .not_valid_after(ca_not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, None)
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(signing_key.public_key())
        .serial_number(0xC2A7E47_1EAF)
        .not_valid_before(not_before)
        .not_valid_after(leaf_not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([C2PA_CLAIM_SIGNING_EKU]), critical=False)
        .sign(ca_key, None)
    )
    return Signer(private_key=signing_key, certificates=(leaf, ca))


def test_embed_refuses_an_expired_carried_ca(signing_key: Ed25519PrivateKey) -> None:
    signer = _signer_with_ca(
        signing_key,
        ca_not_after=datetime.datetime(2026, 2, 1, tzinfo=datetime.timezone.utc),
    )

    with pytest.raises(ValueError, match=r"x5chain\[1\] carried CA.*validity"):
        embed("Hello world.", signer, DISCLOSURE, context=PINNED)


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("instanceID", "xmp:iid:pinned"),
        ("alg", "sha256"),
        ("signature", "self#jumbf=c2pa.signature"),
    ],
    ids=["instanceID", "alg", "signature"],
)
def test_the_claim_fields_survive_the_round_trip_to_the_wire(signer: Signer, field: str, expected: str) -> None:
    """Required claim fields are present in the public producer's parsed wire output."""
    store = extract(embed("Hello world.", signer, DISCLOSURE, context=PINNED))
    assert store is not None
    assert store.claim[field] == expected


def test_the_spec_version_survives_the_round_trip_to_the_wire(signer: Signer) -> None:
    """C2PA 10.2.3.2 places ``specVersion`` in generator info, not the claim root."""
    store = extract(embed("Hello world.", signer, DISCLOSURE, context=PINNED))
    assert store is not None

    generator = store.claim["claim_generator_info"]
    assert isinstance(generator, dict)
    assert generator["specVersion"] == "2.4.0"
    assert "specVersion" not in store.claim, "the claim-level field is deprecated at 2.4"


#: Each function derives the boundary instant from the certificate under test.
_Moment = Callable[[x509.Certificate], datetime.datetime]

_TICK = datetime.timedelta(microseconds=1)


_WINDOW_CASES: list[tuple[_Moment, bool]] = [
    (lambda _leaf: WHEN, True),
    (lambda leaf: leaf.not_valid_before_utc, True),
    (lambda leaf: leaf.not_valid_after_utc, True),
    (lambda leaf: leaf.not_valid_before_utc - _TICK, False),
    (lambda leaf: leaf.not_valid_after_utc + _TICK, False),
    (lambda _leaf: datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc), False),
    (lambda _leaf: datetime.datetime(2047, 6, 1, tzinfo=datetime.timezone.utc), False),
]


@pytest.mark.parametrize(
    ("moment", "ok"),
    _WINDOW_CASES,
    ids=[
        "inside",
        "on-notBefore",
        "on-notAfter",
        "one-tick-before-notBefore",
        "one-tick-after-notAfter",
        "before-notBefore",
        "after-notAfter",
    ],
)
def test_embed_refuses_to_sign_with_a_credential_outside_its_validity(
    signer: Signer, moment: _Moment, ok: bool
) -> None:
    """Every certificate must cover the supplied claimed creation instant.

    The default context supplies the current time. A pinned context makes this a
    deterministic replay check; it does not attest when the function actually ran.

    RFC 5280 4.1.2.5 makes the endpoints inclusive. The adjacent-tick rows distinguish
    both endpoints from the instants immediately outside them.
    """
    when = moment(signer.certificates[0])
    context = EmbedContext(
        manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000007"),
        instance_id="xmp:iid:pinned",
        when=when,
    )

    if ok:
        assert extract(embed("Hello world.", signer, DISCLOSURE, context=context)) is not None
        return

    with pytest.raises(ValueError, match="validity"):
        embed("Hello world.", signer, DISCLOSURE, context=context)
