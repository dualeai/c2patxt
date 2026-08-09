"""CodSpeed benchmarks for public paths and bounded hostile inputs.

Run with ``make test-bench``. Each fixed input has a public semantic precondition
outside the measured region. CodSpeed alone owns comparative CPU and memory signals;
this file sets no timing, allocation or private-call-count threshold.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import unicodedata
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_codspeed import BenchmarkFixture

from c2patxt import EmbedContext, MarkCorruptError, VerifyContext, embed, extract, strip, verify
from c2patxt._locate import find_wrappers
from c2patxt._selectors import build_wrapper, bytes_to_selectors
from c2patxt.constants import MAGIC, MARKER
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from c2patxt.verdict import Provenance
from tests.conftest import DISCLOSURE, build_certificate, mark

#: One paragraph repeated. ASCII, so `.encode()` is a memcpy and the benchmark measures
#: scanning rather than transcoding.
_PARAGRAPH = "The quick brown fox jumps over the lazy dog. "

#: Pin every context value so each sample measures the same produced manifest.
_PINNED_CONTEXT = EmbedContext(
    manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000001"),
    instance_id="xmp:iid:00000000-0000-4000-8000-000000000002",
    when=datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc),
)
_VERIFY_CONTEXT = VerifyContext(now=datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc))
_LARGE_MANIFEST_CONTEXT = EmbedContext(
    manifest_uuid=_PINNED_CONTEXT.manifest_uuid,
    instance_id=_PINNED_CONTEXT.instance_id,
    when=_PINNED_CONTEXT.when,
    generator_name="c2patxt/" + "x" * 100_000,
)
_WIDE_ITEMS = 100_000

#: The small input exposes fixed manifest, certificate, and COSE work. The large input
#: exposes document encoding, normalization, hashing, and scanning work.
_SIZES = [pytest.param(12, id="12B"), pytest.param(1_000_000, id="1MB")]


def _document(size: int) -> str:
    """A document of roughly ``size`` bytes. ASCII, so bytes and characters coincide."""
    return (_PARAGRAPH * (size // len(_PARAGRAPH) + 1))[:size]


@pytest.fixture(scope="module")
def bench_signer() -> Signer:
    """The suite's pinned signer, module-scoped so key generation and certificate
    building never land inside a measured region."""
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    return Signer(private_key=key, certificates=(build_certificate(key),))


# ---------------------------------------------------------------------------
# The honest paths
# ---------------------------------------------------------------------------


def test_bench_verify_unmarked(benchmark: BenchmarkFixture) -> None:
    """Measure the public unmarked-text scan on a large document."""
    text = _document(1_000_000)
    assert verify(text, context=_VERIFY_CONTEXT).state is Provenance.UNMARKED
    benchmark(verify, text, context=_VERIFY_CONTEXT)


@pytest.mark.parametrize("size", _SIZES)
def test_bench_verify_valid(benchmark: BenchmarkFixture, size: int, bench_signer: Signer) -> None:
    """Measure public validation for small and large genuinely signed documents."""
    text = mark(_document(size), bench_signer)
    # Outside the measured region, and not decoration: a regression making find_wrappers
    # return [] would flip this to UNMARKED, cut cost ~95%, and report as an IMPROVEMENT.
    assert verify(text, context=_VERIFY_CONTEXT).state is Provenance.VALID
    benchmark(verify, text, context=_VERIFY_CONTEXT)


def test_bench_extract(benchmark: BenchmarkFixture, bench_signer: Signer) -> None:
    """Measure public JUMBF and CBOR extraction without signature validation."""
    text = mark("Hello world.", bench_signer)
    store = extract(text)
    assert store is not None
    assert store.manifest_label == "urn:c2pa:00000000-0000-4000-8000-000000000007"
    assert set(store.assertions) == {
        "c2pa.actions.v2",
        "c2pa.ai-disclosure",
        "c2pa.metadata",
        "c2pa.hash.data",
    }
    benchmark(extract, text)


@pytest.fixture(scope="module", params=("json", "cbor"))
def bench_wide_assertion_mark(request: pytest.FixtureRequest, bench_signer: Signer) -> tuple[str, str, str]:
    """A fixed wide JSON or CBOR assertion for public extraction."""
    from c2patxt.manifest import ASSERTION_METADATA, Assertion
    from tests.test_verify import (
        _resigned,  # pyright: ignore[reportPrivateUsage] -- build a signed reader input outside the measured region
    )

    mode = str(request.param)
    label = ASSERTION_METADATA if mode == "json" else "com.example.wide"
    wide: list[object] = [{} for _ in range(_WIDE_ITEMS)]

    def mutate(items: list[Assertion], _claim: dict[str, object]) -> None:
        if mode == "json":
            context: dict[str, object] = {}
            document: dict[str, object] = {"@context": context, "com.example:items": wide}
            items[2] = Assertion(
                label=ASSERTION_METADATA,
                payload=document,
                json_ld=json.dumps(document, separators=(",", ":")).encode(),
            )
        else:
            items.append(Assertion(label=label, payload=wide))

    return mode, label, _resigned(bench_signer, mutate)


def test_bench_extract_wide_assertion(
    benchmark: BenchmarkFixture,
    bench_wide_assertion_mark: tuple[str, str, str],
) -> None:
    """Decode a wide JSON or CBOR object tree through public extraction."""
    mode, label, text = bench_wide_assertion_mark
    store = extract(text)
    assert store is not None
    value = store.assertions[label]
    if mode == "json":
        assert isinstance(value, dict)
        items = value["com.example:items"]
    else:
        items = value
    assert isinstance(items, list)
    assert len(items) == _WIDE_ITEMS
    benchmark(extract, text)


def test_bench_decode_selector_run(benchmark: BenchmarkFixture) -> None:
    """Decoding a variation-selector run back to manifest bytes.

    Use a 100 KB payload to exercise a large embedded assertion while staying below the
    2 MiB implementation cap. Drive the public locator rather than its private decoder.
    """
    payload_size = 99_840
    payload = bytes(range(256)) * (payload_size // 256)
    assert len(payload) == payload_size, "the id must name the real size"
    text = "Document. " + build_wrapper(payload)
    matches = find_wrappers(text)
    assert len(matches) == 1
    assert matches[0].payload == payload
    benchmark(find_wrappers, text)


def test_bench_encode_selector_run(benchmark: BenchmarkFixture) -> None:
    """Encode one pinned-size manifest into its variation-selector run.

    ``decode_selector_run`` above covers the decode direction only. These are two
    separate functions with two separate hot paths, and a benchmark on one says nothing
    about the other -- ``bytes_to_selectors`` is a ``str.translate`` over a latin-1
    decode, ``_decode_run`` a regex match plus a different translate.

    The fixed payload is representative of a small, roughly 1.8 KiB manifest. Encoding
    and decoding remain separate measured paths.
    """
    payload_size = 1_795
    payload = (bytes(range(256)) * (payload_size // 256 + 1))[:payload_size]
    assert len(payload) == payload_size, "the docstring must name the real size"
    encoded = bytes_to_selectors(payload)
    expected = "".join(chr(0xFE00 + byte) if byte < 16 else chr(0xE0100 + byte - 16) for byte in payload)
    assert encoded == expected
    benchmark(bytes_to_selectors, payload)


def test_bench_strip(benchmark: BenchmarkFixture, bench_signer: Signer) -> None:
    """Remove a mark from a fixed 1 MB document through the public API."""
    original = _document(1_000_000)
    marked = mark(original, bench_signer)
    assert strip(marked) == original
    benchmark(strip, marked)


@pytest.mark.parametrize("size", _SIZES)
def test_bench_embed(benchmark: BenchmarkFixture, size: int, bench_signer: Signer) -> None:
    """Produce a complete signed mark, including the bounded padding search."""
    text = _document(size)
    marked = embed(text, bench_signer, DISCLOSURE, context=_PINNED_CONTEXT)
    assert verify(marked, context=_VERIFY_CONTEXT).state is Provenance.VALID
    benchmark(embed, text, bench_signer, DISCLOSURE, context=_PINNED_CONTEXT)


def test_bench_embed_large_manifest(benchmark: BenchmarkFixture, bench_signer: Signer) -> None:
    """Produce a manifest carrying a legal 100 KB claim-generator name."""
    text = "Hello world."
    marked = embed(text, bench_signer, DISCLOSURE, context=_LARGE_MANIFEST_CONTEXT)
    assert verify(marked, context=_VERIFY_CONTEXT).state is Provenance.VALID
    benchmark(embed, text, bench_signer, DISCLOSURE, context=_LARGE_MANIFEST_CONTEXT)


def test_bench_verify_stream_safe_normalization(benchmark: BenchmarkFixture, bench_signer: Signer) -> None:
    """Normalize many maximally long accepted nonstarter sequences during verification."""
    unit = "\u034f" + "\u0315" * 15 + "\u0300" * 15
    noncanonical = unit * 1_000
    canonical = unicodedata.normalize("NFC", noncanonical)
    assert canonical != noncanonical
    assert len(canonical.encode("utf-8")) == len(noncanonical.encode("utf-8"))
    marked = mark(canonical, bench_signer)
    text = noncanonical + marked[len(canonical) :]
    verdict = verify(text, context=_VERIFY_CONTEXT)
    assert verdict.state is Provenance.VALID
    assert StatusCode.DATA_HASH_MATCH in verdict.codes()
    benchmark(verify, text, context=_VERIFY_CONTEXT)


# ---------------------------------------------------------------------------
# Hostile inputs
#
# SECURITY.md names CPU and memory exhaustion from adversarial input. These cases carry
# the repeated structures whose cost benign inputs do not exercise, at sizes an
# attacker can send cheaply.
#
# Performance and allocation ownership stays here. Functional tests assert verdicts;
# they do not monkeypatch private helpers to count calls or encoded bytes.
# ---------------------------------------------------------------------------


def _hostile_store(
    *,
    repeats: int,
    templates: int,
    instance: bool = False,
    actions_per_instance: int = 1,
    terminal_malformed_action: bool = False,
    bad_last_template: bool = False,
) -> str:
    """Marked text whose claim links one actions label ``repeats`` times."""
    import uuid as _uuid

    from c2patxt import _cbor
    from c2patxt._jumbf import UUID_CBOR, DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import (
        ASSERTION_ACTIONS,
        ASSERTION_AI_DISCLOSURE,
        ASSERTION_HASH_DATA,
        DIGITAL_SOURCE_TYPE_TRAINED,
        LABEL_ASSERTION_STORE,
        LABEL_CLAIM,
        LABEL_CLAIM_SIGNATURE,
        LABEL_MANIFEST_STORE,
        UUID_ASSERTION_STORE,
        UUID_CLAIM,
        UUID_CLAIM_SIGNATURE,
        UUID_MANIFEST,
        UUID_MANIFEST_STORE,
    )

    def box(label: str, payload: object) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=UUID_CBOR, label=label, requestable=True),
            content=((b"cbor", _cbor.dumps(payload)),),  # pyright: ignore[reportArgumentType] -- fixture is CBOR-shaped
        )

    def payload(box_: JumbfBox) -> bytes:
        return serialize_superbox(box_)[8:]

    def link(box_: JumbfBox, label: str) -> dict[str, object]:
        return {
            "url": f"self#jumbf={LABEL_ASSERTION_STORE}/{label}",
            "hash": hashlib.sha256(payload(box_)).digest(),
        }

    disclosure = box(ASSERTION_AI_DISCLOSURE, {"modelType": "generic"})
    icon = {**link(disclosure, ASSERTION_AI_DISCLOSURE), "alg": "sha256"}
    actions = box(
        ASSERTION_ACTIONS,
        {
            "actions": [{"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED}],
            "templates": [{"action": "c2pa.created", "icon": icon} for _ in range(templates)],
        },
    )
    edited_templates = [
        {
            "action": "c2pa.edited",
            "icon": ({**icon, "hash": b"\x00" * 32} if bad_last_template and index == templates - 1 else icon),
        }
        for index in range(templates)
    ]
    edited_actions: list[object] = [{"action": "c2pa.edited"} for _ in range(actions_per_instance)]
    if terminal_malformed_action:
        edited_actions.append({"action": 7})
    edited = box(
        f"{ASSERTION_ACTIONS}__1",
        {
            "actions": edited_actions,
            "templates": edited_templates,
        },
    )
    repeated, repeated_label = (edited, f"{ASSERTION_ACTIONS}__1") if instance else (actions, ASSERTION_ACTIONS)
    binding = box(ASSERTION_HASH_DATA, {"exclusions": [{"start": 0, "length": 1}], "hash": b"\x00" * 32})
    claim = {
        "instanceID": "x",
        "signature": "self#jumbf=c2pa.signature",
        "claim_generator_info": {"name": "n"},
        "alg": "sha256",
        "created_assertions": [
            link(disclosure, ASSERTION_AI_DISCLOSURE),
            link(binding, ASSERTION_HASH_DATA),
            *([link(actions, ASSERTION_ACTIONS)] if instance else []),
            *([link(repeated, repeated_label)] * repeats),
        ],
    }

    def superbox(uuid_: bytes, label: str, children: tuple[bytes, ...]) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=uuid_, label=label),
            content=tuple((b"jumb", child) for child in children),
        )

    assertion_children = [actions, edited, disclosure, binding] if instance else [actions, disclosure, binding]
    manifest = superbox(
        UUID_MANIFEST,
        f"urn:c2pa:{_uuid.UUID(int=7)}",
        (
            payload(
                superbox(
                    UUID_ASSERTION_STORE,
                    LABEL_ASSERTION_STORE,
                    tuple(payload(child) for child in assertion_children),
                )
            ),
            payload(
                JumbfBox(
                    description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                    content=((b"cbor", _cbor.dumps(claim)),),  # pyright: ignore[reportArgumentType] -- fixture is CBOR-shaped
                )
            ),
            payload(
                JumbfBox(
                    description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
                    content=((b"cbor", b"\x00"),),
                )
            ),
        ),
    )
    store = superbox(UUID_MANIFEST_STORE, LABEL_MANIFEST_STORE, (payload(manifest),))
    return "hello" + build_wrapper(serialize_superbox(store))


def test_bench_verify_hostile_decoys(benchmark: BenchmarkFixture) -> None:
    """Scan 16,000 malformed magic candidates before a wire-valid wrapper."""
    decoys = (MARKER + bytes_to_selectors(MAGIC)) * 16_000
    with pytest.raises(MarkCorruptError):
        find_wrappers(decoys)
    tail = b"not a manifest store"
    text = decoys + build_wrapper(tail)
    matches = find_wrappers(text)
    assert len(matches) == 1
    assert matches[0].payload == tail
    verdict = verify(text, context=_VERIFY_CONTEXT)
    assert verdict.state is Provenance.INVALID
    assert StatusCode.TEXT_CORRUPTED_WRAPPER in verdict.codes()
    benchmark(verify, text, context=_VERIFY_CONTEXT)


def test_bench_verify_hostile_hash_amplification(benchmark: BenchmarkFixture, bench_signer: Signer) -> None:
    """Validate 2,000 claim links that name one 256 KiB assertion.

    The public success-status count holds the repeated-reference shape while CodSpeed
    measures whether digest caching keeps its CPU and memory cost bounded.
    """
    text = _amplification_text(bench_signer, repeats=2_000, filler=256 * 1024)
    verdict = verify(text, context=_VERIFY_CONTEXT)
    assert verdict.state is Provenance.INVALID
    assert verdict.codes().count(StatusCode.ASSERTION_HASHED_URI_MATCH) == 2_003
    benchmark(verify, text, context=_VERIFY_CONTEXT)


def test_bench_verify_hostile_duplicate_actions(benchmark: BenchmarkFixture) -> None:
    """Validate 400 repeated actions links with 800 icon-bearing templates.

    A ``__1`` actions instance keeps the repeated links semantically reachable. The
    public match-status count holds that shape; CodSpeed owns the reference-walk CPU
    and memory history.
    """
    text = _hostile_store(
        repeats=400,
        templates=400,
        instance=True,
        bad_last_template=True,
    )
    verdict = verify(text, context=_VERIFY_CONTEXT)
    assert verdict.state is Provenance.INVALID
    assert verdict.codes().count(StatusCode.ASSERTION_HASHED_URI_MATCH) == 403
    assert StatusCode.HASHED_URI_MISMATCH in verdict.codes()
    benchmark(verify, text, context=_VERIFY_CONTEXT)


def test_bench_verify_hostile_action_product(benchmark: BenchmarkFixture) -> None:
    """Validate repeated links to one multi-action assertion before a bad tail."""
    text = _hostile_store(
        repeats=400,
        templates=0,
        instance=True,
        actions_per_instance=400,
        terminal_malformed_action=True,
    )
    store = extract(text)
    assert store is not None
    repeated = store.assertions["c2pa.actions.v2__1"]
    assert isinstance(repeated, dict)
    repeated_actions = repeated.get("actions")
    assert isinstance(repeated_actions, list)
    assert len(repeated_actions) == 401
    assert repeated_actions[-1] == {"action": 7}
    verdict = verify(text, context=_VERIFY_CONTEXT)
    assert verdict.state is Provenance.INVALID
    assert verdict.codes().count(StatusCode.ASSERTION_HASHED_URI_MATCH) == 403
    assert StatusCode.ASSERTION_ACTION_MALFORMED in verdict.codes()
    benchmark(verify, text, context=_VERIFY_CONTEXT)


def _watermark_label_product(
    signer: Signer,
    *,
    actions: int,
    labels: int,
    include_soft_binding: bool = True,
) -> str:
    """Signed wire with many watermark actions and a late soft-binding label."""
    from c2patxt import _cbor
    from c2patxt.manifest import ASSERTION_ACTIONS, Assertion
    from tests.test_verify import (
        _resigned,  # pyright: ignore[reportPrivateUsage] -- reuse the signed-wire fixture boundary instead of rebuilding C2PA boxes here
    )

    def mutate(items: list[Assertion], _claim: dict[str, object]) -> None:
        watermarks: list[dict[str, _cbor.CborValue]] = [{"action": "c2pa.watermarked"} for _ in range(actions)]
        watermarks[-1] = {
            "action": "c2pa.watermarked",
            "parameters": {
                "relatedAssertions": [
                    {
                        "url": f"self#jumbf=c2pa.assertions/com.example.padding__{labels - 1}",
                        "hash": b"\x00" * 32,
                    }
                ]
            },
        }
        items[0] = Assertion(
            label=ASSERTION_ACTIONS,
            payload={
                "actions": [
                    {
                        "action": "c2pa.created",
                        "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                    },
                    *watermarks,
                ]
            },
        )
        items.extend(
            Assertion(label=f"com.example.padding__{index}", payload={"value": index}) for index in range(labels)
        )
        soft_binding: dict[str, _cbor.CborValue] = {
            "alg": "com.example.test-watermark",
            "blocks": [{"scope": {}, "value": b"test"}],
        }
        if include_soft_binding:
            items.append(Assertion(label="c2pa.soft-binding", payload=soft_binding))

    return _resigned(signer, mutate)


def test_bench_verify_hostile_watermarked_actions(
    benchmark: BenchmarkFixture,
    bench_signer: Signer,
) -> None:
    """Validate many watermark actions with the required soft binding linked last."""
    text = _watermark_label_product(bench_signer, actions=400, labels=400)
    store = extract(text)
    assert store is not None
    actions = store.assertions["c2pa.actions.v2"]
    assert isinstance(actions, dict)
    action_entries = actions.get("actions")
    assert isinstance(action_entries, list)
    assert len(action_entries) == 401
    last_action = action_entries[-1]
    assert isinstance(last_action, dict)
    assert last_action.get("action") == "c2pa.watermarked"
    verdict = verify(text, context=_VERIFY_CONTEXT)
    assert verdict.state is Provenance.INVALID
    assert verdict.codes().count(StatusCode.ASSERTION_HASHED_URI_MATCH) == 405
    assert StatusCode.HASHED_URI_MISMATCH in verdict.codes()
    assert StatusCode.ASSERTION_ACTION_SOFT_BINDING_MISSING not in verdict.codes()
    missing = verify(
        _watermark_label_product(bench_signer, actions=2, labels=2, include_soft_binding=False),
        context=_VERIFY_CONTEXT,
    )
    assert StatusCode.ASSERTION_ACTION_SOFT_BINDING_MISSING in missing.codes()
    benchmark(verify, text, context=_VERIFY_CONTEXT)


def _amplification_text(signer: Signer, *, repeats: int, filler: int) -> str:
    """Marked text whose claim links one large assertion ``repeats`` times.

    Built from a genuine mark and then re-linked, so everything except the link count is
    a manifest this package produced. The signature will not verify -- it covers the
    original claim -- and that is immaterial: the amplification happens in
    ``_check_assertions``, which runs BEFORE ``_check_signature`` precisely because an
    unauthenticated attacker must not be able to command unbounded work.
    """
    from c2patxt import _cbor
    from c2patxt._jumbf import UUID_JSON, DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import (
        ASSERTION_METADATA,
        LABEL_ASSERTION_STORE,
        LABEL_CLAIM,
        LABEL_CLAIM_SIGNATURE,
        LABEL_MANIFEST_STORE,
        UUID_ASSERTION_STORE,
        UUID_CLAIM,
        UUID_CLAIM_SIGNATURE,
        UUID_MANIFEST,
        UUID_MANIFEST_STORE,
    )

    original = extract(mark("Hello world.", signer))
    assert original is not None

    def payload_of(box: JumbfBox) -> bytes:
        return serialize_superbox(box)[8:]

    def assertion(label: str, body: bytes) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=UUID_JSON, label=label, requestable=True),
            content=((b"json", body),),
        )

    # One deliberately large assertion, plus the originals so the store is otherwise
    # real. ``assertion_bytes`` already holds the nested-superbox bytes 8.4.2.3 hashes,
    # so reuse those raw payloads rather than wrapping them as CBOR content.
    big = assertion(
        ASSERTION_METADATA,
        json.dumps({"@context": {}, "dc:format": "text/plain", "pad": "0" * filler}, separators=(",", ":")).encode(),
    )
    children = [raw for label, raw in original.assertion_bytes.items() if label != ASSERTION_METADATA]
    children.append(payload_of(big))

    digest = hashlib.sha256(payload_of(big)).digest()
    link: _cbor.CborValue = {
        "url": f"self#jumbf={LABEL_ASSERTION_STORE}/{ASSERTION_METADATA}",
        "hash": digest,
        "alg": "sha256",
    }
    existing = original.claim["created_assertions"]
    assert isinstance(existing, list)
    # Drop the original metadata link because its digest names the assertion replaced
    # above; otherwise validation stops before walking the repeated links.
    kept = [
        entry
        for entry in existing
        if not (isinstance(entry, dict) and str(entry.get("url", "")).endswith(ASSERTION_METADATA))
    ]
    links: list[_cbor.CborValue] = [*kept, *([link] * repeats)]
    claim: dict[str, _cbor.CborValue] = {**original.claim, "created_assertions": links}

    def superbox(uuid_: bytes, label: str, children: list[bytes]) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=uuid_, label=label),
            content=tuple((b"jumb", child) for child in children),
        )

    manifest = superbox(
        UUID_MANIFEST,
        original.manifest_label,
        [
            payload_of(superbox(UUID_ASSERTION_STORE, LABEL_ASSERTION_STORE, children)),
            payload_of(
                JumbfBox(
                    description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                    content=((b"cbor", _cbor.dumps(claim)),),
                )
            ),
            payload_of(
                JumbfBox(
                    description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
                    content=((b"cbor", original.signature),),
                )
            ),
        ],
    )
    store = superbox(UUID_MANIFEST_STORE, LABEL_MANIFEST_STORE, [payload_of(manifest)])
    return "Hostile. " + build_wrapper(serialize_superbox(store))
