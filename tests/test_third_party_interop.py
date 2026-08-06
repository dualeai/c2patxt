"""Three-way interop against the two other public A.8 implementations.

Agreement between independently written implementations is stronger evidence of
correctness than any assertion we make about ourselves, and it is a better claim
than "we are the reference" -- EncypherAI already publishes a reference
implementation with four language bindings, and c2pa-rs PR #2117 depends on their
crate.

Their vectors are committed under ``tests/vectors/third_party/`` rather than fetched,
so this suite stays offline (``--disable-socket``) and deterministic. Refresh them
with ``make download-vectors``.

Sources, with their own licences:
  EncypherAI  golden/vectors.json                 MIT
  writerslogic vectors/a8-variation-selector.json Apache-2.0
"""

from __future__ import annotations

import pathlib
import struct
import uuid

import pytest

from c2patxt import EmbedContext, embed, extract, locate
from c2patxt._locate import payload_at
from c2patxt._selectors import build_wrapper
from c2patxt.signing import Signer
from tests._json import load_object, str_fields
from tests.conftest import DISCLOSURE, WHEN
from tests.vectors.loader import load_vectors

THIRD_PARTY = pathlib.Path(__file__).parent / "vectors" / "third_party"
ENCYPHER = THIRD_PARTY / "encypher-golden-vectors.json"
WRITERSLOGIC = THIRD_PARTY / "writerslogic-a8-variation-selector.json"

MAGIC = bytes.fromhex("4332504154585400")

_PINNED = EmbedContext(manifest_uuid=uuid.UUID(int=11), instance_id="xmp:iid:interop", when=WHEN)


def _byte_to_selector(b: int) -> str:
    """A.8.3.1, transcribed from the specification rather than imported from src/."""
    return chr(0xFE00 + b) if b <= 0x0F else chr(0xE0100 + (b - 16))


def _wrapper(payload: bytes) -> str:
    body = MAGIC + bytes([1]) + struct.pack(">I", len(payload)) + payload
    return "\ufeff" + "".join(_byte_to_selector(x) for x in body)


def _records(path: pathlib.Path, key: str) -> list[dict[str, str]]:
    """Return the string-valued fields of every record in the array at `key`."""
    raw = load_object(path)[key]
    assert isinstance(raw, list), f"{path.name}: {key} must be a list"
    return [str_fields(item, f"{path.name}:{key}") for item in raw]


def _mapping(path: pathlib.Path, key: str) -> dict[str, str]:
    """Return the string-valued fields of the object at `key`."""
    return str_fields(load_object(path)[key], f"{path.name}:{key}")


@pytest.mark.parametrize("name", ["ascii_small", "unicode_all_bytes"])
def test_encypher_unstructured_vectors_reproduce_byte_for_byte(name: str) -> None:
    """Our spec-derived encoding must equal EncypherAI's published golden output."""
    record = next(r for r in _records(ENCYPHER, "unstructured_embed") if r["name"] == name)

    derived = record["text"] + _wrapper(bytes.fromhex(record["manifest_hex"]))
    assert derived.encode("utf-8").hex() == record["expected_embed_hex"].lower()


def test_writerslogic_byte_to_selector_table_agrees() -> None:
    """Their published mapping table must match A.8.3.1 at every stated point.

    The four entries they publish are exactly the boundary cases: 0x00 and 0x0F at
    the ends of the U+FE00 block, then 0x10 and 0xFF at the ends of the U+E0100
    block. That pair straddles the 3-byte/4-byte UTF-8 cost change, which is where
    an off-by-one in the mapping would first show.
    """
    table = _records(WRITERSLOGIC, "byteToVariationSelector")
    assert table, "expected a non-empty mapping table"

    for entry in table:
        byte = int(entry["byte"], 16)
        expected_utf8 = entry["utf8"].lower().replace(" ", "")
        selector = _byte_to_selector(byte)
        assert selector.encode("utf-8").hex() == expected_utf8, f"byte {entry['byte']}"
        assert f"U+{ord(selector):04X}" == entry["codepoint"], f"byte {entry['byte']}"

    assert {e["byte"] for e in table} >= {"0x0F", "0x10"}, "boundary pair must be covered"


def test_writerslogic_wrapper_vector_reproduces() -> None:
    """Their full wrapper vector must be re-derivable from the spec formula."""
    vector = _mapping(WRITERSLOGIC, "wrapperVector")
    derived = _wrapper(bytes.fromhex(vector["payload_hex"]))
    assert derived.encode("utf-8").hex() == vector["wrapper_utf8_hex"].lower()


@pytest.mark.parametrize("name", ["ascii_small", "unicode_all_bytes"])
def test_the_shipped_encoder_reproduces_the_encypher_vectors(name: str) -> None:
    """The same comparison as above, made against ``build_wrapper`` instead.

    The tests above compare EncypherAI's numbers with ``_wrapper``, the spec
    transcribed a second time inside this file. That is a sound witness for the
    SPECIFICATION and says nothing about the code we ship: both could agree while
    ``c2patxt`` encodes something else. This closes that, and ``unicode_all_bytes``
    is the case worth having -- 256 payload bytes crossing the 0x0F/0x10 boundary,
    under text that is not ASCII.
    """
    record = next(r for r in _records(ENCYPHER, "unstructured_embed") if r["name"] == name)

    marked = record["text"] + build_wrapper(bytes.fromhex(record["manifest_hex"]))
    assert marked.encode("utf-8").hex() == record["expected_embed_hex"].lower()


@pytest.mark.parametrize("name", ["ascii_small", "unicode_all_bytes"])
def test_the_shipped_scanner_reads_text_marked_by_encypher(name: str) -> None:
    """The consumer half: their marked text, read by our detector.

    An encoder agreeing with theirs proves nothing about what we can READ. This
    takes their published output verbatim -- text we never produced -- and requires
    the scanner to find the wrapper and return the manifest bytes they put in it.
    """
    record = next(r for r in _records(ENCYPHER, "unstructured_embed") if r["name"] == name)
    marked = bytes.fromhex(record["expected_embed_hex"]).decode("utf-8")

    assert payload_at(marked) == bytes.fromhex(record["manifest_hex"])


def test_the_shipped_codec_round_trips_the_writerslogic_wrapper_vector() -> None:
    """Their wrapper vector, encoded and then read back by the shipped codec."""
    vector = _mapping(WRITERSLOGIC, "wrapperVector")
    payload = bytes.fromhex(vector["payload_hex"])

    wrapper = build_wrapper(payload)
    assert wrapper.encode("utf-8").hex() == vector["wrapper_utf8_hex"].lower()
    assert payload_at("Doc." + wrapper) == payload


def test_a_wrapper_embed_produced_re_derives_from_the_spec_formula(signer: Signer) -> None:
    """A REAL mark, checked against the transcription rather than against ourselves.

    Every test above works on payloads someone else chose. This one signs a document,
    takes the wrapper bytes out of the emitted text, and rebuilds them from A.8.2.2
    and A.8.3.1 alone -- big-endian length, the two selector blocks, one U+FEFF. A
    wrong magic, a wrong version byte, a little-endian length or an off-by-one in the
    mapping would be emitted and parsed consistently by our own round trip and caught
    only here.
    """
    marked = embed("Interop.", signer, DISCLOSURE, context=_PINNED)

    span = locate(marked)
    store = extract(marked)
    assert span is not None
    assert store is not None
    emitted = marked.encode("utf-8")[span.utf8_start : span.utf8_stop]

    assert emitted == _wrapper(store.raw).encode("utf-8")


def test_our_e0001_is_the_encypher_ascii_small_vector() -> None:
    """The interop anchor, asserted from both directions.

    E0001 in our own file and ``ascii_small`` in theirs are the same case. If these
    ever diverge, one of the two corpora has drifted and the three-way claim is void.
    """
    theirs = next(r for r in _records(ENCYPHER, "unstructured_embed") if r["name"] == "ascii_small")
    ours = next(v for v in load_vectors() if v.id == "E0001")

    assert ours.text.decode("utf-8") == theirs["text"]
    assert ours.payload.hex() == theirs["manifest_hex"].lower()
    assert ours.expect.hex() == theirs["expected_embed_hex"].lower()
