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

import pytest

from tests._json import load_object, str_fields
from tests.vectors.loader import load_vectors

THIRD_PARTY = pathlib.Path(__file__).parent / "vectors" / "third_party"
ENCYPHER = THIRD_PARTY / "encypher-golden-vectors.json"
WRITERSLOGIC = THIRD_PARTY / "writerslogic-a8-variation-selector.json"

MAGIC = bytes.fromhex("4332504154585400")


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
