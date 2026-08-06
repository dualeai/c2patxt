"""
Reader for A8ConformanceTest-<version>.txt.

The flat file is the normative artefact, not this module. A consuming
implementation in any language should be able to parse it with a split on ';'
and a strip of anything after '#'; this reader exists so our own suite does not
reimplement that per test module.

To update vectors: edit the .txt file. It is hand-authored, not generated.
"""

from __future__ import annotations

import dataclasses
import pathlib

__all__ = [
    "VECTOR_FILE",
    "Vector",
    "load_vectors",
    "vector_id",
]

VECTOR_FILE = pathlib.Path(__file__).parent / "A8ConformanceTest-1.1.0.txt"

_COLUMNS = 7


@dataclasses.dataclass(frozen=True, slots=True)
class Vector:
    """One record. Byte fields are decoded from hex; empty fields become b"" / None."""

    id: str
    op: str
    text: bytes
    payload: bytes
    expect: bytes
    status: str
    flags: frozenset[str]
    part: str
    note: str

    @property
    def is_ok(self) -> bool:
        return self.status == "OK"


def _split_comment(line: str) -> tuple[str, str]:
    """Return (data, note). '#' always introduces a comment; data is never quoted."""
    head, sep, tail = line.partition("#")
    return head.strip(), tail.strip() if sep else ""


def load_vectors(path: pathlib.Path | None = None) -> list[Vector]:
    """Parse the vector file into records, preserving file order."""
    src = path or VECTOR_FILE
    raw = src.read_bytes()
    if any(b > 0x7F for b in raw):
        msg = f"{src.name} must be pure US-ASCII; found a byte above 0x7F"
        raise ValueError(msg)

    vectors: list[Vector] = []
    part = ""
    for lineno, line in enumerate(raw.decode("ascii").splitlines(), start=1):
        data, note = _split_comment(line)
        if not data:
            continue
        if data.startswith("@"):
            part = data
            continue

        fields = [f.strip() for f in data.split(";")]
        if len(fields) != _COLUMNS:
            msg = f"{src.name}:{lineno}: expected {_COLUMNS} columns, got {len(fields)}"
            raise ValueError(msg)

        rec_id, op, text_hex, payload_hex, expect_hex, status, flags = fields
        vectors.append(
            Vector(
                id=rec_id,
                op=op,
                text=bytes.fromhex(text_hex),
                payload=bytes.fromhex(payload_hex),
                expect=bytes.fromhex(expect_hex),
                status=status,
                flags=frozenset(f for f in flags.split(",") if f),
                part=part,
                note=note,
            )
        )
    return vectors


def vector_id(vector: Vector) -> str:
    """pytest parametrize id: stable, greppable, and names the expected outcome."""
    return f"{vector.id}-{vector.op}-{vector.status}"
