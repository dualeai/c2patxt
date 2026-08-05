"""Typed access to third-party JSON fixtures.

``json.loads`` returns ``Any``, which this project bans outright, and pyright's
strict mode will not accept an ``isinstance(x, dict)`` narrowing as producing typed
keys and values. Everything here narrows through a closed description of JSON so
that reading a vendored corpus is type-safe rather than asserted into existence.

Shared by the vector suites so the narrowing is written once.
"""

from __future__ import annotations

import json
import pathlib
from typing import TypeAlias

from c2patxt._cbor import CborValue

__all__ = [
    "JsonValue",
    "as_mapping",
    "as_sequence",
    "load_object",
    "str_field",
    "str_fields",
]

JsonValue: TypeAlias = "str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None"


def load_object(path: pathlib.Path) -> dict[str, JsonValue]:
    """Parse a JSON file and narrow the document to an object."""
    doc: JsonValue = json.loads(path.read_text("utf-8"))
    assert isinstance(doc, dict), f"{path.name}: expected a JSON object"
    return doc


def str_fields(value: JsonValue, where: str) -> dict[str, str]:
    """Narrow one JSON object to only its string-valued fields."""
    assert isinstance(value, dict), f"{where}: expected an object"
    return {key: item for key, item in value.items() if isinstance(item, str)}


def str_field(doc: JsonValue, *path: str) -> str:
    """Walk a nested JSON object and return the string leaf at ``path``."""
    node: JsonValue = doc
    for key in path:
        assert isinstance(node, dict), f"expected an object at {key!r}"
        node = node[key]
    assert isinstance(node, str), f"expected a string at {path[-1]!r}"
    return node


def as_mapping(value: CborValue, where: str) -> dict[str, CborValue]:
    """Narrow a decoded CBOR/JSON object to a str-keyed mapping.

    ``isinstance(x, dict)`` narrows only to ``dict[Unknown, Unknown]`` under pyright
    strict, so decoded payloads need an explicit pass to become typed.
    """
    assert isinstance(value, dict), f"{where}: expected a mapping"
    return {key: item for key, item in value.items() if isinstance(key, str)}


def as_sequence(value: CborValue, where: str) -> list[CborValue]:
    """Narrow a decoded array to a typed list."""
    assert isinstance(value, list), f"{where}: expected an array"
    return list(value)
