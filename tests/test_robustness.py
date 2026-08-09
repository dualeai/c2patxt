"""The offline robustness runner's corpus and crash contracts."""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from tools import robustness


def _corpus_bytes(*texts: object) -> bytes:
    return b"".join(json.dumps({"text": text}).encode() + b"\n" for text in texts)


def test_the_published_corpus_identity_and_schema_are_checked(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _corpus_bytes("one", "two")
    path = tmp_path / "train.jsonl"
    path.write_bytes(raw)
    monkeypatch.setattr(robustness, "_CORPUS_MD5", hashlib.md5(raw, usedforsecurity=False).hexdigest())
    monkeypatch.setattr(robustness, "_CORPUS_RECORDS", 2)

    assert robustness.load_documents(path) == ["one", "two"]


def test_a_different_corpus_is_rejected(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "train.jsonl"
    path.write_bytes(_corpus_bytes("not the published corpus"))

    with pytest.raises(ValueError, match="expected the published PAN'26 corpus"):
        robustness.load_documents(path)


@pytest.mark.parametrize(
    ("raw", "expected_records", "pattern"),
    [
        (_corpus_bytes("one"), 2, "has 1 records; expected 2"),
        (_corpus_bytes(7), 1, "string text field"),
        (b"\n", 1, "blank records"),
    ],
    ids=["wrong-count", "wrong-schema", "blank-record"],
)
def test_a_matching_file_still_needs_the_published_shape(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    raw: bytes,
    expected_records: int,
    pattern: str,
) -> None:
    path = tmp_path / "train.jsonl"
    path.write_bytes(raw)
    monkeypatch.setattr(robustness, "_CORPUS_MD5", hashlib.md5(raw, usedforsecurity=False).hexdigest())
    monkeypatch.setattr(robustness, "_CORPUS_RECORDS", expected_records)

    with pytest.raises(ValueError, match=pattern):
        robustness.load_documents(path)


def test_an_unexpected_verifier_exception_stops_the_run(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def load_documents(_path: pathlib.Path) -> list[str]:
        return ["document"]

    def embed(text: str, *_args: object) -> str:
        return text

    monkeypatch.setattr(robustness, "load_documents", load_documents)
    monkeypatch.setattr(robustness, "embed", embed)

    def crash(_text: str) -> None:
        raise RuntimeError("verifier crashed")

    monkeypatch.setattr(robustness, "verify", crash)

    with pytest.raises(RuntimeError, match="verifier crashed"):
        robustness.main(tmp_path / "unused.jsonl")
