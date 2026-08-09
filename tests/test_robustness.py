# pyright: reportPrivateUsage=false
"""The offline robustness runner's corpus and crash contracts."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re

import pytest

from tools import robustness

DOC = pathlib.Path(__file__).resolve().parent.parent / "docs" / "robustness.md"


def _corpus_bytes(*texts: object) -> bytes:
    return b"".join(json.dumps({"text": text}).encode() + b"\n" for text in texts)


def test_the_published_harness_contract_is_pinned_independently() -> None:
    """The shipped command and results table depend on this exact corpus and policy."""
    assert robustness._CORPUS_MD5 == "777a1f5376eb6e0d5b54db2acff8c3ff"
    assert robustness._CORPUS_RECORDS == 300
    assert tuple(robustness.ATTACKS) == (
        "identity",
        "NFKD + casefold + whitespace collapse",
        "strip invisible characters",
        "truncate to 50%",
        "excerpt 30%",
        "delete word indexes 0, 7, 14, ...",
        "case flip every 20th character",
        "synthetic word substitution",
        "whitespace collapse (NBSP folding)",
    )
    assert robustness._GATES == {
        "identity": "verified",
        "NFKD + casefold + whitespace collapse": "located",
    }


_MARK = "\ufeff\ufe00\U000e0100"


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        ("identity", f"Alpha{_MARK}", f"Alpha{_MARK}"),
        ("NFKD + casefold + whitespace collapse", f" CAFÉ\tThe {_MARK}", f"cafe\u0301 the{_MARK}"),
        ("strip invisible characters", f"A\u200b\u200f{_MARK}B", "AB"),
        ("truncate to 50%", f"abcdefgh{_MARK}", f"abcd{_MARK}"),
        ("excerpt 30%", f"0123456789{_MARK}", f"345{_MARK}"),
        (
            "delete word indexes 0, 7, 14, ...",
            f"zero one two three four five six seven{_MARK}",
            f"one two three four five six{_MARK}",
        ),
        ("case flip every 20th character", f"abcdefghijklmnopqrstuvw{_MARK}", f"AbcdefghijklmnopqrstUvw{_MARK}"),
        ("synthetic word substitution", f" the cat is calm and kind {_MARK}", f" a cat was calm plus kind {_MARK}"),
        ("whitespace collapse (NBSP folding)", f" alpha\tbeta\u00a0 gamma {_MARK}", f"alpha beta gamma{_MARK}"),
    ],
)
def test_each_named_attack_performs_its_published_rewrite(name: str, source: str, expected: str) -> None:
    assert robustness.ATTACKS[name](source) == expected


def test_the_results_table_matches_the_reproduced_external_run_and_gate_policy() -> None:
    """Values were reproduced from the pinned Zenodo corpus on 2026-08-09."""
    expected = {
        "identity": ("1.000", "1.000"),
        "NFKD + casefold + whitespace collapse": ("0.000", "1.000"),
        "strip invisible characters": ("0.000", "0.000"),
        "truncate to 50%": ("0.000", "1.000"),
        "excerpt 30%": ("0.000", "1.000"),
        "delete word indexes 0, 7, 14, ...": ("0.000", "1.000"),
        "case flip every 20th character": ("0.000", "1.000"),
        "synthetic word substitution": ("0.000", "1.000"),
        "whitespace collapse (NBSP folding)": ("0.500", "1.000"),
    }
    results: dict[str, tuple[str, str]] = {}
    gates: dict[str, str] = {}
    for line in DOC.read_text("utf-8").splitlines():
        match = re.fullmatch(r"\| ([^|]+) \| (\*\*)?(\d\.\d{3})(\*\*)? \| (\*\*)?(\d\.\d{3})(\*\*)? \|", line)
        if match is None:
            continue
        name, verified_open, verified, verified_close, located_open, located, located_close = match.groups()
        assert (verified_open is None) == (verified_close is None)
        assert (located_open is None) == (located_close is None)
        results[name] = (verified, located)
        if verified_open is not None:
            gates[name] = "verified"
        if located_open is not None:
            assert name not in gates
            gates[name] = "located"

    assert results == expected
    assert tuple(results) == tuple(robustness.ATTACKS)
    assert gates == robustness._GATES


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


def test_the_real_public_codec_satisfies_both_harness_gates(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Only corpus loading is replaced; marking, attacks and verification stay real."""

    def load_documents(_path: pathlib.Path) -> list[str]:
        return ["CAFÉ   the document is clear and complete.\u00a0"]

    monkeypatch.setattr(robustness, "load_documents", load_documents)

    assert robustness.main(tmp_path / "independent.jsonl") == 0

    rows: dict[str, tuple[str, ...]] = {}
    for line in capsys.readouterr().out.splitlines():
        fields = line.rsplit(maxsplit=2)
        if len(fields) == 3 and fields[0] in robustness._GATES:
            rows[fields[0]] = tuple(fields[1:])
    assert rows == {
        "identity": ("1.000", "1.000"),
        "NFKD + casefold + whitespace collapse": ("0.000", "1.000"),
    }


def test_a_failed_gate_returns_one_and_names_the_failure(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Drive the command boundary; testing `_GATES` alone cannot hold its exit code."""

    def load_documents(_path: pathlib.Path) -> list[str]:
        return ["document"]

    def remove_mark(text: str) -> str:
        return text.partition(robustness.MARKER)[0]

    monkeypatch.setattr(robustness, "load_documents", load_documents)
    monkeypatch.setattr(robustness, "ATTACKS", {"identity": remove_mark})

    assert robustness.main(tmp_path / "independent.jsonl") == 1
    captured = capsys.readouterr()
    assert captured.err == "\nFAIL: identity: verified=0.000, expected 1.000 -- the codec is broken\n"
