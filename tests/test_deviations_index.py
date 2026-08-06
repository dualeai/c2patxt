"""The deviations index, regenerated and compared.

``docs/deviations.md`` is 600-odd lines across 29 sections citing 40 distinct clauses,
and the question a reader arrives with is "how do they read 15.12.1.3.1?". Without an
index that is a full-text search. With a HAND-MAINTAINED index it is worse than none:
the document's own opening argues that a stale table is what makes an auditor stop
trusting the whole file.

So the index is derived. This test rebuilds it from the sections and compares, which
makes the table a projection of the document rather than a second thing to maintain.
Add a clause to a section and this fails until the index is regenerated.

DEVIATION NUMBERS ARE LOAD-BEARING. Five files cite them by ordinal, ``src/`` included
-- `_verify.py`, `status.py`, `tests/test_negative.py`, `upstream-filing.md`,
`known-divergences.md`. Withdrawn items keep their number and become stubs rather than
closing the gap, so this also pins that the numbering stays dense and ordered.
"""

from __future__ import annotations

import collections
import pathlib
import re

DOC = pathlib.Path(__file__).resolve().parent.parent / "docs" / "deviations.md"

#: Any dotted clause number, optionally annex-prefixed. Deliberately wide; the filtering
#: is done by :func:`_is_c2pa_clause`, because recognising citations by the words around
#: them misses the phrasings the document actually uses -- "15.12.1.3.1 (steps 5-7)",
#: "A.8.5 delegates", "18.15.2.)" -- and a guard that only sees what it expects reports
#: what it was told to report.
_CLAUSE = re.compile(r"(?<![\d.\w])((?:A\.)?\d{1,2}(?:\.\d+)+)(?![\d.]*\d)")

#: C2PA 2.4's normative body runs from clause 5 to clause 20, plus the annexes. That
#: range is what separates a C2PA clause from RFC 8949's 4.2.1, ISO 19566-5's 4.3, and
#: the specification version "2.4" -- all of which appear in this document.
_FIRST_CLAUSE = 5
_LAST_CLAUSE = 20


def _is_c2pa_clause(clause: str) -> bool:
    if clause.startswith("A."):
        return True
    return _FIRST_CLAUSE <= int(clause.split(".", maxsplit=1)[0]) <= _LAST_CLAUSE


def _sort_key(clause: str) -> tuple[bool, tuple[int, ...]]:
    """Annexes last, and numeric per segment so 15.8 precedes 15.10."""
    bare = clause[2:] if clause.startswith("A.") else clause
    return (clause.startswith("A."), tuple(int(part) for part in bare.split(".")))


def _harvest(document: str) -> dict[str, set[int]]:
    """Clause -> the deviation numbers whose section cites it."""
    by_clause: dict[str, set[int]] = collections.defaultdict(set)
    current: int | None = None
    for line in document.split("\n"):
        heading = re.match(r"^## (\d+)\. (.+)$", line)
        if heading:
            current = int(heading.group(1))
            body = heading.group(2)
        elif line.startswith("## "):
            current = None
            continue
        else:
            body = line
        if current is not None:
            for clause in _CLAUSE.findall(body):
                if _is_c2pa_clause(clause):
                    by_clause[clause].add(current)
    return by_clause


def test_the_index_matches_the_sections_it_indexes() -> None:
    """Regenerate the table and compare, so it cannot drift from the document."""
    document = DOC.read_text("utf-8")
    index_block, sections = document.split("| Clause | Deviations |", 1)[1].split("---\n", 1)

    published = [line for line in index_block.split("\n") if line.startswith("| ") and not line.startswith("| ---")]
    harvested = _harvest(sections)
    assert harvested, "no deviation sections parsed; the heading shape changed"

    expected = [
        f"| {clause} | {', '.join(str(number) for number in sorted(harvested[clause]))} |"
        for clause in sorted(harvested, key=_sort_key)
    ]
    assert published == expected, (
        "the clause index is out of date; regenerate it. Missing rows: "
        f"{[row for row in expected if row not in published]}. Stale rows: "
        f"{[row for row in published if row not in expected]}"
    )


def test_deviation_numbers_are_dense_and_ordered() -> None:
    """Five files cite these by ordinal, so a renumber breaks them silently.

    Withdrawn items keep their number as a stub. Deviations 16 and 19 are stubs today:
    16 was a cosmetic cross-reference bug, 19 turned out to be the specification's own
    rule read from one clause instead of two.
    """
    numbers = [int(match) for match in re.findall(r"^## (\d+)\. ", DOC.read_text("utf-8"), re.MULTILINE)]

    assert numbers == sorted(numbers), f"deviation headings are out of order: {numbers}"
    assert numbers == list(range(1, len(numbers) + 1)), f"deviation numbering has a gap or duplicate: {numbers}"


def test_the_shared_clause_table_matches_between_the_two_documents() -> None:
    """The multiple-wrapper table is duplicated, on purpose, and must not drift.

    ``docs/upstream-filing.md`` holds issue bodies meant to be posted to a specification
    repository. An issue body has to be self-contained -- "see deviations.md" is useless
    to whoever reads it upstream -- so the duplication is deliberate and stays.

    What is not acceptable is the two copies disagreeing while both claim to quote the
    same clauses. This pins them equal, which is the cheap half of the problem.
    """
    upstream = (DOC.parent / "upstream-filing.md").read_text("utf-8")

    def tables(document: str) -> list[tuple[str, ...]]:
        found: list[tuple[str, ...]] = []
        current: list[str] = []
        for line in document.split("\n"):
            if line.startswith("|"):
                current.append(line.strip())
            elif current:
                found.append(tuple(current))
                current = []
        return found

    wanted = "| Clause | Says |"
    in_deviations = [table for table in tables(DOC.read_text("utf-8")) if table[0] == wanted]
    in_upstream = [table for table in tables(upstream) if table[0] == wanted]

    assert in_deviations, "the multiple-wrapper table is gone from deviations.md"
    assert in_upstream, "the multiple-wrapper table is gone from upstream-filing.md"
    assert in_deviations[0] == in_upstream[0], "the two copies of the multiple-wrapper table have drifted"
