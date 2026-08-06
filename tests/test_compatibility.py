"""The wire constants the compatibility claim rests on.

``docs/c2pa-compatibility.md`` states which specification build we implement and which
JUMBF box UUIDs we emit. What is checked here is the CONSTANTS -- the UUIDs and the
wrapper version -- against the 2.4 HTML build (``c7e55d5a``), read out of it on
2026-08-05 rather than copied from an earlier draft or another implementation.

THE DOCUMENT'S CLAUSE TABLES ARE NOT CHECKED. What is held against the document is the
build hash and the two version axes, nothing more. Tests that harvested clause citations
out of
`src/` comments and matched them against the document's inventory tables, in both
directions, were removed on 2026-08-06 as documentation grading. They had found five
rows listed as implemented and cited nowhere. The document invites that report in its
own words -- "If you find a clause listed here that we do not actually implement, that
is a bug in this file and we want the report" -- and that invitation now rests on a
reader taking it up.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from c2patxt import manifest

DOC = pathlib.Path(__file__).resolve().parent.parent / "docs" / "c2pa-compatibility.md"
SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "c2patxt"

#: Specification build the claim names. One build, deliberately -- see the document.
SPEC_VERSION = "2.4"
SPEC_BUILD = "c7e55d5a"

#: Box type UUIDs as printed in C2PA 2.4, clause 11.1.4. Hardcoded in the canonical
#: form the spec uses so a mismatch reads as a diff against the spec, not against
#: another copy of our own constants.
SPEC_UUIDS = {
    "UUID_MANIFEST_STORE": "63327061-0011-0010-8000-00aa00389b71",
    "UUID_MANIFEST": "63326d61-0011-0010-8000-00aa00389b71",
    "UUID_ASSERTION_STORE": "63326173-0011-0010-8000-00aa00389b71",
    "UUID_CLAIM": "6332636c-0011-0010-8000-00aa00389b71",
    "UUID_CLAIM_SIGNATURE": "63326373-0011-0010-8000-00aa00389b71",
}


@pytest.fixture(scope="module")
def document() -> str:
    return DOC.read_text("utf-8")


def test_every_where_column_names_a_file_that_cites_its_clause(document: str) -> None:
    """The inventory's third column, checked against the source it points at.

    THIS IS NOT PROSE GRADING. It reads no sentence and enforces no wording; it takes
    the clause in column one and the filenames in column three and asks whether those
    files mention that clause. The document invites exactly this report in its own
    words -- "If you find a clause listed here that we do not actually implement, that
    is a bug in this file" -- and until now the invitation rested on a reader taking it
    up. Ten rows were wrong when this was written.

    A citation of a SUB-clause counts: ``_jumbf.py`` citing 11.1.4.1.1 satisfies a row
    for 11.1.4. The reverse does not -- a row for 15.12.1.3.2 is not satisfied by a file
    citing only 15.12.1.3.4, which is a different rule.

    The column names where a clause is IMPLEMENTED, not every file that mentions it, so
    only the listed-but-absent direction is an error. A file citing a clause without
    being listed is normal and is not flagged.

    THIS TEST CONSTRAINS THE DOCUMENT, NEVER THE CODE, so all its pressure is toward
    narrowing the inventory -- deleting a module from a row always turns it green. That
    is usually the WRONG fix. When it fails, the question is which module implements the
    clause; if that module does not cite it, add the citation there. Five rows were
    narrowed to satisfy this test on the day it was written, two of them onto files that
    do not implement the clause at all, and a review caught it rather than the suite.
    """
    source = {path.name: path.read_text("utf-8") for path in SRC.glob("*.py")}
    rows = re.findall(r"^\| ([A-Z0-9][0-9A-Za-z.]*) \| (?:.+?) \| (.+?) \|$", document, re.MULTILINE)
    clause_rows = [(clause, where) for clause, where in rows if re.match(r"^(A\.)?\d", clause)]
    assert len(clause_rows) > 60, f"only {len(clause_rows)} clause rows parsed; the table shape changed"

    wrong: list[str] = []
    for clause, where in clause_rows:
        listed = set(re.findall(r"`([A-Za-z_]+\.py)`", where))
        cites = re.compile(r"(?<![\d.])" + re.escape(clause) + r"(?:\.\d+)*(?![\d.]*\d)")
        absent = sorted(name for name in listed if not cites.search(source.get(name, "")))
        if absent:
            wrong.append(f"{clause}: names {absent}, which cite neither it nor a sub-clause")

    assert not wrong, "rows pointing at the wrong file:\n" + "\n".join(wrong)


def test_the_core_clause_table_is_in_clause_order(document: str) -> None:
    """The inventory is for diffing against the spec section by section.

    The document says so: "every clause listed below is one you can open in the spec and
    compare against the code". A table out of clause order turns that into a linear scan
    per clause. Seven runs were out of order when this was written -- 14.3 before 13.1,
    5.1 and 6.x dropped in after 14.5.1.1, 15.8 after 15.10.1.2, 6.9 after 15.12.1.3.4,
    18.6 after 18.17 -- which is the shape a hand-maintained table drifts into as rows
    get appended where they were written rather than where they belong.

    Sorted numerically per segment, so 15.8 precedes 15.10 and a string sort will not do.
    """
    core = document.split("### Core clauses", 1)[1]
    clauses = [row.split("|")[1].strip() for row in core.split("\n") if row.startswith("| ") and row[2].isdigit()]
    assert len(clauses) > 40, f"only {len(clauses)} core clause rows parsed; the table shape changed"

    keyed = [tuple(int(part) for part in clause.split(".")) for clause in clauses]
    assert keyed == sorted(keyed), "core clause table is out of order at: " + ", ".join(
        clauses[i] for i in range(1, len(keyed)) if keyed[i] < keyed[i - 1]
    )


@pytest.mark.parametrize(("name", "expected"), sorted(SPEC_UUIDS.items()))
def test_the_box_uuids_match_the_specification(name: str, expected: str) -> None:
    """The five UUIDs we emit, against the values printed in 2.4 clause 11.1.4.

    These were originally read from the 2.0 PDF and re-confirmed against the 2.4
    build. A wrong byte here produces a manifest no other implementation can parse,
    and the failure would surface only at someone else's verifier.
    """
    actual = bytes(getattr(manifest, name))
    assert actual.hex() == expected.replace("-", "")


def test_the_uuids_carry_the_iso_suffix() -> None:
    """All C2PA box UUIDs share the ISO 19566-5:2023 suffix; only the tag varies."""
    suffix = bytes.fromhex("00110010800000aa00389b71")
    for name in SPEC_UUIDS:
        assert bytes(getattr(manifest, name)).endswith(suffix)


def test_the_wrapper_version_is_one_and_distinct_from_the_spec_version(document: str) -> None:
    """Two unrelated axes that are easy to conflate; the document says so explicitly."""
    from c2patxt.constants import VERSION

    assert VERSION == 1
    assert "Wrapper format version" in document
    assert "Specification version" in document


def test_the_build_the_claim_names_is_the_one_the_package_carries(document: str) -> None:
    """One build hash, seven copies, and a MAJOR-version bump if it ever moves.

    The hash is a commit in ``c2pa-org/specifications``, the repository that publishes
    the HTML -- not a digest of the HTML, which carries no build marker of its own. It
    is stated in seven shipped files, so a bump has seven chances to be missed. This
    holds the two that ship inside the package against the document that defines them.
    """
    import c2patxt
    from c2patxt import constants

    assert SPEC_BUILD in document
    assert SPEC_VERSION in document
    for carrier in (c2patxt.__doc__, constants.__doc__):
        assert carrier is not None
        assert SPEC_BUILD in carrier
        assert SPEC_VERSION in carrier
