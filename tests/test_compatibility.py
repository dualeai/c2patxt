"""The C2PA compatibility claim must stay true as the code changes.

``docs/c2pa-compatibility.md`` states which specification build we implement and
which JUMBF box UUIDs we emit. A conformance claim that drifts from the code is worse
than none: it is a statement a reader will rely on and cannot check without reading
our source, which is the labour the document exists to save them.

These tests are cheap because the claim was written to be checkable. Every constant
below was read out of the 2.4 HTML build (``c7e55d5a``) on 2026-08-05, not copied
from an earlier draft or from another implementation.
"""

from __future__ import annotations

import pathlib
import re

import pytest

import c2patxt
from c2patxt import manifest

DOC = pathlib.Path(__file__).resolve().parent.parent / "docs" / "c2pa-compatibility.md"

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


def test_the_claim_names_a_build_not_only_a_version(document: str) -> None:
    """A version alone is not falsifiable: eleven distinct 2.4 builds exist."""
    assert SPEC_BUILD in document
    assert SPEC_VERSION in document


def test_the_package_docstring_carries_the_same_claim() -> None:
    """The claim must be reachable from ``help(c2patxt)``, not only from the repo.

    A developer who installed the wheel has the docstring and not the docs directory,
    and the wheel is what actually ships.
    """
    docstring = c2patxt.__doc__ or ""
    assert SPEC_VERSION in docstring
    assert SPEC_BUILD in docstring


def test_the_document_states_its_own_boundary(document: str) -> None:
    """Listing what is covered without listing what is not is an overclaim.

    Each of these is something a reader could otherwise reasonably assume we do.
    """
    for excluded in ("A.7", "A.9", "sigTst2", "rVals", "brob", "c2um", "14.5.2"):
        assert excluded in document, f"the exclusion list no longer mentions {excluded}"


def test_the_document_does_not_claim_certification(document: str) -> None:
    """There is no C2PA certification available to claim at this specification level.

    Guarded because it is the single most tempting sentence to soften later, and the
    softening would be a false statement about a compliance artefact.
    """
    # Collapsed because the sentence is line-wrapped in the source; the guard is
    # about the claim, not about where the markdown happens to break.
    assert "carries no conformance certification" in " ".join(document.split())


def test_every_cited_module_exists(document: str) -> None:
    """The clause tables point at files; a stale pointer makes the claim unusable."""
    root = DOC.resolve().parent.parent / "src" / "c2patxt"
    cited = set(re.findall(r"`(_?[a-z_]+\.py)`", document))
    assert cited, "the clause tables no longer cite any module"
    missing = sorted(name for name in cited if not (root / name).exists())
    assert missing == []


def test_the_wrapper_version_is_one_and_distinct_from_the_spec_version(document: str) -> None:
    """Two unrelated axes that are easy to conflate; the document says so explicitly."""
    from c2patxt.constants import VERSION

    assert VERSION == 1
    assert "Wrapper format version" in document
    assert "Specification version" in document


#: Any dotted number. The harvest is deliberately WIDE and the filtering is done by
#: :func:`_is_clause`, because the previous version tried to recognise citations by the
#: words around them -- "C2PA ", "clause ", "section ", "(" -- and silently missed every
#: other phrasing the source actually uses: ``# 15.5.2.1:``, ``A.8.5 designates``,
#: ``15.6.1's rule``, ``A.8.4.2, 15.5.2.5``. A guard that only sees citations written
#: the way it expects is a guard that reports what it was told to report.
#: The trailing lookahead drops measurements: "9.91 s", "2.5 ms", "1.09 MB", "3.89x".
#: A clause number is never followed by a unit.
_DOTTED = re.compile(r"\bA?\.?[0-9]{1,2}(?:\.[0-9]+)+\b(?!\s*(?:s\b|ms\b|[KMG]i?B\b|%|x\b))")

#: An RFC's OWN numbering, together with the RFC that owns it. Removed from a line
#: before harvesting rather than causing the line to be skipped, because a single
#: sentence often cites both -- "C2PA 13.2.1 permits Ed25519; RFC 8032 5.1.6 derives the
#: nonce deterministically" -- and dropping the whole line would lose the C2PA half.
#: Reading RFC sections as C2PA clauses is how the first version of this guard came to
#: be checking "4.1.2.8" against a C2PA inventory.
_ANOTHER_STANDARD = re.compile(r"RFC\s+[0-9]+,?\s+(?:section|appendix|clause)?\s*[0-9A-Z](?:\.[0-9]+)*", re.IGNORECASE)

#: OID arcs. ``2.5`` is the ITU-T/ISO joint arc and ``1.3`` the ISO identified-organization
#: arc, so a long dotted number under either is an object identifier -- 2.5.29.37.0 is
#: anyExtendedKeyUsage -- and never a clause. C2PA's own numbering starts at 1 and its
#: deepest clauses are five segments, so the arc prefix is what separates them.
_OID_ARCS = ("2.5.", "1.3.")
_OID_SEGMENTS = 5

#: C2PA 2.4's normative body runs from clause 5 to clause 20, plus the annexes. Nothing
#: below 5 is citable here, which is what separates a C2PA clause from RFC 8949's 4.2.1,
#: ISO 19566-5's clause 4.3, the specification VERSION "2.4", and a stray "2.5 ms" in a
#: measurement. Those all appear in this source and are not clauses.
_FIRST_CLAUSE = 5
_LAST_CLAUSE = 20


def _is_clause(number: str) -> bool:
    """Whether a dotted number is plausibly a C2PA 2.4 clause.

    The alternatives all appear in this source: RFC 8949's 4.2.1, ISO 19566-5's clause
    4.3, X.509 OIDs, the specification version "2.4", Python versions, and measurements
    like "2.5 ms". Every one of them is excluded by the clause range or the OID arcs.
    """
    if number.startswith("A."):
        return True
    if number.startswith(_OID_ARCS) and len(number.split(".")) >= _OID_SEGMENTS:
        return False
    head = number.split(".", maxsplit=1)[0]
    return head.isdigit() and _FIRST_CLAUSE <= int(head) <= _LAST_CLAUSE


def _cited_clauses(sources: str) -> set[str]:
    """Every C2PA clause the source cites, with other standards' numbering removed."""
    cited: set[str] = set()
    for line in sources.splitlines():
        ours = _ANOTHER_STANDARD.sub(" ", line)
        cited.update(number for number in _DOTTED.findall(ours) if _is_clause(number))
    return cited


def _rows(document: str) -> set[tuple[str, ...]]:
    """The clause number of every inventory table row, as dotted segments."""
    numbers = re.findall(r"^\| (A?\.?[0-9][0-9.]*[0-9]) \|", document, re.MULTILINE)
    return {tuple(number.split(".")) for number in numbers}


def test_the_inventory_guard_matches_rows_and_not_substrings(document: str) -> None:
    """THE GUARD ITSELF, because it spent its whole life passing vacuously.

    ``listed()`` used to ask ``number in document`` -- substring containment against the
    WHOLE file. So ``5.1`` was "listed" because the string ``15.10.1.2`` contains it, and
    ``8.4.2.3`` was "listed" because the ``8.4.2.1`` row contains ``8.4.2``. Any clause
    number that happened to be a substring of any other text passed. **Fourteen**
    genuinely missing clauses hid behind that, among them 8.4.2.3, the rule defining
    what every hashed-URI check hashes, and 15.5.2.1, which decides WHICH manifest is
    validated. Both now have rows, put there by this guard once it started working.

    A test that cannot fail is worse than a missing test: this one carried a docstring
    explaining the failure mode it was built to catch, so nobody looked again.

    Matching is now on parsed table ROWS, as dotted-segment tuples, with an ancestor
    rule -- a row for ``11.1.4`` covers a citation of ``11.1.4.2``, because the
    inventory is a map for a reader, not an index. The three cases below are exactly the
    ones the old logic got wrong.
    """
    rows = _rows(document)
    assert ("15", "10", "1", "2") in rows, "the row parser no longer finds real rows"

    # "5.2" occurs inside the 15.2.2 row's text and is not itself a row. Under the old
    # containment logic that was enough to count as listed.
    assert not _listed("5.2", rows), "a substring of another row is not a row"
    assert _listed("11.1.4.2", rows), "a sub-clause is covered by its ancestor's row"
    assert _listed("11.1", rows), "a parent is covered by a row beneath it"
    assert not _listed("7.1", rows), "an unrelated clause is not covered by anything"


def _listed(number: str, rows: set[tuple[str, ...]]) -> bool:
    """True if a row names this clause, an ancestor of it, or a clause beneath it.

    ANCESTORS because the inventory is a map for a reader, not an index: a row for
    11.1.4 covers a citation of 11.1.4.2. DESCENDANTS because a comment may cite the
    parent -- "15.6 requires" -- where the inventory lists the finer 15.6.1 and 15.6.2
    that actually carry the work.
    """
    parts = tuple(number.split("."))
    if any(parts[:n] in rows for n in range(1, len(parts) + 1)):
        return True
    return any(row[: len(parts)] == parts for row in rows)


def test_the_citation_harvest_does_not_mistake_other_standards_for_c2pa(document: str) -> None:
    """RFC section numbers and X.509 OIDs are dotted too.

    ``trust.py`` cites "RFC 5280, section 4.1.2.8" and names the OID 2.5.29.37.0; the
    old harvest read both as C2PA clauses and then "found" them in the inventory by
    substring. Removing the substring bug without removing these would have produced a
    guard that fails on citations that were always correct.
    """
    del document
    assert _cited_clauses("# as per RFC 5280, section 4.1.2.8") == set()
    assert _cited_clauses("C2PA 13.2.1 permits it; RFC 8032 5.1.6 derives the nonce") == {"13.2.1"}
    assert _cited_clauses("anyExtendedKeyUsage (2.5.29.37.0) shall not be present (14.5.1.1)") == {"14.5.1.1"}
    assert _cited_clauses("C2PA 15.7 and clause 18.6") == {"15.7", "18.6"}
    assert _cited_clauses("Deterministic CBOR, RFC 8949 4.2.1 (Core Requirements).") == set()
    assert _cited_clauses("ISO 19566-5 clause 4.3, quoted verbatim") == set()
    assert _cited_clauses("the 1.09 MB case took 9.91 s to format") == set()
    assert _cited_clauses("Wrapper detection (C2PA 2.4 A.8.4.2, 15.5.2.5).") == {"A.8.4.2", "15.5.2.5"}
    assert _cited_clauses("    # 15.5.2.1: the last manifest is active") == {"15.5.2.1"}


def test_every_clause_cited_in_the_source_appears_in_the_inventory(document: str) -> None:
    """A clause the code implements but the document omits.

    The compatibility document says "If you find a clause listed here that we do not
    actually implement, that is a bug in this file". This checks the INVERSE, which is
    what bit: 15.10.3.1 -- where the most security-critical function in the package
    lives -- was once cited as the non-existent "15.6.3" and appeared nowhere here.

    WHAT THIS DOES NOT PROVE, and the limit is structural rather than an omission: it
    checks that every listed clause is CITED somewhere in ``src/``, never that the
    citation is CORRECT. A row is earned equally by a right citation and a wrong one --
    the 15.5.2.1 row is earned by a comment citing 15.5.2.1 for a rule that lives in
    15.5.1. So this catches a MISSING row and cannot catch a MISATTRIBUTION, which is
    why the pass that added rows found no wrong ones.

    Closing that would mean vendoring clause text to compare against, which the
    specification's licence does not clearly permit. Until it is closed, a row is
    evidence that we thought about the clause, not that we read it correctly.

    REWRITTEN 2026-08-05 after an audit found it passing vacuously. It matched by
    substring against the whole document, so ``5.1`` counted as listed because
    ``15.10.1.2`` contains those characters; see
    ``test_the_inventory_guard_matches_rows_and_not_substrings``. It also harvested
    citations through a regex so narrow that ``# 15.5.2.1:`` and ``18.4's table`` were
    never seen. Both halves were wrong in the same direction: silence.
    """
    root = DOC.resolve().parent.parent / "src" / "c2patxt"
    sources = "\n".join(path.read_text("utf-8") for path in root.glob("*.py"))
    rows = _rows(document)

    cited = _cited_clauses(sources)
    assert cited, "the citation harvest no longer finds anything"

    missing = sorted(number for number in cited if not _listed(number, rows))
    assert missing == [], f"clauses cited in src/ but absent from the inventory: {missing}"


def test_every_clause_the_inventory_lists_is_cited_in_the_source(document: str) -> None:
    """The other direction: a clause we LIST and do not implement.

    The document invites the report itself -- "If you find a clause listed here that we
    do not actually implement, that is a bug in this file and we want the report" -- and
    an audit found five such rows (9.2.4, 11.1.2, 15.2.2.3, 15.12.1.3.4, A.8.7.2). All
    five WERE implemented; none was cited at its implementing site, so nothing tied the
    row to the code.

    Matched against the HARVEST rather than by substring over the concatenated source.
    The substring version let a row pass on the strength of a comment that MIS-cited it,
    which is how a ``15.11.1`` row survived while the sentence it quoted lives in
    15.11.3.3.
    """
    root = DOC.resolve().parent.parent / "src" / "c2patxt"
    sources = "\n".join(path.read_text("utf-8") for path in root.glob("*.py"))

    listed = {".".join(row) for row in _rows(document)}
    assert listed, "the clause tables no longer parse"

    cited = _cited_clauses(sources)
    # A row is satisfied by a citation of itself or of any clause BENEATH it: a row for
    # 11.1.4 is earned by a comment citing 11.1.4.1.1, which is the finer statement.
    uncited = sorted(
        clause for clause in listed if not any(number == clause or number.startswith(f"{clause}.") for number in cited)
    )
    assert uncited == [], f"listed as implemented but cited nowhere in src/: {uncited}"
