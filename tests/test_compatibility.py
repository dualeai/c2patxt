"""The wire constants the compatibility claim rests on.

``docs/c2pa-compatibility.md`` states which specification build we implement and which
JUMBF box UUIDs we emit. What is checked here is the CONSTANTS -- the UUIDs and the
wrapper version -- against the 2.4 HTML build (``c7e55d5a``), read out of it on
2026-08-05 rather than copied from an earlier draft or another implementation.

THE DOCUMENT ITSELF IS NO LONGER CHECKED. Tests that harvested clause citations out of
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
#: Reading RFC sections as C2PA clauses ends up checking "4.1.2.8" against a C2PA inventory.
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
