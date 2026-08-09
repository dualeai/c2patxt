"""Wire constants checked against the named C2PA 2.4 specification build."""

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


def test_the_wrapper_version_and_specification_version_are_distinct() -> None:
    """The carrier wire version is independent from the C2PA release number."""
    from c2patxt.constants import VERSION

    assert VERSION == 1
    assert SPEC_VERSION == "2.4"


def test_the_build_the_claim_names_is_the_one_the_package_carries(document: str) -> None:
    """The package and compatibility document name the same specification build."""
    import c2patxt
    from c2patxt import constants

    assert SPEC_BUILD in document
    assert SPEC_VERSION in document
    for carrier in (c2patxt.__doc__, constants.__doc__):
        assert carrier is not None
        assert SPEC_BUILD in carrier
        assert SPEC_VERSION in carrier


def test_the_core_clause_table_is_in_clause_order(document: str) -> None:
    """Hold the one structural property the compatibility claim says CI checks."""
    core = document.split("### Core clauses", maxsplit=1)[1].split("\n### ", maxsplit=1)[0]
    clauses = [
        match.group(1)
        for line in core.splitlines()
        if (match := re.fullmatch(r"\|\s*(\d+(?:\.\d+)*)\s*\|.*", line)) is not None
    ]

    assert clauses
    assert clauses == sorted(clauses, key=lambda clause: tuple(int(part) for part in clause.split(".")))
