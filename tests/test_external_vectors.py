"""Sanity checks on the vendored third-party corpora.

These assert that the corpora are present, internally consistent, and that our
reading of the structures they encode is correct -- before the modules that consume
them exist. A vector file we have misread is worse than no vector file.

Scope note: we deliberately do NOT vendor NIST ACVP SHA vectors or the full
Wycheproof Ed25519 suite. We call ``hashlib`` and ``cryptography``; we do not
implement SHA or Ed25519. Running those corpora would test CPython and pyca, not this
package, and belongs in their suites rather than ours.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tests._json import load_object, str_field

VECTORS = pathlib.Path(__file__).parent / "vectors"
COSE = VECTORS / "cose"
CBOR = VECTORS / "cbor"
THIRD_PARTY = VECTORS / "third_party"

# C2PA 13.2.1 permits EdDSA over Ed25519 only. The COSE algorithm identifier is -8,
# from the IANA COSE Algorithms registry -- the C2PA specification never states it.
COSE_ALG_EDDSA = -8


def test_cose_corpus_is_present_with_pass_and_fail_cases() -> None:
    """Failure cases are the reason to prefer this corpus over a golden-only one."""
    names = {p.name for p in COSE.glob("*.json")}
    assert {"eddsa-sig-01.json", "eddsa-sig-02.json"} <= names
    assert len([n for n in names if n.startswith("sign-pass")]) == 3
    assert len([n for n in names if n.startswith("sign-fail")]) == 6


@pytest.mark.parametrize("name", ["eddsa-sig-01.json"])
def test_ed25519_cose_signature_verifies_over_the_tobesign_structure(name: str) -> None:
    """The load-bearing check: verify their signature over their Sig_structure.

    This proves three things at once, none of which needs our code to exist yet:
    the vector is internally sound, the public key material parses, and our reading
    of ``Sig_structure`` as the signed input is correct. When #17 assembles that
    structure itself, it must reproduce ``ToBeSign_hex`` byte for byte.

    Only ``eddsa-sig-01`` is exercised: see the Ed448 test below for why its sibling
    is not.
    """
    doc = load_object(COSE / name)

    to_be_signed = bytes.fromhex(str_field(doc, "intermediates", "ToBeSign_hex"))
    public_raw = bytes.fromhex(str_field(doc, "input", "sign0", "key", "x_hex"))
    assert str_field(doc, "input", "sign0", "key", "crv") == "Ed25519"
    assert len(public_raw) == 32, "Ed25519 public keys are 32 bytes"

    # The signature is the last element of the COSE_Sign1 array; the corpus gives the
    # whole tagged message as hex, and the 64-byte tail is the signature.
    full = bytes.fromhex(str_field(doc, "output", "cbor"))
    signature = full[-64:]

    Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, to_be_signed)


def test_a_tampered_signature_is_rejected() -> None:
    """Negative control: the check above must be capable of failing."""
    doc = load_object(COSE / "eddsa-sig-01.json")
    to_be_signed = bytes.fromhex(str_field(doc, "intermediates", "ToBeSign_hex"))
    public_raw = bytes.fromhex(str_field(doc, "input", "sign0", "key", "x_hex"))
    signature = bytearray(bytes.fromhex(str_field(doc, "output", "cbor"))[-64:])
    signature[0] ^= 0x01

    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(public_raw).verify(bytes(signature), to_be_signed)


def test_eddsa_vectors_use_the_algorithm_c2pa_permits() -> None:
    """C2PA 13.2.1: Ed25519 only. The protected header must carry alg = -8.

    The protected bucket is a serialized CBOR map; ``01 27`` is key 1 (alg) with
    value -8, since CBOR encodes negative n as major type 1 with argument -1-n.
    """
    doc = load_object(COSE / "eddsa-sig-01.json")
    protected_hex = str_field(doc, "output", "cbor_diag")
    assert "A201270300" in protected_hex.upper().replace("'", "").replace("H", "")
    assert COSE_ALG_EDDSA == -8


def test_the_corpus_contains_an_algorithm_c2pa_forbids() -> None:
    """``eddsa-sig-02`` is Ed448, and C2PA does not permit it.

    Recorded as a fact rather than skipped, because "EdDSA" is not one algorithm and
    that is an easy thing to get wrong. C2PA 13.2.1 is unambiguous: "Ed25519
    instance only. No other EdDSA instances are allowed", and 13.2.1 further requires
    "elliptic curve keys on the edwards25519 elliptic curve". An implementation that
    accepted this vector because the COSE ``alg`` is also EdDSA (-8) would be
    non-conformant while looking correct.

    So the signer must reject a non-Ed25519 key at construction, not at signing time,
    and the verifier must reject an ``alg`` of -8 whose certificate SPKI is not
    id-Ed25519. This vector is what that rule looks like in the wild.
    """
    doc = load_object(COSE / "eddsa-sig-02.json")
    assert str_field(doc, "input", "sign0", "key", "crv") == "Ed448"
    assert len(bytes.fromhex(str_field(doc, "input", "sign0", "key", "x_hex"))) == 57


def test_cbor_appendix_a_corpus_covers_every_major_type() -> None:
    """RFC 8949 Appendix A, grouped by major type.

    MAJOR TYPE 7 IS SPLIT UPSTREAM into `mt7-float` and `mt7-simple`, so the set is
    nine files rather than eight. That is the float and simple-value path, where the
    bool-as-map-key defect lived, and it is the only place the corpus exercises our
    4.2.1 shortest-form and 4.2.2 NaN rules against published bytes -- six of its
    items are non-canonical encodings we refuse, and their own descriptions say so.

    A FIXED LIST, not a count: `len >= 7` reads as a floor and is really an equality.
    """
    expected = [*(f"mt{n}" for n in range(7)), "mt7-float", "mt7-simple"]
    encoded = sorted(p.stem for p in CBOR.glob("mt*.cbor"))
    assert encoded == expected, f"corpus changed shape: {encoded}"
    for path in CBOR.glob("mt*.cbor"):
        assert path.stat().st_size > 0, f"{path.name} is empty"
        assert path.with_suffix(".edn").exists(), f"{path.name} has no diagnostic pair"


def test_vendored_corpora_carry_their_provenance_and_licence() -> None:
    """An unlicensed vector corpus is legally unvendorable; say where each came from.

    THIRD_PARTY IS THE ONE THAT MATTERS. `cose/` is Unlicense and `cbor/` BSD-2-Clause,
    neither carrying an attribution obligation; the EncypherAI and writerslogic vectors
    are MIT and Apache-2.0, which do. Checking the two permissive corpora and skipping
    the encumbered one is the wrong half.
    """
    for directory in (COSE, CBOR, THIRD_PARTY):
        text = (directory / "PROVENANCE.md").read_text("utf-8")
        assert "Licence" in text or "licence" in text
        assert "https://github.com/" in text
        assert "2026-08-05" in text, "retrieval date must be recorded"

    # A COMMIT, not a push date. A push to an unrelated path cannot tell a maintainer
    # whether the vectors moved -- the same mutable-reference failure CLAUDE.md forbids
    # for GitHub Actions.
    third_party = (THIRD_PARTY / "PROVENANCE.md").read_text("utf-8")
    assert re.search(r"\b[0-9a-f]{12,40}\b", third_party), "pin the upstream commit"
    for obligation in ("MIT", "Apache-2.0"):
        assert obligation in third_party, f"{obligation} notice must travel with the files"


def test_the_checksum_manifest_lists_no_build_artefacts() -> None:
    """SHA256SUMS must pass on a CLEAN checkout, not only on the machine that wrote it.

    tests/vectors/README tells consumers to run `shasum -a 256 -c SHA256SUMS`, and the
    manifest listed two ``__pycache__/*.pyc`` files. Those are gitignored, so the
    check passed here and FAILED for everyone else -- and for anyone on a Python other
    than 3.10, whose bytecode filenames differ anyway::

        shasum: ./__pycache__/loader.cpython-310.pyc: No such file or directory
        shasum: WARNING: 2 listed files could not be read

    For an artefact offered to C2PA and C2SP, an integrity manifest that cannot pass
    is worse than none: it teaches the first person who tries it that our checksums
    are broken.
    """
    manifest = (CBOR.parent / "SHA256SUMS").read_text("utf-8")
    listed = [line.split("  ", 1)[1] for line in manifest.splitlines() if "  " in line]

    assert listed, "the checksum manifest is empty"
    artefacts = sorted(name for name in listed if "__pycache__" in name or name.endswith(".pyc"))
    assert artefacts == [], f"build artefacts in the checksum manifest: {artefacts}"


def test_every_checksummed_file_exists_and_matches() -> None:
    """The manifest must describe the tree as committed. Verified by re-hashing rather
    than by shelling out, so it runs the same way on every platform."""
    import hashlib

    root = CBOR.parent
    for line in (root / "SHA256SUMS").read_text("utf-8").splitlines():
        if "  " not in line:
            continue
        expected, name = line.split("  ", 1)
        path = root / name
        assert path.exists(), f"{name} is checksummed but absent"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name
