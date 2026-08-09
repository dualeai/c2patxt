"""Adversarial robustness battery for A.8 text marking.

RUN MANUALLY, NOT IN CI. It needs the PAN'26 corpus, which the test suite cannot
fetch: verification is offline by design and the suite runs with --disable-socket.

    curl -sSL -o train.jsonl \\
      "https://zenodo.org/records/18620130/files/train.jsonl?download=1"
    uv run python -m tools.robustness train.jsonl

CORPUS: PAN'26 Text Watermarking, zenodo.org/records/18620130,
DOI 10.5281/zenodo.18620130, CC-BY-4.0, 300 records, md5 of train.jsonl
777a1f5376eb6e0d5b54db2acff8c3ff.

WHAT THIS MEASURES, AND WHAT IT DOES NOT
----------------------------------------
Survival rate per attack: the fraction of marked documents that still verify VALID
after the attack. Nothing here is a pass/fail gate except the two rows noted below,
because Article 50(2)'s feasibility clause is what makes a 0.500 publishable rather
than a defect -- a hard binding is not a watermark and is not expected to survive
paraphrase.

BALANCED ACCURACY IS DELIBERATELY NOT THE HEADLINE. For an A.8 hard binding the
true-negative rate is near-trivially 1.0: an 8-byte magic number encoded in variation
selectors essentially cannot occur by accident, so a balanced-accuracy figure is
dominated by the true-positive rate and tells a reader nothing the survival table does
not. The analytic false-positive probability is reported instead, which is the honest
form of the same claim.

The battery uses deterministic byte rewrites derived from the attacks disclosed by
writerslogic/c2pa-text-binding. Duplicate transforms are omitted; these labels describe
what this script does rather than claiming a model or translation service ran.

SINGLE CORPUS. The harness author's own stated limitation is that single-dataset
robustness does not transfer. We used one corpus and say so.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import unicodedata
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt import Provenance, embed, verify
from c2patxt.constants import MARKER, VS_HIGH_BASE, VS_LOW_BASE
from c2patxt.signing import Signer
from tests.conftest import DISCLOSURE, build_certificate

#: Every code point A.8 can place in a document, plus the zero-width characters an
#: attacker or a sanitiser is most likely to strip alongside them. Built from escapes
#: rather than literals: a source file containing invisible characters is one nobody
#: can review, which is the same argument the vector file makes for staying ASCII.
_INVISIBLE = (
    f"{MARKER}\u200b-\u200f{chr(VS_LOW_BASE)}-{chr(VS_LOW_BASE + 15)}{chr(VS_HIGH_BASE)}-{chr(VS_HIGH_BASE + 239)}"
)
_SELECTORS = re.compile(f"[{_INVISIBLE}]")
_CORPUS_MD5 = "777a1f5376eb6e0d5b54db2acff8c3ff"
_CORPUS_RECORDS = 300


def identity(text: str) -> str:
    return text


def strip_invisibles(text: str) -> str:
    """Remove every zero-width character. The attack the carrier cannot survive."""
    return _SELECTORS.sub("", text)


def nfkd_casefold_whitespace(text: str) -> str:
    """Aggressive normalization of the VISIBLE text, mark left in place.

    THE GATE IS ON THE `located` COLUMN, NOT `verified`, and the distinction is the
    whole point. Casefolding and collapsing whitespace REWRITE the visible bytes, so
    a hard binding is supposed to fail -- that is the binding doing its job. What must
    never happen is the MARK DISAPPEARING: variation selectors and U+FEFF have
    combining class 0 and no decomposition mapping, canonical or compatibility, so no
    normalization form may touch them.

    Gating `verified` here would assert that a hash binding tolerates a rewrite of the
    hashed bytes, which would mean the binding was broken, not working.
    """
    visible, _, mark = text.partition(MARKER)
    folded = " ".join(unicodedata.normalize("NFKD", visible).casefold().split())
    return folded + MARKER + mark if mark else folded


def truncate_half(text: str) -> str:
    visible, _, mark = text.partition(MARKER)
    return visible[: len(visible) // 2] + MARKER + mark if mark else visible


def excerpt_30(text: str) -> str:
    visible, _, mark = text.partition(MARKER)
    start = len(visible) // 3
    return visible[start : start + int(len(visible) * 0.3)] + MARKER + mark if mark else visible


def delete_word_indexes_divisible_by_seven(text: str) -> str:
    """Delete zero-based word indexes 0, 7, 14, and so on."""
    visible, _, mark = text.partition(MARKER)
    words = visible.split()
    kept = [word for index, word in enumerate(words) if index % 7]
    return " ".join(kept) + MARKER + mark if mark else " ".join(kept)


def case_flip_every_twentieth_character(text: str) -> str:
    """Swap case at character indexes 0, 20, 40, ... when that character is alphabetic."""
    visible, _, mark = text.partition(MARKER)
    chars = list(visible)
    for i in range(0, len(chars), 20):
        if chars[i].isalpha():
            chars[i] = chars[i].swapcase()
    return "".join(chars) + MARKER + mark if mark else "".join(chars)


def synthetic_word_substitution(text: str) -> str:
    """Apply three fixed visible-word replacements; no model or translation runs."""
    visible, _, mark = text.partition(MARKER)
    reworded = visible.replace(" the ", " a ").replace(" is ", " was ").replace(" and ", " plus ")
    return reworded + MARKER + mark if mark else reworded


def whitespace_collapse(text: str) -> str:
    """CARRIER SURVIVAL IS NOT PROVENANCE SURVIVAL.

    A pandoc md -> html -> md pass, or an email MIME round trip, leaves every
    variation selector intact and REFLOWS the visible text. The mark is still found;
    the hard binding fails on the NFC data hash. That distinction is invisible in a
    table headed "survival" unless it is called out.

    NAMED FOR WHAT IT DOES, NOT FOR WHAT IT MODELS. ``str.split()`` splits on U+00A0 as
    well as on ASCII whitespace, so on a corpus whose documents are already single lines
    this measures NBSP folding and no reflow at all -- see docs/robustness.md, which
    works the numbers through. The row was labelled "markdown round-trip (reflow)" and
    that label was wrong for the corpus it was run against.
    """
    visible, _, mark = text.partition(MARKER)
    # Collapses ASCII whitespace AND U+00A0, which is why the row is named for the
    # latter: see the docstring above.
    collapsed = " ".join(visible.split())
    return collapsed + MARKER + mark if mark else collapsed


ATTACKS: dict[str, Callable[[str], str]] = {
    "identity": identity,
    "NFKD + casefold + whitespace collapse": nfkd_casefold_whitespace,
    "strip invisible characters": strip_invisibles,
    "truncate to 50%": truncate_half,
    "excerpt 30%": excerpt_30,
    "delete word indexes 0, 7, 14, ...": delete_word_indexes_divisible_by_seven,
    "case flip every 20th character": case_flip_every_twentieth_character,
    "synthetic word substitution": synthetic_word_substitution,
    "whitespace collapse (NBSP folding)": whitespace_collapse,
}

#: Rows that GATE, and WHICH COLUMN each gates on. Everything else is a measurement.
#: identity gates `verified`: our own output must verify, or nothing else means
#: anything. The normalization row gates `located`: the carrier must survive every
#: Unicode normalization form, while the binding is EXPECTED to fail because the
#: visible bytes were rewritten.
_GATES = {"identity": "verified", "NFKD + casefold + whitespace collapse": "located"}


def load_documents(path: pathlib.Path) -> list[str]:
    """Load exactly the published PAN'26 corpus used for the reported table."""
    raw = path.read_bytes()
    digest = hashlib.md5(raw, usedforsecurity=False).hexdigest()
    if digest != _CORPUS_MD5:
        msg = f"{path} has md5 {digest}; expected the published PAN'26 corpus {_CORPUS_MD5}"
        raise ValueError(msg)

    documents: list[str] = []
    for line_number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            msg = f"{path}:{line_number}: blank records are not allowed"
            raise ValueError(msg)
        record: object = json.loads(line)
        match record:
            case {"text": str(text)}:
                documents.append(text)
            case _:
                msg = f"{path}:{line_number}: each JSON record must be an object with a string text field"
                raise ValueError(msg)

    if len(documents) != _CORPUS_RECORDS:
        msg = f"{path} has {len(documents)} records; expected {_CORPUS_RECORDS}"
        raise ValueError(msg)
    return documents


def main(path: pathlib.Path) -> int:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Signer(private_key=key, certificates=(build_certificate(key),))

    documents = load_documents(path)
    marked = [embed(doc, signer, DISCLOSURE) for doc in documents]
    character_count = sum(map(len, documents))
    print(f"corpus: {path.name}, md5 {_CORPUS_MD5}, {len(documents)} documents, {character_count} characters\n")

    attack_width = 32
    for name in ATTACKS:
        attack_width = max(attack_width, len(name))
    print(f"{'attack':{attack_width}} {'verified':>9} {'located':>9}")
    print("-" * (attack_width + 20))
    failures: list[str] = []
    for name, attack in ATTACKS.items():
        verified = located = 0
        for text in marked:
            attacked = attack(text)
            # verify() promises not to raise on hostile text. A raised exception is a
            # harness failure, not a zero in a non-gating row, so let it stop the run.
            verdict = verify(attacked)
            if verdict.state is not Provenance.UNMARKED:
                located += 1
            if verdict.at_least(Provenance.VALID):
                verified += 1
        rates = {"verified": verified / len(marked), "located": located / len(marked)}
        print(f"{name:{attack_width}} {rates['verified']:9.3f} {rates['located']:9.3f}")
        gate = _GATES.get(name)
        if gate is not None and rates[gate] < 1.0:
            failures.append(f"{name}: {gate}={rates[gate]:.3f}, expected 1.000 -- the codec is broken")

    # The analytic false-positive probability, which is what the negative class is
    # really telling you. A false positive needs U+FEFF followed by eight variation
    # selectors decoding to exactly the magic number.
    print(
        "\nanalytic false-positive probability: a false positive requires U+FEFF followed by\n"
        "eight variation selectors decoding to 0x4332504154585400. Treating each selector as\n"
        "uniform over the 256 reachable values, that is 256**-8 = 2**-64 per U+FEFF in the\n"
        "corpus. This is an analytic candidate-detection model, not a measured natural-language\n"
        "false-positive rate."
    )

    print("\nCARRIER SURVIVAL IS NOT PROVENANCE SURVIVAL. Compare the two columns: the")
    print("whitespace-collapse row keeps the mark LOCATABLE while the binding fails,")
    print("because the visible bytes changed. A table headed 'survival' hides that")
    print("unless both columns are shown.")

    for failure in failures:
        print(f"\nFAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(pathlib.Path(sys.argv[1])))
