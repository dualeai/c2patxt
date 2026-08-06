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

The attack list is writerslogic/c2pa-text-binding's disclosed list, reused verbatim so
these numbers are directly comparable to the only other published set (their
ROBUSTNESS.md).

SINGLE CORPUS. The harness author's own stated limitation is that single-dataset
robustness does not transfer. We used one corpus and say so.
"""

from __future__ import annotations

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


def identity(text: str) -> str:
    return text


def strip_invisibles(text: str) -> str:
    """Remove every zero-width character. The attack the carrier cannot survive."""
    return _SELECTORS.sub("", text)


def retype(text: str) -> str:
    """A human reading the text and typing it out again: the visible characters only."""
    return "".join(c for c in text if not _SELECTORS.match(c))


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


def carrier_only_nfkd(text: str) -> str:
    """The same, but asking only whether the CARRIER survives, not the binding."""
    return nfkd_casefold_whitespace(text)


def truncate_half(text: str) -> str:
    visible, _, mark = text.partition(MARKER)
    return visible[: len(visible) // 2] + MARKER + mark if mark else visible


def excerpt_30(text: str) -> str:
    visible, _, mark = text.partition(MARKER)
    start = len(visible) // 3
    return visible[start : start + int(len(visible) * 0.3)] + MARKER + mark if mark else visible


def delete_15_percent_of_words(text: str) -> str:
    visible, _, mark = text.partition(MARKER)
    words = visible.split()
    kept = [w for i, w in enumerate(words) if i % 7]  # drops ~14.3%
    return " ".join(kept) + MARKER + mark if mark else " ".join(kept)


def typos_in_5_percent(text: str) -> str:
    visible, _, mark = text.partition(MARKER)
    chars = list(visible)
    for i in range(0, len(chars), 20):  # 5%
        if chars[i].isalpha():
            chars[i] = chars[i].swapcase()
    return "".join(chars) + MARKER + mark if mark else "".join(chars)


def paraphrase(text: str) -> str:
    """Stand-in for a paraphrase: every word replaced by a synonym is equivalent, at
    the byte level, to rewriting the text. No model needed to know the answer."""
    visible, _, mark = text.partition(MARKER)
    reworded = visible.replace(" the ", " a ").replace(" is ", " was ").replace(" and ", " plus ")
    return reworded + MARKER + mark if mark else reworded


def translate_round_trip(text: str) -> str:
    """Stand-in for a round-trip translation: the visible text changes."""
    return paraphrase(text)


def markdown_round_trip(text: str) -> str:
    """CARRIER SURVIVAL IS NOT PROVENANCE SURVIVAL.

    A pandoc md -> html -> md pass, or an email MIME round trip, leaves every
    variation selector intact and REFLOWS the visible text. The mark is still found;
    the hard binding fails on the NFC data hash. That distinction is invisible in a
    table headed "survival" unless it is called out.
    """
    visible, _, mark = text.partition(MARKER)
    reflowed = " ".join(visible.split())  # collapse newlines, the reflow pandoc does
    return reflowed + MARKER + mark if mark else reflowed


ATTACKS: dict[str, Callable[[str], str]] = {
    "identity": identity,
    "nfkd + casefold + whitespace": nfkd_casefold_whitespace,
    "strip invisible characters": strip_invisibles,
    "retype (visible text only)": retype,
    "truncate to 50%": truncate_half,
    "excerpt 30%": excerpt_30,
    "delete 15% of words": delete_15_percent_of_words,
    "typos in 5% of tokens": typos_in_5_percent,
    "paraphrase": paraphrase,
    "translate round-trip": translate_round_trip,
    "markdown round-trip (reflow)": markdown_round_trip,
}

#: Rows that GATE, and WHICH COLUMN each gates on. Everything else is a measurement.
#: identity gates `verified`: our own output must verify, or nothing else means
#: anything. The normalization row gates `located`: the carrier must survive every
#: Unicode normalization form, while the binding is EXPECTED to fail because the
#: visible bytes were rewritten.
_GATES = {"identity": "verified", "nfkd + casefold + whitespace": "located"}


def main(path: pathlib.Path) -> int:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Signer(private_key=key, certificates=(build_certificate(key),))

    documents = [json.loads(line)["text"] for line in path.read_text("utf-8").splitlines() if line.strip()]
    marked = [embed(doc, signer, DISCLOSURE) for doc in documents]
    print(f"corpus: {path.name}, {len(documents)} documents, {sum(map(len, documents))} characters\n")

    print(f"{'attack':32} {'verified':>9} {'located':>9}")
    print("-" * 52)
    failures: list[str] = []
    for name, attack in ATTACKS.items():
        verified = located = 0
        for text in marked:
            attacked = attack(text)
            try:
                verdict = verify(attacked)
            except Exception:  # noqa: BLE001 - an attack producing malformed text is a result, not a crash
                continue
            if verdict.state is not Provenance.UNMARKED:
                located += 1
            if verdict.at_least(Provenance.VALID):
                verified += 1
        rates = {"verified": verified / len(marked), "located": located / len(marked)}
        print(f"{name:32} {rates['verified']:9.3f} {rates['located']:9.3f}")
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
        "corpus. No natural-language process emits that sequence."
    )

    print("\nCARRIER SURVIVAL IS NOT PROVENANCE SURVIVAL. Compare the two columns: the reflow")
    print("row keeps the mark LOCATABLE while the binding fails, because the visible bytes")
    print("changed. A table headed 'survival' hides that unless both columns are shown.")

    for failure in failures:
        print(f"\nFAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(pathlib.Path(sys.argv[1])))
