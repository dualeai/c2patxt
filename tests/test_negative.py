# pyright: reportPrivateUsage=false
# Reaches _claim_malformed and _reparse directly: these are the units that decide
# rejection, and testing them only through verify() would hide which rule fired.
"""Text that must NOT be reported as marked, and marks that must fail correctly.

NOT REPORTING A MARK IS A SECURITY PROPERTY, NOT POLITENESS.
------------------------------------------------------------
If a stray magic-looking run could invalidate a genuine wrapper elsewhere in the same
document, then anyone able to APPEND text -- a comment, a quoted reply, a signature
block -- could destroy the provenance of text they did not write. Denial of service
against a compliance artefact is still a denial of service. So detection has to be
precise in both directions: no false positives, and no false positive that takes a
true positive down with it.

The rejection half uses attack-shaped inputs and asserts the exact boundary each case
must defend.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt import (
    C2paTextError,
    MarkCorruptError,
    Provenance,
    StatusCode,
    UnencodableTextError,
    VerifyContext,
    extract,
    locate,
    verify,
)
from c2patxt._cbor import CborValue

# The decoder owns the MAX_SELECTOR_RUN bound, so the test for that bound has to reach
# for it; find_wrappers only ever sees runs that happen to carry a plausible header.
from c2patxt._locate import _decode_run  # pyright: ignore[reportPrivateUsage] -- the unit that owns the cap
from c2patxt.constants import (
    MAGIC,
    MARKER,
    MAX_MANIFEST_LENGTH,
    MAX_SELECTOR_RUN,
    VS_HIGH_BASE,
    VS_LOW_BASE,
)
from c2patxt.signing import Signer
from tests.conftest import build_certificate, mark


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


def _selectors(payload: bytes) -> str:
    """Encode bytes as variation selectors by hand, per A.8.3.1.

    The literal bases make this hostile-input builder independent of the codec under
    test, matching the formula used by the A.8 vector tests.
    """
    return "".join(chr(0xFE00 + b) if b < 0x10 else chr(0xE0100 + b - 0x10) for b in payload)


# --------------------------------------------------------------------------------
# Text with no mark at all
# --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "\n\t\r\n",
        "a",
        "Ordinary prose, nothing to see.",
        "Text mentioning C2PATXT and variation selectors in words only.",
    ],
)
def test_plain_text_reports_no_mark(text: str) -> None:
    """The overwhelmingly common case. UNMARKED is an absence, not a finding."""
    assert locate(text) is None
    assert extract(text) is None
    assert verify(text).state is Provenance.UNMARKED


def test_a_leading_utf8_bom_is_not_a_mark() -> None:
    """U+FEFF as a byte-order mark is ubiquitous and means nothing here.

    A.8.4.2 keys detection on U+FEFF, so every Windows-authored text file is a
    candidate. Treating a bare BOM as a corrupt mark would make the library raise on
    a large fraction of the world's text files.
    """
    assert locate("﻿Ordinary text saved by a Windows editor.") is None
    assert verify("﻿Ordinary text saved by a Windows editor.").state is Provenance.UNMARKED


def test_emoji_variation_selectors_are_not_a_mark() -> None:
    """U+FE0F is how emoji presentation is requested; it is EVERYWHERE.

    These are genuine, legitimate variation selectors in ordinary content. Reading
    them as a wrapper would make the library see marks in every emoji-bearing
    message on the internet.
    """
    for text in ("❤️ and ✔️", "👨‍👩‍👧‍👦 family", "1️⃣2️⃣3️⃣"):
        assert locate(text) is None
        assert verify(text).state is Provenance.UNMARKED


def test_a_marker_with_no_selector_run_is_not_a_mark() -> None:
    """U+FEFF alone, mid-text, with nothing following it."""
    assert locate("before﻿after") is None
    assert verify("before﻿after").state is Provenance.UNMARKED


@pytest.mark.parametrize("count", [1, 4, 7])
def test_a_run_shorter_than_the_magic_is_not_a_mark(count: int) -> None:
    """Fewer than 8 selectors cannot spell an 8-byte magic number.

    Not corruption -- there is no evidence a mark was ever intended, and raising here
    would turn incidental selector use into an exception.
    """
    assert locate(MARKER + chr(VS_LOW_BASE) * count) is None


def test_a_run_that_does_not_spell_the_magic_is_not_a_mark() -> None:
    """Eight selectors, wrong bytes. The magic number is the whole discriminator."""
    wrong = bytes(b ^ 0xFF for b in MAGIC)
    assert wrong != MAGIC
    assert locate(MARKER + _selectors(wrong + b"\x00" * 8)) is None


# --------------------------------------------------------------------------------
# The key one: a decoy must not take a real mark down with it
# --------------------------------------------------------------------------------


def test_a_garbage_run_before_a_valid_wrapper_does_not_hide_it(signer: Signer) -> None:
    """ATTACK: prepend a decoy so the scanner stops before reaching the real mark.

    If a non-matching run made detection give up, anyone who can prepend text -- a
    mail client adding a quoted header, a CMS adding a byline -- could make a
    document read as UNMARKED rather than as tampered with. UNMARKED is the far more
    dangerous outcome: "no claim was made" invites no investigation, while "the claim
    does not match" does.

    The mark is correctly INVALID here, because prepending shifts every byte offset
    and the hard binding exists to catch exactly that. What must not happen is the
    mark vanishing.
    """
    decoy = MARKER + _selectors(b"NOT-C2PA" + b"\x00" * 16)
    tampered = decoy + mark("Hello world.", signer)

    assert locate(tampered) is not None
    verdict = verify(tampered)
    assert verdict.state is Provenance.INVALID
    assert verdict.state is not Provenance.UNMARKED


def test_a_bom_before_a_valid_wrapper_does_not_hide_it(signer: Signer) -> None:
    """Same property, with the single most likely real-world decoy."""
    tampered = "\ufeff" + mark("Hello world.", signer)
    assert locate(tampered) is not None
    assert verify(tampered).state is Provenance.INVALID


def test_a_decoy_after_the_text_leaves_the_mark_verifiable(signer: Signer) -> None:
    """The case where the decoy costs nothing: it is INSIDE the covered text.

    Here the decoy is part of the document at signing time, so the offsets are
    correct and the mark still verifies. This is the positive half of the pair --
    without it, the test above would pass just as well if detection were broken and
    everything came back INVALID.
    """
    decoy = MARKER + _selectors(b"NOT-C2PA" + b"\x00" * 16)
    assert verify(mark("Hello " + decoy + " world.", signer)).state is Provenance.VALID


def test_emoji_in_the_marked_text_do_not_destroy_the_mark(signer: Signer) -> None:
    """Legitimate variation selectors INSIDE the covered text, not before it."""
    assert verify(mark("Report ✔️ complete 👍🏽", signer)).state is Provenance.VALID


# --------------------------------------------------------------------------------
# Corruption: the right failure, and never a crash
# --------------------------------------------------------------------------------


def test_a_length_that_overruns_the_run_is_corrupt_not_a_crash() -> None:
    """ATTACK: declare a huge manifestLength against a short run.

    The classic length-prefix attack. It must be caught by bounds-checking BEFORE
    the slice, not by an IndexError or a MemoryError.
    """
    header = MAGIC + b"\x01" + (0xFFFF).to_bytes(4, "big")
    with pytest.raises(MarkCorruptError, match="manifestLength") as caught:
        locate(MARKER + _selectors(header + b"\x00" * 4))
    # NOT a bare raises. Every wrapper defect here raises the same type, so without a
    # discriminator the version check answering for the length check -- or the reverse --
    # is invisible, and a mutation that swapped them would survive. The neighbouring
    # docstring in this file explains at length why that matters; this applies it.
    assert caught.value.code is StatusCode.TEXT_CORRUPTED_WRAPPER


def test_a_declared_length_above_the_cap_is_refused_before_payload_acceptance() -> None:
    """A manifestLength above the implementation cap is refused.

    The declared value is checked against MAX_MANIFEST_LENGTH before the parser accepts
    or slices a manifest payload.
    """
    header = MAGIC + b"\x01" + (MAX_MANIFEST_LENGTH + 1).to_bytes(4, "big")

    # The supplied payload exceeds the cap so the limit check, rather than the
    # available-bytes check, determines the error.
    payload = b"\x00" * (MAX_MANIFEST_LENGTH + 8)
    with pytest.raises(MarkCorruptError, match=r"exceeds the \d+-byte limit"):
        locate(MARKER + _selectors(header + payload))


def test_an_unsupported_wrapper_version_is_corrupt() -> None:
    """A.8.2.2 defines version 1. Anything else is a format we cannot read.

    Accepting it would mean guessing at a layout, which is how a parser ends up
    interpreting a future version's bytes under this version's rules.
    """
    header = MAGIC + b"\x02" + (4).to_bytes(4, "big")
    with pytest.raises(MarkCorruptError, match="version 2") as caught:
        locate(MARKER + _selectors(header + b"\x00" * 4))
    # "version 2" specifically: the length is valid here, so a length check answering
    # instead would be a wrong diagnosis with the right verdict.
    assert caught.value.code is StatusCode.TEXT_CORRUPTED_WRAPPER


def test_an_unbounded_selector_run_is_capped() -> None:
    """The decoder stops at the declared selector bound and ignores the next selector."""
    over_cap = MARKER + chr(VS_HIGH_BASE) * (MAX_SELECTOR_RUN + 1)
    marker_length = len(MARKER)

    decoded, stop = _decode_run(over_cap, marker_length)
    assert len(decoded) == MAX_SELECTOR_RUN
    assert stop == marker_length + MAX_SELECTOR_RUN
    assert locate(over_cap) is None


def test_a_truncated_wrapper_reports_a_specification_code(signer: Signer) -> None:
    """Truncation is the commonest real corruption: a copy-paste that clipped the end.

    verify() must report it as a status code rather than raising, because a caller
    handling a stream of untrusted documents cannot wrap every one in a try.
    """
    verdict = verify(mark("Hello world.", signer)[:-300])
    assert verdict.state is Provenance.INVALID
    # The specific code, since the test is named for it: 15.12.1.3.2's, for a wrapper
    # whose declared manifestLength runs past what the run actually carries.
    assert StatusCode.TEXT_CORRUPTED_WRAPPER in verdict.codes()


def test_a_wrapper_whose_manifest_is_garbage_is_corrupt() -> None:
    """ATTACK: valid header, valid length, junk payload.

    The header check passes, so this exercises the JUMBF and CBOR layers under
    attacker control rather than the selector layer.
    """
    payload = b"\x00" * 64
    header = MAGIC + b"\x01" + len(payload).to_bytes(4, "big")
    with pytest.raises(MarkCorruptError, match="jumb superbox") as caught:
        extract("text" + MARKER + _selectors(header + payload))

    # THE MESSAGE DISCRIMINATES; THE CODE DOES NOT, AND THAT IS A KNOWN COMPROMISE. The
    # wrapper here is intact -- magic, version and length all check out -- and it is the
    # JUMBF layer that fails, so manifest.text.corruptedWrapper is not a precise
    # description. 15.12.1.3.2 defines it for a wrapper with an "invalid version,
    # algorithm, or manifest length", none of which applies.
    #
    # It stands because the specification names no code for "the manifest store is not
    # parseable JUMBF": the codes below this level all presuppose a store that parsed
    # (claim.missing, claim.cbor.invalid, assertion.cbor.invalid). Inventing one, or
    # borrowing general.error, would be a wire-visible choice on no clause at all -- so
    # the fallback is asserted here as the deliberate fallback it is, and the MESSAGE
    # carries the diagnosis a reader needs. Recorded in docs/open-questions.md.
    assert caught.value.code is StatusCode.TEXT_CORRUPTED_WRAPPER


# --------------------------------------------------------------------------------
# Rejection: the right failure code, not merely a failure
# --------------------------------------------------------------------------------


def test_a_shifted_second_wrapper_is_covered_by_the_selected_binding(signer: Signer) -> None:
    """Only the first wrapper still matches its declared exclusion after concatenation."""
    first = mark("Document one.", signer)
    second = mark("Document two.", signer)
    verdict = verify(first + second[second.index(MARKER) :])

    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()


def test_appending_after_the_wrapper_cannot_extend_the_exclusion(signer: Signer) -> None:
    """ATTACK: exclusion-range extension.

    Appending after the mark and hoping the excluded range grows to cover it. It
    cannot: the range lives inside the signed claim, so extending it requires a
    signature the attacker does not have. Leaving it alone makes the appended bytes
    part of the hashed text.
    """
    verdict = verify(mark("The contract is void.", signer) + " Just kidding.")
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()


def test_prepending_before_the_text_is_caught(signer: Signer) -> None:
    """ATTACK: prepend rather than append, shifting every offset.

    Caught one step earlier than the hash -- the exclusion no longer names a located
    wrapper -- which is the more precise diagnosis.
    """
    verdict = verify("Editor's note: " + mark("The contract is void.", signer))
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()


@pytest.mark.parametrize("bad", ["\ud800", "\udfff", "a\ud800b"])
def test_a_lone_surrogate_raises_our_own_error_not_a_codec_error(bad: str) -> None:
    """ATTACK: post a lone surrogate to a verification endpoint.

    Python's str happily holds unpaired surrogates -- they arrive from
    surrogateescape decoding, os.fsdecode, and JSON escapes -- but UTF-8 cannot
    represent them, and every offset in this format is a UTF-8 byte offset.

    Before the guard, this surfaced as a bare UnicodeEncodeError from deep inside the
    scan, which an endpoint catching only C2paTextError -- what the documentation
    tells integrators to catch -- would not handle. It only fired when a U+FEFF
    followed the surrogate, so it was attacker-triggerable rather than obvious.
    """
    with pytest.raises(UnencodableTextError):
        verify(bad + MARKER + "x")
    with pytest.raises(UnencodableTextError):
        locate(bad + MARKER + "x")


def test_the_surrogate_error_is_catchable_the_documented_ways() -> None:
    """Catchable as C2paTextError and as ValueError, like every error we raise."""
    with pytest.raises(C2paTextError):
        verify("\ud800" + MARKER)
    with pytest.raises(ValueError, match="unpaired surrogate"):
        verify("\ud800" + MARKER)


def test_a_claim_missing_a_required_field_is_malformed() -> None:
    """C2PA 15.6.2 lists four fields and says a claim missing any "shall be rejected
    with a failure code of claim.malformed".
    """
    from c2patxt._verify import _claim_malformed

    complete: dict[str, CborValue] = {
        "instanceID": "xmp:iid:1",
        "signature": "self#jumbf=c2pa.signature",
        "created_assertions": [],
        "claim_generator_info": {"name": "c2patxt"},
    }
    assert not _claim_malformed(complete)

    for field in ("instanceID", "signature", "created_assertions", "claim_generator_info"):
        assert _claim_malformed({k: v for k, v in complete.items() if k != field}), field


def test_a_generator_info_array_is_malformed_for_a_v2_claim() -> None:
    """claim-map-v2 declares one ``$generator-info-map``; v1 declares an array."""
    from c2patxt._verify import _claim_malformed

    base: dict[str, CborValue] = {"instanceID": "x", "signature": "y", "created_assertions": []}
    assert _claim_malformed({**base, "claim_generator_info": [{"name": "c2patxt"}]})
    assert _claim_malformed({**base, "claim_generator_info": {"version": "1.0"}})
    assert not _claim_malformed({**base, "claim_generator_info": {"name": "c2patxt"}})


@pytest.mark.parametrize(
    "depth",
    [0, 1],
    ids=["manifest-store", "assertion-store"],
)
def test_two_boxes_sharing_a_label_are_rejected(signer: Signer, depth: int) -> None:
    """Resolve manifest boxes by 15.5.1, but reject an ambiguous assertion label.

    At depth 0, 15.5.1 selects the last recognized manifest. At depth 1, the manifest
    carries two assertion-store boxes, for which the status registry has no narrower
    code than ``general.error``. Neither case is a second claim box.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse, parse_manifest_store
    from c2patxt._jumbf import JumbfBox, parse_superbox

    original = extract(mark("Hello world.", signer))
    assert original is not None

    def duplicate_a_child(raw: bytes, remaining: int) -> bytes:
        box, _ = parse_superbox(raw)
        children = list(box.content)
        if remaining:
            # Descend into the first nested superbox and duplicate a child THERE.
            inner = duplicate_a_child(_jumbf.serialize_superbox(_reparse(children[0][1])[0]), remaining - 1)
            children[0] = (children[0][0], inner[8:])
        else:
            children.append(children[0])
        return _jumbf.serialize_superbox(JumbfBox(description=box.description, content=tuple(children)))

    forged = duplicate_a_child(original.raw, depth)
    if depth == 0:
        assert parse_manifest_store(forged).manifest_label == original.manifest_label
    else:
        with pytest.raises(MarkCorruptError, match="more than one box labelled") as caught:
            parse_manifest_store(forged)
        assert caught.value.code is StatusCode.GENERAL_ERROR


def test_a_claim_whose_cbor_is_invalid_reports_the_cbor_code() -> None:
    """C2PA 15.6.2: "If the content of the claim is not well-formed CBOR, the claim
    shall be rejected with a failure code of claim.cbor.invalid." The wrapper itself
    remains structurally intact.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _reparse, parse_manifest_store
    from c2patxt._jumbf import DescriptionBox, JumbfBox, parse_superbox
    from c2patxt.manifest import LABEL_CLAIM, UUID_CLAIM

    signer = _local_signer()
    original = extract(mark("Hello world.", signer))
    assert original is not None

    store, _ = parse_superbox(original.raw)
    manifest, _ = _reparse(store.content[0][1])

    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_CLAIM:
            broken = JumbfBox(
                description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                # 0xff is not a valid CBOR initial byte in any major type.
                content=((b"cbor", b"\xff\xff\xff"),),
            )
            rebuilt.append((tbox, _jumbf.serialize_superbox(broken)[8:]))
        else:
            rebuilt.append((tbox, payload))

    forged = _jumbf.serialize_superbox(
        JumbfBox(
            description=store.description,
            content=(
                (
                    _jumbf.TBOX_SUPERBOX,
                    _jumbf.serialize_superbox(JumbfBox(description=manifest.description, content=tuple(rebuilt)))[8:],
                ),
            ),
        )
    )

    with pytest.raises(MarkCorruptError) as excinfo:
        parse_manifest_store(forged)
    assert excinfo.value.code is StatusCode.CLAIM_CBOR_INVALID


def test_an_assertion_link_outside_the_manifest_has_its_own_code() -> None:
    """C2PA 15.10.3.1 gives TWO codes for two conditions:

        "If the URI does not refer to a location within the same C2PA Manifest (a
        self#jumbf location), the claim shall be rejected with a failure code of
        assertion.outsideManifest. If the URI cannot be resolved and the data
        retrieved, the claim shall be rejected with a failure code of
        assertion.missing."

    We collapsed both into assertion.missing, which tells a caller their assertion is
    absent when in fact the claim pointed somewhere we will never follow.
    """
    from c2patxt._verify import _link_status

    manifest = extract(mark("Hello world.", _local_signer()))
    assert manifest is not None

    outside: dict[str, CborValue] = {"url": "https://evil.example/assertion", "alg": "sha256", "hash": b"\x00" * 32}
    code, label = _link_status(outside, manifest, {})
    assert label is None
    assert code is StatusCode.ASSERTION_OUTSIDE_MANIFEST


def _local_signer() -> Signer:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    return Signer(private_key=key, certificates=(build_certificate(key),))


@pytest.mark.parametrize(
    ("label", "requestable"),
    [("a/b", True), ("a#b", True), ("a\x00b", True), (None, True)],
    ids=["slash", "hash", "nul", "requestable-without-label"],
)
def test_a_bad_description_box_raises_our_own_error_type(label: str | None, requestable: bool) -> None:
    """DescriptionBox validation raised a BARE ValueError, which escaped every catch.

    ``parse_manifest_store`` catches ``(JumbfError, CborDecodeError)``. Both subclass
    ValueError, but a bare ValueError is an instance of NEITHER, so a forbidden label
    character in attacker-supplied manifest bytes propagated straight out of
    ``verify()`` -- which documents that it never raises for corrupt or invalid marks.

    A parser raising the stdlib's generic error rather than its own is the anomaly;
    ``_jumbf`` already has ``JumbfError``.
    """
    from c2patxt import _jumbf
    from c2patxt._jumbf import DescriptionBox, JumbfError

    with pytest.raises(JumbfError):
        DescriptionBox(uuid=_jumbf.UUID_CBOR, label=label, requestable=requestable)


def test_verify_returns_a_verdict_for_a_forbidden_label_in_the_manifest() -> None:
    """The end-to-end form of the above: crafted bytes, not a direct constructor call.

    Reachable by anyone who can put text in front of a verifier, so an uncaught
    exception here is a denial of service on any endpoint catching only
    ``C2paTextError`` -- which is what the documentation tells integrators to catch.
    """
    from c2patxt import _jumbf
    from c2patxt._selectors import build_wrapper

    # A manifest-store superbox whose own label carries a forbidden '/'.
    payload = _jumbf.UUID_CBOR + bytes([0x03]) + b"bad/label\x00"
    description = (8 + len(payload)).to_bytes(4, "big") + b"jumd" + payload
    content = (8 + 1).to_bytes(4, "big") + b"cbor" + b"\xf6"
    body = description + content
    store = (8 + len(body)).to_bytes(4, "big") + b"jumb" + body

    verdict = verify("Doc." + build_wrapper(store))
    assert verdict.state is Provenance.INVALID
    # THE CODE, not only the state. INVALID is reachable from a dozen unrelated
    # branches, so asserting it alone would still pass if a forbidden label started
    # being reported as, say, a signature failure -- sending an investigator to look
    # at a credential when the defect is in the box header.
    assert StatusCode.TEXT_CORRUPTED_WRAPPER in verdict.codes()


@pytest.mark.parametrize("algorithm", ["sha1", "md5", "sha3-256", "", "SHA256"])
def test_an_unsupported_hash_algorithm_is_reported_as_such(signer: Signer, algorithm: str) -> None:
    """C2PA 13.1 permits sha256/384/512 and says implementations "shall not support
    additional algorithms on an optional basis".

    ``"SHA256"`` also fails: registry values are lowercase and the comparison is
    case-sensitive.
    """
    from c2patxt._verify import _binding_status
    from c2patxt.manifest import ASSERTION_HASH_DATA, ManifestStore

    store = ManifestStore(
        manifest_label="urn:c2pa:x",
        claim={},
        claim_bytes=b"",
        assertions={
            ASSERTION_HASH_DATA: {
                "alg": algorithm,
                "hash": b"\x00" * 32,
                "exclusions": [{"start": 0, "length": 1}],
            }
        },
        assertion_bytes={},
        signature=b"",
        raw=b"",
    )
    assert _binding_status("any text", store, []) == (StatusCode.ALGORITHM_UNSUPPORTED,)


@pytest.mark.parametrize(
    ("structure_alg", "claim_alg", "expected"),
    [
        ("sha256", "sha512", "sha256"),  # the structure's own value wins
        (None, "sha384", "sha384"),  # 15.4.1: fall back to the claim
        (None, None, None),  # neither -> algorithm.unsupported
        ("sha1", "sha256", None),  # the structure NAMES an unsupported one: no fallback
        (None, "sha1", None),  # the claim names an unsupported one
        ("sha512", None, "sha512"),  # no claim alg needed when the structure has one
    ],
    ids=["structure-wins", "inherits", "neither", "structure-unsupported", "claim-unsupported", "no-claim-alg"],
)
def test_the_hash_algorithm_resolves_through_the_enclosing_structure(
    structure_alg: str | None, claim_alg: str | None, expected: str | None
) -> None:
    """C2PA 15.4.1, verbatim: "If no alg field is present in the hard binding
    assertion, the value of the alg field in the Claim shall be used as the hash
    algorithm. If no alg field is present in the Claim, the Claim shall be rejected
    with a failure code of algorithm.unsupported."

    15.4.2 says the same for hashed_uri structures, resolving through "the nearest
    enclosing structure that contains an alg field".

    ``alg`` is OPTIONAL in both data-hash-map (18.5.2) and $hashed-uri-map (8.4.2.1),
    and we required it in both -- so a manifest using the COMMON encoding, where the
    per-structure alg is omitted and inherited from the claim, read as INVALID here.
    That is an interop failure pointed at ourselves.

    The `structure-unsupported` case is the one worth stating: naming sha1 explicitly
    must be REJECTED, not quietly resolved to the claim's sha256. Falling back on a
    named-but-unsupported value would let a producer request a weak hash and get a
    strong one, and neither party would know which was used.
    """
    from c2patxt._verify import _resolve_algorithm

    structure: dict[str, CborValue] = {} if structure_alg is None else {"alg": structure_alg}
    claim: dict[str, CborValue] = {} if claim_alg is None else {"alg": claim_alg}

    assert _resolve_algorithm(structure, claim) == expected


@pytest.mark.parametrize(
    ("url", "expected_label"),
    [
        ("self#jumbf=c2pa.assertions/c2pa.hash.data", "c2pa.hash.data"),
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.assertions/c2pa.hash.data", "c2pa.hash.data"),
        ("self#jumbf=/c2pa/urn:c2pa:OTHER/c2pa.assertions/c2pa.hash.data", None),
        ("https://evil.example/assertion", None),
        ("self#jumbf=c2pa.signature", None),
        ("self#jumbf=/c2pa/c2pa.assertions/c2pa.hash.data", None),
    ],
    ids=["manifest-relative", "store-relative", "other-manifest", "http", "not-an-assertion", "no-manifest-label"],
)
def test_an_assertion_uri_resolves_in_both_forms(url: str, expected_label: str | None) -> None:
    """C2PA 8.4.2.1 verbatim: "These self#jumbf URIs may be relative to the entire
    C2PA Manifest Store, in which case they shall start with a `/`, or relative to the
    current C2PA Manifest."

    The specification's OWN Example 1 uses the store-relative form
    (``self#jumbf=/c2pa/urn:c2pa:F095F30E-.../c2pa.assertions/c2pa.thumbnail.claim``),
    and 10.2.1's claim-map-v2 example uses it in ``redacted_assertions``. We accepted
    only the manifest-relative form, so a conforming manifest read as INVALID with
    ``assertion.outsideManifest``.

    THE STORE-RELATIVE FORM IS NOT SIMPLY A LONGER PREFIX. It names a manifest, and
    that manifest must be THIS one -- otherwise a claim could point at a different
    manifest's assertion, which is precisely what ``assertion.outsideManifest`` exists
    to catch. ``other-manifest`` is the case that distinguishes parsing the label from
    widening the prefix test.
    """
    from c2patxt._verify import _assertion_label

    assert _assertion_label(url, "urn:c2pa:MANIFEST") == expected_label


@pytest.mark.parametrize(
    ("labels", "count"),
    [
        (["c2pa.hash.data"], 1),
        (["c2pa.hash.data", "c2pa.hash.data__1"], 2),
        (["c2pa.hash.data", "c2pa.hash.data__1", "c2pa.hash.data__2"], 3),
        (["c2pa.hash.data", "c2pa.ai-disclosure"], 1),
        (["c2pa.hash.data__1"], 1),
        (["c2pa.hash.dataX", "c2pa.hash.data_1"], 0),
        ([], 0),
    ],
    ids=["one", "two", "three", "one-plus-other", "only-indexed", "near-misses", "none"],
)
def test_hard_bindings_are_counted_across_the_instance_convention(labels: list[str], count: int) -> None:
    """C2PA 6.4: "Multiple assertions of the same type can occur in the same manifest…
    accomplished by adding a double-underscore and a monotonically increasing index to
    the label. For example… c2pa.metadata, c2pa.metadata__1 and c2pa.metadata__2."

    15.10.1.2: "Validate that there is exactly one hard binding to content assertion…
    If there is more than one such assertion, the manifest shall be rejected with a
    failure code of assertion.multipleHardBindings."

    ``near-misses`` matters: ``c2pa.hash.dataX`` and ``c2pa.hash.data_1`` (one
    underscore) are DIFFERENT assertions, not instances, so counting them would reject
    manifests that are fine.
    """
    from c2patxt._verify import _count_hard_bindings

    assert _count_hard_bindings(labels) == count


@pytest.mark.parametrize(
    ("url", "resolves"),
    [
        ("self#jumbf=c2pa.signature", True),
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.signature", True),
        ("self#jumbf=/c2pa/urn:c2pa:OTHER/c2pa.signature", False),
        ("self#jumbf=c2pa.assertions/c2pa.actions.v2", False),
        ("https://evil.example/signature", False),
        ("", False),
    ],
    ids=["manifest-relative", "store-relative", "other-manifest", "an-assertion", "http", "empty"],
)
def test_the_claims_signature_uri_must_resolve_inside_this_manifest(url: str, resolves: bool) -> None:
    """C2PA 15.7 verbatim: "The validator shall retrieve the URI reference for the
    signature from the value of the claim's signature field and resolve the URI
    reference to obtain the COSE signature. If the signature field is not present, or
    the URI cannot be resolved, or the URI does not resolve to a location within the
    same C2PA Manifest box (as the claim), then the claim shall be rejected with a
    failure code of claimSignature.missing."

    We took the signature box found BY LABEL and never read ``claim["signature"]``
    beyond a presence check, so a claim naming an https URL or pointing at an
    assertion still verified.

    LOW EXPLOITABILITY TODAY, and worth doing anyway: the URI is inside the signed
    bytes and there is exactly one signature box, so an attacker cannot currently
    redirect us to a signature they control. The moment anything makes a second COSE
    box reachable -- an update manifest, a compressed manifest, an ingredient -- this
    check becomes load-bearing with no warning that it was ever absent.
    """
    from c2patxt._verify import _signature_uri_resolves

    assert _signature_uri_resolves(url, "urn:c2pa:MANIFEST") is resolves


@pytest.mark.parametrize(
    ("link", "expected"),
    [
        ({"hash": b"\x00" * 32}, StatusCode.CLAIM_MALFORMED),
        ({"url": 7, "hash": b"\x00" * 32}, StatusCode.CLAIM_MALFORMED),
        ({"url": "self#jumbf=c2pa.assertions/x", "hash": "not bytes"}, StatusCode.CLAIM_MALFORMED),
        ({"url": "self#jumbf=c2pa.assertions/x", "hash": b"\x00" * 32, "alg": "md5"}, StatusCode.ALGORITHM_UNSUPPORTED),
        ({"url": "self#jumbf=c2pa.assertions/absent", "hash": b"\x00" * 32}, StatusCode.ASSERTION_MISSING),
        ({"url": "https://elsewhere.invalid/a", "hash": b"\x00" * 32}, StatusCode.ASSERTION_OUTSIDE_MANIFEST),
    ],
    ids=["no-url", "url-not-a-string", "hash-not-bytes", "unsupported-alg", "absent-from-the-store", "outside"],
)
def test_every_link_failure_reports_its_own_code(signer: Signer, link: CborValue, expected: StatusCode) -> None:
    """C2PA 15.10.3.1 walks the claim's links and gives each failure its own code.

    Each row is a distinct thing going wrong with one hashed-uri-map, and each earns a
    distinct code. Collapsing them -- returning ``assertion.missing`` for a malformed
    link, say -- would tell an operator the store lacks an assertion when the CLAIM is
    what is wrong, and this package treats the code as load-bearing: its own conformance
    vector file states a validator "shall report exactly that code".

    ``unsupported-alg`` is the one worth naming. 15.4.2 lets a hashed-uri-map carry its
    own ``alg``, and 13.1 permits only sha256/384/512 while stating implementations
    "shall not support additional algorithms on an optional basis" -- so a NAMED but
    unpermitted algorithm is not a fallback-to-the-claim case, it is a rejection.
    """
    from c2patxt._extract import extract
    from c2patxt._verify import _link_status

    manifest = extract(mark("Hello world.", signer))
    assert manifest is not None
    assert isinstance(link, dict)

    code, label = _link_status({key: value for key, value in link.items() if isinstance(key, str)}, manifest, {})

    assert code is expected
    assert label is None, "a failing link resolves to no label"


@pytest.mark.parametrize(
    ("hash_data", "expected"),
    [
        (None, StatusCode.CLAIM_HARD_BINDINGS_MISSING),
        ({"exclusions": [{"start": 0, "length": 1}], "alg": "sha256"}, StatusCode.DATA_HASH_MISMATCH),
        ({"alg": "sha256", "hash": b"\x00" * 32}, StatusCode.DATA_HASH_MALFORMED),
        ({"exclusions": "not a list", "alg": "sha256", "hash": b"\x00" * 32}, StatusCode.DATA_HASH_MALFORMED),
    ],
    ids=["no-hard-binding", "no-hash-field", "no-exclusions", "exclusions-not-a-list"],
)
def test_the_hard_binding_reports_each_way_it_can_be_wrong(
    signer: Signer, hash_data: CborValue, expected: StatusCode
) -> None:
    """15.12.1.1 splits two conditions that are easy to conflate: "If the `hash` field is
    not present, then the manifest shall be rejected with a failure code of
    `assertion.dataHash.mismatch`", while a structurally wrong assertion is
    `assertion.dataHash.malformed`.

    ``no-hard-binding`` is 15.10.1.2's other half: a manifest whose store holds no
    ``c2pa.hash.data`` at all binds to nothing, and ``claim.hardBindings.missing`` says
    so rather than reporting a mismatch against a hash that does not exist.

    Driven through ``_binding_status`` with a substituted assertion because these rows
    need a `c2pa.hash.data` payload no producer emits. The required-assertion check does
    NOT mask them in the full path -- a binding assertion that is linked and hash-matched
    satisfies it whatever its payload holds, so ``verify`` reports
    ``claim.hardBindings.missing`` alone.
    """
    import dataclasses

    from c2patxt._extract import extract
    from c2patxt._locate import find_wrappers
    from c2patxt._verify import _binding_status
    from c2patxt.manifest import ASSERTION_HASH_DATA

    marked = mark("Hello world.", signer)
    manifest = extract(marked)
    assert manifest is not None

    assertions = dict(manifest.assertions)
    if hash_data is None:
        del assertions[ASSERTION_HASH_DATA]
    else:
        assertions[ASSERTION_HASH_DATA] = hash_data

    assert _binding_status(marked, dataclasses.replace(manifest, assertions=assertions), find_wrappers(marked)) == (
        expected,
    )


def test_a_naive_verification_time_is_refused_at_construction(signer: Signer) -> None:
    """A validation instant must carry an explicit UTC offset at construction."""
    import datetime

    with pytest.raises(ValueError, match="timezone-aware"):
        VerifyContext(now=datetime.datetime(2026, 6, 1))  # noqa: DTZ001 -- the naive datetime IS the input under test

    aware = VerifyContext(now=datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc))
    assert verify(mark("Hello world.", signer), context=aware).state is Provenance.VALID
    assert verify("no mark here", context=aware).state is Provenance.UNMARKED


def test_a_credential_that_will_not_parse_yields_a_verdict_not_an_exception(
    signing_key: Ed25519PrivateKey,
) -> None:
    """The end-to-end form: attacker-controlled text whose ``x5chain`` carries a
    certificate ``cryptography`` refuses to read.

    An empty ``ExtKeyUsageSyntax`` is legal to build and illegal to parse. Because
    extensions are parsed lazily, the public verifier must translate the failure to
    ``signingCredential.invalid``.
    """

    certificate = build_certificate(signing_key, extended_key_usage=())
    signer = Signer(private_key=signing_key, certificates=(certificate,), allow_nonconformant=True)

    verdict = verify(mark("Hello world.", signer))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()


def test_the_instance_convention_requires_digits_after_the_double_underscore() -> None:
    """C2PA 6.4: "adding a double-underscore and a monotonically increasing INDEX to the
    label."

    ``__x`` and a bare ``__`` are the discriminating cases: both start with the prefix and
    neither is an index. Counting them would reject manifests that are fine, which is the
    over-strictness half of the same rule.
    """
    from c2patxt._verify import _actions_labels
    from c2patxt.manifest import ASSERTION_ACTIONS

    labels = [
        ASSERTION_ACTIONS,
        f"{ASSERTION_ACTIONS}__1",
        f"{ASSERTION_ACTIONS}__22",
        f"{ASSERTION_ACTIONS}__x",
        f"{ASSERTION_ACTIONS}__",
        f"{ASSERTION_ACTIONS}_1",
        f"{ASSERTION_ACTIONS}X",
    ]

    assert _actions_labels(labels) == [ASSERTION_ACTIONS, f"{ASSERTION_ACTIONS}__1", f"{ASSERTION_ACTIONS}__22"]


@pytest.mark.parametrize(
    ("body", "field"),
    [
        (MAGIC + b"\x02" + (4).to_bytes(4, "big") + b"\x00" * 4, MAGIC),
        (MAGIC + b"\x01" + (0xFFFFFF).to_bytes(4, "big") + b"\x00" * 4, MAGIC + b"\x01"),
    ],
    ids=["bad-version", "length-above-the-cap"],
)
def test_the_reported_offset_points_at_the_field_that_failed(body: bytes, field: bytes) -> None:
    """``MarkCorruptError.pos`` is a byte offset into the stored UTF-8 text.

    Each decoded byte costs three UTF-8 bytes below ``0x10`` and four at or above it
    (A.8.3.1), so the exact source-byte offset includes both the visible prefix and the
    encoded wrapper field.
    """
    prefix = "Doc."
    text = prefix + MARKER + _selectors(body)
    encoded = text.encode("utf-8")
    expected = len((prefix + MARKER + _selectors(field)).encode("utf-8"))

    with pytest.raises(MarkCorruptError) as caught:
        locate(text)

    assert caught.value.pos == expected
    assert encoded[caught.value.pos : caught.value.pos + 1] != b"", "the offset must land inside the text"


def test_a_reference_into_an_unimplemented_data_box_is_missing(signer: Signer) -> None:
    """A local ``self#jumbf`` destination is not an optional remote retrieval."""
    from c2patxt._verify import _reference_status

    manifest = extract(mark("Hello world.", signer))
    assert manifest is not None
    cache: dict[tuple[str, str], bytes] = {}

    databox: dict[str, CborValue] = {"url": "self#jumbf=c2pa.databoxes/c2pa.icon", "hash": b"\x00" * 32}
    assert _reference_status(databox, manifest, cache) is StatusCode.HASHED_URI_MISSING

    # The narrowness, asserted rather than described: an assertion URI that names
    # nothing present is still a failure, because that destination we did look for.
    absent: dict[str, CborValue] = {"url": "self#jumbf=c2pa.assertions/c2pa.nonesuch", "hash": b"\x00" * 32}
    assert _reference_status(absent, manifest, cache) is StatusCode.HASHED_URI_MISSING


def test_a_v1_actions_assertion_is_read_not_rejected(signer: Signer) -> None:
    """C2PA names both action assertion labels. 15.10.3.2.3 opens "If the assertion's label is c2pa.actions
    or c2pa.actions.v2"; Table 7 lists them as one row; 5.1 says a deprecated construct
    "can be read, but never written". The producer emits v2 and the reader accepts v1.

    Validation applies the shared ``actions`` array, action name and
    ``digitalSourceType`` rules. The v2-only ``templates`` and ``softwareAgents`` fields
    do not exist in a v1 body.
    """
    from c2patxt._verify import _actions_labels
    from c2patxt.manifest import ASSERTION_ACTIONS, ASSERTION_ACTIONS_V1

    assert ASSERTION_ACTIONS_V1 == "c2pa.actions"
    assert ASSERTION_ACTIONS == "c2pa.actions.v2", "we still EMIT v2 only; 5.1 forbids writing the deprecated form"

    # Both labels are actions assertions, and 6.4's __N convention applies to each.
    order = ["c2pa.hash.data", ASSERTION_ACTIONS_V1, "c2pa.ai-disclosure", f"{ASSERTION_ACTIONS_V1}__1"]
    assert _actions_labels(order) == [ASSERTION_ACTIONS_V1, f"{ASSERTION_ACTIONS_V1}__1"]

    # V1 appears first so claim order differs from grouping labels by version.
    mixed = [ASSERTION_ACTIONS_V1, ASSERTION_ACTIONS]
    assert _actions_labels(mixed) == mixed, "order comes from the claim, not from the label"


def _manifest_store(*children: tuple[str, bytes]) -> bytes:
    """A manifest store carrying exactly the labelled cbor boxes given.

    Built by hand so a box can be OMITTED or given the wrong shape -- neither of which
    `embed` will produce, and both of which a hostile or broken producer can.
    """
    from c2patxt._jumbf import DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import (
        LABEL_CLAIM,
        LABEL_CLAIM_SIGNATURE,
        UUID_CLAIM,
        UUID_CLAIM_SIGNATURE,
        UUID_MANIFEST,
        UUID_MANIFEST_STORE,
    )

    part_uuids = {
        LABEL_CLAIM: UUID_CLAIM,
        LABEL_CLAIM_SIGNATURE: UUID_CLAIM_SIGNATURE,
    }

    manifest = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST, label="urn:c2pa:00000000-0000-4000-8000-000000000001"),
        content=tuple(
            (
                b"jumb",
                serialize_superbox(
                    JumbfBox(
                        description=DescriptionBox(uuid=part_uuids[label], label=label),
                        content=((b"cbor", payload),),
                    )
                )[8:],
            )
            for label, payload in children
        ),
    )
    store = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST_STORE, label="c2pa"),
        content=((b"jumb", serialize_superbox(manifest)[8:]),),
    )
    return serialize_superbox(store)


def test_a_missing_signature_box_reports_its_own_code_not_the_carrier_s() -> None:
    """The wrapper is intact -- correct magic, version 1, a ``manifestLength`` matching
    what is there. What is absent is the signature box, and 15.7 names a code for
    exactly that: ``claimSignature.missing``.
    """
    from c2patxt._cbor import dumps
    from c2patxt._extract import parse_manifest_store

    with pytest.raises(MarkCorruptError) as excinfo:
        parse_manifest_store(_manifest_store(("c2pa.claim.v2", dumps({"alg": "sha256"}))))
    assert excinfo.value.code == StatusCode.CLAIM_SIGNATURE_MISSING


def test_a_claim_that_is_not_a_map_is_malformed_not_a_corrupt_carrier() -> None:
    """C2PA 15.6.2 separates two cases: ``claim.cbor.invalid`` is for bytes that are not
    well-formed CBOR, ``claim.malformed`` for a claim that decoded and is the wrong
    shape. An array where a map belongs is the second -- the CBOR is impeccable and the
    claim is not a claim.
    """
    from c2patxt._cbor import dumps
    from c2patxt._extract import parse_manifest_store

    with pytest.raises(MarkCorruptError) as excinfo:
        parse_manifest_store(_manifest_store(("c2pa.claim.v2", dumps([1, 2, 3])), ("c2pa.signature", dumps(b"sig"))))
    assert excinfo.value.code == StatusCode.CLAIM_MALFORMED


@pytest.mark.parametrize(
    "url",
    [
        "self#jumbf=c2pa.databoxes/c2pa.icon",
        "self#jumbf=c2pa.databoxesEVIL/c2pa.icon",
        "self#jumbf=C2PA.DATABOXES/c2pa.icon",
        "self#jumbf=c2pa.databoxes",
        "self#jumbf=c2pa.databoxes/",
        "self#jumbf=c2pa.assertions/c2pa.nonesuch",
    ],
    ids=["databox", "lookalike-segment", "uppercased", "no-slash", "empty-tail", "absent-assertion"],
)
def test_an_unresolved_local_reference_is_missing(signer: Signer, url: str) -> None:
    from c2patxt._verify import _reference_status

    manifest = extract(mark("Hello world.", signer))
    assert manifest is not None
    cache: dict[tuple[str, str], bytes] = {}
    reference: dict[str, CborValue] = {"url": url, "hash": b"\x00" * 32}

    assert _reference_status(reference, manifest, cache) is StatusCode.HASHED_URI_MISSING


@pytest.mark.parametrize(
    ("url", "resolves"),
    [
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.assertions/c2pa.hash.data", "c2pa.hash.data"),
        # Right arity and manifest, but the middle segment is not the assertion store.
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.databoxes/c2pa.icon", None),
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.signature/x", None),
        # A label may contain no "/" (11.1.4.1.1), which is why the split is unbounded.
        # With a bounded split this resolves to the label "a/b".
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.assertions/a/b", None),
        # An empty tail names no assertion.
        ("self#jumbf=c2pa.assertions/", None),
        # The store-relative form has the same non-empty-label rule.
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.assertions/", None),
        ("self#jumbf=c2pa.assertions/a/b", "a/b"),
    ],
    ids=[
        "store-relative",
        "wrong-segment",
        "signature-segment",
        "store-label-with-slash",
        "empty-tail",
        "store-relative-empty-tail",
        "manifest-relative-slash",
    ],
)
def test_an_assertion_uri_resolves_only_when_every_component_is_right(url: str, resolves: str | None) -> None:
    """8.4.2.1's two forms, checked component by component rather than by arity alone.

    THE MANIFEST-RELATIVE SLASH CASE IS DELIBERATELY PERMISSIVE: that form has no
    segment after the label, so "a/b" is simply the label. 11.1.4.1.1 forbids a "/" in
    a label, and we do not enforce that here -- the lookup then fails to find it. The
    row is present so the asymmetry with the store-relative form is visible.
    """
    from c2patxt._verify import _assertion_label

    assert _assertion_label(url, "urn:c2pa:MANIFEST") == resolves


def test_the_signature_uri_must_name_the_signature_box_not_merely_this_manifest() -> None:
    """15.7's store-relative form, checked at its third component.

    Every existing row varies the arity or the manifest label, so `len(parts)` or
    `parts[0]` answers first and `parts[1] == LABEL_CLAIM_SIGNATURE` is never reached --
    dropping it passed the whole suite. A claim whose `signature` URI points at its own
    CLAIM box, with the right arity and the right manifest, resolved.
    """
    from c2patxt._verify import _signature_uri_resolves

    assert _signature_uri_resolves("self#jumbf=/c2pa/urn:c2pa:M/c2pa.signature", "urn:c2pa:M")
    assert not _signature_uri_resolves("self#jumbf=/c2pa/urn:c2pa:M/c2pa.claim.v2", "urn:c2pa:M")


def test_a_generator_name_that_is_not_a_string_is_malformed() -> None:
    """15.6.2 types `claim_generator_info.name` as a string, and the check was for
    PRESENCE only in every test: `{"version": "1.0"}` -- name absent -- is covered,
    `{"name": 42}` was not, so relaxing `isinstance(..., str)` to `"name" not in ...`
    passed the suite.
    """
    from c2patxt._verify import _claim_malformed

    base: dict[str, CborValue] = {
        "instanceID": "x",
        "signature": "self#jumbf=c2pa.signature",
        "alg": "sha256",
        "created_assertions": [{"url": "self#jumbf=c2pa.assertions/x", "hash": b"\x00"}],
    }
    assert not _claim_malformed({**base, "claim_generator_info": {"name": "c2patxt"}})
    assert _claim_malformed({**base, "claim_generator_info": {"name": 42}})
    assert _claim_malformed({**base, "claim_generator_info": {"version": "1.0"}})
