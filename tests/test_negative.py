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

The rejection half is written as attacks. Each names the attack it defends against,
so a future reader who finds one inconvenient knows what they would be giving up.
"""

from __future__ import annotations

import contextlib

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
from c2patxt._jumbf import UUID_CBOR

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

    Deliberately NOT calling our own encoder, and deliberately NOT importing its
    constants either: these tests need an independent witness, and a test that builds its
    input with the code under test cannot detect a wrong base offset.

    THE CONSTANTS WERE IMPORTED UNTIL 2026-08-05, which made the second half of that
    sentence false. Shifting the whole low plane -- ``VS_LOW_BASE`` 0xFE00 to 0xFE10 with
    ``VS_LOW_MAX`` to match -- keeps ``_LOW_SPAN`` at 16 and the UTF-8 cost model
    unchanged, so encode and decode stay mutually consistent and every call site here
    stayed green against a codec no longer implementing A.8.3.1. The property was held
    elsewhere, by the literals in ``test_constants.py``; this helper was not what held it,
    while its docstring said it was.

    Spelled as literals now, the way ``test_vector_file.py`` and
    ``test_third_party_interop.py`` do -- neither imports anything from ``c2patxt``, and
    they are the model for an independent oracle in this repository.
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


def test_a_declared_length_above_the_cap_is_refused_before_allocation() -> None:
    """ATTACK: a 4 GiB manifestLength as an allocation bomb.

    Refused against MAX_MANIFEST_LENGTH by inspecting the declared value, so no
    attacker-chosen quantity ever reaches an allocator.
    """
    header = MAGIC + b"\x01" + (MAX_MANIFEST_LENGTH + 1).to_bytes(4, "big")

    # THE PAYLOAD MUST EXCEED THE CAP, and the message must be asserted. With only 16
    # payload bytes and a bare pytest.raises, the "declared > available" check answered
    # instead and the cap itself was never exercised -- deleting it left the suite
    # green. Proved by a mutation audit:
    #     PRISTINE: declared manifestLength 2097153 exceeds the 2097152-byte limit
    #     MUTANT:   declared manifestLength 2097153 exceeds the 16 bytes available
    # constants.py calls this "THE MOST IMPORTANT LIMIT HERE"; it now has a test.
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
    """ATTACK: a multi-megabyte selector run as a CPU exhaustion vector.

    THIS TEST USED TO ASSERT NOTHING THAT COULD FAIL. It checked ``MAX_SELECTOR_RUN > 0``
    -- true of any positive constant -- and then put its only behavioural assertion
    inside ``contextlib.suppress``, where BOTH outcomes were declared acceptable.
    Deleting the cap from ``_locate`` entirely, so ``limit = len(text)``, left the whole
    suite green: the run spells no valid magic either way, so ``locate`` returned
    ``None`` with or without it. The docstring named CPU exhaustion as the threat and
    measured nothing.

    NOW IT MEASURES THE WORK, which is the property the cap exists for. A run TEN TIMES
    the cap must not cost materially more than a run at the cap, because everything past
    the cap is never decoded. Without the cap the cost is linear in the attacker's input
    and the ratio grows with the multiplier.

    ASSERTED ON DECODED BYTES, WHICH IS WHAT THE CAP BOUNDS. This was a CPU-time ratio
    (10x the cap must cost under 4x the time), with a 4x allowance for interpreter
    noise because the suite runs under ``-n auto`` and a wall-clock version here was
    already flaky once, five failures in six under load. Bytes are an exact integer and
    need no allowance: the cap says a run stops at ``MAX_SELECTOR_RUN`` bytes, so that
    is the number, and a scan that ignored the cap returns ten times it.

    The bound now lives inside a compiled character class as ``{0,MAX_SELECTOR_RUN}``
    rather than in a Python counter. This test is what proves it survived that move --
    it passed after the rewrite, but it passed by TIMING, which cannot tell a bound
    that holds from one that is merely fast.
    """
    at_cap = MARKER + chr(VS_HIGH_BASE) * MAX_SELECTOR_RUN
    far_past = MARKER + chr(VS_HIGH_BASE) * (MAX_SELECTOR_RUN * 10)
    marker_length = len(MARKER)

    # The run starts one character past the marker, which is where find_wrappers looks.
    for label, text in (("at the cap", at_cap), ("ten times the cap", far_past)):
        decoded, stop = _decode_run(text, marker_length)
        assert len(decoded) == MAX_SELECTOR_RUN, (
            f"{label}: decoded {len(decoded)} bytes, but the cap is {MAX_SELECTOR_RUN}"
        )
        assert stop == marker_length + MAX_SELECTOR_RUN, (
            f"{label}: the run was walked to index {stop}, past the cap at {marker_length + MAX_SELECTOR_RUN}"
        )

    # And the answer itself must still be one of ours: a run this long spells no valid
    # magic number, so "not a mark" and "corrupt" are both correct -- what must not
    # happen is an OOM, a hang, or somebody else's exception type.
    with contextlib.suppress(MarkCorruptError):
        assert locate(far_past) is None


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


def test_two_valid_wrappers_are_reported_as_multiple_not_as_mismatch(signer: Signer) -> None:
    """ATTACK: append a second valid mark so a consumer reads whichever it prefers.

    A.8.2.1 gives quantity "Zero or one"; 15.5.2.1 makes plural stores all invalid.
    The code must be multipleWrappers -- reporting a hash mismatch instead would send
    an investigator looking for a text edit that never happened.
    """
    first = mark("Document one.", signer)
    second = mark("Document two.", signer)
    verdict = verify(first + second[second.index(MARKER) :])

    assert verdict.state is Provenance.INVALID
    assert StatusCode.TEXT_MULTIPLE_WRAPPERS in verdict.codes()


def test_editing_one_character_is_a_hash_mismatch(signer: Signer) -> None:
    """ATTACK: change the meaning of the text, keep the credential.

    One character, because that is the smallest change a hard binding must catch and
    the one most likely to slip past a weaker scheme.
    """
    verdict = verify(mark("Approved: 100 units.", signer).replace("100", "900", 1))
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MISMATCH in verdict.codes()


def test_appending_after_the_wrapper_cannot_extend_the_exclusion(signer: Signer) -> None:
    """ATTACK: exclusion-range extension (RFC-136 9).

    Appending after the mark and hoping the excluded range grows to cover it. It
    cannot: the range lives inside the SIGNED claim, so extending it requires a
    signature the attacker does not have. Leaving it alone means the wrapper is no
    longer a suffix, which the placement rule rejects before the hash is even
    reached -- so the appended bytes have nowhere to hide.
    """
    verdict = verify(mark("The contract is void.", signer) + " Just kidding.")
    assert verdict.state is Provenance.INVALID
    assert StatusCode.DATA_HASH_MALFORMED in verdict.codes()


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

    manifest.py's Claim docstring asserted this was "enforced on read" long before
    anything enforced it. A claim with no instanceID verified happily.
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
    """claim-map-v2 declares ``$generator-info-map``, singular; v1 declared an array.

    We emit c2pa.claim.v2, and we emitted the ARRAY until 2026-08-05. Pinned in both
    directions so the shape cannot drift back.
    """
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
    """ATTACK: copy a label off the wire and append a second box under it.

    THE CHECK THIS REPLACES WAS DECORATIVE, at three separate sites. ``_children``
    and ``_children_with_bytes`` keyed boxes by label into a plain dict, so a
    duplicate silently overwrote its predecessor -- last write wins -- which defeated:

      * the "more than one manifest" count: two manifests sharing a label collapsed
        to one, and an attacker who read the label off the victim's own output got
        their manifest selected with no status code at all;
      * the "every assertion in the store is linked by the claim" guard, since the
        smuggled box vanished from the set being compared;
      * 15.6.1's "only one c2pa.claim.v2 box per manifest" rule.

    Collapsing is also a producer/consumer divergence in its own right: a third-party
    JUMBF reader may take the FIRST box where we took the last, so two conforming
    implementations authenticate different content from identical bytes.

    ``depth`` selects which store gets the duplicate -- 0 is the manifest store, 1 is
    the assertion store one level in -- because the collapse was in shared code and a
    fix at one call site would leave the others open.
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
    with pytest.raises(MarkCorruptError, match="more than one box labelled"):
        parse_manifest_store(forged)


def test_a_claim_whose_cbor_is_invalid_reports_the_cbor_code() -> None:
    """C2PA 15.6.2: "If the content of the claim is not well-formed CBOR, the claim
    shall be rejected with a failure code of claim.cbor.invalid."

    Reported manifest.text.corruptedWrapper until 2026-08-05, which sends an
    investigator hunting selector-run damage that is not there -- the exact failure
    MarkCorruptError's overridable `code` parameter exists to prevent.
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

    from tests.conftest import build_certificate

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


def test_verify_returns_a_verdict_for_an_unsupported_certificate_key_type() -> None:
    """ATTACK: an x5chain leaf whose SubjectPublicKeyInfo names an OID cryptography
    does not implement.

    ``certificate.public_key()`` raises ``cryptography.exceptions.UnsupportedAlgorithm``,
    which is NOT a ValueError, so it escaped the ``except (CoseError, ValueError)``
    around certificate loading. A truncated DER raises ValueError and WAS caught, so
    the surface was narrow -- and real.
    """
    from cryptography.exceptions import UnsupportedAlgorithm

    assert not issubclass(UnsupportedAlgorithm, ValueError), (
        "if this ever becomes a ValueError the guard below is redundant, not wrong"
    )

    from c2patxt import _verify

    assert UnsupportedAlgorithm in _verify.CERTIFICATE_ERRORS


@pytest.mark.parametrize(
    ("exclusions", "why"),
    [
        ([], "an empty list names no wrapper"),
        (
            [{"start": 12, "length": 100}, {"start": 200, "length": 50}],
            "two ranges: A.8 places one contiguous wrapper",
        ),
        ([{"start": True, "length": 100}], "True would pass as 1 and describe a real range"),
        ([{"start": 12, "length": False}], "False would pass as 0"),
        ([{"start": -1, "length": 100}], "a negative offset"),
        ([{"start": 12}], "no length"),
        ([{"length": 100}], "no start"),
        (["not a map"], "a list entry that is not a map"),
        ("not a list", "exclusions is not a list at all"),
    ],
    ids=[
        "empty",
        "two-ranges",
        "bool-start",
        "bool-length",
        "negative",
        "no-length",
        "no-start",
        "not-map",
        "not-list",
    ],
)
def test_a_malformed_exclusion_list_is_refused(exclusions: CborValue, why: str) -> None:
    """``_single_exclusion`` must return None for every shape but exactly one range.

    A mutation audit removed the ``len(raw) != 1`` check and the ``bool``-before-
    ``int`` guard SEPARATELY, and the suite stayed green for both -- while two
    docstrings asserted the rejection as a security property. Prose claiming a rule
    that nothing checks is the same defect class as the ``urn:uuid:`` label that had a
    test defending it.

    The bool cases are the subtle ones: Python's ``True`` IS ``1``, so without the
    explicit guard ``{"start": True}`` describes a real, attacker-chosen range.
    """
    from c2patxt._verify import _single_exclusion

    assert _single_exclusion({"exclusions": exclusions}) is None, why


def test_a_single_well_formed_exclusion_is_accepted() -> None:
    """The positive half. Without it, the test above passes if the function returned
    None unconditionally."""
    from c2patxt._verify import _single_exclusion

    assert _single_exclusion({"exclusions": [{"start": 12, "length": 100}]}) == (12, 100)


@pytest.mark.parametrize("algorithm", ["sha1", "md5", "sha3-256", "", "SHA256"])
def test_an_unsupported_hash_algorithm_is_reported_as_such(signer: Signer, algorithm: str) -> None:
    """C2PA 13.1 permits sha256/384/512 and says implementations "shall not support
    additional algorithms on an optional basis".

    ``algorithm.unsupported`` was never produced by any test -- it appeared only as a
    name-to-string table entry -- so dropping the membership check from
    ``_binding_status`` was invisible. Note ``"SHA256"``: the comparison is
    case-sensitive, and the registry values are lowercase.
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
    assert _binding_status("any text", store, []) is StatusCode.ALGORITHM_UNSUPPORTED


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

    ``ManifestStore.hash_data`` looks up the EXACT label, so a second binding under
    the ``__N`` convention was invisible: the verifier bound against the first and
    ignored the rest. That is the "different consumers read different claims" failure
    this package refuses elsewhere.

    ``near-misses`` matters: ``c2pa.hash.dataX`` and ``c2pa.hash.data_1`` (one
    underscore) are DIFFERENT assertions, not instances, so counting them would reject
    manifests that are fine.
    """
    from c2patxt._verify import _count_hard_bindings

    assert _count_hard_bindings(dict.fromkeys(labels, b"")) == count


#: 18.15's two named values. We emit the first and must accept the second. Written out
#: rather than imported, so this file states the URI independently -- and asserted equal
#: to the shipped constant below, so the two cannot drift apart in silence.
_SOURCE = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
_EMPTY = "http://c2pa.org/digitalsourcetype/empty"


@pytest.mark.parametrize(
    ("payload", "ok"),
    [
        ({"actions": [{"action": "c2pa.created", "digitalSourceType": _SOURCE}]}, True),
        ({"actions": [{"action": "c2pa.opened"}]}, True),
        ({"actions": [{"action": "c2pa.created", "digitalSourceType": _SOURCE}, {"action": "c2pa.edited"}]}, True),
        ({"actions": [{"action": "c2pa.edited"}]}, False),
        ({"actions": []}, False),
        ({"actions": [{"action": "c2pa.created", "digitalSourceType": _SOURCE}, {"action": "c2pa.opened"}]}, False),
        ({"actions": [{"action": "c2pa.created", "digitalSourceType": _SOURCE}, {"action": "c2pa.created"}]}, False),
        ({"actions": [{"action": "c2pa.edited"}, {"action": "c2pa.created", "digitalSourceType": _SOURCE}]}, False),
        ({"actions": [{"action": "c2pa.created"}]}, False),
        ({"actions": [{"action": "c2pa.created", "digitalSourceType": 7}]}, False),
        ({"actions": [{"action": "c2pa.created", "digitalSourceType": _EMPTY}]}, True),
        ({}, False),
        ({"actions": "not a list"}, False),
        ({"actions": ["not a map"]}, False),
        ("not a map at all", False),
        (None, False),
    ],
    ids=[
        "created",
        "opened",
        "created-plus-edited",
        "only-edited",
        "empty",
        "both-created-and-opened",
        "two-created",
        "inception-not-first",
        "created-without-a-source-type",
        "source-type-not-a-string",
        "created-from-nothing",
        "no-actions-field",
        "actions-not-a-list",
        "entry-not-a-map",
        "payload-not-a-map",
        "no-actions-assertion-at-all",
    ],
)
def test_exactly_one_inception_action_is_required(payload: CborValue, ok: bool) -> None:
    """C2PA 15.10.1.2: "Validate that either a c2pa.created or c2pa.opened action is
    contained in exactly one actions assertion."
    18.15.2: "There shall be at least one actions assertion present in the
    created_assertions array of the Claim of a standard C2PA Manifest."

    THIS MATTERS BEYOND CONFORMANCE. The c2pa.created action is where
    ``digitalSourceType = trainedAlgorithmicMedia`` lives -- the field that actually
    says a model generated this. A manifest with no created action, or with the action
    rewritten to c2pa.edited, verified VALID while asserting nothing about machine
    origin.

    THE CODE IS THE SPECIFICATION'S, AND SO IS THE STRICTNESS. 15.10.1.2 names no code
    itself, and an earlier version of this docstring concluded we had adopted one from
    a neighbouring clause by our own judgement. That was wrong. 15.10.3.2.3 states the
    rule and the code outright:

    > "For each action in the actions list: If the action field is either
    > `c2pa.created` or `c2pa.opened`, then the claim shall be rejected with a failure
    > code of `assertion.action.malformed` unless all of the following are true: the
    > assertion is the first actions assertion in the created_assertions or
    > gathered_assertions array (of a v2 claim), or the first actions assertion in the
    > assertions array of a v1 claim, and **the action is the first element in the
    > actions array in this assertion**."

    So "both created and opened" and "two created" are rejections because the second
    inception action cannot be first -- not because we decided an asset has one
    history. And ``inception-not-first`` is the case that reading exposed: an actions
    array beginning ``c2pa.edited`` and only then ``c2pa.created`` used to pass, and the
    clause rejects it. An asset cannot be edited before it exists.

    The per-assertion half of the rule lives here; the "first actions assertion" half
    needs the claim's link order and is tested in
    ``test_only_the_first_actions_assertion_may_carry_the_inception``.

    THE SOURCE TYPE IS PART OF THE SAME RULE, from 18.15: "For all assets, a
    corresponding `digitalSourceType` field, with an appropriate value, **shall** be
    recorded with the `c2pa.created` action, to indicate the nature of the asset at its
    inception." Without it the mark says a machine made this in its LABEL and says
    nothing in its CONTENT -- and ``manifest.py`` calls that field "the single fact the
    mark exists to carry" while nothing read it.

    ``c2pa.opened`` is exempt, and the exemption is the clause's own: "No
    `digitalSourceType` field is required in conjunction with a `c2pa.opened` action."
    That row is the control against reading the rule too widely.

    THE VALUE IS NOT CONSTRAINED, only its presence and type. 18.15 says "with an
    appropriate value" and names only the empty-content case explicitly; the vocabulary
    is IPTC's plus c2pa.org's, and requiring membership of a list we vendor would reject
    a conforming producer using a term we have not heard of. ``created-from-nothing``
    pins that: the empty-content value is one we never emit and must accept.

    THE LAST TWO ROWS ARE THE OPENING NARROWING, added after coverage showed that line
    was never executed. Everything here is attacker-controlled CBOR and the function
    begins by refusing anything that is not a map -- and ``None`` is what the caller
    actually passes when the assertion decoded to nothing at all, which since the
    embedded-data change is a state a real store can be in.
    """
    from c2patxt._verify import _has_single_inception_action

    assert _has_single_inception_action(payload) is ok


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

    Four of the five branches in ``_link_status`` had never been EXECUTED -- coverage,
    not mutation, is what found that, and it is the sharper tool here: a mutation on a
    line no test reaches always survives, so mutation testing can report these but never
    diagnose them.

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
    """Three branches of ``_binding_status`` had never been executed, including the one
    that carries #82's whole point.

    15.12.1.1 splits two conditions that are easy to conflate: "If the `hash` field is
    not present, then the manifest shall be rejected with a failure code of
    `assertion.dataHash.mismatch`", while a structurally wrong assertion is
    `assertion.dataHash.malformed`. That split was implemented and then observable ONLY
    inside ``_expected_digest`` -- no input reached ``_binding_status`` with a hash-less
    binding, so the distinction never appeared in a status.

    ``no-hard-binding`` is 15.10.1.2's other half: a manifest whose store holds no
    ``c2pa.hash.data`` at all binds to nothing, and ``claim.hardBindings.missing`` says
    so rather than reporting a mismatch against a hash that does not exist.

    Driven through ``_binding_status`` with a substituted assertion rather than through
    ``verify``: the required-assertion check runs first in the full path and would answer
    ``assertion.missing`` before any of these could be reached, which is correct
    behaviour and would make every row here test the same thing.
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

    assert (
        _binding_status(marked, dataclasses.replace(manifest, assertions=assertions), find_wrappers(marked)) is expected
    )


def test_an_exclusion_that_splits_a_code_point_is_malformed_not_a_crash(signer: Signer) -> None:
    """ATTACK: an exclusion range whose boundary falls INSIDE a multi-byte character.

    The binding removes the excluded byte range from the AS-STORED bytes and then decodes
    what is left (15.12.1.3.1 steps 5-7), so a range that splits a code point leaves a
    fragment that is not valid UTF-8. That must be a status, not a ``UnicodeDecodeError``
    escaping ``verify`` -- which promises never to raise.

    DRIVEN AT ``_compare_digest``, WHICH IS THE UNIT THAT OWNS THE BEHAVIOUR, and the
    first version of this test did not. It called ``_binding_status`` with a splitting
    range, asserted ``assertion.dataHash.malformed``, and PASSED -- from a different
    branch. The exclusion must equal a located wrapper span before the hash is ever
    computed, so the span check answered first and returned the same code. Same
    assertion, same result, wrong reason: precisely the defect this suite has been
    hunting all day, committed while hunting it.

    THE BRANCH IS UNREACHABLE THROUGH ``_binding_status`` TODAY, and is kept anyway.
    Located spans are code-point aligned by construction -- a wrapper begins at U+FEFF
    and runs over whole selectors -- so no ``(start, length)`` that passes the membership
    test can split a character. It is defence in depth against a future change to the
    span logic, and the difference it protects is between a status and an exception
    escaping a function documented never to raise. That is worth four lines; the
    unreachable branch removed from ``_actions_status`` was worth none, because its outer
    guard already returned the identical code.
    """
    from c2patxt._verify import _compare_digest

    text = "Héllo"
    encoded = text.encode("utf-8")
    assert len(encoded) == 6, "é is two bytes, so byte 2 is inside it"

    # Start one byte into "é", so removing the range leaves "H" + a lone continuation.
    status = _compare_digest(encoded, "sha256", 2, 3, b"\x00" * 32)

    assert status is StatusCode.DATA_HASH_MALFORMED


@pytest.mark.parametrize(
    ("claim_generator_info", "actions"),
    [
        ("not a map", {"actions": []}),
        ({"name": "x", "icon": "not a map"}, {"actions": []}),
        ({"name": "x"}, {"actions": [], "templates": "not a list"}),
        ({"name": "x"}, {"actions": [], "softwareAgents": {"not": "a list"}}),
    ],
    ids=["generator-not-a-map", "icon-not-a-map", "templates-not-a-list", "softwareAgents-not-a-list"],
)
def test_reference_collection_narrows_every_level(claim_generator_info: CborValue, actions: CborValue) -> None:
    """The reference collectors walk attacker-controlled CBOR and must find nothing
    rather than raise when a level is the wrong shape.

    ``_claim_references``, ``_generator_icon`` and ``_as_list`` each open with a type
    guard, and coverage showed three of those guards had never executed -- every existing
    test hands them well-formed maps and lists. A ``TypeError`` escaping here would reach
    ``verify``, which promises never to raise, from input an attacker fully controls.

    THAT SENTENCE WAS RETRACTED ONCE, AS UNSUPPORTED, AND IT SHOULD NOT HAVE BEEN.
    Three of the four rows below are reachable through the PUBLIC ``verify()`` -- an
    actions assertion carrying ``softwareAgent = {"icon": "not a map"}``, or
    ``softwareAgents = 42``, or a non-list ``templates`` -- and narrowing either guard
    makes ``AttributeError: 'str' object has no attribute 'items'`` and
    ``TypeError: Value after * must be an iterable`` escape ``verify()`` outright.
    ``generator-not-a-map`` is the one row that cannot arrive that way, and the reason
    is ``_claim_malformed`` (15.6.2), NOT the CBOR decoder -- the decoder is perfectly
    happy with ``{"claim_generator_info": "not a map"}``.

    Asserting an EMPTY result rather than a rejection is the point: a malformed generator
    info or a non-list ``templates`` means there are no references to check, not that the
    manifest is invalid. 15.6.2 already rejects a claim whose ``claim_generator_info`` is
    not a map, and rejecting again here for a different reason would report the wrong one.
    """
    from c2patxt._verify import _action_references, _claim_references

    assert _claim_references({"claim_generator_info": claim_generator_info}) == []
    assert _action_references(actions) == []


def test_a_naive_verification_time_is_refused_at_construction(signer: Signer) -> None:
    """``verify`` promises never to raise for absent, corrupt or invalid marks. A naive
    ``VerifyContext.now`` broke that promise for VALID marks and only for those.

    Reproduced before the fix, with ``now=datetime(2026, 6, 1)`` and no ``tzinfo``:

        unmarked text -> Verdict UNMARKED
        corrupt mark  -> Verdict INVALID
        VALID mark    -> TypeError: can't compare offset-naive and offset-aware datetimes

    THE IDENTICAL DEFECT WAS ALREADY FIXED IN THE FIELD BESIDE IT, and ``anchors_pem``'s
    docstring says so verbatim: resolving it lazily "put the failure on the
    signature-valid path ONLY: unmarked and invalid text sailed through while the first
    genuinely good document raised. That asymmetry survives every staging test built on
    unmarked input." ``__post_init__`` existed and validated one field of two.

    REFUSED RATHER THAN ASSUMED UTC. Assuming would make the verdict depend on an
    ambiguity the caller did not resolve, in the value that decides whether a credential
    was live at validation time. A caller error belongs at construction, where it cannot
    be missed.

    The three rows assert the fix at the point it now happens -- the context cannot be
    built at all -- which is why none of them calls ``verify``.
    """
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

    An empty ``ExtKeyUsageSyntax`` is legal to build and illegal to parse, and because
    extensions are parsed lazily it poisons the entire extension set. Before the fix this
    raised ``ValueError`` out of ``verify()`` -- reproduced -- which breaks the promise
    every other test in this file relies on: the right failure, and never a crash.
    """
    from tests.conftest import build_certificate

    certificate = build_certificate(signing_key, extended_key_usage=())
    signer = Signer(private_key=signing_key, certificates=(certificate,), allow_nonconformant=True)

    verdict = verify(mark("Hello world.", signer))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()


def test_the_instance_convention_requires_digits_after_the_double_underscore() -> None:
    """C2PA 6.4: "adding a double-underscore and a monotonically increasing INDEX to the
    label."

    ``_label_instances``' own docstring names ``c2pa.metadata_1`` as the thing that must
    NOT count, and deleting the ``.isdigit()`` guard survived the whole suite. The guard
    now sits behind THREE rules -- hard bindings, actions, and the AI disclosure -- so
    consolidating the grammar into one helper grew its blast radius while nothing held it.

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


def test_json_ld_decoding_needs_the_dot_before_metadata() -> None:
    """``_json_ld_assertion`` scopes on ``label.endswith(".metadata")`` -- 18.17.2's own
    naming rule, where ``.metadata`` is a label SUFFIX under an entity prefix.

    Dropping the dot survived the whole suite, because the scoping test uses
    ``c2patxt.notes``, which misses by a mile. ``c2pa.xmetadata`` is the string that
    separates the two readings: it ends with ``metadata`` and is not a metadata
    assertion.
    """
    from c2patxt import _jumbf
    from c2patxt._extract import _json_ld_assertion
    from c2patxt._jumbf import DescriptionBox, JumbfBox

    def box(label: str) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=_jumbf.UUID_CBOR, label=label, requestable=True),
            content=((b"json", b'{"dc:format": "text/plain"}'),),
        )

    assert _json_ld_assertion(box("c2pa.metadata"), "c2pa.metadata") is not None
    assert _json_ld_assertion(box("c2pa.xmetadata"), "c2pa.xmetadata") is None


@pytest.mark.parametrize(
    ("body", "field"),
    [
        (MAGIC + b"\x02" + (4).to_bytes(4, "big") + b"\x00" * 4, MAGIC),
        (MAGIC + b"\x01" + (0xFFFFFF).to_bytes(4, "big") + b"\x00" * 4, MAGIC + b"\x01"),
    ],
    ids=["bad-version", "length-above-the-cap"],
)
def test_the_reported_offset_points_at_the_field_that_failed(body: bytes, field: bytes) -> None:
    """``MarkCorruptError.pos`` is documented as a byte offset into the as-stored text.
    It was not: three raise sites mixed units.

    ``parse_wrapper_body`` receives the DECODED body and the document byte offset of its
    start, and built the position as ``offset + len(MAGIC)`` — adding a *decoded* index
    to a *document* offset. ``MAGIC`` is 8 decoded bytes and **31** UTF-8 bytes once
    encoded as variation selectors, so the reported position landed inside the magic
    number rather than at the field that failed. Measured before the fix: a bad version
    reported byte 15, where the version field is at byte 38.

    Each decoded byte costs three UTF-8 bytes below ``0x10`` and four at or above it
    (A.8.3.1), so the true offset is computable exactly rather than approximable — which
    is what makes this a defect rather than a limitation.

    The prefix is deliberately non-empty and non-ASCII-free so the test would catch an
    implementation that forgot the text before the marker.
    """
    prefix = "Doc."
    text = prefix + MARKER + _selectors(body)
    encoded = text.encode("utf-8")
    expected = len((prefix + MARKER + _selectors(field)).encode("utf-8"))

    with pytest.raises(MarkCorruptError) as caught:
        locate(text)

    assert caught.value.pos == expected
    assert encoded[caught.value.pos : caught.value.pos + 1] != b"", "the offset must land inside the text"


def test_a_reference_into_a_store_section_we_do_not_implement_does_not_fail_the_claim(signer: Signer) -> None:
    """A generator icon in a DATA BOX rejected the whole claim.

    10.2.3.2 says "Manifest Consumers SHOULD ALSO SUPPORT the data box approach
    recommended by earlier versions of this specification". We do not, and declining a
    SHOULD is legitimate. What is not legitimate is turning that decision into a
    rejection: `self#jumbf=c2pa.databoxes/c2pa.icon` starts with the self#jumbf prefix,
    so it reached `_assertion_label`, which knows only `c2pa.assertions`, returned None,
    and became hashedURI.missing -- and 15.10.3.3 makes that reject the CLAIM.

    THE ESCALATION IS THE DEFECT, NOT THE MISSING FEATURE. This package already passes
    over a reference it chooses not to follow: an external `hashed_ext_uri` returns None
    on the same authority, because the clause scopes external work to resources "the
    validator chooses to retrieve". A data box is the same category -- a destination we
    decline to resolve -- and must be treated the same way.

    NARROW ON PURPOSE. Only a URI naming a store section we do not implement passes
    over. `c2pa.assertions/<label>` where the label is genuinely absent is still
    hashedURI.missing, because there we DID look and the destination was not there.
    """
    from c2patxt._verify import _reference_status

    manifest = extract(mark("Hello world.", signer))
    assert manifest is not None
    cache: dict[tuple[str, str], bytes] = {}

    databox: dict[str, CborValue] = {"url": "self#jumbf=c2pa.databoxes/c2pa.icon", "hash": b"\x00" * 32}
    assert _reference_status(databox, manifest, cache) is None, (
        "a data-box reference must be passed over, not turned into a claim rejection"
    )

    # The narrowness, asserted rather than described: an assertion URI that names
    # nothing present is still a failure, because that destination we did look for.
    absent: dict[str, CborValue] = {"url": "self#jumbf=c2pa.assertions/c2pa.nonesuch", "hash": b"\x00" * 32}
    assert _reference_status(absent, manifest, cache) is StatusCode.HASHED_URI_MISSING


def test_a_v1_actions_assertion_is_read_not_rejected(signer: Signer) -> None:
    """``c2pa.actions`` (v1) reported assertion.missing, naming the wrong condition.

    ``ASSERTION_ACTIONS`` is ``c2pa.actions.v2`` and was the only label the required-
    assertion test and ``_actions_labels`` knew, so a v1 manifest was rejected -- and
    rejected as MISSING an actions assertion it plainly had and linked.

    Every clause names both. 15.10.3.2.3 opens "If the assertion's label is c2pa.actions
    or c2pa.actions.v2"; Table 7 lists them as one row; 5.1 says a deprecated construct
    "can be read, but never written". We emit v2 only and that stays -- reading v1 is
    the other half of the same rule.

    HOW FAR THE ACCEPTANCE GOES, because accepting the label while applying v2 rules to
    a v1 body would be worse than refusing: the rules applied to a v1 assertion are the
    ones whose shape v1 shares -- the ``actions`` array, each entry's ``action`` name,
    and ``digitalSourceType``. The v2-only fields are ``templates`` and the plural
    ``softwareAgents``; a v1 body simply carries neither, so the reference walk finds
    nothing to follow rather than being told to skip.
    """
    from c2patxt._verify import _actions_labels
    from c2patxt.manifest import ASSERTION_ACTIONS, ASSERTION_ACTIONS_V1

    assert ASSERTION_ACTIONS_V1 == "c2pa.actions"
    assert ASSERTION_ACTIONS == "c2pa.actions.v2", "we still EMIT v2 only; 5.1 forbids writing the deprecated form"

    # Both labels are actions assertions, and 6.4's __N convention applies to each.
    order = ["c2pa.hash.data", ASSERTION_ACTIONS_V1, "c2pa.ai-disclosure", f"{ASSERTION_ACTIONS_V1}__1"]
    assert _actions_labels(order) == [ASSERTION_ACTIONS_V1, f"{ASSERTION_ACTIONS_V1}__1"]

    # V1 FIRST, and that is the whole point of the case. `[v2, v1]` is the ONE input on
    # which the correct implementation and the naive concatenation
    # `_label_instances(V2, o) + _label_instances(V1, o)` agree, so guarding with it
    # left the documented bug alive: a mutation to concatenation passed the whole suite.
    # Since "first actions assertion" decides assertion.action.malformed, that is
    # 15.10.3.2.3's position rule going unchecked.
    mixed = [ASSERTION_ACTIONS_V1, ASSERTION_ACTIONS]
    assert _actions_labels(mixed) == mixed, "order comes from the claim, not from the label"


def _manifest_store(*children: tuple[str, bytes]) -> bytes:
    """A manifest store carrying exactly the labelled cbor boxes given.

    Built by hand so a box can be OMITTED or given the wrong shape -- neither of which
    `embed` will produce, and both of which a hostile or broken producer can.
    """
    from c2patxt._jumbf import DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import UUID_MANIFEST, UUID_MANIFEST_STORE

    manifest = JumbfBox(
        description=DescriptionBox(uuid=UUID_MANIFEST, label="urn:c2pa:00000000-0000-4000-8000-000000000001"),
        content=tuple(
            (
                b"jumb",
                serialize_superbox(
                    JumbfBox(
                        description=DescriptionBox(uuid=UUID_CBOR, label=label, requestable=True),
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
    """A manifest with no ``c2pa.signature`` box reported
    ``manifest.text.corruptedWrapper``.

    The wrapper is intact -- correct magic, version 1, a ``manifestLength`` matching
    what is there. What is absent is the signature box, and 15.7 names a code for
    exactly that: ``claimSignature.missing``. Reporting the carrier's code sends an
    investigator hunting selector-run damage that is not present, the same misdirection
    ``claim.cbor.invalid`` was separated out to avoid.
    """
    from c2patxt._cbor import dumps
    from c2patxt._extract import parse_manifest_store

    with pytest.raises(MarkCorruptError) as excinfo:
        parse_manifest_store(_manifest_store(("c2pa.claim.v2", dumps({"alg": "sha256"}))))
    assert excinfo.value.code == StatusCode.CLAIM_SIGNATURE_MISSING


def test_a_claim_that_is_not_a_map_is_malformed_not_a_corrupt_carrier() -> None:
    """A claim decoding to something other than a map reported the carrier's code.

    15.6.2 separates the two: ``claim.cbor.invalid`` is for bytes that are not
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
    ("url", "passed_over"),
    [
        ("self#jumbf=c2pa.databoxes/c2pa.icon", True),
        # The trailing "/" in the prefix is what stops a lookalike segment matching.
        ("self#jumbf=c2pa.databoxesEVIL/c2pa.icon", False),
        ("self#jumbf=C2PA.DATABOXES/c2pa.icon", False),
        ("self#jumbf=c2pa.databoxes", False),
        # Names no destination, so it is not a reference we DECLINED -- it is one that
        # resolves to nothing, which is what hashedURI.missing is for.
        ("self#jumbf=c2pa.databoxes/", False),
        ("self#jumbf=c2pa.assertions/c2pa.nonesuch", False),
    ],
    ids=["databox", "lookalike-segment", "uppercased", "no-slash", "empty-tail", "absent-assertion"],
)
def test_only_a_real_data_box_destination_is_passed_over(signer: Signer, url: str, passed_over: bool) -> None:
    """The data-box pass-over must be exactly as wide as the thing it excuses.

    ``_reference_status`` returns None for a destination we decline to resolve, which
    is legitimate for a data box -- 10.2.3.2 makes support a SHOULD -- and is NOT
    legitimate for anything else. Two mutations that widened it, ``_DATA_BOX_SEGMENT in
    url`` and "any self#jumbf that is not an assertion", both left the whole suite
    green, so the shape of this prefix was asserted nowhere.

    The empty-tail case is the one that was actually wrong: it was passed over, where
    the sibling ``_assertion_label`` deliberately does ``return label or None`` so an
    empty label fails.
    """
    from c2patxt._verify import _reference_status

    manifest = extract(mark("Hello world.", signer))
    assert manifest is not None
    cache: dict[tuple[str, str], bytes] = {}
    reference: dict[str, CborValue] = {"url": url, "hash": b"\x00" * 32}

    status = _reference_status(reference, manifest, cache)
    if passed_over:
        assert status is None, f"{url} should be passed over as a data box"
    else:
        assert status is StatusCode.HASHED_URI_MISSING, f"{url} must not be mistaken for a data box"


#: Attacker CBOR of the wrong shape, and the answer each guard must give. Typed
#: explicitly because pyright cannot infer a useful element type for a heterogeneous
#: parametrize table, and an unannotated one fails strict mode rather than the test.
_NARROWING_CASES: list[tuple[str, CborValue, object]] = [
    ("_action_references", "not a dict", []),
    ("_action_references", 42, []),
    ("_contains_inception", "not a dict", False),
    ("_contains_inception", {"actions": "not a list"}, False),
    ("_contains_inception", {"actions": [{"action": "c2pa.edited"}]}, False),
    ("_contains_inception", {"actions": ["not a dict"]}, False),
    ("_hashed_uri_list", "not a list", None),
    ("_hashed_uri_list", [], None),
    ("_hashed_uri_list", ["not a dict"], None),
    # A non-text key is DROPPED, not rejected: the entry survives with its text keys
    # only, so an entry of nothing but integer keys becomes {} and then fails later for
    # having no "url". CBOR permits int and bytes keys; a hashed-uri-map uses text ones,
    # and a non-text key is not addressable by name.
    ("_hashed_uri_list", [{1: "an integer key"}], [{}]),
]


@pytest.mark.parametrize(("helper", "payload", "expected"), _NARROWING_CASES)
def test_attacker_cbor_of_the_wrong_shape_narrows_rather_than_raising(
    helper: str, payload: object, expected: object
) -> None:
    """Every one of these lines exists because the value is ATTACKER-CONTROLLED CBOR,
    and none of them was executed by any test.

    A decoded manifest is arbitrary CBOR until the signature verifies, so each level of
    these readers narrows explicitly rather than trusting the shape. The narrowing is
    the security property; an unexecuted narrowing branch is a security property nobody
    has run. Coverage counts execution, not attribution, so these sat at "defensive"
    without anyone confirming they defend.

    DRIVEN AT THE HELPER, not through verify(). Reaching them end to end would mean
    building a store whose signature covers a deliberately malformed field, which tests
    the store builder as much as the guard; the guards own these answers.
    """
    import c2patxt._verify as verify_module

    function = getattr(verify_module, helper)
    assert function(payload) == expected


def test_a_chain_with_no_certificate_is_reported_not_indexed() -> None:
    """An empty ``x5chain`` reached ``chain[0]`` before this guard existed.

    14.2 requires the chain to carry the leaf. An attacker supplying an empty array
    gets a verdict, not an IndexError out of ``verify()`` -- which is the one thing
    hostile input must never produce.
    """
    from c2patxt._verify import _accept_credential

    result = _accept_credential([])
    assert isinstance(result, tuple)
    code, explanation = result
    assert code is StatusCode.SIGNING_CREDENTIAL_INVALID
    assert "carried no certificate" in explanation


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ([1, "two", 3.5], [1, "two", 3.5]),
        ([[1], {"a": 2}], [[1], {"a": 2}]),
        (object, "<class 'object'>"),
    ],
    ids=["flat-list", "nested", "unrepresentable"],
)
def test_json_values_cross_into_cbor_by_narrowing_not_by_trust(value: object, expected: object) -> None:
    """``_as_cbor_value`` is the ONE ``Any`` boundary in this package.

    ``json.loads`` is typed as returning ``Any``, so every element has to be narrowed at
    RUNTIME rather than asserted with a cast -- which is banned repo-wide precisely
    because it asserts a type instead of checking one. The list branch and the final
    fallthrough had never run.

    The fallthrough returns ``repr`` rather than dropping the value, so a consumer sees
    that something was there. ``json`` cannot currently produce a value that reaches it;
    it is narrowed rather than trusted anyway.
    """
    from c2patxt._extract import _as_cbor_value

    assert _as_cbor_value(value) == expected


def test_a_claim_whose_created_assertions_is_not_an_array_is_rejected() -> None:
    """``_claim_links`` returns None when ``created_assertions`` is not a usable array.

    18.2's CDDL types it ``[1* $hashed-uri-map]``, so a scalar, an empty array or an
    array of non-maps is not one. Reached with a store whose claim carries the wrong
    shape -- the branch existed for attacker CBOR and had never run.
    """
    from c2patxt._verify import _assertion_links

    malformed: list[CborValue] = ["not an array", [], [42], {"not": "an array"}]
    for created in malformed:
        claim: dict[str, CborValue] = {"created_assertions": created}
        assert _assertion_links(claim) is None, f"{created!r} is not a hashed-uri array"

    ok: CborValue = [{"url": "self#jumbf=c2pa.assertions/x", "hash": b"\x00"}]
    assert _assertion_links({"created_assertions": ok}) == (ok, [])
    # gathered_assertions present and malformed fails the whole read, not just itself.
    assert _assertion_links({"created_assertions": ok, "gathered_assertions": "no"}) is None


def test_a_template_that_is_not_a_map_is_skipped_not_applied() -> None:
    """18.15.6.1's overlay reads templates from attacker CBOR.

    A template that is not a map carries no fields to overlay, so it is skipped. It
    must not raise, and it must not stop later templates being applied -- which is what
    the `continue` is for, and nothing had executed it.
    """
    from c2patxt._verify import _overlaid_action

    action: dict[int | str | bytes, CborValue] = {"action": "c2pa.created"}
    template: CborValue = {"action": "c2pa.created", "digitalSourceType": "from-template"}
    templates: list[CborValue] = ["not a map", 42, template]

    overlaid = _overlaid_action(action, templates)
    assert overlaid["digitalSourceType"] == "from-template", "a later valid template must still apply"


def test_a_leaf_whose_key_algorithm_cannot_be_read_is_a_verdict_not_an_exception() -> None:
    """``chain[0].public_key()`` raises for an SPKI algorithm ``cryptography`` does not
    implement, and the certificate is attacker-supplied.

    ``UnsupportedAlgorithm`` is NOT a ValueError, which is why it once escaped
    ``verify()`` entirely: a plain ``except ValueError`` did not catch it. It must be a
    verdict.
    """
    from cryptography.exceptions import UnsupportedAlgorithm

    from c2patxt._verify import _accept_credential

    # A REAL certificate, with only public_key() replaced: the profile check runs first
    # and reads extensions, so a bare stand-in fails earlier than the branch under test.
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    real = build_certificate(key)

    class Unreadable:
        """The real certificate, except that its key cannot be read."""

        def __init__(self, wrapped: object) -> None:
            self._wrapped = wrapped

        def __getattr__(self, name: str) -> object:
            return getattr(self._wrapped, name)

        def public_key(self) -> object:
            raise UnsupportedAlgorithm("unknown SPKI OID")

    result = _accept_credential([Unreadable(real)])  # pyright: ignore[reportArgumentType] -- a stand-in for a hostile certificate
    assert isinstance(result, tuple)
    code, explanation = result
    assert code is StatusCode.SIGNING_CREDENTIAL_INVALID
    assert "not one we can read" in explanation


def test_an_ecdsa_leaf_is_refused_and_the_message_blames_us_not_the_specification() -> None:
    """This package signs and verifies Ed25519 ONLY, and 13.2.1's list is wider.

    13.2.1 permits ES256/384/512, PS256/384/512 and EdDSA -- with "Ed25519 instance
    only. No other EdDSA instances are allowed" scoped WITHIN EdDSA. So refusing a
    conforming ES256 leaf is OUR narrowing, recorded as deviation 11, and the message
    has to say so: telling a caller with an ECDSA leaf that the specification forbids it
    would be false and would send them to the wrong document.

    The branch had never executed -- every certificate in the suite is Ed25519 -- so the
    one message in the package that exists to avoid misdirecting a reader was itself
    unread.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    from c2patxt._verify import _accept_credential

    key = ec.generate_private_key(ec.SECP256R1())
    leaf = build_certificate(key)  # pyright: ignore[reportArgumentType] -- an EC key is a valid issuer key

    result = _accept_credential([leaf])
    assert isinstance(result, tuple)
    code, explanation = result
    assert code is StatusCode.SIGNING_CREDENTIAL_INVALID
    assert "Ed25519 only" in explanation
    assert "narrower than C2PA 13.2.1" in explanation, "the message must say the restriction is ours"


def test_a_forged_ecdsa_x5chain_reaches_verify_as_an_invalid_credential() -> None:
    """The end-to-end half of the test above, and it needs a FORGED store to exist.

    ``_accept_credential`` returning the right tuple is not the whole property. What an
    integrator sees is a verdict, and the unit test cannot say that ``_check_signature``
    maps that tuple to ``signingCredential.invalid`` AND to ``Provenance.INVALID``
    rather than letting it fall through to ``claimSignature.mismatch`` -- which is where
    an unreadable key would otherwise land, since the signature cannot verify either.

    NO ROUTE THROUGH ``Signer``: it refuses an ECDSA leaf at construction, with the same
    message. So the document has to be built by replacing the claim-signature box with a
    COSE_Sign1 whose protected header carries an ECDSA leaf and 64 junk signature bytes.
    That is also what an attacker would have: they cannot make our Signer emit this.

    The hard binding fails too, because the forged store is a different length and the
    claim's exclusion no longer matches. That is expected and is not what this asserts;
    the credential check is reached first and reports on its own account.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding

    from c2patxt import _cbor, _jumbf, embed
    from c2patxt._extract import _reparse
    from c2patxt._jumbf import JumbfBox, parse_superbox
    from c2patxt._locate import payload_at
    from c2patxt._selectors import build_wrapper
    from c2patxt.manifest import LABEL_CLAIM_SIGNATURE
    from c2patxt.signing import COSE_ALG_EDDSA, Signer
    from tests.conftest import DISCLOSURE

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    marked = embed("Hello world.", Signer(private_key=key, certificates=(build_certificate(key),)), DISCLOSURE)
    raw = payload_at(marked)
    assert raw is not None

    ec_leaf = build_certificate(ec.generate_private_key(ec.SECP256R1()))  # pyright: ignore[reportArgumentType] -- an EC key is a valid issuer key
    protected = _cbor.dumps({1: COSE_ALG_EDDSA, 33: ec_leaf.public_bytes(Encoding.DER)})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))

    original, _ = parse_superbox(raw)
    manifest, _ = _reparse(original.content[0][1])
    rebuilt: list[tuple[bytes, bytes]] = []
    for tbox, payload in manifest.content:
        child, _ = _reparse(payload)
        if child.description.label == LABEL_CLAIM_SIGNATURE:
            child = JumbfBox(description=child.description, content=((b"cbor", forged),))
        rebuilt.append((tbox, _jumbf.serialize_superbox(child)[8:]))
    inner = _jumbf.serialize_superbox(JumbfBox(description=manifest.description, content=tuple(rebuilt)))[8:]
    store = _jumbf.serialize_superbox(
        JumbfBox(description=original.description, content=((_jumbf.TBOX_SUPERBOX, inner),))
    )

    verdict = verify(marked[: marked.index(MARKER)] + build_wrapper(store))
    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes()
    assert StatusCode.CLAIM_SIGNATURE_MISMATCH not in verdict.codes(), (
        "the credential is what failed, not the signature"
    )


@pytest.mark.parametrize(
    ("label", "is_metadata"),
    [
        ("c2pa.metadata", True),
        ("c2pa.metadata__1", True),
        ("c2pa.metadata__22", True),
        ("c2pa.xmetadata", False),
        ("c2pa.metadata__x", False),
        ("c2pa.metadata_1", False),
    ],
)
def test_a_numbered_metadata_instance_is_still_a_metadata_assertion(label: str, is_metadata: bool) -> None:
    """``c2pa.metadata__1`` was not recognised as JSON-LD.

    ``_json_ld_assertion`` scoped on ``label.endswith(".metadata")``, which 6.4's
    ``__N`` convention defeats: a second metadata assertion lands in
    ``assertion_bytes`` but never in ``assertions``, so a store carrying two metadata
    assertions with CONFLICTING ``dc:format`` verifies VALID while a consumer reading
    ``.assertions`` sees only one of them -- and ``dc:format`` is the field the text
    conformance rubric's ``text:is_text_asset`` check reads.

    The identical ``__N`` gap the AI disclosure had. ``_label_instances`` exists
    because of that one; the grammar is the same here -- a double underscore followed
    by DIGITS, so ``__x`` and ``_1`` are different assertions rather than instances.
    """
    from c2patxt._extract import _json_ld_assertion
    from c2patxt._jumbf import UUID_CBOR, DescriptionBox, JumbfBox

    box = JumbfBox(
        description=DescriptionBox(uuid=UUID_CBOR, label=label, requestable=True),
        content=((b"json", b'{"dc:format": "text/plain"}'),),
    )
    assert (_json_ld_assertion(box, label) is not None) is is_metadata


@pytest.mark.parametrize(
    ("url", "resolves"),
    [
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.assertions/c2pa.hash.data", "c2pa.hash.data"),
        # RIGHT arity, RIGHT manifest, WRONG middle segment. Every existing row varies
        # the arity or the manifest label, so `len(parts)` or `parts[0]` answers first
        # and the segment test is never reached -- dropping it entirely passed the suite.
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.databoxes/c2pa.icon", None),
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.signature/x", None),
        # A label may contain no "/" (11.1.4.1.1), which is why the split is unbounded.
        # With a bounded split this resolves to the label "a/b".
        ("self#jumbf=/c2pa/urn:c2pa:MANIFEST/c2pa.assertions/a/b", None),
        # An empty tail names no assertion. _reference_status cites this very line as
        # the precedent for its data-box rule, and the cited case was untested.
        ("self#jumbf=c2pa.assertions/", None),
        # THE SAME RULE ON THE OTHER BRANCH. The two forms have separate `or None`
        # guards, and only the manifest-relative one was covered -- so dropping the
        # store-relative one passed all 1211 tests, and an empty label came back as ""
        # rather than None. Sharper than it looks: "" is falsy, so a caller testing the
        # result for truth still behaves, and a caller testing `is None` does not.
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


def test_an_actions_array_holding_a_non_map_is_not_a_well_formed_inception() -> None:
    """`_has_single_inception_action` narrows every entry to a map; dropping the
    `all(isinstance(entry, dict) ...)` term passed the suite.

    Its sibling `_contains_inception` has exactly this case in the narrowing table, and
    this function had none -- the asymmetry is how it survived. Both read the same
    attacker-controlled array.
    """
    from c2patxt._verify import _has_single_inception_action
    from c2patxt.manifest import DIGITAL_SOURCE_TYPE_TRAINED

    created: CborValue = {"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED}
    assert _has_single_inception_action({"actions": [created]})
    assert not _has_single_inception_action({"actions": [created, "c2pa.edited"]})
