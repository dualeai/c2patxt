"""Regression guards for defects found by adversarial review.

Each test carries the input that demonstrated the defect. These are permanent: never
delete one, never weaken its assertion. A regression test that no longer fails on the
original input has stopped being a regression test, whatever it still asserts.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import struct
import time
from collections.abc import Callable
from typing import Literal

import pytest

from c2patxt import _cbor, _verify, embed, verify
from c2patxt._cbor import CborDecodeError, loads
from c2patxt._extract import extract
from c2patxt._jumbf import TBOX_SUPERBOX, JumbfError, content_type_uuid, parse_superbox
from c2patxt._locate import find_wrappers, locate, payload_at
from c2patxt._selectors import build_wrapper, bytes_to_selectors
from c2patxt.constants import MAGIC, MARKER
from c2patxt.exceptions import MarkCorruptError, UnencodableTextError
from c2patxt.manifest import (
    ASSERTION_ACTIONS,
    ASSERTION_AI_DISCLOSURE,
    DIGITAL_SOURCE_TYPE_TRAINED,
    HASH_ALGORITHMS,
)
from c2patxt.signing import Signer
from c2patxt.status import StatusCode
from c2patxt.verdict import Provenance, Verdict
from tests.conftest import DISCLOSURE, mark
from tests.test_embed import PINNED as _PINNED

#: A CBOR map as the decoder produces one; CBOR admits integer and byte-string keys.
CborMap = dict[int | str | bytes, _cbor.CborValue]


class _CountingStr(str):
    """A ``str`` that counts every BYTE it encodes, slices included.

    ``__getitem__`` is overridden and that is the whole trick. Counting encode CALLS on
    the document object alone does NOT work, and the first version of the scanning test
    below did exactly that and passed with the quadratic reintroduced: the defective
    form is ``text[:index].encode()``, and slicing a ``str`` subclass returns a plain
    ``str``, so every one of those encodes was invisible. Runtime went 0.21 s -> 2.99 s
    while the assertion stayed green -- a regression test that no longer fails on the
    input that demonstrated the defect.

    Propagating the subclass through slicing makes the transitive cost visible, and
    BYTES rather than calls is the quantity that actually goes quadratic.

    ONE BLIND SPOT, named so it is not mistaken for coverage: ``re`` returns a plain
    ``str`` from ``.group()``, as do ``.translate()``, ``str()``, ``+`` and ``.upper()``.
    So the ``.encode("latin-1")`` inside ``_decode_run`` is invisible here -- about 650
    uncounted bytes in a 50-wrapper sample -- and a quadratic reintroduced INSIDE
    ``_decode_run`` would move neither assertion below.
    """

    encoded_bytes = 0

    def __getitem__(self, item: object) -> _CountingStr:
        return _CountingStr(str.__getitem__(self, item))  # pyright: ignore[reportArgumentType] -- index or slice, both valid

    def encode(self, *args: object, **kwargs: object) -> bytes:
        out = str.encode(self, *args, **kwargs)  # pyright: ignore[reportArgumentType, reportCallIssue] -- pass-through
        _CountingStr.encoded_bytes += len(out)
        return out


def _encoded_bytes(operation: Callable[[str], object], text: str) -> int:
    """Total bytes ``operation`` encodes out of ``text``, transitively through slices.

    The unit these tests assert in. A byte count is an integer that is identical on
    every machine, so unlike the CPU-time ratios these tests used to carry, it needs no
    headroom constant and cannot fail under load.
    """
    counting = _CountingStr(text)
    _CountingStr.encoded_bytes = 0
    operation(counting)
    return _CountingStr.encoded_bytes


def _box(tbox: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + tbox + payload


def _description() -> bytes:
    return _box(b"jumd", content_type_uuid(b"cbor") + bytes([2]) + b"x\x00")


def test_xlbox_of_zero_does_not_hang() -> None:
    """A 51-byte input made the content loop advance by nothing, forever.

    _read_header returned the raw uint64 XLBox with no floor, so a declared 0 gave
    child_length == 0 and `pos += child_length` never progressed. SECURITY.md puts
    CPU exhaustion from adversarial input firmly in scope.
    """
    child = struct.pack(">I", 1) + b"free" + struct.pack(">Q", 0)
    data = _box(TBOX_SUPERBOX, _description() + child)

    # THE REAL GUARD HERE IS THE TIMEOUT, NOT THIS ASSERTION. It comes from
    # pyproject.toml's global "--timeout=30" rather than a marker on this test; an
    # earlier version of this comment named @pytest.mark.timeout, which is not here. If the XLBox
    # check is removed, parse_superbox never returns and the line below never runs --
    # pytest-timeout is what fails the test. The assertion catches a slow-but-
    # terminating regression; the timeout catches the hang. Do not delete the timeout
    # timeout believing this assert covers it.
    started = time.process_time()
    with pytest.raises(JumbfError, match="XLBox 0 is shorter"):
        parse_superbox(data)
    assert time.process_time() - started < 1.0, "must fail fast, not spin"


def test_a_short_xlbox_cannot_substitute_a_fabricated_box() -> None:
    """XLBox between 1 and 15 desynchronised the parser.

    It left payload_offset past the box end, so the content loop resumed INSIDE the
    XLBox field: the genuine cbor/REAL box vanished and a fabricated box took its
    place. A caller scanning content for the claim could be handed a different box
    than the bytes declare.
    """
    child = struct.pack(">I", 1) + b"free" + struct.pack(">Q", 8)
    data = _box(TBOX_SUPERBOX, _description() + child + _box(b"cbor", b"REAL"))

    with pytest.raises(JumbfError, match="shorter than the header"):
        parse_superbox(data)


def test_cbor_rejects_a_boolean_map_key() -> None:
    """`isinstance(True, int)` let CBOR true/false through as a map key.

    The key then collided with integer 1 in the output dict, so a two-entry map
    decoded to one entry and silently dropped content the signer wrote. For a
    decoder over signed claim structures that is content substitution, not a
    formatting nit.
    """
    with pytest.raises(CborDecodeError, match="map keys must be"):
        loads(bytes.fromhex("a2016161f56162"))


def test_a_corrupt_candidate_does_not_hide_a_genuine_wrapper() -> None:
    """Appending ~22 characters made a valid wrapper unfindable.

    parse_wrapper_body raised out of the scan loop, discarding every match already
    collected. That is the denial of service the module's own hazard-1 rationale
    rejects, arriving through the parse path instead of the scan path, and it is
    SECURITY.md's "failure to detect a mark that is present and valid".
    """
    genuine = "Genuine document. " + build_wrapper(bytes.fromhex("deadbeef"))
    corrupt_tail = MARKER + bytes_to_selectors(MAGIC + bytes([2]) + b"\x00\x00\x00\x00")

    alone = locate(genuine)
    assert alone is not None
    assert locate(genuine + " PS." + corrupt_tail) == alone


def test_a_corrupt_wrapper_alone_still_reports_corruption() -> None:
    """Tolerating a corrupt neighbour must not silence corruption entirely."""
    from c2patxt.exceptions import MarkCorruptError

    corrupt = "Doc." + MARKER + bytes_to_selectors(MAGIC + bytes([2]) + b"\x00\x00\x00\x00")
    with pytest.raises(MarkCorruptError, match="version 2"):
        locate(corrupt)


def test_scanning_is_linear_not_quadratic() -> None:
    """locate() re-encoded the whole prefix per match.

    32,000 wrappers in 1.5 MB cost 8.3 seconds and tens of gigabytes of transient
    allocation -- allocation was bounded, CPU was not. Doubling the input must
    roughly double the time, not quadruple it.

    COUNTED, NOT TIMED -- and this test used to be timed. It asserted that 4x the input
    cost less than 10x the CPU, measured with ``process_time`` rather than wall clock
    because the wall-clock version failed 5 runs out of 6 under load and 0 out of 3
    unloaded, on a PRISTINE tree, since the suite runs under ``-n auto`` and inflicts
    that contention on itself.

    Counting the encodes is strictly stronger. The defect WAS one whole-document encode
    per match, so the encode count is not a proxy for the regression -- it is the
    regression. A ratio with 10x of headroom passes a 9x constant-factor slowdown; an
    equality does not. And a count is identical on every machine, so the reason the
    timing version needed headroom disappears rather than being tuned.

    ``find_wrappers`` encodes the document ONCE, in ``require_encodable``, and then
    walks a running ``prefix_bytes`` offset. That is why the count does not move with
    the number of wrappers.
    """

    def scan(count: int) -> tuple[int, int]:
        text = "x" + build_wrapper(b"") * count

        def run(document: str) -> None:
            assert len(find_wrappers(document)) == count

        return _encoded_bytes(run, text), len(text.encode("utf-8"))

    for count in (4_000, 16_000):
        encoded, size = scan(count)
        # THREE passes, and the bound is 4 so that a FOURTH fails. An earlier version
        # of this comment named two -- require_encodable and the incremental prefix
        # walk -- and set the bound at 3, which left a margin of FIFTY BYTES at both
        # sizes: 2.999745 and 2.999936 passes. A constant 50 bytes is not headroom, it
        # is the measured value rounded up, and it would have failed on an unrelated
        # change to the wrapper length.
        #
        # The third pass is `wrapper_text.encode("utf-8")`; the prefix walk is the
        # second and re-encodes each wrapper, because `consumed_index` is set to
        # `found` rather than past the wrapper.
        #
        # Against the quadratic, which re-encodes the whole prefix per match at ~2000
        # passes for the smaller input, one pass of headroom or two makes no
        # difference -- three orders of magnitude separate them. The numbers are
        # integers, so nothing here varies by machine.
        assert encoded <= 4 * size, (
            f"{count} wrappers: encoded {encoded} bytes for a {size}-byte document "
            f"({encoded / size:.1f} passes) -- the scan is re-encoding, not walking"
        )


def test_scanning_corrupt_candidates_is_linear_not_quadratic() -> None:
    """The SAME quadratic defect, reintroduced through the exception constructor.

    ``test_scanning_is_linear_not_quadratic`` above covers the match path, which was
    fixed first. The corrupt path then paid a whole-document ``doc.encode("utf-8")``
    inside ``MarkCorruptError.__init__`` for every magic-matching-but-malformed
    candidate -- and ``find_wrappers`` DISCARDS all but the first of those, so the
    cost bought nothing at all.

    Measured before the fix: 544 KB took 2.53 s and 1.09 MB took 9.91 s in verify(),
    so roughly 5 MB was several minutes of CPU on an endpoint anyone can post to.
    After deferring the location to ``__str__``: 0.045 s at 544 KB, a 56x difference.

    Each decoy is a bare magic number with no header behind it -- valid enough to
    enter the parse, malformed enough to raise.

    COUNTED, NOT TIMED, for the reasons given on the test above -- the timed version
    needed 10x of headroom to survive ``-n auto``, and headroom is exactly what a
    constant-factor regression hides in.

    The property is pinned twice, at two levels, because they fail differently:

    1. AT THE UNIT. Constructing the exception must not encode ``doc`` at all; only
       ``str()`` on it may. That is the fix stated directly, and it fails on the line
       that would reintroduce it.
    2. THROUGH THE SCAN. Total bytes encoded while scanning a document full of decoys
       must stay proportional to the document, not to decoys x document.
    """
    decoy = MARKER + bytes_to_selectors(MAGIC)

    # 1. The unit. A huge doc makes the difference unmissable if it ever encodes.
    document = "x" * 100_000
    encoded_at_construction = _encoded_bytes(lambda text: MarkCorruptError("boom", text, 0), document)
    encoded_at_str = _encoded_bytes(lambda text: str(MarkCorruptError("boom", text, 0)), document)
    assert encoded_at_construction == 0, (
        f"MarkCorruptError.__init__ encoded {encoded_at_construction} bytes of the document; "
        "the location must be resolved in __str__, where only a caller who reads it pays"
    )
    assert encoded_at_str > 0, "the location must still be computed when the message IS read"

    # 2. The scan. find_wrappers builds one of these per malformed candidate and keeps
    # only the first, so an eager encode is paid per decoy and thrown away.
    def scan(count: int) -> tuple[int, int]:
        def run(text: str) -> None:
            with contextlib.suppress(MarkCorruptError):
                find_wrappers(text)

        text = decoy * count
        return _encoded_bytes(run, text), len(text.encode("utf-8"))

    for count in (4_000, 16_000):
        encoded, size = scan(count)
        assert encoded <= 3 * size, (
            f"{count} decoys: encoded {encoded} bytes for a {size}-byte document "
            f"({encoded / size:.1f} passes) -- the cost is per-decoy, not per-document"
        )


def test_a_structural_error_with_no_position_claims_no_position() -> None:
    """MarkCorruptError appended "(at end of text)" to errors with NO known offset.

    Every structural error from ``_extract`` was built as ``(msg, "", 0)``, and
    ``0 >= len(b"")`` is true, so the truncation-aware wording fired on all of them.
    "claim is not a CBOR map (at end of text)" states a location that was never
    computed -- worse than omitting it, because a reader trusts it and goes looking.
    """
    assert str(MarkCorruptError("something is wrong", "", 0)) == "something is wrong"
    assert str(MarkCorruptError("truncated", "abc", 99)).endswith("(at end of text)")
    assert str(MarkCorruptError("bad byte", "abcdef", 2)).endswith("(at byte 2)")


@pytest.mark.parametrize("form", ["NFC", "NFD", "NFKC", "NFKD"])
def test_no_normalization_form_removes_the_mark(form: Literal["NFC", "NFD", "NFKC", "NFKD"]) -> None:
    """The gate behind docs/robustness.md's 1.000 in the "mark still found" column.

    The robustness battery needs the PAN'26 corpus and so cannot run in CI, which is
    offline by design. This is the part of it that MUST hold, reduced to something the
    suite can check on every commit: aggressive normalization on ingest must not
    destroy provenance.

    Asserted on the CODE POINTS rather than by round-tripping a mark, so it holds for
    every possible payload rather than for the one this test happened to build.
    """
    import unicodedata

    from c2patxt.constants import MARKER, VS_HIGH_BASE, VS_LOW_BASE

    codepoints = [ord(MARKER), *range(VS_LOW_BASE, VS_LOW_BASE + 16), *range(VS_HIGH_BASE, VS_HIGH_BASE + 240)]
    for codepoint in codepoints:
        char = chr(codepoint)
        assert unicodedata.normalize(form, char) == char, f"U+{codepoint:04X} changed under {form}"


@pytest.mark.parametrize("route", ["created_assertions", "icons"], ids=["created_assertions", "icons"])
def test_repeated_references_to_one_assertion_hash_it_once(
    signer: Signer, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """PRE-AUTHENTICATION HASH AMPLIFICATION. An adversarial review found it; this pins
    the fix.

    ``verify`` calls ``_check_assertions`` BEFORE ``_check_signature``, so every hash
    computed here is computed on the word of an attacker who holds no credential at
    all. Two routes reached the same target repeatedly with no cap and no memoization:

    * ``created_assertions`` is never de-duplicated, so N links naming one assertion
      meant N full digests over it;
    * an actions assertion's ``softwareAgents`` may carry N icon references, and
      15.10.3.3 validation hashed the target once per reference.

    Measured before the fix, against a 1 MiB target: 500 references cost 0.22 s of CPU,
    2000 cost 0.86 s, 4000 cost 1.72 s -- linear in references times target size, and
    all of it returning ``ok=True``. Inside the 2 MiB ``MAX_MANIFEST_LENGTH`` budget an
    attacker fits roughly 11,000 ninety-byte references beside a 1 MiB assertion, which
    is about 11 GiB of hashing from one 2 MiB input.

    THE FIX IS MEMOIZATION, NOT A CAP, because a cap is a policy guess about how many
    references a conforming producer may write and this is not. Hashing the same bytes
    under the same algorithm twice cannot change the answer, so caching by
    ``(label, algorithm)`` bounds the work at the store's own size without rejecting
    anything that used to be accepted.

    COUNTED, NOT TIMED. A wall-clock assertion here would be the flaky kind this suite
    has already had to repair once; the number of digest computations is exactly what
    the fix changes and it is deterministic.
    """
    label = ASSERTION_AI_DISCLOSURE
    repeats = 200
    original = extract(mark("Hello world.", signer))
    assert original is not None

    calls: list[int] = []
    real = HASH_ALGORITHMS["sha256"]

    def counting(data: bytes = b"") -> object:
        calls.append(len(data))
        return real(data)

    # setitem, not setattr: _verify imported the mapping itself, so replacing the
    # module attribute would leave its binding untouched.
    monkeypatch.setitem(HASH_ALGORITHMS, "sha256", counting)

    digest = hashlib.sha256(original.assertion_bytes[label]).digest()
    url = f"self#jumbf=c2pa.assertions/{label}"
    claim = dict(original.claim)
    assertions = dict(original.assertions)

    if route == "created_assertions":
        links = original.claim["created_assertions"]
        assert isinstance(links, list)
        extra: list[_cbor.CborValue] = [{"url": url, "hash": digest, "alg": "sha256"} for _ in range(repeats)]
        claim["created_assertions"] = [*links, *extra]
    else:
        icon: CborMap = {"url": url, "hash": digest, "alg": "sha256"}
        payload: CborMap = {
            "actions": [{"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED}],
            "softwareAgents": [{"name": "x", "icon": icon} for _ in range(repeats)],
        }
        assertions[ASSERTION_ACTIONS] = payload

    store = dataclasses.replace(original, claim=claim, assertions=assertions)
    _, ok = _verify._check_assertions(  # pyright: ignore[reportPrivateUsage] -- the amplification is inside this function; verify() would also run the signature path and hide the count
        store, Verdict(state=Provenance.INVALID)
    )

    assert ok, "the manifest is otherwise sound; the references all resolve"
    over_target = sum(1 for size in calls if size == len(original.assertion_bytes[label]))
    assert over_target <= 1, f"the target was hashed {over_target} times for {repeats} references"

    # AND BOUND THE TOTAL. The line above counts calls whose INPUT LENGTH matches the
    # target's -- identity by byte count, not by bytes -- and says nothing about work
    # done elsewhere. A regression that memoized this assertion correctly while hashing
    # a different one 200 times would pass it, and total CPU is the quantity the threat
    # is about. One digest per distinct assertion, under one algorithm, is the ceiling.
    assert len(calls) <= len(original.assertion_bytes), (
        f"{len(calls)} digests for {len(original.assertion_bytes)} assertions"
    )


@pytest.mark.parametrize("document", ["Hello world.", "x" * 4_000, "é" * 500])
def test_verify_walks_a_marked_document_twice_not_four_times(
    monkeypatch: pytest.MonkeyPatch, signer: Signer, document: str
) -> None:
    """verify() encoded the whole document FOUR times and scanned it TWICE.

    ``_binding_status`` called ``find_wrappers`` on text ``verify`` had already
    scanned, keeping only the spans, and took a whole-document encode purely for its
    length two lines before ``_hash_binding_bytes`` encoded the same text again. The
    second scan cost 59% of a 1 KB verify and 21.8% of a 1 MB one -- the SHORT
    document is where it hurts, because ``_decode_run`` walks the selector run in
    pure Python on every scan. The discarded encode added 10-12% on top.

    COUNTS, NOT TIMINGS. A wall-clock threshold for a constant factor is a flaky test
    on a loaded runner; the number of times the document is walked is the quantity
    that actually regressed, and it is machine-independent.

    Two encodes rather than one is the floor this shape allows: ``require_encodable``
    inside ``find_wrappers`` must encode to reject a lone surrogate, and it returns
    offsets rather than the bytes it produced. Threading those bytes out of the
    locator would buy the last encode and is not done here.
    """
    scans = 0
    real = _verify.find_wrappers

    def counting_find_wrappers(text: str) -> list[object]:
        nonlocal scans
        scans += 1
        return real(text)  # pyright: ignore[reportReturnType] -- pass-through, shape unchanged

    class CountingStr(str):
        """A ``str`` that counts encodes OF THE DOCUMENT ITSELF.

        Subclassed rather than patched globally so an encode of some slice or of the
        NFC form -- both legitimate, and both plain ``str`` -- is not counted.
        """

        encodes = 0

        def encode(self, *args: object, **kwargs: object) -> bytes:
            CountingStr.encodes += 1
            return str.encode(self, *args, **kwargs)  # pyright: ignore[reportArgumentType, reportCallIssue] -- pass-through

    monkeypatch.setattr(_verify, "find_wrappers", counting_find_wrappers)

    text = CountingStr(mark(document, signer))
    CountingStr.encodes = 0
    verdict = verify(text)

    assert verdict.state is Provenance.VALID, verdict.failure
    assert scans == 1, f"document scanned {scans} times"
    assert CountingStr.encodes == 2, f"document encoded {CountingStr.encodes} times"


def test_verify_walks_unmarked_text_exactly_once() -> None:
    """The common case must stay one encode and one ``str.find``.

    Most text on earth is unmarked, so this is the path a verification surface pays
    on nearly every call. Measured at 0.10 ms per MB, linear to 4.32 MB. Pinned
    alongside the marked-document count so a fix to that path cannot pay for itself
    by loading this one.
    """

    class CountingStr(str):
        encodes = 0

        def encode(self, *args: object, **kwargs: object) -> bytes:
            CountingStr.encodes += 1
            return str.encode(self, *args, **kwargs)  # pyright: ignore[reportArgumentType, reportCallIssue] -- pass-through

    text = CountingStr("The quick brown fox jumps over the lazy dog. " * 100)
    CountingStr.encodes = 0

    assert verify(text).state is Provenance.UNMARKED
    assert CountingStr.encodes == 1, f"unmarked text encoded {CountingStr.encodes} times"


def _hostile_store(*, repeats: int, templates: int, instance: bool = False) -> str:
    """Marked text whose claim links an actions label ``repeats`` times.

    The actions assertion carries ``templates`` templates, each with an icon. Both
    counts are attacker-chosen and independent, which is the whole point: the defect
    this builds for costs their PRODUCT.

    With ``instance``, the repeated link names a SECOND actions assertion carried as a
    6.4 ``__1`` instance, whose single action is ``c2pa.edited``. That store passes every
    rule in ``_store_shape_status`` -- ``_actions_status`` asks ``labels[1:]`` only
    whether it CONTAINS an inception action, and an edit is not one -- so it reaches the
    reference walk. Without it the repeated link names the base label, which is rejected
    before the walk.

    Built here rather than through ``embed`` because no conforming producer emits it
    -- ``embed`` links each assertion once -- and an attacker is under no such
    obligation.
    """
    import uuid as _uuid

    from c2patxt._jumbf import UUID_CBOR, DescriptionBox, JumbfBox, serialize_superbox
    from c2patxt.manifest import (
        ASSERTION_HASH_DATA,
        LABEL_ASSERTION_STORE,
        LABEL_CLAIM,
        LABEL_CLAIM_SIGNATURE,
        LABEL_MANIFEST_STORE,
        UUID_ASSERTION_STORE,
        UUID_CLAIM,
        UUID_CLAIM_SIGNATURE,
        UUID_MANIFEST,
        UUID_MANIFEST_STORE,
    )

    def box(label: str, payload: object) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=UUID_CBOR, label=label, requestable=True),
            content=((b"cbor", _cbor.dumps(payload)),),  # pyright: ignore[reportArgumentType] -- test payloads are CBOR-shaped
        )

    def payload(b: JumbfBox) -> bytes:
        """The bytes C2PA 8.4.2.3 hashes: the superbox with LBox and TBox stripped."""
        return serialize_superbox(b)[8:]

    def link(b: JumbfBox, label: str) -> dict[str, object]:
        return {"url": f"self#jumbf={LABEL_ASSERTION_STORE}/{label}", "hash": hashlib.sha256(payload(b)).digest()}

    disclosure = box(ASSERTION_AI_DISCLOSURE, {"modelType": "generic"})
    # AN ICON THAT RESOLVES, pointing at the disclosure with its true digest. A BROKEN
    # icon makes this store useless for counting: the reference walk is a `next(...)`
    # over a generator, so it stops at the first failure and never reaches the second
    # actions label -- the walk count then reads 1 whether the labels are deduped or
    # not. Every reference has to pass for the count to mean what it says.
    icon = {**link(disclosure, ASSERTION_AI_DISCLOSURE), "alg": "sha256"}
    actions = box(
        ASSERTION_ACTIONS,
        {
            "actions": [{"action": "c2pa.created", "digitalSourceType": DIGITAL_SOURCE_TYPE_TRAINED}],
            "templates": [{"action": "c2pa.created", "icon": icon} for _ in range(templates)],
        },
    )
    edited = box(
        f"{ASSERTION_ACTIONS}__1",
        {
            "actions": [{"action": "c2pa.edited"}],
            "templates": [{"action": "c2pa.edited", "icon": icon} for _ in range(templates)],
        },
    )
    repeated, repeated_label = (edited, f"{ASSERTION_ACTIONS}__1") if instance else (actions, ASSERTION_ACTIONS)
    binding = box(ASSERTION_HASH_DATA, {"exclusions": [{"start": 0, "length": 1}], "hash": b"\x00" * 32})

    claim = {
        "instanceID": "x",
        "signature": "self#jumbf=c2pa.signature",
        "claim_generator_info": {"name": "n"},
        "alg": "sha256",
        "created_assertions": [
            link(disclosure, ASSERTION_AI_DISCLOSURE),
            link(binding, ASSERTION_HASH_DATA),
            *([link(actions, ASSERTION_ACTIONS)] if instance else []),
            *([link(repeated, repeated_label)] * repeats),
        ],
    }

    def superbox(uuid_: bytes, label: str, children: tuple[bytes, ...]) -> JumbfBox:
        return JumbfBox(
            description=DescriptionBox(uuid=uuid_, label=label),
            content=tuple((b"jumb", child) for child in children),
        )

    store = superbox(
        UUID_MANIFEST_STORE,
        LABEL_MANIFEST_STORE,
        (
            payload(
                superbox(
                    UUID_MANIFEST,
                    f"urn:c2pa:{_uuid.UUID(int=7)}",
                    (
                        payload(
                            superbox(
                                UUID_ASSERTION_STORE,
                                LABEL_ASSERTION_STORE,
                                # `edited` only when it is LINKED: an unlinked box is
                                # assertion.undeclared, which fails the shape check and
                                # would cost the walk this test is counting.
                                tuple(
                                    payload(b)
                                    for b in (
                                        (actions, edited, disclosure, binding)
                                        if instance
                                        else (actions, disclosure, binding)
                                    )
                                ),
                            )
                        ),
                        payload(
                            JumbfBox(
                                description=DescriptionBox(uuid=UUID_CLAIM, label=LABEL_CLAIM),
                                content=((b"cbor", _cbor.dumps(claim)),),  # pyright: ignore[reportArgumentType] -- test payload
                            )
                        ),
                        payload(
                            JumbfBox(
                                description=DescriptionBox(uuid=UUID_CLAIM_SIGNATURE, label=LABEL_CLAIM_SIGNATURE),
                                content=((b"cbor", b"\x00"),),
                            )
                        ),
                    ),
                )
            ),
        ),
    )
    return "hello" + build_wrapper(serialize_superbox(store))


def test_a_repeated_actions_link_does_not_multiply_the_reference_walk(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pre-authentication quadratic in CPU **and** memory, on the word of an attacker.

    ``_assertion_failure`` materialised the whole ``references`` list BEFORE
    ``_store_shape_status`` -- which holds the check that rejects this very store --
    could run. ``claim_order`` keeps duplicates and ``_label_instances`` does not
    dedupe, so an actions label linked N times called ``_action_references`` N times
    on the SAME assertion, each returning M icon references. N and M are independent
    and both attacker-chosen, so the cost is their PRODUCT.

    Measured through public ``verify()`` before the fix, N = M:

        ====  =========  ========  =========
        N=M   store      CPU       peak RSS
        ====  =========  ========  =========
        100    17 591 B   0.012 s      2.6 MB
        800   134 493 B   0.367 s    155.4 MB
        1600  268 093 B   1.388 s    618.9 MB
        3000  501 893 B   4.869 s   2173.3 MB
        ====  =========  ========  =========

    Half a megabyte of manifest for 2.17 GB, verdict INVALID in every row. The 2 MiB
    ``MAX_MANIFEST_LENGTH`` ceiling extrapolates to an OOM, which makes a body-size
    cap -- the control ``constants.py`` tells integrators to apply -- insufficient.

    ASSERTED AS A CALL COUNT, NOT A DURATION. The quantity that regressed is how many
    times the same assertion is walked; timing that would need a store big enough to
    be slow on a loaded runner, and would still be a threshold to tune. The digest
    memoization does not help here -- the cost is list construction, not hashing.
    """
    from c2patxt import _verify as verify_module

    calls: list[object] = []
    # The defect is HOW MANY TIMES a private helper is called, so the test has to
    # reach for the private helper; there is no public surface that reports it.
    real = verify_module._action_references  # pyright: ignore[reportPrivateUsage] -- the call count IS the property under test

    def counting(payload: _cbor.CborValue) -> list[dict[str, _cbor.CborValue]]:
        calls.append(payload)
        return real(payload)

    monkeypatch.setattr(verify_module, "_action_references", counting)

    verdict = verify(_hostile_store(repeats=200, templates=200))

    assert verdict.state is Provenance.INVALID
    # EXACTLY ZERO, not `<= 1`. `<= 1` is satisfied by a store that never reaches the
    # shape check at all AND by one that reaches it after walking once, so it could not
    # tell the laziness from the dedupe. What holds the laziness is that a store this
    # shape check REJECTS costs no walk whatsoever.
    assert not calls, f"a rejected store was walked {len(calls)} times before it was rejected"

    # AND THE LAZINESS DID NOT DISABLE THE WALK. Moving the collection behind
    # `_store_shape_status` could have put every 15.10.3.3 reference rule out of reach
    # without failing a single test -- the icon checks would simply stop running. One
    # actions link passes the shape check, so the references are collected and walked.
    calls.clear()
    assert verify(_hostile_store(repeats=1, templates=200)).state is Provenance.INVALID
    assert len(calls) == 1, "a store that passes the shape check must still have its references walked"

    # AND THE DEDUPE, ON A STORE THAT REACHES THE WALK CARRYING A REPEATED LABEL.
    # This is the half a first attempt at this test declared unreachable, on the
    # reasoning that _actions_status rejects any repeated actions link. It does not:
    # that check asks labels[1:] only whether it CONTAINS an inception action, so a 6.4
    # __1 instance holding c2pa.edited can be linked N times and pass every shape rule.
    # Measured without the dedupe on stores of 67/134/268 KB -- the size grows with
    # N and M -- at N=M of 400/800/1600, costing
    # 0.293/1.186/4.766 s against 0.032/0.062/0.121 s with it -- x4 per doubling, the
    # same pre-authentication quadratic, still live and reached before any signature is
    # checked. So both halves ARE load-bearing, and this is the assertion that says so.
    calls.clear()
    assert verify(_hostile_store(repeats=200, templates=200, instance=True)).state is Provenance.INVALID
    assert len(calls) == 2, f"two distinct actions labels were walked {len(calls)} times"


@pytest.mark.parametrize(
    "patches",
    [
        # InvalidVersion: 31 is not a valid X509 version
        [(1445, 0x1F)],
        # KeyError: 0 -- raised from `certificate.issuer`, an ATTRIBUTE ACCESS
        [(1473, 0x00)],
        # DuplicateExtension: Duplicate 2.5.29.15 extension found
        [(1047, 105), (1615, 42), (1622, 15)],
    ],
    ids=["x509-version", "issuer-name-oid", "duplicate-extension"],
)
def test_hostile_certificate_bytes_do_not_escape_verify(signer: Signer, patches: list[tuple[int, int]]) -> None:
    """``verify()`` PROMISES NEVER TO RAISE, AND A ONE-BYTE EDIT MADE IT RAISE.

    The promise is stated in eight places -- ``_verify.verify``'s own docstring says
    "Never raises for absent, corrupt or invalid marks -- every outcome is a Verdict",
    with UTF-8 named as the single exception -- and ``exceptions.py`` records that an
    earlier unguarded version "was attacker-triggerable against any endpoint catching
    only C2paTextError, which is what the documentation tells integrators to catch".
    Nothing asserted it against hostile certificate DER, and three exception types got
    out. The comment above each vector is what it raised before the fix.

    WHY THE OLD GUARDS MISSED. ``CERTIFICATE_ERRORS`` was ``(ValueError,
    UnsupportedAlgorithm)``. ``InvalidVersion`` and ``DuplicateExtension`` descend
    straight from ``Exception``, and ``KeyError`` is not a ``ValueError``. The KeyError
    came from ``certificate.issuer`` -- an ATTRIBUTE ACCESS, because ``cryptography``
    parses lazily, so the failure surfaced far from ``load_der_x509_certificate`` and
    outside every ``try`` that was watching it.

    THREE FIXED VECTORS RATHER THAN A FUZZ SWEEP, and that is a deliberate choice. A
    seeded 2 000-trial sweep over this same payload found NONE of these; the audit that
    found them needed 40 000. A sweep small enough to run in the suite is a test that
    passes on broken code, which this repository has already shipped once under another
    name. These offsets are stable because the manifest bytes are pinned by
    ``test_the_signed_manifest_bytes_are_exactly_what_they_were``.

    AND THE VERDICT IS ASSERTED, NOT ONLY THE ABSENCE OF AN EXCEPTION. If the manifest
    layout ever moves, an offset that lands somewhere harmless would still "not raise"
    and this test would pass while covering nothing. Requiring the credential to be
    REJECTED is what keeps the vector pointed at a certificate.
    """
    marked = embed("Hello world.", signer, DISCLOSURE, context=_PINNED)
    payload = bytearray(payload_at(marked) or b"")
    assert len(payload) == 1_797, "the vectors are offsets into the pinned manifest"
    visible = marked[: marked.index(MARKER)]

    for offset, value in patches:
        assert payload[offset] != value, f"offset {offset} already holds {value:#04x}; the vector is inert"
        payload[offset] = value

    verdict = verify(visible + build_wrapper(bytes(payload)))

    assert verdict.state is Provenance.INVALID
    assert StatusCode.SIGNING_CREDENTIAL_INVALID in verdict.codes() or (
        StatusCode.CLAIM_SIGNATURE_MISSING in verdict.codes()
    ), f"the credential must be rejected, not merely survived: {[c.value for c in verdict.codes()]}"


def test_a_repeated_actions_link_allocates_a_bounded_multiple_of_its_input() -> None:
    """The ALLOCATION half of the pre-authentication quadratic, which nothing asserted.

    The walk COUNT is pinned above, and the walk TIME is tracked by the CodSpeed
    benchmark. The PEAK was held only by the ``memory`` instrument -- and it is not
    established that the instrument can see it: memtrack hooks libc while the memory
    pass runs under pymalloc, so every object below 512 B is served from an arena it
    never observes, and pytest-codspeed measures an already-warm SECOND call. A property
    this package commits to in SECURITY.md cannot rest on that.

    Measured 2026-08-06 on a 0.53 MiB store, ``tracemalloc``:

    ==============================  ==========  ========
    tree                            peak        ratio
    ==============================  ==========  ========
    pristine                         1.77 MiB    3.35x
    laziness removed                 1.77 MiB    3.35x
    dedupe removed                   1.77 MiB    3.35x
    both removed                    38.22 MiB   72.17x
    ==============================  ==========  ========

    IT CATCHES THE COMBINATION, NOT EITHER HALF, and that is not a weakness to hide.
    With the generator intact nothing is held; with the dedupe intact the list holds two
    labels. Only both together hold 200 labels x 400 icons live at once. So this is the
    guard for the defect as it actually shipped, and the two halves are held separately
    elsewhere -- the walk count above for the laziness, the benchmark for the dedupe.
    A reader must not take any one of the three for the other two.

    5x, chosen the way the ceiling test's bound was: 1.5x of headroom over the pristine
    ratio and 14x of margin under the defect. A RATIO of integer byte counts rather than
    a MiB figure, because ``tracemalloc`` counts only blocks Python allocated through
    domain 0, which makes the ratio identical on every machine where an absolute number
    is not.
    """
    import tracemalloc

    text = _hostile_store(repeats=400, templates=400, instance=True)
    size = len(text.encode("utf-8"))

    verify(text)  # Warm the interpreter so the measurement is allocation, not import.
    tracemalloc.start()
    try:
        verify(text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert peak <= 5 * size, (
        f"a {size / 2**20:.2f} MiB store peaked at {peak / 2**20:.2f} MiB "
        f"({peak / size:.2f}x); the reference walk is holding its results live again"
    )


def test_a_manifest_at_the_ceiling_allocates_a_bounded_multiple_of_its_input() -> None:
    """SECURITY.md commits to bounded allocation from adversarial input, and
    ``MAX_MANIFEST_LENGTH`` is exported from the package so an operator can size a
    deployment against it. Nothing asserted the RATIO.

    A wrapper declaring the full 2 MiB ceiling arrives as 7.88 MiB of text -- A.8's
    selectors cost 3 or 4 UTF-8 bytes per manifest byte -- and verifying it peaks at
    20.00 MiB, a ratio of 2.54.

    THE BOUND IS 3x, AND WHAT IT CATCHES IS A DOCUMENT COPY HELD LIVE ACROSS THE PARSE.
    Verified: retaining one inside ``find_wrappers`` takes the ratio to 3.54x and fails
    this. Two earlier phrasings were checked and found false --
      * "a second whole copy of the MANIFEST" -- the manifest is 2 MiB against a
        7.88 MiB document, so an extra copy is +0.25x, inside any useful headroom;
      * a merely TRANSIENT extra ``text.encode()`` in ``_binding_status`` -- freed
        before the peak, which falls in the selector decode and JUMBF parse, so it
        moves the ratio not at all.
    The peak is a property of the decode-and-parse phase, and so is this bound. State
    what a bound catches, not what it sounds like it catches.

    ASSERTED RATHER THAN BENCHMARKED, deliberately. As a benchmark this is the most
    expensive input in the suite and buys a CPU curve the icon-sized decode benchmark
    already has 20x more cheaply. What the ceiling adds is a BOUND -- a number that
    holds or does not, on any machine, with no threshold to tune. That is an
    assertion's shape.

    THE INPUT IS NOT A VALID MARK and does not need to be: the allocation happens in
    the selector decode and the JUMBF parse, both of which run before anything is
    authenticated. That is exactly why the bound matters.
    """
    import tracemalloc

    from c2patxt.constants import MAX_MANIFEST_LENGTH

    payload = bytes(range(256)) * (MAX_MANIFEST_LENGTH // 256)
    text = "x" + build_wrapper(payload)
    size = len(text.encode("utf-8"))

    verify(text)  # Warm the interpreter so the measurement is allocation, not import.
    tracemalloc.start()
    try:
        verify(text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert peak <= 3 * size, (
        f"a {size / 2**20:.2f} MiB input peaked at {peak / 2**20:.2f} MiB "
        f"({peak / size:.2f}x); the manifest is being copied more times than it was"
    )


def test_the_truncation_wording_switches_exactly_at_the_end_of_the_document() -> None:
    """``pos >= len(doc.encode())`` chooses between "end of text" and "byte N".

    The existing test uses ``pos=99`` against ``doc="abc"`` -- 96 units past the
    boundary -- so relaxing ``>=`` to ``>`` changed nothing it could see. The boundary
    is the only place the two readings differ, and it is the common case: a
    length-prefixed wrapper that runs off the end stops at exactly ``len(doc)``.
    """
    doc = "abc"
    size = len(doc.encode("utf-8"))

    assert str(MarkCorruptError("truncated", doc, size)).endswith("(at end of text)")
    assert str(MarkCorruptError("bad byte", doc, size - 1)).endswith(f"(at byte {size - 1})")


def test_the_surrogate_position_is_the_index_that_was_reported() -> None:
    """``UnencodableTextError.position`` was never compared to a value, so an off-by-one
    survived. The index is the whole content of this error -- it is what tells a caller
    which character to fix.
    """
    text = "ok\ud800bad"
    with pytest.raises(UnencodableTextError) as excinfo:
        verify(text)

    assert excinfo.value.position == 2, "the lone surrogate is at index 2"
    assert str(excinfo.value).count("index 2") == 1
