# pyright: reportPrivateUsage=false
# Verdict._add is the verdict BUILDER, kept private so the public result type carries
# no mutator a caller could use to assemble a verdict verification never produced.
# This module is the one legitimate builder.
"""
``verify``: the full validation path, producing a :class:`Verdict`.

THE HASH BINDING ORDER IS NORMATIVE AND EASY TO INVERT
------------------------------------------------------
C2PA 15.12.1.3.1, which A.8.5 designates as *the* normative procedure ("refer to the
Validation clause for the normative procedure"):

    5. Remove the wrapper bytes from the text according to the exclusion range(s).
    6. Normalize the remaining text to NFC.
    7. Encode the normalized text as UTF-8 bytes.
    8. Compute the hash over these bytes.

Remove, THEN normalize. A.8.7.3 says the opposite -- "perform normalization before
calculating offsets" -- and the two produce different bytes whenever the wrapper is
not a suffix: for ``"a" + U+FEFF + <run> + U+0301`` the first order yields
``NFC("a" + U+0301)`` = ``c3 a1`` while the second leaves ``61 cc 81``, because
U+FEFF is a starter and blocks composition. We follow 15.12.1.3.1, as both other
public A.8 implementations independently did.

VALIDATION ORDER, AND WHAT IT COSTS
-----------------------------------
15.1.2 says the phases are "listed in no particular order", and we run them assertions,
then binding, then signature -- see ``verify`` at the foot of this module.

AN EARLIER VERSION OF THIS PARAGRAPH CLAIMED THE OPPOSITE, describing a
signature-before-hash order as a deliberate mitigation. The code has never done that,
so the paragraph asserted a security property the package did not have -- and a reviewer
who read it would stop looking, which is the worst thing a docstring can do.

The order is not free, and the consequence is real rather than theoretical: everything
before the signature check runs on the word of an attacker holding no credential. That
is what made pre-authentication hash amplification possible -- one manifest naming a
large assertion many times, re-hashed once per reference -- fixed by memoizing digests
per ``(label, algorithm)`` in ``_assertion_digest``, which bounds the work at the store's
own size. The exclusion range is separately defended: ``_binding_status`` requires it to
equal a located wrapper span before any hash is computed, so an attacker cannot choose
which bytes the binding covers.

Reordering to signature-first would remove that class of exposure at the root, and the
argument once given here against it was wrong: ``verify`` runs all three phases
UNCONDITIONALLY and accumulates every code, so reordering changes the ORDER of entries
in ``Verdict.failure`` and not the set reported. What it would change is how much work
runs before authentication. Recorded in docs/open-questions.md.
"""

from __future__ import annotations

import dataclasses
import datetime
import itertools
import re
import unicodedata
from collections.abc import Sequence

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509 import Certificate, load_der_x509_certificate

from c2patxt import _cose
from c2patxt._cbor import CborValue
from c2patxt._extract import parse_manifest_store
from c2patxt._locate import WrapperMatch, find_wrappers
from c2patxt.exceptions import MarkCorruptError
from c2patxt.manifest import (
    ASSERTION_ACTIONS,
    ASSERTION_ACTIONS_V1,
    ASSERTION_AI_DISCLOSURE,
    ASSERTION_HASH_DATA,
    ASSERTION_URI_PREFIX,
    CLAIM_SIGNATURE_URI,
    HASH_ALGORITHMS,
    LABEL_ASSERTION_STORE,
    LABEL_CLAIM_SIGNATURE,
    LABEL_MANIFEST_STORE,
    ManifestStore,
)
from c2patxt.status import StatusCode
from c2patxt.trust import NoTrustEvaluator, ProfileError, TrustEvaluator, check_claim_signing_profile, load_anchors
from c2patxt.verdict import Provenance, Verdict

__all__ = [
    "VerifyContext",
    "verify",
]


@dataclasses.dataclass(frozen=True, slots=True)
class VerifyContext:
    """Everything verification may consult, supplied explicitly.

    There is no ambient configuration: no file discovery, no implicit credential
    store, and no network. If it is not here or in the text, it does not affect the
    answer.
    """

    anchors_pem: bytes | None = None
    """PEM bundle of trust anchors. ``None`` means no anchors, which is the shipped
    default -- this is the ONLY channel, with no environment variable behind it.

    PARSED EAGERLY, at construction. A malformed bundle is a CALLER error, and
    resolving it lazily inside :func:`verify` put the failure on the signature-valid
    path ONLY: unmarked and invalid text sailed through while the first genuinely
    good document raised. That asymmetry survives every staging test built on
    unmarked input. Parsing here also stops the bundle being re-parsed on every
    single call."""

    now: datetime.datetime | None = None
    """The instant to judge certificate validity against. ``None`` means "now".

    C2PA 15.8 judges the signing certificate against THE CURRENT TIME AT VALIDATION,
    not against any time the document asserts -- a document-supplied time would be
    attacker-controlled, and the holder of an expired key would simply write one
    inside the old window. Injected so verification stays a pure function of its
    arguments when a caller wants it to be.

    MUST BE TIMEZONE-AWARE, and that is checked at construction. A naive datetime
    compares against nothing -- certificate validity is read through the aware
    accessors -- so it raised ``TypeError`` deep inside the signature path. See
    ``__post_init__``."""

    trust_evaluator: TrustEvaluator = dataclasses.field(default_factory=NoTrustEvaluator)
    """Decides whether a chain reaches an anchor. The default trusts nothing, which
    is honest rather than a stub: with no anchors there is nothing to chain to."""

    anchors: tuple[Certificate, ...] = dataclasses.field(init=False, default=())
    """The parsed anchors, derived from ``anchors_pem``.

    ``init=False`` because ``__post_init__`` overwrites this unconditionally. Without
    it, ``VerifyContext(anchors=(cert,))`` CONSTRUCTED, discarded the argument, and
    reported ``signingCredential.untrusted`` on every mark forever -- silent, and
    indistinguishable from having supplied nothing. The docstring said "do not set it
    directly", which is not a mechanism. Now it is a ``TypeError`` naming the keyword.
    """

    def __post_init__(self) -> None:
        """Parse ``anchors_pem`` once, here, so a bad bundle fails immediately.

        Raises:
            ValueError: ``anchors_pem`` is not a parseable PEM bundle, or ``now`` is a
                naive datetime.
        """
        # THE SAME ASYMMETRY anchors_pem's docstring describes, in the field beside it.
        # Certificate validity is read through the timezone-AWARE accessors, so a naive
        # `now` raised TypeError from inside _chain_inside_validity -- on the
        # signature-valid path ONLY. Unmarked and corrupt text returned a verdict as
        # documented; the first genuinely good document crashed, which is the one case a
        # deployment tests least. verify() promises never to raise, and a caller error
        # belongs at construction where it is unmissable.
        #
        # NOT silently assumed to be UTC: that would make the answer depend on an
        # ambiguity the caller did not resolve, in the value deciding whether a
        # credential was live.
        if self.now is not None and self.now.tzinfo is None:
            msg = (
                "VerifyContext.now must be timezone-aware; a naive datetime cannot be compared to certificate validity"
            )
            raise ValueError(msg)
        object.__setattr__(self, "anchors", tuple(load_anchors(self.anchors_pem)))


def _hash_binding_bytes(encoded: bytes, start: int, length: int) -> bytes:
    """Apply 15.12.1.3.1 steps 5-7. Remove, then normalize, then encode.

    This is also 9.2.4 ("Hashing unstructured text assets") and A.8.7.2
    ("Normalization") in practice: the hash covers the NFC form of the visible text
    with the wrapper's byte range removed, and nothing else.

    Takes the document ALREADY ENCODED. It used to take the ``str`` and encode it
    here, which meant ``_binding_status`` -- which needs the encoded length two lines
    earlier for the suffix rule -- encoded the same document a second time and threw
    the result away. That was 10-12% of a whole verify. The offsets this function
    indexes with are UTF-8 byte offsets, so bytes are the honest argument type anyway.
    """
    remaining = encoded[:start] + encoded[start + length :]
    # The excluded range is removed from the AS-STORED bytes, so what is left may not
    # be valid UTF-8 on its own if an attacker chose the offsets. Failing here is
    # correct: a range that splits a code point is malformed, not merely wrong.
    return unicodedata.normalize("NFC", remaining.decode("utf-8")).encode("utf-8")


def _single_exclusion(hash_data: dict[str, CborValue]) -> tuple[int, int] | None:
    """Extract the sole exclusion range, or None if the assertion is malformed.

    Everything here is attacker-controlled decoded CBOR, so each step narrows
    explicitly rather than trusting the shape. Exactly ONE range is required: A.8
    places a single contiguous wrapper, so a manifest naming several is not
    something a conforming producer emits.
    """
    raw = hash_data.get("exclusions")
    if not isinstance(raw, list):
        return None
    if len(raw) != 1:
        return None

    entry = raw[0]
    if not isinstance(entry, dict):
        return None

    start = entry.get("start")
    length = entry.get("length")
    # bool before int: True would otherwise pass as 1 and describe a real range.
    if isinstance(start, bool) or isinstance(length, bool):
        return None
    if not isinstance(start, int) or not isinstance(length, int) or start < 0 or length < 0:
        return None
    return start, length


def _compare_digest(encoded: bytes, algorithm: str, start: int, length: int, expected: bytes) -> StatusCode:
    """Hash the text with the wrapper removed and compare (15.12.1.3.1 steps 5-9)."""
    try:
        digest = HASH_ALGORITHMS[algorithm](_hash_binding_bytes(encoded, start, length)).digest()
    except UnicodeDecodeError:
        # A range that splits a code point leaves invalid UTF-8. Malformed, not
        # merely mismatched.
        return StatusCode.DATA_HASH_MALFORMED
    return StatusCode.DATA_HASH_MATCH if digest == expected else StatusCode.DATA_HASH_MISMATCH


def _resolve_algorithm(structure: dict[str, CborValue], claim: dict[str, CborValue]) -> str | None:
    """Resolve the hash algorithm for one structure, or None if it is unusable.

    C2PA 15.4.1: "If no alg field is present in the hard binding assertion, the value
    of the alg field in the Claim shall be used as the hash algorithm. If no alg field
    is present in the Claim, the Claim shall be rejected with a failure code of
    algorithm.unsupported." 15.4.2 says the same for hashed_uri structures, resolving
    through "the nearest enclosing structure that contains an alg field".

    ``alg`` is OPTIONAL in both data-hash-map (18.5.2) and $hashed-uri-map (8.4.2.1),
    and we required it in both -- so a manifest using the common encoding, omitting
    the per-structure value and inheriting from the claim, read as INVALID here.

    A STRUCTURE THAT NAMES AN UNSUPPORTED ALGORITHM DOES NOT FALL BACK. Only ABSENCE
    inherits. Falling back on a named-but-unsupported value would let a producer ask
    for a weak hash and silently get a strong one, with neither party knowing which
    was used.
    """
    named = structure.get("alg")
    if named is not None:
        return named if isinstance(named, str) and named in HASH_ALGORITHMS else None

    inherited = claim.get("alg")
    if isinstance(inherited, str) and inherited in HASH_ALGORITHMS:
        return inherited
    return None


def _expected_digest(hash_data: dict[str, CborValue]) -> bytes | StatusCode:
    """The digest the hard binding declares, or the code its absence or shape earns.

    C2PA 15.12.1.1: "If the ``hash`` field is not present, then the manifest shall be
    rejected with a failure code of ``assertion.dataHash.mismatch``."

    ABSENT AND MALFORMED ARE DIFFERENT, and we collapsed them into ``malformed``. The
    specification's split is principled rather than incidental: an assertion carrying
    no ``hash`` is complete and well-formed and simply binds nothing, so the binding
    did not hold -- a mismatch. A ``hash`` present as a string, an integer, an array or
    a map is an assertion whose SYNTAX is wrong, which is what ``malformed`` names.

    Returning the digest OR a code, rather than a bool plus an out-parameter, keeps the
    narrowing at the call site: a caller that has not handled the StatusCode branch
    cannot reach bytes this function never vouched for.
    """
    if "hash" not in hash_data:
        return StatusCode.DATA_HASH_MISMATCH
    expected = hash_data["hash"]
    if not isinstance(expected, bytes):
        return StatusCode.DATA_HASH_MALFORMED
    return expected


def _binding_status(text: str, manifest: ManifestStore, matches: Sequence[WrapperMatch]) -> StatusCode:
    """Decide the single status the hard binding earns (15.12.1.3.1).

    ``matches`` is the located wrappers, PASSED IN rather than found here. This
    function used to call ``find_wrappers(text)`` on text the caller had already
    scanned, keeping only the spans -- a second full walk of the document, and of the
    selector run inside it. Re-measured 2026-08-06 against SHIPPED code, 9 repetitions:
    the second scan is 11.1% of a double-scanning verify on a 12 B document and 21.9%
    on a 1 MB one.

    THE SHORT-DOCUMENT FIGURE READ 59% AND THE PREMISE UNDER IT WAS STALE. It said
    ``_decode_run`` "traverses one code point at a time in Python", which stopped being
    true when the run was moved to a regex plus ``str.translate`` -- ``_locate`` says so
    in the same words, one file away. Under that older implementation the share was
    28.8%, still not 59%. The 1 MB figure was taken against current code and reproduces
    to a tenth of a point, which is what shows the pair was measured in two worlds.

    Required rather than defaulted to ``None``-means-rescan: a default would let a
    caller reintroduce the second walk by forgetting an argument, and there is
    exactly one caller.
    """
    hash_data = manifest.hash_data
    if hash_data is None:
        return StatusCode.CLAIM_HARD_BINDINGS_MISSING

    # 13.1 permits sha256/384/512 and states implementations "shall not support
    # additional algorithms on an optional basis"; 15.4.1 says an ABSENT alg inherits
    # the claim's.
    algorithm = _resolve_algorithm(hash_data, manifest.claim)
    if algorithm is None:
        return StatusCode.ALGORITHM_UNSUPPORTED

    expected = _expected_digest(hash_data)
    if isinstance(expected, StatusCode):
        return expected

    exclusion = _single_exclusion(hash_data)
    if exclusion is None:
        return StatusCode.DATA_HASH_MALFORMED
    start, length = exclusion

    # 15.12.1.3.1 steps 2-3: the exclusion must correspond EXACTLY to a located
    # wrapper. Without this an attacker chooses which bytes the hash covers, and
    # could exclude the part of the text they altered.
    #
    # AND the wrapper must be a SUFFIX. The exact-span check alone does not give that:
    # because the binding removes the wrapper before normalizing, composition runs
    # ACROSS the removed gap, so a canonically-equivalent re-spelling with a code-point
    # boundary at the declared start slides the wrapper into the middle of the text and
    # still matches. Demonstrated: embed("ee" with acutes) declares start=4, and
    # "ée" + wrapper + "́" also has a 4-byte prefix, so the mid-text wrapper
    # bound and verified VALID.
    #
    # Canonical equivalence bounds the visible damage, so that is not content forgery
    # by itself -- but it demolishes the invariant everything else rests on. A verifier
    # reading A.8.7.3's ordering computes DIFFERENT bytes for such a string and rejects
    # it, so an attacker could mint text we call VALID and a peer implementation calls
    # INVALID, at will. Requiring a suffix costs nothing: we only ever produce suffixes,
    # and it is what makes the two readings agree by construction.
    # BOTH CONDITIONS ARE INDEPENDENTLY LOAD-BEARING. An earlier comment here claimed
    # the suffix rule subsumed the membership test, on the strength of a mutation that
    # survived the suite. It does not: slide the wrapper one WHOLE CODE POINT earlier
    # and pad the tail to match, and `start + length == encoded_length` still holds
    # while the range names no located wrapper. With the membership test that is
    # dataHash.malformed; without it the input reaches the hash and reports
    # dataHash.mismatch -- a code that sends an investigator hunting a text edit that
    # never happened. (A one-BYTE shift really is indistinguishable, because it splits
    # U+FEFF and _compare_digest's UnicodeDecodeError branch also returns malformed.
    # That near-miss is why the first mutation looked equivalent.)
    #
    # The membership test is 15.12.1.3.1 step 3; the suffix rule is ours. Guarded by
    # test_the_exclusion_must_name_a_located_wrapper_not_merely_be_trailing.
    # ONE encode, used for both the suffix rule and the hash. Taking the length from
    # a throwaway encode here and letting _hash_binding_bytes encode again below cost
    # 14.0% of a whole verify at 1 MB and 0.4% at 12 B -- a 35x spread, because the
    # duplicated work is proportional to the document and nothing else is. This read
    # "10-12% ... on a document of ANY SIZE", and the size-invariance was the false part.
    encoded = text.encode("utf-8")
    spans = {(match.span.utf8_start, len(match.span)) for match in matches}
    if (start, length) not in spans or start + length != len(encoded):
        return StatusCode.DATA_HASH_MALFORMED

    return _compare_digest(encoded, algorithm, start, length, expected)


#: Everything certificate handling may throw at us. UnsupportedAlgorithm is the one
#: that is easy to miss: it is NOT a ValueError, so an x5chain leaf whose
#: SubjectPublicKeyInfo names an OID `cryptography` does not implement escaped a
#: plain `except ValueError` and propagated out of verify(). A truncated DER, by
#: contrast, raises ValueError and was always caught -- which is exactly why the gap
#: was narrow enough to survive.
#:
#: THIS TUPLE IS NOT THE WHOLE SET AND CANNOT BE. Enumerating it has now failed three
#: times: a one-byte edit to a valid mark produced `InvalidVersion`, `KeyError` and
#: `DuplicateExtension`, none of them a ValueError and two of them descending straight
#: from Exception. Use it where the operation is a single narrow call; use
#: :func:`_load_chain` where attacker DER is parsed.
CERTIFICATE_ERRORS = (ValueError, UnsupportedAlgorithm)


def _load_chain(ders: list[bytes]) -> list[Certificate] | None:
    """Parse attacker-supplied DER into certificates, or None if any of it is malformed.

    THE HOSTILE PARSE BOUNDARY, and it is the only place in the package that catches
    ``Exception``. Two facts force that, and neither is a matter of taste.

    ``cryptography`` PARSES LAZILY. ``load_der_x509_certificate`` accepts bytes that
    only fail when a field is read, so the failure surfaces at an ATTRIBUTE ACCESS
    somewhere downstream -- ``certificate.issuer`` raising ``KeyError`` from inside
    ``trust.py``, a hundred lines and two modules from the ``try`` that was watching the
    load. Probing every field here is what pulls those failures back to one place.

    AND ITS EXCEPTION SET FOR MALFORMED INPUT IS NOT DOCUMENTED OR CLOSED. Measured on a
    single valid mark with one byte changed: ``ValueError``, ``KeyError``,
    ``InvalidVersion``, ``DuplicateExtension``, ``UnsupportedAlgorithm`` -- and a
    ``TypeError``, found by dropping the ``issuer`` probe and re-fuzzing. Two of those
    inherit directly from ``Exception``, so no tuple of base classes covers them, and
    the next release of a dependency may add a seventh. ``verify`` promises never to raise
    on attacker input -- a promise this package makes in eight places and that
    integrators are told to rely on by catching ``C2paTextError`` alone -- and a promise
    that broad cannot be kept by a list that has to be complete.

    The narrowness is bought back by SCOPE rather than by exception type: nothing here
    does anything but parse and read, so there is no operation whose bug this could
    mask. A failure means the credential is unreadable, which is a verdict.

    THE PROBE LIST MUST COVER EVERY FIELD THE PACKAGE LATER READS. It is the whole
    mechanism: a field read downstream but not probed here can still raise from outside
    this boundary. Guarded by
    ``tests/test_regressions.py::test_hostile_certificate_bytes_do_not_escape_verify``.
    """
    chain: list[Certificate] = []
    try:
        for der in ders:
            certificate = load_der_x509_certificate(der)
            # Force the lazy parse of every field read anywhere in this package --
            # `_verify` and `trust` between them touch all of these.
            _ = (
                certificate.version,
                certificate.issuer,
                certificate.subject,
                certificate.not_valid_before_utc,
                certificate.not_valid_after_utc,
                certificate.signature_algorithm_oid,
                certificate.tbs_certificate_bytes,
                certificate.extensions,
                # A CALL, not an attribute, and read downstream at `chain[0].public_key()`.
                # It was left out on the reasoning that its failures are ValueError and
                # UnsupportedAlgorithm, which `_accept_credential` catches -- which is
                # exactly the reasoning that failed three times before. An RSA or GOST
                # SPKI OID, a 31-byte Ed25519 key and an unknown EC curve all pass every
                # probe above and raise here.
                certificate.public_key(),
            )
            chain.append(certificate)
    except Exception:  # noqa: BLE001 -- the boundary this function exists to be; see the docstring
        return None
    return chain


#: RFC 3986 scheme production. Any scheme at all, deliberately -- 15.10.3.3 scopes
#: external work to "a hashed_ext_uri whose resource the validator CHOOSES to
#: retrieve", and we choose to retrieve none of them, so singling out https would be
#: inventing a distinction the clause does not draw.
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")

_SELF_JUMBF = "self#jumbf="

#: The store section holding data boxes (10.2.3.2). We do not implement them, and this
#: constant exists so a reference INTO them can be passed over rather than mistaken for
#: an assertion URI that failed to resolve.
_DATA_BOX_SEGMENT = "c2pa.databoxes"
_ASSERTION_URI_PREFIX = ASSERTION_URI_PREFIX

#: The store-relative form's fixed parts: `self#jumbf=/c2pa/<manifest>/c2pa.assertions/<label>`.
_STORE_URI_PREFIX = f"{_SELF_JUMBF}/{LABEL_MANIFEST_STORE}/"
_ASSERTION_STORE_SEGMENT = LABEL_ASSERTION_STORE


def _assertion_label(url: str, manifest_label: str) -> str | None:
    """Resolve an assertion URI to its label, or None if it does not name one here.

    C2PA 8.4.2.1: "These self#jumbf URIs may be relative to the entire C2PA Manifest
    Store, in which case they shall start with a `/`, or relative to the current C2PA
    Manifest." Both forms are accepted:

        self#jumbf=c2pa.assertions/<label>                     manifest-relative
        self#jumbf=/c2pa/<manifest-label>/c2pa.assertions/<label>   store-relative

    The specification's own Example 1 uses the second, and we accepted only the first
    -- so a conforming manifest read as INVALID.

    THE STORE-RELATIVE FORM IS NOT MERELY A LONGER PREFIX: it names a manifest, and
    that manifest must be THIS one. Widening the prefix test instead of parsing the
    label would let a claim point at a DIFFERENT manifest's assertion, which is
    exactly what ``assertion.outsideManifest`` exists to catch. Returning None here
    produces that code.
    """
    if url.startswith(_ASSERTION_URI_PREFIX):
        label = url[len(_ASSERTION_URI_PREFIX) :]
        return label or None

    if not url.startswith(_STORE_URI_PREFIX):
        return None

    # <manifest-label>/c2pa.assertions/<label>. The label may itself contain no '/',
    # since 11.1.4.1.1 forbids it, so a plain split is unambiguous.
    remainder = url[len(_STORE_URI_PREFIX) :]
    parts = remainder.split("/")
    expected = 3
    if len(parts) != expected or parts[1] != _ASSERTION_STORE_SEGMENT:
        return None
    if parts[0] != manifest_label:
        return None
    return parts[2] or None


def _signature_uri_resolves(url: str, manifest_label: str) -> bool:
    """Does the claim's ``signature`` URI name the signature box of THIS manifest?

    C2PA 15.7: "The validator shall retrieve the URI reference for the signature from
    the value of the claim's `signature` field and resolve the URI reference to obtain
    the COSE signature. If the signature field is not present, or the URI cannot be
    resolved, or the URI does not resolve to a location within the same C2PA Manifest
    box (as the claim), then the claim shall be rejected with a failure code of
    `claimSignature.missing`."

    We took the signature box found BY LABEL during the parse and never read the
    claim's field beyond the 15.6.2 presence check, so a claim naming
    ``https://evil.example/sig`` -- or naming another manifest's signature -- still
    verified against the box we happened to hold.

    THAT IS NOT EXPLOITABLE TODAY and is still worth closing. The URI sits inside the
    signed claim bytes, and our stores carry exactly one signature box, so an attacker
    can neither rewrite the field nor supply a second box for us to be redirected to.
    The check is load-bearing the moment a second COSE box becomes reachable -- an
    update manifest, an ingredient, a compressed manifest store -- and at that point
    nothing would announce that the guard had never existed. The cost of having it now
    is one string comparison.
    """
    if url == CLAIM_SIGNATURE_URI:
        return True
    if not url.startswith(_STORE_URI_PREFIX):
        return False
    parts = url[len(_STORE_URI_PREFIX) :].split("/")
    expected = 2
    return len(parts) == expected and parts[0] == manifest_label and parts[1] == LABEL_CLAIM_SIGNATURE


#: Assertions the claim MUST commit to for a mark to mean anything. The hard binding
#: is what ties the claim to the text; the AI disclosure is the single fact an EU AI
#: Act Article 50(2) mark exists to carry; and the actions assertion is where
#: ``digitalSourceType`` lives, which is the field that actually says a model made this
#: (18.15.2 requires it in created_assertions). A manifest that authenticates none of
#: the three is well-formed and says nothing.
#: EXACT LABELS, not 6.4's ``__N`` instances -- so a store whose actions assertion
#: exists only as ``c2pa.actions.v2__1``, with no base label, reports
#: ``assertion.missing``. That is deliberate: 6.4 introduces the suffix as a way to add
#: FURTHER assertions of a type ("c2pa.metadata, c2pa.metadata__1 and c2pa.metadata__2"),
#: so an instance without its base is not a shape the convention describes. It is
#: recorded here because the same labels ARE read through ``__N`` elsewhere -- by
#: ``_actions_labels`` and ``_count_hard_bindings`` -- and one rule with two grammars is
#: the kind of thing that looks like an oversight when it is a choice.
#:
#: Each entry is the set of labels that SATISFIES one requirement, not a single label.
#: The actions requirement takes either version: 15.10.3.2.3 and Table 7 both name the
#: pair, and requiring v2 alone rejected a conforming v1 manifest as assertion.missing.
_REQUIRED_ASSERTIONS: tuple[frozenset[str], ...] = (
    frozenset({ASSERTION_HASH_DATA}),
    frozenset({ASSERTION_AI_DISCLOSURE}),
    frozenset({ASSERTION_ACTIONS, ASSERTION_ACTIONS_V1}),
)


#: C2PA 15.6.2: "If any are absent, then the claim shall be rejected with a failure
#: code of claim.malformed." Listed there verbatim -- this is not our shortlist.
_REQUIRED_CLAIM_FIELDS = ("instanceID", "signature", "created_assertions", "claim_generator_info")


def _claim_malformed(claim: dict[str, CborValue]) -> bool:
    """Apply 15.6.2's required-field check.

    manifest.py's Claim docstring has always SAID these are "enforced on read by
    15.6.2", and nothing enforced them: a claim with no instanceID verified happily.
    A docstring describing behaviour the module does not have is worse than silence,
    because a reviewer reads it and stops looking.

    15.6.2 also requires claim_generator_info to contain a ``name``, and the field to
    be a MAP -- claim-map-v2 declares ``$generator-info-map``, singular, where v1
    declared an array. An array here is malformed for a c2pa.claim.v2 box.
    """
    if any(field not in claim for field in _REQUIRED_CLAIM_FIELDS):
        return True
    generator = claim.get("claim_generator_info")
    if not isinstance(generator, dict):
        return True
    return not isinstance(generator.get("name"), str)


def _assertion_links(
    claim: dict[str, CborValue],
) -> tuple[list[dict[str, CborValue]], list[dict[str, CborValue]]] | None:
    """Extract ``(created_assertions, gathered_assertions)``, or None if malformed.

    ``claim-map-v2`` declares both:

        "created_assertions": [1* $hashed-uri-map],
        ? "gathered_assertions": [1* $hashed-uri-map],

    So ``created_assertions`` is required and non-empty, and ``gathered_assertions`` is
    OPTIONAL BUT NON-EMPTY IF PRESENT -- an empty array is malformed rather than
    equivalent to omitting the field.

    WE READ ONLY THE FIRST ARRAY UNTIL 2026-08-05, and 15.10.3.1 covers both: "Even though the assertions
    listed in the gathered_assertions field were not created by the claim generator,
    they are still part of the Claim and are therefore also validated according to this
    validation algorithm." A conforming manifest whose extra assertion was gathered was
    rejected as undeclared -- and the two lists are returned SEPARATELY rather than
    concatenated because only the created list may satisfy the required-assertion and
    actions rules.
    """
    created = _hashed_uri_list(claim.get("created_assertions"))
    if created is None:
        return None
    if "gathered_assertions" not in claim:
        return created, []
    gathered = _hashed_uri_list(claim["gathered_assertions"])
    if gathered is None:
        return None
    return created, gathered


def _hashed_uri_list(raw: CborValue) -> list[dict[str, CborValue]] | None:
    """One ``[1* $hashed-uri-map]`` array, or None if it is not one."""
    if not isinstance(raw, list) or not raw:
        return None
    links: list[dict[str, CborValue]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            return None
        # CBOR permits int and bytes map keys; a hashed-uri-map uses text keys, and a
        # non-text key is not addressable by name. Narrowing here rather than at each
        # lookup keeps the attacker-controlled shape checked in exactly one place.
        links.append({key: value for key, value in entry.items() if isinstance(key, str)})
    return links


#: Digests computed during ONE call, keyed by ``(label, algorithm)``.
DigestCache = dict[tuple[str, str], bytes]


def _assertion_digest(label: str, algorithm: str, manifest: ManifestStore, cache: DigestCache) -> bytes:
    """Hash one assertion's raw bytes, at most once per algorithm per call.

    WITHOUT THIS, A MANIFEST NOBODY SIGNED CHOOSES HOW MUCH WORK WE DO. ``verify``
    calls ``_check_assertions`` BEFORE ``_check_signature``, so every digest here is
    computed on the word of an attacker holding no credential at all -- and two
    structures let one target be named many times: ``created_assertions`` is never
    de-duplicated, and an actions assertion may carry any number of icon references
    (15.10.3.3). Measured against a 1 MiB assertion: 500 references cost 0.22 s of CPU,
    4000 cost 1.72 s, all returning success. Inside the 2 MiB manifest budget an
    attacker fits roughly 11,000 references beside a 1 MiB assertion, which is about
    11 GiB of hashing from one 2 MiB input.

    MEMOIZATION RATHER THAN A CAP. A cap would be a policy guess about how many
    references a conforming producer may legitimately write, and getting that guess
    wrong rejects valid manifests -- the failure mode this package treats as equal in
    weight to accepting invalid ones. Hashing identical bytes under an identical
    algorithm twice cannot change the answer, so caching bounds the work at the store's
    own size (three algorithms times the 2 MiB limit, worst case) while accepting and
    rejecting exactly what it did before.

    Keyed by LABEL rather than by the bytes, because both callers resolve a label
    first, and hashing the key would cost the scan the cache exists to avoid.
    """
    key = (label, algorithm)
    digest = cache.get(key)
    if digest is None:
        digest = HASH_ALGORITHMS[algorithm](manifest.assertion_bytes[label]).digest()
        cache[key] = digest
    return digest


def _link_status(
    link: dict[str, CborValue], manifest: ManifestStore, cache: DigestCache
) -> tuple[StatusCode, str | None]:
    """Check one hashed-uri-map. Returns its status and the label it resolved to."""
    url = link.get("url")
    expected = link.get("hash")
    if not isinstance(url, str) or not isinstance(expected, bytes):
        return StatusCode.CLAIM_MALFORMED, None
    # 15.4.2: an absent alg resolves through the enclosing structure to the claim.
    algorithm = _resolve_algorithm(link, manifest.claim)
    if algorithm is None:
        return StatusCode.ALGORITHM_UNSUPPORTED, None
    label = _assertion_label(url, manifest.manifest_label)
    if label is None:
        # 15.10.3.1 gives this its OWN code, distinct from assertion.missing: "If the
        # URI does not refer to a location within the same C2PA Manifest (a
        # self#jumbf location), the claim shall be rejected with a failure code of
        # assertion.outsideManifest." Reporting `missing` here would tell a caller
        # their assertion is absent when the claim in fact pointed somewhere we will
        # never follow -- resolving it would mean fetching an attacker-named URL.
        return StatusCode.ASSERTION_OUTSIDE_MANIFEST, None
    if label not in manifest.assertion_bytes:
        return StatusCode.ASSERTION_MISSING, None
    if _assertion_digest(label, algorithm, manifest, cache) != expected:
        return StatusCode.ASSERTION_HASHED_URI_MISMATCH, None
    return StatusCode.ASSERTION_HASHED_URI_MATCH, label


def _reference_status(
    reference: dict[str, CborValue], manifest: ManifestStore, cache: DigestCache
) -> StatusCode | None:
    """Apply C2PA 15.10.3.3, "Validation of References", to one ``hashed_uri``.

    Returns the failure code, or None if the reference is satisfied or is one we
    deliberately do not follow.

    15.10.3.3: "The destination of a hashed_uri is found in its url field. If the field
    is not present or the destination cannot be located (i.e., that data isn't present
    where it is supposed to be) then it shall be treated as a validation failure with
    code hashedURI.missing... Ensure that the hash field is present in the hashed_uri
    structure. If it is not, the claim shall be rejected with a failure code of
    hashedURI.mismatch... Compare the computed hash value with the value in the hash
    field. If they do not match, the claim shall be rejected with a failure code of
    hashedURI.mismatch."

    SEPARATE FROM ``_link_status`` ON PURPOSE, though the arithmetic is nearly the
    same. That function implements 15.10.3.1, which walks the claim's
    ``created_assertions`` and reports ``assertion.*`` codes; this implements
    15.10.3.3, which walks references INSIDE structures and reports the unprefixed
    ``hashedURI.*`` pair. The specification keeps both sets in its status table, and
    telling an operator "an assertion is missing" when a generator icon failed to
    resolve names the wrong object. Merging them would mean choosing one clause's codes
    for both clauses' conditions.

    It can also return ``algorithm.unsupported``, by way of 15.4's resolution, which the
    clause folds in with "any possible failure codes".

    NO SUCCESS CODE IS RECORDED. 15.10.3.1 names ``assertion.hashedURI.match`` for its
    own path; 15.10.3.3 names none, and inventing one would put a code in a verdict
    that no clause authorizes.

    AN EXTERNAL REFERENCE IS PASSED OVER, not failed. The clause scopes external work
    to "a hashed_ext_uri whose resource the validator chooses to retrieve", and this
    package never touches the network -- a verifier whose answer depends on network
    conditions, or on whoever controls an endpoint, is not the offline verifier it
    claims to be.
    """
    url = reference.get("url")
    if not isinstance(url, str):
        return StatusCode.HASHED_URI_MISSING
    if not url.startswith(_SELF_JUMBF):
        # AN EXTERNAL REFERENCE IS ONE WITH A URI SCHEME, which is what makes it
        # fetchable at all. The earlier test was "does not start with self#jumbf=",
        # which is far wider than the escape it was written for: an empty string, a
        # relative path with the prefix missing, a truncated prefix and a miscased one
        # were all being read as "an external resource we chose not to retrieve". None
        # of them is one, and 15.10.3.3 covers them -- "if the field is not present OR
        # THE DESTINATION CANNOT BE LOCATED ... hashedURI.missing".
        #
        # The divergence was inside this file: _link_status, implementing 15.10.3.1 on
        # identical input, returns assertion.outsideManifest for those same strings.
        return None if _SCHEME.match(url) else StatusCode.HASHED_URI_MISSING

    # A DESTINATION IN A STORE SECTION WE DO NOT IMPLEMENT IS PASSED OVER, on the same
    # authority as an external reference: it is a resource we decline to resolve, not
    # one we looked for and failed to find.
    #
    # 10.2.3.2 says "Manifest Consumers SHOULD ALSO SUPPORT the data box approach
    # recommended by earlier versions of this specification". We do not. Declining a
    # SHOULD is legitimate; escalating that decision into a rejection of the whole
    # claim is not, and that is what happened -- self#jumbf=c2pa.databoxes/c2pa.icon
    # reached _assertion_label, which knows only c2pa.assertions, and became
    # hashedURI.missing, which 15.10.3.3 turns into a rejected claim.
    # The tail must be NON-EMPTY, exactly as _assertion_label does `return label or
    # None`: "self#jumbf=c2pa.databoxes/" names no destination at all, and passing it
    # over would let a reference that resolves to nothing be treated as one we chose
    # not to follow. The trailing "/" in the prefix is also load-bearing -- without it
    # "c2pa.databoxesEVIL/x" would match.
    data_box_prefix = f"{_SELF_JUMBF}{_DATA_BOX_SEGMENT}/"
    if url.startswith(data_box_prefix) and url[len(data_box_prefix) :]:
        return None

    label = _assertion_label(url, manifest.manifest_label)
    if label is None or label not in manifest.assertion_bytes:
        return StatusCode.HASHED_URI_MISSING

    algorithm = _resolve_algorithm(reference, manifest.claim)
    if algorithm is None:
        return StatusCode.ALGORITHM_UNSUPPORTED

    # "Ensure that the hash field is PRESENT." A hash present as something other than
    # bytes is folded in here rather than given a code of its own: the clause names
    # none for it, and a non-bytes hash is one no computed digest can equal, so
    # mismatch states the outcome without inventing a condition.
    expected = reference.get("hash")
    matches = isinstance(expected, bytes) and _assertion_digest(label, algorithm, manifest, cache) == expected
    return None if matches else StatusCode.HASHED_URI_MISMATCH


def _claim_references(claim: dict[str, CborValue]) -> list[dict[str, CborValue]]:
    """Every reference in the claim that 15.6.2 obliges us to validate.

    15.6.2: "If there is an icon field in the generator-info-map referenced by the
    claim_generator_info field of the claim-map or claim-map-v2, then its value shall
    be validated as described in Section 15.10.3.3, Validation of References."

    We do not EMIT an icon, so this is read-side only. It still matters: a third
    party's claim may carry one, and a manifest we call VALID must not contain a
    reference we never checked.
    """
    return _generator_icon(claim.get("claim_generator_info"))


def _generator_icon(generator: CborValue) -> list[dict[str, CborValue]]:
    """The ``icon`` of one generator-info-map, as a list of zero or one reference.

    A list rather than an Optional because every caller concatenates: the claim has
    one generator-info-map, an action may have one or many, and returning the same
    shape from each keeps the collection a single flat comprehension.
    """
    if not isinstance(generator, dict):
        return []
    icon = generator.get("icon")
    if not isinstance(icon, dict):
        return []
    return [{key: value for key, value in icon.items() if isinstance(key, str)}]


def _action_references(payload: CborValue) -> list[dict[str, CborValue]]:
    """Every reference an actions assertion carries that 15.10.3.2.3 obliges us to check.

    15.10.3.2.3: "If there is a softwareAgent field in the action-common-map-v2 or one
    or more softwareAgents listed in the softwareAgents field of the actions-map-v2:
    If there is an icon field in the generator-info-map, then it shall be validated as
    described in Section 15.10.3.3." And: "For each template in the templates list: If
    there is an icon field in the action-template-map-v2, then it shall be validated as
    described in Section 15.10.3.3."

    THE SAME THREE CODES REACH US BY A SECOND ROUTE. The claim generator's icon
    (15.6.2) is the site that made the procedure necessary; these are the sites that
    make it worth having as a function rather than as a branch.

    ``parameters.relatedAssertions`` is the one reference site NOT collected here. Its
    rule in the same clause is not only a 15.10.3.3 validation -- it also constrains
    the array's shape and forbids the referenced assertion from being an ingredient or
    an actions assertion, both reported as ``assertion.action.malformed``. Those are
    actions-validation rules rather than reference rules, and half-implementing them
    would leave a claim that we report as fully checked and are not. Recorded in
    docs/c2pa-compatibility.md.

    Everything read here is attacker-controlled CBOR, so each level narrows explicitly.
    """
    if not isinstance(payload, dict):
        return []
    references: list[dict[str, CborValue]] = []
    # softwareAgent lives on each ACTION (action-common-map-v2) while softwareAgents is
    # a list on the ASSERTION (actions-map-v2). Different fields at different depths,
    # so neither can stand in for the other. An action's softwareAgent may also be an
    # integer INDEX into softwareAgents rather than a map; _generator_icon returns
    # nothing for it, and the map it indexes is already walked below.
    agents = [action.get("softwareAgent") for action in _as_list(payload.get("actions")) if isinstance(action, dict)]
    for agent in (*agents, *_as_list(payload.get("softwareAgents"))):
        references.extend(_generator_icon(agent))
    for template in _as_list(payload.get("templates")):
        references.extend(_generator_icon(template))
    return references


def _as_list(value: CborValue) -> list[CborValue]:
    """``value`` if it is a list, else empty. A non-list is not iterated by mistake."""
    return value if isinstance(value, list) else []


def _count_hard_bindings(assertion_bytes: dict[str, bytes]) -> int:
    """Count hard-binding assertions, honouring C2PA 6.4's instance convention.

    6.4: "Multiple assertions of the same type can occur in the same manifest... This
    is accomplished by adding a double-underscore and a monotonically increasing index
    to the label. For example... c2pa.metadata, c2pa.metadata__1 and c2pa.metadata__2."

    15.10.1.2 requires exactly one hard binding. ``ManifestStore.hash_data`` looks up
    the EXACT label, so a second binding under ``__N`` was invisible -- the verifier
    bound against the first and ignored the rest, which is the "different consumers
    read different claims" failure refused elsewhere in this package.

    The suffix must be a double underscore followed by digits. ``c2pa.hash.dataX`` and
    ``c2pa.hash.data_1`` are DIFFERENT assertions, not instances, and counting them
    would reject manifests that are fine.
    """
    return len(_label_instances(ASSERTION_HASH_DATA, list(assertion_bytes)))


def _resolve_labels(
    links: list[dict[str, CborValue]], manifest: ManifestStore, cache: DigestCache
) -> list[str] | StatusCode:
    """Resolve every link to its label IN ORDER, or return the first failing code.

    A list rather than a set because 15.10.3.2.3 defines "the first actions assertion"
    against the claim's array, so link order is part of a rule rather than an incidental
    property of how we iterate.
    """
    labels: list[str] = []
    for link in links:
        code, label = _link_status(link, manifest, cache)
        if label is None:
            return code
        labels.append(label)
    return labels


def _assertion_failure(manifest: ManifestStore) -> tuple[StatusCode, str | None] | None:
    """The first way the assertion store fails to answer for the claim, or None.

    Split from :func:`_check_assertions` so the verdict-building stays in one place and
    each step here can simply return the code it earned. The ORDER is the contract:
    claim shape, then every link, then the store as a whole, then the references --
    so a manifest missing its disclosure is reported as missing its disclosure rather
    than as having a bad generator icon.
    """
    if _claim_malformed(manifest.claim):
        return StatusCode.CLAIM_MALFORMED, "the claim is missing a field 15.6.2 requires"

    arrays = _assertion_links(manifest.claim)
    if arrays is None:
        return (
            StatusCode.CLAIM_MALFORMED,
            "created_assertions and gathered_assertions must each be a non-empty list of maps",
        )
    created, gathered = arrays

    # ONE cache for the whole call. Every structure below can name the same target, so
    # scoping it per-loop would leave most of the hash amplification standing.
    cache: DigestCache = {}

    # ORDERED lists, not sets: 15.10.3.2.3 defines "the first actions assertion" against
    # the created_assertions array, so link order is part of a rule. Gathered assertions
    # are authenticated by the SAME hashed URI as created ones -- declaring an assertion
    # is not trusting it, and 15.10.3.1 applies one algorithm to both -- and are kept
    # apart only because the required-assertion set and the actions rules are defined
    # against created_assertions alone.
    claim_order = _resolve_labels(created, manifest, cache)
    if isinstance(claim_order, StatusCode):
        return claim_order, None
    gathered_order = _resolve_labels(gathered, manifest, cache)
    if isinstance(gathered_order, StatusCode):
        return gathered_order, None

    # 15.6.2 routes the claim generator's icon through 15.10.3.3, and 15.10.3.2.3 routes
    # an action's softwareAgent and template icons through the same clause. Evaluated
    # lazily, AFTER the store's own shape, so a manifest missing its disclosure is
    # reported as missing its disclosure rather than as having a bad generator icon.
    # EVERY actions assertion, not just the base label: 6.4's __N instances each carry
    # their own softwareAgent and templates, so reading one label left a poisoned icon
    # in c2pa.actions.v2__1 unchecked while the same file already counted __N instances
    # for the hard binding.
    # A GENERATOR, not a list, and the labels are DEDUPED. Built as a list this was a
    # pre-authentication quadratic in CPU and memory. `claim_order` keeps duplicates,
    # so a claim naming the actions label N times called _action_references N times on
    # the SAME assertion, each call returning M icon references and allocating M dicts.
    # N and M are independent and both attacker-chosen, so the cost was their PRODUCT:
    # a 502 KB store cost 4.9 s and 2.17 GB, and the 2 MiB MAX_MANIFEST_LENGTH ceiling
    # extrapolates to an OOM -- which would make the body-size cap constants.py tells
    # integrators to apply insufficient on its own.
    #
    # BOTH HALVES ARE LOAD-BEARING, and this comment briefly said otherwise. The
    # generator restores the ordering the comment above claims, so _store_shape_status
    # runs BEFORE anything is collected. The dedupe bounds the work for a store that
    # PASSES the shape rules, and such a store can carry a repeated actions label:
    # _actions_status asks labels[1:] only whether it CONTAINS an inception action, so a
    # 6.4 __1 instance holding c2pa.edited may be linked N times and pass every rule.
    # Measured with the dedupe removed, N=M of 400/800/1600 -- stores of 67/134/268 KB,
    # since the store grows with N and M -- costs 0.293/1.186/4.766 s against
    # 0.032/0.062/0.121 s with it. x4 per doubling, the same quadratic, still before any
    # signature is checked.
    #
    # The dedupe cannot change a verdict: `assertions.get(label)` returns the same
    # assertion for a repeated label, so a second walk can only reach the answer the
    # first one did. And 15.10.3.2.3 defines position by FIRST occurrence, which is what
    # dict.fromkeys preserves. tests/test_regressions.py asserts the walk count for both
    # halves: ZERO for a store the shape check rejects, and one per DISTINCT label for
    # one it accepts.
    references = itertools.chain(
        _claim_references(manifest.claim),
        (
            reference
            for label in dict.fromkeys(_actions_labels(claim_order))
            for reference in _action_references(manifest.assertions.get(label))
        ),
    )
    code = _store_shape_status(manifest, claim_order, gathered_order) or next(
        (status for reference in references if (status := _reference_status(reference, manifest, cache)) is not None),
        None,
    )
    return None if code is None else (code, None)


def _check_assertions(manifest: ManifestStore, verdict: Verdict) -> tuple[Verdict, bool]:
    """Authenticate the assertion store against the claim (C2PA 15.10.3.1, 8.4.2.3).

    WITHOUT THIS THE ASSERTION STORE IS UNSIGNED. The COSE signature covers the CLAIM
    only. The claim commits to each assertion by a ``hashed-uri-map`` -- a URL plus a
    digest -- so an assertion is authenticated only once that digest is recomputed
    over the bytes that actually arrived and compared. Skip it and an attacker who
    holds ONE sample of marked text can keep the claim and signature byte-for-byte,
    swap in a ``c2pa.hash.data`` naming their own digest, and mint arbitrary text
    under the victim's credential -- escalating to TRUSTED wherever that certificate
    chains to an anchor. Demonstrated, then closed; see
    ``tests/test_verify.py::test_swapping_the_assertion_store_does_not_verify``.

    Every required assertion must be present, linked, and hash-matched. Absence is
    treated exactly like a mismatch: a claim committing to a disclosure the store
    does not contain has not disclosed anything.
    """
    failure = _assertion_failure(manifest)
    if failure is not None:
        code, explanation = failure
        return verdict._add(code, explanation), False
    return verdict._add(StatusCode.ASSERTION_HASHED_URI_MATCH), True


#: 15.10.1.2's "inception" actions: an asset is either newly created, or opened from
#: something that already existed.
_INCEPTION_ACTIONS = frozenset({"c2pa.created", "c2pa.opened"})


def _has_single_inception_action(payload: CborValue) -> bool:
    """Whether an actions assertion carries exactly one c2pa.created or c2pa.opened.

    C2PA 15.10.1.2: "Validate that either a c2pa.created or c2pa.opened action is
    contained in exactly one actions assertion."

    This is not only conformance. The c2pa.created action is where
    ``digitalSourceType = trainedAlgorithmicMedia`` lives -- the field that actually
    says a model generated this text. Without the check, a manifest with no created
    action, or with the action rewritten to c2pa.edited, verified VALID while
    asserting nothing about machine origin.

    THE POSITION IS PART OF THE RULE, and 15.10.3.2.3 is where it and the failure code
    both live: "If the action field is either c2pa.created or c2pa.opened, then the
    claim shall be rejected with a failure code of assertion.action.malformed unless
    all of the following are true: the assertion is the first actions assertion in the
    created_assertions or gathered_assertions array (of a v2 claim), or the first
    actions assertion in the assertions array of a v1 claim, and the action is the
    first element in the actions array in this assertion."

    THE ELISION THERE WAS NOT NEUTRAL. The "..." stood exactly where "or the first
    actions assertion in the assertions array of a v1 claim" belongs, so the quotation
    read as if the clause named only the arrays we check. We check created_assertions
    ONLY; that is deviation 25, not something the clause says.

    So "both created and opened" and "two created" fail because the SECOND inception
    action cannot be first, and an actions array beginning c2pa.edited fails for the
    same reason -- an asset cannot be edited before it exists. An earlier version of
    this docstring justified the strictness as our own reading of "exactly one"; the
    specification states it outright, and presenting a spec rule as our judgement is
    the overclaim this repository exists to avoid.

    The "first actions ASSERTION" half of the clause needs the claim's link order and
    lives in ``_actions_status``.

    Everything here is attacker-controlled CBOR, so each level narrows explicitly.
    """
    if not isinstance(payload, dict):
        return False
    entries = payload.get("actions")
    if not isinstance(entries, list):
        return False

    if not entries or not all(isinstance(entry, dict) for entry in entries):
        return False
    # No inception action may appear anywhere but first. 15.10.3.2.3: the action must be
    # "the first element in the actions array in this assertion", so a second one -- or a
    # first one preceded by an edit -- is malformed. An asset cannot be edited before it
    # exists.
    if any(entry.get("action") in _INCEPTION_ACTIONS for entry in entries[1:] if isinstance(entry, dict)):
        return False
    first = entries[0]
    if not isinstance(first, dict) or first.get("action") not in _INCEPTION_ACTIONS:
        return False
    # 18.15.6.1's overlay, before presence is tested: a template may supply
    # digitalSourceType for all actions or for one by name, and the specification's own
    # Example 9 does exactly that while the actions carry none.
    templates = payload.get("templates")
    first = _overlaid_action(first, templates if isinstance(templates, list) else [])
    # 18.15: "For all assets, a corresponding digitalSourceType field, with an
    # appropriate value, shall be recorded with the c2pa.created action, to indicate the
    # nature of the asset at its inception." The clause exempts the other inception
    # action in the next sentence -- "No digitalSourceType field is required in
    # conjunction with a c2pa.opened action" -- so the requirement attaches to
    # c2pa.created alone. That sentence is a NOTE admonition rather than a numbered rule,
    # which is worth knowing: we are reading a non-normative note as scoping a shall,
    # and 18.15.2 is the clause number, not 18.15.
    #
    # PRESENCE AND TYPE ONLY. "An appropriate value" names just the empty-content case
    # explicitly; the vocabulary is IPTC's plus c2pa.org's, and demanding membership of
    # a list we vendor would reject a conforming producer using a term we have not heard
    # of. Without this check the mark asserted machine origin by its label and nothing
    # by its content, while manifest.py called this field "the single fact the mark
    # exists to carry".
    return first.get("action") != "c2pa.created" or isinstance(first.get("digitalSourceType"), str)


def _label_instances(base: str, labels: list[str]) -> list[str]:
    """Every instance of ``base`` in ``labels``, honouring C2PA 6.4's convention.

    6.4: "Multiple assertions of the same type can occur in the same manifest... by
    adding a double-underscore and a monotonically increasing index to the label."

    ONE GRAMMAR, ONE PLACE. It was written three times before -- for hard bindings, for
    actions, and not at all for the AI disclosure, which is how a second
    ``c2pa.ai-disclosure__1`` asserting nothing came to verify VALID. The suffix must be
    a double underscore followed by digits: ``c2pa.metadataX`` and ``c2pa.metadata_1``
    are DIFFERENT assertions, not instances, and counting them would reject manifests
    that are fine.
    """
    prefix = f"{base}__"
    return [label for label in labels if label == base or (label.startswith(prefix) and label[len(prefix) :].isdigit())]


def _overlaid_action(action: dict[int | str | bytes, CborValue], templates: list[CborValue]) -> dict[str, CborValue]:
    """One action with its templates overlaid, per C2PA 18.15.6.1.

    18.15.6.1: "These values are combined by a C2PA Manifest Consumer with actions of the
    same name, or with all actions (if the value of the action field is the `*` special
    value), to get a full picture of an action... A C2PA Manifest Consumer SHALL take the
    values from the template and overlay the values from the action itself."

    So the template supplies defaults and the action wins where both carry a field.
    ``action-template-map-v2`` includes ``action-common-map-v2``, which is where
    ``digitalSourceType`` is declared -- and the specification's OWN Example 9 puts it
    on a ``*`` template while the actions carry none. Reading presence without the
    overlay rejected that example.
    """
    name = action.get("action")
    overlaid: dict[str, CborValue] = {}
    for template in templates:
        if not isinstance(template, dict):
            continue
        target = template.get("action")
        # Compared one at a time rather than against a set: a CBOR value need not be
        # hashable, and the decoder can hand us a list or a map where a name belongs.
        if target == "*" or (isinstance(name, str) and target == name):
            overlaid.update({key: value for key, value in template.items() if isinstance(key, str)})
    overlaid.update({key: value for key, value in action.items() if isinstance(key, str)})
    return overlaid


def _contains_inception(payload: CborValue) -> bool:
    """Does this actions assertion name an inception action ANYWHERE?

    DELIBERATELY NOT ``_has_single_inception_action``, and the difference is a bug this
    separation fixes. That function answers "is this a well-formed FIRST actions
    assertion", and returns False for a dozen unrelated reasons -- a malformed entry, a
    missing ``digitalSourceType``, an inception in the wrong position. Using it to mean
    "carries no inception" let a SECOND assertion holding a bare ``c2pa.created`` read as
    holding none, so two inception actions across two assertions verified clean.

    18.15.2: "The full set of actions assertions in a C2PA Manifest shall contain no more
    than one action whose type is either c2pa.created or c2pa.opened."
    """
    if not isinstance(payload, dict):
        return False
    entries = payload.get("actions")
    if not isinstance(entries, list):
        return False
    return any(isinstance(entry, dict) and entry.get("action") in _INCEPTION_ACTIONS for entry in entries)


def _actions_labels(claim_order: list[str]) -> list[str]:
    """Every actions-assertion label the claim links, in link order.

    C2PA 6.4: "Multiple assertions of the same type can occur in the same manifest...
    by adding a double-underscore and a monotonically increasing index to the label."
    So ``c2pa.actions.v2__1`` is a second actions assertion, not a different assertion
    type, and reading only the base label made a store carrying both invisible to
    15.10.1.2's "exactly one actions assertion".

    ORDER COMES FROM THE CLAIM. 15.10.3.2.3 defines "first" against the
    created_assertions array, so a store that happens to serialize ``__1`` ahead of the
    base label cannot change which assertion is first -- and neither can a third-party
    JUMBF reader that iterates its boxes differently from ours.
    """
    # BOTH LABELS. 15.10.3.2.3 opens "If the assertion's label is c2pa.actions or
    # c2pa.actions.v2", and Table 7 lists them as one row; reading only v2 rejected a
    # conforming v1 manifest as assertion.missing. 5.1's rule is "can be read, but never
    # written" -- we still emit v2 only.
    #
    # Ordered by the CLAIM, not by label, so a v1 and a v2 assertion in one store are
    # ranked the way created_assertions ranks them. Building the two lists separately
    # and concatenating would have made every v1 assertion sort ahead of every v2 one
    # and silently changed which assertion counts as first.
    instances = set(_label_instances(ASSERTION_ACTIONS, claim_order)) | set(
        _label_instances(ASSERTION_ACTIONS_V1, claim_order)
    )
    return [label for label in claim_order if label in instances]


def _actions_status(manifest: ManifestStore, claim_order: list[str]) -> StatusCode | None:
    """Apply the actions rules that span assertions, or None if they hold.

    18.15.2: "There shall be at least one actions assertion present in the
    created_assertions array of the Claim of a standard C2PA Manifest."

    15.10.1.2: "Validate that either a c2pa.created or c2pa.opened action is contained
    in exactly one actions assertion."

    15.10.3.2.3 supplies the code and the position: the inception action's assertion
    must be "the first actions assertion in the created_assertions or
    gathered_assertions array (of a v2 claim)" -- WE CHECK created ONLY, on 18.15.2's
    authority and the 2.4 change log's; the gathered case is open work, and quoting the
    clause with that alternative elided would make our position look like the clause's.
    The
    action must be first within it.

    THIS IS NOT ONLY CONFORMANCE. c2pa.created is where ``digitalSourceType =
    trainedAlgorithmicMedia`` lives -- the field that actually says a model generated
    this text. A manifest with no created action, or with it rewritten to c2pa.edited,
    or with the real one buried in a second actions assertion, verified VALID while
    asserting nothing about machine origin.
    """
    # No `if not labels` guard: _store_shape_status requires ASSERTION_ACTIONS in
    # claim_order before calling this, so labels is never empty here. A guard for it
    # would be a branch no input can reach, returning the code the outer check has
    # already returned -- and an unreachable branch reads as coverage without being it.
    labels = _actions_labels(claim_order)
    # TWO DIFFERENT QUESTIONS, and conflating them was a bug. Later assertions are asked
    # only whether they CONTAIN an inception action; the first is asked whether it is a
    # well-formed inception assertion. Asking the second question of a later assertion
    # made a malformed inception read as no inception at all.
    if any(_contains_inception(manifest.assertions.get(label)) for label in labels[1:]):
        return StatusCode.ASSERTION_ACTION_MALFORMED
    if not _has_single_inception_action(manifest.assertions.get(labels[0])):
        return StatusCode.ASSERTION_ACTION_MALFORMED
    return None


def _disclosure_status(payload: CborValue) -> StatusCode | None:
    """Whether the AI disclosure actually discloses anything (18.28.2).

    18.28.2: "The value of the modelType field is an enumeration of AI model types
    defined in Table 12, 'Model type values' and IT SHALL BE PRESENT in the
    ai-model-disclosure-map object."

    WE CHECKED THE LABEL AND NEVER READ THE PAYLOAD, so a disclosure of ``{}`` was
    linked, hash-matched and reported VALID. This package exists under EU AI Act
    Article 50(2) to carry one fact, and a mark carrying none of it was
    indistinguishable from a mark carrying it. The same shape appeared twice before --
    the disclosure assertion was made required, then an inception action was made
    required, and both were satisfied by PRESENCE.

    ANY NON-EMPTY TEXT STRING IS ACCEPTED, and Table 12 is NOT a closed enumeration. 18.28.4's
    CDDL -- the schema 18.28.2 points at -- extends the socket:

        $model-type-choice /= tstr

    so the twenty-four literals are a union with any ``tstr``, exactly as its sibling
    ``$asset-type-choice`` is, under a rule the specification itself comments as "one of
    the listed choices OR A CUSTOM VALUE". An earlier version of this function checked
    membership of the twenty-four and refused ``ai.duale.types.model.generative`` -- 6.2.2
    entity-specific namespacing, which ``signing.py``'s own comment acknowledges the
    specification permits -- along with any framework Table 12 predates.

    What survives is 18.28.2's actual ``shall``: ``modelType`` shall be PRESENT. That is
    the substance, and a disclosure of ``{}`` still discloses nothing.

    ``scientificDomain`` is deliberately unchecked. 18.28.2 constrains it to the arXiv
    taxonomy, and conformance would need a vendored copy of that taxonomy; nothing here
    resolves over the network.

    THE CODE IS ``general.error`` BY CHOICE, and the choice is recorded in
    docs/deviations.md. 15.10.3.2 gives a validator no ai-disclosure rule at all, so
    18.28.2's ``shall`` binds the producer and no status code exists for a validator
    rejecting here. ``general.error`` is the specification's own catch-all -- "A value
    to be used when there was an error not specifically listed here" -- and inventing a
    code would put a string in a verdict that no clause authorizes.
    """
    if not isinstance(payload, dict):
        return StatusCode.GENERAL_ERROR
    model_type = payload.get("modelType")
    if not isinstance(model_type, str) or not model_type:
        return StatusCode.GENERAL_ERROR
    return None


def _store_shape_status(
    manifest: ManifestStore, claim_order: list[str], gathered_order: list[str]
) -> StatusCode | None:
    """Check the assertion store as a WHOLE, once every link has resolved.

    Separated from the per-link loop because none of these is a question about a single
    URI. Five checks, in this order: is every required assertion present; is there
    exactly one hard binding; do the actions assertions satisfy 15.10.1.2 and
    15.10.3.2.3; does every AI-disclosure instance actually disclose something; and does
    the store hold anything the claim never vouched for.

    The MIDDLE TWO -- the actions rules and the AI disclosure -- read assertion CONTENT
    rather than store shape, so the name is now narrower than the function. Not the last
    three: the undeclared-assertion check is ``set(assertion_bytes) - set(claim_order) -
    set(gathered_order)``, pure label arithmetic and the most store-shape-like of the
    five. They live here because they need the claim's link ORDER,
    which only this caller has.
    """
    # REQUIRED assertions are checked against created_assertions ALONE. 18.15.2 says
    # the actions assertion shall be "present in the created_assertions array", and the
    # 2.4 change log makes it explicit: "Required that the mandatory actions assertion
    # appear only in created_assertions (not gathered_assertions)." The reason
    # generalises to all three: an AI disclosure a producer merely GATHERED is not that
    # producer disclosing anything, and a gathered hard binding binds another asset.
    # The set is built ONCE. Written inside the generator it was rebuilt per required
    # label, and `any` short-circuits only on FAILURE, so the honest path -- every
    # required assertion present -- always paid all three passes over the link list.
    # 2.8x at 500 links and at 50 000.
    created = set(claim_order)
    if any(created.isdisjoint(accepted) for accepted in _REQUIRED_ASSERTIONS):
        return StatusCode.ASSERTION_MISSING

    # 15.10.1.2: "Validate that there is exactly one hard binding to content
    # assertion... If there is more than one such assertion, the manifest shall be
    # rejected with a failure code of assertion.multipleHardBindings." Checked BEFORE
    # the binding is evaluated, so it is never computed against an ambiguous store.
    # COUNTED OVER WHAT THE CLAIM LINKS, not over what the store holds. Reading the
    # store meant an UNLINKED extra binding reported multipleHardBindings -- sending an
    # investigator to look for two bindings the claim never named -- where an unlinked
    # assertion of any other type reports assertion.undeclared. 15.10.1.2's rule is
    # about the bindings the claim vouches for; an unlinked box is unauthenticated
    # bytes, which is a different fault with its own code.
    if _count_hard_bindings(dict.fromkeys(claim_order, b"")) > 1:
        return StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS

    actions = _actions_status(manifest, claim_order)
    if actions is not None:
        return actions

    # EVERY instance, not just the base label. A second c2pa.ai-disclosure__1 asserting
    # nothing was linked, hash-matched and never read.
    for label in _label_instances(ASSERTION_AI_DISCLOSURE, claim_order):
        disclosure = _disclosure_status(manifest.assertions.get(label))
        if disclosure is not None:
            return disclosure

    # 15.10.3.1: "If an assertion that is present in the assertion store is not
    # referenced by an element of either the created_assertions or gathered_assertions
    # arrays in the claim ... the claim shall be rejected with a failure code of
    # assertion.undeclared." An assertion in the store that the claim does not commit
    # to is signed by nothing. Rejected rather than ignored: a consumer reading the
    # store directly would otherwise see attacker-authored content beside authentic
    # content, with nothing in the verdict distinguishing them.
    #
    # The CODE matters as much as the rejection. We reported assertion.missing, which
    # names the opposite condition -- the claim points at something the store lacks --
    # and sends an operator looking for a truncated store instead of the extra box.
    if set(manifest.assertion_bytes) - set(claim_order) - set(gathered_order):
        return StatusCode.ASSERTION_UNDECLARED

    return None


def _check_binding(
    text: str, manifest: ManifestStore, verdict: Verdict, matches: Sequence[WrapperMatch]
) -> tuple[Verdict, bool]:
    """Apply the hard-binding status to the verdict."""
    code = _binding_status(text, manifest, matches)
    return verdict._add(code), code is StatusCode.DATA_HASH_MATCH


def _accept_credential(chain: list[Certificate]) -> tuple[StatusCode, str] | Ed25519PublicKey:
    """Whether the leaf may sign C2PA claims, and if so its key.

    Returns either a rejection code or the verified Ed25519 key. Returning the KEY
    rather than a bool keeps the type narrowing at the check, so the caller cannot
    reach a key this function has not vouched for.
    """
    if not chain:
        return StatusCode.SIGNING_CREDENTIAL_INVALID, "the COSE x5chain header carried no certificate (14.2)"
    try:
        check_claim_signing_profile(chain[0])
    except ProfileError as exc:
        # A profile violation is signingCredential.invalid -- a hard reject where the
        # manifest is not even Valid -- and is NOT the same as an unreachable anchor.
        # The message is CARRIED, not discarded: check_claim_signing_profile already
        # computed exactly which rule failed, and throwing that away leaves a caller
        # with a bare code and no idea which extension to fix.
        return StatusCode.SIGNING_CREDENTIAL_INVALID, str(exc)

    try:
        public_key = chain[0].public_key()
    except CERTIFICATE_ERRORS:
        # An SPKI algorithm OID cryptography does not implement. Attacker-supplied,
        # so it must be a verdict rather than an exception.
        return StatusCode.SIGNING_CREDENTIAL_INVALID, "the leaf's public key algorithm is not one we can read"
    if not isinstance(public_key, Ed25519PublicKey):
        # 13.2.1's allowed list is ES256/384/512, PS256/384/512 and EdDSA -- with
        # "Ed25519 instance only. No other EdDSA instances are allowed" scoped WITHIN
        # EdDSA. So Ed25519-only is OUR restriction, not the specification's, and the
        # message below says so: telling a caller with an ECDSA leaf that the spec
        # forbids it would be false, and would send them to the wrong document.
        # Ed448 shares the COSE alg identifier -8, so
        # the KEY type is what actually distinguishes them.
        return (
            StatusCode.SIGNING_CREDENTIAL_INVALID,
            f"the leaf holds a {type(public_key).__name__}; this package signs and verifies Ed25519 only, "
            "which is narrower than C2PA 13.2.1's allowed list (see docs/c2pa-compatibility.md)",
        )
    return public_key


def _signature_credentials(manifest: ManifestStore) -> list[bytes] | None:
    """The x5chain DER blobs, or None if there is no signature to read them from.

    Two conditions, one answer. The claim's ``signature`` field must RESOLVE to the box
    this manifest holds -- 15.7, where 15.6.2 checked only that the field exists -- and
    that box must parse as a COSE_Sign1. Either failure means the same thing to a
    caller: there is no claim signature here to check.

    Separated out because both were spelled as the same three-value return statement in
    :func:`_check_signature`, twice, which is a branch pretending to be two.
    """
    url = manifest.claim.get("signature")
    if not isinstance(url, str) or not _signature_uri_resolves(url, manifest.manifest_label):
        return None
    try:
        return _cose.parse(manifest.signature).x5chain()
    except (_cose.CoseError, *CERTIFICATE_ERRORS):
        return None


def _check_signature(manifest: ManifestStore, verdict: Verdict, context: VerifyContext) -> tuple[Verdict, bool, bool]:
    """Validate the claim signature and evaluate trust.

    Returns ``(verdict, signature_ok, trusted)``.
    """
    signature_box = manifest.signature

    # THE TWO WAYS THE SIGNATURE CAN BE ABSENT ARE ONE ANSWER, so they are one branch:
    # a claim whose `signature` field does not resolve to the box we hold (15.7 -- 15.6.2
    # checked only that the field EXISTS), and a box that is not a parseable COSE_Sign1.
    # Both are claimSignature.missing, and they were two identical return statements.
    ders = _signature_credentials(manifest)
    if ders is None:
        return verdict._add(StatusCode.CLAIM_SIGNATURE_MISSING), False, False

    # UNREADABLE IS NOT ABSENT. The COSE structure parsed and named a credential; the
    # credential itself is malformed, which is signingCredential.invalid rather than
    # claimSignature.missing -- the distinction an operator acts on.
    chain = _load_chain(ders)
    if chain is None:
        return (
            verdict._add(
                StatusCode.SIGNING_CREDENTIAL_INVALID,
                "the x5chain carried bytes that are not a readable certificate",
            ),
            False,
            False,
        )

    public_key = _accept_credential(chain)
    if isinstance(public_key, tuple):
        code, explanation = public_key
        return verdict._add(code, explanation), False, False

    try:
        _cose.verify_claim(signature_box, manifest.claim_bytes, public_key)
    except (_cose.CoseError, TypeError):
        return verdict._add(StatusCode.CLAIM_SIGNATURE_MISMATCH), False, False

    verdict = verdict._add(StatusCode.CLAIM_SIGNATURE_VALIDATED)

    # 15.8: "the C2PA Manifest is valid if THE CURRENT TIME AT VALIDATION is within
    # the validity period of the signer's certificate". Expiry is the only revocation
    # signal available offline -- we fetch no CRL and staple no OCSP -- so skipping
    # it would discard the mechanism entirely.
    #
    # The reference instant comes from the VERIFIER, never from the document. An
    # earlier version read it from the c2pa.actions `when` field, reasoning that a
    # mark signed while the credential was live should survive the credential. That
    # reasoning is appealing and is not what 15.8 says; surviving expiry is what
    # sigTst2 time-stamping is for, and we do not implement it. It also made the
    # check self-certifying, because `when` is attacker-supplied: the holder of an
    # expired key just wrote a time inside the old window, and omitting the assertion
    # skipped the check while STILL filing insideValidity as a success code.
    if not _chain_inside_validity(chain, context.now or _utcnow()):
        return (
            verdict._add(
                StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY,
                "the signing certificate is outside its validity period at validation time (15.8)",
            ),
            False,
            False,
        )

    verdict = verdict._add(StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY)
    trusted, explanation = _is_trusted(chain, context)
    code = StatusCode.SIGNING_CREDENTIAL_TRUSTED if trusted else StatusCode.SIGNING_CREDENTIAL_UNTRUSTED
    # untrusted is the expected outcome for a self-signed credential: a FAILURE code
    # that does NOT invalidate, since 14.3.5 defines Valid without requiring trusted.
    return verdict._add(code, explanation), True, trusted


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


def _chain_inside_validity(chain: list[Certificate], when: datetime.datetime) -> bool:
    """Whether EVERY certificate in the chain is valid at ``when``.

    C2PA 15.8: "the C2PA Manifest is valid if the current time at validation is within
    the validity period of the signer's certificate AND ALL CA CERTIFICATES UP TO THE
    TRUST ANCHOR."

    We checked the leaf alone, and the docstring here quoted the clause up to -- and not
    including -- the words it omitted. An expired intermediate is the realistic case
    rather than a contrived one: leaves are short-lived and rotated, CAs are long-lived
    and forgotten, and a chain whose CA has lapsed is one nobody is maintaining. RFC
    5280 section 6 path validation rejects it, so checking the leaf alone made us more
    permissive than the chain builder we tell integrators to supply.

    Uses the timezone-aware accessors: the naive ``not_valid_before`` /
    ``not_valid_after`` pair is deprecated in pyca/cryptography and would compare
    wrongly against an aware datetime -- raising TypeError rather than answering.
    """
    return all(certificate.not_valid_before_utc <= when <= certificate.not_valid_after_utc for certificate in chain)


def _is_trusted(chain: list[Certificate], context: VerifyContext) -> tuple[bool, str | None]:
    """Ask the caller's evaluator whether the chain reaches an anchor.

    Returns ``(trusted, explanation)``; the explanation is set only when the evaluator
    raised.

    THE EVALUATOR IS CALLER-SUPPLIED AND THE RECOMMENDED ONE RAISES. The ``[trust]``
    extra ships ``pyhanko-certvalidator``, whose path validation signals an unreachable
    anchor with ``PathBuildingError`` / ``PathValidationError`` -- the single most likely
    outcome of asking it about a chain. Left uncaught, that escaped ``verify()``, which
    is documented never to raise for absent, corrupt or invalid marks, and it escaped
    ONLY on the signature-valid path with anchors configured: the same "bomb that fires
    only on the happy path" asymmetry ``anchors_pem`` was rewritten to remove.

    AN UNREACHABLE ANCHOR IS A VERDICT, NOT AN ERROR, which is what the four-state model
    is for: ``signingCredential.untrusted`` is a normal answer, and a validator that
    cannot chain a credential has learned something rather than failed.

    NOT SWALLOWED, THOUGH. The exception type and message are carried into the verdict,
    so a ``TypeError`` from a buggy evaluator is visible rather than indistinguishable
    from an honest "no path found".
    """
    anchors = list(context.anchors)
    if not anchors:
        return False, None
    try:
        return context.trust_evaluator.is_trusted(chain, anchors), None
    except Exception as exc:  # noqa: BLE001 -- a caller's evaluator may raise anything; see above
        return False, f"the trust evaluator raised {type(exc).__name__}: {exc}"


def verify(text: str, *, context: VerifyContext | None = None) -> Verdict:
    """Validate the Content Credential in ``text`` and report what was found.

    Never raises for absent, corrupt or invalid marks -- every outcome is a
    :class:`Verdict`. The result is a four-state :class:`Provenance`, not a boolean.

    The one exception is text UTF-8 cannot represent: a ``str`` holding an unpaired
    surrogate is not a text asset this specification can describe, so there is no
    verdict to give and :class:`UnencodableTextError` is raised instead.

    THAT PROMISE WAS FALSE UNTIL 2026-08-06, and the shape of the failure is worth
    knowing before changing anything below. A single byte changed in a valid mark's
    certificate produced ``InvalidVersion``, ``KeyError`` or ``DuplicateExtension`` out
    of this function -- none of them a ``C2paTextError``, which is what the
    documentation tells integrators to catch. ``cryptography`` parses lazily, so a
    malformed field raises at an ATTRIBUTE ACCESS two modules away from the load, past
    every ``try`` watching it. :func:`_load_chain` is the boundary that closed it, and
    the promise now rests on its probe list covering every certificate field this
    package reads. Guarded by
    ``tests/test_regressions.py::test_hostile_certificate_bytes_do_not_escape_verify``.

    **A ``VALID`` result carrying ``signingCredential.untrusted`` is the expected
    outcome for a self-signed credential and is not an error.** This package bundles
    no trust anchors, so unless the caller supplies some there is nothing to chain
    to and ``VALID`` is as far as verification can go.
    """
    context = context or VerifyContext()

    try:
        matches = find_wrappers(text)
    except MarkCorruptError as exc:
        return Verdict(state=Provenance.INVALID)._add(exc.code)

    if not matches:
        return Verdict(state=Provenance.UNMARKED)

    verdict = Verdict(state=Provenance.INVALID, span=matches[0].span)
    if len(matches) > 1:
        # 15.12.1.3.1 step 4 and A.8.7.1. A.8.2.1 says "Quantity: Zero or one", and
        # 15.5.2.1 treats plural manifest stores as all invalid; a permissive reading
        # would let an attacker append a second wrapper and choose which one a
        # consumer reads.
        return verdict._add(StatusCode.TEXT_MULTIPLE_WRAPPERS)

    try:
        manifest = parse_manifest_store(matches[0].payload)
    except MarkCorruptError as exc:
        return verdict._add(exc.code)

    verdict = dataclasses.replace(verdict, manifest=manifest)
    # Assertions FIRST: the hard binding lives in an assertion, and reading it before
    # the claim's hashed-URI link is checked means trusting an unauthenticated map.
    verdict, assertions_ok = _check_assertions(manifest, verdict)
    verdict, binding_ok = _check_binding(text, manifest, verdict, matches)
    verdict, signature_ok, trusted = _check_signature(manifest, verdict, context)

    if not (assertions_ok and binding_ok and signature_ok):
        return verdict
    return dataclasses.replace(verdict, state=Provenance.TRUSTED if trusted else Provenance.VALID)
