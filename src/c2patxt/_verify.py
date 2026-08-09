# pyright: reportPrivateUsage=false
# Verdict._add and Verdict._add_many are the verdict builders, kept private so the
# public result type carries no mutator a caller could use to assemble a verdict
# verification never produced. This module is the one legitimate builder.
"""
``verify``: C2PA validation for the supported A.8 profile, producing a
:class:`Verdict`.

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
U+FEFF is a starter and blocks composition. We follow 15.12.1.3.1 because A.8.5
designates the validation clause as normative.

Validation runs the implemented mandatory assertion checks, the hard binding, and the
claim signature, accumulating the applicable status codes. A mandatory assertion that
this package cannot validate fails closed. Before hashing covered text, the verifier
requires each declared wrapper exclusion to match a wrapper it located in the input.
"""

from __future__ import annotations

import dataclasses
import datetime
import itertools
import re
from collections.abc import Sequence

from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509 import Certificate, load_der_x509_certificate

from c2patxt import _cose
from c2patxt._cbor import CborValue
from c2patxt._extract import parse_manifest_store
from c2patxt._locate import WrapperMatch, find_wrappers
from c2patxt._normalization import normalize_nfc
from c2patxt.exceptions import MarkCorruptError, TextNormalizationError
from c2patxt.manifest import (
    ASSERTION_ACTIONS,
    ASSERTION_ACTIONS_V1,
    ASSERTION_HASH_DATA,
    ASSERTION_REPOSITORY_RECEIPT,
    ASSERTION_URI_PREFIX,
    CLAIM_SIGNATURE_URI,
    HASH_ALGORITHMS,
    LABEL_ASSERTION_STORE,
    LABEL_CLAIM_SIGNATURE,
    LABEL_MANIFEST_STORE,
    ManifestStore,
)
from c2patxt.status import Status, StatusCode
from c2patxt.trust import NoTrustEvaluator, ProfileError, TrustEvaluator, check_certificate_chain_profile, load_anchors
from c2patxt.verdict import Provenance, Verdict


@dataclasses.dataclass(frozen=True, slots=True)
class VerifyContext:
    """Everything verification may consult, supplied explicitly.

    Package-owned code performs no file discovery, implicit credential-store lookup,
    or network access. A custom trust evaluator is caller-owned code and is invoked
    synchronously; if it performs I/O, it blocks this call and its external state can
    affect the result.
    """

    anchors_pem: bytes | None = None
    """PEM bundle of trust anchors. ``None`` means no anchors, the default.

    Parsed eagerly at construction. A malformed bundle is a caller error, and the
    parsed certificates are reused by each call to :func:`verify`."""

    now: datetime.datetime | None = None
    """Fallback instant for certificate validity; ``None`` reads the current time.

    C2PA 15.8 prefers the time from a validated trusted ``sigTst2`` token. This
    implementation does not validate such tokens, so it uses this verifier-supplied
    instant. A supplied value must be timezone-aware."""

    trust_evaluator: TrustEvaluator = dataclasses.field(default_factory=NoTrustEvaluator)
    """Decides whether a chain reaches an anchor. The default trusts nothing, which
    is honest rather than a stub: with no anchors there is nothing to chain to."""

    anchors: tuple[Certificate, ...] = dataclasses.field(init=False, default=())
    """Parsed anchors derived from ``anchors_pem``; not a constructor argument."""

    def __post_init__(self) -> None:
        """Parse ``anchors_pem`` once, here, so a bad bundle fails immediately.

        Raises:
            ValueError: ``anchors_pem`` is not a parseable PEM bundle, or ``now`` is a
                naive datetime.
        """
        if self.now is not None and (self.now.tzinfo is None or self.now.utcoffset() is None):
            msg = (
                "VerifyContext.now must be timezone-aware; a naive datetime cannot be compared to certificate validity"
            )
            raise ValueError(msg)
        object.__setattr__(self, "anchors", tuple(load_anchors(self.anchors_pem)))


def _hash_binding_bytes(encoded: bytes, exclusions: Sequence[tuple[int, int]]) -> bytes:
    """Apply 15.12.1.3.1 steps 5-7. Remove every range, normalize, encode.

    This is also 9.2.4 ("Hashing unstructured text assets") and A.8.7.2
    ("Normalization") in practice: the hash covers the NFC form of the visible text
    with the wrapper's byte range removed, and nothing else.

    A.8.5 designates 15.12.1.3.1 as the normative procedure, while A.8.7.3 describes
    normalization before offset calculation. The module docstring and
    ``docs/deviations.md`` work through the conflicting results with literal examples.

    Takes the document already encoded because the exclusion offsets are UTF-8 byte
    offsets.
    """
    parts: list[bytes] = []
    cursor = 0
    for start, length in exclusions:
        parts.append(encoded[cursor:start])
        cursor = start + length
    parts.append(encoded[cursor:])
    remaining = b"".join(parts)
    return normalize_nfc(remaining.decode("utf-8")).encode("utf-8")


def _exclusion_ranges(hash_data: dict[str, CborValue]) -> list[tuple[int, int]] | None:
    """Extract ordered, non-overlapping exclusion ranges, or report malformed.

    Everything here is attacker-controlled decoded CBOR, so each step narrows
    explicitly rather than trusting the shape. C2PA 15.12.1.1 permits more than one
    range, requires ascending order, and rejects overlaps and negative values.
    """
    raw = hash_data.get("exclusions")
    if not isinstance(raw, list) or not raw:
        return None

    ranges: list[tuple[int, int]] = []
    previous_end = 0
    for entry in raw:
        if not isinstance(entry, dict):
            return None
        start = entry.get("start")
        length = entry.get("length")
        # bool before int: True would otherwise pass as 1 and describe a real range.
        if isinstance(start, bool) or isinstance(length, bool):
            return None
        if not isinstance(start, int) or not isinstance(length, int) or start < 0 or length < 0:
            return None
        if ranges and previous_end > start:
            return None
        ranges.append((start, length))
        previous_end = start + length
    return ranges


def _compare_digest(
    encoded: bytes,
    algorithm: str,
    exclusions: Sequence[tuple[int, int]],
    expected: bytes,
) -> StatusCode:
    """Hash the text with the wrapper removed and compare.

    15.12.1.3.1 steps 5-9, which is A.8.6.1 ("Validating a data hash") in practice:
    A.8.6.1 states the requirement and delegates the procedure to the validation clause.
    """
    try:
        binding = _hash_binding_bytes(encoded, exclusions)
    except (TextNormalizationError, UnicodeDecodeError):
        return StatusCode.DATA_HASH_MALFORMED
    digest = HASH_ALGORITHMS[algorithm](binding).digest()
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


def _binding_parameters(
    manifest: ManifestStore,
) -> tuple[str, bytes, list[tuple[int, int]]] | StatusCode:
    """Resolve and validate the data-hash fields used by the binding procedure."""
    hash_data = manifest.hash_data
    if hash_data is None:
        return StatusCode.CLAIM_HARD_BINDINGS_MISSING

    algorithm = _resolve_algorithm(hash_data, manifest.claim)
    if algorithm is None:
        return StatusCode.ALGORITHM_UNSUPPORTED

    expected = _expected_digest(hash_data)
    if isinstance(expected, StatusCode):
        return expected

    exclusions = _exclusion_ranges(hash_data)
    if exclusions is None:
        return StatusCode.DATA_HASH_MALFORMED
    return algorithm, expected, exclusions


def _binding_status(text: str, manifest: ManifestStore, matches: Sequence[WrapperMatch]) -> tuple[StatusCode, ...]:
    """Decide the statuses the hard binding earns (15.12.1.1, 15.12.1.3.1).

    ``matches`` is the wrapper scan already performed by :func:`verify`.
    """
    parameters = _binding_parameters(manifest)
    if isinstance(parameters, StatusCode):
        return (parameters,)
    algorithm, expected, exclusions = parameters

    # 15.12.1.3.1 steps 2-3: the exclusion must correspond EXACTLY to a located
    # wrapper. Without this an attacker chooses which bytes the hash covers, and
    # could exclude the part of the text they altered.
    #
    # Suffix placement is a producer SHOULD in A.8.4.1, not a validator condition.
    # Validation is governed by the exact byte-range match here.
    encoded = text.encode("utf-8")
    spans = {(match.span.utf8_start, len(match.span)) for match in matches}
    matched_wrappers = spans.intersection(exclusions)
    if not matched_wrappers:
        return (StatusCode.DATA_HASH_MALFORMED,)
    if len(matched_wrappers) > 1:
        return (StatusCode.TEXT_MULTIPLE_WRAPPERS,)
    if any(start + length > len(encoded) for start, length in exclusions):
        return (StatusCode.DATA_HASH_MISMATCH,)

    result: list[StatusCode] = []
    if len(exclusions) > 1:
        result.append(StatusCode.DATA_HASH_ADDITIONAL_EXCLUSIONS)
    result.append(_compare_digest(encoded, algorithm, exclusions, expected))
    return tuple(result)


def _load_certificate(der: bytes) -> Certificate | None:
    """Parse and force every certificate field read later, inside one hostile-input boundary."""
    try:
        certificate = load_der_x509_certificate(der)
        _ = (
            certificate.version,
            certificate.issuer,
            certificate.subject,
            certificate.not_valid_before_utc,
            certificate.not_valid_after_utc,
            certificate.signature_algorithm_oid,
            certificate.tbs_certificate_bytes,
            certificate.extensions,
            certificate.public_key(),
        )
    except Exception:  # noqa: BLE001 -- attacker-controlled lazy certificate parsing; see _load_chain
        return None
    return certificate


def _load_chain(ders: Sequence[bytes]) -> tuple[list[Certificate] | None, int]:
    """Parse attacker-supplied DER, returning the unreadable x5chain index on failure.

    ``cryptography`` parses some certificate fields lazily and does not expose a closed
    exception set for malformed DER. ``_load_certificate`` therefore forces every
    field this package later reads inside one attacker-input boundary. The broad catch
    is confined to parsing and field access; any failure means that certificate slot is
    unreadable.
    """
    chain: list[Certificate] = []
    for index, der in enumerate(ders):
        certificate = _load_certificate(der)
        if certificate is None:
            return None, index
        chain.append(certificate)
    return chain, -1


#: RFC 3986 scheme production. Any scheme at all, deliberately -- 15.10.3.3 scopes
#: external work to "a hashed_ext_uri whose resource the validator CHOOSES to
#: retrieve", and we choose to retrieve none of them, so singling out https would be
#: inventing a distinction the clause does not draw.
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")

_SELF_JUMBF = "self#jumbf="

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

    Accept the manifest-relative URI emitted by this producer and the store-relative
    form naming this exact manifest. External, cross-manifest, empty, and overlong
    paths do not resolve.
    """
    if url == CLAIM_SIGNATURE_URI:
        return True
    if not url.startswith(_STORE_URI_PREFIX):
        return False
    parts = url[len(_STORE_URI_PREFIX) :].split("/")
    expected = 2
    return len(parts) == expected and parts[0] == manifest_label and parts[1] == LABEL_CLAIM_SIGNATURE


#: Assertions a standard manifest must commit to. The hard binding ties the claim to
#: the text, while 18.15.2 requires an actions assertion in created_assertions.
#: Assertion-specific producer schemas such as AI disclosure are not generic
#: validator requirements under 15.10.3.2.
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
_REQUIRED_ASSERTIONS: tuple[frozenset[str], ...] = (frozenset({ASSERTION_ACTIONS, ASSERTION_ACTIONS_V1}),)


#: C2PA 15.6.2: "If any are absent, then the claim shall be rejected with a failure
#: code of claim.malformed." Listed there verbatim -- this is not our shortlist.
_REQUIRED_CLAIM_FIELDS = ("instanceID", "signature", "created_assertions", "claim_generator_info")


def _claim_malformed(claim: dict[str, CborValue]) -> bool:
    """Apply 15.6.2's required-field check.

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

    C2PA 15.10.3.1 requires validation of both arrays. They remain separate because only
    ``created_assertions`` may satisfy the required-assertion and actions rules.
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
    computed on the word of an attacker holding no credential at all. Two structures
    let one target be named many times: ``created_assertions`` is not de-duplicated,
    and an actions assertion may carry many icon references (15.10.3.3).

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
) -> tuple[StatusCode, tuple[str, str] | None]:
    """Check one hashed-uri-map. Return its status and resolved ``(label, url)``."""
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
    return StatusCode.ASSERTION_HASHED_URI_MATCH, (label, url)


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

    An external reference is passed over, not failed. The clause scopes external work
    to "a hashed_ext_uri whose resource the validator chooses to retrieve", and this
    package never touches the network -- a verifier whose answer depends on network
    conditions, or on whoever controls an endpoint, is not the offline verifier it
    claims to be.
    """
    url = reference.get("url")
    if not isinstance(url, str):
        return StatusCode.HASHED_URI_MISSING
    if not url.startswith(_SELF_JUMBF):
        # A URI scheme distinguishes a remote external reference that this package
        # declines to retrieve from an unresolvable local reference.
        return None if _SCHEME.match(url) else StatusCode.HASHED_URI_MISSING

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
    if "icon" not in generator:
        return []
    icon = generator["icon"]
    if not isinstance(icon, dict):
        # A PRESENT icon is a reference that 15.6.2/15.10.3.2.3 route through
        # reference validation. An empty map reaches hashedURI.missing, whereas an
        # empty list here would turn malformed attacker input into "no icon".
        return [{}]
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

    ``parameters.relatedAssertions`` is not collected here. Its rule also constrains
    the array's shape and forbids targets that are ingredient or actions assertions.
    ``_related_assertions_status`` owns that complete action-level check.

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


def _count_hard_bindings(labels: Sequence[str]) -> int:
    """Count hard-binding assertions, honouring C2PA 6.4's instance convention.

    6.4: "Multiple assertions of the same type can occur in the same manifest... This
    is accomplished by adding a double-underscore and a monotonically increasing index
    to the label. For example... c2pa.metadata, c2pa.metadata__1 and c2pa.metadata__2."

    C2PA 15.10.1.2 requires exactly one hard binding, including labels that use the
    ``__N`` instance suffix.

    The suffix must be a double underscore followed by digits. ``c2pa.hash.dataX`` and
    ``c2pa.hash.data_1`` are DIFFERENT assertions, not instances, and counting them
    would reject manifests that are fine.
    """
    return sum(_is_label_instance(label, (ASSERTION_HASH_DATA,)) for label in dict.fromkeys(labels))


def _uri_points_into_manifest(url: str, manifest_label: str) -> bool:
    """Whether a JUMBF URI points anywhere inside this manifest."""
    if not url.startswith(_SELF_JUMBF):
        return False
    target = url[len(_SELF_JUMBF) :]
    if not target:
        return False
    if not target.startswith("/"):
        # A non-rooted self#jumbf URI is relative to the current manifest.
        return True
    prefix = f"/{LABEL_MANIFEST_STORE}/{manifest_label}"
    return target == prefix or target.startswith(f"{prefix}/")


def _redacted_assertions_failure(manifest: ManifestStore) -> tuple[StatusCode, str | None] | None:
    """Validate the claim's redacted-assertion list and reject self-redaction."""
    redacted = manifest.claim.get("redacted_assertions")
    if redacted is None:
        return None
    if not isinstance(redacted, list):
        return StatusCode.CLAIM_MALFORMED, "redacted_assertions must be a list of JUMBF URI strings"
    for url in redacted:
        if not isinstance(url, str):
            return StatusCode.CLAIM_MALFORMED, "redacted_assertions must be a list of JUMBF URI strings"
        if _uri_points_into_manifest(url, manifest.manifest_label):
            return StatusCode.ASSERTION_SELF_REDACTED, None
    return None


def _resolve_links(
    links: list[dict[str, CborValue]], manifest: ManifestStore, cache: DigestCache
) -> tuple[list[tuple[str, str]], StatusCode | None]:
    """Resolve links in order, retaining each successful label and original URL.

    A list rather than a set because 15.10.3.2.3 defines "the first actions assertion"
    against the claim's array, so link order is part of a rule rather than an incidental
    property of how we iterate. The partial list is returned with the first failure:
    15.10.3.1 requires one success result for every preceding hash match even when a
    later link makes the claim invalid.
    """
    resolved: list[tuple[str, str]] = []
    for link in links:
        code, item = _link_status(link, manifest, cache)
        if item is None:
            return resolved, code
        resolved.append(item)
    return resolved, None


def _assertion_result(
    manifest: ManifestStore,
) -> tuple[list[str], tuple[StatusCode, str | None] | None]:
    """Matched claim-link URLs and the first assertion-store failure, if any.

    Split from :func:`_check_assertions` so verdict construction stays in one place:
    claim shape, every link, the store as a whole, then references inside structures.
    """
    if _claim_malformed(manifest.claim):
        return [], (StatusCode.CLAIM_MALFORMED, "the claim is missing a field 15.6.2 requires")

    arrays = _assertion_links(manifest.claim)
    if arrays is None:
        return [], (
            StatusCode.CLAIM_MALFORMED,
            "created_assertions and gathered_assertions must each be a non-empty list of maps",
        )
    created, gathered = arrays

    redacted_failure = _redacted_assertions_failure(manifest)
    if redacted_failure is not None:
        return [], redacted_failure

    # ONE cache for the whole call. Every structure below can name the same target, so
    # scoping it per-loop would leave most of the hash amplification standing.
    cache: DigestCache = {}

    # ORDERED lists, not sets: 15.10.3.2.3 defines "the first actions assertion" against
    # the created_assertions array, so link order is part of a rule. Gathered assertions
    # are authenticated by the SAME hashed URI as created ones -- declaring an assertion
    # is not trusting it, and 15.10.3.1 applies one algorithm to both -- and are kept
    # apart only because the required-assertion set and the actions rules are defined
    # against created_assertions alone.
    created_resolved, failure = _resolve_links(created, manifest, cache)
    if failure is not None:
        return [url for _, url in created_resolved], (failure, None)
    gathered_resolved, failure = _resolve_links(gathered, manifest, cache)
    resolved = [*created_resolved, *gathered_resolved]
    matched_urls = [url for _, url in resolved]
    if failure is not None:
        return matched_urls, (failure, None)
    claim_order = [label for label, _ in created_resolved]
    gathered_order = [label for label, _ in gathered_resolved]

    # 15.6.2 routes the claim generator's icon through 15.10.3.3, and 15.10.3.2.3 routes
    # an action's softwareAgent and template icons through the same clause. Evaluated
    # lazily, AFTER the store's own shape, so a malformed store is rejected before
    # references inside its assertions are traversed.
    # EVERY actions assertion, not just the base label: 6.4's __N instances each carry
    # their own softwareAgent and templates, so reading one label left a poisoned icon
    # in c2pa.actions.v2__1 unchecked while the same file already counted __N instances
    # for the hard binding.
    # A generator keeps traversal behind the store-shape check. Labels are deduplicated
    # because a repeated link resolves to the same assertion and cannot change the
    # answer; dict.fromkeys preserves the first occurrence used by 15.10.3.2.3.
    references = itertools.chain(
        _claim_references(manifest.claim),
        (
            reference
            for label in dict.fromkeys([*_actions_labels(claim_order), *_actions_labels(gathered_order)])
            for reference in _action_references(manifest.assertions.get(label))
        ),
    )
    code = _store_shape_status(manifest, claim_order, gathered_order, cache) or next(
        (status for reference in references if (status := _reference_status(reference, manifest, cache)) is not None),
        None,
    )
    return matched_urls, None if code is None else (code, None)


def _check_assertions(manifest: ManifestStore, verdict: Verdict) -> tuple[Verdict, bool]:
    """Authenticate the assertion store against the claim (C2PA 15.10.3.1, 8.4.2.3).

    The COSE signature covers the claim. The claim authenticates each assertion through
    a ``hashed-uri-map``, so validation recomputes every digest over the received bytes.
    Without that step, replacing an assertion would not invalidate the signed claim.

    Every required assertion must be present, linked, and hash-matched.
    """
    matched_urls, failure = _assertion_result(manifest)
    verdict = verdict._add_many(Status(StatusCode.ASSERTION_HASHED_URI_MATCH, url=url) for url in matched_urls)
    if failure is not None:
        code, explanation = failure
        return verdict._add(code, explanation), False
    return verdict, True


#: 15.10.1.2's "inception" actions: an asset is either newly created, or opened from
#: something that already existed.
_INCEPTION_ACTIONS = frozenset({"c2pa.created", "c2pa.opened"})


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
    bases = (ASSERTION_ACTIONS, ASSERTION_ACTIONS_V1)
    return [label for label in claim_order if _is_label_instance(label, bases)]


_INGREDIENT_LABELS = ("c2pa.ingredient", "c2pa.ingredient.v2", "c2pa.ingredient.v3")
_SOFT_BINDING_LABEL = "c2pa.soft-binding"
_WATERMARK_ACTIONS = frozenset({"c2pa.watermarked", "c2pa.watermarked.bound"})
_CLOUD_DATA_LABEL = "c2pa.cloud-data"
_EXTERNAL_REFERENCE_LABEL = "c2pa.external-reference"
_SESSION_KEYS_LABEL = "c2pa.session-keys"
_TIME_STAMP_LABEL = "c2pa.time-stamp"
_ALTERNATIVE_CONTENT_LABEL = "c2pa.alternative-content-representation"
_CLOUD_HARD_BINDING_LABELS = (
    "c2pa.action",
    "c2pa.actions.v2",
    "c2pa.cloud-data",
    "c2pa.hash.bmff.v2",
    "c2pa.hash.bmff.v3",
    "c2pa.hash.boxes",
    "c2pa.hash.collection.data",
    "c2pa.hash.data",
    "c2pa.hash.multi-asset",
    *_INGREDIENT_LABELS,
)
_CLOUD_MALFORMED_LABELS = (
    "c2pa.actions",
    "c2pa.actions.v2",
    "c2pa.cloud-data",
    "c2pa.hash.bmff.v2",
    "c2pa.hash.bmff.v3",
    "c2pa.hash.boxes",
    "c2pa.hash.collection.data",
    "c2pa.hash.data",
    "c2pa.hash.multi-asset",
    *_INGREDIENT_LABELS,
)
_EXTERNAL_FORBIDDEN_LABELS = (
    "c2pa.actions",
    "c2pa.actions.v2",
    "c2pa.cloud-data",
    "c2pa.external-reference",
    "c2pa.hash.bmff.v2",
    "c2pa.hash.bmff.v3",
    "c2pa.hash.boxes",
    "c2pa.hash.collection.data",
    "c2pa.hash.data",
    "c2pa.hash.multi-asset",
    *_INGREDIENT_LABELS,
)


def _is_label_instance(label: str, bases: tuple[str, ...]) -> bool:
    """Whether ``label`` is one of ``bases`` or a C2PA 6.4 ``__N`` instance."""
    for base in bases:
        if label == base:
            return True
        prefix = f"{base}__"
        if label.startswith(prefix) and label[len(prefix) :].isdigit():
            return True
    return False


def _parent_ingredient_count(manifest: ManifestStore, labels: list[str]) -> int:
    """Count linked ingredients whose relationship to the current asset is parentOf."""
    count = 0
    for label in dict.fromkeys(labels):
        if not _is_label_instance(label, _INGREDIENT_LABELS):
            continue
        payload = manifest.assertions.get(label)
        if isinstance(payload, dict) and payload.get("relationship") == "parentOf":
            count += 1
    return count


def _actions_entries(payload: CborValue) -> list[dict[str, CborValue]] | None:
    """Narrow one actions assertion to its ordered action maps."""
    if not isinstance(payload, dict):
        return None
    raw = payload.get("actions")
    if not isinstance(raw, list) or not raw:
        return None
    entries: list[dict[str, CborValue]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            return None
        entries.append({key: value for key, value in entry.items() if isinstance(key, str)})
    return entries


def _action_reference_label(
    raw: CborValue, manifest: ManifestStore, cache: DigestCache
) -> tuple[str | None, StatusCode | None]:
    """Validate one action-internal hashed URI and return its current-manifest label."""
    if not isinstance(raw, dict):
        return None, StatusCode.HASHED_URI_MISSING
    reference = {key: value for key, value in raw.items() if isinstance(key, str)}
    failure = _reference_status(reference, manifest, cache)
    if failure is not None:
        return None, failure
    url = reference.get("url")
    if not isinstance(url, str):
        return None, StatusCode.HASHED_URI_MISSING
    label = _assertion_label(url, manifest.manifest_label)
    if label is None or label not in manifest.assertion_bytes:
        return None, StatusCode.HASHED_URI_MISSING
    return label, None


def _ingredient_references(action: dict[str, CborValue], actions_label: str) -> list[CborValue] | None:
    """Return an action's ingredient references, preserving v1's singular field."""
    parameters = action.get("parameters")
    if not isinstance(parameters, dict):
        return None
    key = "ingredient" if _is_label_instance(actions_label, (ASSERTION_ACTIONS_V1,)) else "ingredients"
    if key not in parameters:
        return None
    raw = parameters[key]
    if key == "ingredient":
        return [raw]
    return list(raw) if isinstance(raw, list) and raw else None


def _ingredients_match(
    references: list[CborValue],
    manifest: ManifestStore,
    cache: DigestCache,
    relationship: str,
    *,
    exactly_one: bool,
) -> bool:
    """Whether every reference names a current-manifest ingredient of one relationship."""
    if exactly_one and len(references) != 1:
        return False
    for reference in references:
        label, failure = _action_reference_label(reference, manifest, cache)
        if failure is not None or label is None or not _is_label_instance(label, _INGREDIENT_LABELS):
            return False
        ingredient = manifest.assertions.get(label)
        if not isinstance(ingredient, dict) or ingredient.get("relationship") != relationship:
            return False
    return True


def _related_assertions_status(
    action: dict[str, CborValue], manifest: ManifestStore, cache: DigestCache
) -> StatusCode | None:
    """Apply 15.10.3.2.3's shape, hash and target rules for relatedAssertions."""
    parameters = action.get("parameters")
    if not isinstance(parameters, dict) or "relatedAssertions" not in parameters:
        return None
    references = parameters["relatedAssertions"]
    if not isinstance(references, list) or not references:
        return StatusCode.ASSERTION_ACTION_MALFORMED
    forbidden = (*_INGREDIENT_LABELS, ASSERTION_ACTIONS, ASSERTION_ACTIONS_V1)
    for reference in references:
        label, failure = _action_reference_label(reference, manifest, cache)
        if failure is not None:
            return failure
        if label is None or _is_label_instance(label, forbidden):
            return StatusCode.ASSERTION_ACTION_MALFORMED
    return None


def _action_ingredient_status(
    action: dict[str, CborValue],
    actions_label: str,
    manifest: ManifestStore,
    cache: DigestCache,
) -> StatusCode | None:
    """Apply the opened/placed/removed/transcoded/repackaged ingredient rules."""
    name = action.get("action")
    if name == "c2pa.removed":
        # 15.10.3.2.3 requires this action to resolve a componentOf ingredient in
        # ANOTHER manifest. ManifestStore exposes the active manifest only, so no
        # current-manifest assertion can satisfy the rule. Do not turn a local
        # componentOf link into a false success.
        return StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH
    if name in {"c2pa.opened", "c2pa.placed"}:
        references = _ingredient_references(action, actions_label)
        relationship = "parentOf" if name == "c2pa.opened" else "componentOf"
        if references is None or not _ingredients_match(
            references,
            manifest,
            cache,
            relationship,
            exactly_one=name == "c2pa.opened",
        ):
            return StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH

    if name in {"c2pa.transcoded", "c2pa.repackaged"}:
        parameters = action.get("parameters")
        if isinstance(parameters, dict):
            key = "ingredient" if _is_label_instance(actions_label, (ASSERTION_ACTIONS_V1,)) else "ingredients"
            if key in parameters:
                references = _ingredient_references(action, actions_label)
                if references is None or not _ingredients_match(
                    references, manifest, cache, "parentOf", exactly_one=False
                ):
                    return StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH
    return None


def _action_redaction_status(action: dict[str, CborValue], manifest: ManifestStore) -> StatusCode | None:
    """Validate the target of a c2pa.redacted action."""
    if action.get("action") != "c2pa.redacted":
        return None
    parameters = action.get("parameters")
    redacted = parameters.get("redacted") if isinstance(parameters, dict) else None
    if not isinstance(redacted, str):
        return StatusCode.ASSERTION_ACTION_REDACTION_MISMATCH
    label = _assertion_label(redacted, manifest.manifest_label)
    if label is not None and label in manifest.assertion_bytes:
        return None
    return StatusCode.ASSERTION_ACTION_REDACTION_MISMATCH


def _action_status(
    action: dict[str, CborValue],
    actions_label: str,
    manifest: ManifestStore,
    cache: DigestCache,
    *,
    has_soft_binding: bool,
) -> StatusCode | None:
    """Apply the per-action requirements in C2PA 15.10.3.2.3."""
    name = action.get("action")
    if not isinstance(name, str):
        return StatusCode.ASSERTION_ACTION_MALFORMED

    ingredient = _action_ingredient_status(action, actions_label, manifest, cache)
    if ingredient is not None:
        return ingredient

    redaction = _action_redaction_status(action, manifest)
    if redaction is not None:
        return redaction

    related = _related_assertions_status(action, manifest, cache)
    if related is not None:
        return related

    if name in _WATERMARK_ACTIONS and not has_soft_binding:
        return StatusCode.ASSERTION_ACTION_SOFT_BINDING_MISSING
    return None


def _actions_status(
    manifest: ManifestStore,
    claim_order: list[str],
    gathered_order: list[str],
    cache: DigestCache,
) -> StatusCode | None:
    """Apply 15.10.1.2, 15.10.3.2.3 and 18.15.2 to every linked actions assertion."""
    groups = (
        tuple(dict.fromkeys(_actions_labels(claim_order))),
        tuple(dict.fromkeys(_actions_labels(gathered_order))),
    )
    all_labels = [*claim_order, *gathered_order]
    has_soft_binding = any(_is_label_instance(label, (_SOFT_BINDING_LABEL,)) for label in dict.fromkeys(all_labels))
    resolved: list[tuple[str, list[dict[str, CborValue]]]] = []
    inception_count = 0

    for labels in groups:
        for assertion_index, label in enumerate(labels):
            entries = _actions_entries(manifest.assertions.get(label))
            if entries is None:
                return StatusCode.ASSERTION_ACTION_MALFORMED
            resolved.append((label, entries))
            for action_index, action in enumerate(entries):
                if action.get("action") not in _INCEPTION_ACTIONS:
                    continue
                inception_count += 1
                if (assertion_index, action_index) != (0, 0):
                    return StatusCode.ASSERTION_ACTION_MALFORMED

    if inception_count != 1:
        return StatusCode.ASSERTION_ACTION_MALFORMED

    for label, entries in resolved:
        for action in entries:
            failure = _action_status(action, label, manifest, cache, has_soft_binding=has_soft_binding)
            if failure is not None:
                return failure
    return None


def _cloud_data_status(payload: CborValue) -> StatusCode | None:
    """Apply C2PA 15.10.3.2.1 without retrieving the optional remote data."""
    if not isinstance(payload, dict) or any(field not in payload for field in ("label", "size", "location")):
        return StatusCode.ASSERTION_CLOUD_DATA_MALFORMED
    target = payload.get("label")
    location = payload.get("location")
    if not isinstance(target, str) or not isinstance(location, dict):
        failure = StatusCode.ASSERTION_CLOUD_DATA_MALFORMED
    elif _is_label_instance(target, _CLOUD_HARD_BINDING_LABELS):
        failure = StatusCode.ASSERTION_CLOUD_DATA_HARD_BINDING
    elif (
        _is_label_instance(target, _CLOUD_MALFORMED_LABELS)
        or not isinstance(location.get("url"), str)
        or not isinstance(location.get("hash"), bytes)
    ):
        failure = StatusCode.ASSERTION_CLOUD_DATA_MALFORMED
    else:
        algorithm = location.get("alg")
        failure = (
            None if isinstance(algorithm, str) and algorithm in HASH_ALGORITHMS else StatusCode.ALGORITHM_UNSUPPORTED
        )
    return failure


def _external_reference_status(payload: CborValue) -> StatusCode | None:
    """Apply C2PA 15.10.3.2.2 without retrieving the optional remote data."""
    if not isinstance(payload, dict):
        return StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED
    location = payload.get("location")
    if not isinstance(location, dict) or not isinstance(location.get("url"), str):
        return StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED
    has_algorithm = "alg" in location
    has_hash = "hash" in location
    if has_algorithm != has_hash:
        failure = StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED
    elif has_algorithm:
        algorithm = location.get("alg")
        if not isinstance(algorithm, str) or algorithm not in HASH_ALGORITHMS:
            failure = StatusCode.ALGORITHM_UNSUPPORTED
        elif not isinstance(location.get("hash"), bytes):
            failure = StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED
        else:
            failure = None
    else:
        failure = None
    target = payload.get("label")
    if (
        failure is None
        and target is not None
        and (not isinstance(target, str) or _is_label_instance(target, _EXTERNAL_FORBIDDEN_LABELS))
    ):
        failure = StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED
    return failure


def _specific_assertion_status(manifest: ManifestStore, labels: list[str]) -> StatusCode | None:
    """Run the type-specific checks C2PA 15.10.3.2 assigns to linked assertions.

    Session-key binding, RFC 3161 token validation, alternative-content validation,
    and full ingredient-chain validation are outside this text profile. Their presence
    fails closed instead of producing a false ``VALID`` result.
    """
    for label in dict.fromkeys(labels):
        payload = manifest.assertions.get(label)
        if _is_label_instance(label, (_CLOUD_DATA_LABEL,)):
            failure = _cloud_data_status(payload)
        elif _is_label_instance(label, (_EXTERNAL_REFERENCE_LABEL,)):
            failure = _external_reference_status(payload)
        elif _is_label_instance(label, (_TIME_STAMP_LABEL,)):
            if not isinstance(payload, dict) or not payload:
                failure = StatusCode.ASSERTION_TIMESTAMP_MALFORMED
            else:
                failure = StatusCode.GENERAL_ERROR
        elif _is_label_instance(
            label,
            (*_INGREDIENT_LABELS, _SESSION_KEYS_LABEL, _ALTERNATIVE_CONTENT_LABEL),
        ):
            failure = StatusCode.GENERAL_ERROR
        else:
            failure = None
        if failure is not None:
            return failure
    return None


def _store_shape_status(
    manifest: ManifestStore,
    claim_order: list[str],
    gathered_order: list[str],
    cache: DigestCache,
) -> StatusCode | None:
    """Check the assertion store as a WHOLE, once every link has resolved.

    Separated from the per-link loop because none of these is a question about a single
    URI. The checks cover required assertions, hard bindings, parent ingredients,
    repository receipts, actions, and assertions that the claim never linked.

    The actions rule reads assertion content; the remaining checks use resolved labels.
    """
    # REQUIRED assertions are checked against created_assertions ALONE. 18.15.2 says
    # the actions assertion shall be "present in the created_assertions array", and the
    # 2.4 change log makes it explicit: "Required that the mandatory actions assertion
    # appear only in created_assertions (not gathered_assertions)." A gathered hard
    # binding binds another asset rather than this claim's asset.
    created = set(claim_order)
    failure: StatusCode | None = None
    if any(created.isdisjoint(accepted) for accepted in _REQUIRED_ASSERTIONS):
        failure = StatusCode.ASSERTION_MISSING

    # 15.10.1.2: "Validate that there is exactly one hard binding to content
    # assertion... If there is more than one such assertion, the manifest shall be
    # rejected with a failure code of assertion.multipleHardBindings." Checked BEFORE
    # the binding is evaluated, so it is never computed against an ambiguous store.
    # Count what the claim links, not every box the store holds. An unlinked box is
    # unauthenticated and is reported separately as assertion.undeclared.
    hard_bindings = _count_hard_bindings(claim_order)
    if failure is None and hard_bindings == 0:
        failure = StatusCode.CLAIM_HARD_BINDINGS_MISSING
    elif failure is None and hard_bindings > 1:
        failure = StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS

    if failure is None and _parent_ingredient_count(manifest, [*claim_order, *gathered_order]) > 1:
        failure = StatusCode.MANIFEST_MULTIPLE_PARENTS

    # 18.27 permits a repository receipt only in an Update Manifest. This package
    # reads Standard Manifests only, so a linked receipt here is always in the wrong
    # manifest type. The status registry has no code for that inverse placement:
    # manifest.update.invalid is specifically an UPDATE manifest carrying a forbidden
    # assertion. Table 4 therefore leaves general.error as the truthful fallback.
    if failure is None and any(
        _is_label_instance(label, (ASSERTION_REPOSITORY_RECEIPT,)) for label in (*claim_order, *gathered_order)
    ):
        failure = StatusCode.GENERAL_ERROR

    if failure is None:
        failure = _actions_status(manifest, claim_order, gathered_order, cache)

    if failure is None:
        failure = _specific_assertion_status(manifest, [*claim_order, *gathered_order])

    # 15.10.3.1: "If an assertion that is present in the assertion store is not
    # referenced by an element of either the created_assertions or gathered_assertions
    # arrays in the claim ... the claim shall be rejected with a failure code of
    # assertion.undeclared." An assertion in the store that the claim does not commit
    # to is signed by nothing. Rejected rather than ignored: a consumer reading the
    # store directly would otherwise see attacker-authored content beside authentic
    # content, with nothing in the verdict distinguishing them.
    #
    # ``assertion.undeclared`` distinguishes an extra store box from the opposite case,
    # where the claim names an assertion the store lacks.
    if failure is None and set(manifest.assertion_bytes) - set(claim_order) - set(gathered_order):
        failure = StatusCode.ASSERTION_UNDECLARED

    return failure


def _check_binding(
    text: str, manifest: ManifestStore, verdict: Verdict, matches: Sequence[WrapperMatch]
) -> tuple[Verdict, bool]:
    """Apply the hard-binding status to the verdict."""
    codes = _binding_status(text, manifest, matches)
    for code in codes:
        verdict = verdict._add(code)
    return verdict, StatusCode.DATA_HASH_MATCH in codes


def _accept_credential(chain: list[Certificate]) -> tuple[StatusCode, str] | CertificatePublicKeyTypes:
    """Whether the leaf meets the X.509 profile, and if so return its key.

    Algorithm/key compatibility belongs to signature validation, after the protected
    ``alg`` value is known. A profile-conforming EC or RSA certificate is not an
    invalid credential merely because this package cannot verify its signature.
    """
    try:
        check_certificate_chain_profile(chain)
    except ProfileError as exc:
        # A profile violation is signingCredential.invalid -- a hard reject where the
        # manifest is not even Valid -- and is NOT the same as an unreachable anchor.
        # The message is CARRIED, not discarded: check_certificate_chain_profile already
        # computed exactly which rule failed, and throwing that away leaves a caller
        # with a bare code and no idea which extension to fix.
        return StatusCode.SIGNING_CREDENTIAL_INVALID, str(exc)

    # _load_chain already forced this lazy parse inside the hostile-DER boundary, and
    # check_certificate_chain_profile read it again before reaching this line.
    return chain[0].public_key()


# Each failure returns its C2PA status where it is classified. Folding these exits into
# a second failure-object hierarchy made the flow longer and duplicated COSE's types.
def _check_signature(  # noqa: PLR0911
    manifest: ManifestStore,
    verdict: Verdict,
    context: VerifyContext,
) -> tuple[Verdict, bool, bool]:
    """Validate the claim signature and evaluate trust.

    Returns ``(verdict, signature_ok, trusted)``.
    """
    url = manifest.claim.get("signature")
    if not isinstance(url, str) or not _signature_uri_resolves(url, manifest.manifest_label):
        return (
            verdict._add(StatusCode.CLAIM_SIGNATURE_MISSING, "the claim signature URI does not resolve"),
            False,
            False,
        )

    try:
        message = _cose.parse(manifest.signature)
    except _cose.CoseCredentialError as exc:
        return verdict._add(StatusCode.SIGNING_CREDENTIAL_INVALID, str(exc)), False, False
    except _cose.CoseStructureError as exc:
        # C2PA has no dedicated code for a located signature box whose COSE structure
        # is malformed. Table 4 defines general.error for an error not listed there.
        return verdict._add(StatusCode.GENERAL_ERROR, str(exc)), False, False

    # Reject an algorithm outside C2PA 13.2.1 before parsing and profiling its
    # credential. All algorithms on the allowed list are verified below.
    try:
        algorithm = _cose._check_algorithm(message)
    except _cose.CoseAlgorithmError as exc:
        return verdict._add(StatusCode.ALGORITHM_UNSUPPORTED, str(exc)), False, False

    # parse() has already selected, validated, and cached the immutable DER tuple.
    ders = message.x5chain()
    chain, unreadable_index = _load_chain(ders)
    if chain is None:
        role = "leaf" if unreadable_index == 0 else "carried CA"
        return (
            verdict._add(
                StatusCode.SIGNING_CREDENTIAL_INVALID,
                f"x5chain[{unreadable_index}] {role} carried bytes that are not a readable certificate",
            ),
            False,
            False,
        )

    public_key = _accept_credential(chain)
    if isinstance(public_key, tuple):
        code, explanation = public_key
        return verdict._add(code, explanation), False, False
    try:
        _cose._verify_signature(message, manifest.claim_bytes, public_key, algorithm)
    except _cose.CoseSignatureError as exc:
        return verdict._add(StatusCode.CLAIM_SIGNATURE_MISMATCH, str(exc)), False, False

    verdict = verdict._add(StatusCode.CLAIM_SIGNATURE_VALIDATED)

    # C2PA 15.8 prefers a validated trusted sigTst2 time. This implementation does not
    # validate sigTst2, so it uses the verifier-supplied instant or current time. The
    # check covers the certificates carried in x5chain. RFC 5280 path construction,
    # further path certificates, revocation data, and trust-anchor policy belong to
    # the caller's TrustEvaluator.
    outside_index = _first_certificate_outside_validity(chain, context.now or _utcnow())
    if outside_index is not None:
        role = "signing certificate" if outside_index == 0 else f"x5chain[{outside_index}] carried CA"
        return (
            verdict._add(
                StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY,
                f"the {role} is outside its validity period at validation time (15.8)",
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


def _first_certificate_outside_validity(chain: list[Certificate], when: datetime.datetime) -> int | None:
    """Return the first out-of-window x5chain index, or ``None``.

    This checks the signer and each CA carried in ``x5chain``. A caller-owned path
    validator remains responsible for any further certificate up to its trust anchor.
    The timezone-aware certificate accessors are compared with a timezone-aware
    verifier instant.
    """
    return next(
        (
            index
            for index, certificate in enumerate(chain)
            if not certificate.not_valid_before_utc <= when <= certificate.not_valid_after_utc
        ),
        None,
    )


def _is_trusted(chain: list[Certificate], context: VerifyContext) -> tuple[bool, str | None]:
    """Ask the caller's evaluator whether the chain reaches an anchor.

    An unreachable anchor is the normal ``signingCredential.untrusted`` result. If the
    caller's evaluator raises, verification also returns untrusted and carries the
    exception type and message in the status explanation.
    """
    anchors = list(context.anchors)
    if not anchors:
        return False, None
    try:
        return context.trust_evaluator.is_trusted(chain, anchors), None
    except Exception as exc:  # noqa: BLE001 -- a caller's evaluator may raise anything; see above
        return False, f"the trust evaluator raised {type(exc).__name__}: {exc}"


def _select_text_manifest(
    matches: Sequence[WrapperMatch],
) -> tuple[WrapperMatch, ManifestStore] | MarkCorruptError | StatusCode:
    """Select the wrapper whose own manifest exclusion names its exact range.

    C2PA 15.12.1.3.1 makes exclusion matching authoritative when several valid
    wrappers occur. A single wrapper needs no disambiguation; its binding phase still
    reports a missing or malformed exclusion with the clause-specific code.
    """
    parsed: list[tuple[WrapperMatch, ManifestStore]] = []
    errors: list[MarkCorruptError] = []
    for match in matches:
        try:
            manifest = parse_manifest_store(match.payload)
        except MarkCorruptError as exc:
            errors.append(exc)
            continue
        parsed.append((match, manifest))

    if len(matches) == 1:
        return parsed[0] if parsed else errors[0]

    candidates: list[tuple[WrapperMatch, ManifestStore]] = []
    for match, manifest in parsed:
        hash_data = manifest.hash_data
        exclusions = _exclusion_ranges(hash_data) if hash_data is not None else None
        own_range = (match.span.utf8_start, len(match.span))
        if exclusions is not None and own_range in exclusions:
            candidates.append((match, manifest))

    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        return StatusCode.TEXT_MULTIPLE_WRAPPERS
    if not parsed and errors:
        return errors[0]
    return StatusCode.DATA_HASH_MALFORMED


def verify(text: str, *, context: VerifyContext | None = None) -> Verdict:
    """Validate the Content Credential in ``text`` and report what was found.

    Never raises for absent, corrupt or invalid marks -- every outcome is a
    :class:`Verdict`. The result is a four-state :class:`Provenance`, not a boolean.

    The one exception is text UTF-8 cannot represent: a ``str`` holding an unpaired
    surrogate is not a text asset this specification can describe, so there is no
    verdict to give and :class:`UnencodableTextError` is raised instead.

    Certificate parsing is kept inside :func:`_load_chain`, including fields that
    ``cryptography`` parses lazily, so hostile certificate bytes become an ``INVALID``
    verdict rather than leaking backend exceptions.

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

    selected = _select_text_manifest(matches)
    if isinstance(selected, StatusCode):
        return Verdict(state=Provenance.INVALID, span=matches[0].span)._add(selected)
    if isinstance(selected, MarkCorruptError):
        return Verdict(state=Provenance.INVALID, span=matches[0].span)._add(selected.code)
    match, manifest = selected

    verdict = Verdict(state=Provenance.INVALID, span=match.span, manifest=manifest)
    # Assertions FIRST: the hard binding lives in an assertion, and reading it before
    # the claim's hashed-URI link is checked means trusting an unauthenticated map.
    verdict, assertions_ok = _check_assertions(manifest, verdict)
    verdict, binding_ok = _check_binding(text, manifest, verdict, matches)
    verdict, signature_ok, trusted = _check_signature(manifest, verdict, context)

    if not (assertions_ok and binding_ok and signature_ok):
        return verdict
    return dataclasses.replace(verdict, state=Provenance.TRUSTED if trusted else Provenance.VALID)
