"""
C2PA validation status codes (2.4 clauses 15.2 and 15.2.1) and the three-bucket result model.

Codes are the specification's own strings, never paraphrases. ``__str__`` is defined
explicitly so formatting returns the same wire string on every supported Python.
"""

from __future__ import annotations

import dataclasses
import enum
import inspect

__all__ = [
    "Status",
    "StatusCode",
    "StatusKind",
]


class StatusCode(str, enum.Enum):
    """A C2PA validation status code.

    The value is the wire string. ``__str__`` is overridden so it stays the wire
    string on every supported Python; see the module docstring.
    """

    # --- Text-specific (A.8.7.1, 15.12.1.3) ---------------------------------
    TEXT_CORRUPTED_WRAPPER = "manifest.text.corruptedWrapper"
    TEXT_MULTIPLE_WRAPPERS = "manifest.text.multipleWrappers"

    # --- Hard binding (15.12.1.1, 15.12.1.3.1) ------------------------------
    DATA_HASH_MATCH = "assertion.dataHash.match"
    DATA_HASH_MISMATCH = "assertion.dataHash.mismatch"
    DATA_HASH_MALFORMED = "assertion.dataHash.malformed"
    DATA_HASH_ADDITIONAL_EXCLUSIONS = "assertion.dataHash.additionalExclusionsPresent"

    # --- Assertion links (8.4.2.3, 15.10.3.1) ----------------------------------
    ASSERTION_HASHED_URI_MATCH = "assertion.hashedURI.match"
    ASSERTION_HASHED_URI_MISMATCH = "assertion.hashedURI.mismatch"
    ASSERTION_ACTION_MALFORMED = "assertion.action.malformed"
    ASSERTION_ACTION_INGREDIENT_MISMATCH = "assertion.action.ingredientMismatch"
    ASSERTION_ACTION_REDACTION_MISMATCH = "assertion.action.redactionMismatch"
    ASSERTION_ACTION_SOFT_BINDING_MISSING = "assertion.action.softBindingMissing"
    ASSERTION_CLOUD_DATA_HARD_BINDING = "assertion.cloud-data.hardBinding"
    ASSERTION_CLOUD_DATA_MALFORMED = "assertion.cloud-data.malformed"
    ASSERTION_CBOR_INVALID = "assertion.cbor.invalid"
    ASSERTION_EXTERNAL_REFERENCE_MALFORMED = "assertion.external-reference.malformed"
    ASSERTION_JSON_INVALID = "assertion.json.invalid"
    ASSERTION_MISSING = "assertion.missing"
    ASSERTION_UNDECLARED = "assertion.undeclared"
    ASSERTION_MULTIPLE_HARD_BINDINGS = "assertion.multipleHardBindings"
    ASSERTION_OUTSIDE_MANIFEST = "assertion.outsideManifest"
    ASSERTION_SELF_REDACTED = "assertion.selfRedacted"
    ASSERTION_TIMESTAMP_MALFORMED = "assertion.timestamp.malformed"

    # --- General fallback and claim signature (15.7) -------------------------
    GENERAL_ERROR = "general.error"
    CLAIM_SIGNATURE_VALIDATED = "claimSignature.validated"
    CLAIM_SIGNATURE_MISMATCH = "claimSignature.mismatch"
    CLAIM_SIGNATURE_MISSING = "claimSignature.missing"
    CLAIM_SIGNATURE_INSIDE_VALIDITY = "claimSignature.insideValidity"
    CLAIM_SIGNATURE_OUTSIDE_VALIDITY = "claimSignature.outsideValidity"

    # --- Signing credential (15.7, 14.3) ------------------------------------
    SIGNING_CREDENTIAL_TRUSTED = "signingCredential.trusted"
    SIGNING_CREDENTIAL_UNTRUSTED = "signingCredential.untrusted"
    SIGNING_CREDENTIAL_INVALID = "signingCredential.invalid"

    # --- Claim structure (15.6), and references inside structures (15.10.3.3) ---
    CLAIM_CBOR_INVALID = "claim.cbor.invalid"
    CLAIM_MALFORMED = "claim.malformed"
    CLAIM_MISSING = "claim.missing"
    HASHED_URI_MISSING = "hashedURI.missing"
    HASHED_URI_MISMATCH = "hashedURI.mismatch"
    CLAIM_MULTIPLE = "claim.multiple"
    CLAIM_HARD_BINDINGS_MISSING = "claim.hardBindings.missing"
    MANIFEST_MULTIPLE_PARENTS = "manifest.multipleParents"

    # --- Algorithm and manifest (13.1, 15.4) ------------------------------
    ALGORITHM_UNSUPPORTED = "algorithm.unsupported"

    def __str__(self) -> str:
        """Return the bare specification string, identically on 3.10 through 3.14."""
        return self.value

    __format__ = str.__format__


#: C2PA 15.2.2.3 ("Failure codes") is the registry these three buckets partition;
#: 15.2.2.1 and 15.2.2.2 give the success and informational halves.
class StatusKind(str, enum.Enum):
    """Which of the specification's three buckets a status belongs to.

    C2PA 15.2 groups statuses as success, informational or failure. The
    ``status-map`` CDDL marks the older ``? "success": bool`` field DEPRECATED in
    favour of exactly these buckets, so a boolean must not be reintroduced.
    """

    SUCCESS = "success"
    INFORMATIONAL = "informational"
    FAILURE = "failure"

    def __str__(self) -> str:
        return self.value

    __format__ = str.__format__


#: What each code means, keyed by member. Enum member assignments do not retain an
#: adjacent string as their member docstring, so the mapping is assigned below.
#:
#: Each entry says the CONDITION that produces the code, the CLAUSE that names it, and
#: -- where a caller can act -- what to do. These are wire strings an integrator
#: interpolates into their own API responses.
_EXPLANATIONS: dict[StatusCode, str] = {
    StatusCode.TEXT_CORRUPTED_WRAPPER: """The wrapper's magic matched but its structure is damaged (15.12.1.3.2).

    A version field that is not 1, a ``manifestLength`` overrunning the decoded run, a
    run shorter than the 13-byte header, or an undecodable selector. Also reported --
    with no better code existing -- when the payload is not parseable JUMBF at all; see
    docs/open-questions.md. The code identifies damaged input; it does not establish
    when or how the damage occurred.""",
    StatusCode.TEXT_MULTIPLE_WRAPPERS: """More than one located wrapper matches a signed exclusion range.

    C2PA 15.12.1.3.1 requires rejection because the exclusions do not select one
    authoritative manifest. Extra wrappers whose ranges do not match remain covered by
    the selected hard binding and do not trigger this code.""",
    StatusCode.DATA_HASH_MATCH: """SUCCESS. The hard binding matches the NFC-normalized covered text.

    The verifier removed the declared exclusions, normalized the remaining text to
    NFC, encoded it as UTF-8, and matched its digest as required by 15.12.1.3.1.""",
    StatusCode.DATA_HASH_MISMATCH: """The text does not hash to what the claim signed (15.12.1.3.1).

    ``claimSignature.validated`` can appear beside this code because the signature
    authenticates the claim, while the hard binding compares that claim with this
    text. The code does not distinguish an edit from a wrong binding or producer
    inconsistency.""",
    StatusCode.DATA_HASH_MALFORMED: """The exclusion range is unusable, so no digest was computed.

    No range names a located wrapper, ranges overlap or are out of order, or removing
    the ranges leaves text that is not UTF-8, or its NFKD form exceeds the package's
    30-nonstarter normalization limit. This is reported instead of a digest mismatch
    because no comparable digest was available.""",
    StatusCode.DATA_HASH_ADDITIONAL_EXCLUSIONS: """
    INFORMATIONAL. The data hash excludes ranges beyond the manifest wrapper.

    C2PA 15.12.1.1 requires this notice when additional exclusion ranges are present.
    Their bytes are omitted from the digest along with the wrapper.""",
    StatusCode.ASSERTION_HASHED_URI_MATCH: """
    SUCCESS. An assertion the claim links hashes to the value the claim recorded.

    15.10.3.1. One per linked assertion, so several normally appear together.""",
    StatusCode.ASSERTION_HASHED_URI_MISMATCH: """
    An assertion's bytes do not match the digest the claim recorded (15.10.3.1).

    Distinct from ``hashedURI.mismatch``, which is 15.10.3.3's code for a reference
    inside a structure -- a generator or action icon -- rather than a claim link. The
    code does not establish how the bytes came to differ.""",
    StatusCode.ASSERTION_ACTION_MALFORMED: """An actions assertion breaks C2PA 15.10.3.2.3.

    This covers a missing or malformed ``actions`` list, an action without a string
    name, an inception action in the wrong position, and malformed or forbidden
    ``relatedAssertions`` references.""",
    StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH: """
    An opened, placed, removed, transcoded or repackaged action does not name the
    ingredient assertions that C2PA 15.10.3.2.3 requires. Opened, transcoded and
    repackaged actions use ``parentOf``; placed uses ``componentOf``; removed must name
    a ``componentOf`` ingredient in another manifest.""",
    StatusCode.ASSERTION_ACTION_REDACTION_MISMATCH: """
    A ``c2pa.redacted`` action has no resolvable JUMBF URI in its ``redacted``
    parameter (15.10.3.2.3).""",
    StatusCode.ASSERTION_ACTION_SOFT_BINDING_MISSING: """
    A ``c2pa.watermarked`` or ``c2pa.watermarked.bound`` action appears without a
    ``c2pa.soft-binding`` assertion in the manifest (15.10.3.2.3).""",
    StatusCode.ASSERTION_CLOUD_DATA_HARD_BINDING: """
    A ``c2pa.cloud-data`` assertion names a hard-binding or ingredient assertion type,
    which C2PA 15.10.3.2.1 forbids from remote storage.""",
    StatusCode.ASSERTION_CLOUD_DATA_MALFORMED: """
    A ``c2pa.cloud-data`` assertion is incomplete or names an assertion type that
    C2PA 15.10.3.2.1 does not permit there.""",
    StatusCode.ASSERTION_CBOR_INVALID: """An assertion's CBOR is invalid (15.10.3.1).

    Malformed bytes fail RFC 8949 Appendix C. Non-deterministic encodings remain
    readable; duplicate map keys are well-formed but invalid and ambiguous, so they
    are refused too.""",
    StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED: """
    A ``c2pa.external-reference`` assertion lacks a usable location, carries only one
    of ``alg`` and ``hash``, or names a forbidden assertion type (15.10.3.2.2).""",
    StatusCode.ASSERTION_JSON_INVALID: """A standard JSON assertion is not well-formed JSON.

    C2PA 15.10.3.1 names the code. JSON follows RFC 8259 and may hold any top-level
    JSON value; metadata and repository receipts are the standard JSON assertions this
    package reads.""",
    StatusCode.ASSERTION_MISSING: """
    The claim links an assertion the store does not contain, or the required actions
    assertion is absent. A missing hard binding has the dedicated
    ``claim.hardBindings.missing`` code.

    A standard manifest requires either ``c2pa.actions.v2`` or v1 ``c2pa.actions`` in
    ``created_assertions``.""",
    StatusCode.ASSERTION_UNDECLARED: """The store holds an assertion the claim never linked.

    Unlinked bytes are unauthenticated: nothing in the signature covers them, so a
    reader who trusts them is trusting whoever last touched the file.""",
    StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS: """More than one hard binding to content (15.10.1.2).

    With two, there is no defined answer to which one binds the text, so the manifest
    is rejected before either is evaluated rather than after picking one.""",
    StatusCode.ASSERTION_OUTSIDE_MANIFEST: """A claim link points outside this manifest (8.4.2.1).

    Either a URI naming a different manifest, or one that is not a resolvable
    ``self#jumbf`` reference at all. A claim may only vouch for its own assertions.""",
    StatusCode.ASSERTION_SELF_REDACTED: """
    The claim's ``redacted_assertions`` list points into its own manifest, which C2PA
    15.10.3.1 forbids. A claim may declare redaction only for an earlier manifest.""",
    StatusCode.ASSERTION_TIMESTAMP_MALFORMED: """
    A ``c2pa.time-stamp`` assertion is not a non-empty CBOR map (15.10.3.2.6).""",
    StatusCode.GENERAL_ERROR: """A validation error occurred for which C2PA defines no more specific code.""",
    StatusCode.CLAIM_SIGNATURE_VALIDATED: """
    SUCCESS. The COSE_Sign1 signature over the claim verifies against the leaf's key.

    This is not a statement about the text. Whether the verified claim describes this
    text is the hard binding's answer, so this code can appear beside a binding
    failure.""",
    StatusCode.CLAIM_SIGNATURE_MISMATCH: """The claim signature does not verify (15.7).

    The received claim, signature, protected algorithm, and leaf key do not form a
    valid signature. This also covers a protected algorithm paired with an incompatible
    key type, which 13.2.1 requires validators to refuse.""",
    StatusCode.CLAIM_SIGNATURE_MISSING: """The manifest carries no ``c2pa.signature`` box (15.7).

    Structurally intact and unsigned, which is not something a conforming producer
    emits.""",
    StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY: """
    SUCCESS. The signer and every certificate carried in ``x5chain`` are inside their
    validity windows at the verifier's reference instant.

    C2PA 15.8 prefers a validated trusted ``sigTst2`` time. Because this implementation
    does not validate that token, it uses ``VerifyContext.now`` or the current time.
    RFC 5280 path construction and any further path certificates are caller-owned.""",
    StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY: """
    A certificate carried in ``x5chain`` is outside its validity window (15.8).

    In the absence of supported trusted ``sigTst2`` validation, the reference instant
    is ``VerifyContext.now`` when supplied and otherwise the current time. This is a
    certificate-validity result, not evidence that the text was altered.""",
    StatusCode.SIGNING_CREDENTIAL_TRUSTED: """SUCCESS. The chain reaches a trust anchor YOU supplied.

    14.3.6. Requires both ``anchors_pem`` and a ``TrustEvaluator`` on the
    ``VerifyContext``; this package ships no anchors and the default evaluator trusts
    nothing, so this code never appears by default.""",
    StatusCode.SIGNING_CREDENTIAL_UNTRUSTED: """
    The signer was not corroborated against any anchor -- AND THIS DOES NOT INVALIDATE.

    THE SINGLE MOST LIKELY MISREADING IN THIS PACKAGE. It sits in the FAILURE bucket
    because the specification puts it there, but C2PA 14.3.5 defines a *Valid* manifest
    WITHOUT requiring trust; 14.3.6 adds trust separately. A correct self-signed mark
    verifies as ``VALID`` carrying this code, and that is the expected outcome, not an
    error.

    ACT: to reach ``TRUSTED``, supply anchors and an evaluator. Do not render this as
    "unverified" or "suspicious"; render it as "signer not independently verified".""",
    StatusCode.SIGNING_CREDENTIAL_INVALID: """
    The leaf or a carried CA does not meet the credential profile (14.5.1.1).

    Checks include the certificate signature algorithm and PSS parameters, subject-key
    curve or RSA size, version and unique IDs, and role-specific Basic Constraints,
    AKI, SKI, Key Usage, and Extended Key Usage rules. The leaf EKU must be present and
    non-empty, but 14.5.1.1 names no single required EKU OID.

    An algorithm/key mismatch is a signature-validation failure, not a defect in a
    certificate that already passed this profile.""",
    StatusCode.CLAIM_CBOR_INVALID: """The claim's bytes are invalid CBOR (15.6.2).

    This covers malformed bytes and ambiguous duplicate-key maps. Distinct from
    ``claim.malformed``: that code means CBOR decoded into the wrong claim shape.""",
    StatusCode.CLAIM_MALFORMED: """The claim decoded but is not a valid claim (15.6.2).

    Not a CBOR map, or missing a field 15.6.2 requires. The CBOR is impeccable; the
    structure inside it is not a claim.""",
    StatusCode.CLAIM_MISSING: """The manifest carries no claim box, or its claim box carries no CBOR (15.6).

    Without a claim there is nothing to validate against.""",
    StatusCode.HASHED_URI_MISSING: """
    A reference inside a structure names a destination that cannot be located (15.10.3.3).

    A generator or action icon whose ``url`` is absent, unresolvable, or names an
    assertion or data-box resource this package cannot locate. A remote
    ``hashed_ext_uri`` that the caller does not retrieve is optional and does not use
    this code.""",
    StatusCode.HASHED_URI_MISMATCH: """A reference's destination does not hash to the recorded value (15.10.3.3).

    Also reported when the ``hash`` field is absent or is not a byte string, since the
    clause names no separate code and no computed digest can equal a non-digest.""",
    StatusCode.CLAIM_MULTIPLE: """The current manifest carries more than one recognized claim box (15.6.1).""",
    StatusCode.CLAIM_HARD_BINDINGS_MISSING: """The claim links no hard binding to content (15.10.1.2).

    Without one, nothing ties the manifest to any particular text, and the mark could be
    lifted onto any document.""",
    StatusCode.MANIFEST_MULTIPLE_PARENTS: """
    A standard manifest links more than one ingredient whose relationship is
    ``parentOf``. C2PA 15.10.1.2 permits at most one parent ingredient.""",
    StatusCode.ALGORITHM_UNSUPPORTED: """The named hash or signature algorithm cannot be used here.

    13.1 permits sha256, sha384 and sha512 and says implementations "shall not support
    additional algorithms on an optional basis". An ABSENT ``alg`` inherits from the
    claim (15.4.1); a PRESENT but unsupported one does not fall back, because falling
    back would let a producer ask for a weak hash and silently get a strong one.

    Signature algorithms outside C2PA 13.2.1's allowed list also land here. Algorithms
    on that list are verified; an allowed algorithm paired with the wrong key or a bad
    signature is instead ``claimSignature.mismatch``.""",
}

for _code, _text in _EXPLANATIONS.items():
    # cleandoc, so the assigned text reads the same as a real docstring: no leading
    # newline, no common indentation. Some entries put their summary on the line after
    # the opening quotes to stay inside the line limit, and that must not show.
    _code.__doc__ = inspect.cleandoc(_text)

#: Which bucket each code belongs to. A code absent here is a programming error, not an
#: input error, so lookup raises rather than guessing.
_KIND: dict[StatusCode, StatusKind] = {
    StatusCode.DATA_HASH_MATCH: StatusKind.SUCCESS,
    StatusCode.ASSERTION_HASHED_URI_MATCH: StatusKind.SUCCESS,
    StatusCode.CLAIM_SIGNATURE_VALIDATED: StatusKind.SUCCESS,
    StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY: StatusKind.SUCCESS,
    StatusCode.SIGNING_CREDENTIAL_TRUSTED: StatusKind.SUCCESS,
    StatusCode.DATA_HASH_ADDITIONAL_EXCLUSIONS: StatusKind.INFORMATIONAL,
    StatusCode.TEXT_CORRUPTED_WRAPPER: StatusKind.FAILURE,
    StatusCode.TEXT_MULTIPLE_WRAPPERS: StatusKind.FAILURE,
    StatusCode.DATA_HASH_MISMATCH: StatusKind.FAILURE,
    StatusCode.DATA_HASH_MALFORMED: StatusKind.FAILURE,
    StatusCode.ASSERTION_HASHED_URI_MISMATCH: StatusKind.FAILURE,
    StatusCode.ASSERTION_ACTION_MALFORMED: StatusKind.FAILURE,
    StatusCode.ASSERTION_ACTION_INGREDIENT_MISMATCH: StatusKind.FAILURE,
    StatusCode.ASSERTION_ACTION_REDACTION_MISMATCH: StatusKind.FAILURE,
    StatusCode.ASSERTION_ACTION_SOFT_BINDING_MISSING: StatusKind.FAILURE,
    StatusCode.ASSERTION_CLOUD_DATA_HARD_BINDING: StatusKind.FAILURE,
    StatusCode.ASSERTION_CLOUD_DATA_MALFORMED: StatusKind.FAILURE,
    StatusCode.ASSERTION_CBOR_INVALID: StatusKind.FAILURE,
    StatusCode.ASSERTION_EXTERNAL_REFERENCE_MALFORMED: StatusKind.FAILURE,
    StatusCode.ASSERTION_JSON_INVALID: StatusKind.FAILURE,
    StatusCode.ASSERTION_MISSING: StatusKind.FAILURE,
    StatusCode.ASSERTION_UNDECLARED: StatusKind.FAILURE,
    StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS: StatusKind.FAILURE,
    StatusCode.ASSERTION_OUTSIDE_MANIFEST: StatusKind.FAILURE,
    StatusCode.ASSERTION_SELF_REDACTED: StatusKind.FAILURE,
    StatusCode.ASSERTION_TIMESTAMP_MALFORMED: StatusKind.FAILURE,
    StatusCode.CLAIM_SIGNATURE_MISMATCH: StatusKind.FAILURE,
    StatusCode.CLAIM_SIGNATURE_MISSING: StatusKind.FAILURE,
    StatusCode.GENERAL_ERROR: StatusKind.FAILURE,
    StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY: StatusKind.FAILURE,
    StatusCode.SIGNING_CREDENTIAL_UNTRUSTED: StatusKind.FAILURE,
    StatusCode.SIGNING_CREDENTIAL_INVALID: StatusKind.FAILURE,
    StatusCode.CLAIM_CBOR_INVALID: StatusKind.FAILURE,
    StatusCode.CLAIM_MALFORMED: StatusKind.FAILURE,
    StatusCode.CLAIM_MISSING: StatusKind.FAILURE,
    StatusCode.HASHED_URI_MISSING: StatusKind.FAILURE,
    StatusCode.HASHED_URI_MISMATCH: StatusKind.FAILURE,
    StatusCode.CLAIM_MULTIPLE: StatusKind.FAILURE,
    StatusCode.CLAIM_HARD_BINDINGS_MISSING: StatusKind.FAILURE,
    StatusCode.MANIFEST_MULTIPLE_PARENTS: StatusKind.FAILURE,
    StatusCode.ALGORITHM_UNSUPPORTED: StatusKind.FAILURE,
}


@dataclasses.dataclass(frozen=True, slots=True)
class Status:
    """One status code, optionally naming the box it concerns.

    Attributes:
        code: the specification code.
        url: a JUMBF URI identifying the box this applies to, when one is known.
        explanation: free text for a human reading a debugger. NEVER assembled into
            a user-facing message by this package -- rendering is the integrator's
            job, and we ship codes rather than prose so they can localise.
    """

    code: StatusCode
    url: str | None = None
    explanation: str | None = None

    @property
    def kind(self) -> StatusKind:
        """The bucket this code belongs to.

        Raises:
            KeyError: if the code has no bucket. That is a bug in this package
                rather than a property of the input, so it is not softened.
        """
        return _KIND[self.code]

    def __str__(self) -> str:
        return str(self.code)
