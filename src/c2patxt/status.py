"""
C2PA validation status codes (2.4 clause 15.2) and the three-bucket result model.

Codes are the specification's own strings, never paraphrases. Someone who reads an
error we produced and searches the C2PA specification for it must land on the right
clause.

WHY THIS IS NOT ``class StatusCode(str, Enum)``
-----------------------------------------------
A plain ``(str, Enum)`` member formats DIFFERENTLY on different interpreters.
Verified on real builds:

    Python 3.10.15   f"{member}"  ->  'signingCredential.untrusted'
    Python 3.14.6    f"{member}"  ->  'StatusCode.SIGNING_CREDENTIAL_UNTRUSTED'

Our supported range is 3.10 through 3.14, and these values are WIRE STRINGS an
integrator will interpolate into their own API responses. A silent, version-dependent
change of a serialized status code is exactly the kind of defect that ships. The
cause is documented in What's New in Python 3.11, ``enum`` section.

``__str__`` is therefore defined explicitly, pinning ``str()``, f-strings,
``format()``, ``%s`` and ``json.dumps`` to the bare specification string on every
supported interpreter. ``backports.strenum`` is unusable here: it declares
``requires_python = ">=3.8.6,<3.11"``, so it cannot install on the versions that
would need it.
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

    # --- Assertion links (8.4.2.3, 15.10.3.1) ----------------------------------
    ASSERTION_HASHED_URI_MATCH = "assertion.hashedURI.match"
    ASSERTION_HASHED_URI_MISMATCH = "assertion.hashedURI.mismatch"
    ASSERTION_ACTION_MALFORMED = "assertion.action.malformed"
    ASSERTION_CBOR_INVALID = "assertion.cbor.invalid"
    ASSERTION_JSON_INVALID = "assertion.json.invalid"
    ASSERTION_MISSING = "assertion.missing"
    ASSERTION_UNDECLARED = "assertion.undeclared"
    ASSERTION_MULTIPLE_HARD_BINDINGS = "assertion.multipleHardBindings"
    ASSERTION_OUTSIDE_MANIFEST = "assertion.outsideManifest"

    # --- Claim signature (15.7), and the AI-disclosure catch-all (18.28.2) ---
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


#: What each code MEANS, keyed by member. Assigned to ``__doc__`` below rather than
#: written as a literal under each member, because an enum discards those: the string
#: after ``NAME = "value"`` never reaches ``StatusCode.NAME.__doc__``, which returns the
#: CLASS docstring instead. Verified. So the form the reader would expect is the one
#: form that does not work, and this mapping is what makes ``StatusCode.X.__doc__``
#: answer the question.
#:
#: Each entry says the CONDITION that produces the code, the CLAUSE that names it, and
#: -- where a caller can act -- what to do. These are wire strings an integrator
#: interpolates into their own API responses, so they are the vocabulary this package
#: asks a third party to republish, and they were shipping with no explanation at all:
#: three had no sentence anywhere in the repository, thirteen appeared in no markdown,
#: and only four told a reader what to DO.
_EXPLANATIONS: dict[StatusCode, str] = {
    StatusCode.TEXT_CORRUPTED_WRAPPER: """The wrapper's magic matched but its structure is damaged (15.12.1.3.2).

    A version field that is not 1, a ``manifestLength`` overrunning the decoded run, a
    run shorter than the 13-byte header, or an undecodable selector. Also reported --
    with no better code existing -- when the payload is not parseable JUMBF at all; see
    docs/open-questions.md.

    ACT: the text was truncated or re-encoded in transit. Re-fetch it from the source
    rather than trying to repair it.""",
    StatusCode.TEXT_MULTIPLE_WRAPPERS: """The text carries more than one wrapper.

    A.8 places exactly one. Two means someone appended a second mark to text that
    already had one, and no rule says which is authoritative -- so neither is honoured.

    ACT: treat as unverifiable, not as tampering. Concatenating two marked documents
    produces this innocently.""",
    StatusCode.DATA_HASH_MATCH: """SUCCESS. The hard binding matched: not one byte of the covered text has changed.

    15.12.1.3.1. The strongest statement this package makes.""",
    StatusCode.DATA_HASH_MISMATCH: """The text does not hash to what the claim signed (15.12.1.3.1).

    The covered text was edited after signing. The signature over the CLAIM may still
    be intact -- ``claimSignature.validated`` can appear beside this -- because only the
    binding between claim and text broke.

    ACT: this is the code that means "edited". Say so; do not say "fake".""",
    StatusCode.DATA_HASH_MALFORMED: """The exclusion range is unusable, so no digest was computed.

    The range does not name a located wrapper, is not a suffix of the text, splits a
    UTF-8 code point, or the assertion names several ranges where A.8 places one.
    Reported INSTEAD of a mismatch, deliberately: a mismatch would send an investigator
    hunting a text edit that did not happen.""",
    StatusCode.ASSERTION_HASHED_URI_MATCH: """
    SUCCESS. An assertion the claim links hashes to the value the claim recorded.

    15.10.3.1. One per linked assertion, so several normally appear together.""",
    StatusCode.ASSERTION_HASHED_URI_MISMATCH: """
    An assertion's bytes do not match the digest the claim recorded (15.10.3.1).

    The assertion was substituted or altered after the claim was signed. Distinct from
    ``hashedURI.mismatch``, which is 15.10.3.3's code for a reference INSIDE a
    structure -- a generator or action icon -- rather than a claim link.""",
    StatusCode.ASSERTION_ACTION_MALFORMED: """The actions assertion breaks 15.10.3.2.3's rules for an inception action.

    Either no ``c2pa.created`` or ``c2pa.opened`` action, or one that is not the first
    element of the first actions assertion the claim links, or a ``c2pa.created``
    carrying no ``digitalSourceType``.

    WHY THIS MATTERS MOST: ``digitalSourceType`` is the field that actually says a model
    generated the text. A manifest missing it declares nothing about machine origin
    while looking otherwise valid.""",
    StatusCode.ASSERTION_CBOR_INVALID: """An assertion's CBOR is not well-formed (15.10.3.1).

    Well-formed is RFC 8949 Appendix C, and this package also refuses encodings 4.2.1
    forbids -- indefinite lengths, non-shortest integers or floats, unordered map keys
    -- because no conforming producer emits them.""",
    StatusCode.ASSERTION_JSON_INVALID: """A ``.metadata`` assertion's JSON-LD box is not a well-formed JSON object.

    15.10.3.1 names a code per serialization; 18.17.2 makes ``c2pa.metadata`` JSON-LD.""",
    StatusCode.ASSERTION_MISSING: """
    The claim links an assertion the store does not contain, or a required one is absent.

    Required in ``created_assertions``: the hard binding, the AI disclosure, and an
    actions assertion (either ``c2pa.actions.v2`` or v1 ``c2pa.actions``). 18.15.2 and
    the 2.4 change log require these in created rather than gathered.""",
    StatusCode.ASSERTION_UNDECLARED: """The store holds an assertion the claim never linked.

    Unlinked bytes are unauthenticated: nothing in the signature covers them, so a
    reader who trusts them is trusting whoever last touched the file.""",
    StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS: """More than one hard binding to content (15.10.1.2).

    With two, there is no defined answer to which one binds the text, so the manifest
    is rejected before either is evaluated rather than after picking one.""",
    StatusCode.ASSERTION_OUTSIDE_MANIFEST: """A claim link points outside this manifest (8.4.2.1).

    Either a URI naming a different manifest, or one that is not a resolvable
    ``self#jumbf`` reference at all. A claim may only vouch for its own assertions.""",
    StatusCode.GENERAL_ERROR: """The AI disclosure discloses nothing: no ``modelType``, on some ``__N`` instance.

    THIS IS THE ARTICLE 50(2) CODE. The disclosure assertion is the reason this package
    exists, and one carrying no model type satisfies the structure while stating none of
    the fact it was added to state. 18.28 defines the assertion; the specification names
    no more specific code, so the general one is used.

    ACT: the producer's configuration is wrong. The mark is not usable as a disclosure.""",
    StatusCode.CLAIM_SIGNATURE_VALIDATED: """
    SUCCESS. The COSE_Sign1 signature over the claim verifies against the leaf's key.

    NOT a statement about the text: it says the claim was signed by that key and has not
    changed. Whether the claim still describes THIS text is the hard binding's answer,
    so this code appears on tampered documents too.""",
    StatusCode.CLAIM_SIGNATURE_MISMATCH: """The claim signature does not verify (15.7).

    The claim was altered after signing, or was signed by a different key than the
    certificate in ``x5chain`` carries.""",
    StatusCode.CLAIM_SIGNATURE_MISSING: """The manifest carries no ``c2pa.signature`` box (15.7).

    Structurally intact and unsigned, which is not something a conforming producer
    emits.""",
    StatusCode.CLAIM_SIGNATURE_INSIDE_VALIDITY: """
    SUCCESS. Every certificate in the chain is inside its validity window AT VALIDATION.

    15.8: "the C2PA Manifest is valid if the current time at validation is within the
    validity period of the signer's certificate". NOT the signing time. A reader
    who believes otherwise expects marks to survive their credential's expiry. They do
    not: a certificate live when it signed and expired now lands on
    ``outsideValidity``.

    Checked across the WHOLE chain, not just the leaf: an intermediate that has
    expired makes the path invalid however good the leaf looks.""",
    StatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY: """
    A certificate is outside its validity window at the time of validation (15.8).

    Judged against ``VerifyContext.now`` if supplied, else the current time -- so an old
    mark from an expired certificate lands here even though nothing was tampered with.

    ACT: this is expiry, not forgery. Say the credential is no longer acceptable, not
    that the text was altered. Supply ``VerifyContext(now=...)`` to judge it as of the
    signing time instead.""",
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
    The signing certificate is unusable (14.5.1.1), or uses an algorithm we refuse.

    The profile: the EKU extension must be present and non-empty, ``cA`` and
    ``keyCertSign`` must not be asserted, and ``digitalSignature`` must be. 14.5.1.1
    names no required EKU OID, so ``c2pa-kp-claimSigning`` is not demanded.

    ALSO OUR OWN NARROWING: this package accepts Ed25519 alone where 13.2.1's list is
    wider, so a conforming ES256 mark is refused under this same code. That is deviation
    11, not the clause speaking.""",
    StatusCode.CLAIM_CBOR_INVALID: """The claim's bytes are not well-formed CBOR (15.6.2).

    Distinct from ``claim.malformed``: this is a decoding failure, that one is a claim
    that decoded and is the wrong shape.""",
    StatusCode.CLAIM_MALFORMED: """The claim decoded but is not a valid claim (15.6.2).

    Not a CBOR map, or missing a field 15.6.2 requires. The CBOR is impeccable; the
    structure inside it is not a claim.""",
    StatusCode.CLAIM_MISSING: """The manifest carries no claim box, or its claim box carries no CBOR (15.6).

    Without a claim there is nothing to validate against.""",
    StatusCode.HASHED_URI_MISSING: """
    A reference inside a structure names a destination that cannot be located (15.10.3.3).

    A generator or action icon whose ``url`` is absent, unresolvable, or names an
    assertion the store does not hold. A reference we deliberately decline to follow --
    an external URI, or one into a data box -- is passed over instead; see deviation 26.""",
    StatusCode.HASHED_URI_MISMATCH: """A reference's destination does not hash to the recorded value (15.10.3.3).

    Also reported when the ``hash`` field is absent or is not a byte string, since the
    clause names no separate code and no computed digest can equal a non-digest.""",
    StatusCode.CLAIM_MULTIPLE: """One label appears on two boxes (15.6.1).

    A manifest may hold one claim box. Applied to duplicated ASSERTION labels too: two
    boxes under one label is ambiguous whichever layer it happens at, and a reader
    taking the first where we take the last would authenticate different content from
    identical bytes.""",
    StatusCode.CLAIM_HARD_BINDINGS_MISSING: """The claim links no hard binding to content (15.10.1.2).

    Without one, nothing ties the manifest to any particular text, and the mark could be
    lifted onto any document.""",
    StatusCode.ALGORITHM_UNSUPPORTED: """A named hash algorithm is not one 13.1 permits, and none was inherited.

    13.1 permits sha256, sha384 and sha512 and says implementations "shall not support
    additional algorithms on an optional basis". An ABSENT ``alg`` inherits from the
    claim (15.4.1); a PRESENT but unsupported one does not fall back, because falling
    back would let a producer ask for a weak hash and silently get a strong one.""",
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
    StatusCode.TEXT_CORRUPTED_WRAPPER: StatusKind.FAILURE,
    StatusCode.TEXT_MULTIPLE_WRAPPERS: StatusKind.FAILURE,
    StatusCode.DATA_HASH_MISMATCH: StatusKind.FAILURE,
    StatusCode.DATA_HASH_MALFORMED: StatusKind.FAILURE,
    StatusCode.ASSERTION_HASHED_URI_MISMATCH: StatusKind.FAILURE,
    StatusCode.ASSERTION_ACTION_MALFORMED: StatusKind.FAILURE,
    StatusCode.ASSERTION_CBOR_INVALID: StatusKind.FAILURE,
    StatusCode.ASSERTION_JSON_INVALID: StatusKind.FAILURE,
    StatusCode.ASSERTION_MISSING: StatusKind.FAILURE,
    StatusCode.ASSERTION_UNDECLARED: StatusKind.FAILURE,
    StatusCode.ASSERTION_MULTIPLE_HARD_BINDINGS: StatusKind.FAILURE,
    StatusCode.ASSERTION_OUTSIDE_MANIFEST: StatusKind.FAILURE,
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
    StatusCode.ALGORITHM_UNSUPPORTED: StatusKind.FAILURE,
}

#: Codes that C2PA defines but which are ABSENT from the normative ``$status-code``
#: CDDL enumeration in 15.2.1, even though all five ``manifest.structuredText.*``
#: codes are present. They validate only via the catch-all custom-code regex
#: ``([\da-zA-Z_-]+\.)+[\da-zA-Z_-]+``. We emit them exactly as Table 4 spells them
#: and expect strict third-party validators to classify them as custom rather than
#: standard. Filed upstream; see the deviations document.
UNREGISTERED_IN_CDDL = frozenset(
    {
        StatusCode.TEXT_CORRUPTED_WRAPPER,
        StatusCode.TEXT_MULTIPLE_WRAPPERS,
    }
)


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
