"""
Trust evaluation: the certificate profile, and the seam for chain building.

WHY CHAIN VALIDATION IS NOT IN THE DEFAULT INSTALL
--------------------------------------------------
``cryptography``'s ``x509.verification`` cannot validate an Ed25519 chain at all.
Its permitted-algorithm lists are compile-time constants in
``cryptography-x509-verification/src/policy/mod.rs`` covering RSA, P-256/384/521 and
ML-DSA; there is no ``ed25519`` entry and no Python override. Tracked as
pyca/cryptography#13391, open since 2025-09-03 with no PR landed. Two further gaps
compound it: there is no generic or code-signing verifier -- only ``server`` and
``client``, which demand ``serverAuth``/``clientAuth`` EKUs and a SAN that C2PA
claim-signing certificates do not carry -- and there is no revocation support.

The API is stable as of 50.0.0. Stable and unusable-for-Ed25519 are independent facts.

So the default install validates everything it can and stops honestly at
``signingCredential.untrusted``: C2PA state **Valid**, but never **Trusted**. Reaching
Trusted needs a :class:`TrustEvaluator`, which the optional ``[trust]`` extra can
back with ``pyhanko-certvalidator`` (RFC 5280 6 path validation, Ed25519 and Ed448,
offline by default). Hand-rolling RFC 5280 6 is roughly 1,200 lines of name
constraints, policy mapping and path-length arithmetic that we would get subtly
wrong, so we do not.

WE BUNDLE NO TRUST ANCHORS
--------------------------
Not the Duale root -- it does not exist yet; Terraform owns it and it is out of scope
here -- and not the official C2PA trust list. This matches ``c2pa-rs``, which sets
``trust_anchors: None`` and includes anchors only under ``#[cfg(test)]``. Anchors
arrive only through the caller. There is no ambient discovery and no implicit file
read, and nothing here ever touches the network: a verifier whose answer depends on
network conditions, or on whoever controls an endpoint, is not the offline verifier
this package claims to be.
"""

from __future__ import annotations

import dataclasses
from typing import Protocol, runtime_checkable

from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    ExtendedKeyUsage,
    ExtensionNotFound,
    KeyUsage,
    Version,
    load_pem_x509_certificates,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier, SignatureAlgorithmOID

from c2patxt.exceptions import C2paTextError

__all__ = [
    "PERMITTED_SIGNATURE_ALGORITHMS",
    "NoTrustEvaluator",
    "ProfileError",
    "TrustEvaluator",
    "check_claim_signing_profile",
    "load_anchors",
]

#: id-kp-anyExtendedKeyUsage. C2PA 14.5.1.1: "shall not be present".
_ANY_EXTENDED_KEY_USAGE = ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE

#: The two purposes 14.5.1.1 makes mutually exclusive with everything else. A
#: certificate valid for either "shall be valid for exactly one of those two purposes,
#: and not valid for any other purpose" -- so a CLAIM-signing certificate may carry
#: neither, and 14.5.1.2 restates it as a validator obligation: "no more than one of
#: the three purposes listed in this section: C2PA signing, time-stamp signing, or
#: OCSP response signing."
_EXCLUSIVE_PURPOSES = {
    ExtendedKeyUsageOID.TIME_STAMPING: "id-kp-timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "id-kp-OCSPSigning",
}

#: The eight values 14.5.1.1 permits in "the algorithm field of the signatureAlgorithm
#: field", verbatim from the clause's table.
#:
#: THIS IS THE ISSUER'S SIGNATURE, NOT THE CLAIM'S. This package restricts the key we verify
#: a claim with to Ed25519; this restricts the algorithm the certificate itself was
#: signed with. An ALLOWLIST rather than a weak-algorithm blocklist, which is what
#: keeps Ed448 -- stronger than Ed25519 and still absent from the profile -- out.
PERMITTED_SIGNATURE_ALGORITHMS: frozenset[ObjectIdentifier] = frozenset(
    {
        SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        SignatureAlgorithmOID.ECDSA_WITH_SHA384,
        SignatureAlgorithmOID.ECDSA_WITH_SHA512,
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA384,
        SignatureAlgorithmOID.RSA_WITH_SHA512,
        SignatureAlgorithmOID.RSASSA_PSS,
        SignatureAlgorithmOID.ED25519,
    }
)

#: Context tags [1] and [2] of TBSCertificate: issuerUniqueID and subjectUniqueID,
#: IMPLICIT BIT STRING and therefore PRIMITIVE, so the constructed bit (0x20) is clear.
_UNIQUE_ID_TAGS = frozenset({0x81, 0x82})

#: DER length octet: the high bit distinguishes the long form from the short.
_DER_LONG_FORM = 0x80


def _tbs_carries_unique_ids(tbs: bytes) -> bool:
    """True if the TBSCertificate carries issuerUniqueID or subjectUniqueID.

    C2PA 14.5.1.1: "The issuerUniqueID and subjectUniqueID optional fields of the
    TBSCertificate sequence shall not be present, as per RFC 5280, section 4.1.2.8."

    ``cryptography`` exposes no accessor for either -- they are v2 legacy syntax it
    declines to surface -- so this is the ONE profile rule that requires reading the
    DER ourselves.

    THE WALK NEVER DESCENDS. It steps across the top-level members of the
    TBSCertificate SEQUENCE and looks at their tags, so a ``0x81`` occurring as a
    length byte or as some tagged field inside issuer, validity or the SPKI cannot be
    mistaken for a unique identifier. That single-level restriction is what makes 30
    lines of hand-rolled DER acceptable where a general parser would not be.

    Raises:
        ProfileError: the encoding does not walk. ``cryptography``'s DER-strict parser
            has already accepted this certificate, so a walk failure means OUR reading
            is wrong -- and the safe direction for a check whose job is to reject is to
            reject rather than to wave the certificate through.
    """
    try:
        offset, end = _der_contents(tbs, 0)
        while offset < end:
            tag = tbs[offset]
            if tag in _UNIQUE_ID_TAGS:
                return True
            _, offset = _der_contents(tbs, offset)
    except (IndexError, ValueError) as exc:
        msg = "the TBSCertificate encoding could not be walked to check for unique identifiers (14.5.1.1)"
        raise ProfileError(msg) from exc
    return False


def _der_contents(encoded: bytes, offset: int) -> tuple[int, int]:
    """Return ``(contents_start, element_end)`` for the DER element at ``offset``.

    Only the low-tag-number form is handled, which is all RFC 5280 uses at this level.

    Raises:
        ValueError: the length is indefinite, which DER forbids, or runs past the end.
        IndexError: the buffer ends inside the length field. Not converted, because the
            only caller catches both together and translating it would cost a branch
            that no input reaches -- but a reader REUSING this helper needs to know, and
            an undocumented IndexError from a parser is the kind that escapes.
    """
    length_offset = offset + 2
    first = encoded[offset + 1]
    if first == _DER_LONG_FORM:
        msg = "indefinite length is not valid DER"
        raise ValueError(msg)
    # `<` versus `<=` on the next line is PROVABLY EQUIVALENT, and a mutation audit
    # filed it as a survivor. The check above means control reaches here only when
    # first != 0x80, so both comparisons agree for all 256 byte values. This helper has
    # exactly two callers, both downstream of that guard. No test can distinguish them;
    # do not write one, and do not "tighten" the comparison expecting a behaviour change.
    if first < _DER_LONG_FORM:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(encoded[length_offset : length_offset + count], "big")
        length_offset += count
    end = length_offset + length
    if end > len(encoded):
        msg = "declared length runs past the end of the encoding"
        raise ValueError(msg)
    return length_offset, end


class ProfileError(C2paTextError, ValueError):
    """A certificate does not satisfy the C2PA claim-signing profile (14.5.1.1).

    Catchable as ``C2paTextError`` and as ``ValueError``. The ``ValueError`` base is kept
    because callers catch it; the ``C2paTextError`` base was added on 2026-08-05, because
    this is what ``Signer()`` raises for the default ``openssl req -x509``
    misconfiguration and a caller following the package's own "catch ``C2paTextError``"
    instruction did not catch it.

    Distinct from "not trusted". A profile violation yields
    ``signingCredential.invalid`` -- a hard reject where the manifest is not even
    Valid -- whereas an unreachable trust anchor yields
    ``signingCredential.untrusted`` and leaves the manifest Valid.
    """


@runtime_checkable
class TrustEvaluator(Protocol):
    """Decides whether a certificate chain reaches a trusted anchor.

    A PROTOCOL RATHER THAN A CONCRETE CLASS, and the bar for that is a real
    implementation this package cannot provide: the real
    implementation is a dependency that genuinely cannot run in the default install,
    because ``cryptography`` refuses Ed25519 chains outright. Integrators plug in the
    ``[trust]`` extra, a corporate PKI, or the C2PA Trust List.
    """

    def is_trusted(self, chain: list[Certificate], anchors: list[Certificate]) -> bool:
        """True if ``chain`` (leaf first) validates to one of ``anchors``.

        RETURN ``False`` FOR AN UNREACHABLE ANCHOR; do not raise. That is not a
        formality: the ``[trust]`` extra ships ``pyhanko-certvalidator``, whose path
        validation signals exactly that case with ``PathBuildingError`` /
        ``PathValidationError``, so the obvious implementation of this Protocol raises
        on its most common outcome.

        An exception is caught and mapped to ``signingCredential.untrusted`` with the
        type and message carried into the verdict's explanation -- ``verify()`` is
        documented never to raise for absent, corrupt or invalid marks, and that promise
        is kept whatever an evaluator does. It is still worth returning ``False``
        yourself: "no path found" and "your evaluator crashed" are different facts, and
        only you can tell them apart.
        """
        ...


@dataclasses.dataclass(frozen=True, slots=True)
class NoTrustEvaluator:
    """The default: nothing is ever trusted, and that is reported honestly.

    Not a stub standing in for missing work. With no anchors bundled there is
    genuinely nothing to chain to, so ``signingCredential.untrusted`` is the correct
    and expected answer for a self-signed credential -- C2PA state Valid, not Trusted.
    """

    def is_trusted(self, chain: list[Certificate], anchors: list[Certificate]) -> bool:
        del chain, anchors  # signature is the Protocol's; the answer never depends on them
        return False


def _check_x509_structure(certificate: Certificate) -> None:
    """Apply 14.5.1.1's four structural requirements, which precede any C2PA role.

    Most govern "all certificates except those in the private credential store"; the
    signatureAlgorithm allowlist is from the earlier group, "All certificates shall
    fulfill the following requirements", with no such exemption. Both are about the
    certificate as an X.509 object -- how it was signed, which
    syntax version it uses, whether it carries legacy v2 fields, and whether it names
    the key that issued it -- rather than about claim signing specifically. Separated
    from the role checks so each function reads as one clause rather than two.

    Raises:
        ProfileError: mapping to ``signingCredential.invalid``.
    """
    if certificate.signature_algorithm_oid not in PERMITTED_SIGNATURE_ALGORITHMS:
        msg = (
            f"the certificate's signatureAlgorithm is {certificate.signature_algorithm_oid.dotted_string}, "
            "which 14.5.1.1 does not list"
        )
        raise ProfileError(msg)

    if certificate.version is not Version.v3:
        msg = f"the certificate is {certificate.version.name}; 14.5.1.1 requires v3"
        raise ProfileError(msg)

    if _tbs_carries_unique_ids(certificate.tbs_certificate_bytes):
        msg = "issuerUniqueID and subjectUniqueID shall not be present in the TBSCertificate (14.5.1.1)"
        raise ProfileError(msg)

    # "shall be present in any certificate that is not self-signed". Self-signed is
    # decided by issuer == subject, which is self-ISSUED strictly speaking; a leaf
    # self-issued but signed by another key is pathological and would fail chain
    # building regardless. Checking it this way keeps the package's own self-signed
    # test credential -- and every self-signed credential C2PA expects to land on
    # signingCredential.untrusted rather than .invalid -- out of a hard reject.
    if certificate.issuer != certificate.subject:
        try:
            certificate.extensions.get_extension_for_class(AuthorityKeyIdentifier)
        except ExtensionNotFound as exc:
            msg = (
                "the Authority Key Identifier extension shall be present in a certificate "
                "that is not self-signed (14.5.1.1)"
            )
            raise ProfileError(msg) from exc


def check_claim_signing_profile(certificate: Certificate) -> None:
    """Apply the C2PA 14.5.1.1 profile checks that govern claim-signing certificates.

    Scoped deliberately to claim signing, which is narrower than 14.5.1.1 as a whole
    but not narrower than it is for the certificate in our hands. We do not validate
    time-stamping or OCSP-signing certificates -- time-stamping needs network access
    and is out of scope, and OCSP arrives stapled in the ``rVals`` unprotected header,
    which we do not parse -- but the clause's mutual-exclusivity rule constrains the
    CLAIM-SIGNING certificate, so it is checked here. The rules look like they govern certificate roles we never
    validate. They do not: a credential able both to sign claims and to mint the
    time-stamps attesting to when they were signed is the separation-of-duties failure
    the clause exists to prevent.

    Two rules from the clause are deliberately NOT implemented, because they cannot
    apply. The named-curve and 2048-bit-modulus requirements govern ``id-ecPublicKey``
    and RSA subject keys, and THIS PACKAGE restricts the key we verify a claim with to
    Ed25519, so a certificate that would reach either rule has already been rejected.
    The Subject Key Identifier requirement is a SHOULD for end-entity certificates,
    and a SHOULD is not a rejection condition.

    Raises:
        ProfileError: mapping to ``signingCredential.invalid``.

    Note what this catches in practice. A default ``openssl req -x509`` certificate
    asserts ``cA`` and carries no EKU, so it fails here -- yielding a hard reject
    rather than the ``signingCredential.untrusted`` a self-signed credential is meant
    to produce. That is the misconfiguration the Terraform-generated credential is at
    risk of.
    """
    # A MALFORMED EXTENSION POISONS THE WHOLE SET, not just its own field. rust-asn1
    # parses extensions lazily, so an empty ExtKeyUsageSyntax -- legal to build, illegal
    # to read -- makes the FIRST get_extension_for_class raise ValueError, whichever
    # extension it asks for. That certificate arrives in the COSE x5chain, from the wire,
    # so without this the exception escapes _accept_credential and escapes verify(),
    # which is documented never to raise for absent, corrupt or invalid marks.
    #
    # BOTH halves are inside the try.
    # _check_x509_structure reads AuthorityKeyIdentifier for any certificate whose issuer
    # differs from its subject -- catching ExtensionNotFound alone -- so a wire
    # certificate that was not self-issued still escaped.
    #
    # signingCredential.invalid is the honest answer: a credential we cannot parse is one
    # we cannot accept, and 14.5.1.1's profile is exactly what it fails.
    try:
        _check_x509_structure(certificate)
        _check_extensions(certificate)
    except ProfileError:
        # RE-RAISED UNCHANGED, and this clause is load-bearing rather than tidy.
        # ProfileError subclasses ValueError, so without it the handler below catches
        # every genuine profile violation and re-labels it a parse failure -- which is
        # what happened for two hours after this wrapper was added. Every rule in
        # _check_extensions reported as "the certificate's extensions could not be
        # parsed", and the tests missed it because they match on the inner text, which
        # the wrapper preserved.
        raise
    except CERTIFICATE_PARSE_ERRORS as exc:
        msg = f"the certificate's extensions could not be parsed: {exc}"
        raise ProfileError(msg) from exc


#: Raised by ``cryptography`` when a DER structure inside a certificate will not parse.
#: A ValueError from the Rust layer, not a Python-level type error.
CERTIFICATE_PARSE_ERRORS = (ValueError,)


def _check_extensions(certificate: Certificate) -> None:
    """The extension half of 14.5.1.1, split out so one ``try`` covers every access.

    Raises:
        ProfileError: an extension is present and violates the profile.
        ValueError: an extension will not parse. Translated by the caller.
    """
    try:
        constraints = certificate.extensions.get_extension_for_class(BasicConstraints).value
        is_ca = constraints.ca
    except ExtensionNotFound:
        is_ca = False

    if is_ca:
        msg = "a claim-signing certificate must not assert cA in BasicConstraints (14.5.1.1)"
        raise ProfileError(msg)

    # "the Key Usage extension shall be present and should be marked as critical."
    # PRESENCE IS REQUIRED IN ITS OWN RIGHT. Tolerating an absent
    # extension -- correctly reasoning that a certificate with no KeyUsage cannot
    # assert keyCertSign, and wrongly concluding there was nothing to check.
    try:
        usage = certificate.extensions.get_extension_for_class(KeyUsage).value
    except ExtensionNotFound as exc:
        msg = "the Key Usage extension shall be present (14.5.1.1)"
        raise ProfileError(msg) from exc

    if usage.key_cert_sign:
        msg = "a claim-signing certificate must not assert keyCertSign (14.5.1.1)"
        raise ProfileError(msg)
    # "Certificates used to sign C2PA manifests shall assert the digitalSignature bit."
    if not usage.digital_signature:
        msg = "a claim-signing certificate shall assert the digitalSignature bit in Key Usage (14.5.1.1)"
        raise ProfileError(msg)

    # "The EKU extension shall be present and non-empty in any certificate where the
    # Basic Constraints extension is absent or the cA boolean is not asserted."
    try:
        ekus = certificate.extensions.get_extension_for_class(ExtendedKeyUsage).value
    except ExtensionNotFound as exc:
        msg = "a claim-signing certificate must carry a non-empty EKU extension (14.5.1.1)"
        raise ProfileError(msg) from exc

    # "shall be present and non-empty". Only presence is checked: RFC 5280 declares
    # ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId, so an empty EKU is
    # not a certificate we could reject -- it is one that cannot be encoded, and
    # cryptography's parser refuses it with InvalidSize before we are reached. A branch
    # for it would be permanently unexecuted code standing in for a guarantee ASN.1
    # already makes.
    oids = list(ekus)
    if _ANY_EXTENDED_KEY_USAGE in oids:
        msg = "anyExtendedKeyUsage (2.5.29.37.0) shall not be present (14.5.1.1)"
        raise ProfileError(msg)
    for oid, name in _EXCLUSIVE_PURPOSES.items():
        if oid in oids:
            msg = (
                f"a certificate valid for {name} shall be valid for exactly one of id-kp-timeStamping and "
                "id-kp-OCSPSigning and no other purpose, so it may not also sign C2PA claims (14.5.1.1)"
            )
            raise ProfileError(msg)

    # NO REQUIRED OID, and demanding c2pa-kp-claimSigning here on 14.4.1's authority is
    # wrong twice over.
    #
    # 14.5.1.1's EKU rules are exhaustively: present and non-empty on a non-CA
    # certificate, no anyExtendedKeyUsage, the timeStamping/OCSPSigning exclusivity
    # rule, and "the presence of any EKUs not mentioned in this profile ... shall not
    # cause the certificate to be rejected". It names no OID at all.
    #
    # 14.4.1 is addressed to VALIDATORS, about their own configuration -- "For each
    # accepted EKU value, a list of trust anchor configurations" -- and it explicitly
    # anticipates other EKUs: a validator "should allow a user to configure additional
    # trust anchor configurations for that EKU and/or for other EKUs (e.g.,
    # id-kp-emailProtection ... or id-kp-documentSigning)". It warns in the same
    # paragraph that "Previous versions of this specification required the presence of
    # id-kp-emailProtection or id-kp-documentSigning EKUs", and the change log records
    # claimSigning as new at 2.2 -- so the whole pre-2.2 installed base carries the older
    # pair alone, and we were giving every one of them signingCredential.INVALID, a hard
    # reject where the manifest is not even Valid.
    #
    # The decisive argument is our own configuration. Under 14.5.1.2 a claim-signing
    # certificate "shall have at least one of the EKUs FOR WHICH THE VALIDATOR HAS AN
    # ASSOCIATED LIST OF TRUST ANCHORS" -- and we ship none, so our accepted-EKU list is
    # empty and the EKU question decides nothing about validity. It is a TRUST question,
    # and the answer for a credential we cannot anchor is signingCredential.untrusted,
    # which leaves the manifest Valid. Which EKUs a deployment will accept belongs to the
    # TrustEvaluator seam, where anchor-to-EKU association lives.

    # Unknown EKUs shall NOT cause rejection (14.5.1.1). Deliberately not checked --
    # over-strictness here is as much a conformance bug as under-strictness.


def load_anchors(pem: bytes | None = None) -> list[Certificate]:
    """Load trust anchors from the supplied PEM bundle, or return an empty list.

    THE ``pem`` ARGUMENT IS THE ONLY CHANNEL. There is no environment variable, no
    bundled store, no directory scan and no network request. That is the package's
    stated contract in three places -- the package docstring, ``VerifyContext`` and
    ``SECURITY.md`` all promise no ambient configuration -- and an environment
    variable would falsify all three.

    There is deliberately no ``C2PATXT_TRUST_ANCHORS`` fallback, though there is one in
    ``c2patool``. Three things go wrong when one exists, all measured: a missing path
    raises ``FileNotFoundError`` and a malformed one raises ``ValueError`` straight out
    of ``verify()``, which promises never to raise; the read happens only on the
    signature-valid path, so unmarked and invalid text verifies fine while VALID text
    crashes -- a bomb that fires only on the happy path; and the file is re-read on
    every call. A trust decision that depends on a
    process environment variable is also neither reproducible nor auditable, which is
    the wrong property for the thing deciding whether a document is TRUSTED.

    An empty result is the normal, shipped default. Verification still reaches C2PA
    state Valid; it simply never reaches Trusted.
    """
    if pem is None:
        return []
    # An empty bundle is a legitimate way to say "no anchors". Raising
    # MalformedFraming at a caller who explicitly asked for nothing would be
    # unhelpful and would make the override impossible to disable.
    return load_pem_x509_certificates(pem) if pem.strip() else []
