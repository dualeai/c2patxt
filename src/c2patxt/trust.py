"""C2PA certificate-profile checks and the caller-owned trust seam.

The base implementation checks the carried certificate profile, claim signature, and
carried-certificate validity. It does not provide an RFC 5280 path-building backend,
trust anchors, revocation processing, or remote fetching. With the default
:class:`NoTrustEvaluator`, an intact mark can therefore be ``VALID`` with
``signingCredential.untrusted`` but cannot become ``TRUSTED``.

Callers supply anchors and a :class:`TrustEvaluator` when they need trust evaluation.
The evaluator is invoked synchronously and owns its path policy, external state, and
I/O. Package-owned code performs no ambient trust-store discovery or network access.
The optional ``[trust]`` extra is retained for install-contract compatibility; this
package does not import or adapt its backend.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    DuplicateExtension,
    ExtendedKeyUsage,
    ExtensionNotFound,
    InvalidVersion,
    KeyUsage,
    SubjectKeyIdentifier,
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
    "check_certificate_chain_profile",
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
#: THIS IS THE ISSUER'S SIGNATURE, NOT THE CLAIM'S. Claim-signature algorithms are
#: checked separately in ``_cose``; this allowlist constrains the algorithm the
#: certificate itself was signed with.
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

#: Minimum RSA subject-key size in C2PA 14.5.1.1.
_MIN_RSA_MODULUS_BITS = 2048

# DER tags used by the one nested structure cryptography does not expose fully:
# RSASSA-PSS-params. These remain local rather than growing into an ASN.1 layer.
_DER_SEQUENCE = 0x30
_DER_OBJECT_IDENTIFIER = 0x06
_PSS_HASH_ALGORITHM = 0xA0
_PSS_MASK_GEN_ALGORITHM = 0xA1
_PSS_PARAMETER_TAGS = frozenset({_PSS_HASH_ALGORITHM, _PSS_MASK_GEN_ALGORITHM, 0xA2, 0xA3})

# OBJECT IDENTIFIER contents, without the DER tag and length.
_RSASSA_PSS_OID = bytes.fromhex("2a864886f70d01010a")
_MGF1_OID = bytes.fromhex("2a864886f70d010108")
_PSS_HASH_OIDS = {
    bytes.fromhex("608648016503040201"): "id-sha256",
    bytes.fromhex("608648016503040202"): "id-sha384",
    bytes.fromhex("608648016503040203"): "id-sha512",
}


def _tbs_carries_unique_ids(tbs: bytes) -> bool:
    """True if the TBSCertificate carries issuerUniqueID or subjectUniqueID.

    C2PA 14.5.1.1: "The issuerUniqueID and subjectUniqueID optional fields of the
    TBSCertificate sequence shall not be present, as per RFC 5280, section 4.1.2.8."

    ``cryptography`` exposes no accessor for either -- they are v2 legacy syntax it
    declines to surface -- so this is one of two narrow profile checks that read DER
    directly. The other checks explicit RSASSA-PSS parameters below.

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
        IndexError: the buffer ends inside the length field. Every production entry
            path translates it together with ``ValueError`` at its profile boundary.
    """
    length_offset = offset + 2
    first = encoded[offset + 1]
    if first == _DER_LONG_FORM:
        msg = "indefinite length is not valid DER"
        raise ValueError(msg)
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


def _algorithm_identifier(encoded: bytes, offset: int) -> tuple[bytes, int, int]:
    """Return ``(OID contents, parameters offset, sequence end)`` for one DER AlgorithmIdentifier."""
    if encoded[offset] != _DER_SEQUENCE:
        msg = "AlgorithmIdentifier is not a DER SEQUENCE"
        raise ValueError(msg)
    contents, end = _der_contents(encoded, offset)
    if contents >= end or encoded[contents] != _DER_OBJECT_IDENTIFIER:
        msg = "AlgorithmIdentifier does not begin with an OBJECT IDENTIFIER"
        raise ValueError(msg)
    oid_contents, oid_end = _der_contents(encoded, contents)
    if oid_end > end:
        msg = "AlgorithmIdentifier OID runs past its SEQUENCE"
        raise ValueError(msg)
    if oid_end < end:
        _, parameters_end = _der_contents(encoded, oid_end)
        if parameters_end != end:
            msg = "AlgorithmIdentifier has more than one parameters value"
            raise ValueError(msg)
    return encoded[oid_contents:oid_end], oid_end, end


def _pss_parameter_fields(certificate: Certificate) -> tuple[bytes, dict[int, tuple[int, int]]]:
    """Return the explicit fields from the certificate's outer RSASSA-PSS-params."""
    encoded = certificate.public_bytes(Encoding.DER)
    if encoded[0] != _DER_SEQUENCE:
        msg = "Certificate is not a DER SEQUENCE"
        raise ValueError(msg)
    certificate_contents, certificate_end = _der_contents(encoded, 0)
    if certificate_end != len(encoded):
        msg = "Certificate has bytes after its outer SEQUENCE"
        raise ValueError(msg)

    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    _, tbs_end = _der_contents(encoded, certificate_contents)
    pss_oid, parameters_offset, signature_algorithm_end = _algorithm_identifier(encoded, tbs_end)
    if pss_oid != _RSASSA_PSS_OID:
        msg = "certificate reports id-RSASSA-PSS but its outer AlgorithmIdentifier does not"
        raise ValueError(msg)
    if parameters_offset >= signature_algorithm_end or encoded[parameters_offset] != _DER_SEQUENCE:
        msg = "id-RSASSA-PSS parameters are absent or are not a SEQUENCE"
        raise ValueError(msg)
    parameters_contents, parameters_end = _der_contents(encoded, parameters_offset)
    if parameters_end != signature_algorithm_end:
        msg = "id-RSASSA-PSS parameters do not fill the AlgorithmIdentifier"
        raise ValueError(msg)

    fields: dict[int, tuple[int, int]] = {}
    offset = parameters_contents
    while offset < parameters_end:
        tag = encoded[offset]
        if tag not in _PSS_PARAMETER_TAGS or tag in fields:
            msg = "id-RSASSA-PSS parameters contain an unknown or duplicate field"
            raise ValueError(msg)
        field_contents, field_end = _der_contents(encoded, offset)
        if field_end > parameters_end:
            msg = "id-RSASSA-PSS parameter runs past its SEQUENCE"
            raise ValueError(msg)
        fields[tag] = (field_contents, field_end)
        offset = field_end
    return encoded, fields


def _pss_hash(encoded: bytes, field: tuple[int, int]) -> tuple[bytes, str]:
    """Read and validate the explicit PSS hashAlgorithm field."""
    oid, _, end = _algorithm_identifier(encoded, field[0])
    if end != field[1]:
        msg = "id-RSASSA-PSS hashAlgorithm has trailing data"
        raise ValueError(msg)
    name = _PSS_HASH_OIDS.get(oid)
    if name is None:
        msg = "id-RSASSA-PSS hashAlgorithm must be id-sha256, id-sha384, or id-sha512 (C2PA 14.5.1.1)"
        raise ProfileError(msg)
    return oid, name


def _pss_mask_hash(encoded: bytes, field: tuple[int, int]) -> bytes:
    """Read the hash OID inside the explicit PSS maskGenAlgorithm field."""
    oid, parameters_offset, end = _algorithm_identifier(encoded, field[0])
    if end != field[1] or oid != _MGF1_OID or parameters_offset >= end:
        msg = "id-RSASSA-PSS maskGenAlgorithm must be MGF1 with hash parameters (RFC 8017 A.2.3)"
        raise ProfileError(msg)
    hash_oid, _, hash_end = _algorithm_identifier(encoded, parameters_offset)
    if hash_end != end:
        msg = "id-RSASSA-PSS MGF1 hash parameters have trailing data"
        raise ValueError(msg)
    return hash_oid


def _check_pss_parameters(certificate: Certificate) -> None:
    """Enforce C2PA 14.5.1.1's explicit SHA-2 and MGF1 requirements."""
    try:
        encoded, fields = _pss_parameter_fields(certificate)
        hash_field = fields.get(_PSS_HASH_ALGORITHM)
        if hash_field is None:
            msg = "id-RSASSA-PSS hashAlgorithm shall be present (C2PA 14.5.1.1)"
            raise ProfileError(msg)
        hash_oid, hash_name = _pss_hash(encoded, hash_field)

        mask_field = fields.get(_PSS_MASK_GEN_ALGORITHM)
        if mask_field is None:
            msg = "id-RSASSA-PSS maskGenAlgorithm shall be present (C2PA 14.5.1.1)"
            raise ProfileError(msg)
        mask_hash_oid = _pss_mask_hash(encoded, mask_field)
        if mask_hash_oid != hash_oid:
            mask_name = _PSS_HASH_OIDS.get(mask_hash_oid, "an unsupported hash")
            msg = f"id-RSASSA-PSS MGF1 uses {mask_name}, not hashAlgorithm {hash_name} (C2PA 14.5.1.1)"
            raise ProfileError(msg)
    except ProfileError:
        raise
    except (IndexError, ValueError) as exc:
        msg = f"the certificate's id-RSASSA-PSS parameters could not be parsed: {exc}"
        raise ProfileError(msg) from exc


class ProfileError(C2paTextError, ValueError):
    """A certificate does not satisfy the C2PA claim-signing profile (14.5.1.1).

    It inherits from both ``C2paTextError`` and ``ValueError``, so callers may catch
    package errors together or handle invalid caller-supplied certificate material as a
    value error.

    Distinct from "not trusted". A profile violation yields
    ``signingCredential.invalid`` -- a hard reject where the manifest is not even
    Valid -- whereas an unreachable trust anchor yields
    ``signingCredential.untrusted`` and leaves the manifest Valid.
    """


@runtime_checkable
class TrustEvaluator(Protocol):
    """Decides whether a certificate chain reaches a trusted anchor.

    A protocol keeps corporate PKI policy replaceable. The optional ``[trust]`` extra
    is retained for install compatibility only; it supplies no evaluator, and this
    package endorses no backend while pyHanko#809 remains open. Evaluators used through
    this synchronous protocol must not fetch; remote validation needs a future async
    interface.
    """

    def is_trusted(self, chain: list[Certificate], anchors: list[Certificate]) -> bool:
        """True if ``chain`` (leaf first) validates to one of ``anchors``.

        Return ``False`` when no path reaches an anchor; do not raise for that normal
        result. An adapter must translate its backend's documented no-path result to
        ``False`` without swallowing unrelated faults.

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

    With no anchors bundled there is nothing to chain to, so a self-signed credential
    yields ``signingCredential.untrusted`` and may still be C2PA Valid.
    """

    def is_trusted(self, chain: list[Certificate], anchors: list[Certificate]) -> bool:
        del chain, anchors  # signature is the Protocol's; the answer never depends on them
        return False


def _is_self_signed(certificate: Certificate) -> bool:
    """Whether the certificate names itself and verifies under its own subject key."""
    if certificate.issuer != certificate.subject:
        return False
    try:
        certificate.verify_directly_issued_by(certificate)
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
        return False
    return True


def _check_x509_structure(certificate: Certificate) -> None:
    """Apply 14.5.1.1 requirements shared by leaf and CA certificates.

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
    if certificate.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
        _check_pss_parameters(certificate)

    public_key = certificate.public_key()
    if isinstance(public_key, ec.EllipticCurvePublicKey) and not isinstance(
        public_key.curve,
        (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1),
    ):
        msg = (
            f"the certificate's subjectPublicKeyInfo uses {public_key.curve.name}; "
            "14.5.1.1 permits only prime256v1, secp384r1, and secp521r1"
        )
        raise ProfileError(msg)
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < _MIN_RSA_MODULUS_BITS:
        msg = (
            f"the certificate's subjectPublicKeyInfo carries a {public_key.key_size}-bit RSA modulus; "
            "14.5.1.1 requires at least 2048 bits"
        )
        raise ProfileError(msg)

    if certificate.version is not Version.v3:
        msg = f"the certificate is {certificate.version.name}; 14.5.1.1 requires v3"
        raise ProfileError(msg)

    if _tbs_carries_unique_ids(certificate.tbs_certificate_bytes):
        msg = "issuerUniqueID and subjectUniqueID shall not be present in the TBSCertificate (14.5.1.1)"
        raise ProfileError(msg)

    # AKI may be absent only on a verifiably self-signed certificate. Read it first so
    # ordinary issued certificates do not pay for a needless self-signature check.
    try:
        authority_key_identifier = certificate.extensions.get_extension_for_class(AuthorityKeyIdentifier)
    except ExtensionNotFound as exc:
        if not _is_self_signed(certificate):
            msg = (
                "the Authority Key Identifier extension shall be present in a certificate "
                "that is not self-signed (14.5.1.1)"
            )
            raise ProfileError(msg) from exc
    else:
        if authority_key_identifier.critical:
            msg = "the Authority Key Identifier extension must be non-critical (RFC 5280 4.2.1.1; C2PA 14.5.1.1)"
            raise ProfileError(msg)
        if authority_key_identifier.value.key_identifier is None:
            msg = "the Authority Key Identifier extension must include keyIdentifier (RFC 5280 4.2.1.1; C2PA 14.5.1.1)"
            raise ProfileError(msg)


def check_claim_signing_profile(certificate: Certificate) -> None:
    """Apply the C2PA 14.5.1.1 profile checks that govern claim-signing certificates.

    This function applies the claim-signing role of the profile, including its
    purpose-separation rules. It does not parse or validate ``sigTst``, ``sigTst2``, or
    ``rVals``.

    The Subject Key Identifier requirement is a SHOULD for end-entity certificates,
    and a SHOULD is not a rejection condition. Subject-key restrictions still run in
    the shared check; claim-algorithm/key compatibility is checked later in ``_cose``.

    Raises:
        ProfileError: mapping to ``signingCredential.invalid``.

    A profile failure maps to ``signingCredential.invalid``. Trust-anchor reachability
    is a separate decision and maps to trusted or untrusted.
    """
    # ``cryptography`` parses extensions lazily. Translate its documented and observed
    # parse failures at this exported profile boundary, while preserving ProfileError
    # raised by the profile checks themselves.
    try:
        _check_x509_structure(certificate)
        _check_leaf_extensions(certificate)
    except ProfileError:
        # ProfileError subclasses ValueError, so it must remain distinct from parse
        # failures caught below.
        raise
    except CERTIFICATE_PARSE_ERRORS as exc:
        msg = f"the certificate could not be parsed: {exc}"
        raise ProfileError(msg) from exc


#: Observed lazy parse failures from ``cryptography`` certificate field access.
#: Keep this finite: a broad catch here would hide programming errors in these
#: exported helpers. ``verify`` has its own broad hostile-DER boundary before this.
CERTIFICATE_PARSE_ERRORS = (
    DuplicateExtension,
    InvalidVersion,
    KeyError,
    TypeError,
    UnsupportedAlgorithm,
    ValueError,
)


def _check_leaf_extensions(certificate: Certificate) -> None:
    """Apply the extension requirements for a claim-signing leaf.

    Raises:
        ProfileError: an extension is present and violates the profile.
        ValueError: an extension will not parse. Translated by the caller.
    """
    try:
        subject_key_identifier = certificate.extensions.get_extension_for_class(SubjectKeyIdentifier)
    except ExtensionNotFound:
        pass  # C2PA says a leaf SHOULD carry SKI; absence is not a rejection.
    else:
        if subject_key_identifier.critical:
            msg = "a claim-signing certificate must mark Subject Key Identifier non-critical (RFC 5280 4.2.1.2)"
            raise ProfileError(msg)

    try:
        constraints = certificate.extensions.get_extension_for_class(BasicConstraints).value
        is_ca = constraints.ca
    except ExtensionNotFound:
        is_ca = False

    if is_ca:
        msg = "a claim-signing certificate must not assert cA in BasicConstraints (14.5.1.1)"
        raise ProfileError(msg)

    # 14.5.1.1 requires the Key Usage extension itself, not merely the absence of a
    # forbidden keyCertSign bit.
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

    # RFC 5280 declares ExtKeyUsageSyntax as a non-empty sequence. cryptography may
    # defer rejecting an encoded empty sequence until this access; the public profile
    # boundary translates that lazy parse failure to ProfileError.
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

    # 14.5.1.1's EKU rules are: present and non-empty on a non-CA
    # certificate, no anyExtendedKeyUsage, the timeStamping/OCSPSigning exclusivity
    # rule, and "the presence of any EKUs not mentioned in this profile ... shall not
    # cause the certificate to be rejected". It names no OID at all.
    #
    # 14.4.1 and 14.5.1.2 associate accepted EKUs with trust-anchor configuration.
    # That deployment policy belongs to the TrustEvaluator seam, not this profile
    # rejection check.

    # Unknown EKUs shall NOT cause rejection (14.5.1.1). Deliberately not checked --
    # over-strictness here is as much a conformance bug as under-strictness.


def _check_ca_extensions(certificate: Certificate) -> None:
    """Apply the extension requirements for a carried CA certificate."""
    try:
        constraints_extension = certificate.extensions.get_extension_for_class(BasicConstraints)
    except ExtensionNotFound as exc:
        msg = "a carried CA must carry Basic Constraints with cA asserted (14.5.1.1)"
        raise ProfileError(msg) from exc
    constraints = constraints_extension.value
    if not constraints.ca:
        msg = "a carried CA must assert cA in Basic Constraints (14.5.1.1)"
        raise ProfileError(msg)
    if not constraints_extension.critical:
        msg = "a carried CA must mark Basic Constraints critical (RFC 5280 4.2.1.9; C2PA 14.5.1.1)"
        raise ProfileError(msg)

    try:
        subject_key_identifier = certificate.extensions.get_extension_for_class(SubjectKeyIdentifier)
    except ExtensionNotFound as exc:
        msg = "a carried CA must carry a Subject Key Identifier extension (14.5.1.1)"
        raise ProfileError(msg) from exc
    if subject_key_identifier.critical:
        msg = "a carried CA must mark Subject Key Identifier non-critical (RFC 5280 4.2.1.2; C2PA 14.5.1.1)"
        raise ProfileError(msg)

    try:
        usage = certificate.extensions.get_extension_for_class(KeyUsage).value
    except ExtensionNotFound as exc:
        msg = "a carried CA must carry a Key Usage extension (14.5.1.1)"
        raise ProfileError(msg) from exc
    if not usage.key_cert_sign:
        msg = "a carried CA must assert keyCertSign in Key Usage (RFC 5280 4.2.1.3; C2PA 14.5.1.1)"
        raise ProfileError(msg)

    # 14.5.1.1 makes EKU mandatory only where Basic Constraints is absent or cA is
    # false. If a CA carries EKU anyway, its values do not affect profile acceptance.


def _check_carried_ca_profile(certificate: Certificate, index: int) -> None:
    """Check one carried CA and add its x5chain index to any failure."""
    try:
        _check_x509_structure(certificate)
        _check_ca_extensions(certificate)
    except ProfileError as exc:
        msg = f"x5chain[{index}] carried CA: {exc}"
        raise ProfileError(msg) from exc
    except CERTIFICATE_PARSE_ERRORS as exc:
        msg = f"x5chain[{index}] carried CA could not be parsed: {exc}"
        raise ProfileError(msg) from exc


def check_certificate_chain_profile(certificates: Sequence[Certificate]) -> None:
    """Check the C2PA profile of a carried x5chain, leaf first.

    This checks each certificate's own profile. It does not build or validate a path,
    choose a trust anchor, or apply revocation policy; those remain the caller's
    :class:`TrustEvaluator` work under 14.5.1.2.

    Raises:
        ProfileError: the leaf or a carried intermediate violates 14.5.1.1.
    """
    if not certificates:
        msg = "the carried x5chain has no leaf certificate"
        raise ProfileError(msg)

    try:
        check_claim_signing_profile(certificates[0])
    except ProfileError as exc:
        msg = f"x5chain[0] leaf: {exc}"
        raise ProfileError(msg) from exc

    for index, certificate in enumerate(certificates[1:], start=1):
        _check_carried_ca_profile(certificate, index)


def load_anchors(pem: bytes | None = None) -> list[Certificate]:
    """Load trust anchors from the supplied PEM bundle, or return an empty list.

    ``pem`` is the sole input. The function reads no environment variable, bundled
    store, directory or network resource. ``None`` and an empty bundle both mean no
    anchors; a valid self-signed mark can therefore remain C2PA Valid without becoming
    Trusted.
    """
    if pem is None:
        return []
    # An empty bundle is a legitimate way to say "no anchors". Raising
    # MalformedFraming at a caller who explicitly asked for nothing would be
    # unhelpful and would make the override impossible to disable.
    return load_pem_x509_certificates(pem) if pem.strip() else []
