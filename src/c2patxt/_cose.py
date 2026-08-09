"""
``COSE_Sign1`` signing and verification, as narrowed by C2PA 2.4 clause 13.2.

C2PA fixes the required detached structure and headers implemented here, so this
module remains narrower than a general COSE implementation:

* ``Sig_structure = ["Signature1", body_protected, external_aad, payload]``
* ``external_aad`` **shall be a zero-length bstr**; external authenticated data
  shall not be used (13.2.3).
* the payload is **detached**, encoded as ``nil`` (``0xf6``), never as a zero-length
  byte string -- 13.2.2 warns about that explicitly (10.3.2.4).
* ``alg`` is integer label **1** in the PROTECTED bucket; the string ``"alg"`` is
  never used.
* generators put ``x5chain`` at integer label **33** in the protected bucket;
  validators accept integer or string labels from either bucket (14.5, RFC 9360).
* exactly ONE identity credential across protected and unprotected (14.2); zero or
  two is a reject.

The ``Sig_structure`` byte layout follows RFC 9052 section 4.4 under the C2PA
restrictions above.
"""

from __future__ import annotations

import dataclasses

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from c2patxt import _cbor
from c2patxt.signing import COSE_ALG_EDDSA, Signer

COSE_HEADER_ALG = 1
"""Protected-header label for the algorithm (RFC 9052)."""

COSE_HEADER_CRIT = 2
"""Protected-header label for parameters a recipient must understand."""

COSE_HEADER_X5CHAIN = 33
"""RFC 9360's integer label for the certificate chain. Wins when both labels appear."""

X5CHAIN_STRING_LABEL = "x5chain"
"""The deprecated STRING label for the certificate chain.

C2PA 14.5 requires validators to accept it alongside the integer, so
:meth:`CoseSign1.x5chain` reads both. We EMIT the integer only.
"""

_PADDING_LABEL = "pad"

_COSE_ALG_ES256 = -7
_COSE_ALG_ES384 = -35
_COSE_ALG_ES512 = -36
_COSE_ALG_PS256 = -37
_COSE_ALG_PS384 = -38
_COSE_ALG_PS512 = -39

_ECDSA_HASHES: dict[int, hashes.HashAlgorithm] = {
    _COSE_ALG_ES256: hashes.SHA256(),
    _COSE_ALG_ES384: hashes.SHA384(),
    _COSE_ALG_ES512: hashes.SHA512(),
}
_PSS_HASHES: dict[int, hashes.HashAlgorithm] = {
    _COSE_ALG_PS256: hashes.SHA256(),
    _COSE_ALG_PS384: hashes.SHA384(),
    _COSE_ALG_PS512: hashes.SHA512(),
}
_ALGORITHM_NAMES = {
    _COSE_ALG_ES256: "ES256",
    _COSE_ALG_ES384: "ES384",
    _COSE_ALG_ES512: "ES512",
    _COSE_ALG_PS256: "PS256",
    _COSE_ALG_PS384: "PS384",
    _COSE_ALG_PS512: "PS512",
    COSE_ALG_EDDSA: "EdDSA",
}

_SIGNATURE_CONTEXT = "Signature1"
_SIGNATURE_SIZE = 64
_MIN_X5CHAIN_ARRAY = 2
_COSE_SIGN1_ELEMENTS = 4  # protected, unprotected, payload, signature


class CoseError(ValueError):
    """A ``COSE_Sign1`` structure is malformed or violates the C2PA profile."""


class CoseStructureError(CoseError):
    """The present claim-signature box is not a well-formed C2PA COSE structure."""


class CoseCredentialError(CoseError):
    """The COSE structure carries no acceptable single signing credential."""


class CoseAlgorithmError(CoseError):
    """The COSE protected header names no algorithm C2PA 2.4 permits."""


class CoseSignatureError(CoseError):
    """The cryptographic signature does not verify over the detached claim."""


def _header_map(
    value: dict[int | str | bytes, _cbor.CborValue] | dict[_cbor.CborKey, _cbor.CborValue],
    bucket: str,
) -> dict[int | str | bytes, _cbor.CborValue]:
    """Narrow a generic CBOR map to RFC 9052's integer-or-text labels."""
    out: dict[int | str | bytes, _cbor.CborValue] = {}
    for label, item in value.items():
        if isinstance(label, (bytes, _cbor.MapKey)):
            msg = f"the {bucket} header contains a label that is not an integer or text string"
            raise CoseStructureError(msg)
        out[label] = item
    return out


@dataclasses.dataclass(frozen=True, slots=True)
class _SignedClaim:
    """The protected bytes and signature fixed before unprotected padding changes."""

    protected: bytes
    signature: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class CoseSign1:
    """A parsed ``COSE_Sign1`` with a detached payload."""

    protected: bytes
    """The serialized protected header map, signed as-is."""

    unprotected: dict[int | str | bytes, _cbor.CborValue]
    signature: bytes
    decoded_protected: dict[int | str | bytes, _cbor.CborValue] = dataclasses.field(
        init=False,
        repr=False,
        compare=False,
    )
    _certificates: tuple[bytes, ...] | None = dataclasses.field(
        init=False,
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        try:
            # RFC 9052 section 3 protects these exact bytes so recipients need not
            # agree on a canonical re-encoding. Its section 9 deterministic rules
            # govern Sig_structure, not this transported map.
            decoded = _cbor.loads(self.protected, deterministic=False) if self.protected else {}
        except _cbor.CborDecodeError as exc:
            raise CoseStructureError(f"the protected header is not valid CBOR: {exc}") from exc
        if not isinstance(decoded, dict):
            msg = "the protected header is not a CBOR map"
            raise CoseStructureError(msg)
        object.__setattr__(self, "decoded_protected", _header_map(decoded, "protected"))

    def x5chain(self) -> tuple[bytes, ...]:
        """Certificates from either header bucket, leaf first.

        RFC 9360 allows a bare ``bstr`` for a single certificate and an array
        otherwise; both are accepted here.

        BOTH LABELS ARE ACCEPTED. C2PA 14.5: "Validators shall accept either the
        string `x5chain` or the integer 33 as the label for this header. If both
        labels are present, validators shall use the header with the integer label 33
        and ignore the header with the string x5chain." That precedence spans both
        buckets. Only the same label repeated across buckets is a second credential.
        """
        if self._certificates is not None:
            return self._certificates

        raw = _credential_value(self)
        if isinstance(raw, bytes):
            return (raw,)
        if isinstance(raw, list):
            if len(raw) < _MIN_X5CHAIN_ARRAY:
                msg = "an x5chain array must contain at least two certificates; use a byte string for one"
                raise CoseCredentialError(msg)
            certificates: list[bytes] = []
            for item in raw:
                if not isinstance(item, bytes):
                    msg = "x5chain must contain only byte strings"
                    raise CoseCredentialError(msg)
                certificates.append(item)
            return tuple(certificates)
        msg = "x5chain must be a byte string or an array of byte strings"
        raise CoseCredentialError(msg)


def _credential_value(message: CoseSign1) -> _cbor.CborValue:
    """Select one x5chain using C2PA 14.5's global integer precedence."""
    for label in (COSE_HEADER_X5CHAIN, X5CHAIN_STRING_LABEL):
        in_protected = label in message.decoded_protected
        in_unprotected = label in message.unprotected
        if in_protected and in_unprotected:
            msg = f"x5chain label {label!r} appears in both header buckets: multiple credentials (14.2)"
            raise CoseCredentialError(msg)
        if in_protected:
            return message.decoded_protected[label]
        if in_unprotected:
            return message.unprotected[label]
    msg = "x5chain is absent from both header buckets"
    raise CoseCredentialError(msg)


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """Build the ``Sig_structure`` that is actually signed (13.2.3).

    ``external_aad`` is a zero-length byte string, unconditionally: C2PA states that
    external authenticated data shall not be used.
    """
    return _cbor.dumps([_SIGNATURE_CONTEXT, protected, b"", payload])


def _protected_header(signer: Signer) -> bytes:
    """Serialize the protected bucket: ``alg`` and ``x5chain``, both required here.

    Both live in the protected bucket, so both are covered by the signature. C2PA
    14.5 requires claim generators to always place ``x5chain`` there.
    """
    chain = signer.x5chain()
    # RFC 9360: a single certificate may be a bare bstr; an array otherwise.
    value: _cbor.CborValue = chain[0] if len(chain) == 1 else list(chain)
    return _cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA, COSE_HEADER_X5CHAIN: value})


def _prepare_signed_claim(  # pyright: ignore[reportUnusedFunction] -- imported by _embed
    signer: Signer, claim_bytes: bytes
) -> _SignedClaim:
    """Sign once; later serialization changes only the unprotected COSE map."""
    protected = _protected_header(signer)
    return _SignedClaim(
        protected=protected,
        signature=signer.sign(sig_structure(protected, claim_bytes)),
    )


def _serialize_signed_claim(  # pyright: ignore[reportUnusedFunction] -- imported by _embed
    signed: _SignedClaim,
    *,
    pad: int = 0,
) -> bytes:
    """Serialize a signed claim with zero-filled unprotected COSE padding.

    C2PA 10.4.2 names the string ``pad`` header. RFC 9052 excludes the unprotected
    bucket from ``Sig_structure``, so changing this field does not alter the signature.
    """
    if pad < 0:
        msg = "COSE padding lengths must be non-negative"
        raise ValueError(msg)
    unprotected: dict[int | str | bytes, _cbor.CborValue] = {_PADDING_LABEL: bytes(pad)}
    message = _cbor.Tagged(
        _cbor.TAG_COSE_SIGN1,
        [signed.protected, unprotected, None, signed.signature],
    )
    return _cbor.dumps(message)


def parse(message: bytes) -> CoseSign1:
    """Parse a tagged ``COSE_Sign1``.

    Raises:
        CoseError: if the structure is not a tag-18 four-element array, if the
            payload is not ``nil``, or if the C2PA profile is violated.
    """
    try:
        # COSE does not require deterministic encoding for the transported message.
        # Duplicate map keys remain forbidden in the relaxed decoder mode.
        decoded = _cbor.loads(message, deterministic=False)
    except _cbor.CborDecodeError as exc:
        raise CoseStructureError(f"claim signature is not valid CBOR: {exc}") from exc

    if not isinstance(decoded, _cbor.Tagged) or decoded.tag != _cbor.TAG_COSE_SIGN1:
        msg = "claim signature is not a tagged COSE_Sign1 (tag 18)"
        raise CoseStructureError(msg)

    body = decoded.value
    if not isinstance(body, list) or len(body) != _COSE_SIGN1_ELEMENTS:
        msg = "COSE_Sign1 must be a four-element array"
        raise CoseStructureError(msg)

    protected, unprotected, payload, signature = body

    if not isinstance(protected, bytes):
        msg = "the protected header must be a byte string"
        raise CoseStructureError(msg)
    if not isinstance(unprotected, dict):
        msg = "the unprotected header must be a map"
        raise CoseStructureError(msg)
    if payload is not None:
        # 13.2.2 is explicit that a zero-length bstr does NOT mean detached content.
        msg = "the payload must be detached, encoded as nil"
        raise CoseStructureError(msg)
    if not isinstance(signature, bytes):
        msg = "the signature must be a byte string"
        raise CoseStructureError(msg)

    parsed = CoseSign1(
        protected=protected,
        unprotected=_header_map(unprotected, "unprotected"),
        signature=signature,
    )
    _check_critical_headers(parsed)
    _check_single_credential(parsed)
    return parsed


def _check_critical_headers(message: CoseSign1) -> None:
    """Reject a critical header this implementation cannot process."""
    if COSE_HEADER_CRIT in message.unprotected:
        msg = "the crit header parameter must be protected (RFC 9052 section 3.1)"
        raise CoseStructureError(msg)

    if COSE_HEADER_CRIT not in message.decoded_protected:
        return
    critical = message.decoded_protected[COSE_HEADER_CRIT]
    if not isinstance(critical, list) or not critical:
        msg = "the protected crit header must be a non-empty array"
        raise CoseStructureError(msg)

    understood = frozenset({COSE_HEADER_ALG, COSE_HEADER_CRIT, COSE_HEADER_X5CHAIN, X5CHAIN_STRING_LABEL})
    for label in critical:
        if isinstance(label, bool) or not isinstance(label, (int, str)):
            msg = "each crit entry must be an integer or text-string header label"
            raise CoseStructureError(msg)
        if label not in message.decoded_protected:
            msg = f"critical header {label!r} is absent from the protected bucket"
            raise CoseStructureError(msg)
        if label not in understood:
            msg = f"critical header {label!r} is not understood by this implementation"
            raise CoseStructureError(msg)


def _check_single_credential(message: CoseSign1) -> None:
    """C2PA 14.2: exactly one identity credential across BOTH buckets.

    "COSE_Sign1_Tagged structures with no credentials, or two or more credentials,
    shall be rejected." C2PA 14.5 narrows the cross-bucket case: only the same label
    in both buckets is duplicated; integer 33 globally supersedes the string label.
    """
    # Parse the RFC 9360 value shape while locating it, before a caller can use the
    # cached credential tuple for signature or profile validation.
    object.__setattr__(message, "_certificates", message.x5chain())


def _check_algorithm(  # pyright: ignore[reportUnusedFunction] -- imported by _verify
    message: CoseSign1,
) -> int:
    """Return a C2PA 2.4 allowed COSE signature algorithm."""
    algorithm = message.decoded_protected.get(COSE_HEADER_ALG)
    # bool and float compare equal to integers in Python. COSE alg is an int/tstr,
    # and this profile requires the integer registry value, so compare type as well.
    if type(algorithm) is not int or algorithm not in _ALGORITHM_NAMES:
        msg = f"unsupported COSE algorithm {algorithm!r}; C2PA 2.4 section 13.2.1 permits {sorted(_ALGORITHM_NAMES)}"
        raise CoseAlgorithmError(msg)
    return algorithm


def _verify_signature(  # pyright: ignore[reportUnusedFunction] -- imported by _verify
    message: CoseSign1,
    claim_bytes: bytes,
    public_key: CertificatePublicKeyTypes,
    algorithm: int,
) -> None:
    """Verify every signature algorithm C2PA 2.4 requires consumers to support."""
    to_be_signed = sig_structure(message.protected, claim_bytes)

    try:
        if algorithm == COSE_ALG_EDDSA:
            if not isinstance(public_key, Ed25519PublicKey):
                msg = f"EdDSA requires an Ed25519 key, not {type(public_key).__name__}"
                raise CoseSignatureError(msg)
            if len(message.signature) != _SIGNATURE_SIZE:
                msg = f"an Ed25519 signature is {_SIGNATURE_SIZE} bytes"
                raise CoseSignatureError(msg)
            public_key.verify(message.signature, to_be_signed)
            return

        if algorithm in _ECDSA_HASHES:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                msg = f"{_ALGORITHM_NAMES[algorithm]} requires an EC key, not {type(public_key).__name__}"
                raise CoseSignatureError(msg)
            component_size = (public_key.curve.key_size + 7) // 8
            expected_size = component_size * 2
            if len(message.signature) != expected_size:
                msg = (
                    f"a COSE ECDSA signature with {public_key.curve.name} is "
                    f"{expected_size} bytes, not {len(message.signature)}"
                )
                raise CoseSignatureError(msg)
            r = int.from_bytes(message.signature[:component_size], "big")
            s = int.from_bytes(message.signature[component_size:], "big")
            public_key.verify(
                encode_dss_signature(r, s),
                to_be_signed,
                ec.ECDSA(_ECDSA_HASHES[algorithm]),
            )
            return

        if not isinstance(public_key, rsa.RSAPublicKey):
            msg = f"{_ALGORITHM_NAMES[algorithm]} requires an RSA key, not {type(public_key).__name__}"
            raise CoseSignatureError(msg)
        hash_algorithm = _PSS_HASHES[algorithm]
        public_key.verify(
            message.signature,
            to_be_signed,
            padding.PSS(
                mgf=padding.MGF1(hash_algorithm),
                salt_length=hash_algorithm.digest_size,
            ),
            hash_algorithm,
        )
    except InvalidSignature as exc:
        raise CoseSignatureError("claim signature does not verify") from exc
