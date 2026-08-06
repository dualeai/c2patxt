"""
``COSE_Sign1`` signing and verification, as narrowed by C2PA 2.4 clause 13.2.

C2PA pins this structure completely, so this module is small and rigid rather than a
general COSE implementation:

* ``Sig_structure = ["Signature1", body_protected, external_aad, payload]``
* ``external_aad`` **shall be a zero-length bstr**; external authenticated data
  shall not be used (13.2.3).
* the payload is **detached**, encoded as ``nil`` (``0xf6``), never as a zero-length
  byte string -- 13.2.2 warns about that explicitly (10.3.2.4).
* ``alg`` is integer label **1** in the PROTECTED bucket; the string ``"alg"`` is
  never used.
* ``x5chain`` is integer label **33**, leaf first, intermediates included, root
  excluded, and it lives in the PROTECTED bucket only (14.5, RFC 9360).
* exactly ONE identity credential across protected and unprotected (14.2); zero or
  two is a reject.

The ``ToBeSign_hex`` field of the cose-wg example corpus is precisely this
``Sig_structure``, which is what lets tests/test_external_vectors.py verify our
reading of it against an independently produced encoding.
"""

from __future__ import annotations

import dataclasses

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from c2patxt import _cbor
from c2patxt.signing import COSE_ALG_EDDSA, Signer

__all__ = [
    "COSE_HEADER_ALG",
    "COSE_HEADER_X5CHAIN",
    "CoseError",
    "CoseSign1",
    "sign_claim",
    "verify_claim",
]

COSE_HEADER_ALG = 1
"""Protected-header label for the algorithm (RFC 9052)."""

COSE_HEADER_X5CHAIN = 33
"""RFC 9360's integer label for the certificate chain. Wins when both labels appear."""

X5CHAIN_STRING_LABEL = "x5chain"
"""The deprecated STRING label for the certificate chain.

C2PA 14.5 requires validators to accept it alongside the integer, so
:meth:`CoseSign1.x5chain` reads both. We EMIT the integer only.

An orphaned string literal sat here saying "Integer 33, not the deprecated string
'x5chain'" -- a no-op expression, attached to nothing, reading as documentation of the
constant it contradicts. It described the integer constant above and had drifted down
to sit under this one.

Integer 33, not the deprecated string ``"x5chain"``. C2PA 14.5: "Claim generators
should use only the integer 33 as the label"; validators accept either, and the
integer wins when both appear.
"""

_SIGNATURE_CONTEXT = "Signature1"
_SIGNATURE_SIZE = 64
_COSE_SIGN1_ELEMENTS = 4  # protected, unprotected, payload, signature


class CoseError(ValueError):
    """A ``COSE_Sign1`` structure is malformed or violates the C2PA profile."""


@dataclasses.dataclass(frozen=True, slots=True)
class CoseSign1:
    """A parsed ``COSE_Sign1`` with a detached payload."""

    protected: bytes
    """The serialized protected header map, signed as-is."""

    unprotected: dict[int | str | bytes, _cbor.CborValue]
    signature: bytes

    def header(self) -> dict[int | str | bytes, _cbor.CborValue]:
        """Decode the protected bucket."""
        decoded = _cbor.loads(self.protected) if self.protected else {}
        if not isinstance(decoded, dict):
            msg = "the protected header is not a CBOR map"
            raise CoseError(msg)
        return decoded

    def x5chain(self) -> list[bytes]:
        """Certificates from the protected bucket, leaf first.

        RFC 9360 allows a bare ``bstr`` for a single certificate and an array
        otherwise; both are accepted here.

        BOTH LABELS ARE ACCEPTED. C2PA 14.5: "Validators shall accept either the
        string `x5chain` or the integer 33 as the label for this header. If both
        labels are present, validators shall use the header with the integer label 33
        and ignore the header with the string x5chain." We read only the integer, so a
        producer using the deprecated-but-legal string label read as carrying no
        credential at all -- while ``_check_single_credential`` already recognised the
        string form in the unprotected bucket, which is what marked this an oversight
        rather than a decision.
        """
        header = self.header()
        raw = header.get(COSE_HEADER_X5CHAIN, header.get(X5CHAIN_STRING_LABEL))
        if isinstance(raw, bytes):
            return [raw]
        if isinstance(raw, list):
            certificates = [item for item in raw if isinstance(item, bytes)]
            if len(certificates) != len(raw):
                msg = "x5chain must contain only byte strings"
                raise CoseError(msg)
            return certificates
        msg = "x5chain is absent from the protected header"
        raise CoseError(msg)


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


def sign_claim(signer: Signer, claim_bytes: bytes) -> bytes:
    """Sign the claim and return the serialized, tagged ``COSE_Sign1``.

    The payload is DETACHED: the message carries ``nil`` in the payload slot, and the
    claim bytes live in the claim box rather than being duplicated here.
    """
    protected = _protected_header(signer)
    signature = signer.sign(sig_structure(protected, claim_bytes))
    message = _cbor.Tagged(_cbor.TAG_COSE_SIGN1, [protected, {}, None, signature])
    return _cbor.dumps(message)


def parse(message: bytes) -> CoseSign1:
    """Parse a tagged ``COSE_Sign1``.

    Raises:
        CoseError: if the structure is not a tag-18 four-element array, if the
            payload is not ``nil``, or if the C2PA profile is violated.
    """
    try:
        decoded = _cbor.loads(message)
    except _cbor.CborDecodeError as exc:
        raise CoseError(f"claim signature is not valid CBOR: {exc}") from exc

    if not isinstance(decoded, _cbor.Tagged) or decoded.tag != _cbor.TAG_COSE_SIGN1:
        msg = "claim signature is not a tagged COSE_Sign1 (tag 18)"
        raise CoseError(msg)

    body = decoded.value
    if not isinstance(body, list) or len(body) != _COSE_SIGN1_ELEMENTS:
        msg = "COSE_Sign1 must be a four-element array"
        raise CoseError(msg)

    protected, unprotected, payload, signature = body

    if not isinstance(protected, bytes):
        msg = "the protected header must be a byte string"
        raise CoseError(msg)
    if not isinstance(unprotected, dict):
        msg = "the unprotected header must be a map"
        raise CoseError(msg)
    if payload is not None:
        # 13.2.2 is explicit that a zero-length bstr does NOT mean detached content.
        msg = "the payload must be detached, encoded as nil"
        raise CoseError(msg)
    if not isinstance(signature, bytes) or len(signature) != _SIGNATURE_SIZE:
        msg = f"an Ed25519 signature is {_SIGNATURE_SIZE} bytes"
        raise CoseError(msg)

    parsed = CoseSign1(protected=protected, unprotected=unprotected, signature=signature)
    _check_single_credential(parsed)
    return parsed


def _check_single_credential(message: CoseSign1) -> None:
    """C2PA 14.2: exactly one identity credential across BOTH buckets.

    "COSE_Sign1_Tagged structures with no credentials, or two or more credentials,
    shall be rejected." Duplicating the same certificate in both buckets counts as
    two, so this checks presence rather than equality.
    """
    header = message.header()
    in_protected = COSE_HEADER_X5CHAIN in header or X5CHAIN_STRING_LABEL in header
    in_unprotected = COSE_HEADER_X5CHAIN in message.unprotected or X5CHAIN_STRING_LABEL in message.unprotected

    if in_protected and in_unprotected:
        msg = "x5chain appears in both header buckets: multiple credentials (14.2)"
        raise CoseError(msg)
    if not in_protected:
        # A DELIBERATE DEVIATION FROM A `shall`, recorded in docs/deviations.md. 14.5
        # says "Validators shall accept the header from either the protected or
        # unprotected bucket, to maintain compatibility with previous versions". We do
        # not: an unprotected header is outside the signature, so a chain taken from
        # there is one an attacker can swap -- and the chain's whole job is to say
        # which key signed the claim.
        msg = "x5chain must be present in the protected header (14.5)"
        raise CoseError(msg)


def verify_claim(message: bytes, claim_bytes: bytes, public_key: Ed25519PublicKey) -> CoseSign1:
    """Verify a detached-payload ``COSE_Sign1`` over ``claim_bytes``.

    Raises:
        CoseError: if the structure is malformed, the profile is violated, the
            algorithm is not EdDSA, or the signature does not verify.
    """
    parsed = parse(message)

    algorithm = parsed.header().get(COSE_HEADER_ALG)
    if algorithm != COSE_ALG_EDDSA:
        # THIS PACKAGE accepts EdDSA only. 13.2.1's allowed list is wider -- ES256/384/512,
        # PS256/384/512 and EdDSA -- so the message says whose restriction this is; telling
        # an ES256 producer that the specification forbids their algorithm would be false
        # and would send them to the wrong document. Ed448 shares this identifier, so the
        # KEY type is what actually distinguishes them, checked when the certificate loads.
        msg = (
            f"unsupported COSE algorithm {algorithm!r}: this package accepts EdDSA "
            f"({COSE_ALG_EDDSA}) only, which is narrower than C2PA 13.2.1's allowed list"
        )
        raise CoseError(msg)

    try:
        public_key.verify(parsed.signature, sig_structure(parsed.protected, claim_bytes))
    except InvalidSignature as exc:
        raise CoseError("claim signature does not verify") from exc

    return parsed
