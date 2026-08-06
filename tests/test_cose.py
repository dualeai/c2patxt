# pyright: reportPrivateUsage=false
# Drives _check_single_credential directly: it is the unit that decides which
# bucket a credential may come from, and 14.2/14.5 give the two buckets different
# rules that a round trip through verify() cannot tell apart.
"""COSE_Sign1 as C2PA 13.2 narrows it: detached payload, zero-length aad, x5chain."""

from __future__ import annotations

import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from c2patxt import EmbedContext, _cbor, _cose, embed, extract
from c2patxt._cose import (
    COSE_HEADER_ALG,
    COSE_HEADER_X5CHAIN,
    CoseError,
    parse,
    sig_structure,
    sign_claim,
    verify_claim,
)
from c2patxt.signing import COSE_ALG_EDDSA, Signer
from tests._json import load_object, str_field, str_fields
from tests.conftest import DISCLOSURE, WHEN, build_certificate
from tests.test_external_vectors import COSE as COSE_VECTORS

_PINNED = EmbedContext(manifest_uuid=uuid.UUID(int=13), instance_id="xmp:iid:cose", when=WHEN)

CLAIM = b"\xa1\x63abc\x01"  # any deterministically-encoded CBOR stands in for a claim


@pytest.fixture
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


def test_sig_structure_shape() -> None:
    """13.2.3: ["Signature1", protected, external_aad, payload]."""
    decoded = _cbor.loads(sig_structure(b"\xa1\x01\x27", CLAIM))
    assert decoded == ["Signature1", b"\xa1\x01\x27", b"", CLAIM]


def test_external_aad_is_always_zero_length() -> None:
    """13.2.3: "external authenticated data shall not be used"."""
    decoded = _cbor.loads(sig_structure(b"", CLAIM))
    assert isinstance(decoded, list)
    assert decoded[2] == b""


def test_signed_message_round_trips(signer: Signer) -> None:
    message = sign_claim(signer, CLAIM)
    parsed = verify_claim(message, CLAIM, signer.private_key.public_key())
    assert len(parsed.signature) == 64
    assert parsed.header()[COSE_HEADER_ALG] == COSE_ALG_EDDSA


def test_the_payload_is_detached_as_nil_not_an_empty_bstr(signer: Signer) -> None:
    """13.2.2 warns explicitly that a zero-length bstr does NOT mean detached."""
    decoded = _cbor.loads(sign_claim(signer, CLAIM))
    assert isinstance(decoded, _cbor.Tagged)
    assert decoded.tag == 18
    body = decoded.value
    assert isinstance(body, list)
    assert body[2] is None, "payload slot must hold nil (0xf6)"

    forged = _cbor.dumps(_cbor.Tagged(18, [body[0], {}, b"", body[3]]))
    with pytest.raises(CoseError, match="detached"):
        parse(forged)


def test_x5chain_lives_in_the_protected_bucket(signer: Signer) -> None:
    """14.5: generators shall always place x5chain in the PROTECTED bucket.

    Accepting it from the unprotected bucket would mean trusting an unsigned
    certificate chain to tell us which key signed the claim.
    """
    parsed = parse(sign_claim(signer, CLAIM))
    assert COSE_HEADER_X5CHAIN in parsed.header()
    assert parsed.unprotected == {}
    assert parsed.x5chain() == signer.x5chain()


def test_x5chain_uses_integer_label_33_not_the_string(signer: Signer) -> None:
    """RFC 9360. C2PA: "use only the integer 33 as the label"."""
    header = parse(sign_claim(signer, CLAIM)).header()
    assert COSE_HEADER_X5CHAIN == 33
    assert "x5chain" not in header


def test_a_credential_in_both_buckets_is_rejected(signer: Signer) -> None:
    """14.2: zero or two-or-more credentials shall be rejected.

    The same certificate duplicated across buckets counts as TWO.
    """
    body = _cbor.loads(sign_claim(signer, CLAIM))
    assert isinstance(body, _cbor.Tagged)
    parts = body.value
    assert isinstance(parts, list)
    forged = _cbor.dumps(_cbor.Tagged(18, [parts[0], {COSE_HEADER_X5CHAIN: b"dup"}, None, parts[3]]))
    with pytest.raises(CoseError, match="multiple credentials"):
        parse(forged)


def test_a_missing_x5chain_is_rejected() -> None:
    """14.2: no credentials is a reject, not a soft failure."""
    protected = _cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))
    with pytest.raises(CoseError, match="must be present in the protected header"):
        parse(forged)


def test_a_tampered_signature_does_not_verify(signer: Signer) -> None:
    body = _cbor.loads(sign_claim(signer, CLAIM))
    assert isinstance(body, _cbor.Tagged)
    parts = body.value
    assert isinstance(parts, list)
    signature = parts[3]
    assert isinstance(signature, bytes)
    broken = bytes([signature[0] ^ 0x01]) + signature[1:]
    forged = _cbor.dumps(_cbor.Tagged(18, [parts[0], {}, None, broken]))

    with pytest.raises(CoseError, match="does not verify"):
        verify_claim(forged, CLAIM, signer.private_key.public_key())


def test_a_different_claim_does_not_verify(signer: Signer) -> None:
    """The binding is to the claim bytes, so substituting them must fail."""
    message = sign_claim(signer, CLAIM)
    with pytest.raises(CoseError, match="does not verify"):
        verify_claim(message, b"\xa1\x63xyz\x02", signer.private_key.public_key())


@pytest.mark.parametrize(
    ("forged", "pattern"),
    [
        (_cbor.dumps([1, 2, 3]), "not a tagged COSE_Sign1"),
        (_cbor.dumps(_cbor.Tagged(18, [b"", {}, None])), "four-element array"),
        (_cbor.dumps(_cbor.Tagged(18, [1, {}, None, b"\x00" * 64])), "protected header must be a byte string"),
        (_cbor.dumps(_cbor.Tagged(18, [b"", 1, None, b"\x00" * 64])), "unprotected header must be a map"),
        (_cbor.dumps(_cbor.Tagged(18, [b"", {}, None, b"short"])), "64 bytes"),
        (b"\xff\xff", "not valid CBOR"),
    ],
)
def test_malformed_structures_are_rejected(forged: bytes, pattern: str) -> None:
    with pytest.raises(CoseError, match=pattern):
        parse(forged)


def test_a_non_eddsa_algorithm_is_rejected(signer: Signer) -> None:
    """13.2.1 permits EdDSA over Ed25519 only for this package."""
    protected = _cbor.dumps({COSE_HEADER_ALG: -7, COSE_HEADER_X5CHAIN: signer.x5chain()[0]})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))
    with pytest.raises(CoseError, match="unsupported COSE algorithm"):
        verify_claim(forged, CLAIM, signer.private_key.public_key())


def test_signing_is_byte_stable(signer: Signer) -> None:
    """Ed25519 is deterministic, so the whole message is too."""
    assert len({sign_claim(signer, CLAIM) for _ in range(20)}) == 1


#: Every vendored cose-wg file carrying a Sig_structure with a zero-length
#: external_aad. Ten of the twelve; the two excluded are named in the tests below,
#: which is deliberate -- a silent skip reads as coverage.
_SIG_STRUCTURE_VECTORS = [
    "eddsa-sig-01.json",
    "eddsa-sig-02.json",
    "sign-fail-01.json",
    "sign-fail-02.json",
    "sign-fail-03.json",
    "sign-fail-04.json",
    "sign-fail-06.json",
    "sign-fail-07.json",
    "sign-pass-01.json",
    "sign-pass-03.json",
]


def test_no_vendored_sig_structure_vector_goes_unread() -> None:
    """The list above must account for every file in the corpus.

    A vendored vector nobody reads is a vector that is not an oracle. Adding a file
    with ``make download-vectors`` and forgetting to list it would otherwise be
    invisible, so the two deliberate exclusions are named here rather than omitted.
    """
    on_disk = {path.name for path in COSE_VECTORS.glob("*.json")}
    accounted = set(_SIG_STRUCTURE_VECTORS) | {"sign-pass-02.json", "eddsa-01.json"}
    assert on_disk == accounted, f"unread vectors: {sorted(on_disk - accounted)}"


@pytest.mark.parametrize("name", _SIG_STRUCTURE_VECTORS)
def test_our_sig_structure_matches_the_cose_wg_encoding(name: str) -> None:
    """THE interop check for this module, over every vendored vector that has one.

    Each file publishes ``intermediates.ToBeSign_hex`` -- the serialized
    Sig_structure. Reproducing it byte for byte proves our assembly matches an
    independently produced encoding rather than merely matching itself.

    THE ALGORITHMS AND THE PROTECTED HEADERS DIFFER ACROSS THE ROWS, which is the
    reason to run all of them: eight are ES256 over P-256 and one is Ed448, none of
    which C2PA 13.2.1 permits us to SIGN with, but the Sig_structure is
    algorithm-independent and a header of a different length is where a width bug in
    the bstr encoding would show.

    Their vectors attach the payload rather than detaching it, so the payload slot
    carries their plaintext; the structure and the zero-length external_aad are what
    is being compared.
    """
    doc = load_object(COSE_VECTORS / name)
    expected = bytes.fromhex(str_field(doc, "intermediates", "ToBeSign_hex"))

    decoded = _cbor.loads(expected)
    assert isinstance(decoded, list)
    context, protected, aad, payload = decoded

    assert context == "Signature1"
    assert aad == b"", "external_aad is zero-length, as C2PA 13.2.3 requires"
    assert isinstance(protected, bytes)
    assert isinstance(payload, bytes)
    assert sig_structure(protected, payload) == expected


def test_the_one_vector_with_external_aad_is_a_negative_oracle() -> None:
    """``sign-pass-02`` is the only vendored vector using external_aad, so it is the
    only one we must FAIL to reproduce.

    13.2.3: "external authenticated data shall not be used". ``sig_structure`` hard-codes
    a zero-length aad, so a vector carrying twelve bytes there cannot be re-derived --
    and the difference must be in that slot and nowhere else. Asserting only that the
    bytes differ would pass on any bug at all.
    """
    doc = load_object(COSE_VECTORS / "sign-pass-02.json")
    expected = bytes.fromhex(str_field(doc, "intermediates", "ToBeSign_hex"))

    decoded = _cbor.loads(expected)
    assert isinstance(decoded, list)
    context, protected, aad, payload = decoded
    assert isinstance(protected, bytes)
    assert isinstance(payload, bytes)

    assert aad == bytes.fromhex("11aa22bb33cc44dd550066 99".replace(" ", ""))
    assert sig_structure(protected, payload) != expected

    # Everything BUT the aad agrees: put their aad back and the encoding matches.
    assert _cbor.dumps([context, protected, aad, payload]) == expected
    assert _cbor.loads(sig_structure(protected, payload)) == [context, protected, b"", payload]


def test_the_multi_signer_vector_is_the_shape_c2pa_excludes() -> None:
    """``eddsa-01`` carries no top-level ToBeSign, and the reason is the point.

    It is a multi-signer ``COSE_Sign``: its Sig_structure is five elements and its
    context string is "Signature", not "Signature1". C2PA 13.2 permits ``COSE_Sign1``
    only, so this file is vendored as the shape we must never emit, and reading it
    keeps ``PROVENANCE.md``'s claim about it checkable.
    """
    doc = load_object(COSE_VECTORS / "eddsa-01.json")
    intermediates = doc["intermediates"]
    assert isinstance(intermediates, dict)
    signers = intermediates["signers"]
    assert isinstance(signers, list)

    decoded = _cbor.loads(bytes.fromhex(str_fields(signers[0], "eddsa-01.json:signers[0]")["ToBeSign_hex"]))
    assert isinstance(decoded, list)
    assert decoded[0] == "Signature", "the multi-signer context, which we never build"
    assert len(decoded) == 5, "COSE_Sign adds the signer's own protected bucket"


def _cbor_head(major: int, length: int) -> bytes:
    """A definite-length CBOR head, RFC 8949 3.1. Transcribed, not imported."""
    if length < 24:
        return bytes([major << 5 | length])
    if length < 0x100:
        return bytes([major << 5 | 24, length])
    if length < 0x10000:
        return bytes([major << 5 | 25]) + length.to_bytes(2, "big")
    return bytes([major << 5 | 26]) + length.to_bytes(4, "big")


def _to_be_signed(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 4.4 Sig_structure, built from the RFC rather than from ``_cose``.

    ``[ "Signature1", protected, external_aad, payload ]`` as a definite-length
    four-element array. ``external_aad`` is empty because C2PA 13.2.3 forbids it.
    """
    return (
        b"\x84"
        + _cbor_head(3, len(b"Signature1"))
        + b"Signature1"
        + _cbor_head(2, len(protected))
        + protected
        + _cbor_head(2, 0)
        + _cbor_head(2, len(payload))
        + payload
    )


def test_a_signature_embed_produced_verifies_over_a_hand_built_sig_structure(signer: Signer) -> None:
    """The producer side of the COSE claim, checked against the RFC not against us.

    ``test_our_sig_structure_matches_the_cose_wg_encoding`` reproduces cose-wg's
    ToBeSign from THEIR protected header and THEIR payload. It never touches a
    signature this package produced, so a claim signed over the wrong bytes would
    pass it and pass ``verify()`` too -- the same wrong assembly on both sides.

    Here the message comes out of a real ``embed``. The Sig_structure is rebuilt by
    ``_to_be_signed`` above, and the arbiter is Ed25519 verification in
    ``cryptography``: it succeeds only if the bytes we signed are the bytes RFC 9052
    says to sign.
    """
    marked = embed("Signed.", signer, DISCLOSURE, context=_PINNED)
    store = extract(marked)
    assert store is not None

    message = parse(store.signature)
    signer.private_key.public_key().verify(
        message.signature,
        _to_be_signed(message.protected, store.claim_bytes),
    )


def test_a_non_map_protected_header_is_rejected() -> None:
    """The protected bucket is a serialized CBOR map, not an arbitrary item."""
    protected = _cbor.dumps([1, 2])
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))
    with pytest.raises(CoseError, match="not a CBOR map"):
        parse(forged)


def test_a_multi_certificate_chain_keeps_the_order_it_was_given(signing_key: Ed25519PrivateKey) -> None:
    """RFC 9360: a bare bstr for one certificate, an array for a chain, leaf first (14.5).

    THE TWO CERTIFICATES DIFFER, AND THE LARGER DER COMES FIRST. This test passed the
    same certificate twice, so ``reversed(self.certificates)`` survived in
    ``Signer.x5chain`` -- against a two-element chain of identical bytes, every ordering
    is the same list. A reversed chain is not cosmetic: a verifier taking element 0 as
    the leaf would check the signature against the wrong public key, or reject a chain
    that is in fact well formed.

    A BARE ``sorted(self.certificates)`` IS NOT A MUTATION THIS HAS TO CATCH, and an
    earlier version of this docstring claimed it had survived. It cannot run at all --
    ``x509.Certificate`` has no ordering, so it raises ``TypeError`` whatever the values
    -- and two existing tests already killed it. Ordering by DER descending is still
    what the rows below are for: it catches a sort with a KEY, which does run, and a
    sort that claims to be a no-op has to be handed a sequence it would actually move.
    """
    certificates: list[x509.Certificate] = sorted(
        (build_certificate(signing_key, common_name=name) for name in ("leaf one", "leaf two")),
        key=lambda certificate: certificate.public_bytes(Encoding.DER),
        reverse=True,
    )
    der = [certificate.public_bytes(Encoding.DER) for certificate in certificates]
    assert der[0] != der[1]
    assert der != sorted(der), "the given order is not the sorted order"

    signer = Signer(private_key=signing_key, certificates=(certificates[0], certificates[1]))
    assert signer.x5chain() == der, "leaf first, as given"
    assert parse(sign_claim(signer, CLAIM)).x5chain() == der, "and the same after a round trip"


def test_a_chain_containing_a_non_byte_string_is_rejected(signer: Signer) -> None:
    """A certificate slot holding something other than DER is malformed input."""
    protected = _cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA, COSE_HEADER_X5CHAIN: [b"der", 1]})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))
    with pytest.raises(CoseError, match="only byte strings"):
        parse(forged).x5chain()


def test_x5chain_accessor_reports_absence(signer: Signer) -> None:
    """Reachable via a header that passed the presence check but holds a bad type."""
    from c2patxt._cose import CoseSign1

    empty = CoseSign1(protected=_cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA}), unprotected={}, signature=b"")
    with pytest.raises(CoseError, match="absent from the protected header"):
        empty.x5chain()


@pytest.mark.parametrize(
    ("labels", "accepted"),
    [
        ((COSE_HEADER_X5CHAIN,), True),
        (("x5chain",), True),
        ((COSE_HEADER_X5CHAIN, "x5chain"), True),
    ],
    ids=["integer-33", "string-label", "both-in-protected"],
)
def test_the_x5chain_string_label_is_accepted_in_the_protected_bucket(
    labels: tuple[int | str, ...], accepted: bool
) -> None:
    """C2PA 14.5 verbatim: "Validators shall accept either the string `x5chain` or the
    integer 33 as the label for this header. If both labels are present, validators
    shall use the header with the integer label 33 and ignore the header with the
    string x5chain."

    We read only the integer, so a producer using the deprecated-but-legal string
    label read as "no credential at all". The asymmetry is what marks it an oversight
    rather than a decision: ``_check_single_credential`` ALREADY recognises the
    string label in the UNPROTECTED bucket, for the 14.2 duplicate check.

    The ``both-in-protected`` case carries DIFFERENT chains under the two labels, so
    "33 wins" is observable rather than assumed.
    """
    integer_chain: list[_cbor.CborValue] = [b"\x01" * 8]
    string_chain: list[_cbor.CborValue] = [b"\x02" * 8]

    protected: dict[int | str | bytes, _cbor.CborValue] = {COSE_HEADER_ALG: COSE_ALG_EDDSA}
    for label in labels:
        protected[label] = integer_chain if label == COSE_HEADER_X5CHAIN else string_chain

    message = _cose.CoseSign1(
        protected=_cbor.dumps(protected),
        unprotected={},
        signature=b"\x00" * 64,
    )

    assert accepted
    chain = message.x5chain()
    # 33 wins wherever it is present; the string label is used only in its absence.
    expected = integer_chain if COSE_HEADER_X5CHAIN in labels else string_chain
    assert list(chain) == list(expected)


def test_the_unprotected_bucket_is_still_refused() -> None:
    """A DELIBERATE DEVIATION FROM A `shall`, pinned so it stays deliberate.

    14.5 also says "Validators shall accept the header from either the protected or
    unprotected bucket, to maintain compatibility with previous versions". We do not.
    An unprotected header is not covered by the signature, so a certificate chain
    taken from there is one an attacker can swap for their own -- and the whole point
    of the chain is to say which key signed the claim.

    Recorded in docs/deviations.md and in the compatibility document's exclusion list.
    Asserted on the exact message so the refusal cannot become incidental.
    """
    message = _cose.CoseSign1(
        protected=_cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA}),
        unprotected={"x5chain": [b"\x01" * 8]},
        signature=b"\x00" * 64,
    )
    with pytest.raises(_cose.CoseError, match="protected header"):
        _cose._check_single_credential(message)
