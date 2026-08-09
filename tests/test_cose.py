# pyright: reportPrivateUsage=false
# Drives private COSE units where a public round trip cannot distinguish header buckets.
"""COSE_Sign1 as C2PA 13.2 narrows it: detached payload, zero-length aad, x5chain."""

from __future__ import annotations

import pathlib
import uuid

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from c2patxt import EmbedContext, _cbor, _cose, embed, extract
from c2patxt._cose import (
    COSE_HEADER_ALG,
    COSE_HEADER_CRIT,
    COSE_HEADER_X5CHAIN,
    CoseAlgorithmError,
    CoseCredentialError,
    CoseError,
    CoseSignatureError,
    CoseStructureError,
    parse,
    sig_structure,
)
from c2patxt.signing import COSE_ALG_EDDSA, Signer
from tests._json import load_object, str_field
from tests.conftest import DISCLOSURE, WHEN

_PINNED = EmbedContext(
    manifest_uuid=uuid.UUID("00000000-0000-4000-8000-00000000000d"),
    instance_id="xmp:iid:cose",
    when=WHEN,
)
COSE_VECTORS = pathlib.Path(__file__).parent / "vectors" / "cose"

CLAIM = b"\xa1\x63abc\x01"  # any deterministically-encoded CBOR stands in for a claim


@pytest.fixture
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


def _signed_claim(signer: Signer, claim: bytes = CLAIM) -> bytes:
    signed = _cose._prepare_signed_claim(signer, claim)
    return _cose._serialize_signed_claim(signed)


def _verify_message(
    message: bytes,
    claim: bytes,
    public_key: CertificatePublicKeyTypes,
) -> _cose.CoseSign1:
    parsed = parse(message)
    algorithm = _cose._check_algorithm(parsed)
    _cose._verify_signature(parsed, claim, public_key, algorithm)
    return parsed


def test_sig_structure_shape() -> None:
    """13.2.3: ["Signature1", protected, external_aad, payload]."""
    decoded = _cbor.loads(sig_structure(b"\xa1\x01\x27", CLAIM))
    assert decoded == ["Signature1", b"\xa1\x01\x27", b"", CLAIM]


def test_external_aad_is_always_zero_length() -> None:
    """13.2.3: "external authenticated data shall not be used"."""
    decoded = _cbor.loads(sig_structure(b"", CLAIM))
    assert isinstance(decoded, list)
    assert decoded[2] == b""


def test_the_payload_is_detached_as_nil_not_an_empty_bstr(signer: Signer) -> None:
    """13.2.2 warns explicitly that a zero-length bstr does NOT mean detached."""
    decoded = _cbor.loads(_signed_claim(signer))
    assert isinstance(decoded, _cbor.Tagged)
    assert decoded.tag == 18
    body = decoded.value
    assert isinstance(body, list)
    assert body[2] is None, "payload slot must hold nil (0xf6)"

    forged = _cbor.dumps(_cbor.Tagged(18, [body[0], {}, b"", body[3]]))
    with pytest.raises(CoseError, match="detached"):
        parse(forged)


def test_x5chain_lives_in_the_protected_bucket(signer: Signer) -> None:
    """14.5: generators always place x5chain in the protected bucket."""
    parsed = parse(_signed_claim(signer))
    assert COSE_HEADER_X5CHAIN in parsed.decoded_protected
    assert parsed.unprotected == {"pad": b""}
    assert parsed.x5chain() == tuple(signer.x5chain())


@pytest.mark.parametrize("size", [23, 24, 255, 256])
def test_cose_padding_is_zero_filled_across_cbor_length_thresholds(signer: Signer, size: int) -> None:
    """10.4.2: the unprotected string ``pad`` contains only zero bytes."""
    signed = _cose._prepare_signed_claim(signer, CLAIM)
    message = _cose._serialize_signed_claim(signed, pad=size)
    assert parse(message).unprotected == {"pad": bytes(size)}


def test_cbor_padding_headers_widen_at_23_and_255_bytes(signer: Signer) -> None:
    """Pin the two preferred-CBOR jumps the solver must search across."""
    signed = _cose._prepare_signed_claim(signer, CLAIM)
    sizes = {size: len(_cose._serialize_signed_claim(signed, pad=size)) for size in (23, 24, 255, 256)}
    assert sizes[24] - sizes[23] == 2
    assert sizes[256] - sizes[255] == 2


def test_unprotected_padding_changes_without_resigning(signer: Signer) -> None:
    """10.4.4: shrinking the unprotected pad does not alter Sig_structure."""
    signed = _cose._prepare_signed_claim(signer, CLAIM)
    first = _verify_message(_cose._serialize_signed_claim(signed, pad=24), CLAIM, signer.private_key.public_key())
    second = _verify_message(
        _cose._serialize_signed_claim(signed, pad=19),
        CLAIM,
        signer.private_key.public_key(),
    )
    assert first.protected == second.protected
    assert first.signature == second.signature
    assert second.unprotected == {"pad": bytes(19)}


def test_negative_cose_padding_lengths_are_rejected(signer: Signer) -> None:
    signed = _cose._prepare_signed_claim(signer, CLAIM)
    with pytest.raises(ValueError, match="non-negative"):
        _cose._serialize_signed_claim(signed, pad=-1)


def test_a_validator_does_not_treat_unsigned_nonzero_padding_as_a_signature_failure(signer: Signer) -> None:
    """Zero-fill is a generator rule; the unprotected bytes are not authenticated."""
    signed = _cose._prepare_signed_claim(signer, CLAIM)
    message = _cbor.dumps(
        _cbor.Tagged(
            _cbor.TAG_COSE_SIGN1,
            [signed.protected, {"pad": b"\xff"}, None, signed.signature],
        )
    )
    _verify_message(message, CLAIM, signer.private_key.public_key())


def test_x5chain_uses_integer_label_33_not_the_string(signer: Signer) -> None:
    """RFC 9360. C2PA: "use only the integer 33 as the label"."""
    header = parse(_signed_claim(signer)).decoded_protected
    assert COSE_HEADER_X5CHAIN == 33
    assert "x5chain" not in header


@pytest.mark.parametrize("label", [COSE_HEADER_X5CHAIN, "x5chain"], ids=["integer-33", "string-label"])
def test_the_same_credential_label_in_both_buckets_is_rejected(signer: Signer, label: int | str) -> None:
    """14.2: zero or two-or-more credentials shall be rejected.

    The same certificate duplicated across buckets counts as TWO.
    """
    body = _cbor.loads(_signed_claim(signer))
    assert isinstance(body, _cbor.Tagged)
    parts = body.value
    assert isinstance(parts, list)
    assert isinstance(parts[0], bytes)
    protected = _cbor.loads(parts[0])
    assert isinstance(protected, dict)
    chain = protected.pop(COSE_HEADER_X5CHAIN)
    protected[label] = chain
    forged = _cbor.dumps(_cbor.Tagged(18, [_cbor.dumps(protected), {label: b"dup"}, None, parts[3]]))
    with pytest.raises(CoseCredentialError, match="multiple credentials"):
        parse(forged)


def test_a_missing_x5chain_is_rejected() -> None:
    """14.2: no credentials is a reject, not a soft failure."""
    protected = _cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))
    with pytest.raises(CoseCredentialError, match="absent from both"):
        parse(forged)


def test_a_tampered_signature_does_not_verify(signer: Signer) -> None:
    body = _cbor.loads(_signed_claim(signer))
    assert isinstance(body, _cbor.Tagged)
    parts = body.value
    assert isinstance(parts, list)
    signature = parts[3]
    assert isinstance(signature, bytes)
    broken = bytes([signature[0] ^ 0x01]) + signature[1:]
    forged = _cbor.dumps(_cbor.Tagged(18, [parts[0], {}, None, broken]))

    with pytest.raises(CoseSignatureError, match="does not verify"):
        _verify_message(forged, CLAIM, signer.private_key.public_key())


def test_a_different_claim_does_not_verify(signer: Signer) -> None:
    """The binding is to the claim bytes, so substituting them must fail."""
    message = _signed_claim(signer)
    with pytest.raises(CoseSignatureError, match="does not verify"):
        _verify_message(message, b"\xa1\x63xyz\x02", signer.private_key.public_key())


def test_well_formed_non_deterministic_cose_encoding_is_accepted(signer: Signer) -> None:
    """RFC 9052 section 9 applies deterministic encoding to Sig_structure, not COSE.

    This message uses an out-of-order protected map, an indefinite outer array, and an
    indefinite unprotected map. The signature covers the exact protected bytes.
    """
    certificate = signer.x5chain()[0]
    protected = b"\xa2\x18\x21" + _cbor.dumps(certificate) + b"\x01\x27"
    signature = signer.sign(sig_structure(protected, CLAIM))
    message = b"\xd2\x9f" + _cbor.dumps(protected) + b"\xbf\xff\xf6" + _cbor.dumps(signature) + b"\xff"

    parsed = _verify_message(message, CLAIM, signer.private_key.public_key())

    assert parsed.decoded_protected[COSE_HEADER_ALG] == COSE_ALG_EDDSA
    assert parsed.x5chain() == tuple(signer.x5chain())


def test_duplicate_protected_keys_remain_rejected_in_cose_mode() -> None:
    """RFC 9052 section 9 forbids duplicate map keys in every decoding mode."""
    protected = bytes.fromhex("a20127180127")  # key 1 twice, using two CBOR spellings
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))

    with pytest.raises(CoseStructureError, match="duplicate map key"):
        parse(forged)


@pytest.mark.parametrize("size", [63, 65])
def test_a_wrong_length_ed25519_signature_is_a_verification_failure(signer: Signer, size: int) -> None:
    protected = _cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA, COSE_HEADER_X5CHAIN: signer.x5chain()[0]})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * size]))

    with pytest.raises(CoseSignatureError, match="64 bytes"):
        _verify_message(forged, CLAIM, signer.private_key.public_key())


@pytest.mark.parametrize("chain", [[], [b"der"]], ids=["empty", "singleton"])
def test_an_x5chain_array_requires_at_least_two_certificates(chain: list[bytes]) -> None:
    protected = _cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA, COSE_HEADER_X5CHAIN: chain})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))

    with pytest.raises(CoseCredentialError, match="at least two"):
        parse(forged)


@pytest.mark.parametrize("algorithm", [-8.0, "-8"], ids=["float", "text"])
def test_the_eddsa_algorithm_identifier_must_be_the_integer_registry_value(
    signer: Signer,
    algorithm: float | str,
) -> None:
    protected = cbor2.dumps({COSE_HEADER_ALG: algorithm, COSE_HEADER_X5CHAIN: signer.x5chain()[0]})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))

    with pytest.raises(CoseAlgorithmError, match="unsupported COSE algorithm"):
        _verify_message(forged, CLAIM, signer.private_key.public_key())


@pytest.mark.parametrize(
    ("protected_crit", "unprotected", "unknown_present", "pattern"),
    [
        (None, {COSE_HEADER_CRIT: [COSE_HEADER_ALG]}, False, "must be protected"),
        (None, {}, False, "non-empty array"),
        ([], {}, False, "non-empty array"),
        ("alg", {}, False, "non-empty array"),
        ([True], {}, False, "integer or text-string"),
        ([b"alg"], {}, False, "integer or text-string"),
        ([999], {}, False, "absent from the protected"),
        ([999], {}, True, "not understood"),
    ],
    ids=[
        "unprotected",
        "null",
        "empty",
        "scalar",
        "bool-label",
        "bytes-label",
        "missing-label",
        "unknown-label",
    ],
)
def test_malformed_or_unsupported_critical_headers_are_rejected(
    signer: Signer,
    protected_crit: _cbor.CborValue,
    unprotected: dict[int | str | bytes, _cbor.CborValue],
    unknown_present: bool,
    pattern: str,
) -> None:
    protected: dict[int, _cbor.CborValue] = {
        COSE_HEADER_ALG: COSE_ALG_EDDSA,
        COSE_HEADER_X5CHAIN: signer.x5chain()[0],
        COSE_HEADER_CRIT: protected_crit,
    }
    if unknown_present:
        protected[999] = "must understand"
    forged = _cbor.dumps(_cbor.Tagged(18, [_cbor.dumps(protected), unprotected, None, b"\x00" * 64]))

    with pytest.raises(CoseStructureError, match=pattern):
        parse(forged)


def test_understood_critical_headers_are_accepted(signer: Signer) -> None:
    protected = _cbor.dumps(
        {
            COSE_HEADER_ALG: COSE_ALG_EDDSA,
            COSE_HEADER_CRIT: [COSE_HEADER_ALG, COSE_HEADER_X5CHAIN],
            COSE_HEADER_X5CHAIN: signer.x5chain()[0],
        }
    )
    signature = signer.sign(sig_structure(protected, CLAIM))
    message = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, signature]))

    _verify_message(message, CLAIM, signer.private_key.public_key())


@pytest.mark.parametrize(
    ("forged", "pattern"),
    [
        (_cbor.dumps([1, 2, 3]), "not a tagged COSE_Sign1"),
        (_cbor.dumps(_cbor.Tagged(18, [b"", {}, None])), "four-element array"),
        (_cbor.dumps(_cbor.Tagged(18, [1, {}, None, b"\x00" * 64])), "protected header must be a byte string"),
        (_cbor.dumps(_cbor.Tagged(18, [b"", 1, None, b"\x00" * 64])), "unprotected header must be a map"),
        (_cbor.dumps(_cbor.Tagged(18, [b"", {}, None, 7])), "signature must be a byte string"),
        (_cbor.dumps(_cbor.Tagged(18, [b"\xff", {}, None, b"\x00" * 64])), "protected header is not valid CBOR"),
        (b"\xff\xff", "not valid CBOR"),
    ],
)
def test_malformed_structures_are_rejected(forged: bytes, pattern: str) -> None:
    with pytest.raises(CoseStructureError, match=pattern):
        parse(forged)


@pytest.mark.parametrize("bucket", ["protected", "unprotected"])
@pytest.mark.parametrize(
    "header_map",
    [bytes.fromhex("a18000"), _cbor.dumps({b"x": 0})],
    ids=["array", "byte-string"],
)
def test_non_label_cbor_keys_are_not_cose_header_labels(bucket: str, header_map: bytes) -> None:
    """The generic CBOR reader stays wider than COSE's header-label model."""
    protected = header_map if bucket == "protected" else _cbor.dumps({})
    unprotected = header_map if bucket == "unprotected" else _cbor.dumps({})
    forged = b"\xd2\x84" + _cbor.dumps(protected) + unprotected + b"\xf6" + _cbor.dumps(b"\x00" * 64)

    with pytest.raises(CoseStructureError, match=f"{bucket} header contains a label"):
        parse(forged)


def test_an_algorithm_outside_c2pa_is_rejected(signer: Signer) -> None:
    protected = _cbor.dumps({COSE_HEADER_ALG: 999, COSE_HEADER_X5CHAIN: signer.x5chain()[0]})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))
    with pytest.raises(CoseAlgorithmError, match="unsupported COSE algorithm"):
        _verify_message(forged, CLAIM, signer.private_key.public_key())


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
    """Check every applicable vendored COSE WG Sig_structure encoding.

    Each file publishes ``intermediates.ToBeSign_hex`` -- the serialized
    Sig_structure. Reproducing it byte for byte checks our assembly against the
    standards working group's corpus rather than against our own encoder.

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
    """The official multi-signer ``COSE_Sign`` must not parse as ``COSE_Sign1``."""
    doc = load_object(COSE_VECTORS / "eddsa-01.json")
    message = bytes.fromhex(str_field(doc, "output", "cbor"))

    with pytest.raises(CoseStructureError, match="not a tagged COSE_Sign1"):
        parse(message)


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
    with pytest.raises(CoseStructureError, match="not a CBOR map"):
        parse(forged)


def test_a_chain_containing_a_non_byte_string_is_rejected(signer: Signer) -> None:
    """A certificate slot holding something other than DER is malformed input."""
    protected = _cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA, COSE_HEADER_X5CHAIN: [b"der", 1]})
    forged = _cbor.dumps(_cbor.Tagged(18, [protected, {}, None, b"\x00" * 64]))
    with pytest.raises(CoseCredentialError, match="only byte strings"):
        parse(forged).x5chain()


@pytest.mark.parametrize(
    "labels",
    [
        (COSE_HEADER_X5CHAIN,),
        ("x5chain",),
        (COSE_HEADER_X5CHAIN, "x5chain"),
    ],
    ids=["integer-33", "string-label", "both-in-protected"],
)
def test_the_x5chain_string_label_is_accepted_in_the_protected_bucket(labels: tuple[int | str, ...]) -> None:
    """C2PA 14.5 verbatim: "Validators shall accept either the string `x5chain` or the
    integer 33 as the label for this header. If both labels are present, validators
    shall use the header with the integer label 33 and ignore the header with the
    string x5chain."

    The ``both-in-protected`` case carries DIFFERENT chains under the two labels, so
    "33 wins" is observable rather than assumed.
    """
    integer_chain = b"\x01" * 8
    string_chain = b"\x02" * 8

    protected: dict[int | str | bytes, _cbor.CborValue] = {COSE_HEADER_ALG: COSE_ALG_EDDSA}
    for label in labels:
        protected[label] = integer_chain if label == COSE_HEADER_X5CHAIN else string_chain

    forged = _cbor.dumps(_cbor.Tagged(18, [_cbor.dumps(protected), {}, None, b"\x00" * 64]))
    chain = parse(forged).x5chain()
    # 33 wins wherever it is present; the string label is used only in its absence.
    expected = integer_chain if COSE_HEADER_X5CHAIN in labels else string_chain
    assert chain == (expected,)


@pytest.mark.parametrize("integer_bucket", ["protected", "unprotected"])
def test_integer_x5chain_wins_across_header_buckets(integer_bucket: str) -> None:
    """14.5's label precedence applies before the protected-bucket preference."""
    integer_chain = b"integer chain"
    string_chain = b"string chain"
    protected: dict[int | str | bytes, _cbor.CborValue] = {COSE_HEADER_ALG: COSE_ALG_EDDSA}
    unprotected: dict[int | str | bytes, _cbor.CborValue] = {}
    if integer_bucket == "protected":
        protected[COSE_HEADER_X5CHAIN] = integer_chain
        unprotected["x5chain"] = string_chain
    else:
        protected["x5chain"] = string_chain
        unprotected[COSE_HEADER_X5CHAIN] = integer_chain
    forged = _cbor.dumps(_cbor.Tagged(18, [_cbor.dumps(protected), unprotected, None, b"\x00" * 64]))

    parsed = parse(forged)

    assert parsed.x5chain() == (integer_chain,)


@pytest.mark.parametrize("label", [COSE_HEADER_X5CHAIN, "x5chain"], ids=["integer-33", "string-label"])
def test_a_validator_accepts_x5chain_from_the_unprotected_bucket(signer: Signer, label: int | str) -> None:
    """14.5 requires this compatibility path even though generators use protected."""
    protected = _cbor.dumps({COSE_HEADER_ALG: COSE_ALG_EDDSA})
    signature = signer.sign(sig_structure(protected, CLAIM))
    message = _cbor.dumps(_cbor.Tagged(18, [protected, {label: signer.x5chain()[0]}, None, signature]))

    parsed = _verify_message(message, CLAIM, signer.private_key.public_key())

    assert parsed.x5chain() == tuple(signer.x5chain())
