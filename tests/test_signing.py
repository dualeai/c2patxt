"""Signer and Disclosure: what a caller supplies, and what is refused at construction."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt.signing import (
    COSE_ALG_EDDSA,
    MODEL_TYPES,
    Disclosure,
    ModelType,
    Signer,
    has_claim_signing_eku,
)
from c2patxt.trust import ProfileError
from tests.conftest import build_certificate


def test_cose_algorithm_identifier_is_minus_eight() -> None:
    """RFC 9053 2.2 / IANA COSE registry. C2PA names EdDSA but never the number."""
    assert COSE_ALG_EDDSA == -8


def test_signer_accepts_a_conformant_ed25519_credential(
    signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate
) -> None:
    signer = Signer(private_key=signing_key, certificates=(signing_certificate,))
    assert signer.leaf is signing_certificate
    assert len(signer.x5chain()) == 1


def test_signature_is_sixty_four_bytes_and_verifies(
    signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate
) -> None:
    signer = Signer(private_key=signing_key, certificates=(signing_certificate,))
    signature = signer.sign(b"to be signed")
    assert len(signature) == 64
    signing_key.public_key().verify(signature, b"to be signed")


def test_signing_is_deterministic(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> None:
    """RFC 8032 5.1.6: the nonce is derived, not random.

    This is the one source of byte-stability we get for free. Everything else that
    could vary lives in manifest construction.
    """
    signer = Signer(private_key=signing_key, certificates=(signing_certificate,))
    assert len({signer.sign(b"same message") for _ in range(50)}) == 1


def test_ed448_is_refused_at_construction() -> None:
    """C2PA 13.2.1: "Ed25519 instance only. No other EdDSA instances are allowed".

    Ed448 shares the COSE algorithm identifier -8, so an implementation checking the
    alg value alone would accept it and be non-conformant while looking correct.
    cose-wg's own eddsa-sig-02 vector is exactly this case.
    """
    key = Ed448PrivateKey.generate()
    certificate = build_certificate(key)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Ed25519 only"):
        Signer(private_key=key, certificates=(certificate,))  # type: ignore[arg-type]


def test_an_ecdsa_certificate_is_refused() -> None:
    """ES256 is permitted by C2PA generally, but this package signs Ed25519 only."""
    key = generate_private_key(SECP256R1())
    certificate = build_certificate(key)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Ed25519 only"):
        Signer(private_key=key, certificates=(certificate,))  # type: ignore[arg-type]


def test_a_mismatched_key_and_certificate_are_refused(signing_key: Ed25519PrivateKey) -> None:
    """Checked in BOTH directions: 14.5.1.1 has no Ed25519 SPKI clause, so this is ours."""
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    certificate = build_certificate(other)
    with pytest.raises(ValueError, match="does not match"):
        Signer(private_key=signing_key, certificates=(certificate,))


def test_an_empty_chain_is_refused(signing_key: Ed25519PrivateKey) -> None:
    """14.2: exactly one identity credential; zero is a reject."""
    with pytest.raises(ValueError, match="at least the leaf certificate"):
        Signer(private_key=signing_key, certificates=())


def test_a_conformant_certificate_carries_the_claim_signing_eku(
    signing_certificate: x509.Certificate,
) -> None:
    assert has_claim_signing_eku(signing_certificate) is True


def test_a_default_openssl_style_certificate_lacks_the_eku(signing_key: Ed25519PrivateKey) -> None:
    """THE misconfiguration to expect from Terraform's tls_self_signed_cert.

    A default `openssl req -x509` certificate asserts cA and carries no EKU. Under
    14.5.1.1 that yields signingCredential.INVALID -- a hard reject where the
    manifest is not even Valid -- rather than the signingCredential.untrusted a
    self-signed credential is supposed to produce.
    """
    certificate = build_certificate(signing_key, conformant=False)
    assert has_claim_signing_eku(certificate) is False


def test_disclosure_requires_a_text_media_type() -> None:
    with pytest.raises(ValueError, match="text/\\* media type"):
        Disclosure(media_type="image/jpeg", model_type=ModelType.GENERIC)


def test_disclosure_requires_a_model_type() -> None:
    """18.28.2: modelType is the assertion's only required field."""
    with pytest.raises(ValueError, match="model_type must not be empty"):
        Disclosure(media_type="text/plain", model_type="")


@pytest.mark.parametrize(
    "media_type",
    ["text/plain", "text/markdown", "text/csv", "text/tab-separated-values", "text/html"],
)
def test_any_text_media_type_is_accepted(media_type: str) -> None:
    """Marking scope is the router's rule (RFC-136 2), not the codec's.

    text/html is accepted even though C2PA assigns it to A.7 and this carrier is the
    wrong mechanism for it. Documented in the Disclosure docstring rather than
    enforced, because the SDK does not own platform policy.
    """
    disclosure = Disclosure(media_type=media_type, model_type=ModelType.GENERIC)
    assert disclosure.media_type == media_type


def test_disclosure_is_frozen_and_carries_no_identifying_fields() -> None:
    """RFC-136 5 forbids tenant, agent, account, user, author or prompt content.

    A closed type turns that legal constraint into a type-system constraint: there
    is no field to put them in and no generic escape hatch.
    """
    disclosure = Disclosure(
        media_type="text/plain",
        model_type=ModelType.GENERIC,
        model_name="some-model",
        model_identifier="pkg:generic/some-model@1",
    )
    fields = set(disclosure.__dataclass_fields__)
    assert fields == {"media_type", "model_type", "model_name", "model_identifier"}
    for forbidden in ("tenant", "agent", "account", "user", "author", "prompt", "conversation"):
        assert not any(forbidden in field for field in fields)

    with pytest.raises(AttributeError):
        disclosure.model_name = "other"  # type: ignore[misc]


def test_a_nonconformant_certificate_is_refused_at_construction() -> None:
    """THE PRODUCER APPLIES THE SAME PROFILE THE VERIFIER DOES.

    Without this, embed() signs happily with a certificate our own verify() rejects,
    and the only way to discover it is to verify your own output -- which nobody
    does. `openssl req -x509` defaults, and the natural way to build a self-signed
    certificate with `cryptography`, both produce cA=TRUE and no EKU. So this is the
    DEFAULT mistake, not an exotic one, and the cost of catching it late is bytes
    that already shipped, signed.
    """
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    with pytest.raises(ProfileError):
        Signer(private_key=key, certificates=(build_certificate(key, conformant=False),))


def test_the_escape_hatch_exists_only_to_build_verifier_tests() -> None:
    """allow_nonconformant must actually work, or the verifier cannot be tested.

    A rejection this strict needs a documented way past it; otherwise the next person
    who needs to build a bad credential weakens the check itself.
    """
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signer = Signer(
        private_key=key,
        certificates=(build_certificate(key, conformant=False),),
        allow_nonconformant=True,
    )
    assert signer.leaf is not None


def test_the_claim_signing_eku_is_reachable_from_the_package() -> None:
    """Reachable from the package, because a caller has to name it to build a leaf.

    NOT required by the profile. 14.5.1.1 names no EKU OID;
    a leaf carrying only id-kp-emailProtection verifies as VALID. It is exported because
    14.5.1.2 lets a validator accept only credentials bearing an EKU it holds anchors
    for, so this is the OID a C2PA-aware trust store looks for.

    Requiring an import from c2patxt.signing -- a module the package docstring
    implies is private -- put the single most necessary value behind the surface.
    """
    import c2patxt

    assert c2patxt.C2PA_CLAIM_SIGNING_EKU.dotted_string == "1.3.6.1.4.1.62558.2.1"


@pytest.mark.parametrize(
    "value",
    [
        ModelType.GENERIC,
        ModelType.HUGGINGFACE_TRANSFORMERS,
        ModelType.ONNX,
        ModelType.PYTORCH,
        ModelType.TENSORFLOW,
    ],
)
def test_every_model_type_is_a_table_12_value(value: str) -> None:
    """C2PA 18.28.2: modelType "is an enumeration of AI model types defined in
    Table 12".

    Earlier releases emitted ``c2pa.types.model.generative`` and
    ``c2pa.types.model.transformative``. NEITHER STRING APPEARS ANYWHERE IN THE
    SPECIFICATION -- Table 12 enumerates model FORMATS (caffe, onnx, pytorch, …)
    headed by the generic ``c2pa.types.model``, and has no concept of a generation
    mode. It was on every mark the package produced, in signed bytes, in the one field
    an EU AI Act Article 50(2) consumer keys on.

    The set below is a verbatim subset of Table 12, transcribed from the specification
    rather than from our own source, so a value that is not in the table fails here
    rather than at someone else's validator.
    """
    table_12 = {
        "c2pa.types.model",
        "c2pa.types.model.caffe",
        "c2pa.types.model.caffe2",
        "c2pa.types.model.catboost",
        "c2pa.types.model.coreml",
        "c2pa.types.model.flax",
        "c2pa.types.model.huggingface.transformers",
        "c2pa.types.model.jax",
        "c2pa.types.model.keras",
        "c2pa.types.model.lightgbm",
        "c2pa.types.model.ml_net",
        "c2pa.types.model.mxnet",
        "c2pa.types.model.onnx",
        "c2pa.types.model.openvino",
        "c2pa.types.model.openvino.parameter",
        "c2pa.types.model.openvino.topology",
        "c2pa.types.model.paddle",
        "c2pa.types.model.pytorch",
        "c2pa.types.model.sklearn",
        "c2pa.types.model.tensorflow",
        "c2pa.types.model.tensorrt",
        "c2pa.types.model.tflite",
        "c2pa.types.model.torchscript",
        "c2pa.types.model.xgboost",
    }
    assert value in table_12

    # BOTH DIRECTIONS, and only one of them was here. Asserting `value in table_12` over
    # ModelType's five members proves ModelType is a SUBSET and never touches
    # MODEL_TYPES at all -- so deleting "keras", deleting "onnx", deleting "tensorflow"
    # or misspelling "ml_net" as "mlnet" each survived the whole suite. A vendored copy
    # of somebody else's table is only honest if something compares it to the table.
    assert set(MODEL_TYPES) == table_12


def test_the_removed_model_types_are_gone() -> None:
    """Guards against the non-conforming values coming back by habit."""
    assert not hasattr(ModelType, "GENERATIVE")
    assert not hasattr(ModelType, "TRANSFORMATIVE")

    exported = {getattr(ModelType, name) for name in dir(ModelType) if not name.startswith("_")}
    assert all(v.startswith("c2pa.types.model") for v in exported)
    assert "c2pa.types.model.generative" not in exported
