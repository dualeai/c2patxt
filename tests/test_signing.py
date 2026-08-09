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


def test_disclosure_requires_a_text_media_type() -> None:
    with pytest.raises(ValueError, match="text/\\* C2PA format-string"):
        Disclosure(media_type="image/jpeg", model_type=ModelType.GENERIC)


def test_disclosure_requires_a_model_type() -> None:
    """18.28.2: modelType is the assertion's only required field."""
    with pytest.raises(ValueError, match="model_type must not be empty"):
        Disclosure(media_type="text/plain", model_type="")


@pytest.mark.parametrize(
    "media_type",
    ["text/plain", "text/csv", "text/tab-separated-values"],
)
def test_unstructured_text_media_types_are_accepted(media_type: str) -> None:
    disclosure = Disclosure(media_type=media_type, model_type=ModelType.GENERIC)
    assert disclosure.media_type == media_type


@pytest.mark.parametrize("media_type", ["text/", "text/plain; charset=utf-8", "TEXT/plain"])
def test_media_type_must_follow_the_c2pa_format_string(media_type: str) -> None:
    with pytest.raises(ValueError, match="C2PA format-string"):
        Disclosure(media_type=media_type, model_type=ModelType.GENERIC)


@pytest.mark.parametrize(
    ("media_type", "annex"),
    [("text/html", "A.7"), ("text/markdown", "A.9")],
)
def test_a8_refuses_formats_with_another_c2pa_carrier(media_type: str, annex: str) -> None:
    with pytest.raises(ValueError, match=annex):
        Disclosure(media_type=media_type, model_type=ModelType.GENERIC)


def test_disclosure_is_frozen_and_carries_no_identifying_fields() -> None:
    """Our marking policy forbids tenant, agent, account, user, author or prompt content.

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

    The set below is a literal subset of Table 12 rather than a value derived from the
    package constants. It covers the generic value and every public convenience member.
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

    # The convenience members are a subset; the exported full vocabulary is exact.
    assert set(MODEL_TYPES) == table_12
