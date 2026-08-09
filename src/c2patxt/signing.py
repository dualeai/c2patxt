"""
Signing inputs: what the caller supplies to :func:`embed`.

``embed`` takes a signer and a disclosure rather than a pre-built manifest. That is
forced by the hard binding: the ``c2pa.hash.data`` exclusion range names the
wrapper's byte span, whose length depends on the manifest length, which contains the
exclusion range. The producer therefore owns construction. It builds and signs once
for each candidate exclusion length, then varies only unprotected COSE padding within
that candidate.

The closed :class:`Disclosure` keeps the producer schema explicit. There is no generic
extra-assertions input.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate
from cryptography.x509.oid import ObjectIdentifier

from c2patxt.trust import CERTIFICATE_PARSE_ERRORS, ProfileError, check_certificate_chain_profile

__all__ = [
    "C2PA_CLAIM_SIGNING_EKU",
    "COSE_ALG_EDDSA",
    "MODEL_TYPES",
    "Disclosure",
    "ModelType",
    "Signer",
]

COSE_ALG_EDDSA = -8
"""COSE algorithm identifier for EdDSA (RFC 9053 2.2).

From the IANA COSE Algorithms registry. The C2PA specification never states the
numeric value, only the name, so citing IANA rather than C2PA here is deliberate.
"""

C2PA_CLAIM_SIGNING_EKU = ObjectIdentifier("1.3.6.1.4.1.62558.2.1")
"""``c2pa-kp-claimSigning`` (C2PA 14.4.1)."""


#: Every value C2PA Table 12 (18.21.1, referenced by 18.28.2) admits for ``modelType``, verbatim.
#:
#: A reference list for producers, not a validator gate. 18.28.4 extends the socket
#: with ``$model-type-choice /= tstr``, so Table 12 is open.
#:
#: :class:`ModelType` exposes a short convenience subset; this set retains Table 12's
#: full producer vocabulary.
MODEL_TYPES: Final = frozenset(
    {
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
)


_FORMAT_STRING = re.compile(r"\w+/[-+.\w]+", flags=re.ASCII)
_OTHER_C2PA_TEXT_CARRIERS: Final = frozenset({"text/html", "text/markdown"})
_CHAIN_LINK_ERRORS = (InvalidSignature, *CERTIFICATE_PARSE_ERRORS)


def _check_chain_link(child: Certificate, parent: Certificate, child_index: int) -> None:
    try:
        child.verify_directly_issued_by(parent)
    except _CHAIN_LINK_ERRORS as exc:
        msg = f"x5chain[{child_index}] is not directly issued by x5chain[{child_index + 1}]: {exc}"
        raise ValueError(msg) from exc


class ModelType:
    """``c2pa.ai-disclosure`` model types, from C2PA Table 12 (18.21.1, referenced by 18.28.2).

    ``modelType`` is the ONLY required field of the assertion, and 18.28.2 says its
    value "is an enumeration of AI model types defined in Table 12".

    TABLE 12 ENUMERATES MODEL *FORMATS*, NOT GENERATION MODES. It is a list of
    serialization frameworks -- caffe, onnx, pytorch, tensorflow, and twenty more --
    headed by the generic ``c2pa.types.model``. Generation mode belongs in the
    ``c2pa.created`` action's ``digitalSourceType`` field, not in ``modelType``.

    Use :data:`GENERIC` unless you know the serialization format of the model that
    produced the text, which for a hosted API you generally do not.
    """

    #: "AI/ML model which is not described by any other model type" -- Table 12's own
    #: description of the generic value, quoted verbatim. The right answer
    #: when the format is unknown, which for text generation it usually is.
    GENERIC = "c2pa.types.model"

    HUGGINGFACE_TRANSFORMERS = "c2pa.types.model.huggingface.transformers"
    ONNX = "c2pa.types.model.onnx"
    PYTORCH = "c2pa.types.model.pytorch"
    TENSORFLOW = "c2pa.types.model.tensorflow"


@dataclasses.dataclass(frozen=True, slots=True)
class Disclosure:
    """The facts the caller contributes to the manifest, and nothing else.

    Everything else is supplied by this package: the ``c2pa.created`` action with
    ``digitalSourceType`` of ``trainedAlgorithmicMedia``, and the ``c2pa.hash.data``
    assertion.

    Attributes:
        media_type: the media type of the unstructured text being marked. It is
            written into the manifest as ``dc:format`` and authenticated through the
            assertion's hashed-URI link.
        model_type: ``c2pa.ai-disclosure`` ``modelType``, the assertion's only
            required field (18.28.2).
        model_name: optional human-readable model name.
        model_identifier: optional stable identifier, e.g. a URI or PURL.

    The producer records ``dc:format`` in a ``c2pa.metadata`` assertion (18.17).
    Annex A.8 applies to unstructured text when no other carrier is feasible. HTML
    and Markdown are refused because C2PA assigns them to A.7 and A.9 respectively.
    Callers remain responsible for choosing A.8 only for other unstructured formats.

    Raises:
        ValueError: ``media_type`` is not a C2PA ``format-string`` for unstructured
            text, or ``model_type`` is empty.
    """

    media_type: str
    model_type: str
    model_name: str | None = None
    model_identifier: str | None = None

    def __post_init__(self) -> None:
        if _FORMAT_STRING.fullmatch(self.media_type) is None or not self.media_type.startswith("text/"):
            msg = f"dc:format must be a text/* C2PA format-string without parameters, got {self.media_type!r}"
            raise ValueError(msg)
        if self.media_type in _OTHER_C2PA_TEXT_CARRIERS:
            annex = "A.7" if self.media_type == "text/html" else "A.9"
            msg = f"{self.media_type} uses the C2PA Annex {annex} carrier, not the Annex A.8 carrier"
            raise ValueError(msg)
        if not self.model_type:
            msg = (
                "model_type must not be empty; use ModelType.GENERIC or another "
                "c2pa.types.model.* string (c2pa.ai-disclosure, 18.28.2)"
            )
            raise ValueError(msg)


@dataclasses.dataclass(frozen=True, slots=True)
class Signer:
    """An Ed25519 private key and the certificate chain that vouches for it.

    Attributes:
        private_key: the signing key.
        certificates: leaf first, then the certificate that issued it, and so on.
            C2PA 14.5 says a separately configured trust anchor should be omitted;
            every certificate supplied here is emitted in ``x5chain``.

    Everything below is checked at construction rather than at signing time, so a
    misconfigured deployment fails at startup instead of on a request.

    Raises:
        ValueError: the leaf's key is not Ed25519, the private key does not match the
            leaf, or ``certificates`` is empty.
        ProfileError: a carried certificate fails the C2PA 14.5.1.1 profile. A subclass
            of both ``C2paTextError`` and ``ValueError``, so either catch works. Pass
            ``allow_nonconformant=True`` to hold a development certificate instead.

    THE VALIDITY PERIOD IS THE EXCEPTION. It changes while a service keeps one
    ``Signer``, so :func:`embed` checks every certificate against
    ``EmbedContext.when`` on each call. The default is the current time; callers that
    pin a historical value are asking for a deterministic replay, not a wall-clock
    production-time check.
    """

    private_key: Ed25519PrivateKey
    certificates: tuple[Certificate, ...]

    allow_nonconformant: bool = False
    """Skip the 14.5.1.1 profile check on the carried certificate chain.

    Exists for negative tests and callers that deliberately carry a nonconforming
    chain. The flag does not change the certificates or wire bytes; a conforming chain
    remains conforming, while a nonconforming one may be rejected by validators.
    """

    def __post_init__(self) -> None:
        if not self.certificates:
            msg = "Signer.certificates must contain at least the leaf certificate, leaf first (x5chain, 14.2)"
            raise ValueError(msg)

        # The opt-out permits a profile violation, not an unreadable signing key.
        try:
            leaf_key = self.certificates[0].public_key()
        except CERTIFICATE_PARSE_ERRORS as exc:
            msg = f"x5chain[0] leaf certificate could not be parsed: {exc}"
            raise ProfileError(msg) from exc

        # 13.2.1 scopes "Ed25519 instance only. No other EdDSA instances are allowed"
        # WITHIN EdDSA; its allowed list also carries ES256/384/512 and PS256/384/512, so
        # accepting Ed25519 alone is this package's restriction and the message says so.
        # Keys must be "on the edwards25519 elliptic curve". Ed448 shares the
        # COSE alg identifier -8, so checking the algorithm name alone is not enough
        # -- cose-wg's own eddsa-sig-02 vector is Ed448 and would otherwise pass.
        if not isinstance(leaf_key, Ed25519PublicKey):
            msg = (
                f"the leaf certificate holds a {type(leaf_key).__name__}; this package signs "
                "with Ed25519 only -- narrower than C2PA 13.2.1's allowed list, and within "
                "EdDSA the specification does permit no other instance"
            )
            raise ValueError(msg)

        # Verify the pairing in BOTH directions. The certificate profile in 14.5.1.1
        # constrains subjectPublicKeyInfo for id-ecPublicKey and RSA but has NO
        # parallel clause for id-Ed25519, so this check is ours to add.
        # No separate length check: the isinstance above already guarantees an
        # edwards25519 point, and Ed25519PublicKey.public_bytes_raw() is 32 bytes by
        # construction. A guard that cannot fire reads as a check and is not one.
        expected = leaf_key.public_bytes_raw()
        actual = self.private_key.public_key().public_bytes_raw()
        if expected != actual:
            msg = "the private key does not match the public key in the leaf certificate"
            raise ValueError(msg)

        # RFC 9360 2 orders x5chain as the end-entity certificate followed by the
        # certificate that signed it, and so on. Profile checks alone cannot establish
        # that relationship: two unrelated, individually conforming certificates have
        # valid extensions too.
        for child_index, (child, parent) in enumerate(zip(self.certificates, self.certificates[1:], strict=False)):
            _check_chain_link(child, parent, child_index)

        # This package applies its verifier profile by default. C2PA 13.2.5 says a
        # validator-capable generator SHOULD validate and MAY still sign; the explicit
        # allow_nonconformant option is that escape hatch for test and migration work.
        # Unreadable key material was already refused above and is not covered by it.
        if not self.allow_nonconformant:
            check_certificate_chain_profile(self.certificates)

    @property
    def leaf(self) -> Certificate:
        """The signing certificate."""
        return self.certificates[0]

    def sign(self, message: bytes) -> bytes:
        """Sign ``message``, producing a 64-byte Ed25519 signature.

        Ed25519 signing is deterministic under RFC 8032, and COSE uses Pure EdDSA.
        """
        return self.private_key.sign(message)

    def x5chain(self) -> list[bytes]:
        """DER-encoded certificates, leaf first, for the ``x5chain`` header.

        C2PA 14.5 requires all intermediates to be present and recommends omitting the
        trust anchor. This method serializes the supplied tuple unchanged; the caller
        is responsible for omitting an independently configured anchor.
        """
        return [certificate.public_bytes(Encoding.DER) for certificate in self.certificates]
