"""
Signing inputs: what the caller supplies to :func:`embed`.

``embed`` takes a signer and a disclosure rather than a pre-built manifest. That is
forced by the hard binding: the ``c2pa.hash.data`` exclusion range names the
wrapper's byte span, whose length depends on the manifest length, which contains the
exclusion range. With the SDK owning construction the circularity is internal and
nothing is patched after signing.

It has a second, better consequence. This project's own marking policy forbids any
tenant, agent, account, end-user, author, prompt or conversation content in the
manifest, on three independent legal grounds. Because the caller supplies a closed ``Disclosure`` rather
than arbitrary assertions, that legal constraint becomes a type-system constraint.
There is deliberately no generic extra-assertions escape hatch; adding one is a
decision with its own review, not a keyword argument.

WHY A DATACLASS AND NOT A CALLABLE PROTOCOL
-------------------------------------------
A bytes-in/signature-out callable, letting the private key live in an HSM or KMS, is
the obvious alternative. No such deployment exists: the platform this was built for
has the router signing locally from a Kubernetes secret, and 'Credential custody' is explicit that the
private key reaches exactly one service so marking adds no network call. A Protocol
needs either multiple concrete production implementations or a dependency that
genuinely cannot run in tests; neither holds. Adding the seam later is a signposted
change at 0.x, which is the reason the version is 0.x.
"""

from __future__ import annotations

import dataclasses
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, ExtendedKeyUsage, ExtensionNotFound
from cryptography.x509.oid import ObjectIdentifier

# At module scope, not inside __post_init__. It was local, justified by "trust.py
# imports this module for C2PA_CLAIM_SIGNING_EKU, and a top-level import would be
# circular" -- trust.py imports nothing from here; the cycle ended when the
# required-EKU check was removed, and the justification outlived it.
from c2patxt.trust import check_claim_signing_profile

__all__ = [
    "C2PA_CLAIM_SIGNING_EKU",
    "COSE_ALG_EDDSA",
    "MODEL_TYPES",
    "Disclosure",
    "ModelType",
    "Signer",
    "has_claim_signing_eku",
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
#: A REFERENCE LIST FOR PRODUCERS, not a validator gate -- and it was the latter until
#: 18.28.4's CDDL was read past the prose above it. That CDDL extends the socket,
#: ``$model-type-choice /= tstr``, so Table 12 is open and the read side accepts any
#: non-empty string; see ``_verify._disclosure_status`` and docs/deviations.md.
#:
#: TWENTY-FOUR, WHERE :class:`ModelType` NAMES FIVE. The five are the ones we expect a
#: caller of this package to want; the twenty-four are what the specification offers,
#: kept here so a caller choosing a ``modelType`` can see the whole vocabulary without
#: opening the specification. It is asserted equal to Table 12 verbatim in
#: ``tests/test_signing.py`` -- a vendored copy of somebody else's table is only honest
#: if something compares it to the table.
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


class ModelType:
    """``c2pa.ai-disclosure`` model types, from C2PA Table 12 (18.21.1, referenced by 18.28.2).

    ``modelType`` is the ONLY required field of the assertion, and 18.28.2 says its
    value "is an enumeration of AI model types defined in Table 12".

    TABLE 12 ENUMERATES MODEL *FORMATS*, NOT GENERATION MODES. It is a list of
    serialization frameworks -- caffe, onnx, pytorch, tensorflow, and twenty more --
    headed by the generic ``c2pa.types.model``. There is no "generative" or
    "transformative" member, and there was never going to be: those describe what a
    model DID, not what it is stored as.

    Earlier releases emitted ``c2pa.types.model.generative`` and
    ``c2pa.types.model.transformative``. Neither string appears anywhere in the
    specification. They were removed rather than kept as an entity-specific namespace
    (6.2.2 would have permitted ``ai.duale.types.model.generative``) because the fact
    they were trying to express is already carried, correctly and by a field designed
    for it: the ``c2pa.created`` action's ``digitalSourceType`` of
    ``trainedAlgorithmicMedia``. Saying it twice, once in a field that cannot express
    it, is worse than saying it once.

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
        media_type: the media type of the text being marked. Validated as ``text/*``,
            and WRITTEN INTO THE MANIFEST as ``dc:format``; see the note below. A caller who believes this
            field is not recorded may put something in it they would not ship in
            signed bytes.
        model_type: ``c2pa.ai-disclosure`` ``modelType``, the assertion's only
            required field (18.28.2).
        model_name: optional human-readable model name.
        model_identifier: optional stable identifier, e.g. a URI or PURL.

    ``media_type`` IS WRITTEN INTO THE MANIFEST, as ``dc:format`` inside a
    ``c2pa.metadata`` assertion (C2PA 18.17). It is not in the CLAIM: the spec says in
    so many words that "the c2pa.claim has a dc:format field which is no longer
    present in c2pa.claim.v2", so 18.17's metadata assertion is its only home in a v2
    manifest. Being an assertion, it is covered by a hashed-URI link and therefore
    authenticated.

    That is not decoration. The C2PA Text Asset Conformance Rubric v0.1.0's second
    check, ``text:is_text_asset``, is "Active manifest declares a supported text MIME
    type in dc:format" -- so a manifest without it fails the only formal conformance
    instrument that exists for text. See ``manifest.py``'s ``_metadata_assertion``.

    It ALSO refuses a non-text media type at construction, which is the applicability
    gate A.8 itself never specifies.

    A note on ``media_type``: any ``text/*`` value is accepted. The marking-scope rule
    -- which formats get marked at all -- lives in the platform router, not here.
    Two things are worth knowing anyway. The C2PA text conformance
    rubric v0.1.0, not the specification, is the only authority partitioning media
    types: ``text/plain``, ``text/csv`` and ``text/tab-separated-values`` to A.8;
    ``text/markdown`` and the XML family to A.9; ``text/html`` to A.7. A.8 itself
    names no media type at all. That router deliberately marks ``text/markdown`` under
    A.8 rather than A.9, because A.9's visible delimiters would break the rendering
    invariant. And ``text/html`` is A.7 territory, for which this carrier is simply
    the wrong mechanism -- nothing here stops you, but the result is non-conformant.

    Raises:
        ValueError: ``media_type`` is not a ``text/*`` type, or ``model_type`` is empty.

            THE EMPTY-``model_type`` CHECK IS NOW THE ONLY PLACE THIS IS CAUGHT ON THE
            PRODUCER SIDE, and it was undocumented. The validator no longer tests
            membership in Table 12 -- 18.28.4's CDDL socket admits any string -- so this
            constructor is what stops a mark shipping with the one field it exists to
            carry left blank. A reader who does not know it raises here will find out
            from a traceback.
    """

    media_type: str
    model_type: str
    model_name: str | None = None
    model_identifier: str | None = None

    def __post_init__(self) -> None:
        if not self.media_type.startswith("text/"):
            msg = f"dc:format must be a text/* media type, got {self.media_type!r}"
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
        certificates: leaf first, then every intermediate. The trust anchor is
            EXCLUDED -- RFC 9360 and C2PA 14.5 both say the root should not appear
            in ``x5chain``.

    Everything below is checked at construction rather than at signing time, so a
    misconfigured deployment fails at startup instead of on a request.

    Raises:
        ValueError: the leaf's key is not Ed25519, the private key does not match the
            leaf, or ``certificates`` is empty.
        ProfileError: the leaf fails the C2PA 14.5.1.1 claim-signing profile. A subclass
            of both ``C2paTextError`` and ``ValueError``, so either catch works. Pass
            ``allow_nonconformant=True`` to hold a development certificate instead.

    THE VALIDITY PERIOD IS THE EXCEPTION, and deliberately so. It is the one property
    that changes without anyone touching the deployment, so a check at construction would
    pass and then go stale in a service that holds one ``Signer`` for weeks. It is
    checked in :func:`embed` instead, against ``EmbedContext.when``, so a credential
    outside its window refuses at the moment it would produce a mark that is invalid the
    moment it is made.
    """

    private_key: Ed25519PrivateKey
    certificates: tuple[Certificate, ...]

    allow_nonconformant: bool = False
    """Skip the 14.5.1.1 claim-signing profile check on the leaf.

    Exists ONLY so a test can build the credentials a verifier must reject. Setting
    it in production produces marks that every conforming verifier -- including ours
    -- rejects as ``signingCredential.invalid``, after the bytes have shipped.
    """

    def __post_init__(self) -> None:
        if not self.certificates:
            msg = "Signer.certificates must contain at least the leaf certificate, leaf first (x5chain, 14.2)"
            raise ValueError(msg)

        leaf_key = self.certificates[0].public_key()

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

        # THE PRODUCER MUST APPLY THE SAME PROFILE THE VERIFIER DOES. Without this,
        # embed() happily signs with a certificate our own verify() hard-rejects, and
        # the only way to find out is to verify your own output -- which nobody does.
        # An ordinary self-signed certificate built the natural way with `cryptography`
        # has cA=TRUE and no EKU, so this is the DEFAULT mistake, not an exotic one.
        # AlreadyMarkedError's docstring already argues the principle: a failure that
        # surfaces only at the consumer, in someone else's system, is the expensive
        # kind. Signed bytes cannot be recalled once a document leaves the building.
        #
        if not self.allow_nonconformant:
            check_claim_signing_profile(self.certificates[0])

    @property
    def leaf(self) -> Certificate:
        """The signing certificate."""
        return self.certificates[0]

    def sign(self, message: bytes) -> bytes:
        """Sign ``message``, producing a 64-byte Ed25519 signature.

        Deterministic by construction: RFC 8032 5.1.6 derives the nonce as
        ``SHA-512(dom2(F,C) || prefix || PH(M))`` with no randomness source, and COSE
        EdDSA is pure EdDSA only. That is what makes a byte-stable re-embed possible
        at all; every other source of instability is in manifest construction rather
        than here.
        """
        return self.private_key.sign(message)

    def x5chain(self) -> list[bytes]:
        """DER-encoded certificates, leaf first, for the ``x5chain`` header.

        C2PA 14.5 requires all intermediates to be present and the header to sit in
        the PROTECTED bucket, with integer label 33 (RFC 9360). The root is excluded.
        """
        return [certificate.public_bytes(Encoding.DER) for certificate in self.certificates]


def has_claim_signing_eku(certificate: Certificate) -> bool:
    """True if ``certificate`` carries ``c2pa-kp-claimSigning`` (14.4.1).

    Reported rather than raised: ``Signer.__post_init__`` already applies the full
    14.5.1.1 profile at construction -- "THE PRODUCER MUST APPLY THE SAME PROFILE THE
    VERIFIER DOES", as it says -- so this predicate exists for a caller who wants to ASK
    rather than be refused. Holding a non-conformant development certificate needs
    ``allow_nonconformant=True``. Note that a default ``openssl req -x509`` certificate
    asserts ``cA`` and carries no EKU at all, which yields
    ``signingCredential.invalid`` -- a hard reject -- rather than the expected
    ``signingCredential.untrusted``.
    """
    try:
        usages = certificate.extensions.get_extension_for_class(ExtendedKeyUsage).value
    except ExtensionNotFound:
        return False
    return C2PA_CLAIM_SIGNING_EKU in usages
