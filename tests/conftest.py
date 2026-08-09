"""Shared fixtures.

Certificates are generated here rather than committed, so the suite carries no key
material and nothing expires. Generation is cheap for Ed25519.
"""

from __future__ import annotations

import dataclasses
import datetime
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from c2patxt import EmbedContext, embed
from c2patxt.signing import C2PA_CLAIM_SIGNING_EKU, Disclosure, ModelType, Signer

# Fixed so certificates are byte-stable across runs; nothing here is time-sensitive.
_NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_NOT_AFTER = datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc)


class RecordingTrustEvaluator:
    """Fixed-answer test double, not a path validator; snapshot each handoff as DER."""

    def __init__(self, *, trusted: bool) -> None:
        self.trusted = trusted
        self.calls: list[tuple[tuple[bytes, ...], tuple[bytes, ...]]] = []

    def is_trusted(self, chain: list[x509.Certificate], anchors: list[x509.Certificate]) -> bool:
        self.calls.append(
            (
                tuple(certificate.public_bytes(Encoding.DER) for certificate in chain),
                tuple(certificate.public_bytes(Encoding.DER) for certificate in anchors),
            )
        )
        return self.trusted


def _name(common_name: str, organization_name: str | None = None) -> x509.Name:
    attributes: list[x509.NameAttribute[str]] = []
    if organization_name is not None:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name))
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attributes)


def build_certificate(
    private_key: CertificateIssuerPrivateKeyTypes,
    *,
    common_name: str = "c2patxt test leaf",
    conformant: bool = True,
    not_before: datetime.datetime = _NOT_BEFORE,
    not_after: datetime.datetime = _NOT_AFTER,
    key_usage: bool = True,
    basic_constraints: bool = True,
    digital_signature: bool = True,
    key_cert_sign: bool = False,
    extra_ekus: tuple[str, ...] = (),
    extended_key_usage: tuple[str, ...] | None = None,
    issuer_name: str | None = None,
    authority_key_identifier: bool = False,
    organization_name: str | None = None,
) -> x509.Certificate:
    """Build a self-signed Ed25519 certificate.

    With ``conformant=True`` it satisfies the C2PA 14.5.1.1 rules the validator enforces:
    ``cA`` NOT asserted, ``keyCertSign`` NOT asserted, ``digitalSignature`` ASSERTED, and
    a present, non-empty EKU. It also carries ``c2pa-kp-claimSigning`` -- which the
    profile does NOT require -- a reader debugging a rejected certificate should
    look at ``digitalSignature``, not at this.

    With ``conformant=False`` it is what ``openssl req -x509`` produces by default --
    ``cA`` asserted and no EKU at all. That combination yields
    ``signingCredential.invalid``, a hard reject, rather than the
    ``signingCredential.untrusted`` a self-signed credential is supposed to produce.

    The remaining keywords each vary ONE property of an otherwise conformant leaf, so
    a 14.5.1.1 test names the rule it violates and nothing else:

    ``key_usage=False``
        omit the Key Usage extension entirely.
    ``basic_constraints=False``
        omit Basic Constraints, which 14.5.1.1 permits: absent is one of the two ways
        of not being a CA, and the EKU requirement is written to cover exactly that.
    ``extended_key_usage=()``
        emit an EKU extension with no OIDs in it.
    ``digital_signature=False``
        keep Key Usage but assert ``contentCommitment`` in place of
        ``digitalSignature``, so the extension is present and still unauthorized.
    ``key_cert_sign=True``
        assert ``keyCertSign`` alongside ``digitalSignature``: a leaf that may also
        issue certificates.
    ``extra_ekus``
        append further EKU OIDs, for the purpose-exclusivity rules. Ignored when
        ``extended_key_usage`` is given, which replaces the list outright.
    ``issuer_name``
        issue under a DIFFERENT name, making the certificate no longer self-signed and
        therefore obliged to carry an Authority Key Identifier. The key is unchanged,
        so the signature still verifies -- the point is the profile check, not a chain.
    ``authority_key_identifier=True``
        add an AKI derived from the signing key. Issued certificates require it;
        self-signed certificates may carry it.
    ``organization_name``
        add an Organization to the subject and, when self-signed, the issuer.
    """
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name, organization_name))
        .issuer_name(_name(issuer_name) if issuer_name is not None else _name(common_name, organization_name))
        .public_key(private_key.public_key())
        # PINNED, not random. x509.random_serial_number() made every test certificate
        # and signature differ between runs, so exact wire assertions described a new
        # fixture on every invocation. A suite that claims byte stability cannot seed
        # itself from an RNG.
        #
        # Uniqueness does not matter here: nothing in this suite builds a CA, and no
        # two certificates are ever compared by serial.
        .serial_number(0xC2A7E47_C0FFEE)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # conformant=False takes the CA branch below and reaches none of the knobs, so a
    # caller combining them is asking for something this builder cannot make. Silently
    # ignoring an argument is how a test comes to assert something about a certificate it
    # did not build.
    varied = (
        not key_usage,
        not basic_constraints,
        not digital_signature,
        key_cert_sign,
        extra_ekus,
        extended_key_usage is not None,
    )
    if not conformant and any(varied):
        msg = "conformant=False ignores the profile knobs; build a conformant certificate and vary it instead"
        raise ValueError(msg)

    if conformant:
        ekus = [C2PA_CLAIM_SIGNING_EKU.dotted_string, *extra_ekus] if extended_key_usage is None else extended_key_usage
        if basic_constraints:
            builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid) for oid in ekus]), critical=False
        )
        # Added SECOND so key_usage=False simply skips it. CertificateBuilder is
        # append-only, so "absent" has to mean "never added" -- and 14.5.1.1
        # distinguishes absent from present-but-wrong, so the case must be real.
        if key_usage:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=digital_signature,
                    content_commitment=not digital_signature,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=key_cert_sign,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        if authority_key_identifier:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),  # pyright: ignore[reportArgumentType] -- Ed25519 is one of the accepted key types
                critical=False,
            )
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    # Edwards certificate signatures take no separately selected hash in cryptography;
    # the other fixture keys use SHA-256.
    algorithm = None if isinstance(private_key, (Ed25519PrivateKey, Ed448PrivateKey)) else SHA256()
    return builder.sign(private_key, algorithm)


@pytest.fixture(scope="session")
def signing_key() -> Ed25519PrivateKey:
    """A deterministic Ed25519 private key.

    Seeded from a fixed 32-byte value so signatures are reproducible across runs,
    which is what makes byte-stability assertions meaningful.
    """
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    """The signer every end-to-end test marks with.

    Here rather than in one test module because any public producer test needs it.
    """
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


@pytest.fixture(scope="session")
def signing_certificate(signing_key: Ed25519PrivateKey) -> x509.Certificate:
    """A profile-conformant self-signed Ed25519 certificate."""
    return build_certificate(signing_key)


DISCLOSURE = Disclosure(
    media_type="text/plain",
    model_type=ModelType.GENERIC,
    model_name="test-model",
)

#: Fixed so the whole suite is byte-reproducible; nothing here is time-sensitive.
WHEN = datetime.datetime(2026, 6, 1, 12, 0, tzinfo=datetime.timezone.utc)
PINNED_EMBED_CONTEXT = EmbedContext(
    manifest_uuid=uuid.UUID("00000000-0000-4000-8000-000000000007"),
    instance_id="xmp:iid:1",
    when=WHEN,
)


class FloatingTimezone(datetime.tzinfo):
    """A ``tzinfo`` object that still makes a datetime naive by Python's rules."""

    def utcoffset(self, dt: datetime.datetime | None) -> None:
        del dt


def mark(text: str, signer: Signer, *, when: datetime.datetime = WHEN) -> str:
    """Produce a byte-stable fixture through the public producer."""
    context = dataclasses.replace(PINNED_EMBED_CONTEXT, when=when)
    return embed(text, signer, DISCLOSURE, context=context)
