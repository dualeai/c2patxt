"""Discriminating tests for C2PA and ISO protocol edges.

Parser fixtures are built by hand from the ISO field layout. The producer-padding
test instead drives the public encoder because emitted bytes are its subject.
"""

from __future__ import annotations

import uuid as uuid_module

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from c2patxt import EmbedContext, _cose, _jumbf, embed, extract
from c2patxt._jumbf import parse_superbox
from c2patxt._selectors import selector_to_byte
from c2patxt.constants import HEADER_SIZE, MAGIC, MARKER
from c2patxt.signing import Signer
from tests.conftest import DISCLOSURE, WHEN

UUID = _jumbf.content_type_uuid(b"cbor")

_PINNED = EmbedContext(
    manifest_uuid=uuid_module.UUID("00000000-0000-4000-8000-000000000007"),
    instance_id="xmp:iid:pinned",
    when=WHEN,
)


@pytest.fixture(scope="session")
def signer(signing_key: Ed25519PrivateKey, signing_certificate: x509.Certificate) -> Signer:
    return Signer(private_key=signing_key, certificates=(signing_certificate,))


def _description(toggles: int, tail: bytes) -> bytes:
    """Hand-build a jumd box: uuid(16) | toggles(1) | fields, per ISO 19566-5 A.3."""
    payload = UUID + bytes([toggles]) + tail
    return (8 + len(payload)).to_bytes(4, "big") + b"jumd" + payload


#: A minimal content box. A superbox must carry at least one, so every fixture here
#: needs one even when the test is only about the description box.
_CONTENT = (8 + 1).to_bytes(4, "big") + b"cbor" + b"\xf6"


def _superbox(description: bytes, content: bytes = _CONTENT) -> bytes:
    body = description + content
    return (8 + len(body)).to_bytes(4, "big") + b"jumb" + body


# --------------------------------------------------------------------------------
# 1. Description-box label bit
# --------------------------------------------------------------------------------


def test_a_label_toggle_alone_is_enough_to_read_a_label() -> None:
    """ISO 19566-5 gates the label on 0x02; 0x01 is Requestable and independent."""
    box, _ = parse_superbox(_superbox(_description(0x02, b"a label\x00")))

    assert box.description.label == "a label"
    assert box.description.requestable is False


def test_an_id_without_a_label_parses_as_id_present() -> None:
    """ISO 19566-5 assigns 0x04 to ID independently of the 0x02 label bit.

    An ID-only box distinguishes the assignment from the common ID-plus-label case.
    """
    box, _ = parse_superbox(_superbox(_description(0x04, (7).to_bytes(4, "big"))))

    assert box.description.box_id == 7
    assert box.description.label is None


def test_our_padding_uses_the_c2pa_unprotected_cose_header(signer: Signer) -> None:
    """C2PA 10.4.2 and 10.4.4 put mutable zero padding in unprotected COSE.

    The selector run ends at ``manifestLength``; 18.5.2's signed data-hash pad stays
    zero-filled, and size-control bytes live in the COSE unprotected map.

    Unlike the hand-built parser cases above, this drives the encoder because the
    requirement concerns the bytes it emits.
    """
    marked = embed("Hello world.", signer, DISCLOSURE, context=_PINNED)
    store = extract(marked)
    assert store is not None

    wrapper = marked[marked.index(MARKER) :]
    body = bytes(selector_to_byte(ord(char)) or 0 for char in wrapper[len(MARKER) :])
    declared = int.from_bytes(body[len(MAGIC) + 1 : len(MAGIC) + 1 + 4], "big")

    # header is magic(8) + version(1) + manifestLength(4); nothing may follow the store
    assert declared == len(store.raw), f"declared {declared} B, store is {len(store.raw)} B"
    assert len(body) == HEADER_SIZE + declared, (
        f"{len(body) - HEADER_SIZE - declared} B of selector run past the manifest"
    )

    # 18.5.2's signed data-hash pad stays mandatory, empty and zero-filled. The size
    # control comes from 10.4.2's zero-filled unprotected COSE header; 10.4.4 permits
    # changing its length after signing.
    hash_data = store.hash_data
    assert hash_data is not None
    assert hash_data["pad"] == b""
    cose = _cose.parse(store.signature)
    pad = cose.unprotected["pad"]
    assert isinstance(pad, bytes)
    assert pad
    assert not any(pad)
