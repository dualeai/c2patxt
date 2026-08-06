# COSE_Sign1 vectors

Source: <https://github.com/cose-wg/Examples> — the COSE working group's own examples.

**Licence: Unlicense (public domain).** No attribution obligation, so these are
freely vendorable.

Retrieved 2026-08-05, at commit `53c9d634333bb4f529d78f5980fffa2667ee2c12`.
`sign1-tests/` last changed 2017-04-06 and `eddsa-examples/` 2020-05-20; stale, but RFC 9052
`COSE_Sign1` is stable and these predate no relevant change.

## What they cover, and what they do not

`eddsa-01` and `eddsa-sig-01` use **Ed25519 with `alg` = -8**, the only signature
algorithm C2PA 2.4 §13.2.1 permits ("Ed25519 instance only. No other EdDSA instances
are allowed"). `eddsa-sig-02` is **Ed448**, and is here precisely because 13.2.1
forbids it — see `tests/test_external_vectors.py`.

`sign-pass-*` and `sign-fail-*` — upstream's `sign1-tests/`, flattened here — add three
passing and six **failing** cases, all **ES256 over P-256**. That
algorithm is outside our narrowing, so they are useless as signature oracles and
valuable as `Sig_structure` oracles, which is algorithm-independent. `sign-fail-05`
does not exist upstream; the gap is theirs, not a vendoring error.

Eleven of the twelve carry `intermediates.ToBeSign_hex` — the serialized
`Sig_structure`. `eddsa-01` does not: it is a multi-signer `COSE_Sign`, not a
`COSE_Sign1`, and carries `intermediates.signers` instead.
That is the single most valuable field here: it lets us assert our
`["Signature1", protected, external_aad, payload]` assembly against an
independently produced encoding rather than against ourselves.

**All twelve are read.** Ten reproduce byte for byte. `sign-pass-02` is the only one
carrying a non-empty `external_aad`, which §13.2.3 forbids, so it is asserted as a
vector we must FAIL to reproduce — and to fail in that slot alone. `eddsa-01` is
asserted to be the five-element `COSE_Sign` shape we never emit.
`tests/test_cose.py::test_no_vendored_sig_structure_vector_goes_unread` holds the
accounting, so a newly downloaded file cannot go unread.

They exercise the **COSE layer**, not C2PA's narrowing of it. These remain ours to
test: zero-length `external_aad` (§13.2.3), detached payload as `nil`/`0xf6`
(§13.2.2), `x5chain` in the protected bucket only (§14.5), and exactly one identity
credential across both buckets (§14.2).

Refresh with `make download-vectors`.
