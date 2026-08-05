# COSE_Sign1 vectors

Source: <https://github.com/cose-wg/Examples> — the COSE working group's own examples.

**Licence: Unlicense (public domain).** No attribution obligation, so these are
freely vendorable.

Retrieved 2026-08-05. Upstream last pushed 2024-03-13; stale, but RFC 9052
`COSE_Sign1` is stable and these predate no relevant change.

## What they cover, and what they do not

`eddsa-*` use **Ed25519 with `alg` = -8**, which is the only signature algorithm
C2PA 2.4 §13.2.1 permits ("Ed25519 instance only. No other EdDSA instances are
allowed"). `sign1-*` add three passing and six **failing** cases.

Each file carries `intermediates.ToBeSign_hex` — the serialized `Sig_structure`.
That is the single most valuable field here: it lets us assert our
`["Signature1", protected, external_aad, payload]` assembly against an
independently produced encoding rather than against ourselves.

They exercise the **COSE layer**, not C2PA's narrowing of it. These remain ours to
test: zero-length `external_aad` (§13.2.3), detached payload as `nil`/`0xf6`
(§13.2.2), `x5chain` in the protected bucket only (§14.5), and exactly one identity
credential across both buckets (§14.2).

Refresh with `make download-vectors`.
