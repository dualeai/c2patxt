# Legacy producer fixture

`v0.1.2-manifest-store.b64` is the manifest store emitted by release tag `v0.1.2`
at commit `7a87f2ffc7004800647858708470c9767dd4091e`. It is not an external
interoperability vector. It holds one reader contract: producer changes must not make
text marked by an older c2patxt release unreadable.

The fixture was generated from public `embed()` with:

- text `Hello world.`;
- Ed25519 private bytes `00 01 ... 1f` and the deterministic certificate from that
  tag's `tests.conftest.build_certificate`;
- manifest UUID `00000000-0000-4000-8000-000000000001`;
- instance ID `xmp:iid:00000000-0000-4000-8000-000000000002`;
- UTC time `2026-06-01T12:00:00Z`;
- that tag's `tests.conftest.DISCLOSURE`.

Recreate it from a detached worktree at the tag, extract `store.raw` from the public
`embed()` result, and encode it with `base64.b64encode`. Do not regenerate it with the
current producer: that would erase the old input shape the test exists to read.
