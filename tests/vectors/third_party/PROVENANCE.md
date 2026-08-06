# Third-party A.8 implementation vectors

Vectors published by the two other public A.8 implementations, vendored so our codec
can be checked against numbers we did not produce.

**These carry attribution obligations.** Unlike the rest of this directory, they are
not CC0 and not public domain. The notices below travel with the files; reproducing
them is the condition of vendoring.

Retrieved 2026-08-05, re-verified byte-identical to upstream 2026-08-06.

## `encypher-golden-vectors.json`

Source: <https://github.com/encypherai/c2pa-text> — `golden/vectors.json`.

**Licence: MIT.** Attribution required.

Upstream `main` at `ad4eaee3705ea5edb610ab37041be496d012e583`. The file itself last
changed in `7a80f0eac631` (2026-05-29, "Release 2.0.0"), which is the content vendored
here — a commit rather than a push date, because a push to an unrelated path cannot
tell a future maintainer whether these vectors moved.

Fifteen records. Two are A.8 unstructured text (`ascii_small`, `unicode_all_bytes`) and
are what we assert against; the other thirteen are A.7 HTML and A.9 structured-text
vectors, which this package does not implement. They are vendored whole rather than
filtered so the file stays diffable against upstream.

## `writerslogic-a8-variation-selector.json`

Source: <https://github.com/writerslogic/c2pa-text-binding> —
`vectors/a8-variation-selector.json`.

**Licence: Apache-2.0.** Attribution and notice required.

Upstream `main` at `2466dbae4f6044f10c953544608807123ac84b7b`, latest release `v0.3.0`
(2026-08-03). The file last changed in `ac48522b6a23` (2026-07-14).

Six top-level keys. `byteToVariationSelector` and `wrapperVector` are asserted;
`wrapper`, `magicSequence`, and the remainder are not yet read.

## Refreshing

`make download-vectors-third-party`, then `make checksums`. Read the diff: these are
other people's numbers, and a silent change on their side is exactly what the checksum
manifest exists to surface.
