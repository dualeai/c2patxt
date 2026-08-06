"""
Exception hierarchy.

Three channels, and the split is deliberate:

===================================  ==================================
Absence of a mark                    return value (``None`` / ``UNMARKED``)
A wrapper is present but unparseable **raises** ``MarkCorruptError``
A manifest parses but fails to verify a ``Verdict`` carrying status codes
===================================  ==================================

The third row is not a style preference. ``manifest.text.multipleWrappers`` is a
specification *failure code*, not an exception, and a bad signature must still hand
the manifest back so a caller can inspect which certificate signed it. Running
validation outcomes through both an exception channel and a result object is the
mistake sigstore-python made and then spent a major version undoing: it removed
``VerificationResult`` in 3.0.0 because it was "mostly just duplication over
existing error types", having sat alongside an exception channel that existed anyway.

Absence is never an exception. Most text on earth is unmarked, and a library that
raises on the common case is one people wrap in a bare ``except``.
"""

from __future__ import annotations

from c2patxt.status import StatusCode

__all__ = [
    "C2paTextError",
    "MarkCorruptError",
    "UnencodableTextError",
]


class C2paTextError(Exception):
    """Base class for every error that escapes a public entry point.

    "Escapes" is the operative word, and the promise was once written without it -- as
    "every error this package raises" -- while ``ProfileError`` and ``FixpointError``
    both sat outside. Both were brought in on 2026-08-05; ``tests/test_api_surface.py``
    now holds the claim.

    Three error types are raised INSIDE private modules and never reach a caller:
    ``CborDecodeError``, ``CoseError`` and ``JumbfError``, each translated at its
    boundary -- ``_extract`` turns the CBOR and JUMBF failures into ``MarkCorruptError``,
    ``_verify`` catches the COSE one. They stay outside the hierarchy because widening a
    public promise to cover types nobody can import would say less rather than more.

    Deriving from bare ``Exception`` rather than ``ValueError``, with the
    conventional builtin mixed into each leaf instead. That is json's shape
    (``JSONDecodeError(ValueError)``) and cbor2's (``CBORDecodeEOF(CBORDecodeError,
    EOFError)``). It is deliberately *not* cbor2's root, which derives from bare
    ``Exception`` alone and so escapes ``except ValueError`` entirely -- a wart
    integrators trip over.
    """


class MarkCorruptError(C2paTextError, ValueError):
    """A wrapper's magic number matched, but the structure is malformed.

    Catchable as ``C2paTextError`` and as ``ValueError``.

    Raised for two different kinds of fault, and ``code`` is what tells them apart.

    STRUCTURAL DAMAGE TO THE CARRIER -- a version field that is not 1, a
    ``manifestLength`` that overruns the decoded run, a selector run shorter than the
    13-byte header, an undecodable selector -- carries
    ``manifest.text.corruptedWrapper`` (15.12.1.3.2).

    A C2PA FAULT INSIDE AN INTACT WRAPPER carries the code its clause names:
    ``claim.missing``, ``claim.malformed``, ``claim.cbor.invalid``, ``claim.multiple``,
    ``claimSignature.missing``, ``assertion.cbor.invalid``, ``assertion.json.invalid``,
    ``assertion.missing``.
    ``manifest.text.multipleWrappers`` reaches ``code`` too, from ``_extract``, and was
    missing from this list while ``extract``'s own docstring advertised it -- a caller
    switching on ``.code`` over the documented set would have missed it.
    The wrapper decoded perfectly; the manifest inside it did not. Reporting the
    carrier's code for these would send an investigator hunting byte damage that is not
    there, which is the whole reason ``code`` is a parameter.

    TWO SITES ARE EXCEPTIONS, AND THEY ARE NOT AN OVERSIGHT. "manifest store contains
    no manifest" and "malformed manifest store" report the carrier's code for a fault that is not in
    the carrier -- because NO CLAUSE NAMES A CODE FOR THEM. Every code below that level
    presupposes a store that parsed, and here the store did not. docs/open-questions.md
    records this as unresolved and says in terms that the carrier's code "is not a
    precise description and we know it". This paragraph exists so the taxonomy above is
    not read as complete when it is not.

    Neither kind is raised for an unsupported hash algorithm -- that is
    ``algorithm.unsupported``, and it is a verdict rather than an exception.
    C2PA 15.12.1.3.2 describes a wrapper as corrupt on "invalid version, algorithm, or
    manifest length", but A.8.2.2 defines no algorithm field in the wrapper; the clause
    is a drafting error and is not followed here.

    Attributes:
        msg: The failure, without any attacker-supplied content interpolated in.
        doc: The text being parsed.
        pos: Where parsing stopped, IN THE UNITS OF ``doc``.

            ``parse_wrapper_body`` passes the whole text and a byte offset into its
            as-stored UTF-8 encoding. ``selectors_to_bytes`` passes the selector RUN and
            a character index into it. ``_extract`` passes an empty ``doc`` and ``0``: a
            manifest that is structurally intact and wrong at the C2PA layer has no
            meaningful position, and ``__str__`` appends no location at all then.
        code: The C2PA status code this corresponds to, so a caught exception maps
            onto the same vocabulary as ``Verdict.failure``.
    """

    def __init__(self, msg: str, doc: str, pos: int, code: StatusCode = StatusCode.TEXT_CORRUPTED_WRAPPER) -> None:
        self.msg = msg
        self.doc = doc
        self.pos = pos
        # Overridable because not every structural rejection is a corrupt WRAPPER.
        # A store carrying two boxes under one label is well-formed at the selector
        # and JUMBF layers and wrong at the C2PA layer, and 15.6.1 has a precise code
        # for it (claim.multiple); 15.6.2 gives another (claim.cbor.invalid).
        # Reporting manifest.text.corruptedWrapper there would send an investigator
        # looking for byte damage that is not present.
        self.code = code
        super().__init__(msg)

    def __str__(self) -> str:
        """Compose the message, resolving the location only when it is READ.

        The location wording needs the document's byte length, and computing it
        eagerly in ``__init__`` made scanning quadratic: ``find_wrappers`` constructs
        one of these per magic-matching-but-malformed candidate and DISCARDS all but
        the first, so a document full of decoys paid a whole-document encode per
        decoy. Measured before the fix: 1.09 MB of crafted text took 9.91 s in
        ``verify()``, with time growing as the square of the input.

        That is the same defect ``_locate`` already removed once on the match path,
        arriving by way of the exception constructor. Deferring here means the cost is
        paid once, by the one exception a caller actually reads.

        An empty ``doc`` means the offset is unknown rather than at the end -- several
        structural errors in ``_extract`` have no meaningful position -- so no
        location is appended at all. Claiming "at end of text" for those was a
        confident lie about where parsing stopped.
        """
        if not self.doc:
            return self.msg
        # Truncation-aware, borrowed from tomllib rather than json: a length-prefixed
        # wrapper that runs off the end is the common corruption for this format, and
        # "byte 41 of 41" reads worse than "end of text".
        where = "end of text" if self.pos >= len(self.doc.encode("utf-8")) else f"byte {self.pos}"
        return f"{self.msg} (at {where})"

    def __reduce__(self) -> tuple[type[MarkCorruptError], tuple[str, str, int, StatusCode]]:
        """Required, not optional.

        ``args`` no longer matches ``__init__`` once the message is composed, so
        without this the exception cannot be pickled and therefore cannot cross a
        process boundary -- which matters the moment anyone runs verification in a
        worker pool. Most code copying json's structured-attribute pattern misses it.
        """
        return (self.__class__, (self.msg, self.doc, self.pos, self.code))


class UnencodableTextError(C2paTextError, ValueError):
    """``text`` contains a lone surrogate and cannot be encoded as UTF-8.

    Catchable as ``C2paTextError`` and as ``ValueError``.

    Python's ``str`` happily holds unpaired surrogates -- they arrive from
    ``surrogateescape`` decoding, ``os.fsdecode``, and JSON's unpaired escapes --
    but UTF-8 cannot represent them. Every offset in this format is a UTF-8 byte
    offset, so such a string is not a text asset this specification can describe at
    all, and there is no verdict to give about it.

    Raised UP FRONT rather than allowed to surface as a ``UnicodeEncodeError`` from
    somewhere inside the scan. The unguarded version was attacker-triggerable against
    any endpoint catching only ``C2paTextError``, which is what the documentation
    tells integrators to catch.
    """

    def __init__(self, position: int) -> None:
        self.position = position
        super().__init__(
            f"text contains an unpaired surrogate at index {position} and cannot be encoded as UTF-8; "
            "decode the input strictly, or re-encode it with errors='replace' before marking or verifying"
        )
