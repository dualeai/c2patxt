"""Public exception hierarchy.

The four public operations use three result channels:

===================================  ==================================
Absence of a mark                    return value (``None`` / ``UNMARKED``)
A wrapper is present but unparseable **raises** ``MarkCorruptError``
A manifest parses but fails to verify a ``Verdict`` carrying status codes
===================================  ==================================

Validation failures use status-bearing verdicts so callers can inspect a parsed,
rejected manifest. Absence is not an exception because unmarked text is a normal
input.
"""

from __future__ import annotations

from c2patxt.status import StatusCode

__all__ = [
    "C2paTextError",
    "MarkCorruptError",
    "TextNormalizationError",
    "UnencodableTextError",
]


class C2paTextError(Exception):
    """Base class for every documented error from a public entry point.

    Private CBOR, COSE and JUMBF errors are translated at their package boundary.
    Concrete public errors also derive from the matching built-in error category.
    """


class TextNormalizationError(C2paTextError, ValueError):
    """NFC normalization would exceed the UAX #15 Stream-Safe input bound.

    ``position`` is a character index into the caller's string.
    """

    def __init__(self, position: int) -> None:
        self.position = position
        super().__init__(
            f"text exceeds the 30-nonstarter normalization limit at character {position} (Unicode UAX #15 D3)"
        )

    def __reduce__(self) -> tuple[type[TextNormalizationError], tuple[int]]:
        return (self.__class__, (self.position,))


class MarkCorruptError(C2paTextError, ValueError):
    """A wrapper's magic number matched, but the structure is malformed.

    Catchable as ``C2paTextError`` and as ``ValueError``.

    Carrier damage uses ``manifest.text.corruptedWrapper`` (15.12.1.3.2). A fault
    inside an intact wrapper uses the narrower claim, signature, assertion or plural
    wrapper code named by its validation clause. Unsupported algorithms remain verdict
    outcomes rather than exceptions.

    Attributes:
        msg: The failure, without any attacker-supplied content interpolated in.
        pos: UTF-8 byte offset where parsing stopped.
        document_length: Total UTF-8 byte length, or ``None`` when the failure has no
            meaningful position.

            The exception stores the length rather than the caller's full, possibly
            hostile document. Manifest failures below the wrapper layer pass ``None``
            because they have no useful text position.
        code: The C2PA status code this corresponds to, so a caught exception maps
            onto the same vocabulary as ``Verdict.failure``.
    """

    def __init__(
        self,
        msg: str,
        pos: int,
        document_length: int | None = None,
        code: StatusCode = StatusCode.TEXT_CORRUPTED_WRAPPER,
    ) -> None:
        self.msg = msg
        self.pos = pos
        self.document_length = document_length
        # Overridable because not every structural rejection is a corrupt WRAPPER.
        # A store carrying two boxes under one label is well-formed at the selector
        # and JUMBF layers and wrong at the C2PA layer, and 15.6.1 has a precise code
        # for it (claim.multiple); 15.6.2 gives another (claim.cbor.invalid).
        # Reporting manifest.text.corruptedWrapper there would send an investigator
        # looking for byte damage that is not present.
        self.code = code
        super().__init__(msg)

    def __str__(self) -> str:
        """Format a byte location when the carrier boundary supplied one."""
        if self.document_length is None:
            return self.msg
        # Truncation-aware, borrowed from tomllib rather than json: a length-prefixed
        # wrapper that runs off the end is the common corruption for this format, and
        # "byte 41 of 41" reads worse than "end of text".
        where = "end of text" if self.pos >= self.document_length else f"byte {self.pos}"
        return f"{self.msg} (at {where})"

    def __reduce__(self) -> tuple[type[MarkCorruptError], tuple[str, int, int | None, StatusCode]]:
        return (self.__class__, (self.msg, self.pos, self.document_length, self.code))


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

    def __reduce__(self) -> tuple[type[UnencodableTextError], tuple[int]]:
        return (self.__class__, (self.position,))
