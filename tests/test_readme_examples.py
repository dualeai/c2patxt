"""The code in README.md, executed.

This tests CODE that happens to live in a markdown file. It does not test prose: no
link resolution, no banned words, no required substrings.

`pyproject.toml` sets `readme = "README.md"`, so that file is the entire PyPI long
description and its quickstart is the first code most readers run. The two failures
this catches are a quickstart that calls a function defined fifty lines below it, and a
worked example quoting dates already in the past.
"""

from __future__ import annotations

import datetime
import pathlib
import re

from cryptography import x509

from c2patxt import Provenance, Verdict, VerifyContext, verify

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Fenced ``python`` blocks in README.md, in file order.
_PYTHON_BLOCK = re.compile(r"```python\n(.*?)```", re.S)


def _readme_blocks() -> list[str]:
    return _PYTHON_BLOCK.findall((ROOT / "README.md").read_text("utf-8"))


def test_every_readme_python_block_at_least_parses() -> None:
    """Not every block can EXECUTE.

    One demonstrates calls that raise on purpose; another reads an ``anchors.pem`` that
    no reader has. Those still have to be valid Python, which is what this holds. The
    runnable path is held by the test below.
    """
    blocks = _readme_blocks()
    assert blocks, "no python blocks found; the fence pattern has drifted from the file"
    for index, block in enumerate(blocks):
        compile(block, f"README.md[python block {index}]", "exec")


def test_the_readme_quickstart_runs_as_written() -> None:
    """Run the first pasted block alone, then its later shelf-life continuation."""
    blocks = _readme_blocks()
    namespace: dict[str, object] = {}
    exec(compile(blocks[0], "README.md[quickstart]", "exec"), namespace)  # noqa: S102 -- running the docs IS the test

    result = namespace["result"]
    assert isinstance(result, Verdict)
    assert result.state is Provenance.VALID

    # The shelf-life block continues this namespace -- it reads `leaf`, `marked` and
    # `datetime` from the quickstart, which is what a reader scrolling down has.
    shelf_life = next(block for block in blocks if "not_valid_after_utc" in block)
    exec(compile(shelf_life, "README.md[shelf life]", "exec"), namespace)  # noqa: S102 -- as above

    # Use the block's own values so its arithmetic remains under test.
    leaf, marked = namespace["leaf"], namespace["marked"]
    inside, after = namespace["inside"], namespace["after"]
    assert isinstance(leaf, x509.Certificate)
    assert isinstance(marked, str)
    assert isinstance(inside, datetime.datetime)
    assert isinstance(after, datetime.datetime)

    assert inside < leaf.not_valid_after_utc < after, "the two instants must straddle expiry"
    assert verify(marked, context=VerifyContext(now=inside)).state is Provenance.VALID
    assert verify(marked, context=VerifyContext(now=after)).state is Provenance.INVALID
