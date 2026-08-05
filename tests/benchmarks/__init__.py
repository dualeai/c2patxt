"""CodSpeed benchmarks. Not tests: nothing here asserts anything about cost.

CONTRIBUTING.md requires that a test fail if you break the code it covers, and a
benchmark has no assertion to fail. The properties this package actually depends on --
that scanning is linear, that the document is walked twice and not four times, that a
repeated link does not multiply the reference walk -- are held by ordinary assertions
in ``tests/test_regressions.py``, and stay there.

What lives here is the complement: constant-factor drift, which no assertion in this
repository watches. A change that makes verification 30% slower without changing any
operation count is invisible to the suite and visible to CodSpeed.
"""
