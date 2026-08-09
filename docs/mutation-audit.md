# Test design and mutation checks

Coverage is a reachability signal, not proof that an assertion detects wrong
behaviour. This repository uses mutation checks as a manual review tool; they are not a
release gate and no current mutation score is published.

## What a useful mutation must establish

A mutation is useful when it changes a reachable behaviour and a test fails for the
public or owner-layer result. A surviving mutation can mean either a test gap or an
equivalent change. The review must construct a distinguishing input before calling it
a gap.

The test suite follows these rules:

- **Test the public boundary for public claims.** A helper-level assertion does not
  prove that `embed`, `extract`, `verify`, `locate`, or `strip` wires the helper into
  the right path.
- **Use an independent expected value.** RFC literals, standards-body vectors, and
  hand-built wire bytes can arbitrate an encoder or parser. A serializer round trip is
  integration evidence, not an independent wire oracle.
- **Keep hostile inputs reachable.** Private states that the parser cannot produce do
  not justify production branches or tests. Hostile public inputs must still reach the
  rule they claim to exercise.
- **Separate semantics from cost.** Functional tests hold verdicts, bounds, and finite
  failure. CodSpeed owns CPU and memory measurements.
- **Keep one emitted-wire gate.** The package-version policy treats producer byte
  changes as wire-major changes; `tests/test_vector_file.py` holds that separate
  compatibility contract.
- **Translate attacker-input failures at public boundaries.** Malformed selector,
  CBOR, JUMBF, COSE, and certificate bytes must become the documented verdict or
  package exception rather than an unrelated dependency exception.

## Manual procedure

1. Change one condition, constant, branch, or call site on a throwaway worktree.
2. State the observable behaviour that should differ and construct the smallest input
   that reaches it.
3. Run the narrow owner-layer test, then `make test`.
4. Restore the source change before testing another mutation.
5. If the mutation survives, add or rewrite one discriminating test at the correct
   layer. Do not add a test that merely repeats the implementation.

A future published mutation result must name the exact source commit, mutation set,
commands, killed and equivalent cases, and date. Without those fields it is a local
diagnostic, not evidence about the current release.
