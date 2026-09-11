# Oracle regression tests

Every detection oracle in this repository, run against a purpose-built target
that is vulnerable in one specific way, and against one that is not.

## Why this exists

The engines were measured by hand. A full benchmark run against the `limeyard`
lab takes ninety minutes, needs seventeen Docker containers, an account, a
control plane and a node, and nobody runs it on a pull request. So the actual
guard against a detection regression was somebody remembering to check, which is
not a guard.

These tests need none of that: a Python fixture, the engine binary, and a socket.
They run in CI in under a minute.

## The thing they are really protecting

Not recall. **Silence.**

Every expensive mistake in this engine has been an oracle that stopped finding
something and said nothing about it, because a negative result gets no scrutiny.
A pacer that serialised the concurrency check so the race could never happen. A
control whose deadline discarded the informative answer. A correlation table that
stranded a substitution so every flow looked authorized. A process-wide cache
that skipped the side effect feeding a chain, so it worked once per process and
then stopped. All four presented as a clean pass.

So every case here declares what the oracle MUST find *and* what it must NOT
report, and the negatives are the point. A case with no `must_not` is a case that
has not been thought about: it can be satisfied by an oracle that reports
everything.

## Running them

    python3 tests/oracles/run.py                # everything
    python3 tests/oracles/run.py race tampering # named cases
    python3 tests/oracles/run.py --list

The runner builds nothing. Point it at binaries with `CORTEX_BIN` / `MACH_BIN`,
or let it default to `target/debug/{cortex,mach}`.

Exit status is 0 only when every case matched exactly: every `must_find` seen and
every `must_not` absent. Anything else is a failure with the diff printed.

## Adding a case

1. A fixture in `fixtures/`. It takes its port as `argv[1]` and prints nothing;
   the runner waits for the port to accept a connection. Give it a vulnerable
   path AND a correctly-implemented one, because the correct one is what proves
   the oracle discriminates rather than fires.
2. An entry in `cases.py` saying what to run and what must and must not come back.
