#!/usr/bin/env python3
"""Break each oracle on purpose, and check the suite notices.

    python3 tests/oracles/mutants.py            # every mutation
    python3 tests/oracles/mutants.py --list

A regression suite that has never failed on a real bug is unproven. This proves
it, one deliberate defect at a time: apply a mutation to the engine source,
rebuild, run the cases the mutation should break, and require that they fail.

**A mutation that survives is a hole in the suite, not a passing test.** The
first version of the opt-in case had exactly that: removing the gate entirely
still passed, because the case asserted a downstream consequence the fixture had
already consumed. It was found this way and fixed.

The mutations are chosen to match how this engine has actually broken, which has
never once been an early return. All four real bugs were mechanisms quietly
becoming the thing they measured: a pacer that serialised the concurrency check,
a control whose deadline discarded the informative answer, a correlation table
that stranded a substitution, a cache that skipped the side effect feeding a
chain. So each mutation here removes a CONTROL or a guard rather than a feature.

Slow on purpose: a rebuild per mutation. Run it when an oracle changes, or
nightly. It is not a per-commit gate.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# (name, file, find, replace, cases that MUST fail, why this matters)
MUTATIONS = [
    (
        "race-gate-removed",
        "cortex/src/inject.rs",
        'let race = classes.iter().any(|c| c == "race").then(|| {',
        "let race = Some(()).map(|_| {",
        ["intrusive-classes-are-opt-in"],
        "a state-changing class running in a scan nobody asked for",
    ),
    (
        "race-accepts-one",
        "cortex/src/race.rs",
        "if accepted.len() < MIN_ACCEPTED {",
        "if false {",
        ["race-negatives"],
        "reporting a limit that held under concurrency as a race",
    ),
    (
        "race-ignores-rate-limiting",
        "cortex/src/race.rs",
        "if control.status == 429 || control.retry_after {",
        "if false {",
        ["race-negatives"],
        "calling a rate limiter a business-logic race",
    ),
    (
        "tampering-skips-determinism-check",
        "cortex/src/inject.rs",
        "if !crate::tamper::close(c.numbers[link.index], at_v1) {",
        "if false {",
        ["tampering-negatives"],
        "a hit counter that moves on its own read as a computed value",
    ),
    (
        # Removing ONE of the two guards proves nothing: `close(want, observed)`
        # and the out-of-domain test each reject a clamped total on their own.
        # This removes both, which is the only way to tell redundant protection
        # apart from absent protection.
        "tampering-accepts-anything-out-of-domain",
        "cortex/src/tamper.rs",
        """pub fn followed_out(how: Link, at_v1: f64, v1: f64, v_bad: f64, observed: f64) -> bool {""",
        """pub fn followed_out(how: Link, at_v1: f64, v1: f64, v_bad: f64, observed: f64) -> bool {
    if true { let _ = (how, at_v1, v1, v_bad, observed); return true; }""",
        ["tampering-negatives"],
        "an application that CLAMPS, which is correct, reported as a bug",
    ),
    (
        # EXPECTED TO SURVIVE, and named so rather than quietly dropped.
        #
        # Two independent guards reject a clamped total: `close(want, observed)`
        # and the out-of-domain test. Removing either alone changes nothing,
        # which is defence in depth rather than untested code - and the only way
        # to know which it is, is to remove BOTH, which
        # `tampering-accepts-anything-out-of-domain` does and the suite catches.
        # A surviving mutant is a question, not a verdict.
        "tampering-ignores-clamping[redundant]",
        "cortex/src/tamper.rs",
        """    let Some(want) = predict(how, at_v1, v1, v_bad) else {
        return false;
    };
    if !close(want, observed) {
        return false;
    }""",
        "    let _ = predict(how, at_v1, v1, v_bad);",
        ["tampering-negatives"],
        "an application that CLAMPS, which is correct, reported as a bug",
    ),
    (
        "smuggling-drops-the-unambiguous-control",
        "cortex/src/smuggle.rs",
        "if unambiguous_time >= control_time + DESYNC_GAP {",
        "if false {",
        ["smuggling-negatives"],
        "a lone slow server reported as a desync, which mirage caught for real",
    ),
    (
        "chain-drops-same-host-control",
        "cortex/src/chain.rs",
        "shape(observed) != shape(control_b)",
        "true",
        ["chain-black-holed-host"],
        "a black-holed address reported as a reachable service",
    ),
    (
        "chain-ignores-authorised-scope",
        "cortex/src/inject.rs",
        ".filter(|t| authorised.admits(&t.host, Some(t.port)))",
        ".filter(|_t| true)",
        ["chain-needs-authorised-scope"],
        "probing an address nobody said we could touch",
    ),
    (
        # The control that the DVWA false positives cost us. Without it the
        # oracle has only the true/false pair and the baseline, and an
        # application that varies its own length between two requests looks
        # exactly like one evaluating the payload.
        "sqli-boolean-drops-the-inert-control",
        "cortex/src/inject.rs",
        """                    if boolean_differential(baseline, &a2, &b2, min_diff)
                        && !inert_splits_the_same_way(client, site, base, t, f, baseline, min_diff)
                            .await
                    {""",
        "                    if boolean_differential(baseline, &a2, &b2, min_diff) {",
        ["sqli-negative-drifting-page"],
        "calling a page that changes on its own a SQL injection",
    ),
    (
        # Same reasoning: the marker is confirmed twice, so removing one check
        # leaves the other doing the work. Both go.
        "proto-pollution-confirms-nothing",
        "cortex/src/inject.rs",
        """        if !after
            .as_ref()
            .map(|r| r.body.contains(&marker))
            .unwrap_or(false)
        {
            continue;
        }
        let again = send_site(client, site, &site.base_value).await;
        if again.map(|r| r.body.contains(&marker)).unwrap_or(false) {""",
        """        let again = send_site(client, site, &site.base_value).await;
        if again.is_some() {""",
        ["proto-pollution-negative"],
        "reporting pollution that never actually persisted",
    ),
    (
        # EXPECTED TO SURVIVE, for the same reason as the clamping mutation
        # above: the marker is confirmed twice and removing one check leaves the
        # other doing the work. `proto-pollution-confirms-nothing` removes both
        # and IS caught, which is what tells redundancy apart from absence.
        "proto-pollution-skips-confirmation[redundant]",
        "cortex/src/inject.rs",
        """        if !after
            .as_ref()
            .map(|r| r.body.contains(&marker))
            .unwrap_or(false)
        {
            continue;
        }""",
        "        if false {\n            continue;\n        }",
        ["proto-pollution-negative"],
        "reporting pollution that never actually persisted",
    ),
    (
        "spa-ignores-source-maps",
        "mach/src/spa.rs",
        "let m = RE_SOURCEMAP.captures(body)?.get(1)?.as_str().trim();",
        "let m = \"\"; let _ = RE_SOURCEMAP.captures(body);",
        ["spa-static"],
        "losing the original source a bundle ships alongside itself",
    ),
    (
        "spa-ignores-lazy-chunks",
        "mach/src/spa.rs",
        "for c in RE_CHUNK_MAP.captures_iter(body) {",
        "for c in RE_CHUNK_MAP.captures_iter(\"\") {",
        ["spa-static"],
        "never seeing the half of a SPA that nothing links to",
    ),
]


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def apply_mutation(path: Path, find: str, replace: str) -> str:
    original = path.read_text()
    if find not in original:
        raise RuntimeError(f"anchor not found in {path.name}: {find[:60]!r}")
    path.write_text(original.replace(find, replace, 1))
    return original


def main() -> int:
    if "--list" in sys.argv:
        for name, f, _, _, cases, why in MUTATIONS:
            print(f"  {name:38} {f:26} -> {', '.join(cases)}")
            print(f"  {'':38} guards against: {why}")
        return 0

    wanted = [a for a in sys.argv[1:] if not a.startswith("-")]
    chosen = [m for m in MUTATIONS if not wanted or m[0] in wanted]

    # Content-based, not `git status --porcelain`. Writing a file and writing it
    # back leaves a fresh mtime, so status reports it modified until the index is
    # refreshed, and this harness does exactly that to every file it touches. It
    # blocked its own next run on a file that was byte-identical to HEAD.
    run(["git", "update-index", "--refresh"])
    dirty = run(["git", "diff", "--name-only", "--", "cortex/src", "mach/src"]).stdout.strip()
    if dirty:
        print("engine sources have uncommitted changes; commit or stash before "
              "mutating, or a failure will not mean what it says:\n" + dirty,
              file=sys.stderr)
        return 2

    survived = []
    for name, rel, find, replace, cases, why in chosen:
        path = ROOT / rel
        t0 = time.time()
        original = apply_mutation(path, find, replace)
        try:
            build = run(["cargo", "build", "--locked", "-p", "cortex", "-p", "mach"],
                        env={**__import__("os").environ, "CARGO_INCREMENTAL": "0"})
            if build.returncode != 0:
                # A mutation that will not compile proves nothing either way.
                print(f"SKIP {name:38} mutation does not build", flush=True)
                print("     " + build.stderr.strip().splitlines()[-1][:120], flush=True)
                continue
            res = run([sys.executable, "tests/oracles/run.py", *cases])
            caught = res.returncode != 0
        finally:
            path.write_text(original)

        redundant = name.endswith("[redundant]")
        if redundant:
            # Expected to survive: another mutation removes the same protection
            # completely and IS caught. Flagged if it is ever caught here,
            # because that means the guards stopped being redundant.
            mark = "note" if not caught else "CHANGED"
            print(f"{mark} {name:38} {time.time()-t0:5.1f}s  "
                  + ("survives as expected (redundant guard)" if not caught
                     else "is now caught - the guards are no longer redundant"),
                  flush=True)
            continue
        mark = "ok  " if caught else "HOLE"
        print(f"{mark} {name:38} {time.time()-t0:5.1f}s  {'caught by' if caught else 'SURVIVED'} "
              f"{', '.join(cases)}", flush=True)
        if not caught:
            survived.append((name, why))

    # Rebuild clean so the tree is left as it was found.
    run(["cargo", "build", "--locked", "-p", "cortex", "-p", "mach"])

    graded = [m for m in chosen if not m[0].endswith("[redundant]")]
    print(f"\n{len(graded) - len(survived)}/{len(graded)} mutations caught"
          + (f", {len(chosen) - len(graded)} expected survivor(s)"
             if len(chosen) != len(graded) else ""))
    for name, why in survived:
        print(f"  HOLE: {name} survived. The suite does not guard against {why}.")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
