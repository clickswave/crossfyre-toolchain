#!/usr/bin/env python3
"""Run every oracle regression case. See README.md.

Exit 0 only when every case matched exactly.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from cases import CASES  # noqa: E402

# How long a fixture gets to start listening, and an engine op gets to finish.
READY_TIMEOUT = 15.0
OP_TIMEOUT = 300.0


def free_port() -> int:
    """A port the OS just confirmed is free.

    Bound and released rather than picked from a range: these tests run
    concurrently with whatever else is on a developer's machine, and a fixed
    range is a flake waiting for the day somebody else is using it.
    """
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_listening(port: int, proc: subprocess.Popen, what: str) -> None:
    deadline = time.time() + READY_TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None:
            out = (proc.stdout.read() if proc.stdout else b"") or b""
            raise RuntimeError(f"{what} exited before listening: {out[-400:]!r}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"{what} never listened on {port}")


class Engine:
    """A cortex or mach daemon, on a port nobody else is using."""

    def __init__(self, binary: Path, env: dict | None = None):
        self.port = free_port()
        self.proc = subprocess.Popen(
            [str(binary), "--daemon", "--port", str(self.port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={**os.environ, **(env or {})},
        )
        wait_listening(self.port, self.proc, binary.name)

    def run(self, request: dict) -> tuple[list, list]:
        """Send one operation. Returns (findings, log messages)."""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=OP_TIMEOUT)
        s.settimeout(OP_TIMEOUT)
        s.sendall((json.dumps(request) + "\n").encode())
        findings, logs, buf, done = [], [], b"", False
        while not done:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                logs.append("HARNESS TIMEOUT")
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    v = json.loads(line)
                except ValueError:
                    continue
                t = v.get("type")
                # Two engine shapes, deliberately handled without an engine
                # switch. cortex wraps a finding as {"type":"finding","data":{..}};
                # mach streams flat crawl events with `url` at the top level. A
                # case should be able to assert on either without knowing which.
                if t == "finding":
                    findings.append(v["data"])
                elif t in ("done", "error"):
                    if t == "error":
                        logs.append("ERROR: " + str(v.get("message")))
                    done = True
                elif v.get("url"):
                    findings.append(v)
                if v.get("message"):
                    logs.append(str(v["message"]))
        s.close()
        return findings, logs

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class Fixture:
    """One fixture process, on a port the OS just handed out.

    `extra` arguments may reference an earlier fixture's port as `{name}`, which
    is how a two-process case is wired: the application needs to be told where
    its internal service is, and both ports are chosen at run time.
    """

    def __init__(self, script: str, extra: list[str] | None = None,
                 known: dict[str, int] | None = None):
        self.port = free_port()
        path = HERE / "fixtures" / script
        args = [a.format(**(known or {})) for a in (extra or [])]
        self.proc = subprocess.Popen(
            [sys.executable, str(path), str(self.port), *args],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        wait_listening(self.port, self.proc, script)

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def matches(finding: dict, want: dict) -> bool:
    """Does this finding satisfy an expectation?

    Compared field by field, and only on the fields the expectation names, so a
    case says `{"class": "cmdi", "param": "host"}` and is not broken by an
    unrelated change to severity wording.
    """
    for key, expected in want.items():
        if key == "class":
            got = finding.get("vuln_class")
        elif key == "url_contains":
            got = finding.get("url") or ""
            if expected not in got:
                return False
            continue
        else:
            got = finding.get(key)
        if got != expected:
            return False
    return True


def describe(f: dict) -> str:
    return (f"{f.get('vuln_class')}/{f.get('severity')} "
            f"param={f.get('param')} {(f.get('url') or '')[:64]}")


def have_browser() -> bool:
    if os.environ.get("MACH_BROWSER"):
        return Path(os.environ["MACH_BROWSER"]).is_file()
    for name in ("chromium", "chromium-browser", "google-chrome",
                 "google-chrome-stable", "chrome"):
        for d in os.environ.get("PATH", "").split(os.pathsep):
            if (Path(d) / name).is_file():
                return True
    return False


def run_case(name: str, case: dict, bins: dict) -> tuple[bool, list[str]]:
    fixtures, problems = [], []
    try:
        ports: dict[str, int] = {}
        for spec in case.get("fixtures", []):
            fx = Fixture(spec["script"], spec.get("args"), ports)
            fixtures.append(fx)
            ports[spec["name"]] = fx.port

        engine = Engine(bins[case.get("engine", "cortex")], case.get("env"))
        try:
            request = case["request"](ports)
            findings, logs = engine.run(request)
        finally:
            engine.stop()

        for want in case.get("must_find", []):
            if not any(matches(f, want) for f in findings):
                problems.append(f"MISSING  {want}")
        for never in case.get("must_not", []):
            hit = next((f for f in findings if matches(f, never)), None)
            if hit:
                problems.append(f"REPORTED {never}  ->  {describe(hit)}")
        for phrase in case.get("must_say", []):
            if not any(phrase in m for m in logs):
                problems.append(f"SILENT   expected the pass to say: {phrase!r}")
        for phrase in case.get("must_not_say", []):
            hit = next((m for m in logs if phrase in m), None)
            if hit:
                problems.append(f"SAID     must not have said {phrase!r}  ->  {hit[:110]}")

        if problems:
            problems.append("  --- what it actually reported ---")
            problems += [f"      {describe(f)}" for f in findings] or ["      (nothing)"]
            notes = [m for m in logs if any(
                w in m.lower() for w in
                ("could not", "no browser", "not looked for", "skipped", "unavailable"))]
            if notes:
                problems.append("  --- what the engine said about it ---")
                problems += [f"      {m[:200]}" for m in notes[:5]]
    except Exception as e:  # a fixture or engine that would not start
        problems.append(f"ERROR    {type(e).__name__}: {e}")
    finally:
        for fx in fixtures:
            fx.stop()
    return (not problems), problems


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "--list" in sys.argv:
        for n, c in CASES.items():
            print(f"  {n:22} {c.get('what', '')}")
        return 0

    bins = {
        "cortex": Path(os.environ.get("CORTEX_BIN", ROOT / "target/debug/cortex")),
        "mach": Path(os.environ.get("MACH_BIN", ROOT / "target/debug/mach")),
    }
    selected = {n: c for n, c in CASES.items() if not args or n in args}
    if not selected:
        print(f"no such case: {', '.join(args)}", file=sys.stderr)
        return 2
    needed = {c.get("engine", "cortex") for c in selected.values()}
    for eng in needed:
        if not bins[eng].exists():
            print(f"missing binary: {bins[eng]}  (build it, or set {eng.upper()}_BIN)",
                  file=sys.stderr)
            return 2

    failures, skipped = 0, 0
    browser = have_browser()
    for name, case in selected.items():
        if case.get("needs_browser") and not browser:
            # Named, never silent. A case that quietly does not run is the exact
            # failure mode this suite exists to catch.
            print(f"SKIP {name:22}   -.-s  {case.get('what','')}  "
                  f"(no browser; set MACH_BROWSER)", flush=True)
            skipped += 1
            continue
        t0 = time.time()
        ok, problems = run_case(name, case, bins)
        mark = "ok  " if ok else "FAIL"
        print(f"{mark} {name:22} {time.time()-t0:5.1f}s  {case.get('what','')}", flush=True)
        if not ok:
            failures += 1
            for p in problems:
                print(f"       {p}", flush=True)

    total = len(selected)
    ran = total - skipped
    print(f"\n{ran - failures}/{ran} cases passed"
          + (f", {skipped} skipped" if skipped else ""))
    if failures:
        print("A case fails when the oracle stopped finding what it should, or "
              "started reporting what it should not. Both are regressions.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
