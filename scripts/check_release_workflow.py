#!/usr/bin/env python3
"""Check that a workflow pins what it runs and keeps signing rights away from
third-party code.

The release workflow signs build provenance. Whatever runs in the job that holds
`id-token: write` or `attestations: write` can mint an attestation for any file,
and whatever an action or image tag resolves to is up to whoever controls that
tag. So for each workflow given (the release workflow by default):

  1. every `uses:` names a full commit SHA, or an image by digest;
  2. every job container and service image is pinned by digest;
  3. a job that can sign runs only actions published by GitHub (`actions/`,
     `github/`), never a third party's;
  4. a Chocolatey install names its version.

Standard library only, so it runs on any runner without installing anything.
It reads the workflow line by line rather than as YAML and understands the block
style this repo writes; flow style (`permissions: {id-token: write}`) is refused
outright rather than guessed at.

Exit codes: 0 = clean, 1 = a rule is broken, 2 = usage error.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = [os.path.join(ROOT, ".github", "workflows", "release.yml")]

SHA_REF = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
USES = re.compile(r"^(\s*)(?:-\s+)?uses:\s*(.*)$")
CONTAINER = re.compile(r"^(\s*)container:\s*(.*)$")
IMAGE = re.compile(r"^(\s*)(?:-\s+)?image:\s*(.*)$")
KEY = re.compile(r"^(\s*)([A-Za-z0-9_-]+):\s*(.*)$")
SIGNING = ("id-token", "attestations")
FIRST_PARTY = ("actions/", "github/")


def value(raw):
    """A scalar with its trailing comment and quotes removed."""
    v = re.sub(r"\s+#.*$", "", raw).strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1]
    return v


def indent(line):
    return len(line) - len(line.lstrip(" "))


def read_permissions(lines, i, own_indent):
    """Permissions from the block opened at lines[i]. Returns (perms, error)."""
    m = KEY.match(lines[i])
    inline = value(m.group(3))
    if inline.startswith("{"):
        return None, "flow-style permissions are not understood here; write them as a block"
    if inline == "write-all":
        return {k: "write" for k in SIGNING + ("contents",)}, None
    if inline in ("read-all", ""):
        perms = {}
        if inline == "":
            j = i + 1
            while j < len(lines):
                line = lines[j]
                if line.strip() and not line.lstrip().startswith("#"):
                    if indent(line) <= own_indent:
                        break
                    km = KEY.match(line)
                    if km:
                        perms[km.group(2)] = value(km.group(3))
                j += 1
        return perms, None
    return None, f"permissions value {inline!r} is not understood"


def check(path):
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    errors = []
    top_perms = {}
    jobs = {}  # name -> {"perms": dict or None, "uses": [(lineno, ref)]}
    job_indent = None
    in_jobs = False
    job = None
    pending_container = None  # indent of a `container:` whose image is on a later line

    for i, line in enumerate(lines):
        n = i + 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        ind = indent(line)

        if ind == 0:
            in_jobs = stripped.startswith("jobs:")
            job = None
            if stripped.startswith("permissions:"):
                top_perms, err = read_permissions(lines, i, 0)
                if err:
                    errors.append(f"{path}:{n}: {err}")
                    top_perms = {}
            continue

        if in_jobs:
            if job_indent is None:
                job_indent = ind
            if ind == job_indent:
                km = KEY.match(line)
                job = km.group(2) if km else None
                if job:
                    jobs[job] = {"perms": None, "uses": []}
                pending_container = None
                continue
            if job and ind == job_indent + 2 and stripped.startswith("permissions:"):
                perms, err = read_permissions(lines, i, ind)
                if err:
                    errors.append(f"{path}:{n}: {err}")
                jobs[job]["perms"] = perms or {}

        if pending_container is not None and ind <= pending_container:
            pending_container = None

        um = USES.match(line)
        if um:
            ref = value(um.group(2))
            if job:
                jobs[job]["uses"].append((n, ref))
            if ref.startswith("./"):
                pass
            elif ref.startswith("docker://"):
                if not DIGEST.search(ref):
                    errors.append(f"{path}:{n}: {ref} is an image by tag; pin it by @sha256 digest")
            elif not SHA_REF.match(ref):
                errors.append(f"{path}:{n}: {ref} is not pinned to a full commit SHA")
            continue

        cm = CONTAINER.match(line)
        if cm:
            img = value(cm.group(2))
            if img:
                if not DIGEST.search(img):
                    errors.append(f"{path}:{n}: container {img} is not pinned by @sha256 digest")
            else:
                pending_container = ind
            continue

        im = IMAGE.match(line)
        if im:
            img = value(im.group(2))
            if img and not DIGEST.search(img):
                errors.append(f"{path}:{n}: image {img} is not pinned by @sha256 digest")
            continue

        if re.search(r"\bchoco(?:\.exe)?\s+install\b", line) and "--version" not in line:
            errors.append(f"{path}:{n}: choco install without --version installs whatever is newest")

    for name, j in jobs.items():
        perms = j["perms"] if j["perms"] is not None else top_perms
        signing = [k for k in SIGNING if perms.get(k) == "write"]
        if not signing:
            continue
        for n, ref in j["uses"]:
            if ref.startswith("./") or ref.startswith(FIRST_PARTY):
                continue
            errors.append(
                f"{path}:{n}: job {name} holds {', '.join(k + ': write' for k in signing)} "
                f"and runs {ref}, which GitHub does not publish; move it to a job without them"
            )
    return errors


def main(argv):
    paths = argv[1:] or DEFAULT
    errors = []
    for p in paths:
        if not os.path.isfile(p):
            print(f"no such workflow: {p}", file=sys.stderr)
            return 2
        errors.extend(check(p))
    for e in errors:
        print(e)
    if errors:
        print(f"{len(errors)} problem(s)")
        return 1
    print("workflow pins and signing permissions are in order")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
