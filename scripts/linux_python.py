#!/usr/bin/env python3
"""The CPython that Linux's cfx-script goes out with in a release of this repository.

cfx-script used to link the build machine's libpython3.11 and did not start on a
host without exactly that library. A Linux release now carries CPython from
python-build-standalone (github.com/astral-sh/python-build-standalone), the
install_only_stripped archive of one release for each arch, pinned by sha256 in
.github/workflows/release.yml. It goes in a folder called python beside cfx-script:

    cfx-script
    python/lib/libpython3.X.so.1.0
    python/lib/python3.X/...          the standard library

cfx-script is built with the bundled-python feature against that CPython, so it is
linked with DT_RPATH $ORIGIN/python/lib and refuses to run with any other libpython
(cfx-script/build.rs and cfx-script/src/bundled.rs).

    linux_python.py folder --archive A --sha256 S --version V --out DIR
        Checks A against S and lays out DIR/python, the folder as it ships, with
        DIR/link/libpython3.X.so, the name the linker looks for, and DIR/pyo3.cfg,
        which PYO3_CONFIG_FILE names so that pyo3 builds against this Python without
        running it.

    linux_python.py check BINARY --version V
        Holds cfx-script to loading that libpython alone: it has to name it and no
        other libpython, and carry DT_RPATH $ORIGIN/python/lib and no DT_RUNPATH.

    linux_python.py notices --version V --release R --out FILE
        Writes the licence texts of everything in the folder, committed under
        cfx-script/linux-python for that pin, as one file.

Everything the libpython compiles in is under a permissive licence: the readline
module uses libedit, not GNU readline. Moving the pin means collecting the texts
again from the release's full archive, whose licenses/ folder and PYTHON.json say
what each module links, and writing the new pin into licences.json.
"""

import argparse
import fnmatch
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
LICENCES = ROOT / "cfx-script" / "linux-python"
DIR = "python"
# The rpath cfx-script has to carry, as objdump -p prints it.
RPATH = "$ORIGIN/python/lib"
# What is left out of the standard library: tkinter, IDLE and turtle, whose Tk is left
# out too, ensurepip and the pip in site-packages, which scripts run here have no use
# for, and the build configuration, which only building against this Python reads.
LEFT_OUT = ("tkinter", "idlelib", "turtledemo", "turtle.py", "ensurepip", "site-packages", "config-*")
# lib-dynload holds the modules built as files of their own, and the folder carries
# none: _tkinter, and _dbm, which links Berkeley DB under the Sleepycat licence.
# Whatever else a later pin puts there stops the build until someone decides about it.
DYNLOAD_LEFT_OUT = ("_dbm", "_tkinter")
# The newest glibc the release binaries may need: Debian 12's.
GLIBC_CEILING = (2, 36)
# The modes the folder's files are given, as the first-party zip gives them.
FILE_MODE = 0o644


def fail(msg: str) -> None:
    sys.exit(f"linux_python.py: {msg}")


def minor_of(version: str) -> str:
    """3.13 from 3.13.18."""
    if not re.fullmatch(r"3\.\d+\.\d+", version):
        fail(f"{version!r} is not a CPython version like 3.13.18")
    return ".".join(version.split(".")[:2])


def libpython(version: str) -> str:
    """The libpython's file name, which is also its soname and what cfx-script names."""
    return f"libpython{minor_of(version)}.so.1.0"


def keeps(name: str, version: str) -> bool:
    """Whether the archive's file `name` goes in the folder: the libpython, and the
    standard library less LEFT_OUT and lib-dynload."""
    if name == f"{DIR}/lib/{libpython(version)}":
        return True
    stdlib = f"{DIR}/lib/python{minor_of(version)}/"
    if not name.startswith(stdlib):
        return False
    top = name[len(stdlib):].split("/", 1)[0]
    return top != "lib-dynload" and not any(fnmatch.fnmatchcase(top, p) for p in LEFT_OUT)


def objdump_p(path: Path) -> str:
    try:
        return subprocess.run(["objdump", "-p", str(path)], check=True, capture_output=True,
                              text=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        fail(f"objdump -p {path} failed ({e})")


def dynamic(text: str, tag: str) -> list:
    """The values of one tag of the dynamic section (NEEDED, RPATH, RUNPATH)."""
    out = []
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] == tag:
            out.append(parts[1].strip())
    return out


def required_glibc(text: str) -> tuple:
    """The newest GLIBC_x.y the object's version references name."""
    found = [tuple(int(n) for n in m) for m in re.findall(r"\bGLIBC_(\d+)\.(\d+)(?:\.\d+)?\b", text)]
    return max(found, default=(0, 0))


def folder(args) -> None:
    body = Path(args.archive).read_bytes()
    got = hashlib.sha256(body).hexdigest()
    if got != args.sha256:
        fail(f"{args.archive} has sha256 {got}, and the pin is {args.sha256}")
    version, minor = args.version, minor_of(args.version)
    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    dynload_dir = f"{DIR}/lib/python{minor}/lib-dynload/"
    kept, dynload = [], set()
    with tarfile.open(args.archive, mode="r:gz") as t:
        for m in t.getmembers():
            # Its modules are the .so files there; it also holds a placeholder, .empty.
            if m.name.startswith(dynload_dir) and m.name.endswith(".so"):
                dynload.add(PurePosixPath(m.name).name.split(".", 1)[0])
            if ".." in PurePosixPath(m.name).parts or m.name.startswith("/"):
                fail(f"the archive holds {m.name}, outside the folder it unpacks to")
            if m.isdir() or not keeps(m.name, version):
                continue
            if not m.isfile():
                fail(f"{m.name} in the archive is a link or a special file, where the folder takes "
                     f"plain files alone")
            dest = out / m.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(t.extractfile(m).read())
            dest.chmod(FILE_MODE)
            kept.append(m.name)
    unknown = sorted(dynload - set(DYNLOAD_LEFT_OUT))
    if unknown:
        fail(f"the archive builds {', '.join(unknown)} as module(s) of their own in lib-dynload, which "
             f"the folder leaves out, and DYNLOAD_LEFT_OUT does not say that is meant. Look at what "
             f"each links and under which licence.")
    lib = out / DIR / "lib" / libpython(version)
    for need in (lib, out / DIR / "lib" / f"python{minor}" / "os.py"):
        if not need.is_file():
            fail(f"the archive holds no {need.relative_to(out)}, which cfx-script loads")
    text = objdump_p(lib)
    need = required_glibc(text)
    if need > GLIBC_CEILING:
        fail(f"{lib.name} requires GLIBC_{need[0]}.{need[1]}, newer than "
             f"{GLIBC_CEILING[0]}.{GLIBC_CEILING[1]}, so cfx-script would not start on Debian 12")
    (out / "link").mkdir()
    (out / "link" / f"libpython{minor}.so").symlink_to(f"../{DIR}/lib/{libpython(version)}")
    (out / "pyo3.cfg").write_text("".join(f"{k}={v}\n" for k, v in (
        ("implementation", "CPython"), ("version", minor), ("shared", "true"), ("abi3", "false"),
        ("lib_name", f"python{minor}"), ("lib_dir", str((out / "link").resolve())),
        ("pointer_width", "64"), ("build_flags", ""), ("suppress_build_script_link_lines", "false"))))
    print(f"{len(kept)} files of CPython {version} in {out / DIR}")


def check(args) -> None:
    text = objdump_p(Path(args.binary))
    want = libpython(args.version)
    python = [lib for lib in dynamic(text, "NEEDED") if lib.startswith("libpython")]
    if python != [want]:
        fail(f"{args.binary} loads {', '.join(python) or 'no libpython'}, where the CPython beside it is "
             f"{want}. It was built against another Python.")
    rpath, runpath = dynamic(text, "RPATH"), dynamic(text, "RUNPATH")
    if rpath != [RPATH] or runpath:
        has = ", ".join([f"DT_RPATH {r}" for r in rpath] + [f"DT_RUNPATH {r}" for r in runpath]) or "no rpath"
        fail(f"{args.binary} has {has}, where it needs DT_RPATH {RPATH} alone to load the libpython "
             f"beside it before any other. It was built without the bundled-python feature.")
    print(f"{args.binary} loads {want} from {DIR}/ beside it (DT_RPATH {RPATH})")


def notices(args) -> None:
    record_path = LICENCES / "licences.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if (record.get("release"), record.get("version")) != (args.release, args.version):
        fail(f"{record_path.relative_to(ROOT)} lists the licences of CPython {record.get('version')} "
             f"({record.get('release')}), and the release pins {args.version} ({args.release}). Collect "
             f"them for the new pin from its full archive's licenses/ and PYTHON.json.")
    rule = "-" * 78
    out = [
        "Third-party notices for the CPython beside cfx-script", "",
        f"CPython {args.version}, as python-build-standalone builds it for Linux in its release",
        f"{args.release} (the install_only_stripped archive of each arch), goes beside cfx-script",
        f"in this archive, in {DIR}/: its libpython and its standard library, without tkinter,",
        "IDLE, turtle, ensurepip, pip, the build configuration and the modules built as files",
        "of their own. Nothing in what goes out is modified:",
        f"  https://github.com/astral-sh/python-build-standalone/releases/tag/{args.release}",
        "", "Below is CPython's own licence, then that of each library its libpython has",
        "built in, each under the licence named beside it.",
    ]
    components = record.get("components", [])
    if not components:
        fail(f"{record_path.name} lists no licences")
    for c in components:
        text = (LICENCES / c["file"]).read_text(encoding="utf-8")
        text = text.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
        out += ["", rule, f"{c['name']} ({c['licence']}), {c['what']}.", "", f"From {c['from']}:", "", text]
    Path(args.out).write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote the licences of {len(components)} components to {args.out}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("folder")
    f.add_argument("--archive", required=True)
    f.add_argument("--sha256", required=True)
    f.add_argument("--version", required=True)
    f.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("binary")
    c.add_argument("--version", required=True)
    n = sub.add_parser("notices")
    n.add_argument("--version", required=True)
    n.add_argument("--release", required=True)
    n.add_argument("--out", required=True)
    args = p.parse_args()
    {"folder": folder, "check": check, "notices": notices}[args.cmd](args)


if __name__ == "__main__":
    main()
