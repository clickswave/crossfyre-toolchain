#!/usr/bin/env python3
"""Write the third-party notices for the binaries one release archive carries.

For each binary, built as the release builds it (BINARIES, with its features) for the
archive's target: cargo-about's licence texts for every crate compiled in, each text
once with the crates it covers, and the licence file of each C library a crate
compiles in, which those texts leave out (NATIVE). A crate that runs a C compiler and
is not in NATIVE stops the notices until someone has said what it compiles in, and so
does a crate under a licence scripts/notices/about.toml does not accept. A crate the
toolchain carries a changed copy of, under vendor/, says so and where that copy is.

Usage:
  scripts/notices.py --target TRIPLE --out FILE [--cargo-about PATH]

Run from anywhere, after the binaries are built (it reads the crates offline).
Standard library only.
"""
import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "scripts", "notices", "about.toml")
VENDOR = os.path.join(ROOT, "vendor")
VENDOR_URL = "https://github.com/clickswave/crossfyre-toolchain/tree/main/vendor"

# Each binary a release archive carries, with the features it is built with: the four
# engines with BoringSSL for a browser's TLS and HTTP/2 fingerprint, each built on its
# own so that no other binary gets their features. cfx-script's depend on the system.
BINARIES = [
    ("crossfyre", []),
    ("plessor", ["impersonate"]),
    ("ambulo", ["impersonate"]),
    ("voyage", ["impersonate"]),
    ("doorward", []),
    ("toolmark", ["impersonate"]),
    ("node", []),
    ("cfx-script", None),
]

# Every crate that runs cc or cmake from its build script in a published binary, and the
# licence file of the C library it compiles in, or None when nothing of its own C is
# compiled in that the crate's licence does not cover.
NATIVE = {
    "aws-lc-sys": ("AWS-LC", "LICENSE"),
    "boring-sys2": ("BoringSSL", "deps/boringssl/LICENSE"),
    "openssl-src": ("OpenSSL", "openssl/LICENSE.txt"),
    "zstd-sys": ("Zstandard", "zstd/LICENSE"),
    # cargo-about's ring workaround reads the notices in ring's own C and assembly.
    "ring": None,
    # Links what openssl-src builds; none of its own C is compiled in.
    "openssl-sys": None,
    # Build tools: nothing of them is compiled in.
    "cc": None,
    "cmake": None,
}


class NoticesError(Exception):
    pass


def features(name, target):
    """The features `name` is built with for `target`."""
    for binary, feats in BINARIES:
        if binary == name:
            if feats is not None:
                return feats
            return ["bundled-python"] if "-linux-" in target else ["abi3"]
    raise KeyError(name)


def run(cmd):
    # cargo writes UTF-8 on every system; Windows would read it in its own code page.
    got = subprocess.run(cmd, cwd=ROOT, capture_output=True, encoding="utf-8")
    if got.returncode != 0:
        raise NoticesError(f"{' '.join(cmd[:3])} failed:\n{got.stderr[-3000:]}")
    return got.stdout


def about(cargo_about, name, target):
    """cargo-about's JSON for `name` as the release builds it for `target`."""
    cmd = [cargo_about, "generate", "--offline", "--locked", "--fail", "-c", CONFIG,
           "-m", os.path.join(ROOT, name, "Cargo.toml"), "--target", target, "--format", "json"]
    feats = features(name, target)
    if feats:
        cmd += ["--features", " ".join(feats)]
    return json.loads(run(cmd))


def compiles_c(name, target):
    """{crate: version} for each crate in `name`'s build for `target` that builds with cc
    or cmake, as `cargo tree` lists them."""
    found = {}
    for tool in ("cc", "cmake"):
        cmd = ["cargo", "tree", "--locked", "--offline", "-p", name, "-e", "normal,build",
               "--target", target, "-i", tool, "--depth", "1", "--prefix", "none"]
        feats = features(name, target)
        if feats:
            cmd += ["--features", ",".join(feats)]
        got = subprocess.run(cmd, cwd=ROOT, capture_output=True, encoding="utf-8")
        if got.returncode != 0:
            # `-i` names a package the build does not have.
            if "did not match any packages" in got.stderr:
                continue
            raise NoticesError(f"cargo tree for {name} failed:\n{got.stderr[-3000:]}")
        for line in got.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                found[parts[0]] = parts[1][1:]
    return found


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def manifests():
    """{(crate, version): its Cargo.toml} for every package the workspace can build, build
    dependencies included, which cargo-about leaves out."""
    meta = json.loads(run(["cargo", "metadata", "--format-version", "1", "--locked",
                           "--offline", "--all-features"]))
    return {(p["name"], p["version"]): p["manifest_path"] for p in meta["packages"]}


def render(target, reports, native, manifests, read=None):
    """The notices text. `reports` is {binary: cargo-about JSON}, `native` is {binary:
    {crate: version}}, `manifests` is what [`manifests`] gives, and `read` reads a file
    (for the tests)."""
    read = read or read_text
    texts = {}
    vendored = set()
    for binary, report in reports.items():
        for crate in report.get("crates", []):
            pkg = crate["package"]
            if pkg.get("source") is None and os.path.dirname(
                    os.path.dirname(pkg["manifest_path"])) == VENDOR:
                vendored.add((pkg["name"], pkg["version"]))
        for lic in report.get("licenses", []):
            key = (lic["id"], lic["text"])
            entry = texts.setdefault(key, {"name": lic["name"], "crates": set()})
            for used in lic.get("used_by", []):
                entry["crates"].add((used["crate"]["name"], used["crate"]["version"]))

    libraries = {}
    for binary, crates in native.items():
        for crate, version in crates.items():
            if crate not in NATIVE:
                raise NoticesError(
                    f"{crate} {version} runs a C compiler in the build of {binary} and "
                    f"is not in NATIVE in scripts/notices.py: say what it compiles in")
            if NATIVE[crate] is None:
                continue
            libraries.setdefault((crate, version), set()).add(binary)

    out = [f"THIRD-PARTY NOTICES: Crossfyre toolchain, open build for {target}", "",
           "The binaries in this archive are built from the Crossfyre toolchain, which is "
           "under the Apache License 2.0 in LICENSE.",
           "They compile in the open source software below, under the licences that "
           "follow.", ""]
    if libraries:
        out += ["== C libraries", ""]
        for (crate, version), binaries in sorted(libraries.items()):
            library, rel = NATIVE[crate]
            manifest = manifests.get((crate, version))
            if manifest is None:
                raise NoticesError(f"{crate} {version} is compiled in and cargo metadata does "
                                   f"not list it, so its licence file cannot be found")
            out += [f"-- {library}, compiled in by {crate} {version}, in "
                    f"{', '.join(sorted(binaries))}", "",
                    read(os.path.join(os.path.dirname(manifest), rel)).rstrip(), ""]
    out += ["== Rust crates", ""]
    for (lid, text), entry in sorted(texts.items(), key=lambda kv: (kv[0][0], sorted(kv[1]["crates"]))):
        crates = ", ".join(f"{n} {v}" for n, v in sorted(entry["crates"]))
        out += [f"-- {entry['name']} ({lid})", f"Used by: {crates}", "", text.strip(), ""]
    if vendored:
        out += ["== Changed copies", ""]
        for name, version in sorted(vendored):
            out.append(f"{name} {version} is changed in this toolchain; the changed source "
                       f"is at {VENDOR_URL}/{name}-{version}")
        out.append("")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--target", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--cargo-about", default="cargo-about")
    a = p.parse_args(argv)
    try:
        reports = {name: about(a.cargo_about, name, a.target) for name, _ in BINARIES}
        native = {name: compiles_c(name, a.target) for name, _ in BINARIES}
        text = render(a.target, reports, native, manifests())
    except NoticesError as e:
        print(f"notices: {e}", file=sys.stderr)
        return 1
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"notices: {a.out} for {a.target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
