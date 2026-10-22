#!/usr/bin/env python3
"""Write the app's "Full notices" from the native build's dependency tree.

Every crate the Android library links is listed with its version, its licence
and the copyright lines its own licence files carry, followed by the Android
libraries, which come from Gradle and are listed by hand below. Run it after
changing a dependency:

    python3 tools/notices.py > app/src/main/res/raw/notices.txt

It reads `cargo metadata` and the crates' sources from the local cargo
registry, so `cargo fetch` must have run first.
"""

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RUST = os.path.join(HERE, "..", "rust")

# Gradle dependencies of the app, which cargo knows nothing about.
ANDROID = [
    ("AndroidX (activity, core, lifecycle, browser)", "Apache-2.0", "Copyright The Android Open Source Project"),
    ("Jetpack Compose", "Apache-2.0", "Copyright The Android Open Source Project"),
    ("CameraX", "Apache-2.0", "Copyright The Android Open Source Project"),
    ("Kotlin standard library and kotlinx.coroutines", "Apache-2.0", "Copyright JetBrains s.r.o. and Kotlin Programming Language contributors"),
    ("ZXing core", "Apache-2.0", "Copyright ZXing authors"),
    ("Inter", "OFL-1.1", "Copyright 2020 The Inter Project Authors"),
    ("Outfit", "OFL-1.1", "Copyright 2021 The Outfit Project Authors"),
    ("JetBrains Mono", "OFL-1.1", "Copyright 2020 The JetBrains Mono Project Authors"),
    ("Orbitron", "OFL-1.1", "Copyright 2018 The Orbitron Project Authors"),
    ("Phosphor Icons", "MIT", "Copyright (c) 2023 Phosphor Icons"),
]

# The line in Apache's appendix that is an example, not a notice.
TEMPLATE = re.compile(r"\[yyyy\]|\{yyyy\}|<year>|\[name of copyright owner\]", re.I)


def copyright_lines(manifest_path: str) -> list[str]:
    root = os.path.dirname(manifest_path)
    found: list[str] = []
    for name in sorted(os.listdir(root)):
        if not re.match(r"(LICEN[CS]E|COPYING|COPYRIGHT|NOTICE)", name, re.I):
            continue
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = " ".join(line.strip().split())
                if s.lower().startswith("copyright") and not TEMPLATE.search(s) and len(s) < 200:
                    if s not in found:
                        found.append(s)
    return found


def main() -> int:
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--filter-platform", "aarch64-linux-android"],
        cwd=RUST,
    ))
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    pkgs = {p["id"]: p for p in meta["packages"]}
    root = next(p["id"] for p in meta["packages"] if p["name"] == "cfx_mobile")
    seen, stack = set(), [root]
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in nodes[i]["deps"]:
            if any(k["kind"] in (None, "normal") for k in d["dep_kinds"]):
                stack.append(d["pkg"])
    crates = sorted((pkgs[i] for i in seen if pkgs[i]["source"]), key=lambda p: (p["name"], p["version"]))

    out = sys.stdout
    out.write("Crossfyre Mobile is licensed under the Apache License 2.0.\n")
    out.write("It includes the components below. Each is listed with its licence and the\n")
    out.write("copyright lines its own licence files carry. The licence texts are under\n")
    out.write("Open source licences.\n\n")
    out.write("ANDROID, FONTS AND ICONS\n\n")
    for name, lic, holder in ANDROID:
        out.write(f"{name}\n  {lic}\n  {holder}\n\n")
    out.write("CAPTURE CORE (the native library)\n\n")
    for p in crates:
        out.write(f"{p['name']} {p['version']}\n  {p.get('license') or 'See the crate'}\n")
        for line in copyright_lines(p["manifest_path"]):
            out.write(f"  {line}\n")
        out.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
