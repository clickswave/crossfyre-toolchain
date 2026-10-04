#!/usr/bin/env python3
"""Guard the F-Droid recipe against the app it claims to describe.

`mobile/fdroid/io.crossfyre.tracer.yml` is a build recipe for somebody else's
builder. Nothing in this repository runs it, so every way it can disagree with
`mobile/app/build.gradle.kts` is invisible here and fails in public on F-Droid's
server instead.

It had drifted four ways at once: a tag that was never created, a version two
dozen releases stale, `gradle: [yes]` after product flavours landed, and a
prebuild cross-compiling one ABI for an APK that packages two. The last one is
the worst of them, because the recipe's whole purpose is the `Binaries:` line:
F-Droid builds from source, compares byte for byte against our signed APK, and
distributes ours on a match. A missing ABI means the comparison cannot match, so
the reproducible build was guaranteed to fail before anyone submitted it.

Checked here:

  * the ABI list in the APK equals the ABI list the prebuild cross-compiles
  * `rustup target add` names a rust triple for each of those ABIs
  * the recipe's versionName/versionCode match the gradle file, in the `Builds`
    entry and in `CurrentVersion`/`CurrentVersionCode`
  * the flavour named in `gradle:` is a product flavour that exists

NOT checked, because nothing local can: that `commit:` exists in the public
repository. The recipe says so in a comment at the point where it matters.

Stdlib only, and parsed with regexes rather than a YAML library, so it runs
wherever python3 does. Exit codes: 0 = agrees, 1 = drift.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GRADLE = os.path.join(ROOT, "mobile", "app", "build.gradle.kts")
RECIPE = os.path.join(ROOT, "mobile", "fdroid", "io.crossfyre.tracer.yml")

# cargo-ndk takes either form for -t, so both are normalised to the ABI name the
# APK uses. A target in neither column is a typo rather than a new architecture.
TRIPLE_FOR_ABI = {
    "arm64-v8a": "aarch64-linux-android",
    "armeabi-v7a": "armv7-linux-androideabi",
    "x86_64": "x86_64-linux-android",
    "x86": "i686-linux-android",
}
ABI_FOR_TRIPLE = {v: k for k, v in TRIPLE_FOR_ABI.items()}


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def strip_comments(text):
    """Drop `#` comment lines, so prose about the recipe is never parsed as it."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def gradle_facts(text):
    out = {}
    m = re.search(r"abiFilters\s*\+=\s*listOf\(([^)]*)\)", text)
    if m:
        out["abis"] = re.findall(r'"([^"]+)"', m.group(1))
    m = re.search(r"versionCode\s*=\s*(\d+)", text)
    if m:
        out["versionCode"] = m.group(1)
    m = re.search(r'versionName\s*=\s*"([^"]+)"', text)
    if m:
        out["versionName"] = m.group(1)
    out["flavours"] = re.findall(r'create\("([^"]+)"\)\s*\{\s*\n\s*dimension', text)
    return out


def recipe_facts(text):
    out = {}
    m = re.search(r"^\s*-\s*versionName:\s*(\S+)", text, re.M)
    if m:
        out["versionName"] = m.group(1).strip("'\"")
    m = re.search(r"^\s*versionCode:\s*(\d+)", text, re.M)
    if m:
        out["versionCode"] = m.group(1)
    m = re.search(r"^CurrentVersion:\s*(\S+)", text, re.M)
    if m:
        out["currentVersion"] = m.group(1).strip("'\"")
    m = re.search(r"^CurrentVersionCode:\s*(\d+)", text, re.M)
    if m:
        out["currentVersionCode"] = m.group(1)
    # The flavour list under `gradle:`, which is a YAML list of bare words.
    m = re.search(r"^\s*gradle:\s*\n((?:\s*-\s*\S+\n)+)", text, re.M)
    if m:
        out["gradle"] = re.findall(r"-\s*(\S+)", m.group(1))
    m = re.search(r"cargo ndk\s+((?:-t\s+\S+\s*)+)", text)
    if m:
        out["ndk_targets"] = re.findall(r"-t\s+(\S+)", m.group(1))
    m = re.search(r"rustup target add\s+([^\n]+)", text)
    if m:
        out["rustup_targets"] = m.group(1).split()
    return out


def as_abi(name):
    if name in TRIPLE_FOR_ABI:
        return name
    return ABI_FOR_TRIPLE.get(name)


def main():
    for path in (GRADLE, RECIPE):
        if not os.path.exists(path):
            print(f"fdroid-recipe: {path} is missing, nothing to compare.")
            return 0

    g = gradle_facts(read(GRADLE))
    r = recipe_facts(strip_comments(read(RECIPE)))
    problems = []

    # Anything unparsed is a problem in itself: a silently empty comparison is
    # the failure mode this whole script exists to stop.
    for key, where in (
        ("abis", "abiFilters in build.gradle.kts"),
        ("versionCode", "versionCode in build.gradle.kts"),
        ("versionName", "versionName in build.gradle.kts"),
    ):
        if not g.get(key):
            problems.append(f"could not read {where}")
    for key, where in (
        ("versionName", "Builds[0].versionName"),
        ("versionCode", "Builds[0].versionCode"),
        ("gradle", "Builds[0].gradle"),
        ("ndk_targets", "the `cargo ndk -t` targets in prebuild"),
        ("rustup_targets", "the `rustup target add` line in prebuild"),
    ):
        if not r.get(key):
            problems.append(f"could not read {where} in the recipe")
    if problems:
        for p in problems:
            print(f"fdroid-recipe: {p}", file=sys.stderr)
        return 1

    want = sorted(set(g["abis"]))
    got_raw = r["ndk_targets"]
    unknown = [t for t in got_raw if as_abi(t) is None]
    if unknown:
        problems.append(
            "prebuild cross-compiles for "
            + ", ".join(unknown)
            + ", which is not an Android ABI or a known rust triple"
        )
    got = sorted({as_abi(t) for t in got_raw if as_abi(t)})
    if got != want:
        problems.append(
            "the APK packages "
            + ", ".join(want)
            + " and the prebuild cross-compiles "
            + ", ".join(got)
            + ". F-Droid's build would differ from ours, so `Binaries` can never match."
        )

    triples = set(r["rustup_targets"])
    for abi in want:
        if TRIPLE_FOR_ABI[abi] not in triples:
            problems.append(
                f"`rustup target add` does not install {TRIPLE_FOR_ABI[abi]}, "
                f"which {abi} needs"
            )

    if r["versionName"] != g["versionName"] or r["versionCode"] != g["versionCode"]:
        problems.append(
            f"the recipe builds {r['versionName']} ({r['versionCode']}) and the app is "
            f"{g['versionName']} ({g['versionCode']})"
        )
    if r.get("currentVersion") != g["versionName"] or r.get(
        "currentVersionCode"
    ) != g["versionCode"]:
        problems.append(
            f"CurrentVersion says {r.get('currentVersion')} "
            f"({r.get('currentVersionCode')}) and the app is "
            f"{g['versionName']} ({g['versionCode']})"
        )

    flavours = g.get("flavours") or []
    for f in r["gradle"]:
        if f == "yes":
            problems.append(
                "`gradle: [yes]` means the app has no product flavours. It has "
                + ", ".join(flavours)
                + ", so this builds all of them and names none."
            )
        elif flavours and f not in flavours:
            problems.append(
                f"the recipe builds the `{f}` flavour, which is not one of: "
                + ", ".join(flavours)
            )

    if problems:
        print("fdroid-recipe: the recipe and the app disagree.", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print(
        f"fdroid-recipe: agrees with the app ({g['versionName']}/{g['versionCode']}, "
        f"{', '.join(want)}, flavour {', '.join(r['gradle'])})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
