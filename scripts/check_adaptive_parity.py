#!/usr/bin/env python3
"""Guard the open-core `adaptive` swap.

`adaptive/` (committed, open baseline) and `adaptive-private/` (git-ignored tuned
drop-in) share a package name and are swapped at build time by the `.cargo/config.toml`
`[paths]` override. For that swap to stay sound, the two crates MUST expose the
*same public API surface* - dependents (core, mach, pulse, voyage) compile against
whichever is present, so a `pub` item that drifts in one but not the other breaks
either the first-party build or the public build, and the break shows up far from
the edit.

This checks that the public API surfaces match. It does NOT look at bodies - the
private crate's whole point is that its implementations differ. Run it locally
(the private drop-in never ships, so no CI ever has both): it is wired into the
committed `.githooks/pre-push`.

Exit codes: 0 = in parity (or private drop-in absent -> skipped), 1 = drift.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC = os.path.join(ROOT, "adaptive", "src")
PRIVATE = os.path.join(ROOT, "adaptive-private", "src")

# A "public surface" line: a top-level or impl/trait item, or a struct field /
# enum variant, that is visible to dependents. `pub(crate)`/`pub(super)` are
# internal, so they are deliberately excluded - they can differ freely.
PUB_ITEM = re.compile(r"^\s*pub\s+(?:unsafe\s+)?(?:async\s+)?"
                      r"(?:fn|struct|enum|trait|type|const|static|mod|union)\b")
PUB_FIELD = re.compile(r"^\s*pub\s+[A-Za-z_][A-Za-z0-9_]*\s*:")  # pub name: Type
PUBCRATE = re.compile(r"^\s*pub\s*\(")  # pub(crate) / pub(super) / pub(in ..)


def strip_line_comment(s: str) -> str:
    # Good enough for signature lines; we never need string-literal fidelity here.
    i = s.find("//")
    return s[:i] if i != -1 else s


def norm(s: str) -> str:
    """Put a declaration into one comparable shape.

    Whitespace collapses, a trailing comma left by a member split goes, and so
    does rustfmt's trailing comma before a closing bracket: `Backoff { a: u64,
    b: bool, }` and `Backoff { a: u64, b: bool }` are the same variant, written
    by the same formatter at two different line lengths.
    """
    s = re.sub(r"\s+", " ", s).strip().rstrip(",").strip()
    s = re.sub(r",\s*([)\]}])", r"\1", s)
    # Space around brackets is formatting. Remove it on both sides rather than
    # trying to reproduce one crate's line-wrapping in the other.
    s = re.sub(r"\s*([)\]}])", r"\1", s)
    s = re.sub(r"([({\[])\s*", r"\1", s)
    return s.strip()


def unname_params(header: str) -> str:
    """Drop the leading underscore from parameter names in a fn signature.

    `fn resolve(mode: &Mode, _seed: Option<&str>)` and the same signature with
    `seed` are one API: the underscore says the body ignores the argument, and
    the open baseline ignores arguments the tuned drop-in uses. A caller cannot
    tell the difference, so neither should this. Only parameter names are
    touched; a struct field named `_x` IS part of the surface and is left alone.
    """
    if not re.match(r"^pub\s+(?:unsafe\s+)?(?:async\s+)?fn\b", header):
        return header
    open_paren = header.find("(")
    if open_paren == -1:
        return header
    close = matching(header, open_paren)
    if close == -1:
        return header
    params = re.sub(r"(^|[(,]\s*)_([A-Za-z][A-Za-z0-9_]*\s*:)", r"\1\2",
                    header[open_paren:close + 1])
    return header[:open_paren] + params + header[close + 1:]


def matching(s: str, start: int) -> int:
    """Index of the bracket closing the one at `start`, or -1."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = s[start]
    closer = pairs[opener]
    depth = 0
    for i in range(start, len(s)):
        if s[i] == opener:
            depth += 1
        elif s[i] == closer:
            depth -= 1
            if depth == 0:
                return i
    return -1


def split_top_level(body: str, sep: str) -> list:
    """Split on `sep` at nesting depth zero, so a generic or a struct-variant
    payload is not cut in half."""
    parts, depth, buf = [], 0, ""
    for ch in body:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    parts.append(buf)
    return [p for p in (norm(x) for x in parts) if p]


def strip_attrs(member: str) -> str:
    """Remove `#[...]` attributes; they are not part of the surface here."""
    while member.startswith("#"):
        end = matching(member, member.find("["))
        if end == -1:
            break
        member = member[end + 1:].strip()
    return member


def signatures(src_dir: str) -> set:
    """Extract the normalized set of public-API declarations from a crate's src.

    For fns/types/consts the full signature is captured (joining continuation
    lines) up to the `{`, `;`, or `where`. For struct/enum/trait the header plus
    each public member (pub fields, all enum variants, trait item signatures) is
    captured, tracking nesting so member scanning stops at the item's close.
    """
    out = set()
    files = []
    for base, _dirs, names in os.walk(src_dir):
        for n in names:
            if n.endswith(".rs"):
                files.append(os.path.join(base, n))
    for path in sorted(files):
        rel = os.path.relpath(path, src_dir)
        with open(path, "r") as f:
            raw = f.readlines()
        lines = [strip_line_comment(l).rstrip("\n") for l in raw]
        i = 0
        while i < len(lines):
            line = lines[i]
            t = line.strip()
            if PUBCRATE.match(line):
                i += 1
                continue
            is_item = bool(PUB_ITEM.match(line))
            is_field = bool(PUB_FIELD.match(line))
            if not (is_item or is_field):
                i += 1
                continue
            # `pub const`/`pub static` carry a VALUE after `=` - and for the tuned
            # drop-in that value IS the secret (WINDOW_MS = 400 vs 500). The API
            # surface is `NAME: Type`, never the value, so terminate those at `=`.
            # Everything else (incl. `pub type X = Y`, where the alias target is
            # part of the API) keeps its full signature.
            is_valued = bool(re.match(r"^\s*pub\s+(?:const|static)\b", line))
            terms = r"[{;=]" if is_valued else r"[{;]"
            # Accumulate the declaration until a signature terminator.
            buf = t
            j = i
            while not re.search(terms, buf) and " where" not in buf and j + 1 < len(lines):
                j += 1
                buf += " " + lines[j].strip()
            # Header = everything up to the first terminator (the signature), normalized.
            header = norm(re.split(terms, buf, maxsplit=1)[0])
            header = unname_params(header)
            kind = header.split()[1] if len(header.split()) > 1 else header
            out.add(f"{rel}:: {header}")
            # For struct/enum/trait, also record the members inside the block.
            if (is_item and re.match(r"^\s*pub\s+(?:struct|enum|trait|union)\b", line)
                    and "{" in buf):
                # Take the whole body, then split it into members. Scanning line
                # by line read a struct-variant's fields as if each were a
                # variant of its own, so `Backoff { delay_ms: u64,
                # rotate_identity: bool }` wrapped across four lines and the
                # same variant on one line did not compare equal. That is
                # rustfmt's choice about line length, not an API difference, and
                # it is the kind of false alarm that gets a guard switched off.
                text = "\n".join(lines[i:])
                open_brace = text.find("{")
                close = matching(text, open_brace)
                if close == -1:
                    i = j + 1
                    continue
                body = text[open_brace + 1:close]
                container = kind
                for member in split_top_level(body, ";" if container == "trait" else ","):
                    member = strip_attrs(member)
                    if not member:
                        continue
                    if container == "enum":
                        out.add(f"{rel}::{header}::variant {member}")
                    elif container in ("struct", "union"):
                        if member.startswith("pub "):
                            out.add(f"{rel}::{header}::field {member}")
                    elif container == "trait":
                        sig = norm(re.split(r"\{", member, maxsplit=1)[0])
                        if re.match(r"^(?:unsafe\s+)?(?:async\s+)?(?:fn|type|const)\b", sig):
                            sig = unname_params("pub " + sig)[4:]
                            out.add(f"{rel}::{header}::item {sig}")
                i = i + text[:close].count("\n") + 1
                continue
            i = j + 1
    return out


def main() -> int:
    if not os.path.isdir(PRIVATE):
        print("adaptive parity: adaptive-private/ absent (public checkout) - skipped")
        return 0
    if not os.path.isdir(PUBLIC):
        print("adaptive parity: adaptive/src missing - cannot check", file=sys.stderr)
        return 1
    pub = signatures(PUBLIC)
    prv = signatures(PRIVATE)
    only_pub = sorted(pub - prv)
    only_prv = sorted(prv - pub)
    if not only_pub and not only_prv:
        print(f"adaptive parity: OK ({len(pub)} public API items match)")
        return 0
    print("adaptive parity: DRIFT - the open `adaptive` and private `adaptive-private`")
    print("public API surfaces differ. The `[paths]` swap requires them identical.\n")
    if only_pub:
        print("  Only in adaptive/ (public baseline):")
        for s in only_pub:
            print(f"    + {s}")
    if only_prv:
        print("  Only in adaptive-private/ (tuned drop-in):")
        for s in only_prv:
            print(f"    - {s}")
    print("\nBring both crates' public signatures back in line before pushing.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
