#!/usr/bin/env python3
"""Tests for notices.py. Run: python3 -I scripts/test_notices.py"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import notices  # noqa: E402

REG = "/registry/src/index.crates.io"


def crate(name, version, source="registry"):
    return {"package": {"name": name, "version": version, "source": source,
                        "manifest_path": f"{REG}/{name}-{version}/Cargo.toml"}}


def licence(lid, text, *used):
    return {"name": lid + " licence", "id": lid, "text": text,
            "used_by": [{"crate": {"name": n, "version": v}, "path": None} for n, v in used]}


MANIFESTS = {
    ("boring-sys2", "4.15.15"): f"{REG}/boring-sys2-4.15.15/Cargo.toml",
    ("openssl-src", "300.6.1+3.6.3"): f"{REG}/openssl-src-300.6.1+3.6.3/Cargo.toml",
}
FILES = {
    f"{REG}/boring-sys2-4.15.15/deps/boringssl/LICENSE": "BoringSSL is under the OpenSSL licence.\n",
    f"{REG}/openssl-src-300.6.1+3.6.3/openssl/LICENSE.txt": "OpenSSL is under Apache 2.\n",
}


def render(reports, native):
    return notices.render("x86_64-unknown-linux-gnu", reports, native, MANIFESTS,
                          read=FILES.__getitem__)


class Notices(unittest.TestCase):
    def test_a_c_library_is_reproduced_whole_with_the_binaries_it_is_in(self):
        reports = {"plessor": {"crates": [crate("boring-sys2", "4.15.15")], "licenses": []},
                   "ambulo": {"crates": [], "licenses": []},
                   "crossfyre": {"crates": [], "licenses": []}}
        native = {"plessor": {"boring-sys2": "4.15.15", "cmake": "0.1.58"},
                  "ambulo": {"boring-sys2": "4.15.15"},
                  # A build dependency cargo-about does not list, found through metadata.
                  "crossfyre": {"openssl-src": "300.6.1+3.6.3", "openssl-sys": "0.9.117"}}
        text = render(reports, native)
        self.assertIn("-- BoringSSL, compiled in by boring-sys2 4.15.15, in ambulo, plessor\n\n"
                      "BoringSSL is under the OpenSSL licence.", text)
        self.assertIn("-- OpenSSL, compiled in by openssl-src 300.6.1+3.6.3, in crossfyre\n\n"
                      "OpenSSL is under Apache 2.", text)
        self.assertNotIn("cmake", text)

    def test_a_crate_that_compiles_c_nobody_has_named_stops_the_notices(self):
        reports = {"toolmark": {"crates": [], "licenses": []}}
        with self.assertRaises(notices.NoticesError) as e:
            render(reports, {"toolmark": {"mystery-sys": "1.0.0"}})
        self.assertIn("mystery-sys 1.0.0", str(e.exception))
        self.assertIn("toolmark", str(e.exception))

    def test_each_licence_text_is_given_once_with_every_crate_it_covers(self):
        mit = "MIT text, copyright someone"
        reports = {"crossfyre": {"crates": [], "licenses": [licence("MIT", mit, ("a", "1.0"))]},
                   "node": {"crates": [], "licenses": [licence("MIT", mit, ("b", "2.0")),
                                                       licence("MIT", "other MIT text", ("c", "3.0"))]}}
        text = render(reports, {})
        self.assertEqual(text.count(mit), 1)
        self.assertIn("-- MIT licence (MIT)\nUsed by: a 1.0, b 2.0\n\n" + mit, text)
        self.assertIn("Used by: c 3.0\n\nother MIT text", text)

    def test_a_changed_copy_says_where_its_source_is(self):
        vendored = {"package": {"name": "lru", "version": "0.13.0", "source": None,
                                "manifest_path": os.path.join(notices.VENDOR, "lru-0.13.0",
                                                              "Cargo.toml")}}
        text = render({"plessor": {"crates": [vendored], "licenses": []}}, {})
        self.assertIn("lru 0.13.0 is changed in this toolchain; the changed source is at "
                      f"{notices.VENDOR_URL}/lru-0.13.0", text)

    def test_the_release_builds_each_binary_as_the_notices_read_it(self):
        """Each `cargo build` of release.yml's two build steps, as {binary: features},
        is what BINARIES says, so the notices describe what was built."""
        with open(os.path.join(notices.ROOT, ".github", "workflows", "release.yml")) as f:
            workflow = f.read()
        steps = re.findall(r"- name: Build the workspace binaries\n(.*?)\n\n", workflow, re.S)
        self.assertEqual(len(steps), 2)
        for step, target in zip(steps, ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]):
            built = {}
            for loop, feats in re.findall(r'for p in ([\w -]+); do\n\s*cargo build [^\n]*-p "\$p"'
                                          r'(?: --features (\S+))?', step):
                for name in loop.split():
                    built[name] = feats.split(",") if feats else []
            for name, feats in re.findall(r"cargo build [^\n]*?-p ([\w-]+) --features (\S+)$",
                                          step, re.M):
                built[name] = feats.split(",")
            want = {name: notices.features(name, target) for name, _ in notices.BINARIES}
            self.assertEqual(built, want)


if __name__ == "__main__":
    unittest.main()
