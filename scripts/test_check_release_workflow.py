#!/usr/bin/env python3
"""Tests for check_release_workflow.py. Run: python3 -I scripts/test_check_release_workflow.py"""
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_release_workflow as crw  # noqa: E402

SHA = "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65"
GH_SHA = "ef244123eb79f2f7a7e75d99086184180e6d0018"
DIGEST = "sha256:" + "ab" * 32


def run(text):
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(textwrap.dedent(text))
        path = f.name
    try:
        return crw.check(path)
    finally:
        os.unlink(path)


class Rules(unittest.TestCase):
    def test_the_shipped_release_workflow_is_clean(self):
        self.assertEqual(crw.check(crw.DEFAULT[0]), [])

    def test_third_party_action_in_a_signing_job_is_refused_even_pinned(self):
        errs = run(f"""
            permissions:
              contents: read
            jobs:
              publish:
                runs-on: ubuntu-latest
                permissions:
                  contents: write
                  id-token: write
                  attestations: write
                steps:
                  - uses: actions/attest-build-provenance@{GH_SHA} # v1.4.4
                  - uses: softprops/action-gh-release@{SHA} # v2.6.2
            """)
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("softprops/action-gh-release", errs[0])
        self.assertIn("id-token: write", errs[0])

    def test_signing_rights_inherited_from_the_workflow_count(self):
        errs = run(f"""
            permissions:
              id-token: write
            jobs:
              publish:
                runs-on: ubuntu-latest
                steps:
                  - uses: softprops/action-gh-release@{SHA}
            """)
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("job publish", errs[0])

    def test_write_all_counts_as_signing(self):
        errs = run(f"""
            jobs:
              publish:
                runs-on: ubuntu-latest
                permissions: write-all
                steps:
                  - uses: softprops/action-gh-release@{SHA}
            """)
        self.assertEqual(len(errs), 1, errs)

    def test_a_job_of_its_own_without_signing_rights_may_run_it(self):
        errs = run(f"""
            permissions:
              contents: read
            jobs:
              attest:
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                  id-token: write
                  attestations: write
                steps:
                  - uses: actions/attest-build-provenance@{GH_SHA}
              publish:
                needs: attest
                runs-on: ubuntu-latest
                permissions:
                  contents: write
                steps:
                  - uses: softprops/action-gh-release@{SHA}
            """)
        self.assertEqual(errs, [])

    def test_tag_refs_are_refused(self):
        errs = run("""
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: "softprops/action-gh-release@v2"
                  - uses: docker://alpine:3
            """)
        self.assertEqual(len(errs), 3, errs)

    def test_containers_need_a_digest_in_either_form(self):
        errs = run(f"""
            jobs:
              a:
                runs-on: ubuntu-latest
                container: rust:bookworm
                steps: []
              b:
                runs-on: ubuntu-latest
                container:
                  image: rust:bookworm
                services:
                  db:
                    image: postgres:16
                steps: []
              c:
                runs-on: ubuntu-latest
                container: rust:bookworm@{DIGEST}
                steps: []
            """)
        self.assertEqual(len(errs), 3, errs)
        self.assertTrue(all("digest" in e for e in errs), errs)

    def test_choco_install_needs_a_version(self):
        errs = run("""
            jobs:
              w:
                runs-on: windows-latest
                steps:
                  - run: |
                      choco install nasm -y --no-progress
                      choco install nasm --version=3.2.0 -y
            """)
        self.assertEqual(len(errs), 1, errs)

    def test_flow_style_permissions_are_refused_not_guessed(self):
        errs = run(f"""
            jobs:
              publish:
                runs-on: ubuntu-latest
                permissions: {{id-token: write}}
                steps:
                  - uses: softprops/action-gh-release@{SHA}
            """)
        self.assertTrue(any("flow-style" in e for e in errs), errs)


if __name__ == "__main__":
    unittest.main()
