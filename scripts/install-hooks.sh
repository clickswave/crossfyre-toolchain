#!/usr/bin/env bash
# Point this repo's git hooks at the committed .githooks/ directory. Run once
# per clone. First-party developers should run it so the adaptive API-parity
# guard fires on push; a public checkout can run it too (the guard no-ops when
# the private drop-in is absent).
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# When this repo is a submodule, the superproject may already point
# core.hooksPath at its own directory. That setting holds one directory, so
# overriding it here silently turns the superproject's hooks off, and a hook
# there that delegates to this repo's .githooks/pre-push already runs the check
# below. Leave it alone, and say which one is in force.
super="$(git rev-parse --show-superproject-working-tree 2>/dev/null || true)"
current="$(git config --get core.hooksPath || true)"
if [ -n "$super" ] && [ -n "$current" ] && [ "$current" != ".githooks" ]; then
    echo "hooks: core.hooksPath already set to $current by the superproject; left as is."
    echo "  .githooks/pre-push here runs from there, if that hook delegates to it."
    exit 0
fi

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true
echo "hooks installed: core.hooksPath -> .githooks"
echo "  pre-push: adaptive open/private API parity (scripts/check_adaptive_parity.py)"
