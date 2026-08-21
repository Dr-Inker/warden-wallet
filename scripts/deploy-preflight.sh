#!/usr/bin/env bash
# Git-only checkout preflight for the live deploy gate (WRDF-0085/0088). Kept
# SEPARATE from deploy-gate.sh so the security-relevant boundary (clean tree +
# release-sha resolves + ancestor-of-HEAD) is hermetically testable in temporary
# git repositories with no RPC / pnpm / monorepo dependency.
#
# Usage: deploy-preflight.sh <release-sha>
# On success: prints the normalized FULL release commit SHA to stdout, exits 0.
# On refusal: prints "REFUSE: <reason>" to stderr, exits 1.
set -uo pipefail

REL="${1:-}"
if [ -z "$REL" ]; then
  echo "REFUSE: no release-sha given" >&2; exit 1
fi
# A clean tree: uncommitted changes could alter the manifest registry or the gate.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "REFUSE: live run requires a CLEAN working tree (uncommitted changes could alter the manifest or gate code)" >&2
  exit 1
fi
# The release-sha must resolve to a real full commit.
full="$(git rev-parse --verify "${REL}^{commit}" 2>/dev/null || echo '')"
if [ -z "$full" ]; then
  echo "REFUSE: release-sha '${REL}' does not resolve to a commit in this repo" >&2
  exit 1
fi
# A commit cannot contain its own SHA, so the RELEASE-INTEGRITY attestation row
# for the release is added in a LATER reviewed commit. Require the release to be
# an ancestor-or-equal of HEAD (the reviewed commit the gate runs over) — WRDF-0085.
if ! git merge-base --is-ancestor "$full" HEAD 2>/dev/null; then
  echo "REFUSE: release-sha ${full} is not an ancestor of HEAD — the gate must run at a reviewed commit that contains the release + its attestation row (WRDF-0085)" >&2
  exit 1
fi
printf '%s\n' "$full"
