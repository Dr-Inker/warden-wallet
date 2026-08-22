#!/usr/bin/env bash
# Test-only `tsx` shim for the hermetic deploy-gate wiring test (WRDF-0088/0092).
# The gate invokes  <repo>/packages/core/node_modules/.bin/tsx <verifier.ts> <va…>
# so $1 is the verifier ENTRYPOINT path and the rest are the verifier args.
# Injection happens via the TEST's OWN temp-repo toolchain — NOT the caller's PATH
# and NOT an env override; the production gate is un-shadowable that way.
# It authenticates the ENTRYPOINT (records argv[1] so the test asserts the gate ran the
# real committed verifier path, not a decoy — WRDF-0088 round 10) AND enforces the
# verifier's real flag/value contract so a renamed/missing/reordered flag fails HERE
# instead of passing silently, recording the exact args of BOTH parse and live modes.
entry="${1:-}"
[ -n "$entry" ] || { echo "fake-verifier: no entrypoint argv[1]" >&2; exit 2; }
[ -f "$entry" ] || { echo "fake-verifier: entrypoint does not exist: $entry" >&2; exit 2; }
printf '%s\n' "$entry" > "$FAKE_ENTRY_FILE"
va=("${@:2}")   # the verifier args (after the entrypoint path)
declare -A m; i=0
while [ $i -lt ${#va[@]} ]; do
  k="${va[$i]}"; v="${va[$((i+1))]:-}"
  [[ "$k" == --* ]] || { echo "fake-verifier: stray arg $k" >&2; exit 2; }
  m["${k#--}"]="$v"; i=$((i+2))
done
if [ -n "${m[parse-release-hash]:-}" ]; then
  # Parse mode must carry BOTH release bindings (WRDF-0088).
  [ -z "${m[release-sha]:-}" ] && { echo "fake-verifier: parse mode missing --release-sha" >&2; exit 2; }
  [ -z "${m[release-integrity-file]:-}" ] && { echo "fake-verifier: parse mode missing --release-integrity-file" >&2; exit 2; }
  printf '%s\n' "${va[@]}" > "$FAKE_PARSE_ARGS_FILE"
  echo "$FAKE_ARTIFACT_HASH"; exit 0
fi
for req in rpc-url manifest release-sha release-integrity-file expect-warden-program expect-multisig expect-authority; do
  [ -z "${m[$req]:-}" ] && { echo "fake-verifier: missing --$req" >&2; exit 2; }
done
[ "${m[manifest]}" = "synthetic" ] || { echo "fake-verifier: wrong manifest ${m[manifest]}" >&2; exit 2; }
printf '%s\n' "${va[@]}" > "$FAKE_ARGS_FILE"
exit "${FAKE_VERIFIER_EXIT:-0}"
