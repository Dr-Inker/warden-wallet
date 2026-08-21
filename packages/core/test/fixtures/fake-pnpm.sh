#!/usr/bin/env bash
# Test-only `pnpm` shadow for the hermetic deploy-gate wiring test (WRDF-0088/0092).
# Intercepts `pnpm --filter @warden/core exec tsx scripts/deploy-gate-verify.ts <va…>`
# and ENFORCES the verifier's real flag/value contract, so a renamed/missing/reordered
# flag from deploy-gate.sh fails here instead of passing silently.
#   - parse mode  → echo $FAKE_ARTIFACT_HASH
#   - live mode   → require every expected --k v pair (else exit 2), record the exact
#                   verifier args to $FAKE_ARGS_FILE, and exit $FAKE_VERIFIER_EXIT
args=("$@"); idx=-1
for i in "${!args[@]}"; do [ "${args[$i]}" = "scripts/deploy-gate-verify.ts" ] && idx=$i && break; done
[ "$idx" -lt 0 ] && { echo "fake-pnpm: not a deploy-gate-verify call: $*" >&2; exit 3; }
va=("${args[@]:$((idx+1))}")
declare -A m; i=0
while [ $i -lt ${#va[@]} ]; do
  k="${va[$i]}"; v="${va[$((i+1))]:-}"
  [[ "$k" == --* ]] || { echo "fake-pnpm: stray arg $k" >&2; exit 2; }
  m["${k#--}"]="$v"; i=$((i+2))
done
if [ -n "${m[parse-release-hash]:-}" ]; then echo "$FAKE_ARTIFACT_HASH"; exit 0; fi
for req in rpc-url manifest release-sha release-integrity-file expect-warden-program expect-multisig expect-authority; do
  [ -z "${m[$req]:-}" ] && { echo "fake-pnpm: missing --$req" >&2; exit 2; }
done
[ "${m[manifest]}" = "synthetic" ] || { echo "fake-pnpm: wrong manifest ${m[manifest]}" >&2; exit 2; }
printf '%s\n' "${va[@]}" > "$FAKE_ARGS_FILE"
exit "${FAKE_VERIFIER_EXIT:-0}"
