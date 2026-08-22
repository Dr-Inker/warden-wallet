# Deployment gate (spec §17 L7, plan Task 11 item 5)

`scripts/deploy-gate.sh` is the last automated check before a program upgrade
is broadcast. It is written now (Task 11), runs at L7 (pre-deploy, at the
release SHA), and **refuses to deploy on any mismatch**. This document is its
spec; the script itself implements it, with a `--dry-run` mode that performs
every check that needs no network access and prints the RPC-dependent checks
it *would* run, without making them.

## Status

**Checks 1, 2, 3, 4a IMPLEMENTED and fixture-verified (Task 11R + WRD-DEP-02);
live-cluster run UNVERIFIED until a release
candidate exists.** The governance + hash logic is `packages/core/src/deploy`
(`verifyDeployGate`, hand-rolled with no `@sqds` dependency — the gate exists to
shrink supply-chain surface, so it does not add npm surface); the script invokes
it via `packages/core/scripts/deploy-gate-verify.ts`. Two ways to run the RPC
checks: `--fixtures <case>` drives a deterministic in-process scenario (no
network — `happy` passes, every other case tampers with one field so the gate
refuses), and `--manifest <name> --rpc-url <url>` runs the REAL checks against a live cluster
with a pin selected from the COMMITTED manifest registry (WRDF-0085; never an
arbitrary file), on a clean tree with the release-sha an ancestor of HEAD, with the shell's
program/multisig/authority cross-checked. Check 3 (adapter-selector re-derivation vs the on-chain Registry) is now implemented and
fixture-verified as the verifier's `registry-config` check (WRD-DEP-02).
Every RPC-dependent path **fails closed**. The fixture suites are
`packages/core/test/deploy-gate.test.ts` (governance/hash) and
`packages/core/test/deploy-registry.test.ts` (check 3); the byte-exact match against
`solana-verify` on a real cluster, and a golden Registry vector from the real Anchor writer,
are the honest residuals verified at a release candidate.

## Invocation

```sh
# fixture-verified (no network):
scripts/deploy-gate.sh <program-id> <expected-authority> <squads-multisig> <release-sha> --fixtures happy
# live (checks 1/2/3/4a): pin from the COMMITTED manifest registry, clean tree, release-sha an ancestor of HEAD:
scripts/deploy-gate.sh <program-id> <expected-authority> <squads-multisig> <release-sha> --manifest <name> --rpc-url <url>
# dry-run (plan + local checks only):
scripts/deploy-gate.sh <program-id> <expected-authority> <squads-multisig> <release-sha> --dry-run
```

| Argument | Meaning |
| --- | --- |
| `<program-id>` | The warden program's on-chain address (base58 pubkey). |
| `<expected-authority>` | The pubkey the `ProgramData` upgrade authority is expected to equal — normally the same as `<squads-multisig>`'s vault PDA, but passed explicitly so the check is never implicit. |
| `<squads-multisig>` | The Squads multisig account that must own upgrade authority (base58 pubkey). |
| `<release-sha>` | The git SHA being deployed — looked up as a row key in `docs/security/RELEASE-INTEGRITY.md`. |
| `--dry-run` | Perform only the checks that need no RPC (arg validation, local `.so` hash lookup/comparison per 4b, scoped TODO/unimplemented!/#[ignore] grep per check 5); print, but do not execute, the RPC-dependent checks (1, 2, 3, 4a). **The final banner in `--dry-run` always reads `DRY RUN — NOT VERIFIED`, never `ALL CHECKS PASSED`** — a dry run is a shape check on the tool, not a deploy verdict. |
| `--rpc-url <url>` | RPC endpoint for the real run. Defaults to `$SOLANA_RPC_URL` if set. Ignored in `--dry-run`. |
| `--fixtures <case>` | Run checks 1/2/3/4a against a deterministic in-process scenario (no RPC); `happy` passes, others refuse. |
| `--manifest <name>` | Live run only: select the pin BY NAME from the COMMITTED `MANIFESTS` registry (`config.ts`), never a file. Requires a CLEAN tree with the release-sha an ANCESTOR-OR-EQUAL of HEAD (a commit cannot contain its own SHA, so the RELEASE-INTEGRITY attestation row for C is added in a later reviewed commit — WRDF-0085); the verifier parses that row for the unique manifest name+digest and artifact hash. The per-proposal governance audit fails closed in-tool with no bypass (WRDF-0028). |

Exit code is non-zero if **any** check fails or is unimplemented in a
non-dry-run invocation (fail-closed).

## The five checks (spec §17 L7 / plan Task 11 item 5)

1. **Upgrade authority.** Read the warden `ProgramData` account over RPC and
   assert `upgrade_authority_address` equals `<expected-authority>` (which
   itself should equal, or be verified to be controlled by, `<squads-multisig>`).
2. **Multisig governance — spec-exact, not a floor on threshold/membership.**
   Fetch `<squads-multisig>`'s config and assert `threshold == 3` **and**
   `member_count == 5` (spec §5.5: "the BPF-loader upgrade authority **is** a
   Squads multisig (**3-of-5**)" — a fixed shape the spec authorized, not a
   minimum; a 4-of-7 multisig is nominally "stronger" but is not what was
   reviewed and must still refuse) **and** `time_lock ≥ 7` days (the one
   field that genuinely is a floor — a longer lock is strictly safer than
   the spec's minimum, so `>=` is correct there and only there).
3. **Adapter selector re-derivation.** Re-derive every adapter selector from
   source — an Anchor sighash from the target program's IDL where one
   exists, and the per-program instruction tag for non-Anchor targets (SPL
   Token/System/Memo/ATA use single-byte/fixed-layout tags, not 8-byte
   discriminators — spec §5.2 rule 1, the selector-derivation rule; DECISION.md
   item C9) — and diff the result against the on-chain `Registry` account.
4. **Release artifact hash — on-chain is authoritative.** The primary
   comparison is the sha256 of the **on-chain** program (dumped via RPC in
   live mode — e.g. `solana-verify get-program-hash` or a raw
   `getAccountInfo` of the ProgramData code buffer) against the row recorded
   for `<release-sha>` in `docs/security/RELEASE-INTEGRITY.md`. A local
   `target/deploy/warden.so` sha256 comparison runs alongside it as a
   best-effort sanity check, never a substitute: a **missing local `.so` is
   a FAILURE**, not a pass-through — a deploy gate that shrugs at "nothing
   to check locally" and lets the check pass is exactly the silent-pass
   failure mode this gate exists to close.
5. **Shipped-source TODO/unimplemented!/#[ignore] scan.** `git grep` scoped
   to `programs/` and `packages/` **only** (never `docs/`, `spikes/`, or the
   plan — those legitimately contain those strings, and an unscoped grep
   fails permanently and gets disabled, which is worse than not having it)
   for `TODO`, `unimplemented!`, `#[ignore]`; fail on any hit.

## Implementation status by check (post Task 11R)

| Check | `--dry-run` | `--fixtures <case>` | Live (`--manifest` + `--rpc-url`) |
| --- | --- | --- | --- |
| 1. Upgrade authority (+ Program→ProgramData chain, vault-PDA binding) | Prints the plan | **Runs** — `verifyDeployGate` over a deterministic scenario | **Runs** the real check; UNVERIFIED until a release candidate |
| 2. Squads governance (pinned identity + owner/discriminator + 3-of-5 exact + member set + masks + 7-day floor + autonomous configAuthority + no stale state) | Prints the plan | **Runs** | **Runs**; UNVERIFIED until release |
| 3. Adapter selector diff vs on-chain `Registry` (`WRD-DEP-02`) | Prints the plan | ✅ implemented + fixture-verified | Authenticates the Registry PDA (owner + `Registry` discriminator + version) and diffs its complete config — every selector RE-DERIVED from source, `role_rules`, list membership, and `treasury` — rejecting any missing/extra/wrong/duplicate entry (gate.ts `registry-config`; @d8e8fce). Live-cluster byte-exact parity + a real mainnet treasury pin remain UNVERIFIED until a release candidate. |
| 4a. On-chain program-code hash vs `RELEASE-INTEGRITY.md` | Prints the plan | **Runs** (sha256 over the trimmed ELF) | **Runs**; byte-exact `solana-verify` parity UNVERIFIED until release |
| 4b. Local `target/deploy/warden.so` hash (best-effort sanity) | **Runs for real** — fails if the `.so` is missing (no silent pass) | Same | Same — no RPC |
| 5. Scoped TODO/unimplemented!/#[ignore] grep | **Runs for real** | Same | Same — no RPC |

The governance + hash + registry logic (checks 1/2/3/4a) lives in `packages/core/src/deploy`
and is exercised by the fixture suites `packages/core/test/deploy-gate.test.ts` +
`packages/core/test/deploy-registry.test.ts`;
the script wires it through `run_gov_hash_verifier` →
`packages/core/scripts/deploy-gate-verify.ts`.

**Hardened after the Task 11R round-1 review (WRDF-0085/0086/0087):**
- **The pin cannot weaken the spec floors.** `assertPinSpecFloors` refuses any pin
  whose threshold ≠ 3, member count ≠ 5, time-lock < 7 days, or config authority ≠
  default — so a tampered or mis-selected manifest can never pass with a 1-of-1 /
  0-lock / controlled-config shape.
- **The cluster is authenticated.** The gate binds the RPC's genesis hash to
  mainnet-beta, so an attacker-controlled fork that serves fabricated accounts
  satisfying every pin is refused. Live mode also cross-checks the shell's
  positional program-id/multisig against the pin (`--expect-warden-program`,
  `--expect-multisig`).
- **Terminal governance history is permitted.** The stale check no longer requires
  a pristine `transaction_index == 0` (which made the gate unusable on any real,
  previously-used multisig and at the moment of a Squads-mediated upgrade). It
  permits terminal history and flags only an inconsistent stale boundary; the
  per-proposal actionable-stale enforcement is trust-rooted at the pinned Squads
  code hash, with a live-chain Proposal/VaultTransaction/ConfigTransaction sweep as
  the documented residual.
- **Fixtures use independent golden vectors** (the vault PDA and the Multisig
  discriminator), not the production derivations under test, and require executable
  Program accounts — so a seed/discriminator/index-encoding regression is caught.

**Hardened again after the Task 11R round-2 review (WRDF-0085/0028):**
- **The pin is a COMMITTED manifest, not a runtime file.** Live mode selects a pin
  BY NAME from the reviewed-source `MANIFESTS` registry (`config.ts`); there is no
  `--pin <file>` arbitrary-JSON path any more. deploy-gate.sh forwards the REQUIRED
  `--expect-warden-program` / `--expect-multisig` / `--expect-authority`, and the
  verifier refuses unless program+multisig match the manifest and the authority is
  the manifest's derived vault PDA.
- **RPC trust model (stated, not assumed authentication).** The genesis-hash bind
  catches a wrong-cluster misconfiguration. It is NOT proof against an actively-
  malicious RPC that reports mainnet genesis while serving fabricated accounts —
  a malicious endpoint is OUT of the gate's threat model, mitigated operationally
  by a known-good endpoint / multi-RPC quorum. This is documented, not silently
  treated as cluster authentication.
- **Per-proposal governance-state audit is a fail-closed REQUIRED LIVE STEP
  (WRDF-0028), not silently passed.** The config-level checks (identity, 3-of-5,
  masks, time-lock, autonomous authority, code hash) are the rigorous automated
  part. Enumerating every Proposal / VaultTransaction / ConfigTransaction / batch
  between the stale boundary and `transaction_index`, accepting only conclusively-
  terminal history, and binding the intended release proposal to its reviewed
  digest is a live-release step the tool does not perform in-process. Live mode is
  **unconditionally REFUSED on this check** — there is NO attestation flag or
  bypass (a plain string would verify nothing, WRDF-0028 round 3). The live gate
  cannot pass the proposal audit until machine-verifiable proposal enumeration +
  release-digest binding are implemented; that is the honest, fail-closed state.

**Licensing:** the Squads wire-format reader is carried UNRESOLVED for owner/counsel
(WRDF-0089, AGPL-3.0 / reference-only prior art) — see `THIRD_PARTY_NOTICES.md`.

A check that "refuses" prints `REFUSE: <reason>` and the script exits
non-zero — this is deliberate fail-closed behavior, not a bug: an
unimplemented safety check must never be treated as a passing one on a
real deploy-gate invocation. `--dry-run` is always safe to run (no network
calls, matching the plan's "no RPC calls in tests" requirement) and is what
CI or a developer should run today to exercise the script's shape.

## Follow-up (tracked, not done here)

- Wire check 1 via `@solana/web3.js` or the `solana` CLI's JSON output
  (`solana program show --url <rpc> <program-id> --output json`).
- Wire check 2 via `@sqds/multisig` (Squads v4 TypeScript SDK) once it's a
  dependency somewhere in `packages/`, or a Rust equivalent.
- Check 3 is implemented (WRD-DEP-02). Residual, tracked for a release candidate: a golden
  Registry byte vector produced by the REAL Anchor writer (the current fixtures round-trip an
  independent encoder), and consuming the pinned Jupiter IDL by hash to auto-extract instruction
  names rather than pinning the reviewed name constants in source.
- Add an integration test that runs the real checks against a local
  validator fork with a known-good multisig/registry fixture — the plan's
  "no network calls in tests" constraint means this belongs in a separate,
  explicitly-networked test target, not `cargo test`/`pnpm test`.
