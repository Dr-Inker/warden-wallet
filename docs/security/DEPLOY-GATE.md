# Deployment gate (spec §17 L7, plan Task 11 item 5)

`scripts/deploy-gate.sh` is the last automated check before a program upgrade
is broadcast. It is written now (Task 11), runs at L7 (pre-deploy, at the
release SHA), and **refuses to deploy on any mismatch**. This document is its
spec; the script itself implements it, with a `--dry-run` mode that performs
every check that needs no network access and prints the RPC-dependent checks
it *would* run, without making them.

## Status

**SPEC + partial dry-run implementation.** Task 11 is tooling/docs only — no
RPC client library is wired in yet, and no on-chain deployment exists to
check against. The script is safe to run today only in `--dry-run` mode or
against local files; every RPC-dependent check **fails closed** (refuses)
rather than silently passing when the supporting client code isn't wired in.
Wiring the RPC calls for real is follow-up work for whichever task first cuts
a release candidate — see "What's stubbed" below.

## Invocation

```sh
scripts/deploy-gate.sh <program-id> <expected-authority> <squads-multisig> <release-sha> [--dry-run] [--rpc-url <url>]
```

| Argument | Meaning |
| --- | --- |
| `<program-id>` | The warden program's on-chain address (base58 pubkey). |
| `<expected-authority>` | The pubkey the `ProgramData` upgrade authority is expected to equal — normally the same as `<squads-multisig>`'s vault PDA, but passed explicitly so the check is never implicit. |
| `<squads-multisig>` | The Squads multisig account that must own upgrade authority (base58 pubkey). |
| `<release-sha>` | The git SHA being deployed — looked up as a row key in `docs/security/RELEASE-INTEGRITY.md`. |
| `--dry-run` | Perform only the checks that need no RPC (arg validation, local hash lookup, scoped TODO/unimplemented!/#[ignore] grep); print, but do not execute, the RPC-dependent checks. |
| `--rpc-url <url>` | RPC endpoint for the real run. Defaults to `$SOLANA_RPC_URL` if set. Ignored in `--dry-run`. |

Exit code is non-zero if **any** check fails or is unimplemented in a
non-dry-run invocation (fail-closed).

## The five checks (spec §17 L7 / plan Task 11 item 5)

1. **Upgrade authority.** Read the warden `ProgramData` account over RPC and
   assert `upgrade_authority_address` equals `<expected-authority>` (which
   itself should equal, or be verified to be controlled by, `<squads-multisig>`).
2. **Multisig threshold + time-lock.** Fetch `<squads-multisig>`'s config and
   assert `threshold ≥ 3` of `≥ 5` members and `time_lock ≥ 7` days, per spec
   §5.5 ("the BPF-loader upgrade authority **is** a Squads multisig (3-of-5)
   whose proposals carry an on-chain 7-day time lock enforced by the multisig
   program itself").
3. **Adapter selector re-derivation.** Re-derive every adapter selector from
   source — an Anchor sighash from the target program's IDL where one
   exists, and the per-program instruction tag for non-Anchor targets (SPL
   Token/System/Memo/ATA use single-byte/fixed-layout tags, not 8-byte
   discriminators — spec §5.2 rule 1, the selector-derivation rule; DECISION.md
   item C9) — and diff the result against the on-chain `Registry` account.
4. **Release artifact hash.** Assert the deployed `.so`'s sha256 equals the
   row recorded for `<release-sha>` in `docs/security/RELEASE-INTEGRITY.md`.
5. **Shipped-source TODO/unimplemented!/#[ignore] scan.** `git grep` scoped
   to `programs/` and `packages/` **only** (never `docs/`, `spikes/`, or the
   plan — those legitimately contain those strings, and an unscoped grep
   fails permanently and gets disabled, which is worse than not having it)
   for `TODO`, `unimplemented!`, `#[ignore]`; fail on any hit.

## What's stubbed in this Task-11 pass

| Check | `--dry-run` | Real run |
| --- | --- | --- |
| 1. Upgrade authority | Prints the RPC call it would make (`solana program show --url <rpc> <program-id>` or equivalent `getAccountInfo` on the ProgramData PDA) | **Refuses** (`NOT IMPLEMENTED`) — no RPC client wired into this bash script yet |
| 2. Multisig threshold/time-lock | Prints the account it would fetch and the fields it would assert | **Refuses** (`NOT IMPLEMENTED`) — decoding a Squads v4 multisig config account needs the Squads SDK (Anchor account deserialization), not shell tooling; no such dependency exists in this repo yet |
| 3. Adapter selector diff vs on-chain `Registry` | Prints the plan | **Refuses** (`NOT IMPLEMENTED`) — the `Registry` account type does not exist in `programs/warden` as of this task (adapter registry is DECISION.md item C9, still open); there is nothing on-chain to diff against yet |
| 4. `.so` hash vs `RELEASE-INTEGRITY.md` | **Runs for real** — looks up the row locally, compares to a local `target/deploy/warden.so` if present | Same — this check needs no RPC |
| 5. Scoped TODO/unimplemented!/#[ignore] grep | **Runs for real** | Same — this check needs no RPC |

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
- Wire check 3 once `programs/warden` has a `Registry` account (C9) and an
  IDL-driven selector derivation tool exists (spec §5.2 rule 1 follow-up).
- Add an integration test that runs the real checks against a local
  validator fork with a known-good multisig/registry fixture — the plan's
  "no network calls in tests" constraint means this belongs in a separate,
  explicitly-networked test target, not `cargo test`/`pnpm test`.
