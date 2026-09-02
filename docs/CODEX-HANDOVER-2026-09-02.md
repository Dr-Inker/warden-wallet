# Codex Handover — 2026-09-02 — post-Fable-audit remediation, review debt, owner decisions

> `TO / TASK / CWD / BASE / READ / WRITE (edit lease) / DO_NOT_TOUCH / ACCEPT / SIDE_EFFECTS / RETURN`
>
> - **TO:** Codex (gpt-5.6-sol @ max — the only reviewer configuration Warden accepts for a
>   recorded round; never `terra`, never a lower effort; see `~/.claude` memory
>   `feedback_codex_sol_max_warden`).
> - **TASK:** (1) run the OWED adversarial review rounds over the 2026-08-23 → 2026-09-02 core +
>   extension + program work in the chunk order of §3, recording every round through
>   `scripts/review.sh` so it lands in `REVIEW-RUNS.jsonl`; (2) adjudicate and fix what those
>   rounds find, RED-test-first, flipping scorecard rows only with the three remediation fields;
>   (3) do NOT take any of the §5 owner decisions — record them, ask, stop.
> - **CWD:** `/opt/warden` (branch `phase1b`, the only working branch; `main` is stale and is not
>   the integration target).
> - **BASE:** `LEDGER_CLOSE_SHA` = the ledger close commit of the Fable session (this memo's
>   parent). Everything in §2 is reachable from it. Fable audit report:
>   `docs/security/FABLE-AUDIT-2026-09-02.md`.
> - **READ:** this memo top to bottom; `docs/security/FABLE-AUDIT-2026-09-02.md` §2 (findings
>   table) and §4 (recommended order); `docs/security/INVARIANTS.md` rows WRD-EXEC-13/14,
>   WRD-EXT-03..06, WRD-REL-04/05 — their `notes` are the honest LIMITS text and name every
>   owner decision; `docs/security/REVIEW-SCORECARD.jsonl` rows WRDF-0109..0111 (thread
>   `06aac9dfd711-20260902T044843Z`); `scripts/review.sh` header (the 40-line comment IS the
>   protocol); `docs/security/CODEX-CONTENT-FILTER-MEMO-2026-08-23.md`.
> - **WRITE (edit lease):** `programs/warden/src/**`, `programs/warden/tests/**`,
>   `packages/core/src/**`, `packages/core/test/**`, `apps/extension/src/**`,
>   `apps/extension/test/**`, `apps/extension/browser/**`, `apps/extension/scripts/**`,
>   `docs/security/invariants.jsonl` + regenerated `INVARIANTS.md`, `docs/security/THREATMODEL.md`,
>   `docs/security/REVIEW-RUNS.jsonl` + `REVIEW-SCORECARD.jsonl` (ONLY via
>   `scripts/append-review-run.mjs` / `scripts/review.sh`, plus the remediation-field flip of §4.3),
>   `docs/program/PHASE1B-MEASUREMENTS.md`, `docs/NEXT-SESSION.md`, `CLAUDE.md` (facts only).
> - **DO_NOT_TOUCH:** see §8 — `.superpowers/**` except `.superpowers/reviews/` artefacts the
>   review scripts write; `/var/www/**`; any keypair, `.env`, trust store, `release-pubkeys/`,
>   `release-pins.json` VALUES; `spikes/**` (never import from it); `main` branch; git tags;
>   remote pushes; signing.
> - **ACCEPT:** every §3 round is either recorded in `REVIEW-RUNS.jsonl` or its failure is written
>   down with the exact blocker (§3.5); every ACCEPTED finding has a RED-then-GREEN test and a
>   scorecard row flipped per §4.3; `bash .claude/test-gate.sh` exit 0 at the final SHA, reported
>   with the counts and the SHA; `node scripts/gen-invariants.mjs --check` clean; no owner
>   decision silently taken.
> - **SIDE_EFFECTS:** none outside the repo and `.superpowers/reviews/`. No push, no tag, no
>   sign, no publish, no deploy, no key material, no store upload.
> - **RETURN:** the §9 report shape, appended to `docs/NEXT-SESSION.md` under a new dated memo AND
>   as your final message.

---

## 1. Why this memo exists

A Fable 5 audit ran on 2026-09-02 (`docs/security/FABLE-AUDIT-2026-09-02.md`; 31 findings) and the
same session then executed the audit's recommended remediation order. The product fixes are in
(§2). What is NOT done — and is yours — is the assurance debt the audit rated **High (process)**:

- **R-1:** the review ledger stops at 2026-08-23. Between `77a8273` and `LEDGER_CLOSE_SHA` there
  are ~350 first-parent commits (~29k product-code lines across `packages/core`, `apps/extension`,
  `programs`) with exactly ONE recorded Codex round (P-1 round 1, 3 findings). The C1–C75 client
  cycles of 2026-08-30 → 2026-09-01 (keyring, MV3 boundary, provider pipeline, approval, release
  tooling) have never been adversarially reviewed at all.
- **P-1 round 2 is owed:** the fixes for WRDF-0109/0110/0111 (`2ddf781`, `14ee34b`, `30e32fe`)
  were sent to `scripts/review.sh` twice and blocked by the OpenAI cyber content filter both times;
  `scripts/review-grok.sh` was tried twice and the anti-silence validator correctly rejected both
  Grok artefacts. Nothing was recorded for round 2. The WRD-EXEC-14 ledger note says so.
- **The 2026-08-23 Codex round over `c5a4514..77a8273` is still owed** (only the Grok fallback,
  round 101, is recorded — see the calibration caveat in `CLAUDE.md`).

The Fable session's own code (§2) has been reviewed by nobody but its author. Treat it with the
same suspicion as the C-cycles.

## 2. Exact state at BASE

Branch `phase1b`, clean tree. Commits since the audit report landed (`06aac9d`), oldest first —
every one made with `git -c core.hooksPath=/dev/null commit` (pre-commit gate bypassed; the FULL
gate was run separately, see §2.3):

| SHA | What | Audit ID | Ledger |
|---|---|---|---|
| `3766e24` | program: generic `execute` refuses foreign token accounts delegated to the vault (err 6078) | P-1 | WRD-EXEC-13 |
| `06aac9d` | audit report + WRD-EXEC-13 row + WRD-CAP-01/09 caveats | — | — |
| `27039aa` | extension: keyring record adoption compares the full pinned context (`expected-keyring-context.ts`, `KeyringLifecycleOptions.expectedContext` required) | K-1 | WRD-EXT-03 |
| `3ae308c`, `6885b73` | K-1 ledger + regen | K-1 | — |
| `039ab87` | hygiene: P-3 stale `transcript.rs` comment, K-8 CLAUDE.md, R-2 (clippy `-D arithmetic_side_effects` + supply-chain gate now IN `.claude/test-gate.sh`), R-5 | P-3/K-8/R-2/R-5 | — |
| `a4c134e`, `0757d7d` | release: producer `git` children use `/usr/bin/git`, allow-listed env, timeout | E-1 | WRD-REL-04 |
| `2ddf781` | program: signer-slot (logical[1]) snapshot + vault-member `Multisig` gate (err 6079) | WRDF-0109/0110 | WRD-EXEC-13 widened, WRD-EXEC-14 |
| `14ee34b` | program: multisig gate re-applied AFTER the CPIs (a payload can create the multisig) | WRDF-0110 | WRD-EXEC-14 |
| `30e32fe` | ledger: WRD-EXEC-14, WRDF-0111 prior-art id corrected, Codex round 1 recorded | WRDF-0111 | — |
| `583f9ec`, `4d964d5` | CI `release-verify` job runs the three anchored verifiers against committed pins (`apps/extension/scripts/release-pins.mjs`, `release-pins.json` PLACEHOLDER) | E-4 | WRD-REL-05 |
| `699beec` | extension: approval arm/dwell/isTrusted guard (`src/approval/approval-arm.ts`, 600 ms) + randomised window placement inside 1024×768 | A-1 | WRD-EXT-04 |
| `215663f` | extension: eager unlock expiry via `chrome.alarms` (`warden.unlock-session.expiry`); manifest gains `alarms`; `main.ts` throws if `chrome.alarms` is absent | A-2 | WRD-KEY-03 note |
| `e0e5549` | A-1/A-2 ledger + THREATMODEL row | — | — |
| `d1007f1` | browser lane (Playwright) adapted to K-1 pin + A-1 arming — TEST CHANGES ONLY, no product code | — | — |
| `69a6282` | extension: X-1 capability-bound terminal settlement (MessagePort handshake) + X-2 per-origin caps (`provider-origin-capacity.ts`) | X-1/X-2 | WRD-EXT-05/06 |
| `243f469` | X-1 handshake made claim-then-grant (real-Chromium lane refuted the push direction: 7/15 browser tests failed) | X-1 | WRD-EXT-05 |
| `e8365a7` | WRD-EXT-05/06 rows + THREATMODEL row | — | — |
| `LEDGER_CLOSE_SHA` | scorecard flip WRDF-0109..0111 (`remediation_verified: true` with gate evidence), WRD-EXEC-14 note records the un-recordable round 2, evidence SHAs repointed from worktree commits to their phase1b cherry-picks (§7.6) | — | — |

Ledger totals at BASE: 97 invariants — 64 `test-covered`, 32 `unimplemented`, 1 `llm-asserted`.
Scorecard: 236 rows, WRDF-0001..0111. REVIEW-RUNS: last recorded round is thread
`06aac9dfd711-20260902T044843Z` (P-1 round 1).

### 2.1 What the extension fixes do and do NOT do (read before reviewing them)

- **K-1** `apps/extension/src/background/expected-keyring-context.ts` pins `solana:mainnet`
  genesis + program id as byte literals; `keyring-lifecycle.ts` `contextForRecord` throws
  `KeyringAuthError` when a record's origin/genesisHash/programId differ. Consequence you will see
  in tests: a wake-time `restore()` of a mismatched record rejects `runtimeBoundariesReady`, sets
  `disposed=true`, and `onStorageChanged` then no longer calls `keyringOwner.lock()`. `account` is
  deliberately not compared.
- **A-1** the arming decision is a pure module (`approval-arm.ts`) fed by `main.ts`; arm requires
  review response + focus settled + a trusted `pointermove` after focus + 600 ms dwell; a click is
  accepted only with a trusted pointerdown/up pair at-or-after `armAt`, or Enter/Space. **A
  keyboard-only user can never arm** (§5). `canApprove` is still false in production.
- **A-2** the alarm is only the OCCASION; the lazy `isUnlocked`/`assertActive` check remains the
  authority. No real `chrome.alarms` delivery was measured.
- **X-1/X-2** are on an UNSHIPPED pipeline: `scripts/build.mjs` keeps
  `page/provider-request-owner.ts` off both bundles and `content/provider-content-transport.ts`
  off the content bundle; `dist/content.js` is byte-identical to pre-X-1. Handshake: the page
  owner posts exactly one `warden:provider:capability-request` claim at construction; the content
  owner answers the FIRST claim per document with a transferred `MessagePort`, never a second.
  First-wins on both halves; a hostile first claimant = suppression (accepted C1 residual), not
  settlement. Caps: windows 1/(origin,documentId) & 4/origin of 16; flows 4/32; approval requests
  4/32; journal rows 16/128 — POLICY numbers, no load data.
- **P-1 + WRDF-0109/0110**: `programs/warden/src/conservation/compare.rs`
  `reject_vault_delegated_foreign_accounts` + `reject_vault_multisig_members`; call sites in
  `instructions/execute.rs` over logical[1..] (signer slot included) BEFORE the CPIs and AGAIN after
  the last CPI. Errors 6078 / 6079. RED reproductions were live drains against the shipped `.so`.

### 2.2 Worktrees / branches

The Fable session integrated its work via cherry-pick from five `audit/*` worktree branches. At
handover the worktrees `/opt/warden-wt-a12`, `/opt/warden-wt-x12` are removed and the `audit/*`
branches deleted (§7.6 explains the SHA repoint that made that safe). If `git worktree list`
shows anything but `/opt/warden`, do not use it — build artefacts in a worktree symlink
`node_modules` back to `/opt/warden` and produce false "esbuild input escapes the repository" reds.

### 2.3 Gate evidence at BASE

The FULL gate (`bash .claude/test-gate.sh`) at `e8365a7` — see the scorecard rows
WRDF-0109..0111 `remediation_gate_cmd` for the exact counts; the first run of it failed ONLY in
the L9 supply-chain lane on an HTTP 401 while `cargo deny` fetched the RustSec advisory DB (§7.9),
every product lane green; the DB was refreshed and the full gate re-run green. Product-lane counts
at that SHA: `@warden/core` 700, `@warden/extension` 700 vitest + 15 Playwright, Rust
`cargo test --workspace --features test-jup` all green, clippy `-D arithmetic_side_effects`
clean.

## 3. The review rounds you owe — in this order

All rounds: `scripts/review.sh <base> <head> --kind task-diff`, clean tree, HEAD checked out AT
`<head>` (the script refuses otherwise). Model/effort default to `gpt-5.6-sol`/`max` — do not pass
`--model`/`--effort`. Every round seeds the whole invariant ledger; silence on a seeded invariant
fails validation, so a "no findings" artefact must still rule on every row.

The range `77a8273..LEDGER_CLOSE_SHA` is far too large for one prompt (Codex runs `git diff`
itself inside a read-only sandbox). It is pre-cut below at natural cycle boundaries with the
product-code line count so you can judge context. If a chunk still blows context or the content
filter, split it at a `feat(...)`/`fix(...)` commit boundary and record BOTH halves; never drop a
sub-range silently.

| # | base..head | commits | product +/- | What it is | Why it matters |
|---|---|---|---|---|---|
| R0 | `06aac9d..LEDGER_CLOSE_SHA` | ~19 | +2.7k / −0.1k | THE FABLE SESSION'S OWN FIXES (§2 table). Includes `2ddf781`+`14ee34b` = **discharges the owed P-1 round 2** if it records. | Unreviewed security fixes in program + extension + release tooling; author-only eyes. Do this FIRST. |
| R1 | `77a8273..d5a8117` | 38 | +6.4k / −0.1k | C1–C6: keyring dual-KEK envelope + persistent record (`packages/core/src/keyring/`), MV3 session boundary, sender classification, zero-privilege provider ports, lazy page bridge, persistent keyring record ownership, session↔record binding, keyring activation authentication, Argon2 async unlock | Trust-boundary code; WRD-KEY-01..04, WRD-EXT-01..03 |
| R2 | `d5a8117..54bc05d` | 19 | +8.9k / −0.03k | C7–C10: approval record substrate (IndexedDB), worker-startup cleanup, strict Solana tx envelope parse, session message prepare/finalize/order, memo intent decode, pinned authority snapshots, blockhash RPC binding, committed session releases (`packages/core/src/session-*`) | The signing path; WRD-APR-*, WRD-SIG-01 (still `unimplemented` on purpose) |
| R3 | `54bc05d..9c6f1c0` | 15 | +4.5k / −0.16k | C11: approval review surface + lifetime, approval window lifecycle, provider leases bound to approval prep, keyring identity bound to committed release, approvals bound to keyring revocation | Approval→signing binding |
| R4 | `9c6f1c0..de0d964` | 48 | +10.9k / −0.09k | C12–C26: provider operation journal/replay, approval bound before opening, page request settlement owner, exact approval action, signed result flow, terminal outcomes, transport recovery, Port replacement, delivery settlement; C22/C26 full-gate evidence | The pipeline X-1/X-2 later patched; largest chunk — expect to split (suggest at `322c28b`) |
| R5 | `de0d964..eddc0f8` | 60 | +5.1k / −0.02k | C27–C43: release tooling — immutable action pins, static source evidence, signed release source tag (`release-source-tag.mjs`), signing-key slice, signed dual evidence | E-1/E-2/E-3/E-5 live here; verify the E-1 fix (`a4c134e`) does not regress the verifier's own env pinning at lines ~675-686 |
| R6 | `eddc0f8..0dadc1e` | 144 | +1.1k / −0.09k | C44–C75: verifier hardening cycles (descriptor sealing, path identity, bounded input, private cwd, unzip child) — mostly docs/tests, small product delta | Low code volume, high commit count; one round is enough |
| R7 | `0dadc1e..06aac9d` | 6 | +0.3k / −0.0k | P-1 fix `3766e24` + audit docs | ALREADY REVIEWED as P-1 round 1 (`25185205..06aac9d`, thread `06aac9dfd711-20260902T044843Z`). Skip unless you split R0 and want a contiguous chain. |
| R8 | `c5a4514..77a8273` | — | — | The 2026-08-23 range recorded only by Grok (round 101). Owed since 08-23. | Content filter blocked it 3× then; try once more (§3.5). |

Full SHAs: `77a82735834a18d24202af77dd196df2e3155d42`, `d5a8117fec0ac8ae0e268213c7c1aae6d8f376b7`,
`54bc05dc5adbbbd9b9a37f08cdf405b5fd66c4fa`, `9c6f1c0be244534a9bbd99075f2a673cc2ac36e6`,
`de0d9649d40b0dabab62ea6568c533eb630fb53d`, `eddc0f88faaeff42a97d2a0eb78b99f4b8b3cda9`,
`0dadc1ed8101ca57ea9907005c43b5df89e5aa29`, `06aac9dfd711eead2ee8dbc00204ee0600710bf1`,
`c5a4514ab5e36faa6b4450bad7103f3f1cb5a7ca`.

### 3.1 Per-round mechanics (do not improvise)

1. `git status --porcelain` must be empty; `git rev-parse HEAD` must equal `<head>`. For R1–R6 that
   means `git checkout <head>` in a DETACHED state, run the round, then `git checkout phase1b`.
   The append step writes to the ledgers in the working tree — on a detached HEAD those writes
   land on the detached checkout. So: after the round, `git stash` is NOT the tool; instead copy
   the two appended lines out (`tail -1 docs/security/REVIEW-RUNS.jsonl`, the new
   `REVIEW-SCORECARD.jsonl` rows) → `git checkout -- docs/security` → `git checkout phase1b` →
   re-append them by re-running `node scripts/append-review-run.mjs <artefact> --expect <expect>
   --kind task-diff` on `phase1b` (it refuses replays by artefact sha256, so do NOT paste lines by
   hand; if it refuses because the row already exists, you already have it). Simpler alternative
   that avoids all of this: review R1–R6 in one sitting using `--dry-run` on the detached head to
   assemble the prompt, then run the real round from `phase1b` HEAD ONLY for R0 — no: the script
   refuses a head that is not HEAD. Use the detached-checkout procedure.
2. Artefacts land in `.superpowers/reviews/<thread>.json` (+ `.raw.json`, `.expect.json`,
   `.prompt.txt`). They are the evidence base; never edit them.
3. Validation is independent of the model's self-report (`--validate <f.json> --expect <f>`).
   A rejected artefact is NOT a recorded round. Say so.
4. Commit the ledger append on `phase1b` with `docs(security): record Codex round <thread> over
   <base>..<head>`; `git add -A` FIRST (§7.1).

### 3.2 Adjudication

For every finding in a recorded round, the scorecard row is written by the append script with
`ruling: null`. You must then set `ruling` ∈ {`adopted`, `disputed`, `scoped-out`}, `ruled_by`
(`"Codex gpt-5.6-sol@max via <session id>"` — never claim a human ruled; R-3 in the audit is that
0 of 233 rows carry a human ruling, and that stays true until the owner rules), and `rationale`.
Disputes must cite the code line that refutes the claim; scoped-out must cite the plan/spec line
that defers it. `truth_status` and `evidence_type` are separate axes — a finding can be
CONFIRMED by `static_trace` and still not `adopted` if it is out of scope; say which.

### 3.3 Fixing

RED first: a failing test at the pre-fix SHA that names the finding id in its test name
(`codex_wrdf0NNN_…` in Rust, `"WRDF-0NNN …"` in vitest). Watch it fail. Then the minimal fix.
Then the FULL gate. Program fixes: `checked_*` arithmetic only, no `unimplemented!`, and every
new error code gets a `errors.rs` entry + `docs/security/invariants.jsonl` mention. TS amounts
are `bigint`. Re-run the round over the fix range (this is the "round N+1" the ledger expects;
converge to a 0-finding round before calling anything done).

### 3.4 What counts as "the round could not be recorded"

Only these, each written into the relevant invariant's `notes` and into §9:
- OpenAI content filter refused (the exact `codex exec` stderr line, retried ONCE after ~5 min);
- `scripts/review.sh --validate` rejected the artefact (paste the validator's first error line);
- `codex exec` exit ≠ 0 for infrastructure reasons (paste the line).
"Codex found nothing" is NOT this — that is a recorded 0-finding round.

### 3.5 Content-filter handling

Drain-proving regressions (`programs/warden/tests/execute.rs` `fable_p1_*`,
`codex_wrdf0109_*`, `codex_wrdf0110_*`) have tripped the OpenAI cyber content filter repeatedly.
Protocol: retry once; if blocked again, try a SMALLER range that excludes the test file
(review the fix and the test in separate rounds — the fix range `programs/warden/src` alone
usually passes); if still blocked, fall back to `scripts/review-grok.sh <base> <head>` and
label the round as the Grok fallback in the ledger note (calibration caveat: Grok is materially
shallower; it does not discharge the Codex debt, it only records that a review happened). A
persistent block on ledger-only scaffolding ranges is a convergence signal, not a bug to fight
(`docs/security/CODEX-CONTENT-FILTER-MEMO-2026-08-23.md`).

## 4. Ledger rules (the validator enforces these; learn them before you touch the files)

### 4.1 `docs/security/invariants.jsonl`

- One JSON object per line, written by Python `json.dumps(row, ensure_ascii=False)` DEFAULT
  separators (`", "` and `": "`). **Do not reformat to compact JSON** — a worker did that in this
  session and every subsequent cherry-pick conflicted on all 97 lines.
- Every `evidence[].sha` and every 40-hex SHA in `notes` MUST be a commit reachable from
  `phase1b` HEAD that actually CONTAINS the cited test (a cherry-picked commit has a new SHA; a
  worktree SHA is garbage once the branch is deleted). Check with:
  `python3 -c` over the file + `git merge-base --is-ancestor <sha> HEAD` (§7.6 has the snippet).
- After any edit: `node scripts/gen-invariants.mjs` regenerates `INVARIANTS.md`; commit both.
  `node scripts/gen-invariants.mjs --check` must be clean (the gate runs it).
- Status promotion is per-row, per-test, never batch (B4 lesson in `CLAUDE.md`). A row whose
  statement certifies unbuilt behaviour (`execute_pending`, shipped signing) stays
  `unimplemented` even if half of it is tested — split the row instead (WRD-CAP-09/10 precedent).

### 4.2 `docs/security/REVIEW-RUNS.jsonl`

Append-only, one row per round, written ONLY by `scripts/append-review-run.mjs` (rolls both
ledgers back together on failure). `kind` values in use: `task-diff`, `baseline-not-recorded`.
`reviewer_model` comes from the API response, not self-report. Rows are keyed by
`artefact_sha256` → replays are refused.

### 4.3 `docs/security/REVIEW-SCORECARD.jsonl` — flipping `remediation_verified`

`packages/core/test/review-runs.test.ts:362-374` rejects any row with `remediation_verified:
true` unless ALL of: `remediation_sha` (40-hex, exists, is the fix commit), `remediation_gate_sha`
(40-hex, exists, CONTAINS `remediation_sha`, reachable from HEAD — the commit at which the FULL
gate ran green), `remediation_gate_cmd` (non-blank; write the literal command AND the counts,
e.g. `bash .claude/test-gate.sh  (exit 0 @<sha>: core 700, extension 700 + 15 browser, rust
all lanes ok, clippy clean, L9 PASS)`), and `claimed_reproducer_verified` not also true. A gate
that ran BEFORE the fix commit is not evidence for it. The precedent rows are WRDF-0109..0111
at BASE.

## 5. OWNER decisions — record, do not take

Each of these is written in the named ledger note. Your job is to surface them in §9, not to
choose. If a fix you are making depends on one, stop that fix and report.

| # | Decision | Where recorded | Default the code ships today |
|---|---|---|---|
| O1 | Keyring context pin is `solana:mainnet` (genesis + program id). Changing it orphans every record sealed under the old pin. | WRD-EXT-03 note; `apps/extension/src/background/expected-keyring-context.ts` | mainnet byte literals |
| O2 | A-1 human-presence = trusted POINTER move ⇒ keyboard-only users cannot arm "Approve and sign". Deliberate (a primed keydown stream is the same threat) but an accessibility exclusion. | WRD-EXT-04 note (6) | pointer-only |
| O3 | A-1 placement bounds assume a 1024×768 display (`APPROVAL_WINDOW_ASSUMED_SCREEN_*`); `system.display` permission was judged not worth it. | WRD-EXT-04 note (3) | 1024×768 |
| O4 | A-2 ships the `alarms` manifest permission; `main.ts` now refuses to start without `chrome.alarms`. | WRD-KEY-03 note; `apps/extension/manifest.json` | required |
| O5 | E-4 CI trigger is tag pattern `v*`; only the source-tag tier is mandatory, the dual-report / artifact-review-signature / store-CRX tuples are optional and skipped with a notice when `null`. | WRD-REL-05 note (1)(2) | `v*`, optional tuples |
| O6 | E-4 `apps/extension/release-pins.json` is a PLACEHOLDER (all-zero fingerprints, `REPLACE_ME`); the `release-verify` job FAILS on every tag until the owner commits real pins + ASCII-armored public keys under `apps/extension/release-pubkeys/` (directory does not exist yet). A test asserts the placeholder is rejected. **Never fill these in yourself.** | WRD-REL-05 note; `release-pins.mjs` | placeholder |
| O7 | X-2 quota numbers (1/4 windows, 4 flows, 4 requests, 16 journal rows per origin) are policy with no usage data. | WRD-EXT-06 note (2); `provider-origin-capacity.ts` | as listed |
| O8 | X-1 ordering precondition (extension's own document_start injection must claim first) is unenforced because no production entry point constructs the page owner yet. | WRD-EXT-05 note (4) | unenforced |
| O9 | E-1 scope: `pnpm --version` (producer) and `unzip` (verifiers) still resolve via inherited PATH. | WRD-REL-04 LIMITS | unpinned |
| O10 | Pre-existing SHIP blockers, unchanged: C1a origin decision, external audit, on-chain deploy, counsel on WRDF-0050/0089 + Jupiter IDL licence. | `CLAUDE.md` | — |

## 6. Audit items NOT remediated (candidate work AFTER §3, only if the owner asks)

From `FABLE-AUDIT-2026-09-02.md` §2, in the audit's own priority. Each has a one-line "what a
fix looks like" so you do not re-derive it:

- **E-2 / E-3** (Low): mirror the `verify-store-package.mjs:94-144` unzip fd/seal/compare pattern
  for both gpg operands in `reviewed-artifact-signature.mjs:102-127`; `fstat`-re-verify the gpg
  launcher immediately before exec in `release-source-tag.mjs:688-715` or drop it for
  `gpg.program=/usr/bin/gpg`.
- **E-5** (Low): sign the dual-build / review-signature / CRX tuple into the tag message grammar,
  not as unsigned CLI args (`release-source-tag.mjs:284-404`); pin `unzip` like git (O9).
- **X-3** (Low/Info, unshipped): retention sweep on `read()`/open (WRD-EXT-06 note (5) says why
  it was NOT done — a behavioural change on the replay hot path; needs a decision), plaintext
  `transactionBytes` in IndexedDB for 10 min, delivery-proof return-type mismatch, receipt id
  exposing the IndexedDB key.
- **A-3** (Low, DoS): rate-limit per-document Port requests in `content/bridge.ts:280-292`.
  X-2 bounds the approval path, not the raw request flood.
- **P-2** (Info): remove the three inert adapters from `registry_default.rs` list 1 or comment
  them as intentionally inert.
- **K-5** (Low): deploy gate genesis check must not use the RPC it is authenticating
  (`packages/core/src/deploy/gate.ts:115-126`).
- **K-7** raise Argon2id floors in `derive.ts:138-140`; **K-9** exact-pin `@solana/web3.js`;
  **K-11** `Number.isInteger` on `kind`/`opsMask`/`programAllowlistId` in
  `webauthn/transcript.ts:130-133`; **K-4** reject unknown ComputeBudget tags client-side.
- **K-2 / K-3 / K-6 / K-10**: plausible, never given a failing input — a RED test or a dispute
  is worth a round of its own.
- **R-3**: 0 human rulings — owner only. **R-4**: partly addressed (WRD-EXT-03..06 are the first
  extension invariants); `SECURITY.md` scope still excludes the extension. **R-5**:
  `docs/NEXT-SESSION.md` is ~1 MB — append your memo at the TOP, do not rewrite the file.
  **R-6**: `bincode` RUSTSEC-2025-0141 ignore expires 2026-11-30; duplicate `@noble/hashes`
  1.8/2.4 and `spl-token` 0.4.9/0.4.14.

## 7. Footguns — every one of these bit the previous session

1. **Commits in `/opt/warden` discard UNSTAGED changes.** Always `git add -A` (or explicit paths)
   before `git commit`. Verify with `git status --porcelain` afterwards that nothing you wanted
   is gone.
2. **The pre-commit gate hook flakes** (vitest on first run after a build). Retry the commit once
   (re-`git add` first). The previous session used `git -c core.hooksPath=/dev/null commit` and
   ran the FULL gate separately — if you do the same, SAY SO in the commit body and in §9.
3. **The full gate takes >10 min** (Rust build + 4 SBF programs + browser lane). Run it detached:
   `setsid nohup bash -c 'bash .claude/test-gate.sh; echo exit=$?' > <log> 2>&1 < /dev/null &`
   and poll for `^exit=`. Never read success from a piped exit code.
4. **Never run two cargo builds concurrently** on this host (hard-hang history). Check
   `pgrep -af 'cargo|rustc'` before starting one.
5. **Browser lane needs a build first**: `pnpm --filter @warden/extension test:browser` = build +
   Playwright. Playwright gotchas: `new URL("chrome-extension://…").origin` is the string
   `"null"`; `worker.evaluate` on a dead worker wrapper HANGS (race it against a timeout);
   `Target.closeTarget` kills the worker; wake it via `chrome.runtime.connect` from an extension
   page or a content-script port, not by navigating `approval.html`.
6. **Evidence SHAs after cherry-picks.** If you fix in a worktree and cherry-pick to `phase1b`,
   every SHA in `invariants.jsonl` notes/evidence must be repointed to the `phase1b` commit (same
   `git patch-id --stable`). Checker:
   ```
   python3 - <<'EOF'
   import json,subprocess,re
   for l in open('docs/security/invariants.jsonl'):
       r=json.loads(l); s={e.get('sha') for e in r.get('evidence',[]) if e.get('sha')}
       s|=set(re.findall(r'\b[0-9a-f]{40}\b', r.get('notes','')))
       for x in s:
           if subprocess.run(['git','merge-base','--is-ancestor',x,'HEAD'],capture_output=True).returncode: print(r['id'], x)
   EOF
   ```
   Empty output = clean. (At BASE it is clean; WRD-EXT-03, WRD-KEY-04 and WRD-REL-04 were
   repointed from `602b200`/`03cf34b` to `27039aa`/`a4c134e` in `LEDGER_CLOSE_SHA`.)
7. **Cherry-pick syntax**: `git -c core.hooksPath=/dev/null cherry-pick <sha>` — the `-c` goes
   before the subcommand.
8. **Disk is at ~96 %** (`df -h /`). `target/` and Playwright profiles are the big movers; do not
   add a second `target/` via a worktree; `cargo clean` only if a build fails on ENOSPC.
9. **L9 supply-chain lane can 401** on the RustSec advisory-db fetch through this host's GitHub
   credential helpers (intermittent). If `cargo deny` fails ONLY on `failed to fetch advisory
   database … 401`, run `git -C /root/.cargo/advisory-dbs/advisory-db-* -c credential.helper=
   fetch --depth=1 -u origin +main:main`, then re-run `./scripts/supply-chain-gate.sh`; a green
   re-run at the same SHA is the evidence. Do not "fix" the gate script for this.
10. **WRDF-0105 prior-art / verify-release-cli "esbuild input escapes the repository" reds** seen
    on worktree branches are worktree artefacts; on `phase1b` they pass. Do not chase them.
11. **`docs/NEXT-SESSION.md` is ~1 MB.** Never `cat` it into a prompt; read the top 120 lines.
12. **K-1 makes fixture context matter.** Any test that seals a keyring record for the background
    to adopt must use `shippedExpectedKeyringContext()` genesis/program (see
    `browser/provider-bridge.pw.ts` `browserPersistentRecord`); a 0x31/0x32 dummy context is
    refused at wake with `KeyringAuthError`, visible only in the worker console.

## 8. DO_NOT_TOUCH (hard)

- `.superpowers/**` except reading/writing `.superpowers/reviews/` through the review scripts.
- `/var/www/**`, `/etc/**`, systemd units, nginx — this box also hosts production sites.
- Any keypair, `.env`, `$CODEX_HOME/warden-review.config.toml` (read-only profile), GPG/trust
  stores, `apps/extension/release-pins.json` VALUES, `apps/extension/release-pubkeys/`.
- `spikes/**` (never import from it into `packages/` or `apps/`).
- `git push`, `git tag`, signing, publishing, deploying, any store upload, any RPC that mutates.
- `main` branch, `docs/spikes/PHASE*-LEDGER.md` (published, sanitized copies).
- Do not "tidy" `docs/security/*.jsonl` formatting, ordering, or field names.

## 9. RETURN shape

Append to the TOP of `docs/NEXT-SESSION.md` (after the title line) a memo in the same
`TO / TASK / … / RETURN` grammar, and end your run with:

```
ROUNDS: R0 <thread|NOT RECORDED: reason> · R1 … · R8 …
FINDINGS: WRDF-0112..0NNN — adopted N / disputed N / scoped-out N
FIXES: <sha> <one line> (RED test <name> red at <sha>, green at <sha>) …
FLIPS: WRDF-… remediation_verified=true @gate <sha>
GATE: bash .claude/test-gate.sh exit=<n> @<sha> — core N, extension N + N browser, rust <lanes>, clippy, L9
LEDGER: invariants N (test-covered N / unimplemented N / llm-asserted N); gen-invariants --check <clean|errors>
OWNER DECISIONS SURFACED: O1..O10 + any new
HOOKS BYPASSED: <list of commits made with core.hooksPath=/dev/null, or "none">
NOT DONE / BLOCKED: …
```

Every number in that block must be copied from tool output you ran in this session, not from
this memo.
