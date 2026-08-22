# Next Session — Claude Security, Vanity, and UI Handoff

> **STATUS UPDATE 2026-08-22 — Phase 1B PROGRAM WORK COMPLETE.** All Phase 1B tasks
> (0/10/1/2b/2/3/4/5/6/8) plus **Task 11** (deploy-gate: WRD-DEP-01 governance/hash + WRD-DEP-02
> adapter-Registry) and **Task 9** (spec → rev 9 close-out) are DONE — 283 `@warden/core` tests,
> whole `phase1b` branch pushed. The Warden landing page is SHIPPED LIVE at drinkerlabs.info/warden/.
> The Phase-1B run order below is HISTORICAL; do not "resume Phase 1B" — it's finished.
> **What actually remains are OWNER decisions and later phases, not more 1B implementation:**
> (1) the C1a `create_account` production-origin + freeze-vs-migration decision before any public
> account creation; (2) an external security audit + the on-chain deploy (the L7 deploy-gate is
> built and tested but UNVERIFIED against a live cluster); (3) counsel sign-off on WRDF-0050
> (Squads AGPL lineage), WRDF-0089 (Squads reader), and the Jupiter-IDL note in THIRD_PARTY_NOTICES.md;
> (4) the client-security-hardening (C1+), vanity (V1+), and UI (U0+) plans, at their stated
> dependency boundaries. Release-candidate residuals are enumerated in PHASE1B-MEASUREMENTS.md.
> Read CLAUDE.md + the spec (rev 9) for the current truth before acting.

TO / Claude Code

TASK / Read the dated research memo, resume Phase 1B in its documented order, execute the client-security plan at its permitted boundaries, carry the approved optional vanity-primary-account feature through V0 and then V1–V6 only after its SDK/extension dependencies are stable, and execute UI U0–U10 only at the design/client/mobile boundaries stated in its plan.

CWD / `/opt/warden`

BASE / Start from the committed `phase1b` HEAD containing this handoff. Before editing, run `git rev-parse HEAD` and verify `e5b5a19a9fb982c95ea294d0fc36ef1fd701096a` is an ancestor; record the actual starting SHA because this handoff cannot self-reference its own commit.

READ / `docs/OVERNIGHT-HANDOFF-2026-08-19.md` first; `CLAUDE.md`; `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md`; `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md`; `docs/superpowers/plans/2026-08-19-warden-vanity-primary-account.md`; `docs/research/2026-08-19-wallet-ui-extension-mobile.md`; `docs/superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md`; `docs/design/figma.md`; `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`; `docs/security/invariants.jsonl`; `docs/security/PRIOR-ART-FINDINGS.md`; `docs/security/THREATMODEL.md`; `docs/security/RELEASE-INTEGRITY.md`; `docs/research/2026-08-18-security-assurance-and-wallet-landscape.md`.

WRITE (edit lease) / Only the files assigned by the next unfinished Phase 1B task. At a clean boundary, client C0 and vanity V0 may edit their named spec/security ledgers, generated invariant Markdown, and ledger-presence tests. UI U0–U2 may edit Figma and `docs/design/figma.md` only under an explicit design lease; those frames do not authorize generated-token or extension-code edits. After Phase 1B Task 8 stabilizes the client SDK, use vanity V1–V3's leases for `packages/core/**`, new `packages/vanity-pda/**`, tests, and build/security ledgers. Client C1 must establish the production extension trust boundary before UI U7 or vanity V4–V6 edits `apps/extension/**`. Native mobile remains research/prototype-only until the owner authorizes implementation and framework selection. One active edit lease and one heavy build at a time. Do not spawn subagents unless the owner explicitly grants a number.

DO_NOT_TOUCH / `/var/www/**`; live deployments or accounts; publisher/store accounts; secrets or keypairs; `.superpowers/**`; `/root/.codex/session-graphs/**`; unrelated user changes; production `programs/warden/**` outside the active Phase 1B lease. The existing `/opt/vanity-bot/**` is read-only evidence only: never import its source, protocol, WASM, or generated assets. Never import production code from `spikes/**`.

ACCEPT / Preserve the Phase 1B order; seed client and vanity invariants before implementation; bind approvals and rendered intent to exact serialized bytes; keep simulation advisory; make authentication gate key release; derive vanity addresses only by grinding a public 32-byte salt for the root-bound Warden PDA; enforce 1–4 ASCII Base58 characters at every layer; default to suffix and case-insensitive matching with an exact-capitalization warning; independently re-derive worker results; perform confirmed account readback before copy/fund/receive; never treat a partial-address match as recipient verification; use exact-address provenance, full-address comparison, fresh authentication, and policy/timelock for poisoning controls; keep origin/decode/simulation/policy as independent UI axes; correct meaningful light warning indicators to at least 3:1; assign work across popup/side-panel/approval-window/full-tab surfaces; treat native mobile credential/link/privacy parity as UNVERIFIED pending real-device spikes; run the full merged-SHA gates; report every green gate with its exact command and SHA.

SIDE_EFFECTS / Repository documentation/code/test edits, Figma edits made under an explicit design lease, generated invariant/token Markdown or CSS produced by their source-controlled generators, and local build/benchmark/browser/accessibility artifacts only. No deploy, live-account mutation, credential creation/rotation, private-key generation/export, remote vanity acceleration, analytics change, store publication, external message, or secret handling without separate authorization.

RETURN / Merged SHA; `git status`; exact commands and results at that SHA; invariant status changes and evidence paths; Figma page/node ids and native-size capture paths; contrast/target/overflow measurements; state-matrix coverage; worker/CSP/storage/permission/network changes; benchmark, browser, accessibility, mobile-device, and comprehension artifacts; remaining UNVERIFIED items; owner decisions; confirmation of no unauthorized external side effects.

## Where to resume

**The governing document is now
[`2026-08-20-warden-research-adjudication-and-campaign-plan.md`](superpowers/plans/2026-08-20-warden-research-adjudication-and-campaign-plan.md)**
(joint Claude + Codex `sol@max` adjudication of this whole research corpus,
SHIP-DOC after three rounds). It sets the order and supersedes the priority list
that was here. Confirm branch/plan state rather than assuming the historical base
is still HEAD.

Landed base: the L0 harness gate, slot freshness, conservation, proof-of-
possession at account creation, the invariant ledger, and repo supply-chain
gates — **plus the 2026-08-20 A0 assurance pass** (executable review lane;
`REVIEW-RUNS.jsonl` recording every round incl. zero-finding; retrospective
threat-model deltas; five RED-verified conservation fund-loss fixes;
`WRD-CONS-*` unit-layer ledger rows). A0 close-out and the five fixes are in
`docs/program/PHASE1B-MEASUREMENTS.md`.

Also **C0+V0 DONE** (2026-08-20, 9 Codex docs rounds, close-out in
`docs/program/PHASE1B-MEASUREMENTS.md`): 26 client/vanity/deploy invariants seeded
at honest `unimplemented`; C1a / C2a / C4b / Task 5E / Task 11R / the Task 2 split
written into their source plans; V4/U7/V2 gating corrected; spec §6.1 vanity
section; cross-cluster AAD and 7-iteration deploy-gate governance hardened.

Remaining, in campaign-plan order:

1. **Task 2 DONE** (2026-08-20, 2A `204a118` + 2B `4c8575a`, 4 review rounds → 0
   findings): `test-mutator` + `test-jup-mock` + 18 harness smoke tests;
   `.claude/test-gate.sh` builds/checks both new `.so`. Close-out in
   `docs/program/PHASE1B-MEASUREMENTS.md`.
2. **Task 3 DONE** (`a7b7824`…`300face`, 7 review
   rounds → WRDF-0034..0044 all adopted+fixed; full gate re-run at the fix SHA,
   282 lib + 42 integration + 104 TS tests, clippy clean): Registry zero-copy
   state, selector-derivation rule (match on the `(program_id, selector)` pair;
   disc_len 8/1/4/0), `registry_allows` with `(program,selector)` authority-
   position role validators (fail-closed), default adapters, `init_registry`
   (upgrade-authority-gated), `grant_session` allowlist validation, `create_account`
   optional registry (**bound into the root ceremony**, CreateBody 183→215 B),
   TS/Rust parity, integration suite. NB: the System program id IS
   `Pubkey::default()`, so used slots are bounded by `n_entries`.
   **Round 5** (`3361d2c`) closed the round-4 deferrals for real:
   - **WRDF-0044** — `grant_session` now takes the account's `Registry` account,
     loads it, and requires `is_allocated_list(program_allowlist_id)` (not just
     structural `is_valid_list_id`) for any non-zero id. A grant can no longer
     persist a dangling list id that a Phase-1C mutable-registry update could
     silently activate without a fresh root ceremony. On-chain RED/GREEN:
     `grant_with_unallocated_allowlist_id_rejected` (id 3 → `InvalidAllowlistId`)
     and `grant_with_allocated_allowlist_id_accepted` (id 1 stored) — the latter
     is the positive on-chain grant that was the documented follow-up, now
     delivered. `WRD-SESS-07` inverted from "must be 0" to "must resolve to an
     allocated list".
   - **WRDF-0042** — TS core exports a canonical `encodeCreateBody` (215 B incl.
     the trailing registry `Pubkey`); doc corrected from 183 B; the pinned
     action-hash vector now validates the exported API, not a hand-roll.
   - **WRDF-0043** — full `./.claude/test-gate.sh` re-run on the fix SHA.
   Round 7 confirmation returned **0 findings at `300face`** — Task 3 is DONE.
   **Task 4 DONE — code-complete** (`d47d8ce`…`08a8b56`): stage_open/chunk/
   finalize/close, content-addressed + creator-bound Stage PDA, 23 integration
   tests incl. the ND-SQD3-LO-01 squat class (closed by construction), MEASURED
   stage_chunk cap **977 B v0/client** (979 legacy); whole-task sol@max review
   CONVERGED (5 rounds, WRDF-0045..0049). WRDF-0050 = owner/counsel
   release-blocker carried (blocks SHIP, not code).
   **Task 5 (`execute`) CODE-COMPLETE** (`a7efe93`…`3632deb`, parts 1–5):
   session/root (XOR) × inline/staged (XOR); fixed deny-list on BOTH paths
   before the registry; adapter registry on the session path;
   `conservation::snapshot`+`compare_and_account` around a real `invoke_signed`
   CPI loop; per-mint caps → `buckets::debit`; stage consume-once (WRD-STAGE-02).
   `OP_EXECUTE_ACTION=0x07` + TS `encodeExecuteBody`, cross-language-pinned. 320
   lib + 25 `tests/execute.rs` (real SPL+mutator CPIs) + 109 TS; clippy clean.
   Two design findings resolved: per-ix duplicate-index reject relaxed
   (vault-sweep close names the PDA twice); PDA-not-writable moved from the pure
   parser into `enforce_pda_writable` (handler, post-`deny_scan`) so the rule-4a
   vault-sweep close can credit the PDA while a writable PDA stays refused
   elsewhere. Errors 6056/6057.
   **Task 5 DONE (2026-08-21).** 4 sol@max review rounds converged (no new
   program findings by round 4): WRDF-0053 whole-logical-list uniqueness fixed
   (6059) + WRDF-0051 Jupiter direct-guard (6058, defense-in-depth, claim
   corrected round 2) + WRDF-0055 ceremony-bound-submitter doc+test + WRDF-0056
   WRD-EXEC-07 narrowed + WRDF-0057 gate evidence recorded. Standing
   `deferred`: 0051-nested → Task 6 adapter preflight; 0052 events → Task 5E;
   0054 dead System adapter → Task-3 hygiene. **Sweep verdict (measured, in
   PHASE1B-MEASUREMENTS §Task 5): the caps are HEAP-bound —
   `MAX_EXECUTE_ACCOUNTS_TOTAL=24` / `MAX_EXECUTE_WRITABLE=20`** (22-writable
   OK / 24 OOM on the default 32 KiB heap; `RequestHeapFrame` inert under
   Anchor's capped allocator; worst CU 83.8k ≪ 360k; v0+ALT ≤ 486 B),
   boundary-tested on-chain. **Task 6 PREREQUISITE DONE (@7936419):** a custom SBF heap
   allocator (`src/heap.rs`, `custom-heap` feature, default ON — uncapped
   upward bump, runtime-frame-bounded, fail-closed past it) replaced the
   entrypoint's 32 KiB-capped default. PROVEN: heap frames now work (mutator
   `heap_hog` 100 KiB fails without / OK with a 128 KiB frame); execute
   re-sweep hit 30-writable at 113k CU with a frame. **Caps lifted 24/20 →
   `MAX_EXECUTE_ACCOUNTS_TOTAL=32` / `MAX_EXECUTE_WRITABLE=28`**, boundary-
   tested; **client contract: the wrapper injects a `RequestHeapFrame` sized
   for the shape on any execute past ~24 accounts** (like the CU limit). Tables
   in PHASE1B-MEASUREMENTS §"Task 6 heap lift". **Task 6 (swap) DONE @949c1f5** — Jupiter v6-pinned adapter, 4 sol@max
   rounds → 0 program findings by round 4. Program+disc pin (real v6 / mock
   under --features test-jup), platform_fee_bps==85, CANONICAL source/dest/fee
   ATAs + PDA authority, net conservation. Native swaps REJECTED in 1B (CRITICAL
   WRDF-0061). Realized fund-loss bound stacked 4-deep: route_hash root-binding
   (0058) + treasury-fee-taken (0059) + writable-vault pinning (0065) +
   canonical-ATA pinning (0070), over net conservation + caps. IDL pinned
   (jup-ag/jupiter-cpi sha256 764ea6d7…). CI publishes a clean default-profile
   production .so + pin attestation. **Deferred, NOT 1B defects:** byte-exact
   Vec<RoutePlanStep> parse before mainnet (WRDF-0031/0059); structured events →
   Task 5E (WRDF-0052). **Task 8 (TS execute client) DONE @ef69e23** — `packages/core`
   `payload.ts` codec + `wrapForExecute` (build→compile→decompile the outer ix, derive
   accounts_hash+caps from runtime-COALESCED effective metas = one source of truth;
   fail-closed rejects for third-party signer / writable PDA / writable root signer;
   payload⊆outer subset guard; ComputeBudget hoist+normalize with CU-floor + always-on
   sized RequestHeapFrame + caller-frame align/range validation; client caps) +
   cross-language golden fixtures (read-only vectors + gate `git diff` drift guard).
   **9 sol@max rounds → round 9 = 0 findings.** SDK product code converged @round 3;
   rounds 4–8 hardened the review LEDGER itself (golden fixtures, scorecard reproducer +
   remediation provenance, CI shallow-clone fail-close, gate-contains-fix ancestry).
   WRD-EXEC-11/12 test-covered; gate green @d73118f. **Deferred, non-blocking:** a typed
   vault-sweep CloseAccount payload builder; an on-chain relayer/optional-alias execute
   integration (client subset guard + Rust cross-language hash oracle cover it short of
   that). **NOW: Task 11R (deploy-gate RPC), then Task 9 (close-out + spec rev 9).**
   **C1a needs a program change** (`create_account` must
   compare against a pinned production `rp_id_hash`, not just self-consistency —
   WRDF-0016/0027) plus the owner's freeze-vs-migration decision.
3. Corrected gating (was C1-only): **V4 waits for C1a + C2a + C3 + C4**; **U7
   token export waits for U0–U2 acceptance** (and live receipt rendering for
   C3 + C4). Client C1's trust boundary still precedes UI U7 and vanity V4.
4. **Task 11 is PARTIAL** — its deployment gate is spec + partial dry-run
   (`docs/security/DEPLOY-GATE.md`); Task 11R owns the RPC checks before Task 9.
5. Keep native mobile at prototype/research scope until the owner authorizes an
   implementation framework and real-device spikes close credential, verified-
   link, MWA, and capture/privacy uncertainties.

Owner decisions owed (none block C0+V0 or Task 2): the C1a freeze-production-ID
vs authenticated-migration choice; a U0–U2 Figma design lease (for a session
after the current two); scheduling the real-device WebAuthn PRF spike; the
Certora quote at 1B close-out; a Task-9 baseline exception for the pre-A0 review
rounds that were never recorded (recommended: approve, gap named honestly); and
CI `fetch-depth: 0` so the evidence-at-SHA ledger gate is load-bearing in CI.

## Plans to carry forward

- [`2026-08-20-warden-research-adjudication-and-campaign-plan.md`](superpowers/plans/2026-08-20-warden-research-adjudication-and-campaign-plan.md) — **governing order**
- [`2026-08-19-warden-client-security-hardening.md`](superpowers/plans/2026-08-19-warden-client-security-hardening.md)
- [`2026-08-19-warden-vanity-primary-account.md`](superpowers/plans/2026-08-19-warden-vanity-primary-account.md)
- [`2026-08-19-wallet-ui-extension-mobile.md`](research/2026-08-19-wallet-ui-extension-mobile.md)
- [`2026-08-19-warden-s-tier-ui-mobile.md`](superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md)

The client plan addresses the largest process holes found in the wallet-source
comparison: key lifecycle, browser message provenance, approval single-use
semantics, exact-bytes intent, simulator binding, recovery export, and release
authority.

The vanity plan records a **go** decision with a narrow design: an optional first
SmartAccount address, not a master private key. Warden already derives the PDA
from `Keccak256("WARDEN/seed/v1" || root_pubkey33 || salt32)`, so the feature
searches salts locally and preserves the passkey root. Four characters is a hard
cap. Suffix and case-insensitive matching are defaults; exact capitalization is
optional and explicitly warned as slower.

The UI research and U0–U10 plan define “S-tier” as measurable comprehension,
state coverage, accessibility, privacy, responsive behavior, token parity, and
real-device evidence—not visual polish alone. Warden Receipt is the flagship
surface, and the popup is only one part of the extension architecture.

## Vanity corrections that must survive handoff

- Base58 excludes only `0`, `O`, `I`, and `l`. All other Base58 characters are
  admissible in 1–4 character prefix/suffix requests.
- Do not copy `/opt/vanity-bot`'s first-character whitelist or special `J` rule;
  it assumes a fixed 44-character encoding and rejects valid 43-character
  addresses. A session-local probe found a valid Warden PDA beginning with `W`.
- Do not copy its `33^n` case estimate or fixed "remaining" countdown. Prefix
  probabilities are character/length dependent and search completion is
  geometric; show calibrated 50%/95% probability windows.
- Do not reuse the bot's private-key-producing WASM or message shape. The Warden
  worker returns only salt/owner-seed/address/bump metadata and is independently
  verified through the supported core derivation.
- Freeze program id, cluster/config, account seed, and seed-domain version before
  any long search. A change to any of them changes the target address.
- Vanity is cosmetic, never identity. Full-address, saved-contact, and
  address-poisoning defenses ship with it.

No build or test gate was run merely because these proposal documents exist. Do
not infer an implemented feature or a green build from this handoff.
