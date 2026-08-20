# Research Adjudication and Campaign Plan — 2026-08-20

> **For agentic workers:** this is a **sequencing and gap-repair plan over existing
> implementation plans**, not a replacement for them. Task-level steps, code, and
> tests live in the four plans it adjudicates — and the new tasks this document
> introduces (A0, C1a, C2a, C4b, 5E, the Task 2 split, the Task 11 repair) are
> **labels until the C0+V0/A0 leases write them into the source plans as full tasks**
> with checkboxes, file lists, red tests, and acceptance commands (§4 step 3 makes
> that amendment work explicit). Execute the source plans in the order and with the
> amendments recorded here. Use superpowers:executing-plans (inline) or
> superpowers:subagent-driven-development only if the owner grants subagents.

**Goal:** Turn the 2026-08-18/19 research corpus (20 raw Codex reports, two reviewed
syntheses, three derived plans) into one adjudicated execution order for the next
sessions, and repair the gaps the corpus leaves unowned.

**Architecture:** Two independent analyses — Claude (this session) and Codex
`gpt-5.6-sol @ max` (thread `01a01dc5-13f7-7390-be68-857c46252e0a`, read-only
adjudication at `fd80b11`) — merged where they converge, with every divergence
resolved by repo evidence. Code wins over stale prose throughout.

**Spec:** `docs/superpowers/specs/2026-08-18-warden-wallet-design.md` (rev 8 + erratum).
**Adjudicated plans:** `2026-08-18-warden-phase1b-execute-swap.md` (rev 3),
`2026-08-19-warden-client-security-hardening.md` (C0–C8),
`2026-08-19-warden-vanity-primary-account.md` (V0–V6),
`2026-08-19-warden-s-tier-ui-mobile.md` (U0–U10).

**Base:** `phase1b` @ `fd80b119cd9d19f1e834c06e1a66fd868f439d89` (tree clean apart
from this plan file), `e5b5a19` verified ancestor. Phase 1B Tasks 0, 10, 1, 2b are
implemented and reviewed. **Task 11 is partial:** its non-RPC lanes landed, but the
deployment-gate item remains incomplete pending Task 11R —
`docs/security/DEPLOY-GATE.md:12` records "SPEC + partial dry-run implementation"
with four live checks NOT IMPLEMENTED, and Task 9 gates on every Task 11 checkbox
green with command+SHA evidence. Remaining program order
**2 → 3 → 4 → 5 → 6 → 8 → 9** is unchanged, plus the Task 11 repair in §2-G11.

## Global constraints (carried, binding)

- Phase 1B order is authoritative; no derived-plan implementation before Task 8.
- One active edit lease and one heavy Rust build at a time; no subagents without an
  explicit owner grant.
- Every task: isolated implementation → Codex adversarial review (sol @ max), seeded
  with `docs/security/INVARIANTS.md` + `PRIOR-ART-FINDINGS.md` + named sibling files;
  silence on a seeded invariant is a FAIL; clean tree before every review.
- Any diff that moves an accept/reject boundary gets a mandatory second review round.
- Amount math: Rust `checked_*` only; TS `bigint` only.
- No deploy, live-account mutation, credential handling, store publication, or
  external side effects. Figma edits only under an explicit design lease.

---

## 1. Sequencing verdict (both analyses, convergent)

1. **A0 (new): assurance-record repair** — before any program work. See §2-G1.
2. **C0 + V0 combined documentation tranche** — one lease, one commit. Both edit the
   same ledger/threat-model/presence-test files (client plan §C0; vanity plan §V0
   says they may combine); we are at the clean boundary they require, and seeding
   the rows now arms every later Codex review of those surfaces. Doing this after
   Task 2 would only invite a ledger merge conflict.
3. **Task 2** — next program task, split into two reviewable commits:
   **2A** `test-mutator` + `mutator_harness.rs` smoke tests, **2B** `test-jup-mock` +
   `jup_mock_harness.rs`. Neither is done until the combined-SHA gate passes. 2B is
   not deferrable to Task 6.
4. **Tasks 3 → 4 → 5 → 6 → 8 → 9 unchanged**, with one amendment: **Task 5E**
   (structured event emission — bucket debit, cap rejection, freeze) is a completion
   requirement of Task 5, closing the L7 observability mandate (synthesis L7) that
   no task owned.
5. **After Task 8:** C1 first — with **C1a as a blocking subgate of C1**: before any
   credential/account creation against a public build, either freeze a pinned
   production extension ID (with dev-origin refusal tests) or design an
   authenticated 1C migration; the choice is the owner's (§4 owner decisions).
   Then C2/C2a/C3/C4(+C4b)/C5. V1–V3 may start as package-only work after Task 8;
   V2's final worker/CSP/shipped-build choice waits for C2, and **C6 is the
   downstream shipped-artifact revalidation of V2/V4 output** — V2's completion does
   not wait on C6, but no vanity artifact ships before C6 re-validates it.
   **V4 waits for C1a + C2a + C3 + C4, not just C1** — its create ceremony and
   confirmed readback need the production origin, normalized assertions, the
   immutable signing record, and the decoder contract. **U7 splits**:
   semantic-model/fixture *scaffolding* may follow Task 8 + C1, but **token export
   waits for U0–U2 acceptance** (U1/U2 create the variables and component contracts
   U7 exports) and live receipt rendering waits for the relevant U3–U5 designs plus
   C3 + C4.
6. **U0–U2 stay unscheduled** until the owner grants an explicit Figma design lease,
   and are **unconditionally out of Sessions A/B** even if granted meanwhile — a
   grant schedules them into a later session, never into the two planned here.

**Code-over-prose corrections found during adjudication (do not "re-fix"):**
- Creation is authenticated NOW — `create_account.rs` runs proof-of-possession and
  consumes the ceremony (starts at nonce 1). `THREATMODEL.md:31` still describes the
  pre-2b squatting exposure as standing — stale prose, repaired in A0. Task 2b must
  not be repeated.

## 2. Gap register → owned tasks

| ID | Gap (evidence) | Owner / when |
|---|---|---|
| G1 | `REVIEW-SCORECARD.jsonl` is 0 bytes despite ~8 review rounds; `THREATMODEL.md` carries only the Task 10 delta (`THREATMODEL.md:52`) — the Task 0/1/2b/11 deltas are missing — and its unauthenticated-create row (`:31–36`) is superseded by landed code; the file is **append-only**, so A0 *appends* a Task-2b correction superseding those lines, never rewrites the baseline; `PHASE1B-MEASUREMENTS.md` lacks the Task 11 command+SHA evidence block Task 9 gates on | **A0**, now |
| G2 | Reviews that yield zero findings are invisible (`scripts/review.sh` records findings only) — L3 cannot demonstrate review coverage | **A0**: a review-runs record with a defined schema + tests (a validated zero-finding round appends exactly one run; a failed/invalid round appends none); past rounds recorded as explicitly `not-recorded`/UNVERIFIED — no fabricated backfill. Task 9 must either block on those gaps or carry an explicit owner-approved baseline exception |
| G3 | Low-S normalization is spec-mandatory (spec:60, :232 — the spec mandates low-S specifically; strict DER→compact parsing is C2a implementation scope, not a spec claim) but no client task owns it; real browser assertions UNVERIFIED end-to-end | **C2a (new)**, before C3/V4; acceptance must include a malformed-DER reject set and a recorded real high-S assertion carried through normalize → production tx builder → precompile accept |
| G4 | `rp_id_hash` binds one exact extension origin; no migration instruction exists; dev-origin accounts must not silently become funded production accounts (synthesis L9) | **C1a (new)**, before any public account creation: freeze a production ID and refuse migration, or design an authenticated 1C migration |
| G5 | Quote-independence adversarial fixtures (stale quote, sandwiched route, shared-upstream "second source") mandated by synthesis L9 but absent from C4 | **C4b (new)** |
| G6 | Task 2 smoke tests have no named executable home; `.claude/test-gate.sh` builds/checks only `warden.so` + `test_middleman.so` | **Task 2** (add both harness test files; extend test-gate `.so` list) |
| G7 | Conservation unit layer (Task 1) has no ledger identity — `WRD-EXEC-*` rows correctly stay `unimplemented` until Task 5 | **A0** (Task-1 ledger repair, not the client/vanity tranche): add `WRD-CONS-*` rows at `test-covered` **only** where a named unit test passes at a cited SHA, else `llm-asserted`; never seed them `unimplemented` (the code exists) and never prematurely promote `WRD-EXEC-*` |
| G8 | UI acceptances mix design gates with runtime gates (U4 exact-bytes, U5 a11y runs) | Recorded amendment: split design-acceptance (now) vs executable acceptance (U7/U8) when U-lane opens |
| G9 | L4 (state-machine/Trident/differential beyond the mutants pilot), L6 (Certora quote), L7 (audit-freeze artifacts, attempted exploits) have no task owner | **Post-Task-9 pre-audit assurance plan** (write at 1B close-out); Certora quote + real-device PRF spike = owner actions, tracked in NEXT-SESSION returns |
| G10 | L8 A/B data must be per-sub-task; nothing collected so far | **A0** turns it on; Tasks 2–9 record reviewer/findings/adjudication per round |
| G11 | Task 11's deployment gate is "SPEC + partial dry-run" (`DEPLOY-GATE.md:12`); RPC-dependent checks unwired, yet Task 9 gates on all Task 11 boxes green | **Task 11R (new)**, before Task 9: implement the non-dry-run RPC checks with deterministic pass/fail fixtures; live-chain verification may stay honestly UNVERIFIED until a release candidate exists |

## 3. Top risks (merged, ranked)

1. **Conservation model mistaken for a proof.** The intra-CPI round trip is
   unclosable by snapshots; `max_in` is a recorded design bet. Mitigation: real-CPI
   tests in 2/5/6, pinned source ATA + decoded `max_in` in 6, C4b fixtures, Task 9
   keeps the claim explicitly bounded until mutation/differential evidence exists.
2. **False-green assurance close-out.** Empty scorecard + stale threat model +
   missing Task 11 evidence block + a deployment gate that is only a partial dry-run
   would let Task 9 "pass" unauditable. Mitigation: A0 first; Task 11R before Task 9;
   every gate names its command + SHA; zero-finding rounds recorded; unrecorded
   pre-A0 rounds surface as an explicit owner-adjudicated baseline exception, never
   silently.
3. **Build-ID change strands accounts.** Immutable origin, no migration path.
   Mitigation: C1a decision gate before onboarding; V4 blocked on it.
4. **Every real root ceremony fails despite correct on-chain code** (high-S browser
   signatures). Mitigation: C2a owns normalization + a recorded high-S fixture
   through the production builder.
5. **Scope creep from 215 open C/V/U checkboxes** while 1B is unfinished — polished
   client/UI code over unstable security state. Mitigation: the gate list in §1;
   only A0, C0+V0, and Phase 1B tasks run before Task 8.

## 4. Next two sessions — execution order

**Session A**
1. Preflight (no lease): clean tree, ancestry check, record starting SHA.
2. **A0 lease** — `docs/security/{THREATMODEL.md,REVIEW-SCORECARD.jsonl}` (+ a
   review-runs record with schema and tests per G2), `docs/security/invariants.jsonl`
   + generated Markdown (the G7 `WRD-CONS-*` repair), `docs/program/PHASE1B-MEASUREMENTS.md`,
   `scripts/review.sh` + its tests, plan status table (DONE-SHA column per task,
   Task 11 marked **partial** per G11). Threat-model deltas for Tasks 0/1/2b/11
   are *appended* with their actual landed SHAs, honestly labeled retrospective,
   including the correction superseding the unauthenticated-create row — the file
   is append-only, the baseline is never rewritten. Rerun Task 11 repo-side gates
   at the resulting SHA and record only what actually passes; the deployment gate
   stays partial until Task 11R. Gates: `git status --porcelain` clean precondition,
   `node scripts/gen-invariants.mjs --check`, `pnpm --filter @warden/core test`,
   `./scripts/supply-chain-gate.sh`, and after commit
   `git diff --check <task-base>..<task-head>` recording both SHAs (a true
   committed-range check — a working-tree `git diff --check` at a clean SHA checks
   nothing, and a head-only `git show --check` misses earlier commits of a task).
   Codex review; A0 changes what a valid review is, so a confirmation round follows
   any fix.
3. **C0+V0 lease** — seed all C0/C1a/C2a/C4b/V0 + event-observability rows at honest
   `unimplemented`; threat-model rows per both plans; extend the required-id
   presence test; **write C1a, C2a, C4b, 5E, the Task 2 split, and Task 11R into
   their source plans as full tasks** (checkboxes, file lists, red tests, acceptance
   commands — e.g. C2a's malformed-DER set + high-S end-to-end acceptance; C4b's
   provenance/freshness rules with explicit block/warn outcomes; 5E's event schemas
   across all root/session paths with attempted-vs-committed semantics; Task 2's
   exact harness paths/test names + fallback builds for both new `.so` files) and
   record the U7 split / V4-after-C1a+C2a+C3+C4 / V2–C6 clarification in the three
   derived plans' dependency sections **and in `docs/NEXT-SESSION.md`** — the
   incumbent handoff still permits V4/U7 after C1 alone and does not reference this
   campaign plan; add it to the handoff's READ list and carry the C1a/C2a/C3/C4,
   U0–U2 token-export, C6, and Task 11R gates into its order contract. Same gates +
   Codex docs review.
4. **Task 2A** (mutator) if budget allows — serialized `anchor build`, harness smoke
   tests, test-gate extension, commit, review round 1.

**Session B**
5. **Task 2B** (jup-mock) → combined Task 2 gate on one SHA:
   `anchor build`; both harness tests; clippy (workspace incl. new crates,
   `-D warnings` and `-D clippy::arithmetic_side_effects` on warden);
   `./.claude/test-gate.sh`; supply-chain gate; ledger check;
   `git diff --check <pre-2A-base>..<task-head>` (range covers 2A and 2B).
   **The Codex review range spans the whole task, pre-2A through 2B**, not just
   the 2B diff. Review + fix loop; second round if
   any accept/reject boundary moved; rerun the full gate on the final post-fix SHA.
6. **Task 3** (registry) as the stretch goal — registry authorization moves an
   accept/reject boundary: round 1 → fixes → clean round 2 required.

**Explicitly not in these sessions:** C1+ implementation, V1+, U0–U10, Figma,
native mobile, deployment, or any `pnpm ui:*` command (none exist yet).

**Owner decisions surfaced (non-blocking for Sessions A/B):**
- Grant a U0–U2 Figma design lease (for a session AFTER A/B), or hold until after
  Task 5?
- **C1a: freeze a pinned production extension ID (refusing migration), or fund an
  authenticated Phase 1C origin-migration design?** Blocks public account creation.
- Schedule the real-device WebAuthn PRF spike (hardware needed; blocks C2 assumptions).
- Request the Certora quote (L6) at 1B close-out?
- Task 9 baseline exception for pre-A0 review rounds that were never recorded
  (recommended: approve, with the gap named in the close-out), or block Task 9 on it?

## Self-review

- Every synthesis mandate now has an owner (§2) or an explicit deferral with a date.
- No task here duplicates steps already specified in the four adjudicated plans;
  amendments are recorded once, in §1/§2, and applied to the plan files inside the
  A0 / C0+V0 leases, not silently.
- Both analyses agreed on items 2–4 of §1 independently; divergences (Task 2 split,
  5E, C1a/C2a/C4b, V4 gating) came from Codex and were verified against repo source
  before adoption (`THREATMODEL.md:31`, `create_account.rs` PoP frame,
  0-byte scorecard, `test-gate.sh:50`, spec:60/:232).

## Codex review of this document

**Round 1 — thread `01a01ddb-257a-7713-b0b7-9565240dd1d6`, `gpt-5.6-sol` @ `max`:
REVISE.** 8 Important findings, all applied above: Task 11 was overstated as
implemented (now partial + Task 11R, G11); the new tasks were labels with no
acceptance criteria (now written into source plans by the C0+V0 lease, with named
acceptance content); C1a was missing from the execution order, the V4 gate, and the
owner-decision list (all three added); U7 token export was allowed before U0–U2
existed (now gated on U0–U2 acceptance; C6 clarified as downstream revalidation);
a forward-only review record left Tasks 0–11 unaccounted at Task 9 (schema + tests +
`not-recorded` baseline + owner exception decision added); `git diff --check` at a
clean SHA checks nothing (replaced with `git status --porcelain` precondition +
committed-range `git show --check`); `WRD-CONS-*` at `unimplemented` contradicted
landed Task 1 code (rescoped to A0 at `llm-asserted`/`test-covered` with cited SHA);
and "no threat-model deltas" was too strong — the Task 10 delta exists at
`THREATMODEL.md:52`, the file is append-only, and corrections are appended, never
rewritten.

**Round 2 — thread `01a01de9-a43c-7952-bddd-f9c1cfc2d2d2`: REVISE** (six round-1
fixes confirmed; four residuals, all applied): the Base line still said
"repo-gate-complete" against its own `partial` ruling (reworded); `git show --check`
is head-only, not a range (both gates now `git diff --check <base>..<head>` with
both SHAs recorded); the amendment tranche omitted `docs/NEXT-SESSION.md`, whose
order contract still permits V4/U7 after C1 alone (added); and Sessions A/B both
excluded and conditionally allowed U0–U2 (now unconditionally excluded from A/B).

**Round 3 — thread `01a01df1-a165-7da2-9de3-ef8d7d78c1a7`: SHIP-DOC** (all four
round-2 residuals confirmed addressed; no new operative contradiction).
