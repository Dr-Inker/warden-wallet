# Warden Wallet — Codex Review Protocol on a Machine-Checkable Invariant Ledger

## Findings

- **Warden already has the scaffolding for this.** The repo runs a two-model loop (Claude implements, Codex reviews) with public per-phase ledgers (`PHASE0-LEDGER.md`, `PHASE1A-LEDGER.md`) and a CI gate (`.claude/test-gate.sh`), plus 292 Rust/50 TS tests and measured CU costs in `docs/program/PHASE1A-MEASUREMENTS.md` (repo: github.com/Dr-Inker/warden-wallet, spec `docs/superpowers/specs/2026-08-18-warden-wallet-design.md` rev 7). The missing piece is a **structured, ID-addressable invariant list** Codex can check against mechanically instead of free-text review.

- **Precedent for a machine-checkable ledger already exists in the Solana ecosystem.** Certora's Squads V4 report (Nov 2024, `github.com/Squads-Protocol/v4/blob/main/audits/certora_squads_v4_security_report_and_formal_verification*.pdf`) publishes exactly this pattern: named, numbered CVL properties (P-02 "any function that might modify the multisig calls `invariant` and all invariants hold," P-04 "integrity of controlled multisig," `invariant_vault_proposal_draft/active/approved/…`) each with a Verified/Violated status and a link to the machine-generated rule report. This is the template to imitate: **invariant ID → rule → status → evidence link**, not prose.

- **TOB-SQUADS-7 (High, Access Controls)** — Trail of Bits, Squads v4 Security Assessment, Oct 19 2023 (`.../trail_of_bits_squads_v4_security_audit.pdf`): `create_key` in `multisig_create` was unauthenticated (no signature required), letting an attacker front-run multisig creation and seed it with their own members, later draining vaults. **This maps directly onto Warden's own documented gap**: "Account creation currently lacks authentication but will be bound to the root key with proof-of-possession in Phase 1B" (per Warden's design spec). TOB-SQUADS-7 is not abstract prior art here — it is the *exact* bug class Warden's `create_account` currently has open.

- **TOB-SQUADS-8 (Medium, Undefined Behavior)** — same report: ephemeral PDA signer seeds derived only from the batch key, not the individual transaction, so all transactions in a batch share one ephemeral keypair and account-creation sub-instructions collide. Maps onto Warden's planned `queue` (staged/timelocked transactions) and any future batched `execute` calls — any PDA whose seeds don't uniquely bind (tx index, creator, nonce) reproduces this class.

- **ND-SQD3-LO-01 (Low, Availability)** — Neodyme, Squads v4 report, 2024 final (`.../neodyme_squads_v4_report_2024_final.pdf`): `TransactionBuffer` PDAs were seeded `[multisig, buffer_index]` (256 slots per multisig), so one malicious member with Initiate permission could fill all 256 with un-closable garbage, DoSing the feature account-wide; fixed by adding the creator pubkey to the seeds (commit `74fafb1`). **Notably corroborated independently**: Certora's own H-01 in the same audit cycle ("Transaction buffer account may become inaccessible and unclosable") flags the identical failure mode from a different verification approach — two firms, two methods, same root cause. This is a recurring vulnerability *class* (unbounded, uncleanable buffer PDAs) that Warden must check against its own planned buffer/queue instructions before Phase 1B ships.

- **ACC-C1/C2/H1/H2/M1/M2** — named in the task brief as prior-art findings from a comparable secp256r1/WebAuthn passkey-rooted smart-account audit. I could not independently re-verify these citations' primary source this session (WebSearch budget was exhausted workflow-wide before I could query it, and no cached copy exists in this workflow's shared tool-results). **Flagging as UNVERIFIED rather than fabricating content.** This is itself a finding: a review protocol that "seeds" from six unverified IDs is exposed to the same failure it's meant to prevent — Codex or Claude could silently treat a phantom citation as ground truth. The protocol below is designed to fail closed on this.

## The Protocol

**1. Invariant ledger (`docs/security/INVARIANTS.md`, YAML/JSON source of truth).** IDs namespaced by spec surface, derived from Warden's own instruction set: `WRD-ROOT-*` (secp256r1/WebAuthn root verification), `WRD-NONCE-*` (clientDataJSON scanning + nonce consumption), `WRD-SESS-*` (session key per-tx/lifetime caps), `WRD-CAP-*` (day/30-day buckets), `WRD-TL-*` (timelock/cancel), `WRD-EXEC-*` (execute rewrite, before/after conservation, adapter registry), `WRD-BUF-*` (staged/buffer PDAs — pre-seeded now from ND-SQD3-LO-01/Certora-H-01). Each entry: `id`, `statement` (single testable sentence), `spec_ref` (path:line in the design spec), `code_ref` (path:line, filled once implemented), `prior_art` (array of finding IDs — TOB-SQUADS-7/8, ND-SQD3-LO-01, ACC-* tagged `unverified: true` until sourced), `status: unimplemented|held|violated|inconclusive`.

**2. Every Codex review is seeded, not freeform.** The reviewer prompt injects (a) the diff, (b) every ledger entry whose `code_ref` overlaps the diff's files/instructions, and (c) the full text of each entry's `prior_art` findings. Codex may not close a review without emitting a per-invariant verdict for every seeded entry — silence on a seeded invariant is itself a FAIL.

**3. Mandatory schema-JSON output** (validated by CI before merge, not just eyeballed):
```json
{"invariant_id":"WRD-ROOT-03","verdict":"VIOLATED|HELD|INCONCLUSIVE",
 "severity":"critical|high|medium|low",
 "prior_art_cited":["TOB-SQUADS-7"],
 "reproducing_test":{"path":"tests/...","name":"...","fails_on_HEAD":true,"passes_after_fix":true},
 "evidence":"path:line","confidence":0.0-1.0,"notes":"..."}
```
A `VIOLATED` verdict with no `reproducing_test` (a red test proving the bug on current `HEAD`) is automatically downgraded to `INCONCLUSIVE` — this is the mechanical check that keeps Codex honest and matches Certora's own "link to rule report" discipline.

**4. Adjudication ladder:** worker (Claude) → seeded Codex review → if `VIOLATED` with a reproducing test, fix required before merge; if `INCONCLUSIVE`, a second independent Codex pass at higher effort, and two `INCONCLUSIVE`s in a row escalate to a human ruling recorded in the phase ledger (mirrors the existing `PHASE1A-LEDGER.md` convention — no new process, just a stricter input format).

**5. False-positive measurement:** every closed `VIOLATED` verdict is logged with outcome (`fixed`/`disputed`/`false_positive`) in `docs/security/REVIEW-SCORECARD.jsonl`; monthly, sample 1-in-10 `HELD` verdicts for blind re-review — an unreviewed `HELD` that later breaks is a **false negative**, weighted worse than a false positive in the scorecard, since a wallet holding funds should bias toward over-flagging.

## Open Questions
- Exact primary source for ACC-C1/C2/H1/H2/M1/M2 — must be resolved (or the IDs dropped) before the ledger ships publicly.
- Whether `WRD-BUF-*` gets a Certora-style CVL spec once `queue` lands, given two independent firms hit this exact bug class on Squads.

## Confidence
High on TOB-SQUADS-7/8, ND-SQD3-LO-01, and the Certora-precedent argument (primary PDFs read directly). Low on ACC-* content (unverified). Medium on protocol design — sound by analogy to Certora/Squads practice, but untested at Warden's scale.