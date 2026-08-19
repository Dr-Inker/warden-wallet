# Warden — invariant ledger (assurance layer L1)

**`docs/security/invariants.jsonl` is the source of truth. This file is generated from it.**
Edit the JSONL, then run `node scripts/gen-invariants.mjs` (or `--check` in CI). Never hand-edit
the table below the marker.

The ledger proves nothing by itself. What it buys is **addressability**: a review verdict becomes
"Codex ruled on `WRD-EXEC-07`" instead of "Codex reviewed the diff", and a gap becomes a row with a
status instead of an absence nobody notices. The shape is copied from Certora's Squads v4 report,
which publishes named CVL properties each with a status and a link to its machine-generated rule
report — **ID → statement → spec ref → code ref → prior art → status → evidence**, not prose.

Binding process: **spec §17** (`docs/superpowers/specs/2026-08-18-warden-wallet-design.md`).
Derivation and sources: `docs/research/2026-08-18-security-assurance-and-wallet-landscape.md` §1.

---

## 1. Record shape

One JSON object per line. Fields:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | `WRD-<NAMESPACE>-<NN>`. Immutable once published; never renumber, retire instead. |
| `title` | string | Short label, for tables and review prompts. |
| `statement` | string | **One testable sentence.** If you cannot imagine the negative test, the statement is too vague. |
| `spec_ref` | string | Path + section in the design spec. The ledger never invents policy; it gives existing spec text an ID. |
| `code_ref` | string \| null | `path` or `path:line` where the invariant is enforced. `null` until implemented. |
| `phase` | `1A` \| `1B` \| `1C` | Which phase owns the surface. |
| `prior_art` | string[] | IDs from `PRIOR-ART-FINDINGS.md`. |
| `status` | enum | The invariant's own standing — see §2. |
| `evidence` | object[] | `{type, path, name?, sha}`. `type` is the evidence-type enum (§3). `sha` is the commit at which the evidence was last verified. |
| `last_reviewed` | object | `{thread, date}` — which review thread last ruled on this row. |
| `notes` | string | Stated limits, open gaps, the reason a status is being held down, measured numbers. |

## 2. `status` — the invariant's own axis

**Ascending proof strength. Exactly one field with these values. There is no `holds: true|false`
boolean alongside it** — a second representation of the same fact is a desync waiting to happen.

| Status | Means |
|---|---|
| `unimplemented` | The surface does not exist yet. The honest default for every 1B/1C row. |
| `llm-asserted` | A model (or a human reading the code) believes it holds. **Not evidence.** |
| `test-covered` | At least one executable test in this repo fails if the invariant is violated. |
| `mutation-tested` | The covering tests survive mutation of the enforcing code (`cargo-mutants`, L4). |
| `proven` | A formal proof exists (Certora/CVLR, L6). **The `notes` field must state the proof's limit**: a CVLR proof says nothing about CPI effects, precompile semantics, account loading, or the SBF the validator runs. |
| `holds` | ≥1 accepted evidence artefact of an allowed type **and** no open contradicting finding. The ledger-side counterpart of a `REFUTED` attack claim. |

**`holds` is the row L3 samples for false negatives** — 1-in-10 monthly, blind re-review, weighting a
missed bug worse than a false alarm. That is the entire reason `holds` is a distinct value and not a
synonym for `test-covered`.

**Who may set `holds`:**

1. An **evidence artefact** of an allowed type (§3), recorded with a path and a SHA; **or**
2. an explicit **human security adjudication**, recorded in `REVIEW-SCORECARD.jsonl` with its rationale.

**Model agreement is a confidence signal, never evidence, and never promotes a row on its own.**
Two models can be confidently wrong together — that is precisely why prior-art seeding exists.
Agreement raises triage priority and nothing else. **No tool confers a proof status until it has been
piloted on this repo**: a clean fuzzing campaign raises an invariant to `test-covered` at best, never
to `proven`.

**Seeding rule: nothing is seeded at `holds`.** Every row starts at its honest status — mostly
`unimplemented` for 1B surfaces and `test-covered` for shipped 1A ones.

## 3. `evidence[].type` — how it is known

`red_test` · `static_trace` · `formal_counterexample` · `config_attestation` · `primary_source`

Same enum as a finding's `evidence_type` (§4), deliberately: the two sides of the ledger have to speak
one vocabulary or a finding can never be matched to the invariant it contradicts.

On the ledger side `red_test` means **an executable test artefact in this repo that fails if the
invariant is violated** — the negative/attack tests, not the happy-path ones. A test that only asserts
the happy path is not evidence for an invariant; it is evidence the feature works.

## 4. How a finding relates to a row

A finding lives in `.codex/schemas/warden-findings.json` and carries **two orthogonal axes that must
never be collapsed**:

- **`truth_status` ∈ `POTENTIAL | CONFIRMED | REFUTED`** — the claim's standing.
- **`evidence_type`** — *how* it is known.

Collapsing them ("no red test ⇒ inconclusive") would discard static traces, supply-chain and
dependency-provenance findings, key-management and release-credential failures, upgrade-authority
misconfiguration, economic/MEV and liveness attacks, and formal counterexamples — all real, most
unreproducible as a LiteSVM test.

**Reproducers.** Required only where one is *feasible*. When present it must **FAIL on `base_sha` and
PASS on `fixed_sha`** — "fails on HEAD" is the wrong predicate the moment a fix lands. Where a
reproducer is infeasible, the finding routes to **human security adjudication** and is recorded with
the reason. It is **never auto-downgraded**.

**Adjudication rules (spec §17, restated because they bind here):**

1. A finding raised by **either** model enters as `POTENTIAL`.
2. Model agreement is confidence, not evidence.
3. `CONFIRMED` requires an evidence artefact of an allowed type **or** a recorded human adjudication.
4. **Disagreement escalates to a human and is never auto-dismissed**; the ruling is recorded.
5. **Any diff that moves an accept/reject boundary gets a mandatory second-round confirm.** Precedent:
   the round-1 fix to the P-256 root check over-corrected and rejected `x = 0` — a valid point — and a
   *second* Codex round caught it (`4b409f7`).
6. **Silence on a seeded invariant is a FAIL, not a pass.**

A `CONFIRMED` finding against a row **immediately** knocks that row down to `llm-asserted` (or lower)
and it stays there until the fix lands *with* a test. A row may not sit at `holds` with an open
contradicting finding, by definition.

## 5. How Codex audits the ledger, per milestone

`scripts/review.sh <base-sha>` is the mechanism; the rules it enforces:

1. **Clean tree is a precondition.** `codex review --base <sha>` on a dirty tree repeats *hallucinated*
   findings unrelated to the diff ([openai/codex#8404](https://github.com/openai/codex/issues/8404)).
2. **Seed the prompt with** the invariant rows overlapping the diff, `docs/security/PRIOR-ART-FINDINGS.md`
   (mandatory, every round), and the **named sibling files carrying cross-cutting invariants** —
   `programs/warden/src/root_verify/transcript.rs`, `programs/warden/src/state/session.rs`,
   `programs/warden/src/errors.rs`, `programs/warden/src/buckets.rs`.
   The one false positive in the 1A pilot came from **reviewer scope, not model identity**: Codex flagged
   `cluster_tag` binding in `create_account.rs`, a property `transcript.rs:69-76` documents as knowingly
   deferred, in a file Codex had not been shown.
3. **Blind and anti-rewrite.** Diff + spec section + seeded invariants; no author framing; an explicit
   instruction against rewriting working code.
4. **Standing checklist item for dimensional/scaling bugs.** Moonwell shipped Claude-authored code using
   a cbETH/ETH ratio as if USD-denominated — 2,000× underpricing, $1.78M, past a human reviewer.
5. **Output is JSON validated by an independent validator**, never trusted because `--output-schema` was
   passed (that flag constrains the *final response*, not every JSONL event).
6. **Silence on a seeded invariant is a FAIL.** Every round must return a verdict for every seeded ID.
7. **Every finding is logged**, including disputed and scoped-out ones, with adjudication rationale.
   Four Codex rounds on Phase 1A produced 1 Critical / 4 Important / 6 Minor at 100% adopted — that is a
   survivorship artifact of what gets committed, **not** a 0% false-positive rate.

**Every task in the Phase 1B plan updates this ledger in its own commit** — new invariants at their
honest status, evidence paths filled in as tests land, `last_reviewed` stamped. **A task is not done
while its invariants are still `llm-asserted`.**

## 6. Namespaces

| Namespace | Surface | Seeded |
|---|---|---|
| `WRD-ROOT-*` | secp256r1 / WebAuthn root verification, proof of possession, precompile binding | yes |
| `WRD-NONCE-*` | root nonce consumption and freshness | yes |
| `WRD-CAP-*` | per-tx / day / rolling-30-day / lifetime caps and bucket arithmetic | yes |
| `WRD-EXEC-*` | `execute`/`swap` conservation, snapshots, value accounting | yes (all `unimplemented`) |
| `WRD-FRZ-*` | freeze gating | yes |
| `WRD-DENY-*` | the fixed deny-list above the registry | yes (all `unimplemented`) |
| `WRD-BUF-*` | buffer/`Stage` PDA squatting **and** the 1232-byte packet budget | yes |
| `WRD-STAGE-*` | staged-content binding and consumption | yes (all `unimplemented`) |
| `WRD-CD-*` | clientDataJSON parsing, if it outgrows `WRD-ROOT-06` | reserved |
| `WRD-SESS-*` | session lifecycle beyond caps | reserved |
| `WRD-REG-*` | adapter registry (Task 3) | reserved |
| `WRD-TL-*` / `WRD-GRD-*` | timelock / guardians (Phase 1C) | reserved |

`WRD-ROOT-01` is referred to as `WRD-PoP-01` in some plan prose; `WRD-ROOT-01` is canonical.

## 7. `REVIEW-SCORECARD.jsonl` (L3)

`docs/security/REVIEW-SCORECARD.jsonl` starts **empty**; `scripts/review.sh` appends to it. One JSON
object per line — a flattened finding plus its adjudication, so the file answers the question the
current loop structurally cannot: **how often is the reviewer wrong?**

```json
{"finding_id":"WRDF-0001","thread":"phase1b/task-05/round-2","date":"2026-08-19",
 "reviewer_model":"gpt-5.6-sol@max","base_sha":"…","severity":"critical",
 "truth_status":"CONFIRMED","evidence_type":"red_test","invariant_ids":["WRD-EXEC-06"],
 "ruling":"adopted","ruled_by":"human:owner","rationale":"…","reproducer_verified":true}
```

**Log every finding — disputed and scoped-out ones included.** Four Codex rounds on Phase 1A produced
1 Critical / 4 Important / 6 Minor at **100% adopted**; that is a survivorship artifact of what gets
committed, not a 0% false-positive rate, and a scorecard that only records adopted findings would
reproduce the artifact forever.

**Monthly:** blind re-review a **1-in-10 sample of rows sitting at `holds`** — that is where a false
negative hides — weighting a missed bug worse than a false alarm.

---

<!-- BEGIN GENERATED: scripts/gen-invariants.mjs -->

_Generated by `scripts/gen-invariants.mjs` from `docs/security/invariants.jsonl` — 43 invariants. Do not edit this table by hand._

| status | count |
|---|---|
| `unimplemented` | 19 |
| `llm-asserted` | 1 |
| `test-covered` | 23 |
| `mutation-tested` | 0 |
| `proven` | 0 |
| `holds` | 0 |

### Phase 1A

| ID | Invariant | Status | Spec | Prior art | Evidence |
|---|---|---|---|---|---|
| `WRD-NONCE-01` | **Root nonce is a strictly increasing odometer** — SmartAccount.root_nonce increases by exactly 1 on every successful root instruction and never decreases, so no assertion is consumable twice. | `test-covered` | design.md#4 (root nonce = an odometer, not a set) | `LZR-ACC-M1` | `programs/warden/tests/root_verify.rs` :: `rotate_nonce_ok_and_nonce_increments`<br>`programs/warden/tests/root_verify.rs` :: `consecutive_ceremonies_each_consume_one_nonce` |
| `WRD-NONCE-02` | **Strict n+1 equality, not a window** — A transcript whose root_nonce is not exactly equal to the stored value is rejected; there is no acceptance window and no replay bitmap. | `test-covered` | design.md#4 | `LZR-ACC-M1` | `programs/warden/tests/root_verify.rs` :: `replay_same_assertion_rejected`<br>`programs/warden/tests/root_verify.rs` :: `stale_nonce_far_in_the_past_rejected_as_challenge_mismatch` |
| `WRD-NONCE-04` | **Wall-clock expiry is the secondary bound** — expiry_ts must satisfy now <= expiry_ts <= now + 600s; an expired transcript and one expiring beyond the 600s horizon are both rejected, and the 600s boundary itself is accepted. | `test-covered` | design.md#4 | — | `programs/warden/tests/root_verify.rs` :: `expired_rejected`<br>`programs/warden/tests/root_verify.rs` :: `future_expiry_beyond_600s_rejected`<br>`programs/warden/tests/root_verify.rs` :: `expiry_exactly_at_the_600s_boundary_accepted` |
| `WRD-CAP-01` | **Cap dominance** — Every accepted spend satisfies amount <= min(per_tx, per_day - spent_today, per_30d - sum(ring)), and for a session additionally lifetime_spent + amount <= lifetime_cap. | `test-covered` | design.md#5.2 rule 4 | — | `programs/warden/src/buckets.rs` :: `tests::within_all_caps_ok`<br>`programs/warden/src/buckets.rs` :: `tests::per_tx_exceeded_err`<br>`programs/warden/src/buckets.rs` :: `tests::day_cap_exceeded_err`<br>`programs/warden/tests/transfer.rs` :: `session_sol_over_per_tx_rejected` |
| `WRD-CAP-02` | **Bucket accounting is exact and the ring self-cleans** — spent_today equals the sum of the day's debits, sum(ring) <= per_30d, and no ring slot survives a rollover that should have zeroed it. | `test-covered` | design.md#5.2 rule 4 | — | `programs/warden/src/buckets.rs` :: `tests::day_rolls_over_at_utc_midnight`<br>`programs/warden/src/buckets.rs` :: `tests::ring_30d_cap_enforced_across_days`<br>`programs/warden/src/buckets.rs` :: `tests::ring_zeroes_skipped_days`<br>`programs/warden/src/buckets.rs` :: `tests::ring_slot_index_at_day_29_30_31`<br>`programs/warden/tests/transfer.rs` :: `rolling_30d_cap_enforced_end_to_end` |
| `WRD-CAP-03` | **No cap means zero, never unlimited** — A mint with no cap entry (and a zeroed cap entry) permits outflow of exactly 0; the missing-cap branch rejects rather than skipping the check. | `test-covered` | design.md#5.2 rule 4; #4 (expired/absent caps) | `LZR-ACC-C2` | `programs/warden/src/buckets.rs` :: `tests::unknown_mint_err`<br>`programs/warden/src/buckets.rs` :: `tests::zero_cap_means_no_spend`<br>`programs/warden/src/buckets.rs` :: `tests::find_cap_never_matches_default_mint`<br>`programs/warden/tests/transfer.rs` :: `session_mint_without_account_cap_rejected`<br>`programs/warden/tests/transfer.rs` :: `root_transfer_of_mint_without_threshold_rejected` |
| `WRD-CAP-04` | **An expired or revoked session is exhausted, not absent** — A session past expiry_ts, with a stale generation_at_grant, revoked, or belonging to another account is treated as having zero remaining allowance on every axis, never as an account with no cap configured. | `test-covered` | design.md#4 (exhausted, not absent) | `LZR-ACC-C2`, `SWIG-ACC-C2` | `programs/warden/tests/transfer.rs` :: `session_expired_rejected`<br>`programs/warden/tests/transfer.rs` :: `session_wrong_generation_rejected`<br>`programs/warden/tests/transfer.rs` :: `session_of_another_account_rejected`<br>`programs/warden/tests/transfer.rs` :: `session_mint_without_session_cap_rejected` |
| `WRD-CAP-05` | **Root direct spend is bounded like a session** — Every root direct path (transfer, and in 1B execute and swap) enforces outflow[mint] <= large_threshold[mint] per transaction AND debits the same account-wide day and rolling-30-day buckets. | `test-covered` | design.md#5.2 rule 4 | — | `programs/warden/tests/transfer.rs` :: `root_transfer_within_threshold_debits_buckets`<br>`programs/warden/tests/transfer.rs` :: `root_transfer_over_threshold_rejected` |
| `WRD-CAP-06` | **Debit is atomic** — A debit that is going to be rejected leaves every bucket field byte-identical to its pre-call value, including when the rejection happens after a day-boundary rollover or an arithmetic overflow guard fires. | `test-covered` | design.md#5.1 (checked arithmetic everywhere) | — | `programs/warden/src/buckets.rs` :: `tests::debit_atomic_on_cap_exceeded_after_day_boundary`<br>`programs/warden/src/buckets.rs` :: `tests::debit_atomic_on_overflow_after_day_boundary`<br>`programs/warden/tests/transfer.rs` :: `token_cpi_failure_leaves_state_unchanged` |
| `WRD-CAP-07` | **Day and 30-day windows are account-wide, not per session** — Every session and the root debit the same SmartAccount.buckets, so N sessions do not get N day caps; and a grant that sets a non-zero per-session per_day/per_30d is rejected rather than stored. | `test-covered` | design.md#4 (what a session cap bounds, exactly) | — | `programs/warden/tests/transfer.rs` :: `two_sessions_share_account_day_cap`<br>`programs/warden/tests/transfer.rs` :: `session_day_cap_across_two_txs`<br>`programs/warden/tests/sessions.rs` :: `grant_with_session_day_caps_rejected` |
| `WRD-CAP-08` | **Session lifetime cap is exact and survives a regrant** — lifetime_spent + amount <= lifetime_cap on every session spend, a regrant merges by mint while preserving spent, and a regrant that would set a lifetime cap below what has already been spent is rejected. | `test-covered` | design.md#4; #5.1 grant_session | `LZR-ACC-H1` | `programs/warden/tests/transfer.rs` :: `session_lifetime_cap_enforced`<br>`programs/warden/tests/sessions.rs` :: `regrant_lower_lifetime_than_spent_rejected`<br>`programs/warden/tests/sessions.rs` :: `regrant_merges_by_mint_and_preserves_spent`<br>`programs/warden/tests/sessions.rs` :: `regrant_cannot_silently_retain_caps_the_signer_never_saw` |
| `WRD-FRZ-01` | **frozen gates every outflow and every grant** — While SmartAccount.frozen is set, no instruction that moves value or widens authority succeeds -- transfer (session and root), grant_session, and in 1B execute, swap and execute_pending. | `test-covered` | design.md#5.1 (cross-cutting) | — | `programs/warden/tests/transfer.rs` :: `frozen_blocks_transfer`<br>`programs/warden/tests/transfer.rs` :: `root_freeze_blocks_transfer_and_grant`<br>`programs/warden/tests/freeze.rs` :: `grant_frozen_rejected` |
| `WRD-FRZ-02` | **A freeze is not a brick** — rotate_nonce still succeeds while frozen, so the root can always prove liveness and reach unfreeze; freeze blocks value movement, not the root ceremony itself. | `test-covered` | design.md#5.1 freeze/unfreeze | `ARGENT-ZERO-GUARDIAN` | `programs/warden/tests/freeze.rs` :: `rotate_nonce_still_allowed_when_frozen`<br>`programs/warden/tests/freeze.rs` :: `unfreeze_before_timelock_rejected`<br>`programs/warden/tests/freeze.rs` :: `unfreeze_after_timelock_ok` |
| `WRD-ROOT-03` | **User verification is mandatory** — authenticatorData must have both UP and UV set; a UP-only assertion is rejected. | `test-covered` | design.md#4 | — | `programs/warden/tests/root_verify.rs` :: `up_only_rejected` |
| `WRD-ROOT-04` | **rpIdHash is SHA-256 of the FULL origin, read from state** — rp_id_hash equals SHA-256("chrome-extension://<id>") -- not SHA-256("<id>") -- it is recomputed on-chain from the stored origin at creation, read from SmartAccount state on every verification, and never taken from caller-supplied instruction data or a compiled-in literal. | `test-covered` | design.md#4 (rpIdHash) | `LZR-ACC-H2` | `programs/warden/tests/create_account.rs` :: `rejects_rp_id_hash_not_sha256_of_origin`<br>`programs/warden/tests/create_account.rs` :: `rejects_rp_id_hash_of_bare_extension_id`<br>`programs/warden/tests/root_verify.rs` :: `wrong_rp_id_hash_rejected`<br>`programs/warden/tests/root_verify.rs` :: `rp_id_hash_of_bare_extension_id_rejected` |
| `WRD-ROOT-05` | **Precompile binding and ordering** — The root path binds exactly one secp256r1 precompile instruction, named by index in its own instruction data, at a lower index than the warden instruction, executed by the real secp256r1 program id, carrying exactly one signature whose (pubkey, message, signature) equal (root.pubkey, authenticatorData \|\| SHA256(clientDataJSON), sig). | `test-covered` | design.md#4 | `LZR-ACC-C1` | `programs/warden/tests/root_verify.rs` :: `hand_built_precompile_ix_matches_crate`<br>`programs/warden/tests/root_verify.rs` :: `two_signature_precompile_rejected`<br>`programs/warden/tests/root_verify.rs` :: `foreign_program_at_named_index_rejected`<br>`programs/warden/tests/root_verify.rs` :: `precompile_after_our_ix_rejected`<br>`programs/warden/tests/root_verify.rs` :: `precompile_ix_index_out_of_range_rejected`<br>`programs/warden/tests/root_verify.rs` :: `two_precompile_ixs_only_named_one_binds`<br>`programs/warden/tests/root_verify.rs` :: `message_mismatch_rejected`<br>`programs/warden/tests/root_verify.rs` :: `foreign_ix_index_rejected` |
| `WRD-ROOT-06` | **Strict depth-0 clientDataJSON scanner** — clientDataJSON is rejected above MAX_CLIENT_DATA_LEN (512 B); the object is walked at depth 0 only; exactly one top-level type/challenge/origin is required and any duplicate top-level key rejects; JSON escapes are decoded before comparison or the value is rejected; type == "webauthn.get"; origin equals the stored origin; challenge equals base64url(transcript hash); a present crossOrigin must be the JSON boolean false. Byte-substring matching is forbidden. | `test-covered` | design.md#4 (strict top-level scanner) | `LZR-ACC-H2` | `programs/warden/src/root_verify/client_data.rs` :: `tests::nested_string_containing_braces_does_not_desynchronise_the_scanner`<br>`programs/warden/src/root_verify/client_data.rs` :: `tests::rejects_duplicate_origin_written_with_unicode_escape`<br>`programs/warden/src/root_verify/client_data.rs` :: `tests::rejects_surrogate_escape`<br>`programs/warden/src/root_verify/client_data.rs` :: `tests::rejects_over_512_bytes`<br>`programs/warden/tests/root_verify.rs` :: `nested_origin_rejected_on_chain`<br>`programs/warden/tests/root_verify.rs` :: `duplicate_origin_rejected_on_chain`<br>`programs/warden/tests/root_verify.rs` :: `cross_origin_true_rejected_on_chain`<br>`programs/warden/tests/root_verify.rs` :: `webauthn_create_type_rejected_on_chain`<br>`programs/warden/tests/root_verify.rs` :: `escaped_origin_accepted_on_chain` |
| `WRD-ROOT-07` | **cluster_tag domain separation** — cluster_tag is a 32-byte client-attested domain separator stored at creation, non-zero-checked, immutable in 1A, and bound into the transcript so an assertion produced against one stored tag cannot be replayed against an account holding a different tag. | `test-covered` | design.md#4 | `LZR-ACC-M2` | `programs/warden/tests/root_verify.rs` :: `wrong_cluster_tag_rejected`<br>`programs/warden/tests/create_account.rs` :: `rejects_zero_cluster_tag` |
| `WRD-ROOT-08` | **Generation staleness rejects** — A transcript carrying a generation other than the account's current generation is rejected, so a recovery (which bumps generation) invalidates every outstanding assertion, session, stage and pending action. | `test-covered` | design.md#4; #5.1 execute_recovery | — | `programs/warden/tests/root_verify.rs` :: `stale_generation_rejected`<br>`programs/warden/tests/sessions.rs` :: `revoke_close_then_regrant_gets_current_generation` |
| `WRD-ROOT-09` | **action_hash binds the complete semantic inputs** — action_hash = Keccak256(op_type:u8 \|\| borsh(op_args)) where op_args contains every semantic input of the instruction the root authorises; the program recomputes it from the instruction it is executing and rejects on mismatch, so no argument or account can be swapped after the passkey ceremony. | `test-covered` | design.md#4 (action_hash) | `LZR-ACC-M2`, `LZR-ACC-H1` | `programs/warden/src/root_verify/transcript.rs` :: `tests::action_hash_separates_op_type_from_args`<br>`programs/warden/tests/transfer.rs` :: `root_transfer_with_substituted_destination_rejected`<br>`programs/warden/tests/transfer.rs` :: `root_transfer_amount_tamper_rejected`<br>`programs/warden/tests/sessions.rs` :: `grant_body_tamper_rejected_field_by_field`<br>`programs/warden/tests/sessions.rs` :: `revoke_by_root_substituted_refund_rejected`<br>`programs/warden/tests/freeze.rs` :: `op_bytes_are_pinned` |
| `WRD-ROOT-10` | **Transcript preimage byte layout is pinned across the language boundary** — transcript_hash = Keccak256("WARDEN/root/v1" \|\| cluster_tag[32] \|\| program_id[32] \|\| account[32] \|\| generation:u64LE \|\| policy_version:u32LE \|\| root_nonce:u64LE \|\| expiry_ts:i64LE \|\| signed_slot:u64LE \|\| action_hash[32]), and the Rust program, the packages/core TS mirror and the IDL agree on it byte for byte. | `llm-asserted` | design.md#4 (canonical preimage) | `LZR-ACC-H2` | `programs/warden/src/root_verify/transcript.rs` :: `tests::transcript_hash_matches_pinned_vector`<br>`programs/warden/src/root_verify/transcript.rs` :: `tests::every_transcript_field_changes_the_hash`<br>`packages/core/test/transcript.test.ts` :: `transcript golden vectors` |
| `WRD-BUF-03` | **Every root-ceremony transaction fits the 1232-byte packet** — A complete root ceremony transaction (secp256r1 precompile instruction + the warden instruction) serialises to at most MAX_TX_BYTES = 1232 for freeze, unfreeze, a 2-cap grant_session, and root transfer of SOL and of an SPL token. | `test-covered` | design.md#5.1 (Phase 1A measured limits) | — | `programs/warden/tests/freeze.rs` :: `freeze_tx_fits_1232_bytes`<br>`programs/warden/tests/freeze.rs` :: `unfreeze_tx_fits_1232_bytes`<br>`programs/warden/tests/sessions.rs` :: `grant_tx_fits_1232_bytes_with_2_caps`<br>`programs/warden/tests/transfer.rs` :: `root_transfer_tx_fits_1232_bytes`<br>`programs/warden/tests/transfer.rs` :: `root_spl_transfer_tx_fits_1232_bytes` |
| `WRD-BUF-04` | **Every session transaction fits the 1232-byte packet** — A session-signed transfer of SOL and of an SPL token each serialise to at most MAX_TX_BYTES = 1232. | `test-covered` | design.md#5.1 | — | `programs/warden/tests/transfer.rs` :: `session_sol_transfer_tx_fits_1232_bytes`<br>`programs/warden/tests/transfer.rs` :: `session_spl_transfer_tx_fits_1232_bytes` |
| `WRD-BUF-05` | **create_account packet limits are measured, not assumed** — A create_account with MAX_MINTS_AT_CREATE = 4 mints (cap + ceiling + threshold) fits the 1232-byte packet, a full 8-mint policy does not, and more than MAX_MINTS_AT_CREATE mints is rejected. | `test-covered` | design.md#5.1 create_account | — | `programs/warden/tests/create_account.rs` :: `realistic_two_mint_policy_transaction_fits_the_packet_limit`<br>`programs/warden/tests/create_account.rs` :: `max_mints_at_create_transaction_fits_the_packet_limit`<br>`programs/warden/tests/create_account.rs` :: `full_max_mint_caps_policy_does_not_fit_the_packet_limit`<br>`programs/warden/tests/create_account.rs` :: `rejects_more_mints_than_max_mints_at_create` |

### Phase 1B

| ID | Invariant | Status | Spec | Prior art | Evidence |
|---|---|---|---|---|---|
| `WRD-NONCE-03` | **Slot-based root freshness** — A root ceremony is accepted only while signed_slot <= Clock::slot < signed_slot + MAX_ROOT_SLOT_AGE (150): a future slot is rejected outright and an age of exactly 150 slots is rejected. | `unimplemented` | design.md#4 (freshness is slot-based, rev 8) | `LZR-ACC-M1` | — |
| `WRD-EXEC-01` | **Field-identity conservation on vault-owned token accounts** — For every account whose BEFORE snapshot is a vault-owned token account, every field except amount is byte-identical AFTER (runtime owner, token owner, mint, delegate, delegated_amount, close_authority, state, is_native, data_len, TLV-tail hash) and the after-state independently satisfies policy (state == Initialized, delegate == None, close_authority == None). | `unimplemented` | design.md#5.2 rule 2 | `SWIG-ACC-C1`, `LZR-ACC-C1` | — |
| `WRD-EXEC-02` | **Outflow is coalesced per mint before a single debit** — outflow[mint] is summed across ALL vault-owned token accounts of that mint (negative = inflow, floored at 0 for cap purposes) and passed to exactly one buckets::debit call per mint per instruction. | `unimplemented` | design.md#5.2 rule 4 | — | — |
| `WRD-EXEC-03` | **The SOL equation counts each lamport exactly once** — outflow[SOL] = (pda_lamports_before - pda_lamports_after) + sum over vault WSOL accounts of (amount_before - amount_after); WSOL token-account lamports are never counted separately, and non-WSOL CloseAccount rent enters only via the decoder's decoded close intents (spec 5.2 rule 4a). | `unimplemented` | design.md#5.2 rules 4 and 4a | — | — |
| `WRD-EXEC-04` | **Mint authority fields are byte-identical** — Whenever a vault-owned token account of mint M is writable, M's mint account must be present; if the vault holds any authority on M, every authority field (mint_authority, freeze_authority, and for Token-2022 transfer_fee_config_authority / withdraw_withheld_authority, extracted by TLV type and offset) is compared byte-for-byte and any change is an instruction reject, not an accounting entry. | `unimplemented` | design.md#5.2 rule 2a | `SWIG-ACC-C1` | — |
| `WRD-EXEC-05` | **A vault-owned token account may not disappear** — A vault-owned token account present BEFORE that does not exist or does not parse AFTER is a reject, unless the payload decoder handed the comparison a matching decoded close intent for that exact account; nothing downstream may infer a close from a disappearance. | `unimplemented` | design.md#5.2 rules 1a, 2, 3 | `SWIG-ACC-C1` | — |
| `WRD-EXEC-06` | **accounts_hash binds the logical list** — accounts_hash is computed over the LOGICAL account list in logical order (logical[0]=smart_account, logical[1]=signer, logical[2+k]=remaining_accounts[k]), hashing pubkey \|\| is_signer \|\| is_writable for each; no payload index ever refers to a physical slot and no code indexes the raw account slice. | `unimplemented` | design.md#5.2 (execute payload contract) | `LZR-ACC-C1`, `LZR-ACC-H1` | — |
| `WRD-EXEC-07` | **No inner instruction may set a delegate on a vault-owned token account** — No inner instruction of execute may set, change or clear a delegate on a vault-owned token account, on either the session path or the root path. | `unimplemented` | design.md#5.2 rules 1a and 3 | `SWIG-ACC-C1`, `LZR-ACC-C2` | — |
| `WRD-EXEC-08` | **Program owner is compared, not just field values** — The before/after snapshot compares each account's runtime program owner, so an account that is transferred out, closed and reopened under a program that fakes the SPL token byte layout fails the comparison. | `unimplemented` | design.md#5.2 rules 2 and 3 | `SWIG-ACC-C1` | — |
| `WRD-EXEC-09` | **Token-2022 danger extensions reject unconditionally in 1B** — permanent_delegate (12), transfer_hook (14) and confidential-transfer mints (4/5) reject unconditionally; transfer_fee (1) also rejects in 1B because the allow-list machinery is 1C. The decision is made by inspecting the mint's TLV, which is why the mint account must be present. | `unimplemented` | design.md#5.2 rule 5 | — | — |
| `WRD-EXEC-10` | **Adapter-decoded max_in and a pinned source ATA bound the call** — Before any inner CPI runs, the adapter parses max_in out of the inner instruction's own data (never inferred from balances) and compares it against the session per_tx and the account buckets, and the adapter's role validator requires the inner instruction's source account to be the specific vault ATA the caller declared. | `unimplemented` | design.md#5.2 rule 4b; #5.3 | — | — |
| `WRD-FRZ-03` | **1B value paths refuse while frozen** — execute, swap and execute_pending each refuse while frozen, re-validated against CURRENT state at execution rather than at queue time. | `unimplemented` | design.md#5.1 execute_pending | — | — |
| `WRD-ROOT-01` | **Proof of possession at account creation** — create_account cannot succeed without a valid root ceremony over the derived address, so the PDA cannot be squatted with an attacker-controlled root. | `unimplemented` | design.md#5.1 create_account | `TOB-SQUADS-7` | — |
| `WRD-ROOT-02` | **Root instructions are transaction-level only** — Every root instruction requires get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, so a root path can never be invoked through a middleman program. | `unimplemented` | design.md#5.1 (cross-cutting) | — | — |
| `WRD-DENY-01` | **Fixed deny-list, on both paths, above the registry** — SetAuthority, Approve, ApproveChecked and Revoke on SPL Token and Token-2022 are rejected in the execute payload decoder on BOTH the session and the root path, before dispatch and before any registry lookup; CloseAccount is rejected unless ALL of: it is a direct payload instruction (not nested inside another program's CPI), the account's amount_before is exactly 0, the decoded destination is the SmartAccount PDA, and the account is neither the PDA itself nor a Mint. | `unimplemented` | design.md#5.2 rule 1a | `SWIG-ACC-C2`, `LZR-ACC-C2` | — |
| `WRD-DENY-02` | **No registry entry can re-enable a denied pair** — A registry (or policy) list containing a denied (program, instruction) pair still fails closed: the decoder runs first, there is no override flag, and the deny-list is unreachable by the section 5.4 loosening lattice. | `unimplemented` | design.md#5.2 rule 1a; #5.4 | `LZR-ACC-C2` | — |
| `WRD-BUF-01` | **A squatted Stage is recoverable** — A stranger who pre-opens a Stage PDA at our content hash cannot permanently block staging: the Stage carries an expiry_ts, anyone may close it after expiry, and the rent goes to the squatter who paid it. | `unimplemented` | design.md#5.1 stage_open/stage_close | `ND-SQD3-LO-01`, `CERTORA-H-01`, `TOB-SQUADS-7` | — |
| `WRD-BUF-02` | **No unbounded uncleanable buffer** — There is no per-account fixed slot table an attacker can exhaust, and every Stage account has at least one permissionless path to closure that returns rent to whoever funded it. | `unimplemented` | design.md#5.1 stage_* | `ND-SQD3-LO-01`, `CERTORA-H-01` | — |
| `WRD-STAGE-01` | **Staged content is bound to generation and policy_version and consumed on use** — stage_finalize records generation and policy_version and checks Keccak256(content) == hash; execution requires both to equal the current values and closes the Stage on use, so staged content is single-use and cannot survive a recovery or a policy change. | `unimplemented` | design.md#5.2 rule 6 | `TOB-SQUADS-8` | — |

<!-- END GENERATED -->
