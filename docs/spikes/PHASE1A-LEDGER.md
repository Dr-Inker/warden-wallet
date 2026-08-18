# SDD ledger — plan: docs/superpowers/plans/2026-08-18-warden-phase1a-program-foundation.md
Spec: docs/superpowers/specs/2026-08-18-warden-wallet-design.md (rev 6) — reachable. Branch: phase1a from main @2b4419b.
Ruling: branch in-place (as Phase 0); Codex = task reviewer every task (owner instruction); cargo builds strictly serialized — tasks 1–7 and 9 run ONE implementer at a time (no parallel dispatch in this plan; Task 8 TS-only may overlap).
## Preflight scan
| Pair / task | Produces vs consumes | Finding |
|---|---|---|
| T1 → all | program id, WardenError, common::setup | consistent |
| T2 → T3..T7 | SmartAccount fields incl. cluster_tag/frozen_at/reserved; SessionKey; buckets::debit; MintCap | consistent after plan rev 2 (Codex) |
| T3 → T4..T7 | RootArgs, verify_root_assertion, action_hash op bytes 0x00–0x05 | consistent |
| T3 tests ↔ T4 | root_verify tests need an account: temporary set_account until T4, then refactor (T4 step 3) | consistent |
| T5 ↔ T6 | grant_frozen_rejected test lives in T6 | consistent |
| T6 → T7 | frozen gate used by transfer | consistent |
| T7 → T8 | none (T8 mirrors T3 transcript vector) | consistent |
| Global | Rust arithmetic rule vs T7 lamport ops | plan rev 2 uses checked ops | consistent |
No contradictions found. Uncertainties named in plan (anchor build path, litesvm clock API).
Task 1: commit 687c5e8; review (Codex thread 01a01549): Needs fixes — Important: gate not reproducible from clean checkout (include_bytes needs target/deploy/warden.so; gate must build SBF first); Important: fresh anchor build regenerates keypair → id mismatch; Minor: TOOLCHAIN.md stale "gate runs no Rust". Security scan: keypair.json (private key) committed. Ruling: remove the private key from git history-forward (git rm, gitignore *keypair*.json), keep only the pubkey in Anchor.toml/declare_id!, document `anchor keys` regeneration for local deploys — plan said "commit it (localnet id only)"; overriding the plan on hygiene grounds — cost if wrong: none (tests use warden::ID; deploy needs a fresh keys sync).
Task 1: squashed to f4e782a (id rotated to 6nX7pb…, old commit purged). Re-review (Codex 01a01551): open — gate staleness ignores Cargo.toml/lock; PROGRAM-KEYS.md:85 wrong about purged commit; Anchor fresh-build keypair mismatch → Ruling: inherent Anchor behaviour, documented = closed (tests use warden::ID; deploy needs owner keypair) — cost if wrong: a dev sees a warning.
Task 1: fix round 2 (2 addressed by inspection: staleness set widened, key-history note fixed; commit f431d0b)
Task 1: complete (commits 2b4419b..f431d0b, review clean; 1 parked ruling: Anchor keypair-mismatch warning documented)
Task 2: commit 0c16a84; review (Codex sol@xhigh thread 01a01560): Needs fixes — Important: debit mutates buckets before validation (must be atomic via candidate copy); Minor: find_cap matches Pubkey::default() slot; Minor: 30-day test abbreviated. Architecture: SmartAccount 4,109 B borsh deserialize overflows SBF 4 KB frame → Ruling (Codex-recommended): SmartAccount becomes `#[account(zero_copy)]` Pod/repr(C) with u8 tags (root_kind/frozen_kind) + explicit padding; borsh enums RootKey/FrozenState remain the INSTRUCTION-ARG types with accessor/setter methods so Tasks 3–7 keep the enum interface (AccountLoader<SmartAccount> in contexts). SessionKey (751 B) stays borsh Account. Cost if wrong: later refactor of contexts; done now = cheapest.
Task 2: fix round 1/5 (4 addressed, 0 open; commit 6a03859). SmartAccount::LEN=4120 zero-copy; Policy 1448; carry to T3/T4: AccountLoader<SmartAccount> + load_init/load_mut; borsh PolicyArgs→Policy From impl.
Task 2: complete (commits f431d0b..6a03859, review clean after round 1)
Task 3: commit 3db010a; review (Codex sol@xhigh 01a0158c): Needs fixes — Important: skipper accepts malformed JSON in ignored values (escapes/control bytes/number FSM/container grammar); Important: error-code assertions derive from WardenError itself → pin literal codes 6000+; Minor: true same-account two-step replay test. CU 15,711 / 680 B.
Task 3: fix round 1/5 (3 addressed, 0 open; commit f896b52). CU 15,533; clippy arithmetic lint enforced (0 hits) — add to gate later.
Task 3: complete (commits 6a03859..f896b52, review clean after round 1)
Task 4: commits 82c1abf,76f4e51; review (Codex 01a015b3): Needs fixes — Critical: PolicyArgs fixed arrays → 1,804 B tx (> 1,232; LiteSVM does not enforce) → Vec<MintCap> sparse args + real ≤1232 tx-size test; Important: session_ceiling/large_threshold must be keyed by mint (lookup, reject orphan/dup); Minor: passed-at-SHA record. Note for all remaining tasks: LiteSVM does NOT enforce the 1,232-B packet limit — every instruction task must assert serialized tx size explicitly.
Task 4: fix round 1/5 (3 addressed, 0 open; commit e1aa3d4). MAX_MINTS_AT_CREATE=4 (1,144 B); create 2-mint = 808 B.
Task 4: complete (commits f896b52..e1aa3d4, review clean after round 1)
Task 5: commit a166331; review (Codex sol@xhigh 01a015d8): Needs fixes — Important: program_allowlist_id unvalidated (accept only 0 until registry); Minor: root revoke rent-refund destination not bound (bind into 0x02 body); Minor: no field-substitution regression tests for GrantBody. Ruling adopted: generation_at_grant refresh on re-grant KEPT (Codex concurs). Grant tx 944 B / 30,325 CU.
Task 5: fix round 1/5 (3 addressed, 0 open; commit a25486a). ProgramAllowlistUnsupported=6028; RevokeBody{session_pubkey,refund_to}; validate-after-authorize ordering (all tampers → ChallengeMismatch 6018).
Task 5: complete (commits e1aa3d4..a25486a, review clean after round 1)
Task 6: commit a0e344b; review (Codex 01a015ed): Needs fixes — Important: RED evidence harness-only → Ruling: mutation-based behavioral RED accepted (revert timelock check / frozen gate → tests fail); Minor: unfreeze reads live policy.timelock_secs — document; 1B set_policy must preserve or snapshot.
Task 6: fix round 1/5 (2 addressed; RED excerpts landed in report after Codex read — verified by controller grep (lines 178/201/235); commit b0e98c0)
Task 6: complete (commits a25486a..b0e98c0, review clean)
Task 8: commit 740af61 (parallel with T7; TS only). Owed: OP_TRANSFER + TransferBody doc mirror after T7 → fold into Task 9.
Task 8: fix round 1/5 (2 addressed; commit 5677960)
Task 8: complete (commits b0e98c0..740af61 + 5677960, review clean after round 1)
Task 7: commit 322df0a; review (Codex sol@xhigh 01a01609): Needs fixes — Critical: session per_day/per_30d stored but unenforced → Ruling: 1A rejects non-zero session per_day/per_30d at grant (spec §4: day caps are account-wide; per-session = per_tx + lifetime); per-session day buckets deferred to 1B (would need a bucket PDA; SessionKey borsh size/stack); Important: tests miss policy-lookup branch, wrong-source-mint, CPI-failure rollback; Minor: RentFloor/ChallengeMismatch ABI vs brief (accept as pinned), root SPL byte assertion missing.
Task 7: fix round 1/5 (Critical+Minor addressed; coverage partial; commit 9217b6a); fix round 2/5 (full-buckets rollback assert; commit 228c2a9; controller-verified by inspection)
Task 7: complete (commits 5677960..228c2a9 (+322df0a), review clean after round 2). CU: session SOL 18,533 / session SPL 20,665 / root SOL 25,555; SessionDayCapsUnsupported=6033.
CHECKPOINT (clean break requested by owner): Tasks 1–8 complete; Task 9 (measurements finalize + spec §12/§4 wording edits + Codex milestone security review sol@xhigh + OP_TRANSFER/TransferBody TS mirror + negative-expiry parity vector) NOT started. Resume: dispatch Task 9 from brief task-9-brief.md; then final whole-branch Codex review, merge phase1a→main, write Phase 1B plan.
RESUMED 2026-08-18: owner instruction — Codex = gpt-5.6-sol at highest effort (max, fallback xhigh) for all rounds from here. Public repo pushed (Dr-Inker/warden-wallet). Task 9 dispatched.
Task 9: complete (commits 49887ca, b59d2ce, 4b409f7, 78a9b3b). Milestone Codex sol@max: R1 01a01637 REVISE (3 Imp fixed: prior_authority_hash 6035, InvalidRootKey 6034 + strict origin, OPS_MASK_KNOWN; 2 Min fixed); R2 01a0164f: x=0 fix; on-curve/proof-of-possession at create DEFERRED to 1B pre-ship gate (big_mod_exp syscall not verifiably active). Spec rev 7. Error ABI 6000–6035.
FINAL REVIEW (Codex sol@max 01a01663): FIX-THEN-MERGE — Important: packages/core/idl/warden.json stale (no transfer, errors to 6030, no prior_authority_hash) + add IDL parity gate; Important: creation-risk wording ("self-inflicted, not theft") too broad — owner_seed visible in flight → RPC/leader can race the PDA (squatting/DoS; theft if pre-funded); fix DECISION/measurements/code comments; Minor: README says rev 6 / 266+22 tests; publish sanitized Phase 1A ledger under docs/. Phase 1B: PoP at create hard gate, O11, O5, set_policy semantics.
