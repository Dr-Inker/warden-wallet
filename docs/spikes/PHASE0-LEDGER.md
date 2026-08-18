# SDD ledger — plan: /opt/warden/docs/superpowers/plans/2026-08-18-warden-phase0-scaffold-spikes.md
Spec: /opt/warden/docs/superpowers/specs/2026-08-18-warden-wallet-design.md (rev 5) — reachable.
Branch: phase0 (created from main @1aeddee). Ruling: work on a branch in-place rather than a separate worktree — repo is brand new, no other consumer; cost if wrong: none (nothing else runs here).

## Preflight scan
| Pair / task | Produces vs consumes | Finding |
|---|---|---|
| T1 → all | workspace scripts, FEE_BPS/MAX_TX_BYTES, Cargo workspace members incl. spikes/02,03 onchain | consistent; T1 .gitignore lacks `.superpowers` → Ruling: implementer adds `.superpowers/` to .gitignore (workspace is scratch) — cost if wrong: none |
| T3 → T4 | out/assertion.json fields {pubkeyDerSpki, authenticatorData, clientDataJSON, signatureDer, challenge, prfFirst, origin, rpId} → prep.ts reads same names → raw.json fields → Rust test reads same | consistent |
| T4 ↔ T1 | Cargo workspace member path spikes/02-webauthn/onchain; include_bytes path ../../../../target/deploy/spike_p256.so | consistent with root target/ |
| T5 ↔ T6 | share result.md (append) | consistent |
| T5 self | wrapForExecute signature same in Interfaces/code/test | consistent |
| T8 self | token names Interfaces = css = test | consistent |
| T9 ← T2..T8 | result.md files, inventory.md | consistent |
| Crate versions (T4/T6) | solana-program "2" vs Agave 3.1 toolchain | plan names fallback (pin what resolves, record) — no ruling needed |
| T4 self | second Rust test specified by substitution | plan-mandated; acceptable |
| T3 self | extension-id discovery under headless uncertain | plan names fallback |
No contradictions with Global Constraints found.

Ruling: Codex (mcp__codex__codex, terra@high per round; sol@xhigh final) is the task reviewer for every task, per owner instruction 2026-08-18 — cost if wrong: none (extra seat).
Ruling: Tasks 2 and 7 (research-only, disjoint dirs spikes/01-squads, spikes/04-compat) dispatched in parallel with Task 1 — no shared files; instructed to `git add <own dir>` only and retry on index.lock — cost if wrong: a commit collision to redo.
Task 2: complete (commits 1766119..ac6d92b, review clean — Codex thread 01a0149a). Verdict KEEP-OWN-PROGRAM.
Task 2: minor (deferred): result.md row 3 "PARTIAL/soft-yes" wording — periodic 30-day reset ≠ rolling cap; say not trivially configurable.
Task 1: review (Codex thread 01a0149c): Needs fixes — Important: gate/test evidence not tied to SHA 1766119. Minor (deferred): Cargo workspace members absent until spikes land (plan-mandated).
Task 1: fix round 1/5 (1 addressed, 0 open — evidence tied to SHA; no code commits)
Task 1: complete (commits 1aeddee..1766119, review clean after round 1)
Task 7: review (Codex thread 01a014a2): Needs fixes — Critical: no documented top-20 source + two substitutions for one slot; Critical: conclusive verdicts on UNVERIFIED/"likely" evidence (Jito, Solend OK; Magic Eden, Photon unsupported); Important: citation rule unmet (Meteora, Helium ephemeral signers, top-level-signer cells); Important: OK count 9 vs 11 listed, SIWS list includes Drift inconsistently.
Ruling: top-20 source — prefer a dated public ranking (DefiLlama users/TVL, Solscan, Step); if none fetchable, keep the brief's example list but label it "unranked example list (source blocked)" with exactly one substitution — cost if wrong: inventory ordering, not verdicts.
Task 3: review (Codex thread 01a014a6): Needs fixes — Important: PRF logged not asserted in test (fallback path silently passes); Important: result.md "Full assertion.json" block is a stale artifact inconsistent with committed file.
Task 3: fix round 1/5 (2 addressed, 0 open; commit 026717f)
Task 3: complete (commits 4af7125..026717f, review clean after round 1)
Task 7: fix round 1/5 (3 addressed, 1 open — Magic Eden + Save still firm without observed evidence; commit 8bb2b8a)
Task 7: fix round 2/5 (partial — Magic Eden/Save provisional OK; open: Phoenix, Sanctum, Realms firm on UNVERIFIED signer cell; commit 49e6629)
Task 4: review (Codex thread 01a014b6, sol@xhigh): Needs fixes — Important: rpIdHash expected value tautological + signed hash = SHA256(full chrome-extension:// origin) not SHA256(ext id) (spec §4 wording wrong — carry to Task 9); Important: substring JSON match not production-safe (nested/duplicate keys) — "reused verbatim" claim must be withdrawn; Important: binding negatives incomplete (no different-message/pubkey/multi-sig/foreign-index/malformed-offset tests, error asserts too loose). Minor (deferred): runtime evidence not tied to SHA (277ee1b vs 9040a75 amend).
Task 7: fix round 3 commit 4ee1ed4 — awaiting re-review.
Task 7: fix round 3/5 (1 addressed, 0 open; commit 4ee1ed4)
Task 7: complete (commits ac6d92b..4ee1ed4 (spike(04) commits), review clean after round 3). Firm 16 (OK 9 / root-only 6 / unsupported 1) + 4 provisional.
Task 4: fix round 1/5 (2 addressed, 2 open — result.md line ~270 still says RP ID = bare id; malformed-offset test accepts any ix-0 error; stale .so size in TOOLCHAIN.md; commit 5a0e334)
Task 4: fix round 2/5 (3 addressed, 0 open; commit c345090)
Task 4: complete (commits 4ee1ed4..c345090 (+277ee1b), review clean after round 2). Key facts: precompile works in LiteSVM (feature "precompiles"); CU 5,055; rpIdHash = SHA256(full chrome-extension:// origin); low-S normalization needed; substring JSON match NOT production-safe (6 hole tests must flip in Phase 1); root-verify tx already 788/1232 B with no payload; spike crate carries own [workspace] (root workspace unresolvable until spikes/03 onchain + programs/ exist) — OPEN for Task 9.
Task 5: commit 9912129 — awaiting review. Headline: 5/5 Jupiter SOL→USDC routes fit inline (599–1059 B), Marinade 662 B, Tensor not measured (API key).
Task 8: review (Codex thread 01a014cf): Needs fixes — Critical: no typed first/last-4 confirmation for first-time recipient (spec §6), DustOnly not a poison-specific blocking treatment; Important: critical red used for ordinary outflow (controller concurs — my own visual QA); Important: light-mode --w-muted ~3.7:1 too faint + tiny all-caps mono overuse; Important: ui-tokens tests non-enforcing. Minor (deferred): diff carries unrelated lockfile hunks. Controller visual QA: cap meters read as underlines (concur w/ implementer self-critique).
Task 5: review (Codex thread 01a014d2): Needs fixes — Critical: account indices encoded into pre-compile `order` not compiled outer message (plan-mandated code defect) → Ruling: fix (compile first, map key→compiled index incl. LUT-resolved order, assert u8) — cost if wrong: minor size deltas; Important: compute-budget ixs must be top-level (measure Phase-1 shape); Important: stagedChunks 900-B constant unsupported → serialize representative stage_chunk txs; Minor (deferred): 45–47 account extrapolation overreach — scope conclusion to sample.
Task 6: commit 7850423; review (Codex thread 01a014d8): Needs fixes — Critical: invariant compares only after-state (delegate cleared / account shrunk passes) — plan-mandated code defect → Ruling: fix (before/after field-by-field compare, require valid token after-snapshot when before was vault-owned) — cost if wrong: CU numbers shift slightly; Important: COption tag decoded as !=0 not strict; Important: negative path is synthetic, invariant fn needs unit tests; Minor: error assert by string. CU: 10→8,688 / 20→16,134 / 30→23,254 (~750/acct).
Task 8: fix round 1/5 (5 addressed, 0 open; commit e58a053)
Task 8: complete (commits c345090..01414f0 + e58a053, review clean after round 1). Figma file GOBwNsRgT5I36H2oGjfSbi; ui-tokens 11 tests. Deferred: 9/11 screens undesigned; dark mode is a mode flip; disabled-primary vs secondary distinction weakest.
Task 5: fix round 1/5 (2 addressed, 2 open — payload indices are message-global not instruction-local; stage_chunk cap realism; commit db8f85a). Ruling: `execute` payload indices are INSTRUCTION-LOCAL (index into execute's own account metas / remaining_accounts) — cost if wrong: Phase-1 SDK re-encoding. Ruling: stage_chunk account contract = spec §5.1 (payer, Stage PDA, system program, 8-B header) — cap 985 B is provisional until Phase 1 program exists; record in DECISION.md — cost if wrong: chunk count off by one.
Task 6: fix round 1 commit e0990ea (16 tests; CU 10→10,011 / 20→18,785 / 30→27,225 ≈ 900/acct) — awaiting re-review.
Task 6: fix round 1/5 (4 addressed, 0 open; commit e0990ea). Minor (deferred, Phase 1): parse+compare is_native COption (WSOL detection currently mint-only) — Ruling: not a bypass in the spike (is_native cannot change without close/recreate, which is blocked) but Phase 1 compares it too — cost if wrong: none for measurements.
Task 6: complete (commits 9912129..7850423 + e0990ea, review clean after round 1). CU ≈ 900/account, 30 accounts ≈ 27k CU.
Task 5: fix round 2/5 (1 addressed, small open — §5.1 citation overclaims (say "assumed shape per controller ruling"), account/session may duplicate in order, n_ixs u8 guard; commit 3b1951a)
Task 5: fix round 3/5 (2 addressed, 1 open — result.md:60 still attributes header shape to §5.1; commit 787ab42). Ruling: round 4 resumes the same implementer (skill says fresh+stronger model) because the residual is a one-line doc wording — cost if wrong: none.
Task 5: fix round 4/5 (1 addressed, 0 open; commit d004ba5)
Task 5: complete (commits 01414f0..9912129 + db8f85a, 3b1951a, 787ab42, d004ba5; review clean after round 4). Headline: post-fix Jupiter SOL→USDC 2/3 fresh routes inline, 43-account route 1,235 B → 1 stage chunk; Marinade 702 B; execute payload indices INSTRUCTION-LOCAL; stage cap 985 B PROVISIONAL.
Task 5: minor (deferred): result.md has grown into a 600-line changelog — trim into DECISION.md summary; Tensor unmeasured (API key).
Task 9: complete (commit e342c0e). Codex round 1 NO-GO (thread 01a014fc: 40-acct cap CU overclaim, 985 B "spec-derived", crossOrigin overstated) → fixed → round 2 GO (thread 01a014ff). Ruling: the two Codex GO/NO-GO rounds on DECISION.md + spec rev 6 serve as Task 9's task review (same diff, same reviewer) — cost if wrong: an unreviewed Cargo.toml/test-gate tweak (final review covers it).
Open items carried to Phase 1: O1 real-device PRF (owner) — Argon2id primary until then; O11 full execute CU unmeasured (early Phase-1 LiteSVM); conservation reject branch never driven by a real CPI; Jupiter v6 route discriminator UNVERIFIED; root Cargo members=[] until programs/warden exists.
FINAL REVIEW (Codex sol@xhigh thread 01a01502): FIX-THEN-MERGE. Important: measure.ts `writableAccounts` counts all keys not writable → 40-writable cap under-evidenced (make provisional, fix metric, fix stale message-global text in result.md:267); conservation spike header claims SOL conservation but lamports never compared → label token-only + no-copy warning; Anchor.toml missing (plan constraint); Phase 1 plan not yet written. Minor: TOOLCHAIN.md/spike manifests say root workspace broken (now resolves), CLAUDE.md says rev 5, Squads row-3 wording, Rust gate command+SHA provenance.
Ruling: Phase 1 plan is written by the controller via writing-plans after merge (handoff step, not a code fix) — cost if wrong: none.
FINAL fix wave commit b2986c4; scoped re-review (Codex thread 01a01512): all 5 ADDRESSED; NOT-READY only for stale DECISION.md line citations into result.md (drift after Round-5 insertions). Ruling: dispatch one mechanical cheap-tier fix converting DECISION.md result.md citations to heading anchors (deviation from one-fix-wave rule; doc-only) — cost if wrong: none.
