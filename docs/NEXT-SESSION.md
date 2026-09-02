# Next Session — Claude Security, Vanity, and UI Handoff

> ## 2026-09-02 POINTER — CODEX PICKUP MEMO SUPERSEDES THIS FILE FOR THE NEXT SESSION
>
> The Fable-5 audit (`docs/security/FABLE-AUDIT-2026-09-02.md`) and its remediation
> (P-1, K-1, E-1, E-4, A-1, A-2, X-1, X-2; ledger close `f63262b`) are DONE on `phase1b`.
> The next session is a **Codex review session**, not an implementation session: read
> **`docs/CODEX-HANDOVER-2026-09-02.md`** first and follow it literally — it carries the exact
> BASE, the owed review rounds R0–R8 with pre-cut commit ranges, per-round mechanics, ledger
> rules, OWNER decisions (record, do not take), and every footgun that bit the previous session.
> The 2026-09-01 memo below is still true for C75 and the external owner work; it is not
> superseded on those points.

> ## 2026-09-01 CLEAN-BREAK PICKUP MEMO — C75 CLOSED; EXTERNAL OWNER WORK REMAINS
>
> `TO / TASK / CWD / BASE / READ / WRITE (edit lease) / DO_NOT_TOUCH / ACCEPT / SIDE_EFFECTS / RETURN`
>
> - **TO:** the next Warden implementation/review session.
> - **TASK:** preserve the closed C75 evidence and stop unless an owner supplies
>   a real store-returned package, production trust material, reviewer decision,
>   or another explicitly bounded local contract. Do not manufacture a local
>   proxy or claim process-group, descendant, sandbox, or executable confinement.
> - **CWD:** `/opt/warden`.
> - **BASE:** C74 close SHA
>   `c0f0ede0ba8a4b6d537901f658e282b59b1669e1`; C75 contract SHA
>   `9421f5892ee08d934a8bcd2502773e498126f14c`; behavioral RED SHA
>   `0dadc1ed8101ca57ea9907005c43b5df89e5aa29`; implementation/evidence
>   `d53bea74d75228707c2d9df538afbe66c2a20866`; evidence-ledger/full-gated SHA
>   `a3bc36d8fc00a35f81a2f3fc2e820574fe7f1d23`; C73 close SHA
>   `ff4100e17767cf4945468adfab32f92d1719f348`; C74 contract SHA
>   `3914a39ab39c8a6cfb074654c5b6e2e78be68147`; behavioral RED SHA
>   `00bc2c6ba99db422e53fd7b94fe9c7097ee8dac8`; implementation/evidence
>   `21b7da8bbfe2c06983505f0a5c69304bf01d24eb`; evidence-ledger/full-gated SHA
>   `21f15aa5ea709685c60c18e80410f532fb0423fb`; C73 behavioral RED SHA
>   `e87845cc9affd7ffba0bf8d2ffa28aba4ca3c306`; implementation/evidence
>   `8c4d020d7a4aead78aec9e88d077d6d892c6f6af`; contract SHA
>   `77206bf96ac1c0f3a68bf24db93ebe47f3cee209`; evidence-ledger/full-gated SHA
>   `19cfdccdb7657a5e5a94abab1c4554f92a2fbca8`; C72 close SHA
>   `d36ff2756743662621840bd033e36eaa9bfc422e`; evidence-ledger/full-gated SHA
>   `bd717bdf19ef9986522e1180cd2c67b8dba96660`; implementation/evidence
>   `a99054d5c5b51a30d564a3d2b6081769ba8d5a2e`; contract SHA
>   `ba854a8ed5aed6bf99c52fb5d0ee03a89bb9cec9`; behavioral RED
>   `b20e3dd77932327394003c57970c0476be47c3bb`; C71 close SHA
>   `6fd9b34fbf4dd294b71bbe7bbd7cfce7402b3a80`; evidence-ledger/full-gated SHA
>   `7facbd975fb46649c3950c9ae47fa3fe7ddd573f`; implementation/evidence
>   `a539e21e66c35b392f921d6c2c8f08d7d6108b28`; contract SHA
>   `b4f6789dee83bd6411f38777fd40a9efaa71a7f1`; initial fixture
>   `4c90b21baff1f6821103b2014f5872171dd0c307`; behavioral RED
>   `58a535a86d54cdde8d129137bf369f1a5ac54ce5`; C70 close SHA
>   `320d1d5186b592b5df77fdc4fbdb01f0b0f5ca94`; evidence-ledger/full-gated SHA
>   `fab2e75f8d03e9e0157685b34a451103fa82786d`; implementation/evidence
>   `c78649e7c63211697fb082b7a563f65e124b9e93`; contract SHA
>   `86279a256335c466f6e1cdd37f4bf29d650f41b3`; behavioral RED
>   `0fad7e841c1a691232ee437537f3c509cfbd2237`; C69 close SHA
>   `4f43e19a525c1788476986a9e05374d1c346136f`; evidence-ledger/full-gated SHA
>   `c500cb88815d5a20e18f06b37918b994a9d57799`; C69 implementation/evidence
>   `a206228cacd95197bbd677af6309f1a130db2f2a`; behavioral RED
>   `8c1828de1de1cdc7369f1131c3fc47636ed15b0c`; C68 close SHA
>   `5e49c3d482540d5adc5a1c3810b0556a91d20c5d`; C68 behavioral RED
>   `f0f751760b3910bafdc087948193a84bf1c36622`; implementation
>   `c57e14cdd9ea15556e2e5fe3ae0f509bc360165e`; corrected implementation/evidence
>   `a223edf8a1d8d5c11381756e9fd013ff4b8f5026`; evidence-ledger/full-gated SHA
>   `8dbac5b9b3836287acbcb7659780c0546dda23f3`; C67 close SHA
>   `7298c69d444a919070b6d107818a92cf5e2d3a43`; evidence-ledger/full-gated SHA
>   `47d419dae0dda40ad6ca461ab7cd81dc3ba32308`; implementation/evidence
>   `5bb34f87d6e0fbafa53e1090fbc93fd67495a476`; behavioral RED
>   `21213293cc184b80d8d397c102b01b3b2d85bf6a`.
> - **READ:** this memo and the C75/C74/C73/C72/C71/C70/C69/C68/C67/C66/C65/C64/C63/C52/C51/C50/C36
>   entries; C6 in the client-security plan; current verifier/tests; clean
>   status.
> - **WRITE (edit lease):** none until a new bounded contract or external owner
>   input exists. C75 source, tests, README, release-integrity prose, evidence,
>   and closeout are complete.
> - **DO_NOT_TOUCH:** `.superpowers/**`,
>   `/root/.codex/session-graphs/**`, live `/var/www/**`, deployment/Web Store
>   publisher/account state, production tags/keys/trust stores, secrets, the
>   empty production release registry, or the C1a production extension-id/
>   permitted-origin owner decision. Do not fetch a key/package, push, tag,
>   sign production bytes, publish, weaken C36/C38–C75 policy, or invent store
>   provenance, freshness, reviewer, builder-independence, key-strength,
>   publisher, or lifecycle policy.
> - **ACCEPT:** calculate the store Info-ZIP deadline from verified embedded ZIP
>   length as `min(120000, 5000 + ceil(bytes / 1048576) * 1000)` milliseconds,
>   use `killSignal: "SIGKILL"`, and prove a sub-MiB direct child that sleeps 12
>   seconds is killed/fail-closed before 10 seconds without writing its
>   completion marker. Preserve C74's exact three-key environment, C73's exact
>   private **0700** `cwd`, C72's exact embedded ZIP digest, `O_RDONLY`
>   descriptor, **0400** inode, refused pathname replacement, exact post-parser
>   comparison, and empty cleanup. Preserve C71's upload-parser bounded direct
>   child, C70's upload-parser environment, C69's upload-parser
>   private **0700** `cwd`, C68's descriptor/inode seal, and all C67/C66/C65/C64/C63 upload-verifier probes,
>   exclusive **0600** construction, identity/seal checks, exact post-parser
>   comparison, cleanup on every outcome, direct/pnpm **0/6/7**, optional
>   unpacked tree, canonical checks, unchanged output, exact 25-input recipe
>   binding, and provider fixed unavailable.
> - **SIDE_EFFECTS:** local `/opt/warden` source/tests/docs, ignored generated
>   extension artifacts, ephemeral GnuPG/files/repos/launchers/CRX fixtures
>   under `/tmp`, and git commits only; no network key/package retrieval,
>   production signature/key/tag, deploy, upload, publishing, live service,
>   external message, secret persistence, legal ruling, or real-account/funds
>   mutation.
> - **RETURN:** C74 close/full SHAs plus C75 contract/RED/implementation/evidence/
>   full/close SHAs, clean/dirty state,
>   exact commands and outcomes, stable-byte proof and temp-copy mode/cleanup,
>   preserved grammar/order/output/scope, invariant and independent-review
>   status, explicit synthetic/production and same-host/independent gaps, and
>   remaining owner/counsel/external-state blockers.
>
> **C60 ledger-inclusive gate:** from a clean tree at
> `401c66de0b3cb56b642c4f353ffde14dd32ef780`, this exact command exited **0**
> and printed that same SHA before and after:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:gate && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:dual-local && if rg -n 'release-source-tag-message|print-release-source-tag-message|formatReleaseTagMessage|warden\.extension-release-tag\.v1|artifact-manifest-sha256|expected-default-artifact-manifest-sha256|expected-artifact-manifest-sha256|expected-detached-signature-sha256|source tag signed|source tag verifier returned|artifact signature verifier returned|artifact manifest sha256|reviewed artifact manifest differs|detached signature differs|release-input-file|readBoundedRegularFile|O_NOFOLLOW|openpgp-signature-policy|reviewed-artifact-signature|verify-reviewed-artifact-signature|release-source-tag|verify-release-source-tag|store-package|verify-store-package|local-dual-extension-release|release-artifact|package-release|verify-release|production-dependency-evidence|bundle-input-evidence|static-input-evidence|release-recipe-input-evidence|expectedArtifactManifestSha256|signedArtifactManifestSha256|artifactReviewSignature|expectedArtifactReviewSignature|artifactReview|reviewedUploadArchive|storePackage|expectedPackageSha256|expectedStorePackageSha256|expectedStoreExtensionId|dualReleaseReport|expectedDualReleaseReportSha256|artifactManifestSha256|boundReleaseFileCount|OFFICIAL_CHROME_WEB_STORE_PUBLISHER_KEY_SHA256|warden\.extension-local-dual-release-rehearsal\.v1|warden\.extension-artifact\.v5|warden\.extension-release-recipe-input-evidence\.v1|OpenPGP verification|OPENPGP_RELEASE_SIGNATURE_POLICY|GIT_GPG_LAUNCHER|signatureCreationDate|signatureExpirationTimestamp' apps/extension/dist; then exit 1; fi && test -z "$(find /tmp -maxdepth 1 -type d \( -name 'warden-extension-dual-release-*' -o -name 'warden-release-tag-message-cli-test-*' -o -name 'warden-release-input-file-test-*' -o -name 'warden-release-source-cli-test-*' -o -name 'warden-store-package-cli-test-*' -o -name 'warden-store-package-verify-*' -o -name 'warden-release-source-gpg-launcher-*' -o -name 'warden-openpgp-signature-policy-test-*' -o -name 'warden-release-source-tag-test-*' -o -name 'warden-reviewed-artifact-signature-*' -o -name 'warden-reviewed-artifact-signature-test-*' \) -print -quit)" && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> It passed action pins **2/2**, core **700/700**, extension **577/577**, UI
> tokens **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real Chromium
> **15/15**, Rust **681 passed / 0 failed / 1 ignored**, builds/typechecks, the
> measured Argon2 benchmark, canonical ZIP/five-sidecar verification with
> **24** recipe inputs, independent Info-ZIP parsing, the real sequential two-
> clean-checkout rehearsal, emitted release-tooling exclusion, all eleven selected
> temp-directory cleanup checks, diff checks, and both clean-tree guards. The
> Argon2 elapsed p50/p95 were **947.6/971.5 ms**, host-task delay p50/p95 were
> **62.5/68.6 ms**, and password-buffer wiping was true. The final rehearsal
> compared **14** files and produced a **3,810-byte** canonical report with
> SHA-256
> `7447973556a3a96fecf772b238f005330281d9785e0f5d984e8f3dad72a55cdb`.
> At this ledger SHA the artifact, bundle, recipe, dependency, and static
> sidecar SHA-256 values were respectively
> `cc554caf8807944b82cf125fc0c102d46954c02dd61ecc827419ca10007a5f30`,
> `54eb78b3eb88c3e49c115b9ad2ac3c5b98093fdb1d9b382a3906325a6131831f`,
> `8636635c4ce153cc35ad44713be72628dca7c26c38217e9e9802393adfc51238`,
> `49e381c50e125602ad9aaddd5b406c5e272c4902d80a2d86df7988e3af7aa146`,
> and `f1a966ef298b9298d020893dcba1a2a0d973a7461aa8ef7141c0c9c5bd31d93f`;
> the recipe sidecar was **4,938 bytes**, named 24 inputs, and bound the
> **1,444-byte** tag-message printer at SHA-256
> `efe3b06c06c1154b0c3abb7c370409a520d0ee19b52838e2b45c844572d2f5a9`.
> ZIP SHA-256 remained
> `ce1b3a4792cd28def0b336d99a990bda3141c26f0b625b206163d505aca2c844`
> and payload-tree SHA-256 remained
> `f0e7ef2c6f3d1133b5e40557a014a656ccd1fe0cb7590632973b8e33a447a879`.
> No selected fixture/verifier/rehearsal temporary directory remained. Known
> Anchor test-middleman key mismatch, legacy macro-`cfg`, target-`cfg`, and Rust
> unused-code warnings remained non-fatal. Independent second-model review
> remains **UNVERIFIED**.
>
> **Stop state:** C67 and C68 are closed with executable REDs, clean
> implementations, focused/release/extension-wide evidence, and their
> repository-wide FULL gates recorded below. C69 is closed with a committed,
> measured behavioral RED, clean implementation, exact single-contract,
> focused/release, extension-wide, and repository-wide FULL evidence at close
> SHA `4f43e19a525c1788476986a9e05374d1c346136f`. C70 is closed with a committed
> contract, measured behavioral RED, clean implementation, and exact single-
> contract, verifier-file, focused/release, extension-wide, and repository-wide
> FULL evidence at close SHA `320d1d5186b592b5df77fdc4fbdb01f0b0f5ca94`.
> C71 is closed with a committed contract, corrected/measured behavioral RED,
> clean implementation, and exact single-contract, verifier-file,
> focused/release, extension-wide, and repository-wide FULL evidence at close
> SHA `6fd9b34fbf4dd294b71bbe7bbd7cfce7402b3a80`.
> C72 has a committed contract, measured behavioral RED, clean implementation,
> and exact single-contract, focused/release, extension-wide, and repository-
> wide FULL evidence at close SHA
> `d36ff2756743662621840bd033e36eaa9bfc422e`.
> C73 is closed with a committed contract, measured behavioral RED, clean
> implementation, exact single-contract, focused/release, extension-wide, and
> repository-wide FULL evidence at close SHA
> `ff4100e17767cf4945468adfab32f92d1719f348` and evidence-ledger/full-gated SHA
> `19cfdccdb7657a5e5a94abab1c4554f92a2fbca8`. C74 is closed with a committed
> contract, measured behavioral RED, clean implementation, exact single-
> contract, focused/release, extension-wide, and repository-wide FULL evidence
> at close SHA `c0f0ede0ba8a4b6d537901f658e282b59b1669e1` and evidence-ledger/full-gated
> SHA `21f15aa5ea709685c60c18e80410f532fb0423fb`. C75 is closed with a committed
> contract, measured behavioral RED, clean implementation, exact single-
> contract, focused/release, extension-wide, and repository-wide FULL evidence
> at evidence-ledger/full-gated SHA
> `a3bc36d8fc00a35f81a2f3fc2e820574fe7f1d23`. This docs-only memo is its close.
> There is still no real store-returned package,
> production reviewer/tag/key/signature, release-registry edit, Web Store account/action,
> deployment, or legal adjudication. `WRD-REL-01`, `WRD-REL-02`, and
> `WRD-REL-03` remain `unimplemented`; every composed CLI/shared-verifier tier
> pins exact artifact bytes, the source-tag signature authenticates that exact
> digest, and a safe command emits its canonical message, but production trust
> and operator-controlled signing remain external.
> C68–C75 are only cooperative-host least privilege. Do not manufacture a local
> proxy for the remaining external trust/owner obligations.

> Older pickup memos (C0 … C75, 2026-08-19 → 2026-09-01) are archived verbatim in
> [`archive/NEXT-SESSION-MEMOS-2026-08-19-to-2026-09-01.md`](archive/NEXT-SESSION-MEMOS-2026-08-19-to-2026-09-01.md).

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
