# Warden Wallet — independent audit by Claude Fable 5 (2026-09-02)

| | |
|---|---|
| **Tree audited** | branch `phase1b`, HEAD `2518520`, working tree clean |
| **Auditor** | Claude Fable 5 (main loop) with four read-only Fable lanes: on-chain program, core SDK, MV3 extension, assurance process |
| **Method** | Every finding labelled **CONFIRMED** below was re-derived by the main loop against source at the cited `file:line` before it was written down. Lane output that could not be re-verified is labelled as such. No files outside this report were modified. Nothing was pushed, tagged, signed, or published. `DO_NOT_TOUCH` list in `docs/NEXT-SESSION.md` respected. |
| **Not done** | No on-chain execution against a validator; no `cargo clippy -D clippy::arithmetic_side_effects` run (the program's product code is unchanged since the last recorded run, see §4). `scripts/supply-chain-gate.sh` **was** run: PASS. |

## 1. Verdict

The on-chain program is in good shape and the assurance apparatus around it is unusually rigorous for a project at this stage — but **the apparatus has stopped tracking the code**. The last recorded external review is dated 2026-08-23 over `c5a4514..77a8273`; since then the branch has grown by 328 first-parent commits (325 unpushed) that add ~10.8k lines to `packages/core` and ~50k lines to `apps/extension`, none of which appear in `REVIEW-RUNS.jsonl` or `REVIEW-SCORECARD.jsonl`. The program's *product* code is byte-for-byte unchanged over that window (the 152-line program diff is entirely `#[cfg(test)]`), so the unreviewed surface is the TypeScript, not the Rust.

Two findings are material:

1. **Program (Medium, CONFIRMED):** a token account that the vault does not own but whose SPL `delegate` is the vault PDA can be emptied through session `execute` with zero recorded outflow and no cap-bucket debit. This is the account-level sibling of the PermanentDelegate hole that took WRDF-0105 three rounds to close; the code comment at `conservation/mod.rs:186-193` describes the exact mechanism but the account-level `delegate` field was never added to the check. Precondition: somebody previously ran `Approve(delegate = vault PDA)` on a non-vault token account.
2. **Keyring trust boundary (Medium, CONFIRMED):** a v2 keyring record self-attests its account / genesis hash / program id, and the extension enforces only `origin` when adopting one. The cross-cluster replay guarantee holds at the AAD layer but not at the trust boundary. Precondition: write access to the extension's `chrome.storage.local`.

A third cluster is worth naming in the verdict even though no single item exceeds Medium: **the release-tooling effort was spent on the wrong child process.** Cycles C63–C75 sealed the fd, inode, cwd, env and deadline of the `unzip -t` cross-check — which is redundant, because the in-process ZIP parser already validates every byte — and then left `unzip` itself `PATH`-selectable. Meanwhile the producer that mints `source.gitCommit` runs `git` from the inherited `PATH` and environment (E-1), the gpg verifier takes its operands by pathname with none of that sealing (E-2), and the only release verifier CI runs is a package-then-self-verify loop with nothing pinned (E-4).

Everything else is Low or Informational, and a large amount of the code I read is demonstrably careful (see §3 "What is sound").

**Recommended order of work:** fix finding P-1 with a red test and a new ledger row → fix K-1 in `keyring-lifecycle.ts` → E-1 (one small edit to `run()`) and E-4 (wire the anchored verifiers into CI) → run one Codex round scoped to `packages/core` + `apps/extension` product code over `77a8273..HEAD` and record it → the extension hardening items (A-1, A-2, X-1, X-2) before signing is ever enabled in a shipped build → ledger hygiene. The owner-side blockers (C1a decision, external audit, deploy, WRDF-0050/0089, Jupiter IDL licence) are unchanged and remain the actual critical path to mainnet.

## 2. Findings

Severity is relative to the spec's stated property ("a compromised session key cannot move more value than its caps allow"). "Precondition" is what an attacker must already have.

| ID | Sev | Status | Component | One line |
|---|---|---|---|---|
| P-1 | **Medium** | CONFIRMED | program | Delegate-held stranger token accounts drain through session `execute` with zero outflow |
| K-1 | **Medium** | CONFIRMED | core + extension | v2 keyring record self-attests context; extension checks only `origin` |
| A-1 | Low now / Medium when signing ships | CONFIRMED (code shape) | extension | Approval popup arms "Approve and sign" instantly; no dwell / focus-settle / `isTrusted` guard |
| A-2 | Low | CONFIRMED | extension | Unlock material sits in `chrome.storage.session` as `number[]` with lazy expiry; no `chrome.alarms` eager lock |
| A-3 | Low | CONFIRMED | extension | Any http(s) frame can keep a Port open to the worker and mint up to 1024 session requests per document (DoS only) |
| E-1 | **Medium** | CONFIRMED | release tooling | `package-release.mjs` mints `source.gitCommit` via `git` from inherited `PATH`/env; verifier side pins `/usr/bin/git` + sanitised env |
| E-2 | Low | CONFIRMED | release tooling | gpg verify child gets operands by pathname with no fd/inode seal or post-exit byte compare (unlike the `unzip` child) |
| E-3 | Low | CONFIRMED (shape) | release tooling | `createPrivateGitGpgLauncher` validates by `stat(path)` then executes by name |
| E-4 | Medium (process) | CONFIRMED | release CI | Only `release:gate` (package + self-verify) runs in CI; the three anchored verifiers and no pinned fingerprints/tag SHA/extension id are in `.github/` |
| E-5 | Low | reported by lane | release tooling | `unzip` still selected by inherited `PATH`; signed tag binds only the artifact-manifest digest, not the dual-build / review-signature / CRX tuple |
| X-1 | Low (gated) | reported by lane; matches documented residual | extension (unshipped) | Page-side request owner authenticates a terminal response by same-window + origin + correlationId it broadcast itself; same-document script can forge a "signed" result. `THREATMODEL.md:379-381` already accepts this for the bridge |
| X-2 | Low (gated) | reported by lane | extension (unshipped) | Approval-path caps (16 windows / 32 flows / 128 journal rows) are flat global counters; one origin can starve every other site for ~10 min |
| X-3 | Low/Info (gated) | reported by lane | extension (unshipped) | Journal retention sweeps only on `claim()`; signed `transactionBytes` sit plaintext in IndexedDB for 10 min; delivery-proof return-type mismatch between transport and terminal owners; receipt id exposes the IndexedDB key |
| P-2 | Info | CONFIRMED | program | Default registry list 1 advertises three adapters that can never execute |
| P-3 | Info | CONFIRMED | program docs | Stale comment on `OP_REVOKE_SESSION` transcript body; WRD-CAP-01/09 notes overclaim |
| K-2 | Low | plausible, not re-verified | core | `wrap.ts` does not model runtime demotion of program-id / sysvar keys to read-only (fail-closed liveness only) |
| K-3 | Low | plausible, not re-verified | core | `wrap.ts` has no client preflight for self-CPI / ComputeBudget / Jupiter inner instructions that the program will reject |
| K-4 | Info | CONFIRMED | core | ComputeBudget passthrough forwards unknown CB tags unchanged (`wrap.ts:440-458`) |
| K-5 | Low | CONFIRMED | core | Deploy gate's genesis-hash check queries the same untrusted RPC it is authenticating (`deploy/gate.ts:115-126`) |
| K-6 | Info | plausible | core | DER long-form leading-zero not rejected in `assertion.ts:44-56` (unreachable for P-256 lengths) |
| K-7 | Info | CONFIRMED | core | Argon2id floors are low (`memoryKiB ≥ 8`, `timeCost ≥ 1`); defaults are 64 MiB and fine |
| K-8 | Info | CONFIRMED | docs | `CLAUDE.md` says KEK/DEK bundle is unbuilt; `bundle.ts` and record v2 implement it |
| K-9 | Low | CONFIRMED | core | `@solana/web3.js` is caret-pinned (`^1.98.0`) while `@noble/*` are exact |
| K-10 | Info | plausible | core | `approval/record.ts:127-145` uses `Object.keys` instead of the `exactDataRecord` helper used elsewhere |
| K-11 | Info | CONFIRMED | core | `webauthn/transcript.ts:130-133` range-checks `kind`/`opsMask`/`programAllowlistId` but not integrality; `setUint16` truncates silently |
| R-1 | **High (process)** | CONFIRMED | assurance | Review ledger stops at 2026-08-23; 328 first-parent commits since, 0 rows |
| R-2 | Medium (process) | CONFIRMED | assurance | Dormant CI gates (clippy `-D arithmetic_side_effects`, cargo-deny, supply-chain) are not in `.claude/test-gate.sh`; supply-chain gate run today: PASS |
| R-3 | Medium (process) | CONFIRMED | assurance | 0 of 233 scorecard rows carry a human ruling |
| R-4 | Medium (process) | CONFIRMED | assurance | 0 invariants cover the extension; `SECURITY.md` scope excludes it |
| R-5 | Low (process) | CONFIRMED | assurance | `docs/NEXT-SESSION.md` is 993 KB; core test count in docs (700) vs static count (~598) |
| R-6 | Low (process) | CONFIRMED | assurance | `bincode` RUSTSEC-2025-0141 ignored to 2026-11-30 and ships in `warden.so`; duplicate `@noble/hashes` 1.8/2.4 and `spl-token` 0.4.9/0.4.14 |

### P-1 — Delegate-held stranger token accounts drain through session `execute` (Medium, CONFIRMED)

**Chain, each link verified against source:**

1. `payload.rs:217` — `Transfer` (tag 3), `TransferChecked` (12) and `Burn` (8) fall through to `SplTokenOp::Other`, so `deny_scan` never names them.
2. `registry_default.rs:54-55` — list 1 admits SPL-Token `Transfer` and `TransferChecked` with `ROLE_VAULT_SIGNER | ROLE_REQUIRES_TOKEN_PROGRAM`.
3. `registry.rs:113-125` — `role_validator_passes` checks only that the pubkey at `authority_index` **is the vault and signs**. The doc comment on the function says so explicitly: "The value half — that a source is *the vault's own* ATA … is `execute`/`conservation`'s".
4. `conservation/compare.rs:216-219` — step (4): `let Some(bt) = b.token.as_ref().filter(|t| t.owner == *vault) else { continue; };` — every token account **not owned by the vault** is skipped before the delegate / close-authority / identity checks at lines 247-268 run.
5. `conservation/mod.rs:194-201` — `MintSnap::holds_authority` covers `mint_authority`, `freeze_authority`, `transfer_fee_config_authority`, `withdraw_withheld_authority`, `permanent_delegate`. All five are **mint-level**. `prescan_vault_mints` (`compare.rs:337-375`) calls only this predicate. The classic SPL **account-level** `delegate` field (which `snapshot.rs:232` does parse into `TokenSnap.delegate`) is never compared against the vault for non-vault-owned accounts.
6. Result: a `Transfer{amount=N}` from stranger account S (owner ≠ vault, `delegate == vault`, `delegated_amount ≥ N`) to any destination, with the vault PDA as the signing authority, passes registry, passes conservation (S is skipped, no vault-owned account changed), records `outflow = 0`, debits no per-mint / day / 30-day bucket, and does not touch the deny-list.

**Why it matters even with the precondition.** The precondition is that someone ran `Approve(delegate = vault PDA)` on a token account the vault does not own. Two realistic ways that arises: the user delegates spend authority from a hot wallet or another account to their Warden PDA (a pattern some protocols and "allowance"-style flows encourage), or a protocol escrow delegates to the PDA. In either case the spec's property is silently conditional: a compromised session key moves the entire delegated allowance through the vault's signature with nothing metered. This is the same shape the team already judged material in WRDF-0105 round 3 — the comment block at `conservation/mod.rs:186-193` narrates "between two THIRD-PARTY token accounts under the PDA's propagated signer. Conservation skips both accounts, `outflow` is zero, and no bucket is debited" — for the mint-level permanent delegate; the account-level field simply wasn't included.

**Fix.** In the pre-CPI scan (before `invoke_signed`), reject any token account in the logical list where `token.owner != vault && token.delegate == Some(vault)`, on **both** the before and after snapshots (the after check catches a CPI that *creates* the delegation and spends it in the same instruction sequence via a later `execute`). Add the red test (`execute` with a delegate-held stranger `TransferChecked` must fail with a dedicated error, plus the same for `Burn`), and add a new invariant row (suggested `WRD-EXEC-13`, status `unimplemented` until the test lands). Per `CLAUDE.md`, a program product-code change requires a Codex round before it is considered closed.

### K-1 — v2 keyring record self-attests its context; extension enforces only origin (Medium, CONFIRMED)

`packages/core/src/keyring/record.ts:559-575` — `resolveRecordContext` for a v2 record returns `snapshotContext(metadata.context)` and *forbids* a caller-supplied context ("record v2 derives context from authenticated metadata; caller context is forbidden"). The context is authenticated as AAD, so it cannot be *modified* without the KEK — but it can be *replaced wholesale* by a different, validly-encrypted record.

`apps/extension/src/background/keyring-lifecycle.ts:198-210` — `contextForRecord` compares only `context.origin !== this.expectedOrigin`; `genesisHash`, `programId` and `account` are taken from the record.

So the invariant "cross-cluster replay rejects" holds at the AEAD layer (a devnet record will not *decrypt* under a mainnet context) but not at the trust boundary: an attacker who can write `chrome.storage.local` can swap in a record whose embedded context names a different cluster / program / account, and the extension will adopt it as long as `origin` matches. The precondition (extension-storage write) is significant — such an attacker already has most of the extension's authority — which is why this is Medium rather than High. It is nonetheless a design gap: the extension already knows its expected genesis hash and program id (`deploy/gate.ts` and the session-intent code pin them), so `contextForRecord` should compare the full canonical six-field context, not one field of it. `PersistentKeyringRecordStore` (`keyring-record-store.ts:40-51`) enforces only "is a v2 record", so it does not help.

**Fix.** In `keyring-lifecycle.ts`, compare every field of `metadata.context` against the extension's pinned expectations and fail closed on any mismatch. Add a test that a v2 record with a foreign `genesisHash` (valid AEAD, matching origin) is refused.

### A-1 — Approval popup arms "Approve and sign" instantly (Low now; Medium the day signing ships)

`apps/extension/src/approval/main.ts:230-232` — on the review response, `approveButton.disabled = !canApprove` runs synchronously; the click handler at `main.ts:336` has no dwell timer, no focus-settle, no `event.isTrusted` / pointer-down-and-up-after-arm guard. A page that primes rapid clicks or keypresses at the coordinates where the 720×600 window appears (`approval-window.ts:416`) can land the user's next input on the button. No threat-model row, invariant, or test mentions click-race / clickjacking (grep is clean). Today this is Low because the shipped bundle is a zero-authority stub (`build.mjs:62-136` forbids the provider pipeline; `canApprove` is `false` in production). Add a threat row and the guard **before** signing is enabled: arm only after N ms of window focus plus a real pointer move, require pointer-down and pointer-up both after arm time, and randomise window left/top.

### A-2 — Unlock material persists in session storage past expiry until next use (Low)

`apps/extension/src/background/unlock-session.ts:167-177` — `encodeStoredSession` serialises `unwrapKey.bytes` as `number[]` into `chrome.storage.session`. Expiry is checked lazily (`assertActive`, and on restore in `keyring-lifecycle.ts`); there is no `chrome.alarms` permission or handler, so after the idle / hard deadline the material remains in session storage until the worker next wakes for an unrelated reason. This is consistent with the wording of WRD-KEY-03 and with `TRUSTED_CONTEXTS` access, and the material is cleared on read-after-expiry. Adding `alarms` and an eager lock at the deadline is cheap and closes the window.

### A-3 — Unauthenticated port hold / request flood (Low, DoS only)

`apps/extension/src/content/bridge.ts:280-292` — any http(s) page in any frame can open a Port and push up to 1024 requests per document; each mints a session request in the background. Caps bound it; effect is keeping the MV3 worker awake and filling the request store. Acceptable, worth a rate-limit if it becomes noisy.

### E-1 — Release producer runs `git` from inherited `PATH` and environment (Medium, CONFIRMED)

`apps/extension/scripts/package-release.mjs:86-99` — `run()` is `execFile(command, args, { cwd, encoding, maxBuffer })` with no `env`, no `timeout`, and a bare `"git"` command; it is used at lines 136-140 for `git status --porcelain` (the clean-tree gate) and `git rev-parse HEAD` (the value written into the artifact manifest as `source.gitCommit`). That commit is the only thing binding the OpenPGP-signed release tag to the built bytes: `release-source-tag.mjs:1003` string-compares `targetCommit !== artifactCommit`. The verifier side of the same chain does this properly — `release-source-tag.mjs:675-686` pins `PATH=/usr/bin:/bin`, `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`.

The lane rated this High. I rate it Medium: an attacker who controls the operator's shell environment already controls the build. The reason it is not Low is a lesser vector that does not need shell control — `pnpm run release:package` prepends `node_modules/.bin` to `PATH`, so a compromised dependency shipping a `git` bin shadows the real one for the *producer* while the *verifier's* pinned `/usr/bin/git` sees nothing wrong. **Fix:** give `run()` the same allow-listed env, absolute `/usr/bin/git` and `timeout` the verifier already uses.

### E-2 / E-3 — gpg and git children in the verifier get none of the C63–C75 sealing (Low, CONFIRMED)

`reviewed-artifact-signature.mjs:102-127` writes both operands with `wx`/`0600` into a `mkdtemp` directory and then hands *pathnames* to `gpg --verify`; there is no `O_NOFOLLOW`/dev-ino check, no `chmod 0400`, no `/proc/<pid>/fd` handoff, and no post-exit comparison of what gpg read against the buffer whose SHA-256 is returned at lines 141-142. `release-source-tag.mjs:688-715` writes a gpg launcher script, validates it with `stat(path)`, then passes the path as `gpg.program` — check-by-name, execute-by-name. `verify-store-package.mjs:94-144` solves exactly these problems for `unzip`. Because `mkdtemp` directories are `0700`, the attacker is same-UID, which is why these are Low — but the asymmetry is the point: the redundant child got thirteen cycles of hardening, the two children carrying cryptographic authority got none. **Fix:** mirror the unzip fd/seal/compare pattern for both gpg operands; either `fstat`-re-verify the launcher immediately before exec or drop it for `gpg.program=/usr/bin/gpg`.

### E-4 — CI runs only a self-consistency release check (Medium, process, CONFIRMED)

`apps/extension/package.json:11` — `release:gate` = `release:package && release:verify`; `.github/workflows/ci.yml:194` runs exactly that. `verify-release.mjs` compares a ZIP against an `.artifact.json` generated seconds earlier by the same job. `grep` for `verify-store-package`, `verify-release-source-tag`, `verify-reviewed-artifact-signature` in `.github/`: zero hits; no expected primary/signing fingerprint, tag SHA or extension id is committed anywhere. `RELEASE-INTEGRITY.md:109-113` acknowledges the co-generation weakness. **Fix:** a release-branch job that runs the three anchored verifiers against committed pins.

### E-5 and the gated extension findings (X-1 … X-3)

Reported by the extension lane with `file:line` citations; I spot-read the surrounding code but did not re-derive each one. Summary: `unzip` is still `PATH`-selected in `verify-store-package.mjs:83,136` (low: the in-process parser is authoritative); the signed tag binds only `artifact-manifest-sha256`, with the dual-build report, review-signature digest, CRX digest and extension id passed as unsigned CLI args (`release-source-tag.mjs:284-404`), and `independentBuilderClaim` is self-labelled `"not-asserted"`. On the unshipped provider pipeline (`page/provider-request-owner.ts` is on both forbidden lists in `build.mjs:71,120`, so none of this is reachable today): the page-side owner authenticates terminal responses by values it broadcast itself (X-1 — already an accepted residual in `THREATMODEL.md:379-381`, but the class a dApp will trust for signed bytes inherits that acceptance silently; the fix is a one-shot capability handshake at `document_start`); the approval-path capacity caps are global rather than per-origin (X-2); and retention/plaintext/return-type items (X-3) are hygiene. The lane's list of areas it examined and found nothing in — manifest/permissions/CSP, provider-object injection surface, logging, zip-slip, IndexedDB downgrade, review→approve TOCTOU — is recorded in its full report in the session transcript; the two things it explicitly did not reach are the signer-side digest recheck in `session-intent.ts`/`session-approval.ts` and the selection/authority resolver.

### P-2 — Dead adapters in the default registry (Info)

`registry_default.rs:57,59-60` — Jupiter `route` / `shared_accounts_route` are refused unconditionally by `reject_jupiter` (`execute.rs:725-731`) and the `swap` path never consults `registry_allows` (`swap.rs:349-350`); System `Transfer` cannot debit a PDA. They are harmless (fail-closed) but they make the registry lie about the surface, and a future relaxation of `reject_jupiter` would silently enable them. Either remove them from list 1 or leave a comment stating they are intentionally inert.

### P-3 — Documentation drift (Info)

- `transcript.rs:51-53` still says the revoke transcript hashes only the session pubkey; `revoke_session.rs:126-137` hashes `RevokeBody{session_pubkey, refund_to}`.
- WRD-CAP-01 / WRD-CAP-09 ledger notes claim every outflow debits a bucket; after P-1 that is true only for vault-owned sources. Caveat the notes now; retire the caveat when the P-1 test lands.

### Core SDK low items (K-2 … K-11)

- **K-4** `wrap.ts:440-458`: the passthrough loop forwards any ComputeBudget instruction whose tag is not `RequestHeapFrame`, including tags the program does not know. The program rejects them, so this is a liveness gap, not safety.
- **K-5** `deploy/gate.ts:115-126`: the genesis-hash check goes through `rpc(opts)`, i.e. the same endpoint whose honesty the check is trying to establish. A pinned trusted endpoint (or two independent ones) for check 0b would make the gate meaningful against a hostile RPC.
- **K-7** `derive.ts:138-140`: minimums of 8 KiB / 1 pass / 1 lane are accepted. Defaults (`derive.ts:126`, 64 MiB) are good; raise the floors so a downgraded record cannot be *written* by this code.
- **K-9** `packages/core/package.json:66`: `@solana/web3.js` `^1.98.0` alongside exact `@noble/*` pins. The lockfile pins 1.98.4; make the manifest match the lockfile discipline.
- **K-11** `webauthn/transcript.ts:130-133`: `kind`, `opsMask`, `programAllowlistId` are range-checked but not `Number.isInteger`-checked; `DataView.setUint16` truncates. The chain signs what the client encodes, so this is a client-side surprise, not an on-chain safety loss.
- K-2, K-3, K-6, K-10 are as reported by the core lane; I read the surrounding code but did not construct a failing input, so they stay "plausible".

**Parity:** the core lane checked every codec pair (borsh bodies, AAD, transcripts, accounts-hash) against the Rust side and found them byte-exact. I did not re-run that table.

## 3. What is sound (things I checked and would not change)

- **Conservation core** (`compare.rs`): before/after snapshots taken around `invoke_signed`; vault-owned accounts require field identity except `amount`, delegate and close-authority `None` on **both** sides, state initialised; new vault accounts rejected (`NewVaultAccountRejected`); mint danger rules run before the close branch and are not gated on `is_writable` (the Codex C1 lesson is applied correctly).
- **Custom heap allocator** (`heap.rs`, 140 lines, `custom-heap` default feature): `bump()` uses `checked_add` for both the align-up and the size step; cursor starts at `HEAP_START_ADDRESS`; dealloc is a no-op. Sound. This file was written in commit `7936419` and appears in neither ledger — it is the one piece of unreviewed `unsafe` in the program and I am recording here that it has now been read.
- **`init_if_needed` in `grant_session`** (`grant_session.rs:146`): the only use in the program; upsert semantics are documented at lines 28-87 and bound by `prior_authority_hash` under the root signer. Deliberate, not a footgun.
- **Root nonce / freshness**: strict `n+1`, slot-based freshness with `MAX_ROOT_SLOT_AGE = 150`.
- **Keyring AEAD** (`record.ts`, `aad.ts`, `aead.ts`): length-prefixed AAD, every integer field `Number.isInteger`-checked with explicit bounds, v2 record forbids caller context. The construction is right; K-1 is about who *trusts* it, not about the cryptography.
- **Extension record store** (`keyring-record-store.ts`): serialised writes, validate-before-write, exact readback, never deletes as cleanup. Good.
- **Extension shipped bundle**: verified by the extension lane to be a zero-authority stub — `build.mjs:62-136` forbids the provider pipeline in the background; content scripts limited to `main.ts`, `bridge.ts`, `provider-protocol.ts`; no main-world injection; `release/unpacked/manifest.json` byte-equal to source. Approval digests are bound at review time (`approval-port.ts:374-386`) and rechecked at `claimSigning` (`approval-store.ts:852-859`); the store is add-only with pending→terminal transitions only.
- **Secrets**: process lane grep for keypairs / `.env` / tokens in tracked files: clean.
- **Supply chain (today)**: `scripts/supply-chain-gate.sh` → cargo-deny (advisories, bans, sources, licences) + frozen-lockfile install + scoped `pnpm audit --audit-level=high`: **PASS**. The single high advisory (`bigint-buffer`, GHSA-3gc7-fjrx-p6mg) is reachable only from `spikes/`.

## 4. Process assessment

The ledgers (`invariants.jsonl` 89 rows, `REVIEW-RUNS.jsonl` 101, `REVIEW-SCORECARD.jsonl` 233) and the "silence on a seeded invariant = FAIL" rule in `INVARIANTS.md` are a genuinely strong design. The problem is coverage, not design:

- **R-1.** `origin/phase1b` is at `6d714b2` (2026-08-23). Local `phase1b` is 325 commits ahead. The last `REVIEW-RUNS` row is the 2026-08-23 grok-4.3 run over `c5a4514..77a8273`. The program product diff over `77a8273..HEAD` is 152 lines, all `#[cfg(test)]` (`execute.rs`, `registry_admin.rs`, `state/registry.rs`, `state/session.rs`, `state/smart_account.rs`). The unreviewed surface is therefore `packages/core/src` (+10,837 lines) and `apps/extension` (+50,164 lines). Cycles C63–C75 spent thirteen consecutive rounds hardening the store-package direct-child verifier in the extension's release tooling; that is a lot of assurance effort concentrated on a tool that ships nothing while the product TypeScript went unreviewed — and, per E-1/E-2/E-3, the hardening went to the redundant `unzip` child rather than the `git` and `gpg` children that actually carry authority. This is the pattern the `feedback_review_loop_converge_then_harden` note predicts: once product code converges, a review loop with no stop condition keeps finding work in its own scaffolding.
- **R-2.** `.claude/test-gate.sh` runs the GitHub-Actions-pins test, `pnpm test`, core build, extension typecheck/build, the Argon2 bench and the Chromium lane. Clippy with `-D clippy::arithmetic_side_effects`, cargo-deny and the supply-chain gate exist only in `ci.yml:196-200`, and CI has not run since nothing has been pushed. I ran the supply-chain gate: PASS. Clippy was not run (program product code unchanged since it last ran in CI; do run it after P-1 lands).
- **R-3.** Every one of the 233 scorecard rows is machine-adjudicated; the `INVARIANTS.md` human-adjudication rules have never been exercised.
- **R-4.** Zero invariants name the extension; `SECURITY.md` scope excludes it; README revision numbers contradict each other. The extension is now 50k lines and the thing users will actually touch.
- **R-5.** `docs/NEXT-SESSION.md` has grown 42× to 993 KB; it should be rotated into an archive with a short live memo. Documented core test count (700) vs static count (~598).
- **R-6.** `bincode` RUSTSEC-2025-0141 is ignored in `deny.toml` until 2026-11-30 and is compiled into `warden.so`; duplicate `@noble/hashes` (1.8 / 2.4) and `spl-token` (0.4.9 / 0.4.14) in the lockfile. Not exploitable as used, but the ignore expiry is a date to calendar.
- Some `red_test` evidence rows point at happy-path tests (e.g. `rotate_nonce_ok_and_nonce_increments`); the `#[ignore]` test at `execute.rs:1691` is a measurement probe, not a skipped assertion.

**Owner blockers, unchanged from CLAUDE.md:** C1a decision, external audit engagement, deploy, WRDF-0050 and WRDF-0089, Jupiter IDL licence. Nothing in this audit changes their priority; they remain the critical path.

## 5. Suggested ledger and doc changes (not applied)

| File | Change |
|---|---|
| `docs/security/invariants.jsonl` | Add `WRD-EXEC-13` — "a token account not owned by the vault whose `delegate` is the vault PDA is rejected pre-CPI" — status `unimplemented`, evidence `red_test` once written |
| `docs/security/invariants.jsonl` | Caveat WRD-CAP-01 / WRD-CAP-09 notes: bucket debit is proven for vault-owned sources only, pending WRD-EXEC-13 |
| `docs/security/invariants.jsonl` | First extension rows: full-context check on record adoption (K-1), approval arm guard (A-1), eager lock at deadline (A-2) |
| `docs/security/REVIEW-RUNS.jsonl` | Row for this audit: `fable-5`, range `77a8273..2518520`, scope program+core+extension+process, findings P-1 K-1 A-1 A-2 A-3 P-2 P-3 K-2..K-11 R-1..R-6 |
| `programs/warden/src/transcript.rs:51-53` | Fix the revoke-body comment |
| `CLAUDE.md` | KEK/DEK bundle is built (`bundle.ts`, record v2); update the "unbuilt" statement |
| `.claude/test-gate.sh` | Add clippy `-D clippy::arithmetic_side_effects` and `scripts/supply-chain-gate.sh` (or an explicit note that they are CI-only and CI requires a push) |

## 6. Verification log (what I personally ran or read)

- `git rev-parse origin/phase1b` / `git log --first-parent 77a8273..HEAD --oneline | wc -l` / `git diff --stat 77a8273..HEAD -- programs packages/core/src apps/extension pnpm-lock.yaml package.json` / `grep 7936419 docs/security/*.jsonl` / `tail -1 docs/security/REVIEW-RUNS.jsonl`.
- Read in full: `programs/warden/src/heap.rs`; `payload.rs:205-225`; `registry_default.rs:50-64`; `registry.rs:100-135`; `conservation/compare.rs:200-270, 330-375`; `conservation/mod.rs:180-215`; `grant_session.rs:28-87,146`; `packages/core/src/keyring/record.ts:559-575`; `keyring/derive.ts:73-74,126,130-145`; `deploy/gate.ts:110-128`; `execute/wrap.ts:438-460`; `webauthn/transcript.ts:125-160`; `apps/extension/src/background/keyring-lifecycle.ts:198-210`; `keyring-record-store.ts` (full); `approval/main.ts:200-260,336`; `unlock-session.ts:160-180`; `.claude/test-gate.sh`; `scripts/supply-chain-gate.sh` header.
- `grep -rn delegate programs/warden/src` to confirm no account-level delegate check exists for non-vault-owned accounts.
- `scripts/supply-chain-gate.sh` → PASS (log in session scratchpad).
