# Warden — design spec (v1)

**Date:** 2026-08-18 · **Status:** rev 2 (after Codex review round 1, see §16) · **Product:** drinkerlabs · **Working name:** Warden (rename = find/replace)
**Predecessor:** `/opt/docs/pq-solana-wallet-research-2026-08-18.md` (feasibility study; the quantum root is out of scope here but every choice keeps its slot).

## 1. Purpose and the one property we promise

A Solana browser-extension wallet that is **more secure than Phantom against the losses that actually happen** — AI-scale phishing, fake dApps, drainers, seed-phrase scraping, poisoned addresses, prompt-injected agents — by moving safety from *warnings the user can click through* to **limits the chain enforces**. It keeps the Phantom core: connect to dApps, send, receive, and an in-app Jupiter swap that earns a platform fee.

**The property (stated exactly, because it is the product):** *If an attacker obtains everything the extension holds while unlocked — the session key, the unlocked keyring, the ability to prompt the user — the value that can leave the account before the owner or a guardian can react is bounded by the account's session caps; anything larger is delayed and cancellable.* Bounded means **token/lamport value leaving the account's own token accounts and lamport balance**. It does **not** cover value the user has already placed under other programs' control (see §5.4) or a compromised OS that can defeat the passkey ceremony.

## 2. Threat model

| # | Threat | v1 answer |
|---|---|---|
| T1 | User is talked into approving a draining tx (fake dApp, deepfake support, poisoned address) | Session key: ≤ per-tx and ≤ daily caps per mint, account-wide across all sessions. Larger outflows — **including by the root** — go through a timelock with a cancel window and notifications |
| T2 | Seed phrase scraped | No seed phrase exists in the default path; the recovery code is a 128-bit code that unlocks a *guardian key*, which cannot move funds and is itself subject to the recovery delay |
| T3 | Malicious/updated extension | Root = **non-exportable P-256 passkey verified on-chain**; the extension never holds root secret material. A malicious extension can spend the session caps, and can *ask* the user to complete a passkey ceremony for a large action — that action is still timelocked and visible on the notifier/second device. Explicitly **not** defended: a malicious extension that lies about intent to a user with no second channel |
| T4 | Device/passkey lost | Guardian recovery (threshold, delayed, root-cancellable) or the recovery-key path (also delayed) |
| T5 | AI agent/bot with wallet access is prompt-injected | Agents get their own session key with tiny caps (on-chain in v1; UI in v1.1) |
| T6 | Bug in our program | Small typed surface, adversarial + property tests, external audit and bug bounty **before any real funds**, per-account `frozen`, upgrade path with an exit window (§13) |
| — | Quantum signature forgery | Out of scope. Preserved: asset holder is a PDA; root/guardian kinds are typed → a hash-based/Falcon kind is additive |
| — | Compromised OS/keylogger with unlocked session | Bounded by caps only |
| — | Lying RPC | Cannot sign; can hide state. Intent view cross-checks simulation vs local pre-check and flags disagreement; user-selectable RPC |

## 3. Architecture

```
┌──────────────────────────── on-chain: warden program (Anchor/Rust) ────────────────────────────┐
│ SmartAccount (PDA ["account", owner_seed])  – holds SOL + SPL/Token-2022 via its ATAs           │
│   root: {kind: P256Passkey{cred_id_hash, pubkey} | Ed25519 | reserved}, generation: u64         │
│   policy (versioned, §5.5), frozen: {by: None|Root|Guardian(idx), until_ts}, day buckets       │
│ SessionKey (PDA ["session", account, pubkey]) – kind, expiry_ts, ops_mask, program_allowlist_id,│
│   caps[mint]{per_tx, per_day}, lifetime{cap, spent}, generation_at_grant, label                │
│ Stage (PDA ["stage", account, hash]) – chunk-uploaded, finalized, consume-once instruction set   │
│ Pending (PDA ["pending", account, nonce]) – timelocked action: transfer | execute | policy |    │
│   grant; content hash, execute_after_ts, created_by, generation                                │
│ Recovery (PDA ["recovery", account, nonce]) – immutable proposal, approvals bitmap, ready_ts   │
│ Treasury = a SmartAccount owned by the drinkerlabs multisig; fee ATAs belong to it              │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
        ▲ session-signed txs (typed ops + allow-listed dApp execute)   ▲ root = passkey ceremony
┌────────────── apps/extension (MV3) ─────────────┐   ┌────────────── packages/core (TS SDK) ─────────────┐
│ service worker: session keyring (encrypted),    │   │ account model · builders · policy pre-check        │
│ tx builder/rewriter, policy pre-check, sim +    │   │ (mirrors on-chain rules) · simulation + intent      │
│ intent renderer, Wallet Standard bridge, event  │   │ (balance diffs, authority changes) · Jupiter client  │
│ watcher; popup/full-page React UI (§9)          │   │ · WebAuthn/PRF + backup envelope crypto · poison    │
│ passkey (WebAuthn from extension origin)        │   │ heuristics · no DOM/chrome.* (node-testable)         │
└─────────────────────────────────────────────────┘   └────────────────────────────────────────────────────┘
```

Repo `/opt/warden`: `programs/warden` (Anchor), `packages/core`, `apps/extension`, `services/{treasury,guardian,notifier}`, `docs/`. pnpm workspaces; Rust/Anchor pinned.

## 4. Key model

**Root = passkey (default).** A platform passkey created from the extension's origin (RP ID = extension id), `userVerification: required`, algorithm restricted to ES256. The P-256 public key is the account root; the program verifies WebAuthn assertions on-chain via the secp256r1 precompile: `authenticatorData ‖ SHA256(clientDataJSON)`, with `rpIdHash` == our RP ID hash, `type == "webauthn.get"`, `challenge` == Keccak256(canonical action transcript ‖ recent blockhash), UP+UV flags set, `origin` == extension origin; sign counter advisory only. The private key never leaves the authenticator; the extension cannot export it. Ed25519 root kind exists for hardware/advanced users and is not the default.

**Session key.** Ed25519 keypair in the service-worker keyring (AES-256-GCM; unlock secret from passkey PRF, fallback Argon2id password per spike §14.2), unlocked for a window (default 15 min idle / 8 h max). Signs routine actions within caps. Multiple sessions (devices, agents) share **account-wide** daily caps; each also has a lifetime cap.

**Guardians.** Up to 5 typed pubkeys (Ed25519 or P-256 passkey of a second device) with threshold (default 2-of-3): second device, a friend's wallet, and the optional **drinkerlabs cloud guardian** (a service key that can only `approve_recovery` and `freeze`, after email magic-link + TOTP + 24 h cooling). Guardians can freeze (bounded, §5.3) and approve recovery; nothing else.

**Recovery key (replaces "backup blob").** At onboarding the extension generates an Ed25519 *recovery key*, registers it on-chain as a guardian with weight = threshold, encrypts it into a versioned envelope (Argon2id id=2, m=256 MiB, t=3, p=1; AAD = account address ‖ version) under a **128-bit recovery code** (12 BIP-39 words) shown once and exportable to file/QR. It can *only* propose+approve recovery — it cannot move funds and is subject to the same delay and root veto. Losing it loses nothing while guardians remain.

**Default policy (user-editable; loosening is timelocked):**
- Session caps (account-wide/day; per-tx): SOL 0.5 / 2; USDC & USDT 100 / 500. Other mints: no transfer/execute outflow unless a cap is set.
- Swap caps (input side, per mint per day, account-wide): SOL 5, stables 2,000, other mints 100% of holdings *only if* out_mint ∈ `allowed_out_mints` (default: SOL, USDC, USDT). Swaps into other mints require an explicit cap or the root.
- Large threshold = anything above session caps → root ceremony **and** timelock (default 12 h, min 1 h). Recipient allowlist entries (added via timelocked loosening) skip the delay for that recipient only.
- Recovery delay 48 h; guardian-freeze max 72 h.

## 5. On-chain program

### 5.1 Instructions

| Instruction | Signer | Effect / invariants |
|---|---|---|
| `create_account(root, policy, owner_seed)` | payer | `owner_seed` = 32 random bytes chosen client-side (address is a hash, not derived from root) |
| `grant_session(...)` | root | Caps ≤ `policy.session_ceiling` per mint, expiry ≤ `policy.max_session_life`, `program_allowlist_id` must exist in policy. Sets `generation_at_grant = account.generation`. Grants above ceiling → must go through `queue(Grant)` |
| `revoke_session(pubkey)` | root or that session | Closes |
| `transfer(mint?, to, amount)` | session (within caps) or root (≤ `large_threshold`, else must be queued) | Native or SPL; day-bucket + lifetime accounting; `to` must not be a vault-owned token account; ATA creation for `to` funded by the outer fee payer, never the vault |
| `swap(route)` | session or root | Jupiter CPI, §5.2 |
| `execute(stage?, ixs?)` | session or root | Allow-listed dApp CPI with conservation checks, §5.2. Root execute above threshold must be queued |
| `stage_open(hash, len)` / `stage_chunk(off, bytes)` / `stage_finalize` / `stage_close` | any payer | Chunked upload; finalize checks Keccak256(content) == hash and records `generation` + `policy_version`; consume-once (closed on use); expiry ts; anyone may close after expiry |
| `queue(action)` → Pending | root | Content-hashed action (transfer/execute/policy/grant); `execute_after = now + timelock` |
| `cancel_pending(nonce)` | root or any guardian | Closes |
| `execute_pending(nonce)` | permissionless after `execute_after` | Re-validates against **current** policy and generation; refuses if frozen |
| `set_policy(policy)` | root | Tightening applies immediately; any loosening (§5.5) rejected here → must be queued |
| `freeze` | root or guardian | Root freeze: indefinite until root `unfreeze` (after timelock). Guardian freeze: `until = now + guardian_freeze_max`, one active guardian freeze at a time, a guardian may freeze at most once per `guardian_freeze_cooldown` (7 d) |
| `unfreeze` | root | After timelock (root freeze) or immediately for a guardian freeze |
| `propose_recovery(new_root, nonce)` | guardian | Immutable proposal; approvals bound to content hash |
| `approve_recovery(nonce)` | guardian | At threshold: `ready_ts = now + recovery_delay` |
| `execute_recovery(nonce)` | permissionless after `ready_ts` | Refused only if **root-frozen** (root veto = "I'm here"; guardian freeze does not block); replaces root, `generation += 1` (invalidates every session, stage, pending) |
| `cancel_recovery(nonce)` | root | Closes. Stalemate note: an attacker holding root can veto/cancel forever, but guardians can freeze forever — funds stay put; documented outcome |

Cross-cutting: `frozen` gates every outflow and session use; every PDA re-derived from seeds; **checked arithmetic everywhere** (overflow = abort); every account `version: u8`; **self-CPI into the warden program is rejected**; time from `Clock.unix_timestamp` (not slots); day buckets are fixed UTC days — the honest bound across a boundary is 2× the daily cap and the UI says so; lifetime caps and per-tx caps are exact.

### 5.2 Conservation checks for `execute` and `swap` (the load-bearing part)

`execute` runs the CPIs itself, so it can snapshot before and after in one instruction. Rules:
1. **Program allowlist.** Session `execute` may CPI only to programs in the session's `program_allowlist_id` (policy-defined lists; default list = well-known Solana programs, extendable only via timelocked loosening). Root `execute` may target any program (still conservation-checked and, above threshold, queued).
2. **Snapshot every writable account** in the tx: existence, owner, lamports, data length, and for token accounts (SPL + Token-2022) the full `(mint, owner, amount, delegate, close_authority, state)`.
3. **Vault-owned accounts** (owner == SmartAccount PDA, or token accounts whose authority is the PDA): after CPIs, `owner` unchanged, `delegate == None`, `close_authority == None`, `state == Initialized`, not closed, not realloc'd. The SmartAccount PDA itself may not be writable to any CPI target. **No other vault-owned account types are allowed to be writable** (stake accounts, nonce accounts, program-owned state with the vault as owner) — unsupported in v1, rejected.
4. **Value accounting.** For each mint, `outflow = Σ decreases − Σ increases` over vault-owned token accounts; **WSOL is canonicalized to SOL** (WSOL amounts + native lamports counted together); native lamport decrease of the PDA counts as SOL outflow **with no rent exemption** (account creation is always funded by the outer fee payer). Session: `outflow[mint] ≤ per_tx[mint]` and day/lifetime buckets updated with checked math; a mint without a cap ⇒ outflow must be 0. Root: ≤ `large_threshold` or the action must have come from `execute_pending`.
5. **Token-2022**: mints with transfer-hook, permanent-delegate, or confidential-transfer extensions rejected unless allow-listed in policy.
6. **Stage binding**: staged content carries `generation` and `policy_version`; both must equal current at execution; consumed on use.
7. **`swap`** = `execute` specialised: CPI pinned to the Jupiter v6 program id + `route`/`shared_accounts_route` discriminators; source = vault ATA(in_mint), destination = vault ATA(out_mint), `platform_fee_account` = treasury ATA (of in or out mint) else reject; post-state: exactly one vault-owned token account decreases (in_mint, ≤ `max_in` ≤ swap caps), out_mint ATA increases ≥ `min_out`, others unchanged; **`out_mint ∈ allowed_out_mints` for sessions** unless a cap exists for it. Swap input debits the swap buckets (per mint per day, account-wide, lifetime per session). *This bounds loss to the swap caps regardless of route quality; it does not check price* — the extension enforces quote sanity (Jupiter quote vs a second price source; > 3% deviation blocks the session path).

### 5.3 What §5.2 does and does not guarantee (§1 boundary)
Guaranteed: bounded token/lamport outflow from vault-owned accounts under session control; no durable authority/delegate can be created on vault-owned token accounts; no vault-owned account can be closed or repurposed. Not guaranteed: semantics inside external programs where the user already holds positions (a session may interact with an allow-listed protocol's position the vault is authority of; e.g. adjust a lending position). Mitigation is the program allowlist + per-op simulation intent; the honest product statement is "bounded loss of what's in your wallet".

### 5.4 Policy lattice (loosening definition, exhaustive)
Fields and their *loosening* direction (must be queued + timelocked; tightening immediate): any cap ↑ (session, swap, ceiling); `large_threshold` ↑; `timelock` ↓; `recovery_delay` ↓; `guardian_threshold` ↓; remove guardian; add allowlisted recipient; add mint to `allowed_out_mints`; add program to any allowlist; enable a Token-2022 extension; `max_session_life` ↑; `guardian_freeze_max` ↓. Anything not listed is treated as loosening by default. `execute_pending` reclassifies against the policy in force at execution.

### 5.5 Upgrade authority
Devnet: upgradeable by the dev multisig. Mainnet: 3-of-5 drinkerlabs multisig with a **7-day timelock**; the extension surfaces any queued upgrade with a one-click "exit" (sweep to a fresh account or an external address via the root path, timelock waived when a program upgrade is pending — encoded on-chain by checking the BPF upgradeable loader's pending buffer authority state is not possible; instead the multisig must call `announce_upgrade(slot)` on the program first, which opens the exit window; upgrading without an announcement is a policy violation we publish). Commit to immutability at v1.x once stable.

## 6. Extension (MV3)

- **Service worker**: keyring, request queue, Wallet Standard handlers, simulation + policy pre-check, Jupiter client, event watcher.
- **Provider**: `registerWallet()` exposing `standard:connect/disconnect/events`, `solana:signTransaction`, `solana:signAndSendTransaction`, `solana:signMessage`, `solana:signIn`; legacy `window.solana` shim.
- **Intent view** (the most important screen): balance diffs per token from simulation, authority/delegate changes (always red, always blocked for sessions anyway), recipient trust (known / first-time / seen-only-via-dust = poison warning), and the policy verdict: *within limits* / *needs passkey + delay* / *blocked (why)*.
- **dApp transactions — the honest boundary.** Warden advertises the SmartAccount PDA as the account. A dApp-built tx is **rewritten**: fee payer = session key; dApp instructions are wrapped into `execute` (inline if ≤ 1,232 B, else stage-and-execute across two txs shown as one flow); ALTs preserved. Because the signed bytes change, the following are **unsupported and rejected with a clear message**: transactions with other required signers/partial signatures, durable-nonce transactions, transactions that need the PDA as a *top-level* signer, instructions that inspect the Instructions sysvar for adjacency, and dApps whose target program is not on the session allowlist (offered: root path). `signMessage`/`signIn` are signed by the session key; dApps that verify against the account address (Sign-In-With-Solana) **will fail** — no Solana-native ERC-1271 exists; Warden publishes a measured per-dApp compatibility list (§14.4) and does not claim Phantom parity.
- **Swap**: `/quote?platformFeeBps=FEE_BPS` → `/swap-instructions` → `swap`; `feeAccount` = treasury ATA; quote sanity vs a second source; `FEE_BPS` = 85 default (owner decision).
- **Address book & poison guard**: first-seen provenance; dust-only senders flagged; first-time recipients require typed confirmation of first/last 4 chars.
- **Passkeys/PRF**: root ceremony = WebAuthn `get()` with challenge = action transcript hash; PRF (if available) derives the keyring key; otherwise Argon2id password. Root never touches the extension's memory.

## 7. Recovery flows

1. **Onboarding** creates root passkey + recovery key (shows the 12-word code once, offers file/QR export) and nudges to add guardians (second device via QR = its passkey pubkey; friend; cloud guardian). Recovery-key alone already makes recovery possible; guardians make it robust to losing the code too.
2. **Lost device**: new device → "Recover" → account address → new passkey → guardians (or the recovery key on the new device) propose+approve → 48 h → execute. Old device (if any) sees "recovery in progress" and can cancel or root-freeze.
3. **Stalemate** (attacker holds root, user holds guardians): guardians freeze; nothing moves; documented.

## 8. Backend (none holds spending keys)

Treasury job (pre-create fee ATAs, sweep, report) · Cloud guardian service (one key: `approve_recovery` + `freeze` only; email + TOTP + 24 h cooling; audit log; de-rooted unit) · Notifier (program events → web push/email; the second channel that makes T3 survivable) · RPC proxy (per-install rate limits; custom RPC allowed; simulation and send use the same endpoint).

## 9. UI/brand — drinkerlabs playbook

Material: paper on `--bone`/`--midnight`; one accent `--indigo`; semantic ok/warn/critical hues separate from accent; Inter + JetBrains Mono, one Tiempos italic phrase on the onboarding hero; hairlines, tabular numerals, three shadow tiers, one imperfection (asymmetric corner radius). Sentence-case operator voice. Figma first (variables → components → frames), extension consumes the same tokens as CSS variables. Screens (popup 360×600 + full-page): 01 onboarding · 02 home (balances, pending, session status) · 03 receive · 04 send · 05 swap · 06 sign request/intent · 07 connect · 08 policy · 09 sessions & devices · 10 guardians & recovery · 11 settings/trust (program id, upgrade authority, pending upgrades, exports).

## 10. Testing & verification

Program: unit per instruction; LiteSVM integration; **adversarial suite** — cap bypass via CPI (Approve/SetAuthority/Close/realloc), rent-drain via vault-funded ATA creation, WSOL laundering, day-boundary burst, multi-session aggregate caps, expired/regenerated sessions, stale stages, replay of pending actions after policy tightening, guardian DoS (freeze spam/cooldown), recovery race with root veto, Jupiter route with wrong destination/fee ATA/hook mint, self-CPI, compute exhaustion; property tests on conservation (property-based-testing skill). SDK: builder/pre-check parity fixtures (same inputs → same verdicts on-chain and off), intent snapshots, envelope round-trip + Argon2id vectors. Extension: Playwright vs local validator with a Jupiter mock (nightly vs mainnet-fork); dApp compat harness for the top-20 list. Gates: `.claude/test-gate.sh` in the global commit hook; Codex reviews spec, each program milestone, and a pre-deploy recon; **independent audit + public bug bounty before any real-funds mainnet**.

## 11. Rollout

devnet internal → devnet public beta (test funds) → **audit + bounty** → mainnet guarded beta (low default caps, cloud guardian on, upgrade timelock + exit window live) → GA → immutability decision.

## 12. Spikes (each ≤ 1 day, run first; results can change this spec)

1. **Squads Smart Account API** — typed signers + spending limits + single-tx execution good enough to host v1? (< 20% compromise → switch the vault to Squads, keep the rest.)
2. **WebAuthn from an MV3 extension origin**: ES256 passkey creation/assertion + PRF on Chrome/Brave desktop with platform and synced passkeys; on-chain verification of a real assertion via secp256r1 precompile in LiteSVM.
3. **Wrapped-tx byte budget**: rewrite three real dApp txs (Jupiter swap, Tensor buy, Marinade stake) through `execute`; inline-fit rate; stage+execute UX; CU of conservation checks with ~30 writable accounts.
4. **Compatibility inventory**: top-20 dApps — which need SIWS/message verification, co-signers, durable nonces, or off-allowlist programs.

## 13. Non-goals (v1)

Mobile · agent-key UI · quantum root · multi-chain · hardware wallets · NFT gallery beyond a list · fiat on-ramp · staking UI · plain-keypair accounts inside Warden · vault-owned stake/nonce/program-state accounts (positions live in external programs' accounts).

## 14. Open decisions for the owner

Fee bps default (85) · cloud guardian in v1 (proposed yes) · working name.

## 15. Glossary of on-chain accounts (for the plan)

`SmartAccount`, `SessionKey`, `Stage`, `Pending`, `Recovery`, `Treasury(SmartAccount)`; policy = `{session_caps[], session_ceiling[], swap_caps[], allowed_out_mints[], recipient_allowlist[], program_allowlists[][], large_threshold[], timelock, recovery_delay, guardian_threshold, guardians[], guardian_freeze_max, guardian_freeze_cooldown, max_session_life, t22_allowed_ext, version}`.

## 16. Review log

**Codex round 1 (gpt-5.6-sol@xhigh, thread 01a01477…): REJECT** — 6 BLOCKER / 6 MAJOR. All folded into rev 2: swap caps + `allowed_out_mints` (was "swaps always safe"); `execute` restricted to allow-listed programs with full writable-account snapshots, WSOL canonicalization, no rent exemption, outer-payer-funded creation, no self-CPI, unsupported vault-owned account types rejected; root paths bound by `large_threshold` + queue; grant ceilings + aggregate account-wide caps; root = on-chain-verified P-256 passkey (extension never holds root secret) with the residual "lying extension" risk stated; guardian freeze bounded (max + cooldown), immutable nonce-addressed recovery proposals, root-only veto, generation bump invalidates sessions/stages/pending; exhaustive loosening lattice; honest dApp-compat boundary (rewrite = unsupported co-signers/nonces/SIWS); chunked consume-once staging bound to generation + policy version; recovery key (128-bit code, Argon2id params, AAD) replaces the contradictory backup blob; UTC-day buckets with the 2× boundary bound stated + lifetime caps + checked math; audit + bounty before real funds, upgrade timelock + announced exit window.
