# Warden — design spec (v1)

**Date:** 2026-08-18 · **Status:** draft for owner review · **Product:** drinkerlabs · **Working name:** Warden (rename is a find/replace; nothing below depends on it)
**Predecessor:** `/opt/docs/pq-solana-wallet-research-2026-08-18.md` (feasibility study; the quantum root is *out of scope* here but every choice below keeps its slot).

## 1. Purpose

A Solana wallet that is **more secure than Phantom against the losses that actually happen** — AI-scale phishing, fake dApps, drainers, seed-phrase scraping, poisoned addresses, prompt-injected agents — by moving the safety from *warnings the user can click through* to **limits the chain enforces**. It keeps Phantom's core feel: connect to dApps, send, receive, and an in-app swap (Jupiter) that earns a platform fee.

Success for v1 = a Chrome/Brave extension a real user can install, onboard without ever seeing a seed phrase, use with mainstream Solana dApps, swap with a fee collected to our treasury, and — the point — **a phished user loses at most their session cap, never the wallet.**

## 2. Threat model (what v1 defends and what it doesn't)

| # | Threat | v1 answer |
|---|---|---|
| T1 | User is talked into signing a draining tx (fake dApp, deepfake support, poisoned address) | Session key can only move ≤ per-tx cap and ≤ daily cap per mint; larger outflows need the root **and** a timelock with a cancel window |
| T2 | Seed phrase scraped (malware, clipboard stealer, phishing page) | There is no seed phrase in the default path; the root secret lives only as an encrypted blob the user cannot paste into a website |
| T3 | Malicious/updated extension steals the hot key | Hot key = session key, capped; root needs a fresh passkey ceremony (user-verification) per use; large moves are timelocked and visible |
| T4 | Device lost / passkey lost | Guardian recovery (2-of-3, delayed, owner-cancellable) |
| T5 | AI agent/bot with wallet access is prompt-injected | Agents get their own session key with its own tiny caps (on-chain support in v1; UI in v1.1) |
| T6 | Bug in *our* program | Small typed surface, adversarial tests, external audit before mainnet, upgrade authority = timelocked 2-of-3 multisig, per-account `frozen` switch |
| — | Quantum signature forgery | Out of scope for v1. Preserved: asset holder is a PDA (hash-derived, not a raw pubkey), authorities are typed → a hash-based/Falcon root signer is an additive signer type later, no address migration |
| — | Compromised OS / keylogger with a live unlocked session | Bounded by caps; not prevented |
| — | Compromised RPC/quote server | Simulation and intent are computed from an RPC we choose; a lying RPC can hide state but cannot sign; treated in §9 |

## 3. Architecture

```
┌───────────────────────────── on-chain: warden program (Anchor/Rust) ─────────────────────────────┐
│ SmartAccount (PDA ["account", owner_seed])   – holds SOL + SPL/Token-2022 via its ATAs           │
│   root_key: Ed25519 pubkey (typed: RootKind::Ed25519 | ::Passkey_P256 | reserved for PQ kinds)   │
│   policy:  large_tx_threshold per mint, timelock_secs, guardian set + threshold, recovery_delay │
│   frozen:  bool (root or any guardian can freeze; only root can unfreeze after timelock)         │
│ SessionKey (PDA ["session", account, pubkey]) – kind, expiry_slot, ops_mask, caps[mint]:        │
│   {per_tx, per_day, day_start_slot, spent_today}, lifetime_cap/spent, label                    │
│ StagedTx  (PDA ["staged", account, hash])   – content-addressed staged instruction bundle       │
│ PendingTransfer (PDA ["pending", account, nonce]) – timelocked large outflow, cancellable       │
│ RecoveryProposal (PDA ["recovery", account]) – new root, approvals bitmap, execute_after         │
│ Treasury = another SmartAccount owned by the drinkerlabs multisig; fee ATAs belong to it        │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
        ▲ Wallet Standard / Jupiter / dApp txs (session-signed)          ▲ rare root ceremonies
┌────────────── apps/extension (MV3) ─────────────┐   ┌────────────── packages/core (TS SDK) ─────────────┐
│ service worker: keyring (encrypted), tx builder,│   │ account model · instruction builders · policy      │
│ policy pre-check, simulation, intent renderer,  │   │ pre-check (mirrors on-chain rules) · simulation +  │
│ Wallet Standard provider bridge                 │   │ intent (balance diffs, authority changes) · Jupiter │
│ popup/UI: onboarding, home, send, swap, sign,   │   │ client (quote/swap-instructions, platformFeeBps) ·  │
│ policy, sessions, recovery, settings, connect   │   │ passkey/PRF + backup-blob crypto · address-poison  │
│ passkey (WebAuthn, extension origin)            │   │ heuristics · no DOM, no chrome.* (testable in node)  │
└─────────────────────────────────────────────────┘   └────────────────────────────────────────────────────┘
```

Repo: `/opt/warden` monorepo — `programs/warden` (Anchor), `packages/core`, `apps/extension`, `docs/`. pnpm workspaces; Rust toolchain pinned; Anchor version pinned.

## 4. Key model (who can do what)

**Root key** — an Ed25519 keypair generated in the extension at onboarding. Its secret is encrypted at rest with a key derived from the user's **passkey via the WebAuthn PRF extension** (fallback: a strong local password through Argon2id if PRF is unavailable on the device — decided by a spike, §12). Every root use requires a fresh passkey ceremony with user verification. Root signs: session grants/revocations, policy changes, large (timelocked) transfers, guardian changes, recovery cancellation, unfreeze. Root kind is typed so a P-256 passkey (secp256r1 precompile) or, later, a hash-based key can be the root without changing accounts.

**Session key** — an Ed25519 keypair held in the service worker's encrypted keyring, unlocked for a session window (default 15 min idle / 8 h max; configurable). It signs everything routine: dApp transactions, sends, swaps, message signing. It has caps and expiry enforced **on-chain**; the extension additionally pre-checks so the user sees "this exceeds your session limit — confirm with your passkey to move it as a large transfer" instead of a failed tx.

**Guardians** — up to 5 pubkeys with a threshold (default 2-of-3). Guardian types are just pubkeys: the user's second device (its own root key), a friend's wallet, and an optional **drinkerlabs cloud guardian** (a service key that only ever co-signs a recovery after email/2FA and a mandatory delay; it can never move funds). Guardians can *freeze* the account and *approve recovery*; nothing else.

**Default policy (v1 defaults; user-editable):**
- Session per-tx cap: 0.5 SOL and 100 USDC-equivalent per stable; per-day: 2 SOL / 500 stables. Other mints: **no outflow via transfer or dApp** unless a cap is set — but **swaps of any held token are always allowed** because output returns to the vault (loss bounded by `min_out`).
- Large-transfer threshold = anything over session caps → root + timelock (default 12 h; min 1 h; the user may pre-approve a specific recipient allowlist to skip the timelock for that recipient).
- Recovery delay 48 h; owner can cancel any time in the window; a cancel does not consume anything.

## 5. On-chain program — instructions and invariants

Anchor program `warden`, ~1.5k LOC target. All amounts `u64`; slots for time (Clock sysvar); every account carries `version: u8` for migrations.

| Instruction | Signer | Effect / invariants |
|---|---|---|
| `create_account(root_kind, root_key, policy)` | payer (any) | Creates SmartAccount; `owner_seed` = 32 random bytes chosen client-side so the address is a hash, not derivable from the root key |
| `grant_session(pubkey, kind, expiry, ops_mask, caps[], label)` | root | Upserts SessionKey. Rejects expiry > policy.max_session_life |
| `revoke_session(pubkey)` | root **or the session itself** | Closes SessionKey (a session may always self-revoke) |
| `set_policy(policy)` | root; if it *loosens* limits it goes through PendingTransfer-style timelock (`policy_change` op) | Loosening = raising any cap, shortening timelock/recovery delay, removing a guardian |
| `transfer(mint?, to, amount)` | session (within caps) or root (any) | Native SOL or SPL. Session: `amount ≤ per_tx`, `spent_today + amount ≤ per_day` (day resets on slot window), `to` not a vault ATA authority change; ATA creation for `to` allowed and paid by fee payer |
| `execute(bundle)` | session or root | Runs a staged or inline instruction bundle by CPI with the SmartAccount PDA as signer. **Post-state invariants** (checked after all CPIs): for every writable token account owned by the account in the tx: `owner` unchanged, `delegate == None`, `close_authority == None`; per-mint net outflow ≤ session caps (root: unlimited); native lamport outflow (minus rent for created ATAs) ≤ SOL cap; no `SetAuthority`/`Approve`/`Revoke`/`CloseAccount` targeting vault-owned accounts (checked by post-state, not by parsing) |
| `swap(route)` | session or root | Specialised `execute` for Jupiter: CPI target pinned to the Jupiter v6 program id + `route`/`shared_accounts_route` discriminators; source ATA = vault ATA of `in_mint`, destination = vault ATA of `out_mint`, `platform_fee_account` = treasury ATA of the fee mint (else reject); post-state: exactly one vault-owned token account decreases (in_mint, ≤ `max_in`), out_mint ATA increases ≥ `min_out`, all others unchanged; Token-2022 mints with transfer-hook or permanent-delegate extensions rejected unless allow-listed in policy. Swaps never count against `transfer` caps (value stays in the vault) but do count `in_mint` against a separate `swap_per_day` cap (default: unlimited for SOL/stables; sanity cap for others) |
| `stage(hash, ixs)` / `unstage` | any payer | Content-addressed StagedTx for bundles that don't fit one tx; immutable; anyone can close after expiry (rent to creator) |
| `queue_large_transfer(mint?, to, amount)` | root | Creates PendingTransfer with `execute_after = now + timelock`; emits event (extension + optional cloud notifier watch it) |
| `cancel_pending(nonce)` | root **or any guardian** | Closes PendingTransfer |
| `execute_pending(nonce)` | anyone (permissionless crank) after `execute_after` | Executes; refuses if account frozen |
| `freeze` | root or any guardian | Sets `frozen`; blocks all outflows and session use |
| `unfreeze` | root, after `timelock` | Clears |
| `propose_recovery(new_root_kind, new_root_key)` | guardian | Creates/overwrites RecoveryProposal, approvals={proposer} |
| `approve_recovery` | guardian | Adds approval; when threshold met sets `execute_after = now + recovery_delay` |
| `execute_recovery` | anyone after `execute_after` | Replaces root, **revokes all sessions**, clears pending transfers, requires account not frozen by root within window (a root freeze during the window = "I'm still here", blocks execution) |
| `cancel_recovery` | root | Closes proposal |

Cross-cutting: `frozen` gates every outflow; every instruction re-derives PDAs from seeds (no trusted account passing); CPI depth: our `execute` → dApp program (→ its CPIs) keeps within Solana's max depth of 4 for all common cases (Jupiter routes are depth 2 under us); compute: `execute` requests its own budget via `SetComputeUnitLimit` in the outer tx.

Upgrade authority: 2-of-3 Squads multisig (drinkerlabs) with a 24 h timelock, published in docs; the extension shows the program id + upgrade authority under Settings → Trust.

## 6. Extension (MV3) — structure

- **Service worker** (ephemeral): keyring (AES-256-GCM vault; unlock secret from passkey-PRF or Argon2id password; sealed with `chrome.storage.session` for the unlock window and `chrome.alarms` for expiry), request queue, Wallet Standard handlers, simulation + policy pre-check, Jupiter client, event watcher (pending transfers, recovery proposals).
- **Content script + injected provider**: `registerWallet()` (Wallet Standard) exposing `standard:connect/disconnect/events`, `solana:signTransaction`, `solana:signAndSendTransaction`, `solana:signMessage`, `solana:signIn`. Legacy `window.solana` shim for old dApps.
- **Popup / full-page UI** (React + Vite): screens in §8. Every signing request renders **intent**: balance diffs per token (from simulation), authority/delegate changes (always red), recipient trust state (known / first-time / seen-only-via-incoming-dust = poison warning), and the policy verdict (within session limits / needs passkey + timelock / blocked).
- **How a dApp tx becomes a Warden tx**: the dApp builds a tx believing our advertised address (the SmartAccount PDA) is the fee-payer/signer. The provider re-writes it: fee payer = session key; each dApp instruction is wrapped into `execute` (inline if the rewritten tx ≤ 1,232 B, else `stage` first, then `execute` — two txs, shown as one flow), account-index compaction, ALTs preserved. Instructions that require the PDA as a *transaction* signer are satisfied by `invoke_signed` inside `execute`. Known limitation: dApps that verify a **message** signature against the address (Sign-In-With-Solana) will not verify a session-key signature; v1 answers `signIn`/`signMessage` with the session key **and** includes the account address in the returned account metadata, documents the boundary, and tracks which major dApps break (see §12 spike). No Solana-native ERC-1271 analogue exists; not solved in v1.
- **Passkeys**: WebAuthn from the extension's own origin (RP ID = extension id), platform authenticator, `userVerification: required`, PRF extension for key derivation. Backup of the root: an encrypted blob (root secret + account seed + metadata) wrapped with a 6-word recovery code (BIP-39 words, 66 bits + KDF) *and* the PRF key, exportable to file/Drive/iCloud/QR; the recovery code is shown once and is the only "phrase" a user ever sees, and it cannot move funds on its own (blob + code + on-chain policy still apply).
- **Swap**: Jupiter Swap API `/quote?platformFeeBps=<FEE_BPS>` → `/swap-instructions` → wrapped in `swap`; `feeAccount` = treasury ATA for the input or output mint (created by our treasury job ahead of time for the top mints; on-demand creation paid by us for others). `FEE_BPS` default 85 (Phantom parity) — a single constant; owner decision.
- **Address book & poison guard**: contacts with first-seen source; recipients that only ever appeared as senders of dust are flagged; first-time recipients require full-address confirmation of the last 4 + first 4 chars typed.

## 7. Guardian recovery flow (user-facing)

1. Onboarding nudges to add guardians (second device via QR = its root key; a friend's wallet address; the cloud guardian by email). Not adding = a persistent, non-nagging "recovery not set" banner.
2. Lost device: on a new device, install → "Recover" → enter account address (or scan a guardian's link) → the new device generates a new root and asks guardians to approve (deep-link/QR/email for cloud guardian). Threshold met → 48 h delay starts; the old device (if any) sees "recovery in progress — cancel?" and can cancel or freeze.
3. After delay, anyone (the new device) executes: root replaced, sessions revoked, funds untouched. Backup blob + recovery code can bypass the guardians entirely (same root restored, nothing on-chain changes).

## 8. UI/brand — drinkerlabs surface playbook for Warden

Material: **paper on `--bone` (light) / `--midnight` (dark)** — a wallet is an instrument, not a terminal; one accent `--indigo` (`oklch(50% 0.12 270)`); semantic states use fixed hues that don't count as accent (ok/warn/critical); type = **Inter (UI) + JetBrains Mono (addresses, amounts, hashes)**, cross-axis via one Tiempos italic phrase on the onboarding hero only. Hairlines, tabular numerals, three shadow tiers, one imperfection: asymmetric corner radius (`12px 12px 4px 12px`) on cards. Copy voice: sentence case, verbs an operator would say; no "seamless/empower".

Screens (Figma frames, popup 360×600 + full-page variants): 01 onboarding (create with passkey / recover / import advanced), 02 home (balances, pending timelocks, session status), 03 receive, 04 send (recipient trust, policy verdict), 05 swap (quote, fee line, route), 06 sign request (intent view — the most important screen), 07 connect (origin, permissions), 08 policy (caps, timelock, allowlist), 09 sessions & devices, 10 guardians & recovery, 11 settings/trust (program id, upgrade authority, backup export). Design tokens are produced first in Figma (variables), then components, then screens; the extension consumes the same tokens as CSS variables.

## 9. Backend (minimal, none holds keys)

- **Fee treasury job**: pre-creates treasury ATAs for top mints; sweeps to the treasury SmartAccount; report.
- **Cloud guardian service** (optional guardian): holds one key that can only call `approve_recovery` / `freeze`; requires email magic-link + TOTP + 24 h cooling before approving; audit log; rate limits. Runs on the /opt box as its own de-rooted systemd unit; key in a file readable only by its user.
- **Notifier**: watches program events for a user's account (pending transfer, recovery proposal, freeze) → push (web push) and email if opted in.
- **RPC**: paid RPC key lives in the extension config through our proxy with per-install rate limits; the extension allows a custom RPC. Simulation always runs against the same RPC that will send, and the intent view flags if simulation and the pre-check disagree.

## 10. Testing & verification

- **Program**: unit tests per instruction; LiteSVM/Bankrun integration tests including adversarial suites — cap bypass via CPI (Approve/SetAuthority/Close), replay of grants, expired sessions, day-window rollover, frozen-state gating, guardian collusion below threshold, recovery race with root freeze, Jupiter route with malicious accounts (wrong destination, wrong fee ATA, hook mints), stage/execute mismatch, compute exhaustion. Fuzz `execute` post-state checks with property tests (property-based-testing skill).
- **SDK**: node tests for builders, policy pre-check parity with on-chain rules (same fixtures produce same verdicts), intent renderer snapshot tests, backup blob round-trip.
- **Extension**: Playwright against a local validator (`solana-test-validator` with the program + a Jupiter mock program for CI; real Jupiter on devnet/mainnet-fork in a nightly job); dApp compatibility harness with 10 top dApps' connect/sign flows recorded.
- **Gates**: `.claude/test-gate.sh` opted into the global commit hook; Codex reviews spec (this doc), each program milestone, and a pre-deploy recon of the full diff (CODEX-USAGE-DOCTRINE ladder); external audit before mainnet with real funds; devnet public beta first.

## 11. Rollout

devnet (internal) → devnet public beta with capped test funds → mainnet "guarded beta" (program frozen behind multisig, per-account default caps low, cloud guardian on) → audit → general availability. Chrome Web Store listing owned by the drinkerlabs org account with 2FA; reproducible build hash published in Settings → Trust.

## 12. Spikes that gate the plan (each ≤ 1 day, done first)

1. **Squads Smart Account API check** — does it already give typed signers + spending limits + single-tx execution good enough to host v1? If yes with < 20% compromise, switch to approach B for the vault and keep the rest of this spec.
2. **WebAuthn PRF from an MV3 extension origin** on Chrome/Brave (desktop) with platform + synced passkeys — works? If not, root encryption falls back to Argon2id password and passkey stays UX-only.
3. **Wrapped-tx byte budget** — rewrite three real dApp txs (Jupiter swap, Tensor buy, Marinade stake) through `execute`; measure inline fit rate; measure `stage`+`execute` UX.
4. **SIWS breakage inventory** — which of the top 20 Solana dApps verify `signMessage` against the address (will break) vs only need `signTransaction`.

## 13. Non-goals (v1)

Mobile app · agent-key UI · quantum root signer · multi-chain/EVM · hardware wallets · NFT gallery beyond a list · fiat on-ramp · staking UI (dApps work via connect) · legacy plain-keypair accounts inside Warden.

## 14. Open decisions for the owner

- Fee bps default (85 proposed).
- Whether the drinkerlabs cloud guardian ships in v1 or v1.1 (proposed v1: it's what makes "no seed phrase" survivable for a solo user).
- Working name.
