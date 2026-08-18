# Phase 0 decision gate — spike roll-up

**Date:** 2026-08-18 · **Spec:** `docs/superpowers/specs/2026-08-18-warden-wallet-design.md` (rev 5 in, **rev 6** out) · **Plan:** `.superpowers/sdd/2026-08-18-warden-phase0-scaffold-spikes/`

Inputs, all read for this document (citations below are `file:line`):

| Spike | Result file | Task |
|---|---|---|
| 1 — Squads Smart Account API | `spikes/01-squads/result.md` | 2 |
| 2a — WebAuthn/PRF from an MV3 origin | `spikes/02-webauthn/result.md` part (a) | 3 |
| 2b — on-chain binding (secp256r1 + Instructions sysvar) | `spikes/02-webauthn/result.md` part (b)/(c) | 4 |
| 3a — wrapped-tx byte budget | `spikes/03-txbudget/result.md` part (a) | 5 |
| 3b — conservation snapshot CU | `spikes/03-txbudget/result.md` part (b) | 6 |
| 4 — dApp compatibility inventory | `spikes/04-compat/inventory.md` | 7 |
| — design foundation (not a spike) | `docs/design/figma.md` | 8 |

Rulings recorded during the campaign live in `.superpowers/sdd/2026-08-18-warden-phase0-scaffold-spikes/progress.md`; the ones that bind the spec are carried into §"Consequences" below.

---

## Spike 1 — Squads Smart Account API: **KEEP-OWN-PROGRAM**

Products evaluated: Squads **Smart Account Program** (`SMRTzfY6…`, v0.1.0, the closer architectural match) and Squads **Multisig v4** (`SQDS4ep6…`, no policy/allowlist/sync machinery at all) — `spikes/01-squads/result.md:6-9`.

| # | Criterion (spec §5) | Squads | Evidence (`spikes/01-squads/result.md`) |
|---|---|---|---|
| 1 | Typed signers: Ed25519 **+ secp256r1 passkey** parsed on-chain | **NO** | `:15` — `SmartAccountSigner { key, permissions }`, one Ed25519-shaped field, zero `secp256r1/webauthn/passkey` matches in source; passkeys announced "coming soon"/devnet only |
| 2 | Per-mint / per-tx / per-period spending limits, pooled across members | **YES** | `:16` — `QuantityConstraints{max_per_period,max_per_use}`, `Period(V2)`, `SpendingLimit.signers: Vec<Pubkey>` with one pooled `remaining_amount` |
| 3 | Rolling 30-day cap | **PARTIAL** | `:17` — `PeriodV2::Monthly`/`Custom(i64)` exists, but reset is a **periodic bucket anchored at `last_reset`**, not a sliding window; not trivially configurable into one |
| 4 | Single-tx execution of an arbitrary CPI for a limited member | **YES** | `:18` — `validate_synchronous_consensus()` + `executeTransactionSync` for a `Policy` consensus account with threshold 1 |
| 5 | Program-id + discriminator allowlist | **YES** | `:19` — `InstructionConstraint{program_id, account_constraints, data_constraints}`; `DataConstraint` at offset 0 with `Equals` == 8-byte Anchor sighash match |
| 6 | Post-state conservation (delegate/close-authority/owner; WSOL canonical) | **PARTIAL** | `:20` — `check_pre_balances`/`evaluate_balance_changes` cover owner/delegate/closed, but **zero `close_authority` matches** and **no WSOL canonicalization** anywhere |
| 7 | Timelock + cancel window; **guardian** cancel | **PARTIAL** | `:21` — `time_lock` + `Proposal::cancel()` exist; **no guardian actor** (0 matches for `guardian`), cancels come from ordinary voting signers |
| 8 | Guardian recovery with delay + root contest | **NO** | `:22` — 0 matches for `guardian|recover` in source or IDL |
| 9 | Freeze semantics (root vs guardian bounds) | **NO** | `:23` — 0 matches for `freeze|pause` in source or IDL |
| 10 | Upgrade authority = timelocked multisig | **UNVERIFIED → treated as NO** | `:24` — programData authority `HT3Jknwuu…` is a System-owned 0-byte account; could not disambiguate keypair vs uninitialised vault PDA (Solscan 403) |
| 11 | Reserved signer kinds (future hash-based/Falcon) | **NO** | `:25` — no kind tag/enum on `SmartAccountSigner` |

**Score 3/11 clear YES (#2, #4, #5), 4/11 counting #3 generously** (`:29`). The mandatory gate — rows 4 **and** 6 both YES — fails on row 6 (`:31`), and the ≥9/11 threshold is nowhere near. **Verdict: `KEEP-OWN-PROGRAM`** (`:35`).

**Borrow list** (`:39-44`, carried into Phase 1 as design references, not dependencies): (1) permissions bitmask `Permission::{Initiate,Vote,Execute}`; (2) the `InstructionConstraint`/`DataConstraint` allowlist model for §5.2's adapter registry; (3) the `TimeConstraints`/`QuantityConstraints`/`UsageState` split for caps — **with a true rolling window**, unlike Squads' bucket reset; (4) the `evaluate_balance_changes` pre/post skeleton — **plus** the two gaps Squads has (`close_authority` immutability, WSOL canonicalization), both of which Warden's §5.2 already specifies; (5) the two-tier `Settings`-vs-`Policy` consensus split; (6) the timelock + threshold-cancel pattern, **plus** a distinct guardian actor.

**Residual doubt:** row 10 is genuinely unverified rather than a confident NO (`:56`). It does not move the verdict — rows 1, 6, 8, 9, 11 alone decide it.

---

## Spike 2a — WebAuthn ES256 + PRF from an MV3 extension origin: **PASS (virtual authenticator only)**

- **ES256 create/get from a real `chrome-extension://` origin works.** `navigator.credentials.create()/.get()` round-trip against a CDP virtual authenticator, origin `chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi`, `getPublicKeyAlgorithm() === -7` asserted, 91-B SPKI DER pubkey — `spikes/02-webauthn/result.md:7-22`.
- **PRF returned — virtual only.** `WebAuthn.addVirtualAuthenticator` accepted `hasPrf:true`; `prf.enabled === true` on create and `prf.results.first` (32 B) present on get, asserted (not merely logged) — `:23-27`, `:79-98`. The file states plainly that this is **not** evidence a real platform authenticator (Touch ID / Windows Hello / GPM-synced passkey) supports PRF from an extension origin — `:27-32`. Owner checklist to close it: `:183-202`.
- **Extension-id discovery needed a background service worker.** `ctx.backgroundPages()`/`waitForEvent("serviceworker")` never fire for a manifest with no `background` key; `chrome://extensions` is unreachable under `--headless=new` (`net::ERR_INVALID_URL`); `Extensions.loadUnpacked` is not implemented in Chromium 151. The kept method adds a trivial `background.service_worker` and reads the id off `sw.url()` — deterministic across three runs — `:123-151`.
- **Headless gotcha.** Passing `headless: true` **together with** `--headless=new` in `args` silently breaks extension loading (no error, no service worker). Fix: `headless: false` + `--headless=new` — `:154-164`.
- Chromium under test: Chrome for Testing **151.0.7922.34**; an older pinned Chromium may not reproduce this pass — `:100-108`.

## Spike 2b — on-chain binding of a real assertion: **PASS**, with one spec correction

| Question | Answer | Evidence |
|---|---|---|
| secp256r1 precompile in LiteSVM? | **Yes**, but only with the non-default `precompiles` feature (`litesvm = { version = "0.12", features = ["precompiles"] }`); without it the tx dies `InvalidProgramForExecution` before any log | `spikes/02-webauthn/result.md:266` |
| CU for the full binding | **5,055** of 400,000 (precompile verification is charged as a signature, not to the CU meter) | `:267` |
| Low-S normalization | **Required on the very first real sample** — Chrome's authenticator emitted high-S; un-normalized ⇒ `InstructionError(0, Custom(2))` | `:268`, negative test `:344` |
| Precompile byte layout | Confirmed against `solana-secp256r1-program` 3.0.0: offsets 16 / 49 / 113, all `*_instruction_index == 0xFFFF`; 182 B of ix data for our sample | `:269` |
| **`rpIdHash` preimage** | **SHA-256 of the FULL origin string** `chrome-extension://<id>` — **not** SHA-256(`<id>`) | `:221-242`, hash pair at `:230-232` |
| Minimal root-verify tx size | **788 B** of 1,232 (precompile ix 182 B + our ix 367 B), two accounts, no ALT, **no payload** | `:281-291` |
| Crates | `solana-program`/`solana-sdk` 3.x, `litesvm` 0.12; `solana_program::hash::hash` is SHA-256 (not keccak) | `:266`, `:274` |
| Tests | 21 passing (6 unit + 15 LiteSVM), 8 program-rejection negatives each asserting the exact `InstructionError` **and** the specific log | `:295-330` |

**The rpIdHash correction is the single most consequential Phase-0 finding.** Signed `authenticatorData[0..32]` = `be5c4af7…da34` = `SHA-256("chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi")`; `SHA-256("maikadpaobbjkmaomnpnhjglpabllaoi")` = `68dd094e…f051`, which does **not** match (`:230-232`). A Phase-1 program following the plain reading of the WebAuthn spec — and of spec rev 5 §4's wording "`rpIdHash` == our RP ID hash" — would reject **every** assertion. Both sides are now derived independently (`prep.ts` hashes four candidate preimages and throws if none match; the Rust test recomputes `SHA-256(origin)` and asserts `SHA-256(bare id)` differs) — `:249-260`. Because the id derives from the unpacked path / signing key, this constant differs between dev-loaded and store-published builds and must be **per-build configuration, never a literal** (`:238-242`).

**Not production-safe: the `clientDataJSON` substring matcher** (`:348-394`). The spike checks `"type":"webauthn.get"`, `"challenge":"…"`, `"origin":"…"` by raw byte substring. Six unit tests in `onchain/src/lib.rs::substring_match_holes` **assert the current wrong behaviour** so Phase 1's parser flips them: nested `origin` inside an unknown extension object passes (headline hole), duplicate top-level `origin` passes, `crossOrigin:true` passes unexamined, and a legally escaped `chrome-extension:\/\/…` is falsely rejected (`:363-369`). There is also **no length cap**, so a caller can inflate CU and tx size at will (`:381-383`). The file's binding Phase-1 requirement is a top-level, duplicate-rejecting, escape-aware scanner validating `type`/`challenge`/`origin`/`crossOrigin` with a hard length cap (`:385-394`).

Other carry-forwards: UV is required by the spike program and some synced/cross-device flows return UP-only (`:398-401`); root pubkey and expected rpIdHash **must come from account state, not instruction data** in Phase 1 (`:416-420`); signCount is ignored, so replay protection rests entirely on the challenge bound to on-chain state (`:412-415`).

---

## Spike 3a — wrapped-transaction byte budget

Read the **post-fix** numbers; round 1's "100% inline, 45–47-account ceiling" headline was withdrawn by the spike itself (`spikes/03-txbudget/result.md:241-249`).

| Case | Original | Wrapped | Inline? | Chunks | Accounts | Evidence |
|---|---|---|---|---|---|---|
| Jupiter SOL→USDC run A | 1,085 | **1,235** | **no** (3 B over) | **1** | 43 | `:180` |
| Jupiter SOL→USDC run B | 796 | 934 | yes | 0 | 35 | `:181` |
| Jupiter SOL→USDC run C | 518 | 604 | yes | 0 | 15 | `:182` |
| Jupiter runs D / E (round-2 confirm) | 618 / 682 | 711 / 786 | yes | 0 | 18 / 24 | `:222-223` |
| Marinade `deposit(1 SOL)` | 559 | **702** | yes | 0 | 13 | `:199-201` |
| Tensor buy-now | — | — | — | — | — | **not measured**: every endpoint 403s without `TENSOR_API_KEY` (`:308-320`) |

**Headline: 2 of 3 fresh post-fix Jupiter routes fit inline; 1 needed exactly 1 staged chunk** (`:247-249`). Across all 8 Jupiter measurements accounts ranged 15–43 and the only overflow was the 43-account route; the honest breakpoint statement for this pair/size is **somewhere in the 35–43 account band**, not a validated ceiling (`:251-261`). Staging is therefore **not a rare edge case** — Phase 1/2 must ship `stage_chunk`/staged `execute` fully working, not as an untested fallback (`:277-286`).

Three contract facts fall out of the fixes and bind the spec:

1. **`execute` payload account indices are INSTRUCTION-LOCAL** — index *i* = position *i* in the execute instruction's own key list `[account, sessionKey, ...order]`, because on-chain the handler only ever sees its own instruction's account slice, never the message's global key list. `wrap.ts` now indexes `outerKeys` directly and asserts, after compiling and decompiling, that the resolved key order equals `outerKeys` exactly — a permanent regression guard (`:39-57`).
2. **Compute-budget instructions must be top-level.** `ComputeBudgetProgram` ixs are honored only at the transaction's top level, never inside a CPI, so wrapping them into the payload would silently make them inert. `wrapForExecute` hoists any it finds and adds a default `setComputeUnitLimit(600_000)` when the dApp tx carries none — this is the +40 B that took Marinade from 662 to 702 B (`:418-429`).
3. **The 985-B `stage_chunk` payload cap is PROVISIONAL and stays PROVISIONAL.** It was *measured*, not guessed — `maxStageChunkPayloadBytes()` binary-searches the largest payload keeping a representative `stage_chunk` tx ≤ 1,232 B (`:431-437`) — but the account shape (payer / Stage PDA / System Program) and the 8-byte `[offset:u32, len:u32]` header are an **assumed** layout: spec rev 5 §5.1 fixed only the signer ("any payer") (`:58-65`, `:207-210`). Spec rev 6 §5.1 now fixes the layout, which makes the number deterministically re-measurable — it does **not** retroactively make 985 B correct for that encoding: the measured instruction carried no program discriminator, so the cap under §5.1 is at most ≈977 B. Phase 1 measures it against the built program and records the exact value.

## Spike 3b — conservation snapshot CU

| N vault-owned SPL token accounts | CU consumed |
|---|---|
| 10 | **10,011** |
| 20 | **18,785** |
| 30 | **27,225** |

`spikes/03-txbudget/result.md:697-699`. Two-point fit: base ≈ 1,404 CU, **≈861 CU per additional account** (`:702-704`) — call it ≈900 CU/account for budgeting. N=30 clears the 200,000 CU per-instruction limit with ~7.3× headroom; the mechanism could snapshot ~231 accounts before exhausting one instruction budget, so **the CU cost of conservation is not the binding constraint — the 1,232-B packet limit is** (`:709-714`).

These are the **post-fix** numbers. The pre-fix figures (10→8,688 / 20→16,134 / 30→23,254, ≈728 CU/acct — `:862-868`) came from a check that inspected only the AFTER snapshot, so a pre-existing delegate that got *cleared* during the call passed, and an account that became unparseable was silently skipped (`:625-633`, `:808-810`). The fixed pattern, which is what the spec must require, compares **before vs after, field by field**: runtime owner, token owner, mint, delegate value, `delegated_amount`, `close_authority` value, `state`, `data_len`, TLV-tail hash — and independently requires the AFTER state to satisfy policy (Initialized, delegate None, close_authority None) — `:648-653`. COption tags are decoded **strictly** (`0`/`1`/error, not `!= 0`) — `:629`. 12 direct unit tests on the extracted `check_vault_invariants` cover every branch including the two the Critical bug missed (`:762-768`).

**Scope limit — read this before budgeting `execute`.** The spike contains **no CPI**: it deliberately isolates the pure snapshot-and-compare cost, reading each account twice with nothing in between (`:643-646`, `:792-794`). Two things therefore remain unmeasured: (i) the **total** CU of a real `execute` (snapshot + inner CPI + compute-budget instruction), and (ii) the reject-on-mutation branch **end to end** — it cannot be triggered without a CPI to do the mutating, so it is proven by direct unit tests only, with LiteSVM covering just the ownership filter (`:756-771`). Phase 1 must re-measure `execute` end to end against a real CPI before the writable-account cap is treated as final.

Token-2022: one 265-B account with a 100-B TLV tail costs **11,147 CU** vs the 10,011 CU 10-SPL baseline, i.e. ≈1,136 CU for the extra account including hashing the tail twice (`:718-722`). **keccak and SHA-256 are CU-identical at this size** (11,147 both, on genuinely different `.so` builds) — Phase 1 may pick on other grounds; keccak stays the default (`:724-743`).

Deferred: `is_native` is parsed in the layout (`:661`) but **not compared** before/after — ruled not a bypass in the spike (is_native cannot change without close/recreate, which the invariants already block) but Phase 1 compares it too (progress ledger `:49`). Also unflagged: an `amount` *increase* is treated as zero outflow (`:801-804`).

---

## Spike 4 — dApp compatibility inventory

**16 firm + 4 provisional = 20** (`spikes/04-compat/inventory.md:267`).

| Verdict | Count | dApps | Evidence |
|---|---|---|---|
| **OK** | 9 | Jupiter, Raydium, Orca, Meteora, Kamino, Marinade, Drift (core flow), Phoenix, marginfi | `:248` |
| **root-only** | 6 | Tensor, Sanctum, Parcl, Helium, Realms (voting), Squads | `:249` |
| **unsupported** | 1 | Pump.fun | `:250` |
| **provisional** | 4 | Jito (OK), Solend/Save (OK), Magic Eden (unsupported), Photon (unsupported) | `:262-265` |

The four provisional rows are not fixable by more inspection in this environment: the deciding fact (does `signMessage` fire?) sits *after* wallet selection, which needs a real wallet extension to respond (`:267-273`). The top-20 list is honestly labelled "an unranked example list assembled from the task brief" after DappRadar returned 403 and DefiLlama's ranking was not usable, with exactly one substitution (Zeta → Photon) (`:119-128`).

**SIWS-login list** (connect itself is gated behind a wallet signature, ordered by confidence): Pump.fun (firm, Privy), Realms **Hub** (firm, `sign-in-with-solana.tsx` read from source; the core governance-ui voting app is unaffected), Magic Eden (provisional), Photon (provisional) — `:275-290`. **Signed-message subflow** (not a login gate): Drift "Swift" opt-in orders — `:292-297`. These are exactly the flows spec §6 already declares unsupported, so the inventory **confirms** the spec's honest boundary rather than changing it: the SIWS blast radius is 1 firm unsupported dApp + 1 sub-product + 1 opt-in subflow, not the whole top 20.

**Adapter seed list** (`:302-334`): 15 `(program_id, discriminator)` pairs with values, of which only 2 are ground truth — Meteora DLMM `swap` (IDL-embedded) and Pump.fun `buy` (published), each cross-validating a computed value. Jupiter v6 `route`/`sharedAccountsRoute` — the one the spec's §5.2.7 `swap` path pins — is **UNVERIFIED**. Non-Anchor programs (Raydium AMM V4, Phoenix, SPL Stake Pool, spl-governance, Solend/Save) do not have sighash discriminators at all and need per-program tag rules; Solend/Save's `DepositReserveLiquidity` tag was corrected to `4` from source (`:331`). The file's own instruction stands: **Phase 2 re-derives every discriminator programmatically from each program's IDL** (`:339-340`).

---

## Design foundation (Task 8, not a spike)

`docs/design/figma.md` — tokens (colour/type/space/radius collections with Light/Dark modes), components, and screens **06 / 06a / 06b / 06c / 02** exist as real frames. Load-bearing for the spec: the typed first/last-4 confirmation gate is designed and wired (`ConfirmField` above the primary action, primary is `PrimaryDisabled` until matched — `docs/design/figma.md:152-156`), the dust-only/poisoning case gets a **blocking** treatment with an inverted destructive primary (`:164-174`), semantic colours are never used as text and `critical` appears in exactly three places (`:55-72`), and `--w-muted` is ink @ 68 % (`:83`) after the light-mode contrast fix. 9 of 11 screens remain undesigned (`:190-195`) — a Phase-3 input, not a Phase-1 blocker.

---

## Consequences for the spec (rev 5 → rev 6)

Each is a concrete edit; all are applied in `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`.

| # | Section | Edit | Driven by |
|---|---|---|---|
| C1 | §4 | Define `rpIdHash` as **SHA-256(full extension origin string `chrome-extension://<id>`)**, with the matching/non-matching hash pair inline as evidence, and require it to be per-build configuration held in account state — never a literal, never SHA-256(id) | 2b `:221-242` |
| C2 | §4 | **Low-S normalization is mandatory client-side** before every submission (not a later edge case) | 2b `:268` |
| C3 | §4, §5.2 | `clientDataJSON` verification = **strict top-level scanner**, defined exactly: depth-0 keys only; **exactly one** top-level `type`, `challenge` and `origin`; any duplicate top-level key ⇒ reject; `crossOrigin` **absent or `false`** (present-and-true ⇒ reject — the spike requires the field be examined, not that it be present); JSON escapes decoded before comparison, else reject; hard length cap. Substring matching is explicitly forbidden, and the spike's six hole tests must flip | 2b `:348-394` |
| C4 | §5.2 | `execute` payload account indices are **instruction-local**; compute-budget ixs are **top-level only** with a default `setComputeUnitLimit(600_000)`; **cap writable accounts in a session `execute` at 40** — a byte-limit-driven conservative choice, not a CU-driven one (see the justification note below) | 3a `:39-57`, `:180-182`, `:418-429`; 3b `:702-704` |
| C5 | §5.1 | Define the `stage_chunk` account layout explicitly (payer signer, Stage PDA writable, System program; data = discriminator ‖ `offset:u32 LE` ‖ `len:u32 LE` ‖ payload) so the cap becomes **deterministically re-measurable** instead of resting on an assumed shape. **The 985-B figure stays PROVISIONAL** and is not a spec-derived cap: it was measured against a representative tx whose data was header+payload with **no program discriminator**, so the cap for §5.1's encoding is ≈8 B lower (≤ 977 B). Phase 1 measures the real number against the built program | 3a `:58-65`, `:431-437` |
| C6 | §5.2.2 | Conservation = **before/after field-by-field** compare over the named field list **including `is_native`**, with strict COption decoding; the §5.2.2 "UNVERIFIED" tag is replaced by the measured numbers | 3b `:648-653`, progress `:49` |
| C7 | §6 | Root-verify tx budget note: 788 B baseline with **no payload** ⇒ root instructions carry ≤ ~400 B of payload or use the staged path | 2b `:281-291` |
| C8 | §6 | The extension needs a background service worker anyway under MV3 (it is also how the extension id is discovered); RP ID = extension id, `rpIdHash` = SHA-256(origin) — stated so the two are never conflated | 2a `:123-151`; 2b `:272` |
| C9 | §5.2.1 / §12.4 | Adapter registry discriminators are **UNVERIFIED seeds**, re-derived from IDLs in Phase 2; non-Anchor programs need per-program tag rules | 4 `:302-340` |
| C10 | §12 | A "Result:" line under each of the four spikes, recording verdict + the numbers that now constrain Phase 1 | all |
| C11 | §5 (no change) | Squads is **not** adopted; the six borrowed patterns are design references only. Spec §5.5's use of a Squads multisig as the *upgrade authority* is unaffected — that is Squads v4 as a governance tool, not as the vault | 1 `:35` |

**Justification note for C4's cap of 40.** What is measured is the *snapshot* cost: ≈900 CU/account over a ≈1,400 CU base, so 40 accounts ≈ 37k CU of snapshot work (3b `:697-704`). What is **not** measured is the inner CPI's own CU, because spike 3b contains no CPI at all (`:643-646`, `:792-794`) — so "37k CU fits in the 200k limit" is a statement about the snapshot alone, not about a whole `execute`. The cap is therefore chosen off the **byte** budget, which is the constraint that actually bit: a real 43-account Jupiter route serialized to 1,235 B against a 1,232-B limit, and a 35-account route fit (3a `:180-182`). 40 sits just below the observed 35–43 breakpoint band. Phase 1 must measure a full `execute` — snapshot + real CPI + compute-budget instruction — and lower the cap if the combined CU, not the bytes, turns out to bind first.

Deliberately **not** changed: §6's unsupported-flows list (spike 4 confirms it), §5.2.7's swap conservation rules (unaffected by any measurement), and §5.4's loosening lattice.

---

## Phase 1 GO / NO-GO

**GO** — build `programs/warden` as our own program.

The two questions that could have killed the design are both answered affirmatively with executable evidence:

1. **Can a passkey be the on-chain root?** Yes. A real assertion from a real `chrome-extension://` origin was bound on-chain through the secp256r1 precompile + Instructions-sysvar introspection for **5,055 CU**, with eight negative tests proving each check bites (2b `:214-219`, `:267`, `:310-323`). The two things that would have silently broken it — the rpIdHash preimage and high-S signatures — were both found *now*, in Phase 0, rather than in Phase 1 debugging.
2. **Does the wrap-into-`execute` model fit real dApp traffic?** Yes, with staging as a first-class path, not a fallback: real Jupiter routes land at 604–1,235 B against a 1,232-B limit, and the conservation mechanism costs ~900 CU/account against a 200,000 CU budget (3a `:180-182`; 3b `:697-699`).

Squads cannot host the vault (3–4/11, and the mandatory row-4-**and**-6 gate fails), so there is no cheaper path (1 `:29-35`).

Phase 1 entry conditions, all met: root `cargo metadata` resolves (this document's workspace fix), the spec is at rev 6 with every measured constraint written into it, and the design foundation covers the screens Phase 1's flows surface.

**What GO does and does not mean.** It means Phase 1 may build `programs/warden` — the architecture is validated, not the implementation numbers. Three things Phase 0 did **not** establish, all of which Phase 1 must close by measurement rather than inherit as settled:

- **No end-to-end `execute` exists yet.** Spike 3b has no CPI, so the reject-on-mutation branch was proven by unit tests only and the *total* CU of a real `execute` is unmeasured (3b `:643-646`, `:756-771`). The 40-account cap is a byte-driven conservative bound, not a CU-validated one.
- **`is_native` was never measured**, only specified — it was deferred out of the spike and added to §5.2 by ruling (progress `:49`).
- **UV vs UP-only synced passkeys is undecided** (2b `:398-401`); some synced/cross-device flows return UP-only assertions and the spike program requires UV.

**Nothing open below is a Phase-1 blocker.** Real-device PRF gates only the *keyring unlock* path, for which spec §4 already mandates an Argon2id password fallback; Tensor gates only a compat data point; the stage cap and discriminators are Phase-1/2 refinements of numbers the spec now records as provisional.

---

## Open items carried out of Phase 0

| # | Item | Status | Owner / gate |
|---|---|---|---|
| O1 | **Real-device PRF** (Touch ID / Windows Hello / GPM-synced) from an extension origin | **UNVERIFIED** — virtual authenticator only (2a `:27-32`) | Owner runs the manual checklist at 2a `:183-202`. Until then **Argon2id fallback stays mandatory in v1** — this is a spec §4 requirement, not a nice-to-have |
| O2 | **Tensor** wrapped-tx byte measurement | **not measured** — API 403 without `TENSOR_API_KEY` (3a `:308-320`) | Phase 2, or drop: two measured dApp shapes (Jupiter, Marinade) already bracket the budget |
| O3 | **985-B `stage_chunk` payload cap** | **PROVISIONAL** — assumed account layout (3a `:58-65`) | Phase 1 re-measures against the real instruction; spec §5.1 now fixes the layout so the re-measure is a confirmation, not a redesign |
| O4 | **Anchor discriminators** for the adapter registry | mostly **UNVERIFIED**; only Meteora `swap` and Pump.fun `buy` are ground truth; **Jupiter v6 `route` unverified** (4 `:310`, `:335-340`) | Phase 2 derives them from IDLs programmatically. Jupiter's is needed by §5.2.7 and should be first |
| O5 | **`is_native` before/after compare** | deferred out of the spike, therefore **never measured** (progress `:49`); now **required by spec §5.2** | Phase 1 implementation; re-measure per-account CU with it included |
| O6 | **`clientDataJSON` strict scanner** + the six hole tests that currently assert the wrong behaviour | required, specified (2b `:385-394`) | Phase 1 — the tests must flip to asserting rejection |
| O7 | **Squads row 10** (Squads' own upgrade authority) | UNVERIFIED (1 `:56`) | Informational only; does not affect the verdict or §5.5 |
| O8 | **result.md bloat** — `spikes/03-txbudget/result.md` is an 874-line round-by-round changelog (progress `:55`); `spikes/02-webauthn/result.md` is 467 | cosmetic | Trim to the post-fix findings once Phase 1 no longer needs the fix history; this document is the durable summary |
| O9 | **9 of 11 screens undesigned**, plus full-page variants and the §12.4 compat surface (`docs/design/figma.md:190-195`) | expected | Phase 3 |
| O10 | **UV requirement vs UP-only synced passkeys** (2b `:398-401`) | decision owed | Phase 1: recommended UV mandatory for root, configurable below |
| O11 | **End-to-end `execute` CU** (snapshot + real inner CPI + compute-budget ix) and the **reject-on-mutation branch exercised through a CPI** | not measured — spike 3b deliberately has no CPI (3b `:643-646`, `:756-771`) | Phase 1, before the 40-writable-account cap in §5.2 is treated as final |

---

## Codex review

Reviewer: `mcp__codex__codex`, `gpt-5.6-terra` @ `high`, `approval-policy: on-request`, read-only, no subagents, `cwd: /opt/warden`.

**Round 1 — thread `01a014fc-8a50-7fc0-895c-57f362e6b229`: NO-GO.** Per-spike verdicts confirmed as supported by the cited evidence (and spike 2 correctly limited to virtual-authenticator evidence; the full-origin `rpIdHash` claim confirmed as independently derived, valid for the tested Chrome environment). Three gaps named:

1. **C4** — the 40-writable cap is a reasonable conservative policy choice, but its "comfortable … even with inner CPI" justification was **unmeasured**: spike 3b isolates snapshot cost and contains no CPI.
2. **C5** — wrongly upgraded 985 B to "spec-derived". The evidence says the layout was assumed and must be re-measured; the measured instruction also carried no program discriminator, so 985 cannot be claimed for §5.1's encoding.
3. **C3** — overstated the evidence as requiring exactly one `crossOrigin` key, where the spike requires the field be *validated* and spec §4 makes it optional-if-present.
Plus: the GO rationale downplayed that the conservation mutation path was never exercised end-to-end with a CPI, that `is_native` was not measured, and that UV-vs-UP-only remains undecided.

**Fixes applied** (all three, plus the GO caveats): C4's justification re-grounded on the packet boundary with an explicit Phase-1 end-to-end measurement requirement (here and spec §5.2); C5 restored to PROVISIONAL with the ≤ ~977 B discriminator-bearing bound (here and spec §5.1); C3 reworded to match spec §4; a "What GO does and does not mean" block and open item **O11** added.

**Round 2 — thread `01a014ff-ca58-7003-b2fa-1102f5697ec3`: GO.** "All three named gaps are now correctly closed… The added GO caveats and O11 accurately preserve the remaining unknowns. I found no material new overclaim introduced by these fixes."

**Gate result: GO for Phase 1.**
