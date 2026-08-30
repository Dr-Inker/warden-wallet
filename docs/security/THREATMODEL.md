# Warden — threat model (append-only, SHA-stamped)

Seeded from **spec §2**. This file is the **L5 artefact**: per milestone, append what changed in the
trust surface, SHA-stamped, and sign it off **before** merge. Append only — never rewrite a past
entry; if an earlier entry was wrong, append a correction that says so.

The point of this file is not to restate the spec. It is to answer, at every milestone, one question:
**what can now reach the user's funds that could not reach them before?**

## Baseline (spec §2, rev 8)

| # | Threat | v1 answer | Ledger rows that carry it |
|---|---|---|---|
| T1 | User is talked into approving a draining transaction (fake dApp, deepfake support, poisoned address) | Session key bounded by per-tx and account-wide day caps per mint; larger outflows — **including by the root** — go through a timelock with a cancel window and notifications | `WRD-CAP-01`, `WRD-CAP-05`, `WRD-CAP-07`, `WRD-EXEC-10` |
| T2 | Seed phrase scraped | No seed phrase exists in the default path; the recovery code unlocks a *guardian* key, which cannot move funds and is itself subject to the recovery delay | 1C (`WRD-GRD-*`) |
| T3 | Malicious or updated extension | Root is a non-exportable P-256 passkey verified on-chain; the extension never holds root secret material. A malicious extension can spend the session caps and can *ask* for a passkey ceremony — that action is still timelocked and visible on the notifier. **Explicitly not defended:** a malicious extension that lies about intent to a user with no second channel | `WRD-ROOT-03`, `WRD-ROOT-05`, `WRD-ROOT-06`, `WRD-CAP-05`; L7 event emission |
| T4 | Device or passkey lost | Guardian recovery (threshold, delayed, root-contestable) or the recovery-key path (also delayed) | 1C (`WRD-GRD-*`, `WRD-TL-*`), `WRD-ROOT-08` |
| T5 | AI agent or bot with wallet access is prompt-injected | Agents get their own session key with tiny caps | `WRD-CAP-01`, `WRD-CAP-04`, `WRD-CAP-08` |
| T6 | Bug in our program | Small typed surface, adversarial + property tests, external audit and bug bounty **before any real funds**, per-account `frozen`, upgrade path with a 7-day lock and an exit window | The whole ledger; `WRD-FRZ-01`..`-03` |
| T7 | Synced-passkey extraction / assertion forgery from a compromised endpoint | Three 2026 disclosures (SpecterOps Entra passkey-registration replay, Unit 42's recovery of the Chrome Security Domain Secret, a Windows Hello session hijack) mean a compromised endpoint can produce assertions without a fresh biometric. `userVerification: required` raises the bar but **does not eliminate the class** — UV is asserted by the authenticator, and a hijacked authenticator session asserts it too. The answer is defence in depth: account-wide day/30-day buckets bound what a forged ceremony extracts, a timelock plus notifier makes anything larger visible and cancellable, guardians can freeze | `WRD-ROOT-03`, `WRD-CAP-05`, `WRD-CAP-02`, `WRD-FRZ-01` |
| — | Quantum signature forgery | Out of scope. Preserved: the asset holder is a PDA and root/guardian kinds are typed, so a hash-based/Falcon kind is additive | — |
| — | Compromised OS / keylogger with an unlocked session | Bounded by caps only | `WRD-CAP-*` |
| — | Lying RPC | Cannot sign; can hide state. The intent view cross-checks simulation against the local pre-check and flags disagreement; user-selectable RPC | L9 client lane |

**Open owner decision carried into 1C (T7):** whether a *synced* (multi-device, cloud-backed) passkey
may be a root at all, or whether roots must be device-bound (`authenticatorAttachment: "platform"`,
no cloud-backup flag) with synced credentials permitted only as guardians. Detecting a *cloned*
credential via the WebAuthn sign counter is explicitly rejected: synced authenticators return 0 or a
non-monotonic counter, and LazorKit and Swig both ignore it.

**Standing 1A exposure until `WRD-ROOT-01` lands:** `create_account` is unauthenticated and
`owner_seed` is visible in flight, so a malicious RPC or leader can front-run the PDA and install its
own root at the client-chosen address — squatting and DoS, and theft if funds are sent before a
successful root round-trip (`TOB-SQUADS-7`). The mitigation until then is procedural: **the extension
MUST complete a `rotate_nonce` ceremony and verify the on-chain root equals its passkey BEFORE showing
a receive address or funding anything.** Proof of possession at create is a hard pre-deployment gate.

---

## Milestone deltas

_Append one section per milestone. Template:_

```
## <milestone> — <sha> — <date> — signed off by <who>
**New trust surface:** what an attacker can now reach that they could not before.
**Removed / narrowed:** what closed.
**New invariants:** WRD-…-NN (status at merge).
**Residual, stated honestly:** what is still open and why it was accepted.
```

## Phase 1B / Task 10 (assurance scaffold) — 208f7d5 — 2026-08-19 — pending sign-off

**New trust surface:** none. This milestone adds documentation, a JSON Schema, a review wrapper and a
TypeScript test; it changes no on-chain code and no client code path.

**Removed / narrowed:** nothing on-chain. What narrows is *reviewer* scope: every subsequent review is
seeded with named invariants, the prior-art corpus and the cross-cutting sibling files, and silence on
a seeded invariant is now a FAIL rather than an implicit pass.

**New invariants:** 43 rows seeded — 23 `test-covered` (Phase 1A surfaces), 19 `unimplemented` (1B/1C
surfaces), 1 `llm-asserted` (`WRD-ROOT-10`, held down deliberately because the Rust and TS golden
vectors are hand-synced with no mechanical cross-language gate). **Nothing seeded at `holds`.**

**Residual, stated honestly:** the ledger records what the spec claims and what the 1A tests cover. It
does not verify that the tests are adequate — that is L4 (mutation testing, unpiloted on this
workspace) — and it does not verify that the harness runs real cryptography — that is L0
(`tests/sigverify_wiring.rs`, not yet landed). Every `test-covered` row inherits both caveats.

---

_The four deltas below are **retrospective**: their milestones landed 2026-08-19 but their entries
were only appended 2026-08-20 by the A0 assurance-repair task (campaign plan 2026-08-20, gap G1).
The dates and SHAs are the milestones' real ones; the recording lag is the dishonesty being
corrected, not repeated. — recorded by A0, pending owner sign-off._

## Phase 1B / Task 0 (L0 gate + slot freshness) — 26a8c1e, fix 050809e — 2026-08-19 — retrospective (A0), pending sign-off

**New trust surface:** none. `RootArgs` gains `signed_slot` (a breaking ABI change, 1A args no longer
decode) and root instructions are rejected when invoked via CPI (top-level only).

**Removed / narrowed:** the root replay window shrank from a 600 s wall-clock `expiry_ts` alone to
`signed_slot ≤ current_slot < signed_slot + 150` **and** the wall-clock deadline — both clocks are
independent bounds. `tests/sigverify_wiring.rs` now proves the harness runs real secp256r1 in both
directions (valid ⇒ accept, forged ⇒ `PrecompileError::InvalidSignature`), closing the silent-feature-
regression hole; `litesvm` is pinned `=0.12.0`.

**New invariants:** `WRD-NONCE-03` (test-covered), sigverify wiring rows per the ledger.

**Residual, stated honestly:** slot freshness trusts `Clock::slot`; a colluding leader can still land
a captured assertion within 150 slots. The window bounds exposure; it does not eliminate replay-by-
the-leader inside the window. The review round for this task is in REVIEW-RUNS.jsonl as
`baseline-not-recorded` — its thread id was not retained.

## Phase 1B / Task 1 (conservation module) — f0f38ca, fixes 2023902 + d394b74 — 2026-08-19 — retrospective (A0), pending sign-off

**New trust surface:** none yet. The `conservation` module (snapshot / compare / accounting, ~97 unit
tests) compiles into the program but no shipped instruction calls it — `execute` lands in Task 5.
Nothing an attacker can reach changed.

**Removed / narrowed:** nothing at runtime. What the round-1/round-2 fixes narrowed is the module's
own future fail-open surface before it ever went live: vault-controlled mint pre-scan, AFTER-driven
classification (`NewVaultAccountRejected`), duplicate-pubkey rejection, non-native lamport freeze,
fail-closed token-account TLV walks, close-path lamport checks.

**New invariants:** `WRD-CONS-01`..`WRD-CONS-06` (unit layer, test-covered — added to the ledger by
A0, 2026-08-20; the end-to-end `WRD-EXEC-*` rows correctly stay `unimplemented` until Task 5).

**Residual, stated honestly:** unit tests exercise the comparison functions on synthetic snapshots;
no CPI has ever run against this module. The intra-CPI round-trip blind spot is a permanent spec
boundary (§5.3), not a residual to fix.

## Phase 1B / Task 2b (root-bound address + proof-of-possession) — 50dc590 — 2026-08-19 — retrospective (A0), pending sign-off

**CORRECTION — supersedes the "Standing 1A exposure until `WRD-ROOT-01` lands" paragraph in the
baseline above.** That exposure is closed: `create_account` now derives the PDA seed on-chain as
`Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt32)` and verifies a root ceremony over the derived
address before initialization, consuming the creating assertion (the account starts at nonce 1). A
squatter cannot produce the assertion, and a different root derives a different address. The baseline
paragraph stays in place because this file is append-only; it describes history, not the present.

**New trust surface:** none — creation became *harder* to reach, not easier.

**Removed / narrowed:** front-run PDA squatting (`TOB-SQUADS-7` class), theft-if-funded-before-
readback, and the procedural `rotate_nonce`-before-funding mitigation is no longer the only defence
(the extension still performs readback as belt-and-braces). `MAX_MINTS_AT_CREATE` dropped 4 → 1 for
packet budget.

**New invariants:** `WRD-ROOT-01` (test-covered, CLOSED), plus the Task 2b rows per the ledger.

**Residual, stated honestly:** the creation ceremony binds origin and cluster_tag as signed by the
client; a compromised client that signs for the wrong cluster still creates a valid account there.
The review round's thread id was not retained (REVIEW-RUNS.jsonl, `baseline-not-recorded`).

## Phase 1B / Task 11 (L9 repo-side gates) — b320ecd, fixes d8e3f54 + 56c543b + d0072fd — 2026-08-19 — retrospective (A0), pending sign-off — **PARTIAL**

**New trust surface:** none on-chain. New *process* surface: CI (`.github/workflows/ci.yml`),
cargo-deny, a fail-closed supply-chain gate, release-integrity documentation, and a deployment-gate
**specification**.

**Removed / narrowed:** dependency drift (lockfile + cargo-deny + scoped audit fail closed), silent
CI toolchain drift (pinned), unattributed third-party code (notices provenance committed).

**Honest status:** `docs/security/DEPLOY-GATE.md:12` records "SPEC + partial dry-run implementation" —
the RPC-dependent checks (ProgramData upgrade-authority assertion, multisig threshold/timelock
readback) are **NOT IMPLEMENTED**. Task 11 is therefore **partial**; Task 11R (campaign plan G11) owns
the non-dry-run implementation with deterministic fixtures before Task 9, and live-chain verification
stays UNVERIFIED until a release candidate exists.

**New invariants:** supply-chain/release rows per the ledger.

**Residual, stated honestly:** three review rounds for this task ran with no retained thread ids
(REVIEW-RUNS.jsonl). The deployment gate can currently be *read* but not *run* against a cluster.

## Phase 1B / C0+V0 seeding (client + vanity threat surface) — 2026-08-20 — seeded, unimplemented

_These rows are the threat surface the client-security (C0/C1a/C2a/C4b) and vanity (V0) invariants
defend. They are seeded now, at honest `unimplemented` status, so every future review of that code is
armed — no `apps/extension` or vanity worker exists yet. Carried by the campaign plan 2026-08-20._

**Client / extension (C0, C1a, C2a, C4b):**

| # | Threat | v1 answer | Ledger rows |
|---|---|---|---|
| C-1 | Compromised dApp page forges origin/account/approval to a privileged method | Privileged background methods derive origin/id/tab/frame from browser-owned sender metadata only; page-supplied context is stripped | `WRD-EXT-01`, `WRD-EXT-02` |
| C-2 | Malicious iframe / cross-frame request | Same browser-owned provenance; the request is bound to its originating port/tab/frame and cancelled on navigation | `WRD-EXT-01`, `WRD-APR-01` |
| C-3 | Service-worker (MV3) suspension drops or races unlock state | Absolute wall-clock idle/hard deadlines checked on every key use and after every wake; expiry clears session material; alarms are a wake aid, not the authority | `WRD-KEY-03` |
| C-4 | Approval UI race — approve twice / resolve the wrong request | One atomic winner; single-use immutable approval record; signer rechecks the digest immediately before signing | `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03` |
| C-5 | Poisoned simulator/reputation response shows a false "safe" | Simulation bound to digest/account/cluster/freshness; advisory only; can neither authorize a denied action nor bypass policy | `WRD-SIM-01`, `WRD-SIM-02` |
| C-6 | Sandwiched / stale / shared-upstream swap quote | Quote provenance recorded; stale re-quotes, >3% divergence blocks unoverridably, shared-upstream renders as no independent check | `WRD-QTE-01` |
| C-7 | Dependency / build compromise ships a malicious payload (Trust Wallet / Shai-Hulud class) | Byte-reproducible payload from two isolated builders; published store payload compared to the approved artifact; lockfile pinning + provenance | `WRD-REL-01`, `WRD-REL-02` |
| C-8 | Publisher-account takeover (leaked CWS credential) | Least-privilege, phishing-resistant, two-person publisher authority; no long-lived publishing secret in CI | `WRD-REL-03` |
| C-9 | Build-ID change strands an account, or a dev account becomes a funded production account | Stored-origin mismatch fails closed; dev build cannot create a funded mainnet account; production id frozen or authenticated 1C migration | `WRD-ORG-01` |
| C-10 | High-S browser assertion silently bricks every root ceremony, or a malformed DER is mis-parsed | Strict DER parse + mandatory low-S normalization before submission; recorded real high-S sample proven end to end | `WRD-SIG-01` |
| C-11 | Key export / recovery reveal without fresh authentication | Any reveal/export needs a fresh ceremony; root/session secrets never exportable; recovery envelope keeps 128-bit strength + contextual AAD | `WRD-EXP-01`, `WRD-KEY-01`, `WRD-KEY-02`, `WRD-KEY-04` |

**Vanity address feature (V0):**

| # | Threat | v1 answer | Ledger rows |
|---|---|---|---|
| V-1 | Malicious worker/binary returns a private key or a salt for an attacker-controlled address | The worker returns only salt/owner-seed/address/bump metadata; the trusted client independently re-derives; a static+runtime test rejects secret-shaped fields | `WRD-VAN-01`, `WRD-VAN-04` |
| V-2 | Stale program config / frozen-target drift makes the searched address wrong | Program id, cluster/config, account seed, and seed-domain version are frozen before any long search; the create ceremony re-binds them | `WRD-VAN-03` |
| V-3 | Overlapping worker ranges / reused job nonce / counter wrap corrupts the search | Disjoint nonce/counter search; stale jobs discarded by job id + config digest; boundary/property tests | `WRD-VAN-02` |
| V-4 | Predictable salt nonce or CSPRNG failure narrows the keyspace | Salt is a full 32-byte CSPRNG value; a CSPRNG exception aborts rather than degrades | `WRD-VAN-01` |
| V-5 | CPU/battery denial of service from an unbounded search | Cancellation bounded by a tested maximum batch duration; calibrated 50%/95% probability windows, not a fake countdown | `WRD-VAN-02` |
| V-6 | Server-side metadata linkage deanonymizes the wallet | v1 generation is local, bundled, and emits no wallet-linkable telemetry | `WRD-VAN-04` |
| V-7 | Vanity treated as identity / address poisoning | Vanity is cosmetic, never identity; full-address comparison, saved-contact provenance, and the poisoning controls ship with it (see the UI research binding correction) | `WRD-VAN-03` |

### C0+V0 seeding corrections (append-only, same tranche) — 2026-08-20

Two rows in the C0+V0 seeding block above are wrong as written; per this file's
append-only rule they are corrected here, not rewritten in place.

- **C-11 overclaims (WRDF-0024).** "root/session secrets never exportable" is the
  broad claim removed from `WRD-KEY-01`/`WRD-EXP-01` in round 3. The correct,
  enforceable statement: **Warden exposes no root/session export API and root
  material never enters extension memory; a recovery-secret reveal/export requires
  a fresh ceremony.** A backup-eligible *synced* passkey remains movable by the
  platform (WebAuthn L3 / FIDO) — that is threat **T7**, outside Warden's
  enforcement, not a Warden guarantee.
- **V-4 salt construction (WRDF-0025).** "Salt is a full 32-byte CSPRNG value" is
  wrong: the authoritative construction (vanity plan §V2) is
  `salt32 = job_nonce24 ‖ counter64_le` — a **192-bit CSPRNG job nonce** plus a
  disjoint `u64` counter so parallel workers have non-overlapping lanes. The
  correct answer: the 192-bit nonce is CSPRNG; a CSPRNG failure, a reused job
  nonce, and a counter wrap each reject (`WRD-VAN-01`/`WRD-VAN-02`). The final
  eight bytes are deterministic by design and are not a keyspace weakness.

### Deployment trust-root assumption (WRDF-0017) — 2026-08-20

The deployment gate (`WRD-DEP-01`, Task 11R) authenticates Warden's ProgramData
and the Squads multisig identity/governance/config-authority, and pins the
**audited Squads program code hash**. Beyond that, **Squads' own upgrade
governance is an accepted external trust assumption** — this gate does not, and
cannot, recurse indefinitely into the governance of every dependency. The
concrete anchor is the pinned audited Squads code hash; if Squads ships new code,
the gate fails closed until the new hash is reviewed and re-pinned. This is the
documented terminus of the on-chain deployment trust root.

---

## GROK exploit-audit remediation (EXP-01..07) — deb16e4 — 2026-08-22 — pending sign-off

Independent third-model adversarial pass (`docs/security/GROK-EXPLOIT-AUDIT-2026-08-22.md`)
against BASE `9a427aa`. Seven findings triaged; six reproducible/confirmed, patched with
red-at-BASE regressions (details: `docs/program/PHASE1B-MEASUREMENTS.md` §"GROK exploit-audit
remediation").

**New trust surface:** none — every change is a fail-closed narrowing. No new instruction,
account, or authority path is reachable.

**Removed / narrowed:**
- Root `execute` / nested-hop **issuance and freeze control**: `MintTo`/`MintToChecked`/
  `FreezeAccount`/`ThawAccount` are now on the fixed deny-list (both paths, above the registry),
  and conservation compares `supply` byte-for-byte for any mint the vault controls — so a
  `MintTo` under a vault-held `mint_authority`, direct or nested inside a Jupiter hop, is now
  rejected instead of being unmetered (EXP-02).
- **Stake / Vote / BPF-upgradeable-loader value**: any *writable* remaining account owned by one
  of these is rejected pre-CPI and in `compare_and_account`, closing the "read-only PDA signer
  authorizes `Stake::Withdraw` with no cap debit" path on both `execute` and `swap` (EXP-03).
- **Session `swap` reach into Jupiter hops**: the session path now refuses the `route` variant
  (which forwards the vault PDA signer to every AMM hop), accepting only `shared_accounts_route`
  (Jupiter signs hops with its own programAuthority); root keeps both, byte-bound by
  `route_hash` + `accounts_hash`. Optional `route[4]` destination is pinned when writable (EXP-05).
- **Swap protocol fee**: the treasury-fee check is now the realized 85 bps *rate*
  (`fee_delta ≥ floor(base×85/10000)`), not "any positive delta" — a 0-bps route paying 1 base
  unit is rejected (EXP-01).
- **Empty `execute` payload** is rejected before the registry/stage gate, closing the list-id-0
  stage-GC / auth-shape hole (EXP-04).
- **Reincarnation (direct)**: ATA `Create`/`CreateIdempotent` and SPL/T22 `InitializeAccount*`
  whose target was a vault token account in the BEFORE snapshot are deny-listed (EXP-06).

**New invariants:** none seeded here; no `invariants.jsonl` status was promoted (B4 stays deferred
per the 2026-08-22 reassessment). The ABI grew by one error only — `SwapRouteVariantSessionDenied`
(6075); the pinned drift table went 75→76.

**Residual, stated honestly:**
- **EXP-06 nested-both-halves** (a close AND a same-pubkey recreate inside ONE middleman CPI) is
  invisible to any before/after comparison and is **not** closed. Fund-flow analysis: rule-8
  (non-native lamports unchanged), native metering, and the PDA-credit floor mean the *vault*
  cannot net-lose lamports this way — only the fee payer's own rent can fund a replacement, and a
  compromised signer can already spend its own SOL. Recorded as an accepted §5.3-class residual.
- **EXP-01 is the realized-fee floor, not the byte-exact `route_plan` parse** (WRDF-0031/0059),
  which remains owed before mainnet.
- **Assurance-lane gap:** the canonical Codex `sol@max` review of this range could not be recorded
  — both `scripts/review.sh` and the `mcp__codex__codex` lane hit OpenAI's cyber content-filter
  false-positive on the security diff (documented class; not a convergence signal for real product
  code). A recorded adversarial round over `9a427aa..deb16e4` is **owed** before this milestone is
  signed off. Interim assurance = author self-review + 17 red-at-BASE regressions + full gate green.

---

## Client C1 provider-request schema — 16663cb — 2026-08-30 — **PARTIAL**

**New trust surface:** none in the emitted extension. The pure parser is not imported by
`main.ts`, and the built worker contains no parser symbol or provider listener.

**Removed / narrowed:** the future page-controlled request language now has one closed,
size-bounded JSON form. Page-supplied origin/tab/frame/approval/policy fields, unknown methods,
ambiguous options, non-dense byte arrays, unsupported chains, and malformed envelopes reject.
Only connect, disconnect, sign-transaction, and sign-and-send-transaction syntax survives; parsed
transactions and options are copied and frozen. The design no longer advertises `signMessage` or
`signIn`, because a session-key Ed25519 signature cannot verify as the advertised SmartAccount PDA.

**New invariants:** none promoted. `WRD-EXT-01` and `WRD-EXT-02` remain `unimplemented`.

**Residual, stated honestly:** there is no provider/content script, response schema, live Port,
runtime routing, authorized-account lookup, approval owner, cancellation, or privileged method.
The account address is only a bounded Base58 selector until a future background-owned account
record resolves it. The page correlation id is not a security id and has no uniqueness guarantee;
the future owner must mint an independent request id and reject duplicate in-flight correlations.
The local 16 KiB ceiling has not been compatibility-measured. Independent second-model review is
UNVERIFIED.
