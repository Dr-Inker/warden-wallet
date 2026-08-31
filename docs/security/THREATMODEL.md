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

---

## Client C1 zero-privilege provider Port owner — 2975296 — 2026-08-30 — **PARTIAL**

**New trust surface:** the emitted MV3 worker now installs one named `runtime.onConnect` listener
after trusted-only storage restriction and session restoration. It accepts only provider-shaped,
extension-owned web-frame sender provenance and the closed provider-request schema, then returns a
fixed `WARDEN_METHOD_UNAVAILABLE` response. The current manifest has no content script, page provider,
UI page, host permission, external connection, or web-accessible resource, so no webpage can yet
reach it. The listener has no account, approval, RPC, key, signing, decrypt, export, or dispatch
capability.

**Removed / narrowed:** every accepted request is owned by the exact browser-derived
extension/document/origin/tab/frame tuple and an independent 128-bit Web Crypto id which is never
echoed to the page. Page correlations are unique only while pending and are never authority.
Requests and provenance are copied/frozen; settlement requires the exact lease object. Per-Port
pending/total limits, a global active-Port limit, one owner per `documentId`, absolute-time rechecks
plus a best-effort expiry timer, and synchronous abort on disconnect/malformed input/account
change/disposal bound memory and stale authority. Invalid channels, senders, and messages close the
Port. A browser-safe `@warden/core/constants` export prevents the parser's first live bundle from
importing Node-only `node:fs`/`node:url` code.

**New invariants:** none promoted. `WRD-EXT-01` and `WRD-EXT-02` remain `unimplemented`.

**Residual, stated honestly:** there is no content-script/page bridge, Wallet Standard adapter,
privileged UI Port, authorized account or cluster binding, success/event protocol, approval
digest, idempotent sign/send owner, persistent request store, or wallet method. `accountAddress`
is still only an untrusted lexical selector. Account-change cancellation is not wired to account
state. Worker restart discards in-memory work rather than proving recovery semantics. Unit mocks
prove local Port teardown and document-slot reuse, but actual Chromium navigation/disconnect and
content-script sender shapes remain UNVERIFIED. TTL and cap values are local, compatibility-
unmeasured choices. Independent second-model review remains UNVERIFIED.

---

## Client C1 MV3 wake-listener correction — 26f3904 — 2026-08-30 — **PARTIAL**

**New trust surface:** none beyond the existing zero-privilege provider listener. Its registration
moves from an asynchronous storage-readiness continuation to synchronous top-level worker startup,
as required by Chrome's MV3 event-dispatch contract. Before readiness it can still only parse the
closed request shape and return `WARDEN_METHOD_UNAVAILABLE`; a composition test proves no session
storage read occurs on that path.

**Removed / narrowed:** a stopped service worker can no longer miss its wake connection merely
because storage restriction/restoration promises have not settled. Readiness rejection, explicit
disposal, and synchronous bootstrap failure each remove the listener. Privileged/storage-backed
subsystems must still await `background.ready`; this correction does not weaken that gate.

**New invariants:** none promoted. `WRD-EXT-01` and `WRD-EXT-02` remain `unimplemented`.

**Residual, stated honestly:** registration timing is proven with unit event mocks, not a killed and
reawakened Chromium service worker. There is still no content script/provider to open this Port and
no privileged method behind it. The prior full-gated SHA `6cabc403` was executable-test green but
architecturally wrong for MV3 wake dispatch; that is exactly why prose and unit green cannot replace
the missing real-browser lane. Independent second-model review remains UNVERIFIED.

---

## Client C1 lazy page bridge — 692e550 — 2026-08-30 — **PARTIAL**

**New trust surface:** one default-isolated static content script now runs at `document_start` in
every ordinary HTTP(S) frame. Its match patterns are broad Chrome host access and may produce a
read/change warning even without a separate `host_permissions` key. A page can send an exact
direction-tagged outer envelope through `window.postMessage`; the content script can open the named
provider Port and return only the closed `WARDEN_METHOD_UNAVAILABLE` response. File, internal,
extension, data, and opaque about/srcdoc frames remain excluded. There is no main-world injection,
web-accessible resource, external connection, Wallet Standard registration, account/UI/RPC/key
capability, or successful provider method.

**Removed / narrowed:** the bridge requires exact outer fields, `event.source === window`, and the
captured canonical document origin, but conveys neither check as authority. The service worker still
derives extension/document/origin/tab/frame only from Chrome-owned `Port.sender` and reparses the
inner request. Unexpected background shapes close rather than cross into the page. Ports open only
for matching requests, reconnect only on a later request after disconnect, retry a stale send once,
and share a 1,024-request lifetime ceiling per document across reconnects. The content bundle has an
exact three-source dependency allowlist, so importing background/storage/keyring/RPC code fails the
build. Real Chromium now covers top-level and cross-origin-frame sender acceptance, cross-context
forgery rejection, same-tab navigation, forced worker-target removal, execution-global reset, and
same-document wake/reconnect. The real-browser lane is mandatory in `.claude/test-gate.sh` and main
CI provisions its exact Playwright Chromium dependency.

**New invariants:** none promoted. `WRD-EXT-01` and `WRD-EXT-02` remain `unimplemented`; the only
reachable method boundary has zero authority and no successful path.

**Residual, stated honestly:** any same-page script can forge, observe, suppress, or spoof bridge
traffic. That is caller compromise, not an authenticated sub-principal; future successful responses
must not pretend otherwise. No provider is injected/registered, every valid request is unavailable,
and authorized account/cluster lookup, approval ownership, privileged UI routing, success/events,
RPC, and keys do not exist. Killing a settled worker and issuing a later request does not prove
pending privileged-request recovery. Repeated navigation/tab-id reuse, cap compatibility, Chrome
version/store/manual-install behavior, and opaque-frame demand remain unmeasured. The new broad host
warning provides no user-facing wallet value until provider registration lands. Independent
second-model review remains UNVERIFIED.

---

## Client C1 zero-authority action popup — 1420582 — 2026-08-30 — **PARTIAL**

**New trust surface:** the manifest now exposes an extension action whose local
`popup.html` opens the distinct `warden:popup:v1` runtime channel. One
synchronous top-level router owns `runtime.onConnect` and directs only the exact
provider and popup names to their separate parsers; unknown names disconnect.
The popup has one status request and one fixed unavailable response. It imports
no core, provider, storage, session, approval, RPC, signing, decrypt, export, or
key module and has no dispatch hook, so the new privileged-origin route carries
zero wallet authority.

**Removed / narrowed:** popup privilege requires this extension's id, exact
`chrome-extension://<id>` origin, and exact `/popup.html` URL. Tab-hosted
extension pages additionally require a browser document id and top-frame
identity. Bundled Chromium 151's real toolbar popup was measured with
`chrome.action.openPopup()`; its browser-owned sender contained only id,
extension origin, and exact popup URL. Because Chrome omitted document, tab,
frame, and lifecycle fields for that tabless shape, its binding is the exact
extension origin/path plus the lifetime of the browser-owned Port—not an
invented document id. A real isolated content script with the same extension id
was rejected causally because its sender origin/URL belonged to the web page.
Per-Port requests/correlations, total active Ports, optional document ownership,
and bundle dependencies are bounded and tested. The real action-popup route,
direct response, rendered state, tab-hosted route, and content-script rejection
passed three consecutive Playwright runs at implementation commit
`14205821687cf3da51abfa12866985e2a545b15a`.

**New invariants:** none promoted. `WRD-EXT-01` and `WRD-EXT-02` remain
`unimplemented`: only an unavailable status is reachable, and the required
full-page approval lane does not exist.

**Residual, stated honestly:** there is still no injected/registered Wallet
Standard provider, authorized account/cluster record, approval owner/digest,
atomic approval winner, success/event protocol, RPC, signing, key use, or
pending-request recovery. A discovery-only Wallet Standard registration was
rejected after reading Anza wallet-adapter commit
`ca731858affa36fa91b593cc670747b671c4589f`: its compatibility predicate
requires connect, events, and a transaction feature, so registering now would
advertise capabilities Warden does not have. Chrome 106 ordinary-action
compatibility is not established by the newer `action.openPopup` automation
API or by one Linux Chromium build. A tabless action sender supplies no
document-level identity, so the concurrency cap and Port lifetime contain
resource use but cannot prove one Port per popup document. The page is a plain
pre-alpha boundary indicator, not release UX. Independent second-model review
remains UNVERIFIED.

---

## Client C2 persistent Chrome record owner — 7e18f27 — 2026-08-30 — **PARTIAL**

**New trust surface:** the emitted background now reads one encrypted keyring
record from `chrome.storage.local` after both local and session areas have been
restricted to `TRUSTED_CONTEXTS`. The store can replace or clear that one key,
but the raw owner is not exported by the background runtime and no reachable
Port, popup, content script, or provider method can invoke mutation or key use.
The existing `storage` permission does not expand.

**Removed / narrowed:** only the strict canonical core record is accepted.
Calls through this owner are serialized; replace validates before touching
storage, writes one property, and exact-readback checks; clear exact-readback
checks absence. Chrome failures retain their cause. Ambiguous mismatched
readback does not trigger destructive cleanup. Startup never parses a session
when the persistent record is absent, removes session state on absence or
corruption, and rejects readiness on corruption. A real Chromium canary is
written and read by the worker before the actual isolated content-script world
is causally denied `storage.local` access.

**New invariants:** none promoted. `WRD-KEY-03` and `WRD-KEY-04` remain
`unimplemented`; this closes only part of their extension-storage conjuncts.

**Residual, stated honestly:** Chrome exposes no documented transaction, CAS,
rollback, or durability guarantee for this owner. Serialization excludes
out-of-band writes from a different trusted context, and a whole older valid
same-context record can still replay without external freshness. A restored
session is not yet bound to the stored record's public bundle id. No creation,
Argon2 benchmark/floor, PRF ceremony/device matrix, derivation, account/context
registry, record mutation lifecycle, privileged consumer, or seeded
worker-death/wake vector exists. A cleanup rejection can leave stale session
bytes in browser-managed storage even though readiness fails locally.
Independent second-model review remains UNVERIFIED.

---

## Client C2 session-to-record binding — c3b74eb — 2026-08-30 — **PARTIAL**

**New trust surface:** the existing `storage.session` unlock record is now v2
and adds the public 16-byte encrypted-bundle id. Background startup decodes the
id from the already validated persistent local record and supplies only that id
to the session owner. No new permission, message, page, popup, provider-success,
record-mutation, or key-use surface is reachable.

**Removed / narrowed:** activation snapshots and exact-readback checks the
bundle id beside the unwrap key. Restore snapshots the current persistent id
before its first await, strictly parses v2, and removes a well-formed session
whose id differs. The obsolete v1 slot is removed without parsing. A transition
generation check prevents cleanup based on a stale awaited read from erasing a
newer unlock. Unit tests cover matching restore, mismatch removal, caller
mutation, malformed/legacy data, readback corruption, missing persistent state,
and the forced stale-read/new-unlock race. Real Chromium exact-readback proves a
canonical local record, mismatched session, and independent session canary were
present; after actual worker-target death and same-document wake, only the
mismatched session is absent while the canary survives.

**New invariants:** none promoted. `WRD-KEY-03` and `WRD-KEY-04` remain
`unimplemented`; this is one extension lifecycle conjunct, not a usable keyring
or privileged consumer.

**Residual, stated honestly:** bundle-id equality is not a hash of the complete
persistent record and does not authenticate Chrome storage. Random ids bind
ordinary replacement, but an older valid same-context record can replay and a
trusted context that preserves the id can alter ciphertext until AEAD opening
later rejects it. A session already active in one worker is not revalidated if
another trusted context writes local storage out of band. There is no composed
record-mutation/session-revocation owner, creation/unlock ceremony, Argon2
benchmark/floor, PRF device evidence, account/context registry, key derivation,
sign/decrypt/export consumer, transaction/CAS/durability guarantee, or policy
for browser cleanup rejection. The browser vector is structurally valid but
does not derive a real key. Independent second-model review remains UNVERIFIED.

---

## Client C2 live record-change revocation — 0e3fc0f — 2026-08-30 — **PARTIAL**

**New trust surface:** the service worker now owns one global
`chrome.storage.onChanged` listener and one internal fatal lifecycle promise.
The listener is installed synchronously during top-level evaluation, before
storage readiness settles, because Chrome's MV3 lifecycle requires synchronous
event registration. It examines only Chrome's change-area label and whether the
change dictionary owns `warden.keyring-record.v1`; it parses no attacker value
and adds no permission, page, method, account, approval, RPC, or key-use route.
Current platform references:
<https://developer.chrome.com/docs/extensions/reference/api/storage/> and
<https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers#register-listeners-synchronously>.

**Removed / narrowed:** every reported local mutation, removal, or clear that
contains the keyring property now conservatively increments the session
transition, aborts live leases, zeroes owned account/bundle/key buffers, and
starts selective removal of the v2 and legacy-v1 session properties. The
in-memory authority change happens synchronously before the cleanup promise is
returned. Wrong-area and unrelated-key events do not revoke. Successful cleanup
keeps the closed runtime boundary available. Cleanup rejection keeps memory
locked, preserves the typed failure, disables the storage handler, disconnects
existing provider/popup Ports, and disables the sole runtime connection handler.
Registration failure, readiness rejection, and explicit disposal roll both
listeners back. Unit tests measure active lease abort and active-Port teardown;
real Chromium measures actual event delivery, exact persistent replacement,
selective Warden-session removal, and survival of an unrelated session canary.

**New invariants:** none promoted. `WRD-KEY-03` and `WRD-KEY-04` remain
`unimplemented`; this closes one extension lifecycle conjunct without creating
or consuming a real derived key.

**Residual, stated honestly:** `storage.onChanged` is notification, not a
transaction, lock, CAS, durability proof, storage authenticator, or freshness
authority. A different trusted context can still race writes, preserve a bundle
id, or replay an older valid same-context record. If session removal rejects,
stale unwrap-key bytes can remain in browser storage even though this worker is
locally locked and unreachable; replaying the matching old record before a
later worker start remains dangerous. The fatal state closes every runtime
surface that exists today, all of which are zero-authority, but future privileged
surfaces must use the same health gate rather than merely await initial
readiness. No composed mutation owner, real activation/open path, Argon2 device
floor, PRF ceremony matrix, account/context registry, signing/decrypt/export
consumer, or real-key worker vector exists. Independent second-model review
remains UNVERIFIED.

---

## Client C2 authenticated session-signer activation — bddb0cc — 2026-08-30 — **PARTIAL**

**New trust surface:** the background runtime now exposes one internal composed
keyring lifecycle owner. It can accept password bytes and the complete public
keyring context, authenticate the canonical local record, activate a session,
and lend an isolated plaintext Ed25519 seed to one local callback. Record replace
and clear operations also live on this owner. No content-script, provider, popup,
or other browser-reachable method can invoke these operations; there is still no
signature consumer or RPC route. The emitted background includes the existing
pure-JavaScript Argon2 implementation and measured **136,560 bytes** at the
implementation SHA.

**Removed / narrowed:** v1 session-signer plaintext is strictly one 32-byte seed,
with its schema and key kind bound by existing contextual AAD. Caller password
bytes are overwritten synchronously; the derived KEK succeeds only by fresh AEAD
authentication, never an equality check. Plaintext is schema-validated and
overwritten before session commit. The session retains the KEK, account, public
bundle id, and absolute deadlines—not the seed. Activation exact-readback checks
the same canonical record before and after commit. Every local use reloads that
record, checks account and bundle identity, authenticates the complete supplied
context, lends isolated buffers, and performs deadline/revocation and exact-record
checks before releasing callback output. Lock, record replacement, clear, and
Chrome record-change notification share synchronous transition invalidation;
late seed leases and results are overwritten. Unit tests measure stale unlock,
pending-use, unnotified record-swap, disappearance, schema/auth failure, callback
failure, wake corruption, and matching/mismatched restore paths. The real browser
lane still measures wake/change storage behavior rather than password/signature
use.

**New invariants:** none promoted. `WRD-KEY-02`, `WRD-KEY-03`, and `WRD-KEY-04`
remain `unimplemented`; their low-level and internal-lifecycle conjuncts are
stronger, but the compound product requirements are not satisfied.

**Residual, stated honestly:** there is no creation/onboarding or browser-
reachable unlock flow, production Argon2 benchmark/floor or attempt policy, PRF
device matrix, persisted authoritative account/cluster/program configuration,
on-chain check that the encrypted seed matches a currently granted session,
approval owner, transaction signing/sending consumer, RPC, or real-key browser
vector. A local callback can copy a seed or perform an irreversible side effect;
the current contract forbids that behavior but cannot revoke bytes already sent.
JavaScript overwrite is best effort. The session KEK remains sufficient to open
the record until its deadline. Context is supplied anew on each use. Chrome
storage supplies no transaction/CAS, authenticated event, rollback, durability,
or freshness primitive; valid same-context replay remains possible. A delayed
self-write change event can conservatively revoke a later unlock, and future
privileged handlers must await the runtime readiness/fatal health gates. Cleanup
rejection can retain browser-owned KEK bytes. Independent second-model review
remains UNVERIFIED.

---

## Client C2 self-contained context and authenticated wake restore — 8653fed — 2026-08-30 — **PARTIAL**

**New trust surface:** canonical keyring record v2 stores the complete public
account/origin/key-kind/schema/genesis/program context in its one bounded binary
record. The extension accepts only that record version and derives the permitted
origin from browser-owned `chrome.runtime.id`; normal unlock and use callers no
longer select context. The public background lifecycle is a frozen readiness
facade whose owner and gate are ECMAScript-private. These changes add no page,
popup, provider method, account registry, signature, approval, RPC, permission,
or network request. The existing local property name remains
`warden.keyring-record.v1`; that stable slot name is not the binary record
version.

**Removed / narrowed:** record-v2 context bytes are canonical, length-bounded,
copy-owned, and authenticated both by the outer record binding and bundle AEAD.
A locked parse exposes public routing metadata but does not claim it is authentic;
successful password/PRF/retained-KEK open supplies that proof. Record v2 rejects
caller context, while core record v1 is available only to explicit legacy
migration calls and the extension refuses it. Wake restore no longer treats the
public bundle id as sufficient: before readiness resolves true, the retained KEK
must open the exact current record under its runtime-origin-checked context, the
plaintext must decode as the strict session-signer schema, session account/bundle
copies must match, deadlines must remain live, and exact persistent readback must
still match. Failure revokes memory and removes serialized session material.
Pre-ready lifecycle calls reject without reading keyring storage, and a pre-ready
password buffer is overwritten synchronously. Unit regressions measure metadata
tamper, wrong runtime origin, v1 refusal, parser length/version/truncation, valid
authenticated wake, readiness isolation, and cleanup. Chromium measures an actual
extension-id-compatible record plus wake mismatch and live change cleanup; it does
not perform password authentication.

Chrome primary references for the platform facts are
<https://developer.chrome.com/docs/extensions/reference/api/runtime>,
<https://developer.chrome.com/docs/extensions/develop/concepts/network-requests>,
and <https://developer.chrome.com/docs/extensions/reference/api/storage/>.

**New invariants:** none promoted. `WRD-KEY-02`, `WRD-KEY-03`, and
`WRD-KEY-04` remain `unimplemented`; this hardens internal ownership and wake
authentication but does not satisfy their browser-reachable compound product
requirements.

**Residual, stated honestly:** there is no creation/onboarding, v1 migration,
browser password/passkey ceremony, production Argon2 benchmark/floor or attempt
policy, PRF device matrix, authoritative account registry, on-chain session-grant
match, approval owner, signer/send/RPC consumer, or real-key browser vector.
Record metadata is public and untrusted until a successful open. Core migration
support has no safe product workflow. Runtime-origin checking does not decide the
production extension-ID freeze versus authenticated migration required by
`WRD-ORG-01`. A local callback can copy a seed or create an irreversible side
effect before post-use checks; JavaScript clearing is best effort. Chrome storage
still provides no transaction/CAS, authenticated freshness/event, rollback, or
durability proof; valid same-context record replay and cleanup-retained KEK bytes
remain possible. A delayed self-write event may conservatively revoke a later
unlock. Independent second-model review remains UNVERIFIED.

---

## Client C2 Argon2 host responsiveness and pending-unlock revocation — 125ad76 — 2026-08-30 — **PARTIAL**

**New trust surface:** production password record seal/open now use the exact-pinned
`@noble/hashes` 2.4.0 asynchronous Argon2id implementation. On scheduling hosts
that expose `scheduler.postTask`, derivation runs at background priority under the
lifecycle's `AbortSignal`; Noble's internal yields inherit that scheduling context.
The deploy verifier's fail-closed dependency allow-list and byte attestation were
updated for the exact dependency. A temporary-extension benchmark is now part of
the repository deploy gate and executes the RFC 9106 second recommended profile in
real Chromium. No WASM implementation, network permission, host permission, page,
message method, or `wasm-unsafe-eval` exception was added; extension CSP remains
`script-src 'self'`.

**Removed / narrowed:** password derivation no longer monopolizes the tested Chrome
151 extension host for its full approximately 0.9-second run. At implementation SHA
`125ad761b3af1879f42fa13135e5a07d57721223`, five real-browser 64 MiB / t=3 /
p=4 derivations measured **901.1 ms minimum / 901.8 ms p50 / 927.1 ms p95-max**;
a browser task requested after 50 ms ran at **53.1–67.7 ms**, before every
derivation completed. A separate revocation dispatched at 61.4 ms rejected with
`KeyringLockedError` 29.0 ms later and the caller password buffer was zeroed.
Lock, record replacement, clear, a competing unlock, and startup restore now revoke
the one pending derivation authority before suspending. Already-revoked requests
refuse before Argon allocation. Lifecycle-owned password, KEK, plaintext, and
decoded-seed copies are wiped best effort on abort and a late result cannot
activate. A deterministic regression also closes a startup race in which restore
could previously adopt a session serialized by a just-superseded unlock; restore
now clears and refuses a same-owner pending unlock.

**New invariants:** none promoted. `WRD-KEY-02`, `WRD-KEY-03`, and `WRD-KEY-04`
remain `unimplemented`. This establishes browser-backed responsiveness and one
pending-ceremony revocation mechanism, not a browser-reachable keyring product or
a production parameter policy.

**Residual, stated honestly:** this is one fast server-class host—Headless Chrome
151, Linux 6.8, AMD EPYC-Milan, 4 logical CPUs, and 15.25 GiB RAM—not a
slowest-supported-device matrix. No acceptable latency band, production creation
floor, below-floor record rejection/upgrade rule, or online attempt-rate/backoff
policy has been selected. Cheap record metadata remains intentionally accepted for
tests and would be unsafe as product-created policy. The pure-JavaScript
implementation remains slower relative to native attackers, and Argon2 `p=4`
lanes are not four JavaScript CPU workers. On hosts without `scheduler.postTask`,
Noble's timer fallback yields the host and revoked output is suppressed, but an
initialized KDF may run to normal completion before cleanup. Chrome 106 fallback
behavior has not been measured. JavaScript/VM zeroization remains best effort.
There is still no browser creation/unlock/re-prompt flow, PRF real-device matrix,
authoritative account registry, on-chain session-grant match, approval/RPC/signer
consumer, or real-key browser vector. Independent second-model review remains
UNVERIFIED.

---

## Client C3 transactional approval-record substrate — c3be2c1 — 2026-08-30 — **PARTIAL**

**New trust surface:** core now exports a browser-safe strict approval-record
domain, and the extension source contains an internal approval owner plus a native
IndexedDB repository. One dedicated version-1 database has one `approvals` object
store keyed by a background-minted 128-bit id. Records retain public provenance,
authority, exact serialized message bytes, a recomputed SHA-256 digest, policy
version, bounded timestamps, and terminal state. Live pending records are capped
at 32, total retained records at 128, lifetimes at ten minutes, and terminal
tombstones at ten minutes. The module is not instantiated by the shipped
background, is tree-shaken from its bundle, and adds no manifest permission,
host access, network request, CSP relaxation, page, or message method. Trusted
same-extension contexts share its IndexedDB origin.

**Removed / narrowed:** every create, expiry read, terminal transition, and
startup invalidation is one `readwrite` transaction over that one object store.
Overlapping transactions serialize, so independent extension contexts cannot
both change one pending record to different terminal states. Creation uses
`add`, preventing overwrite. Every persistence boundary strictly validates and
copy-owns the record and recomputes the message digest. A wrong expected digest
atomically invalidates the record; malformed stored data is deleted; the exact
deadline expires; a backwards clock deletes pending authority; and worker
startup cancels, never restores, unexpired pending records whose Port died. A
temporary real MV3 extension measures two independent database connections,
approve/reject and double-approve races, returned-buffer mutation, identical
payload independence, direct raw-byte tamper, wrong-digest retry, exact expiry,
and forced service-worker stop/wake. Primary platform bases are Chrome's service
worker lifecycle and storage documentation and the IndexedDB atomicity and
transaction-scheduling specification:
<https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
<https://developer.chrome.com/docs/extensions/reference/api/storage/>, and
<https://www.w3.org/TR/IndexedDB/>.

**New invariants:** none promoted. `WRD-APR-01`, `WRD-APR-02`, and
`WRD-APR-03` remain `unimplemented`. This is a tested persistence and record
primitive, not a browser-reachable approval-to-signature product.

**Residual, stated honestly:** `startBackground()` does not construct this owner,
and no provider, popup, or approval page can reach it. There is no authoritative
account/network/policy registry, exact-byte intent decoder, UI, current-state
comparison, signer, RPC, navigation cancellation, root ceremony, nonce consumer,
or signed-result replay. The SHA-256 binds only the raw message; it is not a MAC
over origin/account/network/policy metadata, which remains trusted-background
state and must be rechecked against current authority immediately before future
signing. Transitioning to `approved` before a future signature prevents a second
claim but makes a crash lose availability. Short tombstones and random ids bound
ordinary replay rather than proving indefinite non-reuse. IndexedDB strict
durability is only a browser hint; browser, process, host, disk, rollback, and
malicious-trusted-context failure remain outside the measurement. The browser
lane kills one MV3 worker on one Chrome build, not the browser or host, and no
Chrome-floor/Brave/disk-corruption matrix exists. Independent second-model review
remains UNVERIFIED.

---

## Client C3 shipped approval-startup ownership — f3b4946 — 2026-08-30 — **PARTIAL**

**New trust surface:** the production background bundle now includes the internal
approval owner, SHA-256 record domain, and native IndexedDB repository. It opens
the dedicated `warden-approvals-v1` database during every worker evaluation and
runs one startup invalidation before internal readiness. The emitted background
is 194,123 bytes at the implementation SHA, up from the prior tree-shaken build;
content and popup bundles remain 8,269 and 3,229 bytes. No manifest permission,
host access, CSP directive, extension page, network request, successful provider
method, or approval message route was added. The owner and repository do not
escape the returned application.

**Removed / narrowed:** runtime readiness now composes trusted Chrome-storage
restriction, authenticated keyring restore, and approval startup invalidation.
Keyring operations remain closed until all settle. Approval failure rejects
readiness, removes provider/popup and storage-change listeners, disconnects live
Ports, and closes its database connection. Initialization rollback, fatal
record-change cleanup, and explicit disposal also close it exactly once. A unit
contract measures pending readiness and the failure cleanup. The real shipped
MV3 bundle initializes its production database, accepts a test-seeded pending
record from the trusted worker context, loses its execution global under a CDP
forced stop, wakes through the actual provider Port, and changes that record to
`cancelled`. The independent temporary-extension lane continues to measure the
repository's transactional races and tamper behavior.

**New invariants:** none promoted. `WRD-APR-01`, `WRD-APR-02`, and
`WRD-APR-03` remain `unimplemented`. Shipping cleanup closes one lifecycle
conjunct; it does not create an approval-to-signature flow.

**Residual, stated honestly:** every external provider and popup method remains
fixed-unavailable. There is no authoritative account/network/policy registry,
record-creation route, approval page, exact-byte decoder, current-state/digest
signer recheck, RPC, root ceremony, navigation cancellation, nonce consumer, or
signed-result replay. Worker death intentionally cancels all pending approvals,
so availability is lost even if a future approval window survives and retries.
The browser test seeds IndexedDB directly from a trusted worker test context; it
does not prove a nonexistent page-to-background creation path. Same-extension
trusted contexts remain able to access the same database, message SHA-256 is not
a MAC over all public metadata, and strict durability remains a hint rather than
a disk/rollback guarantee. Only one Chrome build and worker stop/wake are tested,
not Chrome floor, Brave, full browser/host crash, disk corruption, or rollback.
Independent second-model review remains UNVERIFIED.

---

## Client C3/C4 strict serialized-transaction envelope — d49529c — 2026-08-30 — **PARTIAL**

**New trust surface:** core now exports `@warden/core/transaction`, a manual
browser-safe parser for the serialized Solana transaction supplied by Wallet
Standard. It retains an owned copy of the exact 1–1,232 bytes and exposes
copy-isolated signatures, message bytes, static keys, required signers,
blockhash, and compiled instructions. The package is not imported by the
extension, so no background route, page, permission, network request, CSP rule,
or successful provider method changed.

**Removed / narrowed:** the parser accepts only legacy and lookup-free v0. It
enforces strict Solana ShortU16 form, exact end-of-input, signature/header
agreement, one writable fee payer, unique static accounts, non-payer static
program ids, in-range account indices, and optional membership of the requested
wallet account in the real signer prefix. Unknown versions, lookup-dependent
messages, aliases, overflow, truncation, trailing bytes, duplicate accounts, and
ambiguous/out-of-range indices fail with typed errors. Hand-authored legacy/v0
goldens agree byte-for-byte with web3 as a differential oracle; every proper
prefix rejects; canonical two-byte compact length accepts while an alias of the
same value rejects; every returned byte buffer is isolated. The implementation
does not call the more permissive web3 deserializers.

Primary sources establish that Wallet Standard passes a serialized transaction,
while Warden's program-owned PDA cannot directly sign it and instead requires a
distinct wrapped `execute` transaction:
<https://github.com/anza-xyz/wallet-standard/blob/master/packages/core/features/src/signTransaction.ts>,
<https://github.com/anza-xyz/wallet-standard/blob/master/packages/core/features/src/signAndSendTransaction.ts>,
<https://github.com/wallet-standard/wallet-standard/blob/master/extensions/solana.md>,
<https://solana.com/docs/core/transactions>, and
<https://github.com/anza-xyz/solana-sdk/blob/master/message/src/versions/v0/loaded.rs>.

**New invariants:** none promoted. `WRD-APR-01`, `WRD-APR-02`, and
`WRD-TXI-01` remain `unimplemented`. Syntactic framing is a prerequisite, not
the approval-to-signature or semantic no-blind-sign product invariant.

**Residual, stated honestly:** the parser deliberately accepts syntactically
valid unknown programs, arbitrary signature bytes, empty instruction lists, and
stale/zero blockhashes. It does not authenticate current cluster/account/policy,
resolve lookups, decode program intent, understand Warden payloads, calculate
balance/authority consequences, simulate, wrap, construct the final transaction,
create or render an approval, recheck a digest, or sign. Fixed goldens plus a
web3 differential are not the full C4 independent Rust differential/fuzzer
corpus. Lookup transactions are blocked, reducing compatibility. Most
critically, recording the incoming dApp transaction and later signing a distinct
wrapped transaction would violate WYSIWYS; the next coordinator may create a
record only after constructing and reparsing the exact final wrapped message and
binding its recent-blockhash rules. Independent second-model review remains
UNVERIFIED.

---

## Client C3/C4 exact session-message construction — 8c29a22 — 2026-08-31 — **PARTIAL**

**New trust surface:** core now exports the opt-in
`@warden/core/transaction/session` structural rewrite. It accepts a strict
serialized dApp transaction plus explicit SmartAccount, session delegate,
SessionKey account, Registry, Warden program, and final blockhash. It returns
copy-isolated source bytes, exact final message bytes, an unsigned transaction
template, execute payload, and accounts hash. The shipped extension imports none
of this path; permissions, pages, CSP, network access, and fixed-unavailable
provider behavior are unchanged. The parser-only `@warden/core/transaction`
subpath remains independent of web3.

**Removed / narrowed:** the source must have exactly one zero-filled required
signature for the advertised SmartAccount. Partial signatures, co-signers,
empty/compute-only intent, durable nonce at instruction zero, Instructions-sysvar
introspection, lookup tables, generic writable-PDA/writable-session-signer shapes,
and an oversized final packet fail closed. The final wrapper is lookup-free v0,
self-paid by the session delegate, and carries literal Anchor/Borsh session
`execute` framing with explicit SessionKey/Registry accounts. Its complete
serialized transaction must fit 1,232 bytes. The implementation reparses the
final envelope and checks its sole zero signature slot, exact signing message,
blockhash, execute data, effective account flags, and accounts hash before
return. A real Ed25519 test proves the signature verifies over approval's message
bytes, not over the transaction's mutable signature vector.

Primary sources confirm that web3 signs `message.serialize()` and that Solana
durable transactions are identified by an `AdvanceNonceAccount` System
instruction at index zero:
<https://github.com/solana-foundation/solana-web3.js/blob/master/src/transaction/versioned.ts>,
<https://solana.com/developers/cookbook/transactions/durable-nonces>, and
<https://solana.com/developers/cookbook/transactions/confirmation>.

**New invariants:** none promoted. `WRD-APR-01`, `WRD-APR-02`, and
`WRD-TXI-01` remain `unimplemented`. The exact final signing object now exists,
but the compound approval, render/recheck/sign, and no-blind-sign product
invariants do not.

**Residual, stated honestly:** no shipped route consumes the builder. There is
no authoritative cluster/genesis/program/account/session/policy resolution,
blockhash-validity RPC check, semantic decode, allowlist decision, simulation,
approval creation/UI, digest claim, keyring signature, send, or durable result
replay. Any nonzero 32-byte final blockhash passes structurally; an expired hash
must cancel and rebuild a new approval, never be replaced under the old digest.
Inline-only output has no staging fallback; LUTs remain blocked. The generic
wrapper's writable-PDA refusal makes common wallet-authority dApp shapes
incompatible until typed Warden builders exist. Unknown programs can still be
wrapped structurally, so this is not a benign semantic verdict. Fixed contracts
and web3 plus noble Ed25519 are not an independent Rust final-message/fuzzer
corpus. Independent second-model review remains UNVERIFIED.

---

## Client C3 exact approved-byte signing — 349e73a — 2026-08-31 — **PARTIAL**

**New trust surface:** the opt-in core session subpath now directly depends on
exact-pinned `@noble/curves` 1.9.7 and exports a synchronous Ed25519 finalizer.
It accepts exact message bytes plus a leased 32-byte seed and returns a
copy-isolated signed transaction, signature, derived signer, and bound
blockhash. The shipped extension imports none of it and every provider path
remains fixed unavailable.

**Removed / narrowed:** the caller cannot supply or refresh a public key,
blockhash, compiled transaction, or signature slot at signing time. The
finalizer derives the public key from the seed and requires it to be the sole
signer of a strict lookup-free-v0 approval message with a nonzero blockhash. It
constructs the canonical empty envelope, proves web3 and the independent parser
see the same bytes, signs those bytes, changes only the sole 64-byte signature
slot, and reparses/verifies both views before release. Typed failures cover
malformed/trailing bytes, whole-transaction confusion, legacy/future versions,
lookups, extra or wrong signers, invalid seed width, zero blockhash, and packet
overflow. A Node/OpenSSL verifier accepts the emitted signature over the
approval message and rejects a one-byte message mutation independently of the
production Noble implementation.

Solana's current primary RPC documentation says `getLatestBlockhash` returns a
hash, last-valid height, and context; `isBlockhashValid` evaluates an exact hash
at a requested commitment and can require `minContextSlot`; `sendTransaction`
relays bytes unchanged but acceptance is not confirmation and an expiring hash
can still prevent landing:
<https://solana.com/docs/rpc/http/getlatestblockhash>,
<https://solana.com/docs/rpc/http/isblockhashvalid>, and
<https://solana.com/docs/rpc/http/sendtransaction>.

**New invariants:** none promoted. This closes a low-level exact-byte signing
seam only. The compound approval, atomic resolution, contextual key-use, and
no-blind-sign product invariants remain `unimplemented`.

**Residual, stated honestly:** no coordinator reads an approved record or calls
the keyring lease and no authoritative resolver/RPC client exists. The
finalizer has no semantic knowledge of Warden execute, supported programs,
discriminators, account roles, policy, or simulation; a privileged caller could
feed it a structurally valid unknown-program message. Therefore it must remain
unreachable until a blocking local decoder verdict and current authority/policy/
blockhash checks surround it. Claim and signing are not transactionally
composed, expiry has no durable result, send/confirmation/replay are absent, and
JavaScript secret zeroization is only best effort. There is no independent Rust
final-message/signature golden or fuzzer corpus. Independent second-model review
remains UNVERIFIED.

---

## Client C3 session-approval coordinator ordering — cafced9 — 2026-08-31 — **PARTIAL**

**New trust surface:** core exports a separate opt-in
`@warden/core/transaction/session-approval` orchestration domain. It accepts
injected authority, blockhash-RPC, synchronous local-intent, approval-owner, and
contextual-keyring capabilities. It owns a maximum of 32 worker-memory capsules
containing public approval/authority/blockhash observations. The extension's
approval and keyring owners now compile-time implement those structural
interfaces; the keyring lease exposes callback-lifetime copies of its
AAD-authenticated genesis hash and Warden program id in addition to account and
seed. These are type-only coordinator imports. The emitted extension does not
contain the coordinator/builder/signer, all provider methods remain fixed
unavailable, and no permission, CSP, storage schema, page, or network endpoint
changed.

**Removed / narrowed:** the coordinator rejects sign-and-send and accepts one
fixed `confirmed` commitment. Preparation resolves a requested account/chain at
a monotonic context, fetches exactly one blockhash, re-resolves and exact-compares
every explicit authority plus canonical authorization-state byte, constructs
the final session wrapper, requires a synchronous local verdict on its exact
message, and persists that exact message. Approval rereads every record binding,
atomically invalidates a wrong UI digest, revalidates authority/verdict before
the pending-to-approved CAS, validates only the bound blockhash afterward, and
never rebuilds under the existing digest. Post-claim RPC work occurs before
plaintext key borrow. The lease must match SmartAccount, genesis, and program;
one final authority observation and verdict are followed synchronously by exact
message signing. Strict reparse, digest/signer/message/blockhash comparison, and
Ed25519 verification guard the returned bytes.

Twenty-nine focused contracts cover exact successful ordering and four identical
decoder views, drift in every authority field at preparation, drift before and
after claim/validity and inside the key lease, monotonic-context regression,
expired blockhash with no refresh, wrong-digest invalidation, record-metadata
tamper, all three keyring context mismatches, async/throwing gate refusal,
post-finalizer signature mutation, approve/cancel and double-approve races,
unsupported sign-and-send, and real resolver/RPC/gate/result buffer mutation.
The copy-isolation lane was corrected after review because its first version had
not actually returned the mutable blockhash it claimed to test.

Primary RPC contracts remain:
<https://solana.com/docs/rpc/http/getlatestblockhash>,
<https://solana.com/docs/rpc/http/isblockhashvalid>, and
<https://solana.com/docs/rpc/http/sendtransaction>.

**New invariants:** none promoted. `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, `WRD-TXI-01`, and `WRD-KEY-04` remain `unimplemented`.
This is tested ordering around injected fakes, not a browser-reachable complete
approval authority.

**Residual, stated honestly:** there is no real authoritative account/session/
registry resolver, canonical authorization-state encoder, live cluster-bound RPC
client, or deterministic semantic decoder. A no-op injected gate can still allow
a structurally valid unknown program, so no no-blind-sign claim exists. No
approval page renders exact bytes and no provider/UI route can create, resolve,
or receive a signature. Live Port/navigation cancellation is not composed with
the capsule, and the real IndexedDB and decrypted-key owners are not exercised
together through this coordinator.

The existing `approved` terminal state means “digest claimed,” not “signature
success.” Any post-claim expiry, RPC failure, lock, drift, or key mismatch consumes
availability and leaves that tombstone without a durable result; idempotent
response replay is absent. One final authority RPC holds plaintext seed bytes
inside the abortable lease. State can change immediately after observation and
blockhashes can expire immediately after a true response. Sender, confirmation,
fees/simulation, Chrome-floor/Brave/device matrices, independent Rust
differential/fuzzing, and independent second-model review remain UNVERIFIED.

---

## Client C4 deterministic Memo intent gate — fa71bf3 — 2026-08-31 — **PARTIAL**

**New trust surface:** core exports a separate opt-in
`@warden/core/transaction/session-intent` module. It accepts exact final message
bytes plus a fixed-width raw observation of SmartAccount, SessionKey, and
Registry state and returns a frozen primitive-only description. It also exports
a synchronous coordinator gate and the canonical packet encoder. No extension
source imports this subpath; no provider method, page, permission, CSP rule,
storage schema, or network path changed.

**Removed / narrowed:** a benign verdict now exists for exactly one
account-less printable-ASCII Memo inner instruction. The decoder pins the
lookup-free-v0 signer/header/static-key layout, ComputeBudget order and bounds,
Warden program/discriminator/account indices, exact Borsh inline-session shape,
single inner payload, Memo id/data bounds, canonical state owners/lengths/
discriminators/versions/PDAs/reserved bytes, unfrozen/generation/policy/session
authority, and selected Registry membership. Unknown, malformed, ambiguous,
future-versioned, aliased, staged/root, extra-instruction, or account-bearing
shapes throw; there is no permissive fallback. Inputs are read once, bounded
before copying, and copy-owned. A fixed 333-byte golden equals the production
session builder's output. Rust pins the client-consumed account offsets plus all
four Anchor discriminators.

Research against Solana transactions, Agave ComputeBudget parsing, the Memo
program, and SPL Token's instruction source establishes the scope boundary:
program bytes are enough to describe an account-less Memo, but not enough to
state the actual consequence of a token transfer without message-keyed account
state (mint, owner, balance, and destination). Token and every other instruction
therefore remain denied.

**New invariants:** none promoted. `WRD-TXI-01` remains `unimplemented`: one
narrow decoder exists, but the shipped extension still has no real resolver,
approval render/recheck path, or successful signing route, and the compound
invariant requires all supported instructions to be locally decoded with no
blind fallback.

**Residual, stated honestly:** the packet binds only the supplied raw
SmartAccount/SessionKey/Registry observation; no real RPC implementation proves
those bytes came from one canonical cluster context. It does not attest the
Warden executable/ProgramData bytes, loader/upgrade state, or public-chain
genesis-label mapping. Registry state is exact-compared during approval, but
only the selected Memo entry is interpreted here; complete reviewed Registry
configuration remains the deploy gate's job. The synchronous clock is locally
injected and not cluster-authenticated. Lamports/rent epoch are omitted as
non-authorizing fields, but absent accounts still need explicit resolver
handling. There is no simulation or on-chain Memo landing test, real authority
resolver, approval UI, provider composition, send/confirmation/replay owner, or
token consequence model. The decoder's size and Memo-only utility are poor.
Independent second-model review and fuzz/differential coverage remain
UNVERIFIED.

---

## Client C5 pinned authority/RPC snapshot resolver — 5edb932 — 2026-08-31 — **PARTIAL**

**New trust surface:** core exports the separate opt-in
`@warden/core/transaction/session-authority` boundary. An explicitly trusted
RPC/Connection capability and reviewed immutable release configuration now
determine a canonical authority snapshot. Each snapshot is one exact ordered
six-account `confirmed` request with `minContextSlot`: SmartAccount, SessionKey,
Registry, shipped Warden Program, canonical ProgramData, and Clock. Public
mainnet/devnet/testnet genesis hashes and one explicit localnet hash are pinned.
The extension imports none of this boundary and every provider route remains
unavailable.

**Removed / narrowed:** the resolver rejects absent/extra accounts, hostile
getter drift, oversized input before copying, wrong state owner/size/executable
flags, malformed account discriminators/versions, noncanonical ProgramData,
wrong loader state, wrong upgrade authority/slot/allocation, code-hash or raw-
hash drift, malformed/noncanonical Clock, response/Clock slot disagreement,
unsafe time, wrong genesis, expired/revoked/frozen/stale-generation sessions,
and policy/Registry disagreement. RPC methods are snapshotted at adapter
construction. All returned values are bounded, copy-owned, and primitive or
immutable. Rust tests pin current loader and Clock byte offsets in addition to
the Warden state ABI.

The real Memo intent and approval coordinator now consume this resolver. Every
approval capsule binds the ProgramData address, deployment slot, governed
upgrade authority, code hash, full raw account hash, allocation, and
cluster-observed Clock. Clock is checked between immediately consecutive
authority observations, allowing forward time and rejecting regression. The
real resolver/intent/coordinator/signing integration fixes all six resolver
minimum contexts to `[0, 52, 52, 52, 62, 62]`.

The focused test began red because the module did not exist. Subsequent harsh
review created two more genuine red failures: an adapter followed mutation of
its Connection method after construction, and chained authority observations
could regress Clock from an intermediate value while remaining above the
original capsule. Both are fixed and regression-tested. The ProgramData PDA
was independently derived rather than guessed; fixture hashes use independent
Node/OpenSSL goldens; extension source and emitted-dist isolation are recursive
executable checks. Independent second-model review remains **UNVERIFIED**
because the local review subprocess could not initialize its in-process app
server on this read-only host.

Primary RPC/ABI evidence:
<https://solana.com/docs/rpc/http/getmultipleaccounts>,
<https://solana.com/docs/rpc/http/getgenesishash>,
<https://docs.rs/solana-clock/latest/solana_clock/struct.Clock.html>,
<https://docs.rs/solana-loader-v3-interface/latest/solana_loader_v3_interface/state/enum.UpgradeableLoaderState.html>,
and
<https://github.com/solana-labs/solana/blob/master/sdk/src/genesis_config.rs>.
Clock monotonicity is explicitly version-scoped to audited Agave commit
`a4144392c8ffd8d0840e312ecc3a59d35533c005`, whose Tower and Alpenglow paths
enforce nondecreasing ancestor time:
<https://github.com/anza-xyz/agave/blob/a4144392c8ffd8d0840e312ecc3a59d35533c005/runtime/src/bank.rs#L2405-L2460>,
<https://github.com/anza-xyz/agave/blob/a4144392c8ffd8d0840e312ecc3a59d35533c005/runtime/src/bank.rs#L3333-L3368>, and
<https://github.com/anza-xyz/agave/blob/a4144392c8ffd8d0840e312ecc3a59d35533c005/runtime/src/block_component_processor.rs#L653-L713>.

Exact-SHA evidence at `5edb932503fdeebb72c029eba49c5f79653599fc`:
the focused resolver/intent/coordinator suites passed **141/141**; core passed
**620/620**, typecheck, build, and compiled subpath resolution; the Rust
resolver ABI suite passed **3/3**; extension passed **246/246**, typecheck, build,
and emitted resolver-isolation scanning. The preceding ledger SHA
`01d6694da877b33022c02cc48c6815f38d2d35b5` passed the exact full command `env
npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit **0**.
The full gate for this ledger-inclusive boundary is pending and that earlier
verdict is not transferred.

**New invariants:** none. `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03`,
`WRD-TXI-01`, and `WRD-KEY-04` remain `unimplemented`.
`docs/security/invariants.jsonl` is intentionally unchanged.

**Residual, stated honestly:** the trusted RPC remains a trust terminus; genesis
binding does not make a malicious endpoint truthful. Six full ProgramData
fetches per approval are expensive and expose an availability lever. Rechecking
code through signing cannot prevent a governed upgrade after signature and
before landing. `solana-verify` trailing-zero code-hash parity remains release-
candidate **UNVERIFIED**, and every raw/config hash must come from an
independently reviewed release manifest. Loader/Clock layout and Agave Clock
monotonicity are versioned compatibility assumptions, not protocol guarantees.

No trusted Connection owner, reviewed release-pin manifest, real blockhash RPC
adapter, runtime composition, approval UI, successful provider route, sender,
confirmation, or durable replay exists. Memo is still the only decoded verb;
the extension cannot reach any of it. This is a strong authority primitive, not
a deployable no-blind-sign product.

---

## Client C6 chain-bound blockhash RPC and pinned composition — 933245d — 2026-08-31 — **PARTIAL**

**New trust surface:** core exports the separate opt-in
`@warden/core/transaction/session-rpc` module. One explicitly trusted web3.js
Connection plus a complete caller-supplied release pin set can now construct
the real authority resolver, contextual blockhash client, deterministic
Memo-only gate, approval coordinator, and exact-byte session signer. The
extension imports none of this module; recursive source and emitted-bundle
checks find no RPC, resolver, or composition symbols/strings, and all provider
methods remain unavailable.

**Removed / narrowed:** the blockhash adapter is fixed to one supported chain,
canonical public genesis or explicit localnet genesis, `confirmed` commitment,
and caller-supplied non-regressing minimum context. It deliberately rejects the
context-dropping `Connection.getLatestBlockhash()` convenience API and calls
only `getLatestBlockhashAndContext()` and `isBlockhashValid()` with exact
configs. Every operation first checks `getGenesisHash`; every request and
response field is read once and every byte array is copy-owned. Cross-chain,
cross-genesis, malformed/zero/noncanonical hashes, unsafe heights, malformed
booleans, and context regression reject. It performs no retry, fallback,
endpoint switch, refresh, send, or confirmation.

The factory requires the literal shipped Warden program plus deployment slot,
upgrade authority, code hash, full raw ProgramData hash, and exact allocation.
It copy-owns those pins and the session signer and captures Connection,
approval-owner, and keyring methods. The real integration additionally proves
that later mutation of release arrays, supplied methods, and exported internal
class prototypes cannot redirect the active coordinator: internal resolver,
blockhash, and intent behavior is supplied through frozen bound capabilities.
The successful path makes six authority snapshots with minimum contexts
`[0, 52, 52, 52, 62, 62]`, one latest request at slot 42, one exact approved-
hash validity request at slot 52, eight genesis checks, and returns the exact
394-byte signed transaction.

Three real red failures drove the boundary: missing module before collection;
**17 passed / 2 failed** when later getters could replace earlier Connection
references or mutate a context object before copying; and **37 passed / 1
failed** when post-construction prototype replacement redirected the internal
latest-blockhash method. All are now regression-covered. Independent
second-model review is **UNVERIFIED** because `codex review --uncommitted`
could not initialize its in-process app-server client on the host's read-only
path.

Primary contracts:
<https://solana.com/docs/rpc/http/getlatestblockhash>,
<https://solana.com/docs/rpc/http/isblockhashvalid>,
<https://solana.com/docs/rpc/http/getgenesishash>, and
<https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Connection.html>.
The lockfile-pinned web3.js `1.98.4` source confirms that the convenience
latest-blockhash call discards the response context while the selected methods
retain it.

Exact-SHA evidence at `933245dac0c95c2deb6bdfda72666aeb56528cc5`:
`env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
vitest run test/session-rpc.test.ts test/session-authority-resolver.test.ts
test/session-intent.test.ts test/session-approval-coordinator.test.ts` passed
**161/161**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
@warden/core test` passed **640/640**; `env
npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core typecheck`
and `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core
build` exited **0**. From `packages/core`, `node --input-type=module -e "const
module = await import('@warden/core/transaction/session-rpc'); if (typeof
module.ConnectionSessionApprovalBlockhashClient !== 'function' || typeof
module.createPinnedSessionApprovalCoordinator !== 'function') process.exit(1);
console.log('session-rpc subpath resolves')"` exited **0**. `env
npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test`
passed **246/246**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
@warden/extension typecheck` and `env
npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build`
exited **0**. The exact recursive emitted-dist scan command is recorded in
`docs/NEXT-SESSION.md`; it exited **0** with no match at the same SHA. The prior
ledger-inclusive SHA `7ce245336f5ed1e7d89a927c0872a37adc8d716d` passed the
exact full command `env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh`, exit **0**. This C6 ledger-inclusive SHA has not yet run
that gate; the prior verdict is not inherited.

**New invariants:** none. `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03`,
`WRD-TXI-01`, and `WRD-KEY-04` remain `unimplemented`.
`docs/security/invariants.jsonl` is intentionally unchanged.

**Residual, stated honestly:** complete pin shape is not reviewed provenance.
No committed production release manifest or trusted-RPC owner supplies this
factory. Genesis and contextual state are separate, non-atomic RPC calls; a
malicious trusted endpoint can lie consistently, and load-balanced honest
backends can change between calls. Six full ProgramData reads and eight genesis
queries on the successful path are an availability lever. Rechecking through
signing cannot prevent a governed upgrade, authority change, or hash expiry
after observation. The approval owner's `approved` state remains a claim
tombstone, not durable evidence of signature success; post-claim failures have
no replay/recovery owner. There is no approval render, successful provider
route, simulation, fee surface, sender, confirmation, durable result, or token
consequence model. Memo is the only decoded verb. This is a real but still
unreachable composition primitive, not a deployable wallet.

---

## Client C7 committed release statement and empty registry — 54bc05d — 2026-08-31 — **PARTIAL**

**New trust surface:** core exports the separate opt-in
`@warden/core/transaction/session-release` module. It accepts one exact v1
in-toto Statement-shaped record whose ordered digest subjects are the Warden
release artifact and every raw ProgramData byte. The predicate binds a full
release SHA, committed deploy-manifest name/digest, chain/genesis, literal
Warden program, canonical ProgramData PDA, deployment slot, exact allocation,
and governed upgrade authority. Its custom canonical JSON digest is then bound
to a dedicated leading-value `session-release:<name>@<digest>` field in the
unique `RELEASE-INTEGRITY.md` row.

The source-owned runtime registry is frozen, null-prototype, and deliberately
empty. A future entry must embed both its exact statement and canonical release
row; runtime callers may select only its committed name. The earlier design in
which a runtime caller supplied release Markdown was rejected because it could
fabricate the *presence* of a repository row, even though it could not change
the source-owned pins. A separate document-drift assertion is release tooling,
not a pin-injection route. The only C6 composition wrapper refuses an absent
name before reading any Connection, signer, approval-owner, or keyring
capability. Extension source and emitted output contain no C7 boundary.

**Removed / narrowed:** exact own-key and plain-prototype validation rejects
missing, extra, inherited/custom-prototype, symbolic, sparse, and hidden array
data. Type/predicate/schema versions, subject count/order/names, lowercase
nonzero hashes, full release SHA, canonical names/base58/decimal u64, public
genesis, literal Warden program, ProgramData PDA, nonzero authority, and bounded
allocation all fail closed. Localnet may not alias a pinned public genesis.
Fields are single-read into immutable primitive state; later getters cannot
rewrite prior observations. Binding independently copy-owns and canonicalizes
the entire deploy pin, recomputes its digest, derives the Squads vault, and
requires exact release-SHA, statement-digest, artifact/code-hash, manifest,
program, genesis, and authority agreement. The incumbent deploy registry and
synthetic members are frozen, and lookups use own keys so prototype names no
longer resolve.

The initial focused suite was red because the module did not exist. Subsequent
adversarial runs produced: **44 passed / 2 failed** for hidden array properties
and duplicate release tokens; **31 passed / 1 failed** when the unsafe
caller-document resolver still had two arguments; and **32 passed / 2 failed**
for custom-prototype statements and a localnet/devnet-genesis alias. All are
closed. Harsh test review also found false attribution: the authority-drift case
was failing first on a stale statement digest. It now recomputes the row and
asserts the specific derived-authority refusal. Deploy-verifier attestation
correctly failed **19 passed / 1 failed** after its three closure files changed;
the repository generator rediscovered/re-pinned all seven files and the suite
returned to **20/20**. Independent second-model review remains **UNVERIFIED**
because `codex review --uncommitted` could not initialize its app-server client
on the read-only host path.

Primary format evidence:
<https://slsa.dev/spec/v1.2/provenance>,
<https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>,
<https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md>,
<https://docs.sigstore.dev/cosign/verifying/verify/>, and
<https://docs.github.com/en/actions/concepts/security/artifact-attestations>.
The source record is deliberately described as **unsigned**. Repository review
is the current trust anchor; no DSSE/Sigstore signer authentication, builder
identity, transparency proof, SLSA provenance, audit assurance, or safety claim
is inferred from matching digests.

Exact-SHA evidence at `54bc05dc5adbbbd9b9a37f08cdf405b5fd66c4fa`:
the focused release/deploy-attestation/C6 suites passed **106/106**; core passed
**675/675**, typecheck, build, and compiled subpath resolution; extension passed
**246/246**, typecheck, build, and emitted C7 isolation. Exact commands are in
`docs/NEXT-SESSION.md`. The preceding ledger SHA
`351541877f6165dffe84dfda72666aeb56528cc5` passed `env
npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit **0**.
This C7 ledger-inclusive SHA has not yet run that gate; the prior verdict is not
inherited.

**New invariants:** none. `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03`,
`WRD-TXI-01`, and `WRD-KEY-04` remain `unimplemented`;
`docs/security/invariants.jsonl` is intentionally unchanged.

**Residual, stated honestly:** no production release entry or production deploy
manifest exists, so this path cannot construct a coordinator. No real
ProgramData readback, reproducible release attestation, signature/certificate
policy, or independent build establishes provenance. The RPC is still an
explicit trust terminus and separate genesis/context reads are non-atomic. A
governed upgrade can occur after observation. Signing failures after approval
still leave an `approved` tombstone without a durable result/recovery owner.
There is no approval UI, provider success route, simulation, fee presentation,
sender, confirmation/replay owner, or token consequence model. Memo remains the
only decoded verb. This is a fail-closed release trust boundary, not a deployable
wallet.

---

## Client C8 durable approval signing outcome — 0dc769a — 2026-08-31 — **PARTIAL**

**New trust surface:** the emitted MV3 worker now owns a versioned durable
signing-outcome record beside each approval in the existing IndexedDB object
store. One atomic envelope binds the exact approval to one of `signing`,
`signed`, or `failed`; a background-minted 128-bit attempt id is the CAS token,
the attempt number is bounded to u32, failures use a closed code set, and a
signed result stores copy-owned transaction bytes plus their SHA-256 digest.
Legacy pending and non-approved terminal records migrate on their next write.
A legacy raw `approved` tombstone is rejected and deleted because it cannot
prove whether signing produced bytes.

The still-opt-in coordinator claims approval and attempt ownership in the same
readwrite transaction, persists completion before returning any signature,
and reparses/verifies the durable transaction against the exact approved
message before every release. A committed signed result can be replayed
without the keyring, RPC, or volatile authority capsule. Lost acknowledgements
after claim, completion, or failure are recovered by rereading the exact CAS
record. A failed attempt can retry under a fresh token before approval expiry
while its original coordinator still owns the volatile capsule. MV3 startup
cancels pending approvals and converts unresolved `signing` attempts to
`failed/worker-restarted`; already `signed` bytes survive worker death.

**Removed / narrowed:** overlapping IndexedDB readwrite scopes have one atomic
winner for pending approval resolution, attempt claim, retry, completion, and
failure. Old attempt tokens cannot finish a newer retry. Empty/oversized
transactions, unknown failure codes, u32 exhaustion, stale tokens, regressed
clocks, malformed envelope/outcome shapes, digest tamper, and incompatible
legacy approved records fail closed. Caller-controlled validation errors are
checked before persistence or take explicit non-deleting branches. Clock
regression on an unresolved attempt preserves the CAS record and makes startup
fatal rather than erasing evidence. Disposal during completion may leave a
replayable durable result but cannot release bytes from the disposed worker.
Transient reads retain the only retry capsule instead of silently converting
an availability error into permanent loss.

The first outcome test was red before collection because the module did not
exist. The extension owner then had **2 passed / 2 failed** before completion
and failure methods existed, and the coordinator initially had **24 passed / 13
failed** before attempt ownership was plumbed through. The real extension
browser suite also exposed a QA defect: provider restart still read the old
top-level approval shape and failed after the atomic envelope shipped; the
reader now measures either the envelope or the legacy shape. Harsh review
subsequently produced two more executable REDs. The coordinator focused suite
was **41 passed / 1 failed** because a committed failure with a lost
acknowledgement discarded its capsule; reread recovery closes it. The real
Chromium approval lane received `ApprovalRecordFormatError` where it expected
`ApprovalStateConflictError` because an expired wrong-digest claim attempted an
impossible `invalidated` transition and deleted the record; expiry/clock checks
now precede digest invalidation and preserve an `expired` record.

Primary behavior evidence:
<https://www.w3.org/TR/IndexedDB/>,
<https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
and <https://www.rfc-editor.org/info/rfc8032/>. IndexedDB readwrite completion
establishes an atomic logical commit and overlapping scopes serialize. The
`strict` durability option is only a browser hint, not proof against OS/device
rollback. Chrome documents that extension workers terminate and lose globals,
which is why a signed result—not the key—is persisted. Ed25519 is deterministic
for one key/message, so retrying exact finalization does not require a fresh
random nonce. Independent second-model review remains **UNVERIFIED**:
`codex review --uncommitted` exited **1** because its in-process app-server
client could not initialize on this host's read-only path.

Exact-SHA evidence at `0dc769aaf43554c69b59ff04b11b534d0b022fd6`:
the focused outcome/coordinator/authority/RPC/release suites passed **120/120**;
core passed **686/686**, typecheck, build, and compiled approval-subpath
resolution; extension passed **247/247**, typecheck, build, and the real
Chromium lane **2/2**. An emitted-artifact command required the outcome schema,
worker-restart code, and transaction-digest check in `dist/background.js` while
recursively forbidding the coordinator, signer, C6 composition, C7 resolver,
and success-state strings; it exited **0**. Exact commands are in
`docs/NEXT-SESSION.md`. The C7 ledger SHA
`7431865ae749aa04c81c5e58928d60f8f2b5254c` passed `env
npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit **0**.
This C8 ledger-inclusive SHA has not yet run that gate; no prior verdict is
inherited.

**New invariants:** none. `WRD-APR-01`, `WRD-APR-02`, and `WRD-APR-03` remain
`unimplemented`; their notes now record this partial boundary. No successful
browser route composes it with navigation, UI provenance, or a real release.

**Residual, stated honestly:** this is atomic logical ownership, not guaranteed
physical durability. Browser/OS rollback, profile corruption, storage eviction,
and a compromised extension origin remain outside the guarantee. A signed
result survives normal worker death; a failed or orphaned attempt does not
retain its volatile authority capsule across death, so the next worker reports
the closed failure rather than retrying it. The coordinator and signer remain
absent from emitted output, the C7 production release registry is empty, and
every provider method still returns unavailable. There is no approval page,
exact-byte render, navigation/Port cancellation composition, successful result
protocol, simulation/fee surface, sender, confirmation owner, or replay
delivery route. Memo is still the only decoded verb. This removes the approved-
tombstone ambiguity; it does not make the wallet deployable.

---

## Client C9 exact-byte approval review surface — 65df168 — 2026-08-31 — **PARTIAL**

**New trust surface:** the emitted MV3 worker owns one new exact channel for an
extension page at `/approval.html?request=req_<128-bit lowercase hex>`. Browser-
owned sender id, origin, exact URL, document id, tab id, frame 0, and Port
lifetime independently bind the page to that request. The route's only owner
capabilities are `read`, `reject`, and `cancel`; its only request methods are
getReview and reject. It cannot create/enumerate/claim an approval, touch the
keyring, call RPC, sign, send, or settle a provider success.

The background snapshots one pending digest-authenticated record and reparses
its exact raw message through the strict Solana envelope parser. It accepts only
the canonical lookup-free v0 one-signer Warden/Memo form with exact header,
seven-key order, compute instructions, execute account indexes, inline
account-less Memo program, canonical Warden program, and bounded printable ASCII
payload. The page receives frozen primitive rendering facts, never message bytes
or authority state. It renders by `textContent`; signing is explicitly and
permanently disabled. The build limits the page graph to its UI and closed
protocol and excludes coordinator, authority/RPC, release-registry, and signer
modules from the worker.

**Removed / narrowed:** exact own data-property schemas reject getters,
prototype tricks, symbols, unknown/missing fields, invented approve/sign
methods, malformed ids/correlations/origins, non-32-byte base58 values, invalid
times/ranges, duplicate correlations, and out-of-order traffic. Unique request
and document maps plus a 16-page cap bound live state. Content scripts share the
extension id but fail the exact extension-origin/URL classifier; real Chromium
causally observes disconnect. Review then reject is a one-way state machine.
Navigation/Port loss durably cancels; explicit rejection commits before its
acknowledgement; simultaneous reject/close ends only rejected or cancelled.

Synchronous parent disposal does not pretend it can await IndexedDB. It removes
all routes and disconnects Ports without starting a transition that would race
repository close; a same-turn queued cancellation also stops. Mandatory next-
startup invalidation owns the abandoned pending record. This may delay its
terminal row but never leaves an actionable approval route.

Three meaningful REDs preceded the feature: the six-case core review suite
failed because the projector did not exist; the extension protocol/Port modules
were absent and all 12 new approval provenance cases failed; and production
Chromium returned `net::ERR_FILE_NOT_FOUND` for the exact review URL. Later harsh
review closed duplicate pending responses, regex-only public-key validation,
native Proxy-introspection errors, a widened reject/disconnect microtask, and
late owner calls during runtime teardown.

Official behavior sources:
<https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
<https://developer.chrome.com/docs/extensions/reference/api/runtime>, and
<https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>.
Port disconnect, not a stale lifecycle string, owns navigation/frame teardown;
worker globals are not continuity. Independent second-model review is
**UNVERIFIED**; none ran for C9.

Exact-SHA evidence at `65df16854c1ecfbb5e288091c6dc4d76bd10b700`:
the exact-byte review/intent command passed **98/98**; the closed protocol,
Port, provenance, static-page, and runtime command passed **98/98**; core and
extension typechecks/builds exited **0**; and the rebuilt production extension
passed the real Chromium lane **3/3**. That lane measured zero horizontal
overflow at 720 px and 390 px, controls at least 44 px high, stacked mobile
actions, navigation cancellation, durable rejection, reject/close single-winner
terminalization, exact displayed origin/Memo/network/account/digest, and
content-script rejection. The emitted-artifact scan and esbuild input-graph
fence both passed. Exact commands and generated capture paths are in
`docs/NEXT-SESSION.md`. This C9 ledger-inclusive SHA has not yet run
`env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`; no prior
SHA's verdict is inherited.

**New invariants:** none. `WRD-EXT-01`, `WRD-EXT-02`, `WRD-APR-01`,
`WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; their notes
record this partial review-only composition.

**Residual, stated honestly:** no shipped provider path creates or opens this
record, no approve/sign route exists, and the committed production release
registry is empty. Display is a subset of the projected technical facts and has
no live expiry terminalization. Authority/registry/account/cluster state is not
refreshed by the display projection; a future signer must repeat the full
verdict. There is no simulation, fee/balance consequence, switch binding,
onboarding, send, confirmation, event, or result delivery. A compromised
extension origin remains outside the boundary. Memo is the only decoded verb.
This is a measurable, fail-closed approval review—not a deployable wallet.

### C9 full-gate addendum — 04c810a — 2026-08-31

The ledger-inclusive SHA `04c810a649a537d46e38e0898548c06287cb6ec7`
passed the exact command `env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh`, exit **0**. The command ran the complete pnpm workspace,
core **698/698**, extension **282/282**, production Chromium **3/3**, the pinned
Argon2 worker benchmark, core/extension builds and typechecks, fixture-drift
guard, feature-resolution check, and the complete Rust workspace. Afterward
HEAD remained that SHA, the worktree was clean, and `git diff --check` exited
**0**. This verdict belongs only to `04c810a…`; it does not promote any C9
invariant or remove the residuals above.

---

## Client C10 honest review lifetime and technical disclosure — 7149b72 — 2026-08-31 — **PARTIAL**

**New trust surface:** the existing review-only extension page now owns a
visual deadline loop and an initially closed native technical disclosure. The
page accepts only protocol timestamps inside JavaScript's renderable Date
range, displays the exact ISO expiry plus a live countdown, anchors the
remaining lifetime to both wall time and `performance.now()`, and rechecks on
`visibilitychange`, `focus`, and `pageshow`. Expiry is terminal in the page:
both controls disable, the page states that no signature was produced, and its
Port disconnects. The existing background owner remains the durable clock and
atomically records expiry; the page gained no repository, keyring, RPC,
approval, signer, send, or provider-success capability.

The native `<details>/<summary>` surface reveals every primitive already
derived from the digest-authenticated serialized message: session signer and
account, registry, Warden and Memo programs, genesis hash, recent blockhash,
compute limit, heap frame, serialized-message bytes, and Memo bytes. It is
closed by default, keyboard operable, and has a 48 px minimum summary target.
All values still render through `textContent`; no HTML, caller labels, raw
message bytes, authority objects, or new action methods cross the Port.

**Removed / narrowed:** a response timestamp that `Date#toISOString` cannot
render is now a closed protocol error instead of a post-acceptance page
exception. A backward wall-clock jump cannot extend a currently displayed
request beyond its anchored monotonic lifetime; a forward jump closes it on
the next tick/resume. Frozen-page timers remain best-effort, but the page must
recheck before it is visible/focused/actionable again. The formerly omitted
projected keys and compute facts can now be independently compared with the
exact serialized fixture instead of being hidden from review.

The browser and protocol REDs preceded production code: the focused real-
Chromium lane failed **2/2** because the disclosure and countdown were absent,
and the focused protocol lane failed **1/14** because it accepted a timestamp
one millisecond beyond the ECMAScript Date limit. Harsh verification then
found two stale hard-coded address oracles in the browser test. The session
account and registry were corrected only after independently decoding static
account-key slots 2 and 5 from the golden serialized message. A first custom
artifact scan also failed from its own missing `background` variable; the
corrected executable command is recorded in `docs/NEXT-SESSION.md`. None of
those broken QA attempts is presented as green evidence.

Official behavior sources:
<https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum>,
<https://html.spec.whatwg.org/dev/interactive-elements.html>, and
<https://developer.chrome.com/docs/web-platform/page-lifecycle-api>. Chrome
documents that frozen pages suspend freezable tasks, so the countdown is not
treated as an authorization mechanism. Independent second-model review remains
**UNVERIFIED**; none ran for C10.

Exact-SHA evidence at `7149b727c75476f4919a957c4866d21bdf0f3a1b`:
the extension passed **283/283**, typecheck exited **0**, and the rebuilt real
production extension passed Chromium **4/4**. The review lane verifies exact
technical strings and numbers against serialized-fixture constants, native
Enter-key disclosure, a summary target at least 44 px high, zero horizontal
overflow at 720 px and 390 px after expansion, visible terminal expiry,
disabled controls, and the durable `expired` record. Collapsed desktop,
expanded desktop/mobile, and expired-mobile capture paths plus the exact
commands are in `docs/NEXT-SESSION.md`. The corrected emitted-artifact scan
required the C10 HTML ids while forbidding storage, keyring, RPC, coordinator,
and signer surfaces; it exited **0**. This C10 ledger-inclusive SHA has not yet
run `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`; no
prior SHA's verdict is inherited.

**New invariants:** none. `WRD-EXT-01`, `WRD-EXT-02`, `WRD-APR-01`,
`WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`. This
slice narrows only review lifetime, timeout, and exact-display subclaims; it
does not ship the successful privileged path required by those compound
invariants.

**Residual, stated honestly:** no provider request can successfully create and
launch this page, no approve/claim/sign path is emitted, and the production
release registry remains empty. The page's clock is visual/fail-closed only;
a frozen page does not tick, and the durable owner must remain authoritative.
The displayed projection does not refresh authority, registry, account,
cluster, or release state. There is no simulation, fee/balance/token
consequence model, account/network switching contract, send/confirmation
owner, result delivery, onboarding, or non-Memo verb. This makes the closed
review more truthful; it does not make Warden deployable.

### C10 full-gate addendum — f6fcde9 — 2026-08-31

The ledger-inclusive SHA `f6fcde93d66694ed8e5b6da9cc73489ff1d39aea`
passed the exact command `env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh`, exit **0**. The command ran the complete pnpm workspace,
core **698/698**, extension **283/283**, production Chromium **4/4**, the pinned
Argon2 worker benchmark, core/extension builds and typechecks, fixture-drift
and feature-resolution guards, and the complete Rust workspace. Afterward
HEAD remained that SHA, the worktree was clean, and `git diff --check` exited
**0**. This verdict belongs only to `f6fcde9…`; it does not promote any C10
invariant or remove the residuals above.

---

## Client C11 background-owned approval-window lifecycle — 439c399 — 2026-08-31 — **PARTIAL**

**New trust surface:** the emitted MV3 worker now imports and owns one internal
approval-window launcher. It accepts only a strict request id and an
`AbortSignal` from future trusted background composition. The background, not
the caller, constructs the exact extension review URL and fixes popup type,
focus, requested `720×600` bounds, and `setSelfAsOpener: false`. No caller can
choose a URL, window id, position, incognito state, opener, tab query, or Chrome
options. No runtime Port, extension page, content script, or web page receives
this facade. Provider and popup routes remain fixed unavailable.

The launcher registers `windows.onRemoved` synchronously during worker
evaluation. Before any await it reserves the request id and enforces one window
per request plus a 16-request cap. It snapshots and integrity-validates the
exact durable row as pending before `windows.create`, validates Chrome's result
as a safe non-negative id, refuses active id reuse, calls `windows.get` to close
the create-to-remove race, and snapshots the same row as pending again. URL
input is never accepted and a strict lowercase request id cannot escape the
fixed query slot.

**Removed / narrowed:** provider abort, user window close, create rejection,
undefined/malformed Chrome results, get failure, late create after abort, and a
post-create terminal winner all remove only the owned mapping/window. A still-
pending row is cancelled through the transactional approval owner. If cancel
loses to reject/expiry/invalidation, an exact read may prove that terminal
winner; missing is also non-actionable. If cancel fails and the row remains
pending, or the proving read fails/mismatches, the error enters the parent's
fatal lifecycle, which removes all runtime routes and closes the repository.
No uncertainty is treated as cancellation success.

Synchronous disposal removes the Chrome listener, wakes readiness- or create-
blocked launch callers, closes mapped windows, and arranges best-effort removal
for a window returned after disposal. It deliberately begins no new approval
transition before the parent closes IndexedDB. Worker death discards every
window map; mandatory startup invalidation, not a resurrected global, cancels
the abandoned pending row. Real Chromium force-stops the exact worker while a
popup and proven-pending row remain, observes the popup survive, then observes
the replacement worker have no old marker and read the row as `cancelled`.

The manifest remains exactly `permissions: ["storage"]`. There is no `tabs`,
`activeTab`, `scripting`, host-permission, external-connect, or web-accessible-
resource addition. Chrome's current windows documentation says `tabs` is
needed for sensitive Tab fields; this owner never populates or reads tabs. The
real browser contract loads a temporary extension with no permissions and
observes exact extension URL, popup type, focus, and durable user-close
cancellation. Headless Chrome resolved requested `720×600` bounds as
`1280×720`; requested size is not claimed as a browser-enforced guarantee.

The first module RED failed because the owner did not exist. Subsequent REDs
exposed an already-aborted row left pending, absent production listener/
launcher composition, teardown-blocked promises, a late-created window after
dispose, and unnecessary cancel/read work after a terminal second read. The
first browser dimension assertion also failed by measuring Chrome's headless
window-manager choice as a product guarantee. A later harsh audit found the
dimension/cap tests derived expectations from exported production constants;
commit `d2d6c5b2fc8fdfc0dede6a55e5caa3d3987edbe9` pins independent `720`, `600`,
and `16` oracles. Failed or adaptive harness results are not green evidence.

Official behavior sources:
<https://developer.chrome.com/docs/extensions/reference/api/windows> and
<https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>.
The latter explicitly warns that globals disappear and workers can terminate
unexpectedly. `codex review --commit
1fea6ed8328721b207e2aaa17760f9ecea1b5a16` failed before review because its in-
process app-server client could not initialize on this host's read-only state
path. Independent second-model review remains **UNVERIFIED**.

Exact-SHA evidence at `439c3995d7109f110668c82ddd893672ea679d8a`:
the extension passed **310/310**, typecheck and production build exited **0**,
and real Chromium passed **5/5**. The emitted-artifact command rejected any
test-only window global/marker, coordinator, authority resolver, release, RPC,
session transaction/signer, `chrome.tabs`, host-permission, or external-
connect string; it exited **0**. Exact commands and RED outputs are recorded in
`docs/NEXT-SESSION.md`. This C11 ledger-inclusive SHA has not yet run the full
deploy gate, so no earlier SHA's verdict is inherited.

**New invariants:** none. `WRD-EXT-01`, `WRD-EXT-02`, `WRD-APR-01`,
`WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`. The
launcher narrows lifecycle and exact-cancellation subclaims only.

**Residual, stated honestly:** there is no provider-to-launch production path,
authoritative account/cluster/policy composition, non-empty production release
registry, trusted production RPC endpoint, approve/claim/sign method,
simulation/fee consequence model, send/confirmation owner, or result delivery.
The launcher browser contract uses a test-only static page while another lane
tests the actual production review page; the complete provider→record→window→
review chain is unverified. Provider AbortSignal wiring is unit/composition
evidence, not a reachable production behavior. Current headless Chromium is not
a Chrome 106/store/manual, incognito, multi-monitor, OS-window-manager, or
focus-stealing UX matrix. A future approval method must recheck the durable row,
digest, account, cluster, registry, authority, release, and keyring immediately
before signing. This is a fail-closed internal launcher, not a deployable
wallet.

### C11 full-gate addendum — 9c6f1c0 — 2026-08-31

The ledger-inclusive SHA `9c6f1c0be244534a9bbd99075f2a673cc2ac36e6`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. The gate ran the complete pnpm workspace, core
**698/698**, extension **310/310**, production Chromium **5/5**, the pinned
Argon2 worker benchmark, core and extension builds/typechecks, fixture-drift
and feature-resolution guards, and the complete Rust workspace. It printed
the same SHA before and after the gate and proved a clean worktree. Anchor's
test-program key mismatch notice and legacy macro `cfg` notices were warnings,
not skipped failures. This verdict belongs only to `9c6f1c0…`; it promotes no
C11 invariant and removes none of the residuals above.

---

## Client C12 provider lease-to-preparation owner — cdaa663 — 2026-08-31 — **INTERNAL / UNSHIPPED**

**New internal boundary:** `ProviderApprovalRequestOwner` can consume one exact
live `ProviderPortSession` lease and, only after trusted account/chain
selection, call the existing strict coordinator and C11 fixed-window launcher.
It accepts no Connection, endpoint, release document, program id, deployment
pin, approval decision, signer, send capability, or provider response writer.
The production build lists this module as a forbidden background input, so this
boundary is not reachable from a Port and every emitted provider method remains
fixed unavailable.

The owner independently requires the trusted 32-byte SmartAccount to Base58-
encode to the untrusted page selector and requires any requested chain to match
the trusted chain. Only copied transaction bytes plus Chrome-owned origin, tab,
frame, and document provenance enter `prepare`. A strict returned id and digest
are treated only as a lookup hint: the exact durable row must independently
match that id, digest, provenance, method, account, and chain before the window
opens. This prevents a malformed coordinator return from becoming its own
cleanup proof.

**Removed / narrowed:** duplicate ownership and more than 32 preparing/active
requests reject before asynchronous resolution. Disconnect, open failure,
disposal, or prepared/durable disagreement can affect only the bound durable
id. Cancel success must return the exact terminal binding; a losing cancel is
accepted only after an exact read proves the row terminal or absent. A malformed
locator/digest, wrong browser-owned row, or cancel-plus-read failure is fatal:
the owner locally poisons itself, begins cancellation of its other entries, and
reports to the parent fatal lifecycle. Concurrent settlement and cancellation
use independent proof-buffer snapshots, so one completion cannot zero another
operation's binding during an await.

The focused lane began RED because the module was absent. Its first behavioral
implementation then failed **1/12** because a wrong prepared account made a
correct durable cancellation look unproven; cleanup now rebinds from durable
state. The final focused lane passes **20/20**, including wrong/malformed
coordinator results, cross-browser durable locator, cap/duplicate, disconnect,
window, authority, disposal, terminal-winner, and settle/cancel races. Official
contracts reviewed: Chrome messaging/runtime and the Wallet Standard Solana
extension at
<https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
<https://developer.chrome.com/docs/extensions/reference/api/runtime>, and
<https://github.com/wallet-standard/wallet-standard/blob/master/extensions/solana.md>.
Wallet Standard's signed-byte return and batching surface are not yet provided
by Warden. Independent second-model review is **UNVERIFIED**; none ran for C12.

Exact-SHA evidence at `cdaa6639edcc50fc68aca1923e198540aba9b9cf`:
the exact command recorded in `docs/NEXT-SESSION.md` printed that SHA before and
after, proved a clean tree, passed extension **330/330**, typecheck, production
build, `git diff --check`, and an emitted-worker scan requiring
`WARDEN_METHOD_UNAVAILABLE` while forbidding C12/coordinator/release/RPC/signer
markers. The build's metafile guard independently rejects the C12 source file
and coordinator/release/RPC modules if they become reachable. Ledger-inclusive
full-gate evidence is recorded below.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the invariants JSONL is
intentionally unchanged.

**Residual, stated honestly:** this module is tree-shaken. There is no
authenticated account/cluster selection owner, non-empty committed release,
trusted production RPC/Connection factory, approve/sign method, durable
provider result/replay protocol, simulation/consequence model, send/confirm
owner, Wallet Standard registration/batching, onboarding, or root ceremony.
The outer owner's transaction identity depends on the existing coordinator's
tested transformation and digest; it does not independently duplicate that
authority-dependent transformation. Local fatal poisoning prevents further C12
work, but complete shutdown still requires the parent to honor `onFatal`. This
is a fail-closed internal composition primitive, not deployable wallet behavior.

### C12 full-gate addendum — 537f325 — 2026-08-31

The ledger-inclusive SHA `537f3254b72af593720f3f3d2e0dc9f8c664a7ef`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. It printed the same SHA before and after, proved
a clean worktree, and ran the complete pnpm workspace, core **698/698**,
extension **330/330**, production Chromium **5/5**, the pinned Argon2 worker
benchmark, core/extension builds and typechecks, fixture/ledger/feature guards,
and the complete Rust workspace. The known Anchor test-program key mismatch
notice and legacy macro `cfg` notices were warnings, not skipped failures. This
verdict belongs only to `537f325…`; the evidence-only follow-up does not inherit
it or promote an invariant.

---

## Client C13 authenticated committed-release selection — 63521de — 2026-08-31 — **INTERNAL / UNSHIPPED**

**New internal boundary:** the still-unreachable
`CommittedProviderApprovalSelectionResolver` accepts one repository-configured
release name, a zero-argument trusted Connection factory, the approval owner,
and the keyring lifecycle. It resolves the committed release before reading any
other capability. The actual registry is empty, so production composition fails
before Connection, keyring, approval, clock, or TTL access. Page-controlled
account/chain selectors, RPC URL, release statement, program id, and deploy pin
cannot choose those capabilities; C12 separately compares account/chain after
selection.

The emitted keyring lifecycle now exposes an authenticated public-identity read
to background code. It uses the existing exact unlock lease, v2 record AAD,
strict signer-payload schema, decrypt/readback checks, and derives only the
Ed25519 public half from an isolated seed copy. Caller-visible results contain
copied account, genesis hash, program id, and public signer bytes, never the
seed. The exact unlock generation's stable `AbortSignal` accompanies those
facts. Every plaintext/intermediate byte array owned by the method is cleared
on settlement; JavaScript overwrite is still best effort, not VM erasure.

**Removed / narrowed:** the resolver requires two complete public identity
snapshots to match the committed release, each other, and the same signal object.
A lock/record replacement/re-unlock therefore wins even if the replacement has
identical public bytes. Already-revoked and second-read-revoked generations are
rejected. C12 snapshots the returned signal before preparation, propagates it
through durable recovery, and combines it with the provider signal for the C11
window lifetime. Either revocation synchronously aborts the window signal and
starts cancellation of the exact proven durable row. Revocation in the async
resolver settlement gap prevents `prepare`; revocation while `prepare` is in
flight recovers and cancels the exact row; revocation after launch closes the
window lifetime and cancels. Listener install plus immediate state inspection
shares one cleanup scope so a malformed signal cannot strand an active entry.

The first helper/keyring/selection runs were RED because the APIs/modules did
not exist. The first generation-aware adversarial run then failed **7/37** and
proved the resolver Promise gap, same-bytes re-unlock blindness, preparation
race, and active-window race. The corrected focused lane passes **39/39**.
Exact commands and the individual RED counts are recorded in
`docs/NEXT-SESSION.md`; failed runs are not accepted as verification.

Official contracts reviewed:
<https://solana.com/docs/rpc/http/getgenesishash>,
<https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Connection.html>,
<https://developer.chrome.com/docs/extensions/reference/api/storage>, and
<https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/events>.
The factory is only a trust-boundary shape: no real endpoint, release, or live
genesis query exists here. Independent second-model review remains
**UNVERIFIED**; none ran for C13.

Exact-SHA evidence at `63521de32b7b1be425aeaaed504c1e177d689c4b`:
the exact clean-tree command in `docs/NEXT-SESSION.md` passed core **699/699**,
extension **347/347**, both typechecks, both builds, `git diff --check`, and an
emitted-worker scan. It printed the same SHA before and after. The artifact
contains the public identity helper/read boundary and the fixed
`WARDEN_METHOD_UNAVAILABLE` provider, while C12, C13, committed-release, and
coordinator markers are absent. The build metafile independently forbids those
source inputs. This ledger-inclusive SHA has not yet run the full repository
gate; no earlier verdict is inherited.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the invariants JSONL is
intentionally unchanged.

**Residual, stated honestly:** the happy resolver path uses mocked committed
release/coordinator factories. The only real registry behavior is refusal, and
“source-owned” is conditional on a future reviewed runtime composition. The v1
payload intentionally stores no redundant public key, so selection decrypts the
seed twice to derive it; seed bytes stay internal and are scrubbed, but this is
still additional plaintext exposure and computation. The generation signal
revokes synchronously on explicit lifecycle transitions, not merely because a
wall-clock deadline passes without another keyring check. The emitted provider
cannot prepare an approval. There is no committed release, trusted endpoint,
approve/claim/sign route, durable provider result/replay owner, simulation,
fee/balance consequence model, send/confirmation owner, onboarding, Wallet
Standard registration/batching, or root ceremony. C13 reduces authority
confusion in code that remains unreachable; it does not make Warden deployable.

### C13 full-gate addendum — 8355394 — 2026-08-31

The ledger-inclusive SHA `835539457aa211a1ebfe8ac46f52b2a563b8c8ba`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. It printed the same SHA before and after, proved
a clean worktree, and ran the complete pnpm workspace, core **699/699**,
extension **347/347**, production Chromium **5/5**, the pinned Argon2 worker
benchmark, core/extension builds and typechecks, fixture/ledger/feature guards,
and the complete Rust workspace. The known Anchor test-program key mismatch
notice and legacy macro `cfg` notices were warnings, not skipped failures. This
verdict belongs only to `8355394…`; the evidence-only follow-up does not inherit
it or promote an invariant.

---

## Client C14 durable provider operation / result replay — ad66c16 — 2026-08-31 — **INTERNAL / UNSHIPPED**

**New internal boundary:** one stable operation identity commits the exact
closed `solana:signTransaction` request (correlation, selector, chain, options,
and transaction bytes) to Chrome-owned extension/origin/tab/frame/document
provenance. Volatile background ids and request timestamps are excluded so the
same document can recover after Port reconnect or MV3 restart; changing any
request/provenance discriminator derives a different SHA-256 key.

A separate IndexedDB database owns strict `preparing`, `bound`, and `failed`
records. A unique claim commits before one callback may create a durable
approval. Competing connections cannot both invoke preparation. The callback
may not open a window or sign; it returns only the approval id and exact approved
message digest, which are durably attached to the request digest. Startup fails
all abandoned preparations rather than resuming them. This ordering sacrifices
liveness in the cross-database crash gap and makes no cross-DB atomicity claim.
The journal caps 32 preparing and 128 total rows and prunes terminal rows after a
ten-minute replay horizon, so at-most-once preparation is asserted only while
the row is retained.

The terminal owner rederives the exact current request identity, reads its bound
locator, checks the approved row's id/digest/provenance/method/account/chain, and
uses the core durable signed-result verifier. That verifier atomically reads the
approval/outcome pair, strictly reparses the signed transaction, recomputes and
matches the approved message digest/raw bytes, requires exactly one signer and
signature, and verifies Ed25519. No coordinator, RPC, keyring, or signing retry
is required. The success response copies signed transaction bytes and exposes no
approval or authority object.

**Delivery constraint:** Chrome Port enqueue is not a page receipt. No delivered
bit is persisted; enqueue failure permits replay of the same committed bytes
without another signing attempt. Enqueue success followed by lost in-memory
ownership remains an ambiguous delivery and future page code must deduplicate
the stable correlation id. C14 provides no page acknowledgment protocol.

The meaningful module REDs were the missing core restart reader (**1 failed / 42
passed**) and missing extension operation module (collection failure). The final
C14 unit lane passes **11/11**. Native Chromium opens competing IndexedDB
connections, observes one callback, force-stops the exact worker, proves globals
were lost, then observes bound replay without a callback and startup failure of
the interrupted row. Official contracts reviewed: Chrome service-worker
lifecycle, messaging, and runtime `documentId`, plus Anza's Wallet Standard and
reference Solana wallet implementation; exact links and commands are in
`docs/NEXT-SESSION.md`.

Independent second-model review is **UNVERIFIED**. `codex review --commit
ad66c1633bea96e5cda14e96ab8982c3ae824985` exited before review because the
in-process app-server client could not initialize on this host's read-only state
path.

Exact implementation-SHA evidence at
`ad66c1633bea96e5cda14e96ab8982c3ae824985`: the commands recorded in
`docs/NEXT-SESSION.md` passed core **699/699**, extension **358/358**, both
typechecks/builds, real Chromium **6/6**, `git diff --check`, clean-tree proof,
and an emitted-artifact scan. The build metafile forbids all C12–C14 owner/result
modules and the coordinator; both emitted page/background bundles retain
`WARDEN_METHOD_UNAVAILABLE` and contain no C12–C14/coordinator markers. This
ledger-inclusive SHA has not yet run the full repository gate; no earlier gate
verdict is inherited.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the invariants JSONL is
intentionally unchanged.

**Residual, stated honestly:** C12 currently opens the approval window inside
`launch()` before returning, so it cannot satisfy C14's bind-before-visible-
action contract. It must be split into prepare/prove, operation bind, and window
open phases, with disconnect/keyring-revocation cleanup across each boundary.
The operation and approval stores are separate; a crash can strand an invisible
pending row. Retention is bounded. Extension terminal tests use a signed-reader
seam while the actual cryptographic replay path is tested in core; the Chromium
lane does not produce a real signature. No success language is emitted. There
is still no non-empty committed release, trusted endpoint, approve/sign action,
simulation or fee/balance consequences, send/confirmation owner, page receipt
deduplication, Wallet Standard registration/batching, onboarding, or root
ceremony. C14 narrows restart/replay risks in unreachable code; it does not make
Warden deployable.

### C14 full-gate addendum — 19557ff — 2026-08-31

The ledger-inclusive SHA `19557ff540c6e5701f619378979e9e595d0b954e`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. It printed the same SHA before and after, proved
a clean worktree, and ran the complete pnpm workspace, core **699/699**,
extension **358/358**, production Chromium **6/6**, the pinned Argon2 worker
benchmark, core/extension builds and typechecks, fixture/ledger/feature guards,
and the complete Rust workspace. The known Anchor test-program key mismatch
notice and legacy macro `cfg` notices were warnings, not skipped failures. This
verdict belongs only to `19557ff…`; the evidence-only follow-up does not inherit
it or promote an invariant.

---

## Client C15 bind-before-open composition — a9271c9 — 2026-08-31 — **INTERNAL / UNSHIPPED**

**Closed ordering gap:** C12 now separates durable approval preparation from
window visibility. `prepare()` proves the exact pending row and installs Port
and keyring-generation cancellation ownership without invoking the window
launcher. Its `open()` edge is Promise-idempotent and rechecks owner, Port,
authority, and active-row state before and after the launcher. The compatibility
`launch()` wrapper still performs prepare then open.

C15 composes that split through C14. The operation journal claims the stable
browser request before its callback. The callback stops after C12 preparation
and returns only the approval id/digest. Only a newly created operation whose
exact binding is durably proven may invoke `open()`. A retained binding returns
`replay-required` without another preparation or window, including when the
first window failed and the bound approval was subsequently cancelled.

Every failure after a handle exists attempts its exact cancellation. The
focused executable lane proves no window on an unproven bind, Port disconnect
or authenticated-authority revocation during a delayed bind, and malformed
visibility capability. It also proves binding remains the sole replay locator
when open fails after commit. Harsh review found and fixed a draft cleanup hole
where handle validation preceded retention of its cancel capability.

The meaningful REDs were one missing `prepare()` case (**1 failed / 23 passed**)
and then a missing C15 module collection failure. Final focused C12/C15 is
**31/31**. Exact implementation-SHA evidence at
`a9271c979ea2707f4d0c92ddd0d03db5e2e0ce3d` passed extension **366/366**,
typecheck, build, real Chromium **6/6**, emitted-artifact exclusion,
`git diff --check`, and clean-tree checks using the exact combined command in
`docs/NEXT-SESSION.md`. The build metafile forbids C15 and all C12–C14 provider
owner/result modules; emitted background/content remain fixed-unavailable and
contain none of their markers. No ledger-inclusive SHA has yet run the full
repository gate; no earlier verdict is inherited.

Independent second-model review is **UNVERIFIED**. `codex review --commit
a9271c979ea2707f4d0c92ddd0d03db5e2e0ce3d` exited before review because the
in-process app-server client could not initialize on this host's read-only state
path.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the invariants JSONL is
intentionally unchanged.

**Residual, stated honestly:** C15 is the intended ordering path, not a runtime
capability proof against every internal caller. C12 still exports its legacy
`launch()` and prepared `open()` edges; production is safe only because the
build forbids this entire graph. Before enablement, composition must expose only
C15 or remove/guard the bypass. Separate operation and approval databases still
have a crash gap; worker death after a bound commit but before open also loses
review liveness because replay may not reopen. C15 ordering is unit-tested with
an in-memory journal while native IndexedDB and worker restart are separately
browser-tested in C14; there is no single real-browser signature flow. Page
delivery has no receipt/deduplication protocol. No success language is emitted,
and release/RPC authority, approve/sign action, consequence review,
send/confirmation, Wallet Standard, onboarding, and root ceremony remain absent.
C15 closes one internal ordering defect; it does not make Warden deployable.

### C15 full-gate addendum — a292000 — 2026-08-31

The ledger-inclusive SHA `a2920004847b89e13385f4ea1689684dc4c60fbc`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. It printed the same SHA before and after, proved
a clean worktree, and ran the complete pnpm workspace, core **699/699**,
extension **366/366**, production Chromium **6/6**, the pinned Argon2 worker
benchmark, core/extension builds and typechecks, fixture/ledger/feature guards,
and the complete Rust workspace. The known Anchor test-program key mismatch
notice and legacy macro `cfg` notices were warnings, not skipped failures. This
verdict belongs only to `a292000…`; the evidence-only follow-up does not inherit
it or promote an invariant.

---

## Client C16 main-world terminal idempotence — d376a88 — 2026-08-31 — **INTERNAL / UNSHIPPED**

**Closed replay/alias gap:** a new page request owner accepts only one closed
`solana:signTransaction` input, copies it through the existing parser, mints its
own 128-bit Web Crypto correlation, and installs the pending Promise before
posting the exact direction-tagged envelope. The page never chooses the
correlation. Issued ids remain tombstones for the bounded document lifetime, so
success, unavailable error, timeout, send failure, and disposal cannot release
an id for a later request. Eight collision attempts fail closed.

One module instance claims one page object and never releases that claim after
disposal. This closes the draft's disjoint-registry hole where two owners on the
same document could each issue and accept one coincidentally equal correlation.
Construction failure removes/inerts any partially registered listener and rolls
back the claim; a completed owner cannot be replaced within that module
instance.

Only an exact same-window/same-origin response wrapper containing either the
strict C14 signed-transaction response or fixed-unavailable response is
recognized. These event fields route traffic but grant no authority. The owner
removes the exact pending entry and timer before its first resolve/reject, copies
the signed bytes, and ignores every late duplicate, conflicting terminal,
unknown id, wrong context, outer-envelope accessor, sparse byte array, or
malformed/open envelope. Limits are 32 pending, 1,024 issued per document, a
two-minute default TTL, and a ten-minute maximum. Timers are backed by absolute-time checks and
reschedule if early.

Chrome's official messaging/runtime contracts and the Window messaging contract
provide enqueue APIs, not a page-consumption receipt. C14 therefore remains
correct not to persist a delivered bit. C16 narrows the eventual page behavior
to at-most-one Promise settlement per retained owner-issued id. Web Crypto's
official `getRandomValues` contract supplies the random bytes, and the Wallet
Standard reference implementation confirms that sign-transaction results carry
signed bytes. Exact source links are recorded in `docs/NEXT-SESSION.md`.

The focused RED was a missing-module collection failure. The final focused lane
passes **14/14**, including reverse-order concurrency, first-terminal wins,
collision/non-reuse, transport failure, absolute timeout, hostile schemas,
bounded counts, listener rollback, disposal, and single-document ownership.
Exact implementation-SHA evidence at
`d376a885937066b3f54a661fa6ae09fc3b920d5d` passed extension **380/380**,
typecheck, build, real Chromium **6/6**, emitted-artifact exclusion,
`git diff --check`, and clean-tree proof with the combined command in
`docs/NEXT-SESSION.md`. Production content/background still contain only the
unavailable protocol; C12–C16 markers are absent.

Independent second-model review is **UNVERIFIED**. `codex review --commit
d376a885937066b3f54a661fa6ae09fc3b920d5d` exited before review because the
in-process app-server client could not initialize on this host's read-only state
path.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the invariants JSONL is
intentionally unchanged.

**Residual, stated honestly:** the owner is not in any emitted bundle. Its
single-owner WeakSet is scoped to one evaluated module and is not proof against
a separately reinjected bundle; actual MAIN-world injection must prove one
evaluation per document in Chromium. Same-page JavaScript is the hostile caller
principal and can forge/suppress terminal traffic or interfere with main-world
platform methods. C16 has no Port-disconnect signal, retry, receipt ACK, or
durable page state, and it does not bind page-visible success cryptographically
beyond the correlation; the trusted background owns exact operation binding.
There is no Wallet Standard registration/batching, real-browser successful
provider path, non-empty release/trusted RPC, approve/sign action, consequence
review, send/confirmation, onboarding, or root ceremony. This is an internal
replay primitive, not a deployable wallet feature.

### C16 full-gate addendum — a7a5301 — 2026-08-31

The ledger-inclusive SHA `a7a5301c9ab97aecb169f7482f100e5e46c1d58d`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. It printed the same SHA before and after, proved
a clean worktree, and ran the complete pnpm workspace, core **699/699**,
extension **380/380**, production Chromium **6/6**, the pinned Argon2 worker
benchmark, core/extension builds and typechecks, fixture/ledger/feature guards,
and the complete Rust workspace. The known Anchor test-program key mismatch
notice and legacy macro `cfg` notices were warnings, not skipped failures. This
verdict belongs only to `a7a5301…`; the evidence-only follow-up does not inherit
it or promote an invariant.

---

## Client C17 exact approval action — b36aeec — 2026-08-31 — **INTERNAL / UNSHIPPED**

**New internal authority surface:** C17 introduces the first extension-side
capability that can ask the exact live C12 coordinator to sign. It is not
reachable in the production build. A volatile `ProviderApprovalActionOwner`
copy-binds a background-minted approval id and digest to bound `approve` and
`settle` methods plus the provider/keyring lifetime signal. It holds no key,
transaction, endpoint, release, Connection, or signed result. Duplicate ids,
the 32-entry cap, malformed methods/signals, listener failure, disposal, and an
already-ended lifetime fail closed.

C15 now requires this registry. Its order is executable: durable provider
operation claim → C12 approval preparation → durable operation/approval bind →
synchronous action registration → window open. The facade returned after open
strips `approve`, `signal`, and `open`; only the registry retains the action.
Any registration or later open failure cancels the exact prepared row. The
production build explicitly forbids the C17 action module and all C12–C16
provider/signing/page owners, so this internal composition cannot reach funds
in the shipped extension.

C12 owns one Promise-idempotent coordinator call. It chooses the already-bound
id/digest, validates and scrubs all accessible returned digest/transaction/
signature copies, proves the exact durable row is `approved`, and returns only
a boolean. Id or digest substitution poisons the owner. A shaped signed result
without an exact approved durable row is refused. Provider or keyring lifetime
loss during the coordinator await suppresses page success even if a durable
signed outcome won the race; C14 is the only intended replay route.

The approval protocol admits `approval:approve` with exactly one page-provided
field: the URL/provenance-bound request id. The background reads the trusted
pending row and computes `canApprove` by matching its binary digest against the
volatile registry. The page cannot choose the digest, bytes, account, chain,
release, RPC, or signer. Success contains only approved status and request id;
no transaction or signature crosses the UI Port. Rejection, navigation,
disconnect, malformed messages, and missing capability terminalize the durable
row and settle/drop any surviving route. Production composes no action owner,
so `canApprove` remains false and real Chromium still sees a disabled button.

The meaningful REDs were a missing action module, **2 failed / 30 passed** for
the absent C12 action handle, a missing approved-response constructor, and
**3 failed / 8 passed** for the unbound Port action. Final focused
C12/C15/action/protocol/Port is **69/69**. Harsh self-review additionally found
and fixed false-fatal reporting after normal route self-removal and digest
cleanup on malformed capability binding.

Exact implementation-SHA evidence at
`b36aeecd3c2b49ee18144ab1144d46dcddddd88f` passed extension **395/395**,
typecheck, build, production Chromium **6/6**, emitted-artifact exclusion,
`git diff --check`, identical before/after SHA, and clean-tree proof with the
combined command recorded in `docs/NEXT-SESSION.md`. The build metafile rejects
C17 and every earlier internal provider owner; emitted background/content still
retain the fixed-unavailable marker. No ledger-inclusive SHA has yet run the
full repository gate, and no earlier verdict is inherited.

Primary Chrome MV3/runtime, Solana blockhash/genesis RPC, and Wallet Standard
contracts reviewed for this boundary are linked in `docs/NEXT-SESSION.md`.
MV3 global state is ephemeral, so C17 deliberately never recreates pending
signing authority from durable storage. This is an architectural inference:
durable identity supports replay and invalidation, not resurrection of an
in-memory keyring/coordinator capsule.

Independent second-model review is **UNVERIFIED**. `codex review --commit
b36aeecd3c2b49ee18144ab1144d46dcddddd88f` exited before review because the
in-process app-server client could not initialize on the host's read-only state
path.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the invariants JSONL is
intentionally unchanged.

**Residual, stated honestly:** there is no non-empty committed production
release, trusted production endpoint, reviewed real deployment, or production
composition of the coordinator/action/result/page graph. The real browser lane
proves that signing stays disabled, not that a signature succeeds. Unit lanes
compose the real C12/C15/action registry and separately exercise the Port, but
there is no one-browser action → durable signature → C14 result → C16 Promise
test. Worker restart drops pending actions by design; pending-row startup
invalidation and already-signed replay remain separate owners. An approved UI
terminal proves neither provider delivery nor page consumption. Legacy internal
open/launch bypasses, consequence review, Wallet Standard batching and
registration, send/confirmation, onboarding, production KDF policy, root
ceremony, and external audit remain. C17 reduces authority ambiguity in
unreachable code; it does not make Warden deployable.

### C17 full-gate addendum — 4fd8fc9 — 2026-08-31

The ledger-inclusive SHA `4fd8fc979c4ac7f1c3af6378dc047d64548d17a9`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. It printed the same SHA before and after, proved
a clean worktree, and ran the complete pnpm workspace, core **699/699**,
extension **395/395**, production Chromium **6/6**, the pinned Argon2 worker
benchmark, core/extension builds and typechecks, fixture/ledger/feature guards,
and the complete Rust workspace. The known Anchor test-program key mismatch
notice and legacy macro `cfg` notices were warnings, not skipped failures. This
verdict belongs only to `4fd8fc9…`; the evidence-only follow-up does not inherit
it or promote an invariant.

---

## Client C18 signed-result composition — 47f728b — 2026-08-31 — **INTERNAL / UNSHIPPED**

**New internal composition surface:** C18 adds no signer, key, release, RPC,
Port listener, page listener, or signed-byte reader. Its bounded
`ProviderSignedResultFlowOwner` joins C15's approval launch to the existing C14
terminal-result owner by passing one exact browser-owned delivery lease through
both. For a new operation it waits for C12's byte-free terminal Promise; for a
retained bound operation it bypasses preparation and delegates directly to C14.
The same exact in-memory request shares one Promise, the owner refuses a 33rd
unresolved flow, and a completed/rejected flow releases its capacity.

The critical state distinction is now executable. `ApprovalRecord.state === "approved"`
is the core repository's atomic signing-**claim** state, not proof
that `completeSigning()` committed transaction bytes. The coordinator claims
before post-claim authority checks, blockhash validity, keyring use, exact-byte
signing, reparsing, signature verification, and durable completion. C12 may
therefore resolve its terminal `true` only after the exact coordinator Promise
returns a structurally valid signed result and an independent read matches the
exact approved binding. Cancellation and settlement await any already-started
approve Promise before resolving `false`, so an approved claim cannot race a
false result while the coordinator can still prove completion. First settlement
wins; fatal owner poisoning resolves false. C14 then independently checks the
operation identity, approval/browser binding, durable `signed` outcome, exact
message digest, transaction envelope, and Ed25519 signature before constructing
the provider response. The boolean never grants access to transaction bytes.

Provider loss after durable completion causes the first delivery lease to fail;
replacement-worker C15 sees the retained operation and C14 replays without a
new prepare or sign. Keyring-lifetime loss still makes the volatile approval
action reject, but if the coordinator had already completed the durable signed
result, C18 may deliver it while the provider lease remains active. This is a
commit-point rule, not authority resurrection: C17's action registry remains
volatile and cannot be reconstructed from storage.

The meaningful RED was the missing C18 module (Vitest exited **1** before
collection). Final focused C12–C18/Port/page evidence is **87/87**. The
implementation SHA `47f728b5769c679feaafbc51d8e4218bbac52b1f` passed extension
**403/403**, typecheck, build, production Chromium **6/6**, emitted-artifact
exclusion, identical before/after SHA, `git diff --check`, and clean-tree proof
with the exact command recorded in `docs/NEXT-SESSION.md`. The production build
metafile explicitly forbids C18 and every earlier internal provider/signing/page
owner; emitted background and content bundles retain the fixed-unavailable
marker. Ledger-inclusive full-repository evidence is not yet claimed.

Independent second-model review is **UNVERIFIED**. `codex review --commit
47f728b5769c679feaafbc51d8e4218bbac52b1f` exited before review because its
in-process app-server client could not initialize on this host's read-only state
path.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.

**Residual, stated as a threat:** the integration test manually forwards C14's
exact response envelope through a fake page window and uses C14's explicit
`readSigned` test seam. The real content bridge accepts only the unavailable
response, and real Chromium proves the feature remains disabled rather than
proving a cryptographic signing flow. No owner yet preserves the original C16
Promise across content/background disconnects, maps rejection/cancellation/
expiry into strict page-terminal errors, or acknowledges page consumption;
Chrome `postMessage()` is only enqueue. There is still no non-empty reviewed
release, trusted RPC, production coordinator/keyring composition, real-browser
signature test, Wallet Standard registration, send/confirmation, onboarding,
production KDF policy, root ceremony, consequence review, or audit. C18 closes
an internal result-scheduling race only; it is not deployment evidence.

### C18 full-gate addendum — eaeb26c — 2026-08-31

The ledger-inclusive SHA `eaeb26c55925e9dfe01c123d8bd0431cd57ad80a`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. It printed the same SHA before and after, proved
a clean worktree, and ran the complete pnpm workspace, core **699/699**,
extension **403/403**, production Chromium **6/6**, the pinned Argon2 worker
benchmark, core/extension builds and typechecks, fixture/ledger/feature guards,
and the complete Rust workspace. The known Anchor test-program key mismatch
notice and legacy macro `cfg` notices were warnings, not skipped failures. This
verdict belongs only to `eaeb26c…`; this evidence-only follow-up does not inherit
it or promote an invariant.

---

## Client C19 closed provider terminal outcomes — 322c28b — 2026-08-31 — **INTERNAL / UNSHIPPED**

**Threat closed internally:** C18 previously knew only “signed terminal true”
versus an exception. That was insufficient for user rejection, cancellation,
expiry, worker interruption, preparation failure, invalidation, or a durable
failed signing attempt, and it invited an unsafe exception → page-error
translation. C19 introduces a durable classifier that derives the exact
browser-owned provider-operation identity and then rechecks the complete
operation → approval → signing binding before selecting any response.

Only an approval whose atomic signing outcome is exactly `signed` can delegate
to C14. A merely `approved` row with no outcome or `signing` remains
non-terminal and produces no response. Exact failed states map to four fixed
public outcomes: user rejected, request cancelled, request expired, or generic
request failed. Internal signing failure codes, raw exceptions, RPC failures,
keyring state, and stack text are never serialized. C16 recognizes only the
exact code/message pairs and removes the original pending entry before rejecting
its owner-minted Promise; late success cannot reverse that tombstone.

Harsh review found that C13 intentionally throws for a retained `failed`
operation rather than returning C15's `replay-required`. C18 now attempts C19
recovery after a rejected launch, but only C19's exact durable proof can turn
that into delivery. If recovery is absent, non-terminal, malformed, inactive,
or returns anything other than literal `true`, the path fails closed. A
malformed successful launch is not eligible for this fallback. No catch around
C14 translates a possibly-enqueued success into an error response.

The missing-module RED exited 1 before collection. Focused C18/C19/C16 evidence
is **46/46**; the complete extension lane is **430/430**. Exact clean-SHA
evidence at `322c28b358528f53b76cb0d636f1bcb07d57b207` passed extension tests,
typecheck, build, production Chromium **6/6**, emitted-artifact exclusion,
`git diff --check`, identical before/after SHA, and clean-tree proof with the
full command recorded in `docs/NEXT-SESSION.md`. Production build metadata and
artifact scanning prove the C19 outcome owner, terminal error codes, and every
C12–C18 provider/signing/page owner remain absent; emitted content/background
retain only `WARDEN_METHOD_UNAVAILABLE`.

Primary lifecycle/error evidence is linked in `docs/NEXT-SESSION.md`: Chrome's
runtime, messaging, and MV3 service-worker contracts plus the Wallet Standard
reference Solana wallet. The four Warden error codes are a closed internal
protocol choice, not a claimed Wallet Standard taxonomy. Independent
second-model review is **UNVERIFIED** because `codex review --commit
322c28b358528f53b76cb0d636f1bcb07d57b207` failed before model startup on the
host's read-only app-server state path.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.

**Residual, stated as a threat:** all success/failure page integration remains
fake-window only. The real content script intentionally rejects these terminal
messages, stores no exact outstanding request, performs no bounded resend after
Port loss, and has no receipt acknowledgment. A page Promise can still hang to
its absolute timeout despite a durable result. There is no non-empty reviewed
release, trusted production RPC, production coordinator/keyring graph,
real-browser signature, Wallet Standard registration, send/confirmation,
onboarding, production KDF policy, root ceremony, consequence review, or audit.
C19 is a safer unreachable protocol primitive, not deployable wallet behavior.

**Ledger-gate correction:** the first full-repository attempt at ledger SHA
`7e196697cd3034006b5d996a2fa33b416ce26002` was **red**, despite core reaching
699/699: the extension stopped at 429/430 because its concurrent-operation test
used one microtask yield as a proxy for completion of asynchronous WebCrypto
identity derivation. Under the full workspace scheduler, the second call could
become claimant and deadlock the harness. Test-only commit
`267163b5769cc8547b00d6417538acc784f33b50` replaces that timing guess with an
explicit first-preparation signal. The exact clean-SHA command recorded in
`docs/NEXT-SESSION.md` then exited 0 at `267163b…`, including core 699/699,
extension 430/430, production Chromium 6/6, the remaining TypeScript workspace,
build/type checks, KDF benchmark, and Rust workspace. This ledger addendum is an
evidence-only commit and does not inherit that verdict.

---

## Client C20 bounded content transport recovery — b09f41b — 2026-08-31 — **INTERNAL / UNSHIPPED**

**New internal transport surface:** C20 adds a build-excluded content owner for
C16's exact `solana:signTransaction` request. It closes over one canonical copy
of each accepted request and can resend that same object once after loss of its
active Chrome Port generation. It never changes the correlation, account,
transaction, chain, or options, and it grants no browser provenance, approval,
RPC, release, key, or signing authority. Background owners must still rederive
the request identity from Chrome-owned sender provenance and durable state.

The owner caps pending requests at 32, document-lifetime correlations at 1,024,
automatic recovery attempts at one, and retention at a two-minute default /
ten-minute maximum absolute TTL. It opens lazily, never reconnects an idle
document, and spends recovery budget before opening the replacement, so
synchronous disconnect/setup behavior cannot create an unbounded MV3 wake
loop. Expiry removes volatile content state without claiming the durable
request failed; C16's independent deadline remains the page settlement owner.

Only exact unavailable, signed, or C19 terminal-failure responses are accepted.
A response must match a pending correlation and that request's active Port
generation. It is reconstructed before forwarding, and pending state is
removed before `window.postMessage()`, making first exact terminal settlement
authoritative under reentrancy. Malformed background data closes the boundary
without reflecting private detail. Stale Port callbacks, unknown correlations,
late terminal values, and duplicates cannot reach the page.

The meaningful REDs were the missing module, a **13 pass / 1 fail** review that
exposed time-unbounded retention, and a **15 pass / 1 fail** review that exposed
one final `Port.postMessage()` after a delayed connect crossed the deadline.
The focused lane is now **16/16** and the complete extension lane is **446/446**.
Exact clean-SHA evidence at
`b09f41b08736285512209935435a7d2b4c264976` passed extension tests, typecheck,
build, production Chromium **6/6**, emitted-artifact exclusion, `git diff
--check`, identical before/after SHA, and clean-tree proof with the full command
recorded in `docs/NEXT-SESSION.md`. The emitted content bundle retains only the
fixed-unavailable path; C20 and the earlier terminal/page owners are absent.

Chrome service-worker lifecycle, messaging, and runtime Port contracts are
linked in `docs/NEXT-SESSION.md`. They support demand-bound reconnection and
strict handling of disconnected Ports; they do **not** prove that content-side
enqueue is page consumption or promise a safe cross-context order between the
old Port's cleanup and a replacement connection. Independent second-model
review is **UNVERIFIED** because `codex review --commit b09f41b…` exited before
review when its in-process app-server client could not initialize on the
host's read-only state path.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.

**Residual, stated as a threat:** the immediate content reconnect can arrive
while the incumbent background boundary still owns the old Port for the same
browser `documentId`; that boundary rejects the replacement. C20 has no real
Chromium worker-death or old/new-Port ordering evidence, no page receipt ACK,
and no per-request cancellation message. Page, content, and background TTLs are
separate clocks/configurations. Its 1,401 lines are unit-tested complexity in
unreachable code, not shipped value. A future background replacement/replay
owner must make either disconnect ordering safe without resurrecting a dead
volatile approval or signing capability, then compose and browser-test the
deadline path. All non-empty release, trusted RPC, production keyring/
coordinator, real-browser signing, Wallet Standard, send, onboarding, KDF,
ceremony, consequence-review, and audit blockers remain.

### C20 full-gate addendum — 66dd2ca — 2026-08-31

The ledger-inclusive SHA `66dd2cad0d79047ca5ca42e6a5414275ed7263b7`
passed this exact command, exit **0**: `git rev-parse HEAD && test -z "$(git
status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash
.claude/test-gate.sh && git diff --check && git rev-parse HEAD && test -z
"$(git status --porcelain)"`. It printed the same SHA before and after, proved a
clean worktree, and ran the complete pnpm workspace, core **699/699**, extension
**446/446**, production Chromium **6/6**, the pinned Argon2 worker benchmark,
core/extension builds and typechecks, fixture/ledger/feature guards, and the
complete Rust workspace. The known Anchor test-program key mismatch and legacy
macro `cfg` notices were warnings, not skipped failures. This verdict belongs
only to `66dd2ca…`; this evidence-only follow-up does not inherit it or promote
an invariant.

---

## Client C21 background replacement-Port ownership — cd0cc9c — 2026-08-31 — **INTERNAL / UNSHIPPED**

**Threat closed internally:** C20 could reconnect before the old background
Port owner observed cleanup, while the production unavailable boundary rejects
a second Port for the same `documentId`. C21 replaces that ordering assumption
with one browser-provenance route. An overlapping exact Port generation
preserves the existing volatile request lease; a cleanup-first disconnect
aborts that lease permanently and a later generation must rely on the durable
C13–C19 operation graph. Old callbacks are generation-stale, and no terminal
response may cross a replacement until that generation has presented the same
correlation and completed the same SHA-256 operation identity. Payload or
provenance drift closes the route.

Admission is bounded at 256 documents, 32 pending/hash-blocked messages, 1,024
correlations, one replay per correlation, and 2,048 unique background request
ids. Same-worker replay retains the initial background receive deadline;
hashing that finishes at or after that deadline cannot mint a lease. A typed
operation-identity input replaces the prior temptation to forge a partial
`OwnedProviderRequest`. Build metadata forbids C21 and all earlier provider
authority/result/page owners from production.

The focused C21 lane is **15/15** and the complete extension lane is
**462/462**. Chromium is **8/8**, including two new measured contracts: real
overlapping content Ports preserve exactly one volatile flow and deliver only
on the verified replacement; real CDP worker death composes C20, C21, the
IndexedDB operation owner, and C19 so one preparing row becomes one fixed page
cancellation without a second preparation. Exact clean-SHA command and
artifact scan are recorded in `docs/NEXT-SESSION.md` at
`cd0cc9cd1b7802fe99b78e6f7addeb8f2c0b8a21`.

The first complete extension attempt was **red at 461/462** because the new
test counted digest invocation rather than completion. That QA defect could
reward unfinished state; unit and Chromium barriers now count completed
digests. Independent second-model review remains **UNVERIFIED** because
`codex review --commit cd0cc9c…` failed before model startup on the host's
read-only app-server state path.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.

**Residual, stated as a threat:** the browser worker-death proof deliberately
delivers a durable failure; it never opens a real approval, reads trusted RPC,
uses key material, or signs. C20 does not carry its original absolute deadline
to a replacement worker. Death before a durable claim can therefore give the
new background lease a fresh lifetime after the initiating page request has
already spent most of its own. Content expiry sends no cancellation. A Port
enqueue is not a content/page receipt, `window.postMessage()` is not proof C16
settled, and one replay may be exhausted after enqueue while the page still
times out. Navigation remains unmeasured for this owner. C21 removes one Port
ordering race; it does not make the provider or wallet deployable.

Ledger-inclusive full-repository evidence belongs to
`4ffb49c0dad6618db7eb6b13f5096d7550e3d5d7` only. From a clean tree,
`git rev-parse HEAD && test -z "$(git status --porcelain)" && env
npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && git diff
--check && git rev-parse HEAD && test -z "$(git status --porcelain)"` exited
**0** and printed the same SHA before and after. It covered the complete pnpm
workspace, core **699/699**, extension **462/462**, UI tokens **11/11**,
transaction-budget **8/8**, WebAuthn **1/1**, Chromium **8/8**, the pinned
Argon2 worker benchmark, builds/typechecks, repository guards, and the complete
Rust workspace. The Anchor test-program key mismatch and legacy macro `cfg`
notices remained non-fatal warnings. The evidence-only ledger commit recording
this result does not inherit that verdict or promote an invariant.

---

## Client C22 immutable deadline and delivery settlement — 43b6b12 — 2026-08-31 — **INTERNAL / UNSHIPPED**

**Threat closed internally:** C21 still minted content, background, and page
lifetimes independently, while both Chrome Port enqueue and
`window.postMessage()` stopped short of proving that the initiating Promise had
consumed a terminal result. Worker loss near expiry could therefore extend the
background lease, and loss after enqueue could consume the one replay without
settling the page. C22 defines a closed five-envelope transport language:
request, terminal, page receipt, background settled acknowledgment, and exact
expiry cancellation. C16 mints the only absolute deadline. C20 canonicalizes
and replays that same request envelope, and C21 opens every replacement lease
with that timestamp rather than a fresh TTL.

Terminal enqueue now stages one immutable response and a deterministic receipt
id derived from the complete C14 operation identity. C16 records the receipt
tombstone before settling its Promise and re-acknowledges only an exact duplicate
terminal. C20 retains its entry through page forwarding and receipt send; only
the matching current-generation settled acknowledgment removes it. After Port
loss it resends the original request. If the page already consumed the terminal,
the same terminal on the replacement causes receipt replay without a second page
settlement. At the initiating deadline C20 sends a cancellation containing the
same canonical request and timestamp; C21 recomputes the operation identity and
cancels only that exact active lease.

The background does not release delivery ownership merely because
`Port.postMessage()` returned. The C14/C19 flow must enqueue one exact terminal,
mark enqueue-side completion, and return the closed delivery proof. Only then
may a matching receipt for the current Port generation, correlation, operation
receipt id, and deadline call `ProviderPortSession.finish()` and receive the
settled acknowledgment. Early, forged, expired, wrong-generation, or
identity-changing receipts close the route. Duplicate exact receipts after
settlement are idempotently re-acknowledged.

Harsh review found and fixed two additional authority races. A superseded Port
could finish asynchronous operation hashing and start a flow before its
replacement presented the request; post-hash code now rechecks exact current
Port identity. Receipt settlement also initially trusted `finish()` before the
flow Promise returned its exact proof; `flowProven` is now required, and any
later malformed/rejected dependency result closes the route even if state was
otherwise cleared. Both defects have focused regressions.

At implementation SHA `43b6b12a8914414a9d68ab7ae97006e8541ad9eb`,
the clean-SHA extension command recorded in `docs/NEXT-SESSION.md` exited **0**:
extension **473/473**, typecheck, build, real Chromium **9/9**, emitted-artifact
exclusion, `git diff --check`, and identical SHA before/after. Chromium now
measures (1) one live lease across overlapping Ports through receipt settlement,
(2) one durable fixed cancellation after real CDP worker death without a second
preparation, and (3) a replacement worker holding the exact initiating deadline,
then losing ownership at that timestamp with C20 pending count zero and no page
terminal or receipt fabricated. Build metadata explicitly forbids the C22
protocol and page/content/background owners from both production graphs.

Primary browser contracts checked:
<https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
<https://developer.chrome.com/docs/extensions/develop/concepts/messaging>, and
<https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers>.
Chrome requires MV3 state to survive unexpected worker termination and documents
Port messaging and service-worker lifetime behavior. Treating a send as enqueue
rather than end-to-end Promise consumption remains Warden's conservative
architectural inference, now enforced by the explicit receipt state machine.

**New invariants:** none. `WRD-EXT-01`, `WRD-APR-01`, `WRD-APR-02`,
`WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented` because this graph is
unreachable in shipped bundles and has not signed a production-composed request.
Independent second-model review remains **UNVERIFIED**; the immediately preceding
C21 attempt could not initialize on this host's read-only app-server state path.

**Residual, stated as a threat:** this is a safety-oriented volatile receipt
protocol with one recovery budget, not an exactly-once distributed transaction.
Two consecutive worker/Port losses may still leave the page to time out, though
they cannot extend the original deadline or authorize another signature. The
receipt id reveals a document/correlation-specific operation digest to the
initiating page and is an identity token, not a secret. Navigation during each
receipt phase is not yet measured. The Chromium worker still produces only a
durable fixed failure; no real browser lane opens an approval, selects a
reviewed non-empty release, reads trusted RPC, consumes an unlocked signer,
verifies exact signed bytes, or registers a Wallet Standard method. C22 closes
the deadline/acknowledgment class internally; it does not make Warden deployable.

Ledger-inclusive SHA `afb0347543820608ec3c100a07dc6073d6ede17a` passed, from a
clean tree, `git rev-parse HEAD && test -z "$(git status --porcelain)" && env
npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && git diff
--check && git rev-parse HEAD && test -z "$(git status --porcelain)"`, exit
**0**, with the same SHA printed before and after. The executable gate passed
core **699/699**, UI tokens **11/11**, transaction-budget **8/8**, WebAuthn
**1/1**, extension **473/473**, typecheck/build, the Argon2 benchmark, real
Chromium **9/9**, and the full Rust workspace suite. Known Anchor key/cfg and
Rust unused-code warnings were non-fatal. This verdict belongs only to that
exact SHA; the documentation-only addendum commit that records it does not
inherit the result.
