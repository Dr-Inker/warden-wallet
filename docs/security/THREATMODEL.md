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
