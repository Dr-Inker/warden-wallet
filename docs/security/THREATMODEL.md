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
