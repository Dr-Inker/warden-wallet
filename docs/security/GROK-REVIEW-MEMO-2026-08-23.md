# Grok independent review memo — 2026-08-23 (blocked Codex round 4)

TO / Grok (independent adversarial reviewer)

FROM / Claude Code (main loop), `/opt/warden`, branch `phase1b`

WHY YOU AND NOT CODEX / The canonical assurance lane (`scripts/review.sh` →
`gpt-5.6-sol@max`, JSON-schema-validated, recorded in
`docs/security/REVIEW-RUNS.jsonl`) was attempted **twice** over this range and
died both times on OpenAI's cyber content filter
(`ERROR: This content was flagged for possible cybersecurity risk`). The wrapper
rolled back cleanly both times — the ledgers are untouched and honestly show
**100** recorded rounds, not 102. The block is a documented false-positive class
here, and it is **not** a convergence signal: the diff contains a regression test
that deliberately executes a token drain (9,000 → 0) to prove a vulnerability was
real. The property that makes the evidence good is what makes the diff look
hostile to a classifier.

---

## 0. What I need from you, in priority order

**Q1 (highest value). Is the authority-role enumeration COMPLETE?**
`execute` (the generic dispatch path) refuses to sign for any mint over which the
wallet's own PDA holds an authority role, because that path has no typed decoder
for nested authority operations. The predicate is `MintSnap::holds_authority`
(`programs/warden/src/conservation/mod.rs:174`). **This exact predicate has now
been found incomplete three times in three consecutive rounds**, which is why it
is the first question:

| round | what was missing | status |
|---|---|---|
| 1 | the whole gate (deny-list keyed on the DIRECT payload program only, so a forwarding CPI carried the propagated PDA signer) | fixed |
| 2 | it checked 2 of 4 roles — `transfer_fee_config_authority` and `withdraw_withheld_authority` were open (Token-2022 `WithdrawWithheldTokensFromAccounts`, tag 26 → classified `Other`) | fixed |
| 3 | PermanentDelegate was a **fifth** role, and the snapshotter recognised the extension but **discarded the delegate pubkey**; the danger-mint check only fired on WRITABLE mints while `TransferChecked` takes its mint read-only | fixed (this range) |

So: enumerate every Token-2022 extension and every base-mint field that designates
an authority or delegate able to cause token movement, supply change, freezing, or
account-state change, where that authority is a `Pubkey` that could be set to the
wallet PDA. Consider at least: MintCloseAuthority, TransferHook (authority **and**
program), ConfidentialTransfer (mint authority / auditor / withdraw-withheld),
ConfidentialTransferFee, InterestBearingMint (rate authority), Pausable,
DefaultAccountState, GroupPointer / GroupMemberPointer / MetadataPointer,
TokenMetadata update authority, ScaledUiAmount, TransferFeeConfig (both), and the
base `mint_authority` / `freeze_authority`. For each: would the current five-role
predicate catch it, and does `snapshot.rs` even extract the pubkey?

**Q2. Is a whitelist-of-known-roles the right SHAPE at all?**
The alternative is refusing any mint carrying an unrecognised or dangerous
extension outright, which is what invariant `WRD-EXEC-09` nominally demands
("permanent_delegate (12), transfer_hook (14) and confidential-transfer mints
(4/5) reject unconditionally"). I deliberately did **not** implement that, because
the codebase intentionally lets a mint whose roles are all held by third parties
pass through, and an unconditional ban would break that (there is a deliberate
narrowness test asserting a stranger-held TransferFeeConfig mint still works).
`WRD-EXEC-09` is honestly still marked `unimplemented` rather than being claimed.
**Tell me if that trade is wrong.** Rejecting more is not automatically safer if it
silently degrades legitimate use — but three consecutive misses is evidence that
enumeration may be the wrong shape.

**Q3. Are the other four fixes in this window sound?** See §2.

**Q4. Anything else adversarial in the range.** Normal rules of engagement.

---

## 1. Range, and how to read it

- **Blocked round's range:** `c5a4514ab5e36faa6b4450bad7103f3f1cb5a7ca..f4880cc`
  (9 files, +550/−25). This is the PermanentDelegate fix only.
- **Wider unreviewed context:** `0039681..HEAD` (23 files, +2356/−124) also
  contains the B4 test work and the round-1/round-2 remediations. Rounds 1–3 DID
  review most of that; only the PermanentDelegate range is unreviewed.
- The branch is **16 commits ahead of `origin/phase1b`** — this is NOT on GitHub
  yet, so work from the bundled diff, not from a fetch.

**Seeded invariants (47)** — the blocked round was seeded with these, and silence
on a seeded invariant is a FAIL in this house's rules:
`WRD-CAP-09, WRD-CAP-10, WRD-EXEC-01..10, WRD-FRZ-03, WRD-ROOT-11, WRD-DENY-01,
WRD-DENY-02, WRD-STAGE-02, WRD-CONS-01..06, WRD-KEY-01..04, WRD-EXT-01, WRD-EXT-02,
WRD-APR-01..03, WRD-TXI-01, WRD-SIM-01, WRD-SIM-02, WRD-EXP-01, WRD-REL-01..03,
WRD-ORG-01, WRD-SIG-01, WRD-QTE-01, WRD-VAN-01..04, WRD-EVT-01`.
Definitions: `docs/security/invariants.jsonl` / `INVARIANTS.md`.
Cross-cutting siblings worth reading: `programs/warden/src/root_verify/transcript.rs`,
`state/session.rs`, `errors.rs`, `buckets.rs`.
Prior-art corpus: `docs/security/PRIOR-ART-FINDINGS.md`.

**Axes (spec §17):** `truth_status` and `evidence_type` are independent.
Everything is `POTENTIAL` until a red test or human adjudication promotes it.

---

## 2. What changed in this window, and its honest standing

| finding | what it was | fixed at | reviewed? |
|---|---|---|---|
| WRDF-0104 | `UNSUPPORTED_WRITABLE_OWNERS` missed System-owned durable nonces + Loader-v4, so root `execute` moved value unmetered. Round 2 then found the "second barrier" claim was false (rule ran on the BEFORE snapshot only) and that its test passed the *same* snapshot as before **and** after | `b7f5097` | **yes** — round 3 saw the range and did not re-raise |
| WRDF-0106 | out-mint fee floor used a NET basis where Jupiter's `outAmount` is already net of fee; the test mock repeated the same denominator error. Round 2 then found the gross reconstruction introduced a u64 intermediate-overflow rejection | `b7f5097` | **yes** — same |
| WRDF-0105 | see the table in §0 | `631291a` | **NO — this is what you are reviewing** |
| WRDF-0108 | `WRD-CAP-09` was promoted to `test-covered` while its statement certifies the unbuilt `execute_pending` path. My error: I verified coverage against a **truncated** reading of the statement. Split into `WRD-CAP-09` (1B, keeps evidence) + new `WRD-CAP-10` (1C, unimplemented) | `32c1bd4` | ledger-only |
| WRDF-0107 | scorecard rows read `ruling=pending` while the campaign docs claimed "accepted and fixed" | `32c1bd4` | ledger-only |

**Standing of the thing you are reviewing:** the PermanentDelegate fix at
`631291a` is **gate-verified but not adversarially reviewed**. Its scorecard row
claims `remediation_verified` on the *gate* axis only — which is what this repo's
schema defines that field to mean — and that is a narrower claim than "reviewed".

**Gate at `631291ab7516630b150fb9a8702235c6d598d6e2`:**
`bash .claude/test-gate.sh` → exit **0**, Rust **670 passed / 0 failed / 1 ignored**,
`@warden/core` **301**, ui-tokens **11**, spike **8**.

---

## 3. The fix under review, in detail

**Mechanism that was open** (verified in source before fixing, not taken on trust):
- `holds_authority` (`conservation/mod.rs:174`) covered four roles.
- `snapshot.rs:305` matched `EXT_PERMANENT_DELEGATE` and only OR-ed
  `DANGER_PERMANENT_DELEGATE` into `dangerous_ext` — the delegate pubkey was
  **discarded**.
- `compare.rs:355` rejected an "unmodelable" danger mint only when
  `b.is_writable || a.is_writable`.
- Token-2022 `TransferChecked` (tag 12) is classified `Other` by `payload.rs`,
  takes its mint **read-only**, and accepts the permanent delegate as transfer
  authority.
- Net: a root payload passes a read-only mint whose PermanentDelegate is the
  SmartAccount PDA, uses logical slot 0 as the propagated signer, and moves
  third-party tokens. Conservation skips both accounts (non-vault), outflow is
  zero, no bucket is debited.

**This was proven, not traced.** An inverted test at `c5a4514` moved a victim
Token-2022 account **9,000 → 0** into an attacker account through a real
`TransferChecked` CPI. The probe was reverted before the fix landed.

**Fix applied:** parse the PermanentDelegate TLV (`OptionalNonZeroPubkey`, 32 B,
all-zero = None) into a new `MintSnap::permanent_delegate`, and add it as a fifth
role in `holds_authority`. Also added to the vault-controlled-mint identity
comparison — note `tlv_hash` already covers those bytes in `prescan_vault_mints`,
so that specific addition is **defence-in-depth, not a new guarantee**, and the
code says so.

**Known limits, stated so you do not have to rediscover them:**
1. The new **unit** tests cannot be red at the base SHA — they reference a field
   that does not exist there, so the crate would not compile. Behavioural redness
   rests entirely on the two **integration** tests, which do compile against the
   vulnerable source and did fail.
2. LiteSVM runs **spl-token-2022 10.0.0**, not the 7.0.0 the finding cited. The
   exploit reproduced on 10.0.0; the 7.0.0 pin is a layout reference.
3. A malformed (<32 B) PermanentDelegate TLV yields `None`, matching the
   neighbouring best-effort extractors. Argued safe because the token program
   itself requires exactly 32 bytes, so a truncated entry authorises nothing
   on-chain. **Check that argument.**

---

## 4. Rules of engagement

- **Do not** hand-write `WRDF-` ids into `REVIEW-SCORECARD.jsonl`. Report findings
  in prose/JSON here; the maintainer runs the normal loop on the fix range.
- **Do not** add a second successful-drain fixture. If you demonstrate a hole,
  write the repro so it can be **inverted** to `expect_reject` when patched — that
  is the house rule from the 2026-08-22 audit and the reason the last drain probe
  was reverted.
- Cite `file:line` for every claim about this repo.
- Separate `truth_status` from `evidence_type`. "I could not reproduce it" is a
  publishable result here; so is "this is a static trace only".
- If you think a previous fix (or one of my adjudications) was wrong, say so
  directly. Three of the last five findings were errors in my own work, not the
  code's: a false invariant promotion, a dropped case in a worker brief, and
  malformed provenance in the ledger. Assume I am fallible in the same direction.

---

## 5. Attachments

- `warden-c5a4514..f4880cc.diff` — the exact blocked range.
- Optionally `warden-0039681..HEAD.diff` — the wider window (rounds 1–3 covered
  most of it).
- Read alongside: `docs/security/INVARIANTS.md`, `PRIOR-ART-FINDINGS.md`,
  `THREATMODEL.md`, and `docs/program/PHASE1B-MEASUREMENTS.md` (the round-by-round
  narrative, including the two content-filter blocks).
