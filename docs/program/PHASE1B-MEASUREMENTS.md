# Phase 1B — measured costs and recorded design withdrawals

Companion to `docs/program/PHASE1A-MEASUREMENTS.md`. Task 9 folds the Task 0
re-measurements recorded there into this file; everything below is added by the
task named in the heading.

---

## Task 1 — `conservation`

### `Outflow` has no `gross_turnover` field, and must not grow one

Recorded here so that a later reader who finds only the code does not "restore"
a field that was deliberately withdrawn (research §3(a).6; spec §5.2 rule 4b and
§5.3). Two independent, permanent reasons:

1. **There is no prior art to copy.** LazorKit's "gross" accounting is *SOL
   summed between outer CPIs*; its **token** per-transaction limit is an
   ordinary before/after **net** diff. `SWIG-GROSS-OUTFLOW` in
   `docs/security/PRIOR-ART-FINDINGS.md` says so explicitly. The first draft of
   the rev-8 research proposed a persistent gross-turnover bucket on the false
   premise that such a precedent existed, and withdrew it when the premise did
   not survive checking.
2. **No snapshot granularity can observe the quantity it would hold.** A single
   CPI that moves 100 SOL of vault value out and returns 99.5 SOL *within its
   own execution* presents a net delta of 0.5 SOL. Per-inner-instruction
   snapshots do not help: the round trip completes below the boundary at which
   the caller regains control. A `gross_turnover` field would therefore report a
   number the program cannot measure — worse than an honest gap, because it
   would read as a bound.

What 1B enforces instead (spec §5.2 rule 4b): the **adapter-decoded `max_in`**,
parsed out of the inner instruction's own data rather than inferred from
balances, plus a **pinned source ATA**, both checked before the CPI runs
(Task 6). That is a bound on the value the program can see being *authorised*.
It is an explicit **design bet**, not a proof, and the product statement must not
claim that a conservation check bounds intra-CPI turnover.

`conservation::tests::outflow_has_no_gross_turnover_field` destructures
`Outflow` exhaustively, so adding a field breaks that test.

### Token / Token-2022 layout constants: provenance

Every constant in `constants.rs`'s conservation block was re-derived from
vendored crate source at the versions this repo resolves — not from memory:

| Fact | Source |
|---|---|
| `Account::LEN == 165`, `Mint::LEN == 82`, `Multisig::LEN == 355` | `spl-token 9` (dev-dependency), asserted at runtime by `conservation::tests::spl_crate_layout_lengths_are_pinned` |
| `BASE_ACCOUNT_LENGTH == 165`; `AccountType` byte at absolute offset 165; TLV tail from absolute offset 166, for **both** mints and token accounts; a mint's bytes 82..165 must be zero padding; a buffer of exactly `Multisig::LEN` is never extensible | `spl-token-2022 7.0.0`, `src/extension/mod.rs` — `type_and_tlv_indices`, `unpack_tlv_data`, `check_min_len_and_not_multisig` |
| TLV entry = `type: u16 LE ‖ length: u16 LE ‖ value[length]`; a `type` of `Uninitialized (0)` terminates the walk | same file — `get_tlv_indices`, `get_extension_indices` |
| `AccountType::{Uninitialized = 0, Mint = 1, Account = 2}` | same file |
| `ExtensionType` discriminants: `TransferFeeConfig 1`, `ConfidentialTransferMint 4`, `ConfidentialTransferAccount 5`, `PermanentDelegate 12`, `TransferHook 14`, `ConfidentialTransferFeeConfig 16`, `ConfidentialTransferFeeAmount 17`, `ConfidentialMintBurn 24` | same file — `pub enum ExtensionType` |
| `TransferFeeConfig` = `transfer_fee_config_authority[0..32] ‖ withdraw_withheld_authority[32..64] ‖ withheld_amount[64..72] ‖ older_transfer_fee[72..90] ‖ newer_transfer_fee[90..108]`, each `TransferFee` = `{epoch u64, maximum_fee u64, bps u16}`; the two authorities are `OptionalNonZeroPubkey` (a bare 32-byte key, all-zeros = `None`, **no tag**) | `src/extension/transfer_fee/mod.rs` |

The deny-list instruction tags (§5.2 rule 1a) are **not** in this table — they
are Task 5's to derive and pin, with its own unit test against the `spl-token`
crate's `TokenInstruction` encoding.

### Deliberate tightenings beyond the spec's letter (each can only reject more)

- **`DANGER_CONFIDENTIAL` covers extensions 4, 5, 16, 17 and 24**, where spec
  §5.2 rule 5 names 4/5. Every one of them hides an amount behind a ZK
  ciphertext, which is the property that makes conservation *unverifiable*
  rather than merely hard. Widening a permanent deny cannot open a hole.
- **Mint authority fields are compared for every required mint**, where the
  spec compares them only "if the vault holds any authority on M". The spec's
  condition is a CU optimisation; comparing unconditionally is a superset and
  no legitimate 1B flow changes a mint authority.
- **A `CloseIntent` must agree with the snapshot** (`amount_before` equal to the
  BEFORE balance, the account actually gone, every intent consumed exactly
  once). A decoder/comparison desync fails loudly instead of silently passing.

### Round-1 review fixes (Codex sol@max, thread `01a018fa`) — recorded rulings

Four fail-open paths and one parsing weakness, each now with a regression:

| # | Hole | Fix |
|---|---|---|
| C1 | Vault-**controlled** mints were only checked when reached through a vault token account, and that check ran *after* the `CloseIntent` branch | `compare::prescan_vault_mints` validates every mint whose `mint_authority` / `freeze_authority` / T22 fee authority is the PDA, independently of any token account and before anything else; the token-account-driven mint checks moved ahead of the close branch |
| C2 | Classification was BEFORE-driven, so an account that *became* the vault's mid-instruction was never examined | anything vault-owned in the AFTER snapshot must have been the same vault-owned token account of the same mint under the same program BEFORE — else `NewVaultAccountRejected` (6051) |
| C3 | Positional comparison under-counts when one account is listed twice | duplicate pubkeys rejected up front (`PayloadInvalid`) |
| C4 | Token-2022 `WithdrawExcessLamports` (tag 38) drains rent with every compared field unchanged | lamports must be unchanged on **non-native** vault token accounts; `is_native.is_some()` (not the mint key) is the exemption |
| C5 | Token-**account** TLV tails were hashed but never walked; `classify` was program-agnostic | tails are walked with bounded, fail-closed parsing; classic SPL Token accepts **only** exactly 165 B (account) / 82 B (mint) — it has no extension mechanism |

**The presence rule is no longer gated on `is_writable`** (round-1 adjudication).
Gating on writable let a caller opt out of the danger-extension check and the
mint-authority comparison by passing the vault ATA read-only. Spec §5.2 rule 2a
was amended to match.

**One deliberate false positive, scheduled for 1C.** `prescan_vault_mints`
compares the TLV **tail hash** for a vault-controlled mint, where `check_mint`
(mints reached through a vault token account) deliberately does not. The
false positive §5.2 rule 2a warns about — a legitimate `transfer_fee` accrual
mutating `withheld_amount` in the tail — can only occur on a fee mint, and a fee
mint backing a vault token account already rejects outright in 1B
(`TransferFeeMintUnsupported`). The residue is a **vault-controlled fee mint
with no vault token account in the list**: its withheld-fee accrual rejects in
1B and must become a field-wise comparison in 1C, when fee mints become legal.

**`supply` stays uncompared** in both paths — re-confirmed in the round-1
adjudication against spec §5.2 rule 2a.

---

## A0 — assurance-record repair (campaign plan 2026-08-20)

Not a program task: A0 repaired the assurance records so Task 9's close-out is
auditable (campaign plan gaps G1/G2/G7/G10/G11). No program code changed.

**What changed:**

- `docs/security/REVIEW-RUNS.jsonl` (new) — one line per completed review
  round, **including zero-finding rounds**; `scripts/review.sh` now appends a
  run record via `scripts/append-review-run.mjs` (step 8), which re-validates
  the artefact independently and appends nothing for a failed round. 15
  `baseline-not-recorded` entries record the pre-A0 rounds honestly: fix-commit
  or citing-doc evidence only, no invented finding counts, thread ids only
  where a committed doc retained them.
- `docs/security/THREATMODEL.md` — retrospective milestone deltas appended for
  Tasks 0, 1, 2b, 11 (append-only; the stale unauthenticated-create baseline
  paragraph is superseded by the Task 2b delta, not rewritten).
- `docs/security/invariants.jsonl` — `WRD-CONS-01`..`-06` unit-layer rows added
  at `test-covered` with named tests at `d394b74` (campaign plan G7); the
  end-to-end `WRD-EXEC-*` rows stay `unimplemented` until Task 5.
- `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md` — per-task
  status/SHA/review table added; Task 11 marked **PARTIAL** pending Task 11R.
- `packages/core/test/review-runs.test.ts` (new) — pins the run-record contract:
  a validated zero-finding round appends exactly one run; a failed/invalid
  round appends none; live runs carry full provenance; baseline entries must
  say `retrospective`/`UNVERIFIED` and source any finding count they claim.

**Task 11 gate evidence, rerun at the A0 SHA (campaign plan: record only what
actually passes; the deployment gate stays partial until Task 11R):**

Run at `41806e4ecbf087cfce48b10f4f3f9c3bc37f4a81` (2026-08-20):

```
$ node scripts/gen-invariants.mjs --check
INVARIANTS.md is up to date (59 invariants).
$ scripts/review.sh --selftest        # codex CLI contract
selftest OK
$ pnpm --filter @warden/core test
 Test Files  5 passed (5)
      Tests  95 passed (95)
$ ./scripts/supply-chain-gate.sh
== L9 supply-chain gate: PASS ==
$ git diff --check b008190..41806e4
(clean)
```

NOT rerun here and still owned elsewhere: the deployment gate
(`scripts/deploy-gate.sh`) remains SPEC + partial dry-run (Task 11R); cargo /
anchor builds and the Rust suite were not part of A0's lease (no Rust source
changed; the serialized-build rule reserves them for Task 2).
