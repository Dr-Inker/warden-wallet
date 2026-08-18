# Warden Phase 1A — measured costs

Compute units and transaction sizes measured with LiteSVM (`litesvm 0.12`,
`precompiles` feature) against the SBF artifact `target/deploy/warden.so` built
by `anchor build` (Anchor 1.1.2, Agave `cargo-build-sbf` 3.1.10). Numbers come
from `res.compute_units_consumed` on the positive-path test named below — run
`cargo test -p warden --test <suite> -- --nocapture` to reproduce.

CU figures are for the **whole transaction** (the secp256r1 precompile's own
verification cost is charged separately by the runtime and is not included in
`compute_units_consumed` for our instruction).

| Path | CU | Tx size | Test | Notes |
| --- | ---: | ---: | --- | --- |
| `root_verify` (`rotate_nonce`, full root ceremony) | 15,533 | 680 B | `root_verify::rotate_nonce_ok_and_nonce_increments` | 37 B `authenticatorData`, 161 B `clientDataJSON`, 1 precompile ix + 1 program ix. Includes the strict clientDataJSON scan, Keccak transcript, SHA-256 of `clientDataJSON`, and Instructions-sysvar introspection of the precompile instruction. |
| `create_account` (all-defaults `PolicyArgs`, no mint caps used) | 8,777 | 472 B | `create_account::creates_with_defaults` | 235 B of instruction data (8 B discriminator + `CreateAccountArgs`). **Round-1 review fix: was 12,767 CU / 1,804 B** when `PolicyArgs` mirrored `Policy`'s fixed 8-slot arrays — see the fixed finding below. |
| `create_account` (2 mints — SOL + USDC, each with a cap, session ceiling, and large-transfer threshold) | not separately measured (CU is dominated by fixed decode cost, not mint count) | 808 B | `create_account::realistic_two_mint_policy_transaction_fits_the_packet_limit` | Asserted `<= 1,232 B` in the test itself, not just printed. |
| `create_account` (`MAX_MINTS_AT_CREATE` = 4 mints, each with a cap, session ceiling, and large-transfer threshold) | not separately measured | 1,144 B | `create_account::max_mints_at_create_transaction_fits_the_packet_limit` | Asserted `<= 1,232 B`; margin is 88 B — this is why `MAX_MINTS_AT_CREATE` is 4, not 8 (see below). |
| `grant_session` (full root ceremony, `MAX_CAPS_PER_GRANT` = 2 caps) | 31,829 | 944 B | `sessions::grant_ok_and_readback` (CU) / `sessions::grant_tx_fits_1232_bytes_with_2_caps` (bytes) | 423 B of instruction data (8 B discriminator + 218 B `RootArgs` + 197 B `GrantBody`) plus a 182 B precompile instruction; 37 B `authenticatorData`, 164 B `clientDataJSON`. CU is ~2× `rotate_nonce` because the same root check is followed by a `system_program::create_account` CPI for the 751 B `SessionKey` PDA and a full Borsh write-back of it. **Asserted `<= 1,232 B` in the test** — margin is 288 B. Re-measured 31,842 CU after Task 7's round-1 review added the `SessionDayCapsUnsupported` check (+13 CU); size unchanged, since `MintCap` is fixed-width whether or not its day fields are zero. |
| `revoke_session_root` (full root ceremony, closes the session PDA) | 20,774 | 778 B | `sessions::revoke_by_root_ok` | 8 B discriminator + 218 B `RootArgs` + 64 B `RevokeBody` (`session_pubkey` ‖ `refund_to`) of instruction data, plus the 182 B precompile instruction. Asserted `<= 1,232 B`. Round-1 review: was 20,505 CU / 746 B before `refund_to` was added to the signed body. |
| `revoke_session_self` (session key signs; no root ceremony) | 7,323 | 341 B | `sessions::revoke_by_session_self_ok` | 8 B of instruction data and no precompile instruction at all — the cheapest authenticated path in the program. |
| `freeze` (full root ceremony, root-only, 1A scope) | 15,697 | 680 B | `freeze::freeze_sets_state` (CU) / `freeze::freeze_tx_fits_1232_bytes` (bytes) | No arguments beyond `RootArgs` — same shape as `rotate_nonce`, so the size and CU are effectively identical (`rotate_nonce` measured 15,533–15,664 CU / 680 B across the two suites that measure it; the ~30–160 CU spread between runs is compilation/measurement noise, not a real cost difference). |
| `unfreeze` (full root ceremony, timelock elapsed) | 15,717 | 680 B | `freeze::unfreeze_after_timelock_ok` (CU) / `freeze::unfreeze_tx_fits_1232_bytes` (bytes) | Same shape as `freeze`/`rotate_nonce` — no arguments beyond `RootArgs`. The `checked_add(frozen_at, policy.timelock_secs)` comparison is negligible CU on top of the shared root-verify cost. |
| `transfer` (session key, native SOL) | 18,533 | 386 B | `transfer::session_sol_transfer_within_caps` (CU) / `transfer::session_sol_transfer_tx_fits_1232_bytes` (bytes) | No precompile instruction and no root ceremony at all — 8 B discriminator + 18 B `TransferArgs` (`root: None` 1 B, `mint: None` 1 B, `amount` 8 B, plus option tags) over 7 accounts. The CU is the account PDA re-derivation, the session checks, `buckets::debit` (day roll + 30-slot ring sum) and the direct lamport move. |
| `transfer` (session key, SPL token) | 20,665 | 482 B | `transfer::session_spl_transfer_ok` (CU) / `transfer::session_spl_transfer_tx_fits_1232_bytes` (bytes) | +2,132 CU over the native path: two 165 B token-account parses plus the `spl_token::Transfer` CPI (the CPI's own cost is charged to this transaction). +96 B of accounts (source ATA + token program instead of two `None` placeholders). |
| `transfer` (passkey root, native SOL) | 25,555 | 727 B | `transfer::root_transfer_within_threshold_debits_buckets` (CU) / `transfer::root_transfer_tx_fits_1232_bytes` (bytes) | 8 B discriminator + 218 B `RootArgs` + 10 B of own arguments, plus the 182 B precompile instruction. ~7,000 CU above the session path is exactly the root ceremony (cf. `rotate_nonce` at 15.5k, which does the ceremony and nothing else); the `large_threshold` lookup is negligible. Root payload budget (C7) is respected with room to spare: 10 B of own arguments against the 400 B allowance. |
| `transfer` (passkey root, SPL token) | 27,692 | 823 B | `transfer::root_spl_transfer_ok` (CU) / `transfer::root_spl_transfer_tx_fits_1232_bytes` (bytes) | The root ceremony plus the SPL path — the most expensive shape Phase 1A has, still 14% of a default 200k-CU budget and 409 B under the packet limit. Asserted `<= 1,232 B` in the test, not merely printed (round-1 review). Worst case at `MAX_CLIENT_DATA_LEN` = 512 B of `clientDataJSON` would be ~1,171 B — inside the limit, but with only ~61 B to spare, which is the tightest margin of any 1A instruction. |

## Headroom

* CU: 15.5k of the 200k default per-transaction budget (1.4M max) for
  `root_verify`; 8.8k for `create_account`. Phase 1B's `execute`/swap paths
  ride on top of this, so the root check is ~8% of a default-budget
  transaction. (`root_verify` first measured at 15,711 CU; 15,533 after the
  round-1 review replaced the bracket-counting skipper with a full JSON
  validator.)
* Size: `root_verify` is 680 B of the 1,232 B transaction limit. `clientDataJSON`
  is capped at `MAX_CLIENT_DATA_LEN` = 512 B, which is the dominant variable;
  the worst case is ~1,030 B, still inside the limit but leaving little room
  for extra accounts. Root payload budget (C7) is respected: `rotate_nonce`
  carries 8 B of discriminator + 215 B of `RootArgs`; `grant_session`, the
  heaviest root instruction in Phase 1A, carries 197 B of its own arguments
  beyond `RootArgs` — about half the 400 B C7 allows.
* CU: `grant_session` is 31.8k of the 200k default budget (16%), and the
  create-the-PDA CPI is a one-off — a re-grant into an existing PDA skips it.

### `grant_session` transaction-size gate — why `MAX_CAPS_PER_GRANT` = 2

The plan (rev 2) fixed the limit at 2 caps from an estimate; this is the
measurement. A 2-cap grant is **944 B** of the 1,232 B packet limit, leaving
288 B of margin. Each additional cap costs 64 B on the wire (56 B `MintCap` +
8 B parallel `lifetime_cap`), so 3 caps would measure ~1,008 B and 4 caps
~1,072 B — both nominally inside the limit *for this `clientDataJSON`*.

The limit is nonetheless 2, because the variable that dominates is not the cap
count but `clientDataJSON`, which the program accepts up to
`MAX_CLIENT_DATA_LEN` = 512 B. A real browser's document is 164 B here, but a
different origin length, a `crossOrigin` field ordering, or any UA that pads
the document eats the margin directly: at 512 B of `clientDataJSON` a 2-cap
grant is already ~1,292 B and would not fit at all. Two caps is the
conservative choice that keeps a realistic-but-not-minimal ceremony inside the
packet even with a materially larger `clientDataJSON`, and a session still
accumulates up to `MAX_MINT_CAPS` (8) mints across several grants because
`grant_session` merges by mint rather than replacing.

`sessions::grant_tx_fits_1232_bytes_with_2_caps` asserts the measured length
(it does not merely print it) **and** asserts the `clientDataJSON` really is a
realistic Chrome-shaped document, because LiteSVM has no wire layer: it will
happily execute a transaction a real validator would drop before execution.
`sessions::grant_with_3_caps_rejected` proves the limit is enforced *by the
program* (`BadInstructionLayout`), not merely advised by the constant.

### `create_account` transaction-size finding — FIXED, round-1 review

**Original finding (Task 4, first pass):** `CreateAccountArgs::policy:
PolicyArgs` carried `Policy`'s three full `[MintCap; MAX_MINT_CAPS]` arrays
(`caps`, `session_ceiling`, `large_threshold` — 8 slots each, 56 B per
`MintCap`), Borsh-serialized in full regardless of how many slots were
actually used: `3 * 8 * 56 = 1,344 B` of arrays alone. The measured
all-defaults (zero mints configured) transaction was **1,804 B**, ~46% over
Solana's 1,232 B packet limit (`PACKET_DATA_SIZE`). LiteSVM's
`send_transaction` does not enforce this limit (no wire/UDP layer in the
simulator), which is why the test passed in the suite but the shape would
have been rejected by a real validator before execution even began. Marked
Critical on review.

**Fix (round-1):** `PolicyArgs.caps`/`session_ceiling`/`large_threshold` are
now `Vec<MintCap>` (sparse on the wire), each capped at
`MAX_MINTS_AT_CREATE` = 4 entries. `PolicyArgs::expand` (in
`state/smart_account.rs`) rebuilds `Policy`'s fixed 8-slot arrays from them:
`caps[i]` keeps its wire position; `session_ceiling`/`large_threshold`
entries are re-keyed by `mint` onto the matching `caps` index (not
positional — see `expand_stores_ceiling_and_threshold_at_the_caps_index_not_wire_position`
and the identical end-to-end LiteSVM test
`ceiling_stored_at_the_caps_index_not_wire_position`), rejecting orphan
mints, mismatched mints, and duplicate mints within any of the three
vectors (all `WardenError::InvalidAccountData`).

**Why `MAX_MINTS_AT_CREATE` = 4, not `MAX_MINT_CAPS` = 8:** measured
directly, not estimated. `full_max_mint_caps_policy_does_not_fit_the_packet_limit`
builds (but never submits, since `expand` would reject it structurally
first) a full 8-mint `create_account` transaction — every mint with a cap,
ceiling, AND threshold, the heaviest realistic shape — and measures
**1,816 B**, ~47% over the 1,232 B limit. `max_mints_at_create_transaction_fits_the_packet_limit`
measures the same shape at `MAX_MINTS_AT_CREATE` = 4 mints: **1,144 B**, 88 B
of margin under the limit, and that one IS submitted and asserted to
succeed. This is independent of `MAX_MINT_CAPS` (still 8 — the on-chain
`Policy`'s fixed array width is unchanged): mints 5–8 are added
post-creation via a root-authorized `set_policy` instruction (Phase 1B),
never by raising `MAX_MINTS_AT_CREATE` itself.

Both size-sensitive tests assert `tx_bytes <= 1232` directly (not just print
it), so a future regression here fails the suite instead of only showing up
in this file.

## Design notes

### `unfreeze` reads `policy.timelock_secs` LIVE, at lift time

`instructions::unfreeze::handler` computes `unlock_at = frozen_at +
policy.timelock_secs` using the account's CURRENT policy, not a value
snapshotted when `freeze` ran. In Phase 1A this is a distinction without a
difference — no 1A instruction ever changes `timelock_secs` after
`create_account` sets it — but Phase 1B's `set_policy` will be able to. When
it lands, `set_policy` must make a deliberate choice for an account that is
currently frozen: either (a) preserve today's live-read behavior, so a
shortened timelock also shortens the wait on an in-progress freeze, or (b)
snapshot `timelock_secs` into `frozen_at`'s companion state at `freeze` time
so a later `set_policy` cannot retroactively change how long a freeze already
in effect lasts. This is not decided here — flagged for whoever implements
`set_policy` in 1B.

### `transfer`: what a session cap bounds in Phase 1A

**Bound statement: a session's bound is `per_tx x (calls) <= lifetime_cap`;
the day / 30-day bound is account-wide.**

`SessionKey` carries a `MintCap` per mint but has **no bucket fields** (no
`day_start`, no 30-day ring), so there is nowhere to accumulate a per-session
day or 30-day total. Per spec §4 those windows are ACCOUNT-WIDE and a session's
own caps are `per_tx` + `lifetime_cap`. Phase 1A therefore:

* **rejects** a grant that sets `per_day != 0 || per_30d != 0`
  (`SessionDayCapsUnsupported`, error 6033 — `grant_session::validate_shape`,
  proven by `sessions::grant_with_session_day_caps_rejected`). A stored-but-
  unenforced cap is worse than no cap: it would be displayed to the user as if
  it bounded something. Round-1 review ruling — the first pass stored those
  fields and silently never read them.
* enforces, per session, `caps[mint].per_tx` and `lifetime_spent + amount <=
  lifetime_cap`;
* enforces the day and rolling-30-day windows **only** through
  `SmartAccount.buckets`, which every session AND the root debit via the same
  `buckets::debit` call (`transfer::two_sessions_share_account_day_cap`,
  `transfer::root_transfer_within_threshold_debits_buckets`).

`instructions::transfer` carries a `debug_assert!` on the session cap's day
fields, so the invariant is stated where it is relied upon and not only where
it is enforced.

**1B owes:** real per-session day buckets need a **bucket PDA** — a 30-slot
ring is 8 + 8 + 8 + 240 = 264 B and does not fit `SessionKey._reserved`'s 64 B.
When that lands, the check above becomes enforcement rather than being relaxed,
and `policy.session_ceiling`'s `per_day`/`per_30d` comparisons (kept in
`validate_against_policy`, currently unreachable) become live again.

### Runtime gotcha: a credited destination must stay rent-exempt

Solana's runtime rejects any transaction that leaves a **credited** account
below the rent-exempt minimum for its size — `InsufficientFundsForRent`,
raised *after* the instruction returns `Ok`, so it is a transaction error, not
a program error, and no on-chain check can convert it into a friendlier one.
For a 0-byte system account that minimum is 890,880 lamports, which means a
transfer of (say) 600,000 lamports to a brand-new address fails as a whole
transaction even though every Warden rule passed.

`tests/transfer.rs` funds its destinations (`funded_dest`) rather than scaling
every cap in the suite above 890,880 lamports, because a real destination is an
existing wallet. **The extension must surface this**: "send 0.0006 SOL to an
address that has never been used" is not a valid Solana transaction at all, and
the failure will look like a Warden rejection if the client does not check the
destination's balance first.

### `RentFloor` (error 6031) is about the VAULT, not the destination

`transfer` refuses to leave the smart account itself below
`Rent::minimum_balance(data_len)` (`transfer::sol_transfer_cannot_breach_rent_floor`).
That is a separate concern from the runtime check above: without it a session
could drain the vault's lamports to the point where the ~4.1 KB `SmartAccount`
account itself became rent-collectible, taking the wallet's own state with it.
Draining down to *exactly* the floor is allowed.

### Error ABI added by Task 7

Anchor derives the on-wire code from declaration order, so these are permanent
once any client ships against them. Appended, never inserted (the enum's
append-only rule); `root_verify::pinned_error_codes_match_the_enum_today` is
the single test that pins all 34 variants against the enum.

| Code | Variant | Raised when |
| ---: | --- | --- |
| 6031 | `RentFloor` | A native transfer would leave the **vault** below `Rent::minimum_balance(data_len)`. Distinct from the runtime's `InsufficientFundsForRent`, which is about the **destination** and is a transaction error no program can catch. |
| 6032 | `VaultDestination` | The SPL destination token account is owned by the smart account itself (or is the source) — value would not leave the wallet while the caps were debited. |
| 6033 | `SessionDayCapsUnsupported` | A `grant_session` cap sets `per_day` or `per_30d` (round-1 review; see the bound statement above). |

Both `RentFloor` and `ChallengeMismatch` (6018, raised by `transfer` when a
root ceremony's destination or amount is substituted) are deliberately reused
rather than specialised further: `ChallengeMismatch` is what every other root
instruction raises for a rebuilt-transcript mismatch, and splitting it per
instruction would tell an attacker which field they got wrong.

## Update policy

Append a row per measured path; do not delete rows — a regression is only
visible against the previous number. Re-measure when the SBF toolchain or
Anchor version changes.
