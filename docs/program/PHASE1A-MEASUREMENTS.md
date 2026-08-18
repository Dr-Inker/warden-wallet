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
| `grant_session` (full root ceremony, `MAX_CAPS_PER_GRANT` = 2 caps) | 31,829 | 944 B | `sessions::grant_ok_and_readback` (CU) / `sessions::grant_tx_fits_1232_bytes_with_2_caps` (bytes) | 423 B of instruction data (8 B discriminator + 218 B `RootArgs` + 197 B `GrantBody`) plus a 182 B precompile instruction; 37 B `authenticatorData`, 164 B `clientDataJSON`. CU is ~2× `rotate_nonce` because the same root check is followed by a `system_program::create_account` CPI for the 751 B `SessionKey` PDA and a full Borsh write-back of it. **Asserted `<= 1,232 B` in the test** — margin is 288 B. |
| `revoke_session_root` (full root ceremony, closes the session PDA) | 20,774 | 778 B | `sessions::revoke_by_root_ok` | 8 B discriminator + 218 B `RootArgs` + 64 B `RevokeBody` (`session_pubkey` ‖ `refund_to`) of instruction data, plus the 182 B precompile instruction. Asserted `<= 1,232 B`. Round-1 review: was 20,505 CU / 746 B before `refund_to` was added to the signed body. |
| `revoke_session_self` (session key signs; no root ceremony) | 7,323 | 341 B | `sessions::revoke_by_session_self_ok` | 8 B of instruction data and no precompile instruction at all — the cheapest authenticated path in the program. |
| `freeze` (full root ceremony, root-only, 1A scope) | 15,697 | 680 B | `freeze::freeze_sets_state` (CU) / `freeze::freeze_tx_fits_1232_bytes` (bytes) | No arguments beyond `RootArgs` — same shape as `rotate_nonce`, so the size and CU are effectively identical (`rotate_nonce` measured 15,533–15,664 CU / 680 B across the two suites that measure it; the ~30–160 CU spread between runs is compilation/measurement noise, not a real cost difference). |
| `unfreeze` (full root ceremony, timelock elapsed) | 15,717 | 680 B | `freeze::unfreeze_after_timelock_ok` (CU) / `freeze::unfreeze_tx_fits_1232_bytes` (bytes) | Same shape as `freeze`/`rotate_nonce` — no arguments beyond `RootArgs`. The `checked_add(frozen_at, policy.timelock_secs)` comparison is negligible CU on top of the shared root-verify cost. |

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

## Update policy

Append a row per measured path; do not delete rows — a regression is only
visible against the previous number. Re-measure when the SBF toolchain or
Anchor version changes.
