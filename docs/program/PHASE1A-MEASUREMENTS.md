# Warden Phase 1A — measured costs

**Status: FINAL for Phase 1A.** Every number below was re-measured at commit
`4b409f7` (branch `phase1a`), after the milestone security review's fixes —
earlier figures quoted in task reports are superseded.

Compute units and transaction sizes measured with LiteSVM (`litesvm 0.12`,
`precompiles` feature) against the SBF artifact `target/deploy/warden.so` built
by `anchor build` (Anchor 1.1.2, Agave `cargo-build-sbf` 3.1.10, platform-tools
v1.52, rustc 1.89.0 for SBF / 1.97.1 host). Numbers come from
`res.compute_units_consumed` on the positive-path test named below — run
`cargo test -p warden --test <suite> -- --nocapture` to reproduce.

**The harness runs on mainnet-beta's feature set.** `LiteSVM::new()` enables
*no* runtime features at all, which is not the chain this program deploys to;
`common::setup` uses `LiteSVM::new().with_mainnet_features()` so the CU figures
are measured against the features actually active on mainnet (litesvm's
snapshot of 2026-04-26). This matters: `grant_session` measures 30,696 CU here
and 32,196 CU under the all-features-disabled default.

CU figures are for the **whole transaction** (the secp256r1 precompile's own
verification cost is charged separately by the runtime and is not included in
`compute_units_consumed` for our instruction).

## Instruction costs

| Path | CU | Tx size | Test | Notes |
| --- | ---: | ---: | --- | --- |
| `root_verify` (`rotate_nonce`, full root ceremony) | 15,858 | 680 B | `root_verify::rotate_nonce_ok_and_nonce_increments` | 37 B `authenticatorData`, 161 B `clientDataJSON`, 1 precompile ix + 1 program ix. Includes the strict `clientDataJSON` scan (now preceded by a whole-document UTF-8 validation, +~194 CU — milestone review), the Keccak transcript, SHA-256 of `clientDataJSON`, and Instructions-sysvar introspection of the precompile instruction. History: 15,711 CU (first pass) → 15,533 (strict JSON validator) → 15,664 (Task 7) → 15,858 (UTF-8 + mainnet feature set). |
| `create_account` (all-defaults `PolicyArgs`, no mint caps used) | 8,866 | 472 B | `create_account::creates_with_defaults` | 235 B of instruction data (8 B discriminator + `CreateAccountArgs`). Includes the root-encoding check and the canonical-origin check added by the milestone review. **Round-1 review fix: was 12,767 CU / 1,804 B** when `PolicyArgs` mirrored `Policy`'s fixed 8-slot arrays — see the fixed finding below. |
| `create_account` (2 mints — SOL + USDC, each with a cap, session ceiling, and large-transfer threshold) | not separately measured (CU is dominated by fixed decode cost, not mint count) | 808 B | `create_account::realistic_two_mint_policy_transaction_fits_the_packet_limit` | Asserted `<= 1,232 B` in the test itself, not just printed. |
| `create_account` (`MAX_MINTS_AT_CREATE` = 4 mints, each with a cap, session ceiling, and large-transfer threshold) | not separately measured | 1,144 B | `create_account::max_mints_at_create_transaction_fits_the_packet_limit` | Asserted `<= 1,232 B`; margin is 88 B — this is why `MAX_MINTS_AT_CREATE` is 4, not 8 (see below). |
| `create_account` (8 mints — the full `MAX_MINT_CAPS` width) | — | 1,816 B | `create_account::full_max_mint_caps_policy_does_not_fit_the_packet_limit` | Built but never submitted: 47% over the packet limit. The measurement that fixes `MAX_MINTS_AT_CREATE` at 4. |
| `grant_session` (full root ceremony, `MAX_CAPS_PER_GRANT` = 2 caps) | 30,696 | 976 B | `sessions::grant_ok_and_readback` (CU) / `sessions::grant_tx_fits_1232_bytes_with_2_caps` (bytes) | 455 B of instruction data (8 B discriminator + 218 B `RootArgs` + 229 B `GrantBody`) plus a 182 B precompile instruction; 37 B `authenticatorData`, 164 B `clientDataJSON`. CU is ~2× `rotate_nonce` because the same root check is followed by a `system_program::create_account` CPI for the 751 B `SessionKey` PDA and a full Borsh write-back of it. **Asserted `<= 1,232 B` in the test** — margin is 256 B. History: 30,325 CU / 944 B → +13 CU for `SessionDayCapsUnsupported` → **+32 B and +~100 CU for `prior_authority_hash`** (milestone review), then re-measured under the mainnet feature set. |
| `revoke_session_root` (full root ceremony, closes the session PDA) | 20,968 | 778 B | `sessions::revoke_by_root_ok` | 8 B discriminator + 218 B `RootArgs` + 64 B `RevokeBody` (`session_pubkey` ‖ `refund_to`) of instruction data, plus the 182 B precompile instruction. Asserted `<= 1,232 B`. Round-1 review: was 20,505 CU / 746 B before `refund_to` was added to the signed body. |
| `revoke_session_self` (session key signs; no root ceremony) | 7,324 | 341 B | `sessions::revoke_by_session_self_ok` | 8 B of instruction data and no precompile instruction at all — the cheapest authenticated path in the program. |
| `freeze` (full root ceremony, root-only, 1A scope) | 15,891 | 680 B | `freeze::freeze_sets_state` (CU) / `freeze::freeze_tx_fits_1232_bytes` (bytes) | No arguments beyond `RootArgs` — same shape as `rotate_nonce`, so size and CU are effectively identical to it (the tens-of-CU spread between the two suites is measurement noise, not a real cost difference). |
| `unfreeze` (full root ceremony, timelock elapsed) | 15,914 | 680 B | `freeze::unfreeze_after_timelock_ok` (CU) / `freeze::unfreeze_tx_fits_1232_bytes` (bytes) | Same shape as `freeze`/`rotate_nonce`. The `checked_add(frozen_at, policy.timelock_secs)` comparison is negligible CU on top of the shared root-verify cost. |
| `transfer` (session key, native SOL) | 18,533 | 386 B | `transfer::session_sol_transfer_within_caps` (CU) / `transfer::session_sol_transfer_tx_fits_1232_bytes` (bytes) | No precompile instruction and no root ceremony at all — 8 B discriminator + 18 B `TransferArgs` (`root: None` 1 B, `mint: None` 1 B, `amount` 8 B, plus option tags) over 7 accounts. The CU is the account PDA re-derivation, the session checks, `buckets::debit` (day roll + 30-slot ring sum) and the direct lamport move. |
| `transfer` (session key, SPL token) | 20,665 | 482 B | `transfer::session_spl_transfer_ok` (CU) / `transfer::session_spl_transfer_tx_fits_1232_bytes` (bytes) | +2,132 CU over the native path: two 165 B token-account parses plus the `spl_token::Transfer` CPI (the CPI's own cost is charged to this transaction). +96 B of accounts (source ATA + token program instead of two `None` placeholders). |
| `transfer` (passkey root, native SOL) | 25,749 | 727 B | `transfer::root_transfer_within_threshold_debits_buckets` (CU) / `transfer::root_transfer_tx_fits_1232_bytes` (bytes) | 8 B discriminator + 218 B `RootArgs` + 10 B of own arguments, plus the 182 B precompile instruction. ~7,200 CU above the session path is exactly the root ceremony (cf. `rotate_nonce` at 15.9k, which does the ceremony and nothing else); the `large_threshold` lookup is negligible. Root payload budget (C7) is respected with room to spare: 10 B of own arguments against the 400 B allowance. |
| `transfer` (passkey root, SPL token) | 27,886 | 823 B | `transfer::root_spl_transfer_ok` (CU) / `transfer::root_spl_transfer_tx_fits_1232_bytes` (bytes) | The root ceremony plus the SPL path — **the most expensive shape Phase 1A has**, still 14% of a default 200k-CU budget and 409 B under the packet limit. Asserted `<= 1,232 B` in the test, not merely printed (round-1 review). Worst case at `MAX_CLIENT_DATA_LEN` = 512 B of `clientDataJSON` would be ~1,171 B — inside the limit, but with only ~61 B to spare, which is the tightest margin of any 1A instruction. |

## Account sizes and artifact

| Thing | Size | Where it is pinned |
| --- | ---: | --- |
| `SmartAccount::LEN` (8 B Anchor discriminator + `Pod` body) | **4,120 B** | `state::smart_account::tests::smart_account_len_matches_size_of` (asserted against `size_of` AND a hand-summed field list) |
| — of which `Policy::LEN` | 1,448 B | `policy_len_matches_size_of_with_documented_padding` |
| — of which `buckets: [MintBuckets; 8]` | 2,112 B | `MintBuckets::LEN` = 264 B (`8 + 8 + 8 + 8 × RING_DAYS`), `mint_buckets_len_has_no_padding` |
| `SessionKey::LEN` (borsh, incl. discriminator) | **751 B** | `buckets::tests::len_constants_match_serialized_size_and_reserved_zeroed` (asserted against a real `try_to_vec`) |
| `MintCap::LEN` | 56 B | `mint_cap_len_has_no_padding` |
| `target/deploy/warden.so` | **382,832 B** | `anchor build` output at `4b409f7` (sha256 recorded in the task report) |

`SmartAccount` is `#[account(zero_copy)]` **because** 4,109 B of borsh
deserialization overflowed the 4 KB SBF stack frame (Task 2 review). Both
accounts carry a `_reserved` tail (256 B / 64 B) plus `guardians_config`,
`registry`, `frozen_at` and `cluster_tag`, so Phase 1B adds fields **without a
realloc**.

## Headroom

* CU: 15.9k of the 200k default per-transaction budget (1.4M max) for
  `root_verify`; 8.9k for `create_account`. Phase 1B's `execute`/swap paths
  ride on top of this, so the root check is ~8% of a default-budget
  transaction.
* Size: `root_verify` is 680 B of the 1,232 B transaction limit. `clientDataJSON`
  is capped at `MAX_CLIENT_DATA_LEN` = 512 B, which is the dominant variable;
  the worst case is ~1,030 B, still inside the limit but leaving little room
  for extra accounts. Root payload budget (C7) is respected: `rotate_nonce`
  carries 8 B of discriminator + 215 B of `RootArgs`; `grant_session`, the
  heaviest root instruction in Phase 1A, carries 229 B of its own arguments
  beyond `RootArgs` — about half the 400 B C7 allows.
* CU: `grant_session` is 30.7k of the 200k default budget (15%), and the
  create-the-PDA CPI is a one-off — a re-grant into an existing PDA skips it.
* The heaviest 1A shape end to end is a root SPL `transfer`: 27.9k CU (14%)
  and 823 B (67%). **Phase 1B's `execute` therefore has ~172k CU and ~409 B
  to work with on a root-authorized path**, before raising the compute-unit
  limit explicitly — which is the binding constraint the 1B plan must design
  against, not the 200k figure.

### `grant_session` transaction-size gate — why `MAX_CAPS_PER_GRANT` = 2

The plan (rev 2) fixed the limit at 2 caps from an estimate; this is the
measurement. A 2-cap grant is **976 B** of the 1,232 B packet limit, leaving
256 B of margin. Each additional cap costs 64 B on the wire (56 B `MintCap` +
8 B parallel `lifetime_cap`), so 3 caps would measure ~1,040 B and 4 caps
~1,104 B — both nominally inside the limit *for this `clientDataJSON`*.

The limit is nonetheless 2, because the variable that dominates is not the cap
count but `clientDataJSON`, which the program accepts up to
`MAX_CLIENT_DATA_LEN` = 512 B. A real browser's document is 164 B here, but a
different origin length, a `crossOrigin` field ordering, or any UA that pads
the document eats the margin directly: at 512 B of `clientDataJSON` a 2-cap
grant is already ~1,324 B and would not fit at all. Two caps is the
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

### Native SOL's cap key is the WRAPPED SOL mint

`Policy.caps`, `Policy.session_ceiling`, `Policy.large_threshold`,
`SessionKey.caps` and `SmartAccount.buckets` are all **keyed by mint**, and
`Pubkey::default()` is `buckets::find_cap`'s unused-slot sentinel — so native
SOL needs *some* real key. It uses the wrapped-SOL mint
`So11111111111111111111111111111111111111112` (`constants::NATIVE_MINT`),
which is what every Solana client already means by "SOL" in a mint-keyed
table.

This is the **cap-lookup key only**. A native transfer moves lamports
directly (the vault is a *data* account owned by this program, so the System
program cannot debit it) and never touches the wrapped-SOL mint account, never
wraps, never unwraps. The signed `TransferBody` says `native: true, mint:
Pubkey::default()` — the document a user sees says "no mint" rather than
leaking a sentinel — while the caps behind it are read under `NATIVE_MINT`.
Anything holding real WSOL *tokens* is an SPL transfer of that mint and shares
the same bucket, which is the intended behaviour: SOL and WSOL are one budget.

### Program id policy

`declare_id!` / `Anchor.toml` carry **`6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2`**,
and only the public key is committed — the program keypair is NOT in the repo
(Task 1 review: the first commit contained it; it was removed and the id
rotated, history-forward, with `*keypair*.json` gitignored). Consequences,
documented in full in `docs/PROGRAM-KEYS.md`:

* Tests never hardcode the id: they use `warden::ID`, and
  `transcript::tests::program_id_bytes_are_pinned` pins its raw bytes because
  the id is half the input of the pinned transcript vector — a silent
  `declare_id!` change would otherwise invalidate the digest instead of
  failing loudly.
* The **program id is inside every root transcript** (spec §4), so rotating it
  invalidates every outstanding assertion. That is the intended migration
  mechanism, not an accident.
* A fresh `anchor build` in a clone regenerates a *different* local keypair and
  warns about the mismatch. This is inherent Anchor behaviour and is left as
  is: tests are unaffected, and an actual deploy needs the owner's keypair plus
  `anchor keys sync`.
* Mainnet/devnet deployment ids are a Phase 1B/1C decision; nothing in 1A
  depends on the id beyond the transcript binding above.

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

## Pinned error ABI (6000–6035)

Anchor derives the on-wire code from **declaration order** (`6000 +
declaration index`), so every one of these is permanent the moment any client
ships against it: variants are **appended, never inserted or reordered**.
`root_verify::pinned_error_codes_match_the_enum_today` pins all 36 as
literals — it is the single place the enum is consulted, and it fails loudly
on any reorder. The table below is copied from that test's `mod err`.

| Code | Variant | Raised when |
| ---: | --- | --- |
| 6000 | `Overflow` | Any checked arithmetic would wrap (the crate forbids `clippy::arithmetic_side_effects`, so this is the only outcome). |
| 6001 | `Frozen` | The account is frozen and the instruction is an outflow-enabling one. |
| 6002 | `Unauthorized` | Signer/PDA-derivation mismatch: the account is not the PDA for its own `owner_seed`, or a session/refund key is not the bound one. |
| 6003 | `InvalidRootAssertion` | `rp_id_hash != SHA-256(origin)` at `create_account`. |
| 6004 | `NonceMismatch` | Reserved for an explicit nonce comparison; the transcript binds `root_nonce`, so a stale ceremony surfaces as `ChallengeMismatch`. |
| 6005 | `Expired` | `now > expiry_ts`, or `expiry_ts > now + 600 s`, or a grant's session `expiry_ts` is not in the future. |
| 6006 | `CapExceeded` | A per-tx / lifetime / day / 30-day cap would be breached, a granted cap exceeds `policy.session_ceiling`, a cap names a mint with no ceiling entry, a re-grant sets `lifetime_cap` below what is already spent, or every session cap slot is taken. |
| 6007 | `SessionExpired` | The session's `expiry_ts` has passed, or its `generation_at_grant` is stale. |
| 6008 | `OpNotAllowed` | `ops_mask` lacks the bit for this operation, exceeds `policy.session_ops_ceiling`, or sets a bit outside `OPS_MASK_KNOWN`. |
| 6009 | `InvalidAccountData` | Malformed values in a well-shaped instruction: bad `RootKey`/`FrozenState` tag, non-Ed25519 session kind, default/duplicate mint, orphan or mismatched ceiling entry, unparseable token account. |
| 6010 | `BadInstructionLayout` | Structurally wrong instruction: more than `MAX_CAPS_PER_GRANT` caps, parallel vectors of different length, both/neither of `root` and `session` on `transfer`, wrong Instructions-sysvar address. |
| 6011 | `ClientDataTooLong` | `clientDataJSON` exceeds `MAX_CLIENT_DATA_LEN` (512 B). |
| 6012 | `ClientDataMalformed` | The document is not valid UTF-8, or not well-formed JSON for the strict depth-0 scanner (bad escape, control byte, broken number/container grammar). |
| 6013 | `ClientDataDuplicateKey` | A duplicated top-level key — known or unknown, raw or unicode-escaped. |
| 6014 | `ClientDataMissingKey` | A required top-level key (`type`, `challenge`, `origin`) is absent. |
| 6015 | `ClientDataTypeMismatch` | `type != "webauthn.get"`. |
| 6016 | `CrossOriginNotAllowed` | A top-level `crossOrigin` key is present and true. |
| 6017 | `OriginMismatch` | `origin` is not the account's stored origin. |
| 6018 | `ChallengeMismatch` | The rebuilt transcript does not match the signed `challenge` — the catch-all for a tampered argument, a stale nonce, or a substituted `transfer` destination/amount. |
| 6019 | `AuthDataTooShort` | `authenticatorData` is under 37 bytes. |
| 6020 | `RpIdHashMismatch` | `authenticatorData[0..32]` is not the account's stored `rp_id_hash`. |
| 6021 | `UserVerificationRequired` | UP and UV are not both set (decision **O10**: UV is mandatory for the root in v1). |
| 6022 | `PrecompileNotFound` | No secp256r1 instruction at the named index *before* this one. |
| 6023 | `PrecompileBindingMismatch` | The precompile instruction does not bind exactly this key and message, or carries more than one signature, or uses non-self-contained instruction indices. |
| 6024 | `RootKindUnsupported` | The stored root is Ed25519 on a passkey path — and, since the milestone review, an attempt to CREATE an Ed25519-rooted account. |
| 6025 | `InvalidOrigin` | The origin is not exactly `chrome-extension://` + 32 characters from `a..=p`. |
| 6026 | `ZeroClusterTag` | `cluster_tag` is all zero. |
| 6027 | `InvalidPolicy` | Timelock/recovery below one hour, `max_session_life_secs` non-positive or above 30 days, cap ordering violated, ceiling above cap, or an unassigned bit in `session_ops_ceiling`. |
| 6028 | `ProgramAllowlistUnsupported` | `program_allowlist_id != 0` before the Phase 1B adapter registry exists. |
| 6029 | `AlreadyFrozen` | `freeze` on an account already frozen by the root. |
| 6030 | `TimelockNotElapsed` | `unfreeze` before `frozen_at + policy.timelock_secs`. |
| 6031 | `RentFloor` | A native transfer would leave the **vault** below `Rent::minimum_balance(data_len)`. Distinct from the runtime's `InsufficientFundsForRent`, which is about the **destination** and is a transaction error no program can catch. |
| 6032 | `VaultDestination` | The SPL destination token account is owned by the smart account itself (or is the source) — value would not leave the wallet while the caps were debited. |
| 6033 | `SessionDayCapsUnsupported` | A `grant_session` cap sets `per_day` or `per_30d` (see the bound statement above). |
| 6034 | `InvalidRootKey` | The P-256 root is not a well-formed compressed-point encoding (prefix not `0x02`/`0x03`, or `x >= p`). Milestone review. |
| 6035 | `SessionPriorStateMismatch` | `GrantBody.prior_authority_hash` is not the session's current retained authority (or is non-zero for a PDA that does not exist yet). Milestone review. |

Both `RentFloor` and `ChallengeMismatch` (6018, raised by `transfer` when a
root ceremony's destination or amount is substituted) are deliberately reused
rather than specialised further: `ChallengeMismatch` is what every other root
instruction raises for a rebuilt-transcript mismatch, and splitting it per
instruction would tell an attacker which field they got wrong.

## Verification provenance

Both commands were run, serialized (`nice -n 10`, one cargo build at a time —
this host hard-hangs on concurrent heavy builds), under
`source ~/.cargo/env; export PATH=/root/.local/share/solana/install/active_release/bin:$PATH`:

| Command | Result | Passed at |
| --- | --- | --- |
| `./.claude/test-gate.sh` | **exit 0** — 292 Rust tests (144 lib + 27 `create_account` + 12 `freeze` + 33 `root_verify` + 33 `sessions` + 1 `smoke` + 42 `transfer`) and 39 TS tests (20 `packages/core` incl. the transcript parity vectors, 11 `packages/ui-tokens`, 8 `spikes/03-txbudget`, 1 Playwright WebAuthn spike) | `4b409f7` |
| `cargo clippy -p warden --lib -- -D clippy::arithmetic_side_effects` | **exit 0**, zero lint hits (13 pre-existing `unexpected_cfgs` warnings from Anchor's `#[program]` macro) | `4b409f7` |

The gate builds the SBF artifact itself when any source, manifest, lockfile or
`Anchor.toml` is newer than `target/deploy/warden.so`, so a clean checkout
reproduces green without a manual `anchor build`. The only changes made after
this run were to Markdown files (this document, the spec, `DECISION.md`),
which the gate does not read.

## Milestone review (Phase 1A close-out)

Reviewer: `mcp__codex__codex`, **`gpt-5.6-sol` @ `max`**, `approval-policy:
on-request`, read-only, no subagents, `cwd: /opt/warden`. (Every task also got
its own review at commit time — threads in the SDD ledger.)

**Round 1 — thread `01a01637`, at `49887ca`: REVISE.** 0 Critical, 3
Important, 2 Minor.

1. *Important — re-grant did not bind the authority it produced.*
   `grant_session` merges caps by mint and refreshes `generation_at_grant`, so
   a one-mint body produced a session that still held every previously granted
   mint: authority absent from the signed document, and after a 1B generation
   bump a minimal re-grant would have revived every capability of a session the
   bump had just invalidated. **Fixed:** `GrantBody.prior_authority_hash` binds
   the pre-merge state (`SessionPriorStateMismatch`, 6035); the merge is a pure
   function of `(pre-state, body)`, so binding both binds the result. +32 B on
   the wire. Proven by
   `sessions::regrant_cannot_silently_retain_caps_the_signer_never_saw`, which
   signs the actual attack.
2. *Important — `create_account` could mint a permanently unusable root.*
   **Fixed:** Ed25519 refused at creation, the root must be a compressed-point
   encoding (`InvalidRootKey`, 6034), and the origin must be exactly
   `chrome-extension://` + 32 `a..p` characters (the old rule accepted
   `chrome-extension://abc`, whose `rp_id_hash` no authenticator will ever
   sign).
3. *Important — unassigned `ops_mask` bits were storable* and would become
   authority the day a later version assigned them. **Fixed:** `OPS_MASK_KNOWN`
   enforced in both `create_account` (the ceiling) and `grant_session`.
4. *Minor — `clientDataJSON` was not UTF-8-validated.* **Fixed:** one
   `core::str::from_utf8` pass up front (+~194 CU).
5. *Minor — `max_session_life_secs` had no lower bound.* **Fixed:** must be
   positive, or the account can never grant a session.

**Round 2 (scoped to the fix diff `49887ca..b59d2ce`) — thread `01a0164f`:
REVISE.** Confirmed every fix above as sound (and the prior-state hash's
covered/excluded field set, its computation before mutation, and the
fresh-vs-existing separation as correct), with two findings on the root-key
check:

* *Minor — rejecting `x == 0` was wrong.* P-256 **has** a valid point at
  x = 0. **Fixed** (`4b409f7`).
* *Important — an encoding check is weaker than an on-curve check.*
  **ACCEPTED and DEFERRED to Phase 1B, deliberately.** Two complete fixes were
  attempted: (1) Euler's criterion via `sol_big_mod_exp` — implemented, then
  reverted, because the syscall is gated behind `enable_big_mod_exp_syscall`,
  which litesvm 0.12's mainnet-active snapshot (2026-04-26) does not list, and
  the program aborted with "unsupported BPF instruction" even under
  `with_mainnet_features()`; shipping a program that calls a syscall whose
  activation on the target cluster cannot be verified would make **every**
  `create_account` fail, which is strictly worse than the defect; (2)
  hand-rolled 256-bit field arithmetic — rejected on risk at the close of a
  milestone. The complete property is **proof of possession at creation** (the
  precompile then does the curve validation for free), which does not fit 1A's
  packet budget beside a 4-mint policy and is carried into 1B's pre-ship gate
  (`docs/spikes/DECISION.md`). The residual is a **self-inflicted-loss vector,
  not a theft vector** — a root nobody can sign for is a dead account, not a
  stolen one, and reaching it requires a client that invents a root pubkey
  instead of reading the authenticator's SPKI. The unit test
  `root_accepts_an_off_curve_x_phase_1a_gap` states the gap in the suite and
  must flip when 1B closes it. **Client requirement until then: round-trip one
  real root instruction (`rotate_nonce`) against a new account BEFORE funding
  it.**

**What the reviewer considers PROVEN by tests** (round 1, verbatim in
substance): nonce consumption and real replay rejection; expiry boundaries;
transcript field separation; stored origin / `rp_id_hash` and UP+UV; scanner
depth, duplicate, escape, grammar and length handling; precompile key/message
binding, self-contained indices, single signature, prior ordering; policy
expansion and ceilings; `GrantBody` tamper binding, expiry/ops/allowlist
checks, revoke refund binding; UTC rollover, the 30-day ring, skipped days,
overflow, debit atomicity; buckets shared across two sessions and across
root+session; lifetime caps; root freeze/timelock; the SOL rent floor; SPL
owner/mint/program/destination validation; CPI rollback; `TransferBody`
destination and amount binding.

**Merely implemented, or out of 1A scope:** adversarial pre-funded /
re-initialization cases for `init_if_needed`; full root/native
downstream-failure rollback (only the session SPL CPI has a raw-state rollback
assertion); any *real* cluster binding (`cluster_tag` is caller-attested by
construction); root usability (the gap above). Guardian freeze expiry/cooldown,
the recovery-open interplay and queued guardian unfreeze are **not implemented
in 1A** — `FrozenState::Guardian` is reserved state only — and the rest of §5
(`execute`, `swap`, `queue`, recovery) is 1B.

## Update policy

Append a row per measured path; do not delete rows — a regression is only
visible against the previous number. Re-measure when the SBF toolchain, the
Anchor version, **or the harness feature set** changes.
