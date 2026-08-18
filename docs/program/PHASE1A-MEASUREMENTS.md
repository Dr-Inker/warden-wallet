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
| `create_account` (all-defaults `PolicyArgs`, no mint caps used) | 12,767 | 1,804 B | `create_account::creates_with_defaults` | 1,567 B of instruction data (8 B discriminator + `CreateAccountArgs`), no precompile ix (no root signature required to create). **`CreateAccountArgs` alone exceeds the 1,232 B packet limit — see the note below; this is not submittable as a real Solana transaction as currently shaped.** |

## Headroom

* CU: 15.5k of the 200k default per-transaction budget (1.4M max) for
  `root_verify`; 12.8k for `create_account`. Phase 1B's `execute`/swap paths
  ride on top of this, so the root check is ~8% of a default-budget
  transaction. (`root_verify` first measured at 15,711 CU; 15,533 after the
  round-1 review replaced the bracket-counting skipper with a full JSON
  validator.)
* Size: `root_verify` is 680 B of the 1,232 B transaction limit. `clientDataJSON`
  is capped at `MAX_CLIENT_DATA_LEN` = 512 B, which is the dominant variable;
  the worst case is ~1,030 B, still inside the limit but leaving little room
  for extra accounts. Root payload budget (C7) is respected: `rotate_nonce`
  carries 8 B of discriminator + 215 B of `RootArgs`.

### `create_account` transaction-size finding (owed follow-up)

`CreateAccountArgs::policy: PolicyArgs` carries `Policy`'s three full
`[MintCap; MAX_MINT_CAPS]` arrays (`caps`, `session_ceiling`,
`large_threshold` — 8 slots each, 56 B per `MintCap`), Borsh-serialized in
full regardless of how many slots are actually used. That alone is
`3 * 8 * 56 = 1,344 B`; with `owner_seed`(32) + `root`(34) + `rp_id_hash`(32)
+ `origin`(4 B length prefix + up to 64) + `cluster_tag`(32) +
`timelock_secs`/`recovery_delay_secs`/`max_session_life_secs`(24) +
`session_ops_ceiling`(2) + the 8 B Anchor discriminator, the measured
all-defaults instruction is **1,567 B of data alone** — before the
transaction header, the `payer` signature (64 B), and account keys. The
measured all-defaults transaction is **1,804 B**, ~46% over Solana's
1,232 B packet limit (`PACKET_DATA_SIZE`). LiteSVM's `send_transaction`
does **not** enforce this limit (there is no wire/UDP layer in the
simulator), which is why `creates_with_defaults` passes in this suite but
would be rejected by a real validator before execution even begins.

This is a shape the reviewers specified for Task 4 (`CreateAccountArgs`
carries a Borsh `PolicyArgs` mirroring `Policy` field-for-field), so this
report flags it rather than silently redesigning the interface. Candidates
for a follow-up task: (a) a variable-length `Vec<(u8 slot_index, MintCap)>`
of only the *used* slots in the wire args, expanded into the fixed 8-slot
`Policy` on-chain (zero-filling the rest) — this is the standard "sparse on
the wire, dense on account" pattern and would cut the common case (0-2 caps
configured) to well under the limit; or (b) splitting policy configuration
into its own root-authorized instruction issued after `create_account`
(mirrors how `rotate_nonce` already treats policy changes as root actions in
spec §5.1), so `create_account` itself only ever carries the always-present
scalar fields. Either requires a plan-level decision, not a Task 4 code
change, since Task 4's args shape was pinned by the reviewers' follow-on
requirement.

## Update policy

Append a row per measured path; do not delete rows — a regression is only
visible against the previous number. Re-measure when the SBF toolchain or
Anchor version changes.
