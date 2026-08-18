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

## Headroom

* CU: 15.5k of the 200k default per-transaction budget (1.4M max). Phase 1B's
  `execute`/swap paths ride on top of this, so the root check is ~8% of a
  default-budget transaction. (First measured at 15,711 CU; 15,533 after the
  round-1 review replaced the bracket-counting skipper with a full JSON
  validator.)
* Size: 680 B of the 1,232 B transaction limit. `clientDataJSON` is capped at
  `MAX_CLIENT_DATA_LEN` = 512 B, which is the dominant variable; the worst case
  is ~1,030 B, still inside the limit but leaving little room for extra
  accounts. Root payload budget (C7) is respected: `rotate_nonce` carries 8 B of
  discriminator + 215 B of `RootArgs`.

## Update policy

Append a row per measured path; do not delete rows — a regression is only
visible against the previous number. Re-measure when the SBF toolchain or
Anchor version changes.
