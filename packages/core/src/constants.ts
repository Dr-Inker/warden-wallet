/** Platform fee on in-app swaps, basis points (spec §14: Phantom parity). */
export const FEE_BPS = 85;
/** Whole serialized Solana transaction limit in bytes (spec global constraints). */
export const MAX_TX_BYTES = 1232;
/**
 * Largest payload a single `stage_chunk` transaction may carry (spec §5.1,
 * Task 4). This is the **v0 (`VersionedTransaction`) cap** — the format this
 * client compiles — which is 2 B larger on the wire than legacy (979), so it is
 * the conservative contract. Mirrors the Rust `STAGE_CHUNK_PAYLOAD_CAP` and is
 * pinned to it by the on-chain measurement `stage::stage_chunk_payload_cap_is_measured`.
 * A client splits a payload into `ceil(len / STAGE_CHUNK_PAYLOAD_CAP)` chunks.
 */
export const STAGE_CHUNK_PAYLOAD_CAP = 977;
/**
 * The most `remaining_accounts` one `execute` accepts (logical accounts past the
 * two privileged slots). MEASURED and HEAP-bound (PHASE1B-MEASUREMENTS §"Task 6
 * heap lift"); mirrors the Rust `MAX_EXECUTE_ACCOUNTS_TOTAL`, enforced on-chain
 * (`remaining.len() <= MAX_EXECUTE_ACCOUNTS_TOTAL`, else `TooManyExecuteAccounts`).
 * The wrapper enforces it client-side so an over-cap shape fails fast, not on-chain.
 */
export const MAX_EXECUTE_ACCOUNTS_TOTAL = 32;
/**
 * The most WRITABLE `remaining_accounts` one `execute` accepts. Mirrors the Rust
 * `MAX_EXECUTE_WRITABLE`, enforced on-chain (else `TooManyExecuteWritable`).
 */
export const MAX_EXECUTE_WRITABLE = 28;
