/**
 * The ONE place the shipped extension names the cluster and the Warden
 * deployment it will adopt an encrypted keyring record for (audit finding K-1).
 *
 * Why this module exists at all: the keyring record's context is
 * AAD-authenticated, so it cannot be edited without the KEK — but a whole record
 * can be REPLACED by a different, validly sealed one. Without a build-owned
 * expectation, `KeyringLifecycleOwner` would take the cluster and program id
 * from the very record it is deciding whether to trust, and `WRD-KEY-04`'s
 * cross-cluster promise would stop at the AEAD layer instead of reaching the
 * trust boundary. A Warden SmartAccount PDA is not network-qualified, so the
 * same address exists on devnet and mainnet: a devnet record must not unlock a
 * mainnet-pinned build.
 *
 * Why the bytes are literals here rather than imported from core: the core
 * module that publishes these public pins is one of the RPC/authority-resolver
 * modules `scripts/build.mjs` forbids in the background bundle, and a core test
 * additionally asserts that no file under `apps/extension/src` names it at all.
 * The literals below are the SAME public values, and
 * `test/expected-keyring-context.test.ts` — which is not bundled — imports the
 * core constants and fails on any drift between the two.
 *
 * Changing `EXTENSION_PINNED_CHAIN` is a release decision, not a refactor: every
 * record sealed under the previous pin stops unlocking, by design.
 */

/** The chain literal this build pins, in the repo's `solana:<cluster>` spelling. */
export const EXTENSION_PINNED_CHAIN = "solana:mainnet" as const;

/**
 * `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d` — Solana mainnet-beta genesis
 * hash, the same literal as `SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES["solana:mainnet"]`
 * and `MAINNET_GENESIS_HASH` in `packages/core/src/deploy/config.ts`.
 */
const PINNED_GENESIS_HASH = Uint8Array.of(
  0x45, 0x29, 0x69, 0x98, 0xa6, 0xf8, 0xe2, 0xa7,
  0x84, 0xdb, 0x5d, 0x9f, 0x95, 0xe1, 0x8f, 0xc2,
  0x3f, 0x70, 0x44, 0x1a, 0x10, 0x39, 0x44, 0x68,
  0x01, 0x08, 0x98, 0x79, 0xb0, 0x8c, 0x7e, 0xf0,
);

/**
 * `6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2` — the shipped Warden program id,
 * the same literal as `SESSION_AUTHORITY_WARDEN_PROGRAM_ID`.
 */
const PINNED_PROGRAM_ID = Uint8Array.of(
  0x01, 0x7b, 0x5f, 0x72, 0xe2, 0xc0, 0x74, 0xfa,
  0x85, 0x55, 0x20, 0x6d, 0xb7, 0xcc, 0xf4, 0x65,
  0xc1, 0xdb, 0x51, 0x3c, 0x72, 0x59, 0x13, 0xca,
  0x7c, 0xe6, 0x85, 0xf1, 0x35, 0xf8, 0xbd, 0x51,
);

/**
 * A fresh copy of the shipped pin. Returns new buffers on every call because
 * `Object.freeze` does not make a `Uint8Array`'s contents immutable, and a
 * consumer that could edit these bytes could widen the check it is meant to
 * enforce.
 */
export function shippedExpectedKeyringContext(): {
  readonly genesisHash: Uint8Array;
  readonly programId: Uint8Array;
} {
  return Object.freeze({
    genesisHash: PINNED_GENESIS_HASH.slice(),
    programId: PINNED_PROGRAM_ID.slice(),
  });
}
