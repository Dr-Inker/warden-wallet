/**
 * TypeScript mirror of `programs/warden/src/root_verify/transcript.rs`.
 *
 * This is the exact byte encoding the passkey signs over, and the
 * base64url encoding the browser puts in `clientDataJSON.challenge`. Every
 * value here MUST stay byte-for-byte identical to the Rust source — the
 * pinned test vector in `test/transcript.test.ts` is copied verbatim from
 * the Rust `transcript_hash_matches_pinned_vector` /
 * `action_hash_matches_pinned_vectors` tests to prove cross-language parity.
 * If the two ever disagree, one side has drifted and every root ceremony
 * breaks.
 *
 * ```text
 * transcript = Keccak256(
 *     "WARDEN/root/v1"
 *   ‖ cluster_tag         (32 B)   <- SmartAccount.cluster_tag, client-attested
 *   ‖ program_id          (32 B)
 *   ‖ account              (32 B)
 *   ‖ generation           u64 LE
 *   ‖ policy_version       u32 LE
 *   ‖ root_nonce           u64 LE
 *   ‖ expiry_ts            i64 LE
 *   ‖ signed_slot          u64 LE   <- Phase 1B: freshness is slot-based
 *   ‖ action_hash          (32 B)
 * )
 * action_hash = Keccak256(op_type:u8 ‖ borsh(op_args))
 * challenge   = base64url_nopad(transcript)
 * ```
 *
 * **`signed_slot` sits between `expiry_ts` and `action_hash`, and the position
 * is part of the ABI** (spec §4, rev 8) — not an implementation detail. A
 * disagreement between this file and `transcript.rs` on that position forges
 * or bricks every ceremony (prior-art finding `LZR-ACC-H2`: write/read layout
 * drift). Three golden vectors pin it: the positive one, an
 * `expiryTs = -1n` companion that proves two's-complement i64 LE, and a
 * `signedSlot = 2^64 - 1` companion that proves the slot really is a full
 * `u64` LE and not a truncated `u32`.
 *
 * The caller must fetch the current slot (`connection.getSlot()`) before the
 * ceremony and sign it: the program requires
 * `signedSlot <= Clock.slot < signedSlot + 150`, so a ceremony built against a
 * slot more than ~60 s old, or against a future slot, is rejected
 * (`RootSlotStale` 6036 / `RootSlotInFuture` 6037).
 *
 * No `blockhash` is included, deliberately: a program cannot authenticate
 * the outer message's blockhash, so binding one would be security theatre.
 * Replay is prevented by `root_nonce` (consumed on every successful root
 * instruction) plus the two freshness windows. See `transcript.rs` for the
 * full rationale, including the caveat that `cluster_tag` is a client-attested
 * domain separator, not a verified genesis binding.
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

/** Domain separator. Bumping the `/v1` suffix invalidates every outstanding assertion. */
export const TRANSCRIPT_DOMAIN: Uint8Array = new TextEncoder().encode("WARDEN/root/v1");

/**
 * `op_type` byte for `rotate_nonce` (Task 3). Further ops are appended below;
 * the byte is part of the signed transcript, so values are permanent.
 */
export const OP_ROTATE_NONCE = 0x00;
/**
 * `op_type` byte for `grant_session` (Task 5); hashed over
 * `borsh(GrantBody)` — every `grant_session` argument except `root`.
 *
 * `GrantBody` field order (borsh, `programs/warden/src/instructions/grant_session.rs`):
 * `expiry_ts: i64`, `session_pubkey: Pubkey (32B)`, `kind: u8`,
 * `ops_mask: u16`, `caps: Vec<MintCap>`, `lifetime_cap: Vec<u64>`,
 * `program_allowlist_id: u16`, `label: [u8; 16]`,
 * `prior_authority_hash: [u8; 32]` — the WRD-SESS-05 merge binding
 * (`SessionKey::authority_hash()` of the session PDA BEFORE this grant, or the
 * 32-zero sentinel for a fresh grant). Build the body with {@link
 * encodeGrantBody}: the trailing hash is signed but carried nowhere else, so a
 * hand-rolled short body signs a different action hash and the program answers
 * `ChallengeMismatch` (6018) — exactly the WRDF-0042 create-body hole, which is
 * why grant now has a canonical encoder too (GROK-EXP-07).
 */
export const OP_GRANT_SESSION = 0x01;

/**
 * Session `ops_mask` BITS (`state::session.rs`: `OP_TRANSFER = 1<<0`,
 * `OP_EXECUTE = 1<<1`, `OP_SWAP = 1<<2`, `OP_SIGN_MESSAGE = 1<<3`). These are a
 * DIFFERENT namespace from the `OP_*` action-hash bytes above: the action byte
 * `OP_TRANSFER` is `0x05`, but the transfer ops-mask bit is `0x01`. A grant's
 * `ops_mask` MUST be built from these `OPS_MASK_*` constants — using the action
 * bytes would grant a wider or wrong permission set that the program then
 * verifies against, because that mask is what was hashed (defense-in-depth
 * item 4, GROK-EXP-07).
 */
export const OPS_MASK_TRANSFER = 1 << 0;
export const OPS_MASK_EXECUTE = 1 << 1;
export const OPS_MASK_SWAP = 1 << 2;
export const OPS_MASK_SIGN_MESSAGE = 1 << 3;

/** Fields of a `grant_session` ceremony body. */
export interface GrantBodyFields {
  /** Absolute unix seconds the SESSION expires. */
  expiryTs: bigint;
  /** The session delegate key (32 bytes). */
  sessionPubkey: Uint8Array;
  /** `SESSION_KIND_ED25519` (0) is the only value 1B accepts. */
  kind: number;
  /** Bit-OR of the `OPS_MASK_*` constants — NOT the `OP_*` action bytes. */
  opsMask: number;
  /** Per-mint caps, in the same mint order as `lifetimeCap`. */
  caps: { mint: Uint8Array; perTx: bigint; perDay: bigint; per30d: bigint }[];
  /** Lifetime cap per `caps[i].mint`; exactly as long as `caps`. */
  lifetimeCap: bigint[];
  /** spec §5.1 adapter-registry list id (0 = none). */
  programAllowlistId: number;
  /** 16-byte free-form display label. */
  label: Uint8Array;
  /** `SessionKey::authority_hash()` before this grant, or 32 zero bytes for a
   * fresh grant (32 bytes). */
  priorAuthorityHash: Uint8Array;
}

/**
 * Canonical borsh encoding of `GrantBody` — mirrors the Rust field order
 * exactly, INCLUDING the trailing `prior_authority_hash`. Do not hand-roll it
 * (GROK-EXP-07 / WRDF-0042).
 */
export function encodeGrantBody(f: GrantBodyFields): Uint8Array {
  require32(f.sessionPubkey, "sessionPubkey");
  require32(f.priorAuthorityHash, "priorAuthorityHash");
  if (f.label.length !== 16) throw new Error("label must be 16 bytes");
  if (f.caps.length !== f.lifetimeCap.length)
    throw new Error("caps and lifetimeCap must be the same length");
  assertU8(f.kind, "kind");
  assertU16(f.opsMask, "opsMask");
  assertU16(f.programAllowlistId, "programAllowlistId");
  assertI64(f.expiryTs, "expiryTs");
  // borsh: i64 | pubkey | u8 | u16 | Vec<MintCap> | Vec<u64> | u16 | [u8;16] | [u8;32]
  const capBytes = 4 + f.caps.length * (32 + 8 + 8 + 8);
  const lifeBytes = 4 + f.lifetimeCap.length * 8;
  const body = new Uint8Array(8 + 32 + 1 + 2 + capBytes + lifeBytes + 2 + 16 + 32);
  const dv = new DataView(body.buffer);
  let o = 0;
  dv.setBigInt64(o, f.expiryTs, true); o += 8;
  body.set(f.sessionPubkey, o); o += 32;
  body[o] = f.kind; o += 1;
  dv.setUint16(o, f.opsMask, true); o += 2;
  dv.setUint32(o, f.caps.length, true); o += 4;
  for (const c of f.caps) {
    require32(c.mint, "cap.mint");
    assertU64(c.perTx, "cap.perTx"); assertU64(c.perDay, "cap.perDay"); assertU64(c.per30d, "cap.per30d");
    body.set(c.mint, o); o += 32;
    dv.setBigUint64(o, c.perTx, true); o += 8;
    dv.setBigUint64(o, c.perDay, true); o += 8;
    dv.setBigUint64(o, c.per30d, true); o += 8;
  }
  dv.setUint32(o, f.lifetimeCap.length, true); o += 4;
  for (const l of f.lifetimeCap) { assertU64(l, "lifetimeCap[i]"); dv.setBigUint64(o, l, true); o += 8; }
  dv.setUint16(o, f.programAllowlistId, true); o += 2;
  body.set(f.label, o); o += 16;
  body.set(f.priorAuthorityHash, o);
  return body;
}
/**
 * `op_type` byte for the root path of session revocation (Task 5); hashed
 * over `borsh(RevokeBody)`. The session-self path carries no root assertion
 * and therefore no action hash.
 *
 * `RevokeBody` field order (borsh, `programs/warden/src/instructions/revoke_session.rs`):
 * `session_pubkey: Pubkey (32B)`, `refund_to: Pubkey (32B)`.
 */
export const OP_REVOKE_SESSION = 0x02;
/**
 * `op_type` byte for `freeze` (Task 6). Like `rotate_nonce`, it has no
 * arguments of its own beyond `RootArgs`, so it is hashed over an empty
 * borsh payload (`actionHash(OP_FREEZE, new Uint8Array())`).
 */
export const OP_FREEZE = 0x03;
/** `op_type` byte for `unfreeze` (Task 6); same empty-payload shape as `OP_FREEZE`. */
export const OP_UNFREEZE = 0x04;

/**
 * `op_type` byte for the ROOT path of `transfer` (Task 7); hashed over
 * `borsh(TransferBody)`.
 *
 * Named `OP_TRANSFER_ACTION` in Rust
 * (`programs/warden/src/root_verify/transcript.rs`) purely to avoid colliding
 * with `state::session::OP_TRANSFER`, which is the session `ops_mask` BIT
 * (`1 << 0`) — an unrelated number in an unrelated namespace. If a future task
 * mirrors the `ops_mask` bits here, they MUST be exported under a distinct
 * prefix (e.g. `OPS_MASK_TRANSFER`) rather than shadowing this constant.
 *
 * `TransferBody` field order (borsh, `programs/warden/src/instructions/transfer.rs`):
 * `native: bool (1B, 0x00/0x01)`, `mint: Pubkey (32B)`,
 * `destination: Pubkey (32B)`, `amount: u64 (8B LE)` — 73 B total, fixed
 * width (no Option tags, no Vec length prefixes).
 *
 * Two field notes matter for building the ceremony client-side:
 * - `native` is carried ALONGSIDE `mint`, not inferred from it: when
 *   `native` is `true`, `mint` is the all-zero pubkey (`Pubkey::default()`),
 *   even though the on-chain caps for native SOL are looked up under the
 *   wrapped-SOL mint `So11111111111111111111111111111111111111112`. The
 *   signed document says "no mint" so a client displaying a pending
 *   assertion never has to know the zero pubkey is a sentinel.
 * - `destination` is the DESTINATION ACCOUNT's key (a plain system account
 *   for SOL, a token account for SPL) taken from the accounts actually
 *   passed — `transfer` has no destination *argument* at all. The client must
 *   therefore sign over exactly the account key it will submit, or the
 *   on-chain rebuild fails with `ChallengeMismatch` (6018).
 */
export const OP_TRANSFER = 0x05;

/**
 * `op_type` byte for `create_account`'s proof-of-possession ceremony (Phase 1B
 * Task 2b); hashed over `borsh(CreateBody)`.
 *
 * `CreateBody` field order (borsh,
 * `programs/warden/src/instructions/create_account.rs`):
 * `salt: [u8; 32]`, `rp_id_hash: [u8; 32]`, `origin: Vec<u8>` (u32 LE length
 * prefix, then the bytes), `cluster_tag: [u8; 32]`,
 * `policy_hash: [u8; 32]`, `registry: Pubkey` (32 B) — 215 B for the
 * canonical 51-byte `chrome-extension://…` origin. `policy_hash` is
 * `Keccak256(borsh(PolicyArgs))`. `registry` is the supported-version
 * Registry PDA the account binds to (Task 3, WRDF-0034); pass the
 * all-zero `Pubkey::default()` to bind no registry. Build the body with
 * {@link encodeCreateBody} — do not hand-roll it, or the omitted trailing
 * `registry` word signs a different action hash and the program answers
 * `ChallengeMismatch` (6018).
 *
 * Three things a client must get right, because each one is signed but not
 * transmitted in the body:
 * - **`salt`, never `owner_seed`.** The seed is DERIVED on-chain (see
 *   {@link deriveOwnerSeed}); signing it too would be redundant and would let
 *   the two drift.
 * - **The transcript's `account` is the derived address**, not an address the
 *   client picks: `["account", deriveOwnerSeed(rootPubkey33, salt)]` under the
 *   Warden program id. Sign the wrong address and the program answers
 *   `ChallengeMismatch` (6018).
 * - **The transcript state is the newborn account's**: `generation = 0n`,
 *   `policyVersion = 1`, `rootNonce = 0n`. The account is written with
 *   `root_nonce = 1` — creation consumes its own ceremony — so the NEXT
 *   ceremony for that account signs `rootNonce = 1n`, not `0n`.
 *
 * The root key is deliberately absent from the body: the assertion is verified
 * *under* that key by the secp256r1 precompile, and the address is derived
 * from it, so substituting it cannot produce a valid challenge.
 */
export const OP_CREATE = 0x06;

/** Fields of a `create_account` ceremony body. All hashes/keys are 32 bytes. */
export interface CreateBodyFields {
  /** 32 client-chosen random bytes. */
  salt: Uint8Array;
  /** `Sha256(rp_id)` — 32 bytes. */
  rpIdHash: Uint8Array;
  /** The WebAuthn origin string, e.g. `chrome-extension://…` (UTF-8 encoded here). */
  origin: string;
  /** 32-byte cluster domain separator. */
  clusterTag: Uint8Array;
  /** `Keccak256(borsh(PolicyArgs))` — 32 bytes. */
  policyHash: Uint8Array;
  /**
   * The supported-version Registry PDA this account binds to (32 bytes).
   * Omit or pass the all-zero key to bind no registry (`Pubkey::default()`).
   */
  registry?: Uint8Array;
}

/** 32 all-zero bytes — `Pubkey::default()`, the "no registry" sentinel. */
const PUBKEY_DEFAULT = new Uint8Array(32);

/**
 * Serialize a {@link CreateBodyFields} into the exact `borsh(CreateBody)` the
 * program hashes (see the {@link OP_CREATE} field order). This is the ONE
 * supported construction — clients MUST NOT hand-roll the byte layout, because
 * the trailing `registry` word is signed but not otherwise transmitted, so
 * omitting it silently signs a different action hash (`ChallengeMismatch`).
 *
 * `origin` is length-prefixed with a borsh `Vec<u8>` u32 LE prefix.
 */
export function encodeCreateBody(f: CreateBodyFields): Uint8Array {
  require32(f.salt, "salt");
  require32(f.rpIdHash, "rpIdHash");
  require32(f.clusterTag, "clusterTag");
  require32(f.policyHash, "policyHash");
  const registry = f.registry ?? PUBKEY_DEFAULT;
  require32(registry, "registry");
  const origin = new TextEncoder().encode(f.origin);
  const body = new Uint8Array(32 + 32 + 4 + origin.length + 32 + 32 + 32);
  let o = 0;
  body.set(f.salt, o);
  o += 32;
  body.set(f.rpIdHash, o);
  o += 32;
  new DataView(body.buffer).setUint32(o, origin.length, true); // borsh Vec<u8> length
  o += 4;
  body.set(origin, o);
  o += origin.length;
  body.set(f.clusterTag, o);
  o += 32;
  body.set(f.policyHash, o);
  o += 32;
  body.set(registry, o);
  return body;
}

/**
 * `op_type` byte for the ROOT path of `execute` (Phase 1B Task 5); hashed
 * over `borsh(ExecuteBody)`.
 *
 * `ExecuteBody` field order (borsh,
 * `programs/warden/src/instructions/execute.rs`):
 * `payload_hash: [u8; 32]` — `Keccak256(ExecutePayload wire bytes)` — then
 * `accounts_hash: [u8; 32]` — `Keccak256(logical list: pubkey ‖ is_signer ‖
 * is_writable, in logical order)`. 64 bytes, no prefixes. Both hashes are
 * rebuilt ON-CHAIN from the bytes and accounts actually passed, so the SDK
 * must reconstruct the logical list `[smart_account, signer] ++
 * remaining_accounts` exactly as the handler will (spec §5.2) and hash it
 * with the same 34-byte-per-entry encoding before signing. Root `swap`
 * (Task 6) binds the same `accounts_hash` construction via `SwapBody`.
 *
 * Named `OP_EXECUTE_ACTION` in Rust to avoid colliding with the session
 * `ops_mask` BIT `state::session::OP_EXECUTE` (1 << 1) — same convention as
 * {@link OP_TRANSFER}.
 */
export const OP_EXECUTE = 0x07;

/**
 * Canonical borsh encoding of `ExecuteBody` — build the body with this, do
 * not hand-roll the concatenation (see {@link OP_EXECUTE} for the layout).
 */
export function encodeExecuteBody(
  payloadHash: Uint8Array,
  accountsHash: Uint8Array,
): Uint8Array {
  require32(payloadHash, "payloadHash");
  require32(accountsHash, "accountsHash");
  const body = new Uint8Array(64);
  body.set(payloadHash, 0);
  body.set(accountsHash, 32);
  return body;
}

/**
 * `op_type` byte for the ROOT path of `swap` (Phase 1B Task 6); hashed over
 * `borsh(SwapBody)` — `in_mint: [u8;32]`, `out_mint: [u8;32]`, `max_in: u64 LE`,
 * `min_out: u64 LE`, `discriminator: [u8;8]` (the 8-byte Jupiter route
 * selector), `route_hash: [u8;32]` (`Keccak256` of the exact route bytes
 * executed, WRDF-0058), then `accounts_hash: [u8;32]` (the SAME logical-list
 * construction {@link OP_EXECUTE} binds). Rebuilt on-chain, so a bearer
 * assertion cannot
 * substitute the route, the mints, the bound, or any account after signing.
 * Named `OP_SWAP_ACTION` in Rust to avoid colliding with the `ops_mask` BIT
 * `state::session::OP_SWAP` (1 << 2).
 */
export const OP_SWAP = 0x08;

/**
 * Canonical borsh encoding of `SwapBody` — build the body with this, do not
 * hand-roll the concatenation (see {@link OP_SWAP} for the layout).
 */
export function encodeSwapBody(f: {
  inMint: Uint8Array;
  outMint: Uint8Array;
  maxIn: bigint;
  minOut: bigint;
  discriminator: Uint8Array;
  routeHash: Uint8Array;
  accountsHash: Uint8Array;
}): Uint8Array {
  require32(f.inMint, "inMint");
  require32(f.outMint, "outMint");
  require32(f.routeHash, "routeHash");
  require32(f.accountsHash, "accountsHash");
  if (f.discriminator.length !== 8) throw new Error("discriminator must be 8 bytes");
  // WRDF-0064: `setBigUint64` is modulo 2^64 — reject out-of-range amounts so
  // the signed body can never represent a different base-unit value than the
  // caller's, exactly as the transcript counters do.
  assertU64(f.maxIn, "maxIn");
  assertU64(f.minOut, "minOut");
  const body = new Uint8Array(32 + 32 + 8 + 8 + 8 + 32 + 32);
  const dv = new DataView(body.buffer);
  let o = 0;
  body.set(f.inMint, o); o += 32;
  body.set(f.outMint, o); o += 32;
  dv.setBigUint64(o, f.maxIn, true); o += 8;
  dv.setBigUint64(o, f.minOut, true); o += 8;
  body.set(f.discriminator, o); o += 8;
  body.set(f.routeHash, o); o += 32;
  body.set(f.accountsHash, o);
  return body;
}

/**
 * Domain separator for the `create_account` PDA seed derivation. Mirrors
 * `instructions::create_account::OWNER_SEED_DOMAIN`.
 */
export const OWNER_SEED_DOMAIN: Uint8Array = new TextEncoder().encode("WARDEN/seed/v1");

/**
 * `owner_seed = Keccak256("WARDEN/seed/v1" ‖ root_pubkey33 ‖ salt32)` — the
 * seed of the `SmartAccount` PDA (`["account", owner_seed]`).
 *
 * Mirrors `instructions::create_account::derive_owner_seed` byte-for-byte and
 * is pinned by a shared golden vector (Rust
 * `create_account::tests::owner_seed_matches_pinned_vector`,
 * TypeScript "matches the Rust-pinned owner_seed vector").
 *
 * **The IDL cannot express this seed** — Anchor's IDL seed parser handles
 * constants, plain instruction arguments and account fields, not a Keccak of
 * two arguments — so `create_account`'s `smart_account` account carries no
 * `pda` block and a client CANNOT auto-derive the address from the IDL. This
 * function is the supported derivation. Getting it wrong does not merely fail
 * to find the account: it signs the wrong address, and the program answers
 * `ChallengeMismatch`.
 *
 * The address is a hash of BOTH inputs, and both matter: the salt keeps one
 * passkey able to hold several independent accounts (and keeps an observer who
 * knows only the root key from computing the address); the root key is what
 * makes the address unsquattable, because a front-runner who copies the salt
 * and substitutes their own root lands somewhere else entirely.
 *
 * @param rootPubkey33 Compressed SEC1 P-256 point (33 bytes, prefix 0x02/0x03).
 * @param salt 32 client-chosen random bytes.
 */
export function deriveOwnerSeed(rootPubkey33: Uint8Array, salt: Uint8Array): Uint8Array {
  if (rootPubkey33.length !== 33) {
    throw new Error(`rootPubkey33 must be exactly 33 bytes, got ${rootPubkey33.length}`);
  }
  require32(salt, "salt");
  const preimage = new Uint8Array(OWNER_SEED_DOMAIN.length + 33 + 32);
  preimage.set(OWNER_SEED_DOMAIN, 0);
  preimage.set(rootPubkey33, OWNER_SEED_DOMAIN.length);
  preimage.set(salt, OWNER_SEED_DOMAIN.length + 33);
  return keccak_256(preimage);
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * RFC 4648 §5 base64url **without** padding — the encoding WebAuthn uses for
 * `clientDataJSON.challenge`. Hand-rolled (mirroring the Rust `b64url_no_pad`)
 * rather than delegated to a platform API, so behaviour is identical in
 * Node and browser/extension contexts and is pinned by the same vectors.
 */
export function challengeB64Url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out += B64URL[(n >>> 18) & 0x3f];
    out += B64URL[(n >>> 12) & 0x3f];
    out += B64URL[(n >>> 6) & 0x3f];
    out += B64URL[n & 0x3f];
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = (bytes[i] as number) << 16;
    out += B64URL[(n >>> 18) & 0x3f];
    out += B64URL[(n >>> 12) & 0x3f];
  } else if (rem === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += B64URL[(n >>> 18) & 0x3f];
    out += B64URL[(n >>> 12) & 0x3f];
    out += B64URL[(n >>> 6) & 0x3f];
  }
  return out;
}

/** Little-endian byte encoding of an unsigned 64-bit `bigint`. */
function u64le(v: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return b;
}

/** Little-endian byte encoding of an unsigned 32-bit number. */
function u32le(v: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, true);
  return b;
}

/** Little-endian byte encoding of a signed 64-bit `bigint`. */
function i64le(v: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, v, true);
  return b;
}

function require32(bytes: Uint8Array, name: string): void {
  if (bytes.length !== 32) {
    throw new Error(`${name} must be exactly 32 bytes, got ${bytes.length}`);
  }
}

const U32_MAX = 0xffffffff;
const U64_MAX = (1n << 64n) - 1n;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

/**
 * Asserts `v` is an integer in `[0, 255]`. Used for `op_type`, which Rust
 * encodes as `u8` — a JS `number` outside that range would otherwise
 * silently narrow (e.g. `256 & 0xff` truncates to `0`) instead of throwing.
 */
function assertU8(v: number, name: string): void {
  if (!Number.isInteger(v) || v < 0 || v > 0xff) {
    throw new RangeError(`${name} must be an integer in [0, 255] (u8), got ${v}`);
  }
}

/**
 * Asserts `v` is an integer in `[0, 2^32 - 1]`. Used for `policy_version`,
 * which Rust encodes as `u32`.
 */
function assertU32(v: number, name: string): void {
  if (!Number.isInteger(v) || v < 0 || v > U32_MAX) {
    throw new RangeError(`${name} must be an integer in [0, ${U32_MAX}] (u32), got ${v}`);
  }
}

/** Reject JS coercion before encoding a Rust u16 authority field. */
function assertU16(v: number, name: string): void {
  if (!Number.isInteger(v) || v < 0 || v > 0xffff) {
    throw new RangeError(`${name} must be an integer in [0, 65535] (u16), got ${v}`);
  }
}

/**
 * Asserts `v` is a `bigint` in `[0, 2^64 - 1]`. Used for `generation` and
 * `root_nonce`, which Rust encodes as `u64` — these are `bigint`, not
 * `number`, precisely because `number` cannot represent the full u64 range
 * without precision loss.
 */
function assertU64(v: bigint, name: string): void {
  if (typeof v !== "bigint" || v < 0n || v > U64_MAX) {
    throw new RangeError(`${name} must be a bigint in [0, 2^64 - 1] (u64), got ${v}`);
  }
}

/**
 * Asserts `v` is a `bigint` in `[-2^63, 2^63 - 1]`. Used for `expiry_ts`,
 * which Rust encodes as `i64`.
 */
function assertI64(v: bigint, name: string): void {
  if (typeof v !== "bigint" || v < I64_MIN || v > I64_MAX) {
    throw new RangeError(`${name} must be a bigint in [-2^63, 2^63 - 1] (i64), got ${v}`);
  }
}

export interface TranscriptInput {
  /** `SmartAccount.cluster_tag` — client-attested domain separator, not a verified genesis binding. */
  clusterTag: Uint8Array;
  /** The Warden program id (32 bytes). */
  programId: Uint8Array;
  /** The `SmartAccount` pubkey (32 bytes). */
  account: Uint8Array;
  generation: bigint;
  policyVersion: number;
  rootNonce: bigint;
  expiryTs: bigint;
  /**
   * The slot the client observed when building the ceremony. PRIMARY freshness
   * bound: the program requires
   * `signedSlot <= Clock.slot < signedSlot + MAX_ROOT_SLOT_AGE (150)`.
   */
  signedSlot: bigint;
  /** Output of {@link actionHash} (32 bytes). */
  actionHash: Uint8Array;
}

/**
 * Keccak256 over the canonical transcript encoding. Mirrors
 * `root_verify::transcript::transcript_hash` byte-for-byte.
 */
export function transcriptHash(input: TranscriptInput): Uint8Array {
  require32(input.clusterTag, "clusterTag");
  require32(input.programId, "programId");
  require32(input.account, "account");
  require32(input.actionHash, "actionHash");
  assertU64(input.generation, "generation");
  assertU32(input.policyVersion, "policyVersion");
  assertU64(input.rootNonce, "rootNonce");
  assertI64(input.expiryTs, "expiryTs");
  assertU64(input.signedSlot, "signedSlot");

  const preimage = new Uint8Array(
    TRANSCRIPT_DOMAIN.length + 32 + 32 + 32 + 8 + 4 + 8 + 8 + 8 + 32,
  );
  let o = 0;
  preimage.set(TRANSCRIPT_DOMAIN, o);
  o += TRANSCRIPT_DOMAIN.length;
  preimage.set(input.clusterTag, o);
  o += 32;
  preimage.set(input.programId, o);
  o += 32;
  preimage.set(input.account, o);
  o += 32;
  preimage.set(u64le(input.generation), o);
  o += 8;
  preimage.set(u32le(input.policyVersion), o);
  o += 4;
  preimage.set(u64le(input.rootNonce), o);
  o += 8;
  preimage.set(i64le(input.expiryTs), o);
  o += 8;
  preimage.set(u64le(input.signedSlot), o);
  o += 8;
  preimage.set(input.actionHash, o);

  return keccak_256(preimage);
}

/**
 * Keccak256(`op_type` ‖ `borsh_args`). Mirrors
 * `root_verify::transcript::action_hash` byte-for-byte. The caller
 * re-serializes the *executing* instruction's arguments, so no argument can
 * be swapped between the passkey ceremony and submission.
 */
export function actionHash(opType: number, borshArgs: Uint8Array): Uint8Array {
  assertU8(opType, "opType");
  const preimage = new Uint8Array(1 + borshArgs.length);
  preimage[0] = opType;
  preimage.set(borshArgs, 1);
  return keccak_256(preimage);
}
