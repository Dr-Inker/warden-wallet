import { describe, it, expect } from "vitest";
import {
  transcriptHash,
  actionHash,
  challengeB64Url,
  OP_ROTATE_NONCE,
  OP_GRANT_SESSION,
  OP_REVOKE_SESSION,
  OP_FREEZE,
  OP_UNFREEZE,
  OP_TRANSFER,
  OP_CREATE,
  OP_EXECUTE,
  OP_SWAP,
  encodeCreateBody,
  encodeExecuteBody,
  encodeSwapBody,
  OWNER_SEED_DOMAIN,
  deriveOwnerSeed,
} from "../src/index.js";

const hex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

const fromHex = (s: string): Uint8Array => {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const fill = (n: number, byte: number): Uint8Array => new Uint8Array(n).fill(byte);

// Pinned against programs/warden/src/root_verify/transcript.rs
// `transcript_hash_matches_pinned_vector` (Phase 1B Task 0 vector — it REPLACES
// the Phase-1A one, because inserting `signed_slot` changes the preimage and
// the old digest is wrong rather than merely stale; see task-0-report.md).
// The program id is `crate::ID` = 017b5f72e2c074fa8555206db7ccf465c1db513c725913ca7ce685f135f8bd51
// (pinned separately in Rust's `program_id_bytes_are_pinned`).
const PROGRAM_ID = fromHex("017b5f72e2c074fa8555206db7ccf465c1db513c725913ca7ce685f135f8bd51");
const CLUSTER_TAG = fill(32, 0x11);
const ACCOUNT = fill(32, 0x22);
const ACTION_HASH = fill(32, 0x33);
const GENERATION = 7n;
const POLICY_VERSION = 3;
const ROOT_NONCE = 42n;
const EXPIRY_TS = 1_760_000_000n;
// A realistic mainnet-scale slot whose LE encoding has several distinct
// non-zero bytes; the u64::MAX companion vector below covers the rest of the
// range. Mirrors Rust's `VECTOR_SIGNED_SLOT`.
const SIGNED_SLOT = 314_159_265n;

const EXPECTED_CHALLENGE = "0iukGHw3iP1zKFk8_xdrFguCkQpq88yeG6MsESK55Zs";

describe("transcriptHash", () => {
  // Pinned against the Rust
  // `transcript_hash_matches_pinned_negative_expiry_vector` (Task 9). Same
  // inputs as the positive vector below with `expiryTs = -1n` (all-0xff i64) and
  // nothing else changed, so it proves this mirror encodes `expiry_ts` as
  // two's-complement little-endian — a divergence the positive-only vector
  // cannot catch, and one that would surface only against a clock-skewed or
  // pre-epoch timestamp.
  it("matches the Rust-pinned NEGATIVE-expiry vector (transcript_hash_matches_pinned_negative_expiry_vector)", () => {
    const t = transcriptHash({
      clusterTag: CLUSTER_TAG,
      programId: PROGRAM_ID,
      account: ACCOUNT,
      generation: GENERATION,
      policyVersion: POLICY_VERSION,
      rootNonce: ROOT_NONCE,
      signedSlot: SIGNED_SLOT,
      expiryTs: -1n,
      actionHash: ACTION_HASH,
    });
    expect(hex(t)).toBe("ce70570590fa61713d351480103bd85de57db23843dae12a3328a39060d56a6f");
    expect(challengeB64Url(t)).toBe("znBXBZD6YXE9NRSAEDvYXeV9sjhD2uEqMyijkGDVam8");
  });

  it("matches the Rust-pinned vector (transcript_hash_matches_pinned_vector)", () => {
    const t = transcriptHash({
      clusterTag: CLUSTER_TAG,
      programId: PROGRAM_ID,
      account: ACCOUNT,
      generation: GENERATION,
      policyVersion: POLICY_VERSION,
      rootNonce: ROOT_NONCE,
      signedSlot: SIGNED_SLOT,
      expiryTs: EXPIRY_TS,
      actionHash: ACTION_HASH,
    });
    expect(hex(t)).toBe("d22ba4187c3788fd7328593cff176b160b82910a6af3cc9e1ba32c1122b9e59b");
    expect(challengeB64Url(t)).toBe(EXPECTED_CHALLENGE);
  });

  // Pinned against the Rust
  // `transcript_hash_matches_pinned_max_slot_vector`. Same inputs as the
  // positive vector with `signedSlot = 2^64 - 1` (all-0xff u64) and nothing
  // else changed, so it proves this mirror encodes `signed_slot` as a full
  // 8-byte little-endian u64 — a divergence the realistic-slot vector cannot
  // catch, since 314_159_265 fits in four bytes and a truncated u32 encoding
  // would reproduce it.
  it("matches the Rust-pinned MAX-SLOT vector (transcript_hash_matches_pinned_max_slot_vector)", () => {
    const t = transcriptHash({
      clusterTag: CLUSTER_TAG,
      programId: PROGRAM_ID,
      account: ACCOUNT,
      generation: GENERATION,
      policyVersion: POLICY_VERSION,
      rootNonce: ROOT_NONCE,
      signedSlot: 2n ** 64n - 1n,
      expiryTs: EXPIRY_TS,
      actionHash: ACTION_HASH,
    });
    expect(hex(t)).toBe("87822c4c2c26c21ec09a7f4d3cd8b992e897b0899fea27a2ffd1c3234eebdf5c");
    expect(challengeB64Url(t)).toBe("h4IsTCwmwh7Amn9NPNi5kuiXsImf6iei_9HDI07r31w");
  });

  // Mirrors Rust's `signed_slot_and_expiry_ts_are_not_interchangeable`.
  // `expiryTs` and `signedSlot` are adjacent fixed-width integers, so a mirror
  // that emitted them in the wrong ORDER would still build a preimage of the
  // right length. Both values below are representable as i64 and u64, so the
  // swap is a pure ordering change.
  it("does not treat expiryTs and signedSlot as interchangeable", () => {
    const base = { clusterTag: CLUSTER_TAG, programId: PROGRAM_ID, account: ACCOUNT, generation: GENERATION, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE, actionHash: ACTION_HASH };
    const a = transcriptHash({ ...base, expiryTs: 1000n, signedSlot: 2000n });
    const b = transcriptHash({ ...base, expiryTs: 2000n, signedSlot: 1000n });
    expect(hex(a)).not.toBe(hex(b));
  });

  it("changes when every field changes (mirrors every_transcript_field_changes_the_hash)", () => {
    const base = transcriptHash({
      clusterTag: CLUSTER_TAG,
      programId: PROGRAM_ID,
      account: ACCOUNT,
      generation: GENERATION,
      policyVersion: POLICY_VERSION,
      rootNonce: ROOT_NONCE,
      signedSlot: SIGNED_SLOT,
      expiryTs: EXPIRY_TS,
      actionHash: ACTION_HASH,
    });

    const clusterTag2 = new Uint8Array(CLUSTER_TAG);
    clusterTag2[0] ^= 1;
    const actionHash2 = new Uint8Array(ACTION_HASH);
    actionHash2[31] ^= 1;
    const otherPubkey = fill(32, 0x99);

    const variants = [
      transcriptHash({ clusterTag: clusterTag2, programId: PROGRAM_ID, account: ACCOUNT, generation: GENERATION, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE, signedSlot: SIGNED_SLOT, expiryTs: EXPIRY_TS, actionHash: ACTION_HASH }),
      transcriptHash({ clusterTag: CLUSTER_TAG, programId: otherPubkey, account: ACCOUNT, generation: GENERATION, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE, signedSlot: SIGNED_SLOT, expiryTs: EXPIRY_TS, actionHash: ACTION_HASH }),
      transcriptHash({ clusterTag: CLUSTER_TAG, programId: PROGRAM_ID, account: otherPubkey, generation: GENERATION, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE, signedSlot: SIGNED_SLOT, expiryTs: EXPIRY_TS, actionHash: ACTION_HASH }),
      transcriptHash({ clusterTag: CLUSTER_TAG, programId: PROGRAM_ID, account: ACCOUNT, generation: GENERATION + 1n, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE, signedSlot: SIGNED_SLOT, expiryTs: EXPIRY_TS, actionHash: ACTION_HASH }),
      transcriptHash({ clusterTag: CLUSTER_TAG, programId: PROGRAM_ID, account: ACCOUNT, generation: GENERATION, policyVersion: POLICY_VERSION + 1, rootNonce: ROOT_NONCE, signedSlot: SIGNED_SLOT, expiryTs: EXPIRY_TS, actionHash: ACTION_HASH }),
      transcriptHash({ clusterTag: CLUSTER_TAG, programId: PROGRAM_ID, account: ACCOUNT, generation: GENERATION, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE + 1n, signedSlot: SIGNED_SLOT, expiryTs: EXPIRY_TS, actionHash: ACTION_HASH }),
      transcriptHash({ clusterTag: CLUSTER_TAG, programId: PROGRAM_ID, account: ACCOUNT, generation: GENERATION, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE, signedSlot: SIGNED_SLOT, expiryTs: EXPIRY_TS + 1n, actionHash: ACTION_HASH }),
      transcriptHash({ clusterTag: CLUSTER_TAG, programId: PROGRAM_ID, account: ACCOUNT, generation: GENERATION, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE, signedSlot: SIGNED_SLOT + 1n, expiryTs: EXPIRY_TS, actionHash: ACTION_HASH }),
      transcriptHash({ clusterTag: CLUSTER_TAG, programId: PROGRAM_ID, account: ACCOUNT, generation: GENERATION, policyVersion: POLICY_VERSION, rootNonce: ROOT_NONCE, signedSlot: SIGNED_SLOT, expiryTs: EXPIRY_TS, actionHash: actionHash2 }),
    ];

    for (const v of variants) {
      expect(hex(v)).not.toBe(hex(base));
    }
  });
});

describe("actionHash", () => {
  it("matches the Rust-pinned vectors (action_hash_matches_pinned_vectors)", () => {
    expect(hex(actionHash(5, new TextEncoder().encode("hello")))).toBe(
      "2beb245583b000d9052c7c9e84130b33accc05ab47ac43180743e302047ea29b",
    );
    expect(hex(actionHash(OP_ROTATE_NONCE, new Uint8Array()))).toBe(
      "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",
    );
  });

  it("separates op_type from args (mirrors action_hash_separates_op_type_from_args)", () => {
    expect(hex(actionHash(1, new Uint8Array([2])))).not.toBe(hex(actionHash(2, new Uint8Array([1]))));
    expect(hex(actionHash(0, new Uint8Array()))).not.toBe(hex(actionHash(1, new Uint8Array())));
  });
});

describe("challengeB64Url", () => {
  // RFC 4648 §10 vectors minus padding, plus a value exercising both
  // URL-safe alphabet substitutions — mirrors b64url_no_pad_matches_rfc4648_vectors.
  it("matches RFC 4648 vectors with no padding", () => {
    const cases: Array<[Uint8Array, string]> = [
      [new Uint8Array(), ""],
      [new TextEncoder().encode("f"), "Zg"],
      [new TextEncoder().encode("fo"), "Zm8"],
      [new TextEncoder().encode("foo"), "Zm9v"],
      [new TextEncoder().encode("foob"), "Zm9vYg"],
      [new TextEncoder().encode("fooba"), "Zm9vYmE"],
      [new TextEncoder().encode("foobar"), "Zm9vYmFy"],
      [new Uint8Array([0xfb, 0xff, 0xbe]), "-_--"],
    ];
    for (const [input, want] of cases) {
      expect(challengeB64Url(input)).toBe(want);
    }
  });

  it("encodes a 32-byte digest as exactly 43 unpadded chars", () => {
    for (const b of [0x00, 0x01, 0x7f, 0xff]) {
      const encoded = challengeB64Url(fill(32, b));
      expect(encoded.length).toBe(43);
      expect(encoded.includes("=")).toBe(false);
    }
  });
});

describe("op-type constants", () => {
  it("mirror the Rust root_verify::transcript byte assignments", () => {
    expect(OP_ROTATE_NONCE).toBe(0x00);
    expect(OP_GRANT_SESSION).toBe(0x01);
    expect(OP_REVOKE_SESSION).toBe(0x02);
    expect(OP_FREEZE).toBe(0x03);
    expect(OP_UNFREEZE).toBe(0x04);
    // Rust calls this one `OP_TRANSFER_ACTION` (it shares a name, not a
    // value, with the `ops_mask` bit `state::session::OP_TRANSFER` = 1 << 0).
    expect(OP_TRANSFER).toBe(0x05);
  });
});

describe("integer range validation", () => {
  const base = {
    clusterTag: fill(32, 0x11),
    programId: PROGRAM_ID,
    account: fill(32, 0x22),
    generation: GENERATION,
    policyVersion: POLICY_VERSION,
    rootNonce: ROOT_NONCE,
    expiryTs: EXPIRY_TS,
    signedSlot: SIGNED_SLOT,
    actionHash: ACTION_HASH,
  };

  it("actionHash throws RangeError for opType 256 (out of u8 range)", () => {
    expect(() => actionHash(256, new Uint8Array())).toThrow(RangeError);
  });

  it("actionHash throws RangeError for opType -1 (out of u8 range)", () => {
    expect(() => actionHash(-1, new Uint8Array())).toThrow(RangeError);
  });

  it("actionHash throws RangeError for a non-integer opType", () => {
    expect(() => actionHash(1.5, new Uint8Array())).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for generation >= 2^64", () => {
    expect(() => transcriptHash({ ...base, generation: 2n ** 64n })).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for a negative generation", () => {
    expect(() => transcriptHash({ ...base, generation: -1n })).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for policyVersion >= 2^32", () => {
    expect(() => transcriptHash({ ...base, policyVersion: 2 ** 32 })).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for a non-integer policyVersion", () => {
    expect(() => transcriptHash({ ...base, policyVersion: 1.5 })).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for expiryTs >= 2^63", () => {
    expect(() => transcriptHash({ ...base, expiryTs: 2n ** 63n })).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for expiryTs < -2^63", () => {
    expect(() => transcriptHash({ ...base, expiryTs: -(2n ** 63n) - 1n })).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for rootNonce >= 2^64", () => {
    expect(() => transcriptHash({ ...base, rootNonce: 2n ** 64n })).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for signedSlot >= 2^64", () => {
    expect(() => transcriptHash({ ...base, signedSlot: 2n ** 64n })).toThrow(RangeError);
  });

  it("transcriptHash throws RangeError for a negative signedSlot", () => {
    expect(() => transcriptHash({ ...base, signedSlot: -1n })).toThrow(RangeError);
  });

  // `signedSlot` is a bigint, not a number: a `number` cannot represent the
  // full u64 range without precision loss, and a slot silently rounded to the
  // nearest float would produce an unverifiable ceremony.
  it("transcriptHash throws RangeError for a number-typed signedSlot", () => {
    expect(() => transcriptHash({ ...base, signedSlot: 1 as unknown as bigint })).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// Phase 1B Task 2b — proof of possession at create_account
// ---------------------------------------------------------------------------

describe("create_account (OP_CREATE, 0x06)", () => {
  // The P-256 generator's x-coordinate, big-endian, with the even-parity
  // prefix — a point that indisputably exists, matching the Rust vector's
  // input (`create_account::tests::generator_pubkey33`).
  const GENERATOR_PUBKEY33 = fromHex(
    "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  );
  const SALT = fill(32, 0x44);

  it("pins the op byte (it is part of the signed transcript, so it is permanent)", () => {
    expect(OP_CREATE).toBe(0x06);
    // ...and it is distinct from every other op.
    const ops = [OP_ROTATE_NONCE, OP_GRANT_SESSION, OP_REVOKE_SESSION, OP_FREEZE, OP_UNFREEZE, OP_TRANSFER, OP_CREATE];
    expect(new Set(ops).size).toBe(ops.length);
  });

  it("mirrors the Rust seed domain separator byte-for-byte", () => {
    expect(new TextDecoder().decode(OWNER_SEED_DOMAIN)).toBe("WARDEN/seed/v1");
  });

  // Pinned against the Rust `create_account::tests::owner_seed_matches_pinned_vector`,
  // which was itself computed with an INDEPENDENT from-spec Keccak-256 (see
  // task-2b-report.md). This is an ADDRESS vector: a mirror that disagreed
  // would compute a different account address, sign for it, and be told
  // `ChallengeMismatch` — or, if it disagreed only later, would orphan every
  // account already created.
  it("matches the Rust-pinned owner_seed vector (owner_seed_matches_pinned_vector)", () => {
    expect(hex(deriveOwnerSeed(GENERATOR_PUBKEY33, SALT))).toBe(
      "794e590e0ff775f60fe3a1ebd85d9c1be8e5653c417018a63063f461e095b092",
    );
  });

  it("binds BOTH the root key and the salt", () => {
    const otherParity = new Uint8Array(GENERATOR_PUBKEY33);
    otherParity[0] = 0x03;
    const otherSalt = new Uint8Array(SALT);
    otherSalt[31] ^= 1;
    const base = hex(deriveOwnerSeed(GENERATOR_PUBKEY33, SALT));
    expect(hex(deriveOwnerSeed(otherParity, SALT))).not.toBe(base);
    expect(hex(deriveOwnerSeed(GENERATOR_PUBKEY33, otherSalt))).not.toBe(base);
  });

  it("rejects a root key that is not a 33-byte compressed point", () => {
    expect(() => deriveOwnerSeed(fill(32, 2), SALT)).toThrow();
    expect(() => deriveOwnerSeed(fill(34, 2), SALT)).toThrow();
  });

  it("rejects a salt that is not 32 bytes", () => {
    expect(() => deriveOwnerSeed(GENERATOR_PUBKEY33, fill(31, 0))).toThrow();
  });

  // Pinned against the Rust
  // `create_account::tests::create_body_action_hash_matches_pinned_vector`.
  // The borsh encoding is hand-built here on purpose: it is the encoding a
  // client must produce, and hand-building it is what proves this package and
  // the program agree on the field order and on `Vec<u8>`'s u32 LE length
  // prefix.
  it("matches the Rust-pinned CreateBody action hash (create_body_action_hash_matches_pinned_vector)", () => {
    // Build through the canonical exported encoder (WRDF-0042): the pinned
    // vector must validate the API clients actually use, not a hand-roll.
    const body = encodeCreateBody({
      salt: SALT,
      rpIdHash: fill(32, 0x55),
      origin: "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi",
      clusterTag: fill(32, 0x5a),
      policyHash: fill(32, 0x66),
      // registry omitted → Pubkey::default() = none (Task 3, WRDF-0034)
    });
    expect(body.length).toBe(215);

    expect(hex(actionHash(OP_CREATE, body))).toBe(
      "748fb53596c08c44303df545bec9432220ec1cdadae3413ef4ca267614d4d59a",
    );
  });
});

describe("execute (OP_EXECUTE, 0x07)", () => {
  it("pins the op byte (it is part of the signed transcript, so it is permanent)", () => {
    expect(OP_EXECUTE).toBe(0x07);
    // ...and it is distinct from every other op.
    const ops = [OP_ROTATE_NONCE, OP_GRANT_SESSION, OP_REVOKE_SESSION, OP_FREEZE, OP_UNFREEZE, OP_TRANSFER, OP_CREATE, OP_EXECUTE];
    expect(new Set(ops).size).toBe(ops.length);
  });

  it("encodeExecuteBody is payload_hash then accounts_hash, 64 bytes, no prefixes", () => {
    const body = encodeExecuteBody(fill(32, 0xaa), fill(32, 0xbb));
    expect(body.length).toBe(64);
    expect(hex(body.slice(0, 32))).toBe("aa".repeat(32));
    expect(hex(body.slice(32))).toBe("bb".repeat(32));
  });

  it("rejects hashes that are not exactly 32 bytes", () => {
    expect(() => encodeExecuteBody(fill(31, 1), fill(32, 1))).toThrow();
    expect(() => encodeExecuteBody(fill(32, 1), fill(33, 1))).toThrow();
  });

  // Pinned against the Rust
  // `execute::tests::execute_action_hash_matches_pinned_vector` — the one
  // place both languages prove they hash the same ExecuteBody bytes under the
  // same op byte. If this moves, every outstanding root `execute` ceremony
  // breaks: that is a deliberate migration, never a refactor.
  it("matches the Rust-pinned ExecuteBody action hash (execute_action_hash_matches_pinned_vector)", () => {
    const body = encodeExecuteBody(fill(32, 0x11), fill(32, 0x22));
    expect(hex(actionHash(OP_EXECUTE, body))).toBe(
      "971cfa437b2d03ae9063c9117d4c7ef61539d7a485d9ed1b991aab6e52d50c77",
    );
  });
});

describe("swap (OP_SWAP, 0x08)", () => {
  it("pins the op byte and is distinct from every other op", () => {
    expect(OP_SWAP).toBe(0x08);
    const ops = [OP_ROTATE_NONCE, OP_GRANT_SESSION, OP_REVOKE_SESSION, OP_FREEZE, OP_UNFREEZE, OP_TRANSFER, OP_CREATE, OP_EXECUTE, OP_SWAP];
    expect(new Set(ops).size).toBe(ops.length);
  });

  it("encodeSwapBody layout: in_mint | out_mint | max_in | min_out | disc | accounts_hash", () => {
    const body = encodeSwapBody({
      inMint: fill(32, 0x11), outMint: fill(32, 0x22), maxIn: 7n, minOut: 3n,
      discriminator: fill(8, 0x09), routeHash: fill(32, 0xcc), accountsHash: fill(32, 0xbb),
    });
    expect(body.length).toBe(152);
    expect(hex(body.slice(0, 32))).toBe("11".repeat(32));
    expect(hex(body.slice(32, 64))).toBe("22".repeat(32));
    expect(hex(body.slice(64, 72))).toBe("0700000000000000");
    expect(hex(body.slice(72, 80))).toBe("0300000000000000");
    expect(hex(body.slice(80, 88))).toBe("09".repeat(8));
    expect(hex(body.slice(88, 120))).toBe("cc".repeat(32));
    expect(hex(body.slice(120, 152))).toBe("bb".repeat(32));
  });

  it("rejects wrong-size fields", () => {
    const ok = { inMint: fill(32, 1), outMint: fill(32, 1), maxIn: 0n, minOut: 0n, discriminator: fill(8, 1), routeHash: fill(32, 1), accountsHash: fill(32, 1) };
    expect(() => encodeSwapBody({ ...ok, inMint: fill(31, 1) })).toThrow();
    expect(() => encodeSwapBody({ ...ok, discriminator: fill(7, 1) })).toThrow();
    expect(() => encodeSwapBody({ ...ok, routeHash: fill(31, 1) })).toThrow();
    // WRDF-0064: out-of-range u64 amounts are rejected, not wrapped.
    expect(() => encodeSwapBody({ ...ok, maxIn: -1n })).toThrow();
    expect(() => encodeSwapBody({ ...ok, minOut: 2n ** 64n })).toThrow();
  });

  // Pinned against Rust `swap::tests::swap_action_hash_matches_pinned_vector`.
  it("matches the Rust-pinned SwapBody action hash", () => {
    const body = encodeSwapBody({
      inMint: fill(32, 0x11), outMint: fill(32, 0x22), maxIn: 7n, minOut: 3n,
      discriminator: fill(8, 0x09), routeHash: fill(32, 0xcc), accountsHash: fill(32, 0xbb),
    });
    expect(hex(actionHash(OP_SWAP, body))).toBe(
      "1dc529b694012bbcfe50b10dff494ab093fbc0295494ed8f5d9b2555e8d61891",
    );
  });
});
