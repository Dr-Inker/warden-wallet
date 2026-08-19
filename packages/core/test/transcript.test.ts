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
