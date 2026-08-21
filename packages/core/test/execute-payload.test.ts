import { describe, it, expect } from "vitest";
import { writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  encodeExecutePayload,
  decodeExecutePayload,
  computeAccountsHash,
  splitForStage,
  FLAG_SIGNER,
  FLAG_WRITABLE,
  type ExecutePayload,
  type LogicalAccount,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
// programs/warden/tests/fixtures relative to packages/core/test
const fixturesDir = resolve(here, "../../../programs/warden/tests/fixtures");

const hex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
const fill = (n: number, byte: number): Uint8Array => new Uint8Array(n).fill(byte);

describe("encodeExecutePayload / decodeExecutePayload", () => {
  it("round-trips a two-instruction payload", () => {
    const p: ExecutePayload = {
      ixs: [
        {
          programIndex: 2,
          accounts: [
            { index: 0, flags: FLAG_SIGNER },
            { index: 3, flags: FLAG_WRITABLE },
          ],
          data: Uint8Array.from([9, 9, 9]),
        },
        {
          programIndex: 4,
          accounts: [
            { index: 1, flags: FLAG_SIGNER },
            { index: 5, flags: 0 },
          ],
          data: Uint8Array.from([]),
        },
      ],
    };
    const bytes = encodeExecutePayload(p);
    expect(decodeExecutePayload(bytes)).toEqual(p);
  });

  it("encodes the empty payload as a single zero byte", () => {
    expect(hex(encodeExecutePayload({ ixs: [] }))).toBe("00");
    expect(decodeExecutePayload(Uint8Array.from([0]))).toEqual({ ixs: [] });
  });

  it("rejects a duplicate index within one ix at neither layer (allowed — see payload.rs)", () => {
    // The per-inner-ix duplicate rule was relaxed (a vault-sweep close names the
    // PDA twice); encode/decode must accept it.
    const p: ExecutePayload = {
      ixs: [{ programIndex: 9, accounts: [{ index: 0, flags: 0 }, { index: 0, flags: FLAG_SIGNER }], data: Uint8Array.from([]) }],
    };
    expect(decodeExecutePayload(encodeExecutePayload(p))).toEqual(p);
  });

  it("rejects unknown flag bits, writable PDA, and out-of-slot signers on ENCODE", () => {
    expect(() => encodeExecutePayload({ ixs: [{ programIndex: 2, accounts: [{ index: 3, flags: 0b100 }], data: new Uint8Array() }] })).toThrow();
    expect(() => encodeExecutePayload({ ixs: [{ programIndex: 2, accounts: [{ index: 0, flags: FLAG_WRITABLE }], data: new Uint8Array() }] })).toThrow();
    expect(() => encodeExecutePayload({ ixs: [{ programIndex: 9, accounts: [{ index: 2, flags: FLAG_SIGNER }], data: new Uint8Array() }] })).toThrow();
  });

  it("rejects the same shapes on DECODE, plus trailing bytes and truncation", () => {
    // n_ixs=1 but no ix bytes.
    expect(() => decodeExecutePayload(Uint8Array.from([1]))).toThrow();
    // trailing byte after a complete payload.
    const ok = encodeExecutePayload({ ixs: [{ programIndex: 2, accounts: [{ index: 0, flags: FLAG_SIGNER }], data: new Uint8Array() }] });
    expect(() => decodeExecutePayload(Uint8Array.from([...ok, 0xff]))).toThrow();
    // data_len past the end: n_ixs=1, program=2, n_accts=0, data_len=5, 2 bytes.
    expect(() => decodeExecutePayload(Uint8Array.from([1, 2, 0, 5, 0, 0xaa, 0xbb]))).toThrow();
    // writable PDA in the bytes.
    expect(() => decodeExecutePayload(Uint8Array.from([1, 2, 1, 0, FLAG_WRITABLE, 0, 0]))).toThrow();
  });
});

describe("computeAccountsHash", () => {
  it("is order- and flag-sensitive and reproducible", () => {
    const a = fill(32, 0xa1);
    const b = fill(32, 0xb2);
    const base: LogicalAccount[] = [
      { key: a, isSigner: true, isWritable: false },
      { key: b, isSigner: false, isWritable: true },
    ];
    const h = hex(computeAccountsHash(base));
    expect(hex(computeAccountsHash([base[1]!, base[0]!]))).not.toBe(h); // reorder
    expect(hex(computeAccountsHash([{ ...base[0]!, isWritable: true }, base[1]!]))).not.toBe(h); // flag flip
    expect(hex(computeAccountsHash(base))).toBe(h); // reproducible
  });
});

describe("splitForStage", () => {
  it("splits into ceil(len/cap) sequential chunks", () => {
    const payload = fill(2500, 7);
    const chunks = splitForStage(payload, 977);
    expect(chunks.length).toBe(Math.ceil(2500 / 977)); // 3
    expect(chunks[0]!.offset).toBe(0);
    expect(chunks[1]!.offset).toBe(977);
    expect(chunks[2]!.offset).toBe(1954);
    expect(chunks[2]!.bytes.length).toBe(2500 - 1954);
    // reassembly is byte-identical
    const joined = new Uint8Array(2500);
    for (const c of chunks) joined.set(c.bytes, c.offset);
    expect(hex(joined)).toBe(hex(payload));
  });
  it("yields no chunks for an empty payload", () => {
    expect(splitForStage(new Uint8Array(), 977)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Cross-language fixture: this test WRITES the byte vector + the accounts_hash
// that a Rust test (`payload::tests::ts_payload_vector_round_trips`) reads back
// and asserts `parse_payload` / `compute_accounts_hash` match byte-for-byte.
// ---------------------------------------------------------------------------
describe("cross-language fixture", () => {
  it("writes payload_vector.bin + accounts_hash.hex for the Rust decoder", () => {
    const payload: ExecutePayload = {
      ixs: [
        {
          programIndex: 4,
          accounts: [
            { index: 2, flags: FLAG_WRITABLE },
            { index: 3, flags: FLAG_WRITABLE },
            { index: 0, flags: FLAG_SIGNER },
            { index: 4, flags: 0 },
          ],
          data: Uint8Array.from([3, 0xd0, 0x07, 0, 0, 0, 0, 0, 0]), // SPL Transfer, amount 2000
        },
        {
          programIndex: 5,
          accounts: [{ index: 1, flags: FLAG_SIGNER }],
          data: Uint8Array.from([]),
        },
      ],
    };
    const bytes = encodeExecutePayload(payload);
    // A deterministic 6-account logical list for the hash vector.
    const logical: LogicalAccount[] = Array.from({ length: 6 }, (_, i) => ({
      key: fill(32, 0x10 + i),
      isSigner: i === 0 || i === 1,
      isWritable: i === 0 ? false : i >= 2 && i <= 3,
    }));
    const ah = computeAccountsHash(logical);

    mkdirSync(fixturesDir, { recursive: true });
    writeFileSync(resolve(fixturesDir, "payload_vector.bin"), bytes);
    writeFileSync(resolve(fixturesDir, "payload_accounts_hash.hex"), hex(ah));
    // Sanity: the vector round-trips in TS too.
    expect(decodeExecutePayload(bytes)).toEqual(payload);
    expect(bytes.length).toBeGreaterThan(0);
  });
});
